use crate::error::{CoreError, Result};
use age::secrecy::{ExposeSecret, SecretString, SecretBox};
use age::{Encryptor, Decryptor, x25519};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::fmt;
use zeroize::ZeroizeOnDrop;
use totp_rs::{Algorithm, Secret, Builder as TotpBuilder};
use base64::{Engine, engine::general_purpose};
use sha2::{Digest, Sha256};

/// Master Key - 32 bytes, encrypted with age per user
#[derive(ZeroizeOnDrop)]
pub struct MasterKey(SecretBox<Vec<u8>>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey").finish_non_exhaustive()
    }
}

/// Age public key for envelope encryption (the `age1...` recipient string)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AgePublicKey(pub String);

impl AgePublicKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_recipient(&self) -> Result<Box<dyn age::Recipient>> {
        let recipient: age::x25519::Recipient = self.0.parse()
            .map_err(|e| CoreError::InvalidInput(format!("Invalid age recipient: {}", e)))?;
        Ok(Box::new(recipient))
    }
}

/// An age X25519 identity: the private key that can open an [`Envelope`].
///
/// The inner string is a `SecretBox<str>` because `age` treats bech32 private
/// keys as secret — it zeroizes them on drop and won't hand back a plain
/// `Display`. Call [`AgeIdentity::expose`] deliberately, at the point of use.
pub struct AgeIdentity(SecretBox<str>);

impl AgeIdentity {
    /// Generate a fresh identity.
    pub fn generate() -> Self {
        Self(x25519::Identity::generate().to_string())
    }

    /// Parse the bech32 `AGE-SECRET-KEY-1...` form, tolerating surrounding whitespace.
    pub fn parse(s: &str) -> Result<Self> {
        s.trim()
            .parse::<x25519::Identity>()
            .map(|id| Self(id.to_string()))
            .map_err(|e| CoreError::InvalidInput(format!("Invalid age identity: {}", e)))
    }

    /// The corresponding public key, for wrapping envelopes.
    pub fn public_key(&self) -> Result<AgePublicKey> {
        let id: x25519::Identity = self.as_str().parse()
            .map_err(|e| CoreError::InvalidInput(format!("Invalid age identity: {}", e)))?;
        Ok(AgePublicKey(id.to_public().to_string()))
    }

    pub fn as_str(&self) -> &str {
        self.0.expose_secret()
    }

    /// Borrow the secret string. Named to make the exposure greppable.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for AgeIdentity {
    fn clone(&self) -> Self {
        Self::parse(self.as_str()).expect("stored age identity must stay parseable")
    }
}

impl fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private half.
        f.debug_struct("AgeIdentity").field("public_key", &self.public_key().ok()).finish()
    }
}

/// Age encrypted envelope containing the master key
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub user_id: uuid::Uuid,
    pub ciphertext: String,  // age encrypted master key
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Who an envelope is addressed to besides the member who owns the master key.
#[derive(Debug, Clone, Default)]
pub struct SealOptions {
    /// Also wrap the master key to the server's own age recipient, so the
    /// server can serve `get_secret` / `run_with_secret` on the member's
    /// behalf.
    ///
    /// This is the deliberate trade-off documented in `docs/SECURITY.md`: an
    /// attacker who steals only the database at rest still cannot decrypt,
    /// but an attacker who also compromises the running server can. Callers
    /// that hold the age identity and unwrap the envelope themselves leave
    /// this `None`, which locks the server out entirely.
    pub server: Option<AgePublicKey>,
}

impl Envelope {
    /// Create a new envelope for a user, addressed to `recipient` and — when
    /// `opts.server` is set — to the server as well.
    pub fn create(
        user_id: uuid::Uuid,
        master_key: &MasterKey,
        recipient: &AgePublicKey,
        opts: &SealOptions,
    ) -> Result<Self> {
        let mut recipients: Vec<Box<dyn age::Recipient>> = vec![recipient.to_recipient()?];
        if let Some(server) = &opts.server {
            recipients.push(server.to_recipient()?);
        }

        let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
            .map_err(|e| CoreError::Internal(format!("Encryptor error: {}", e)))?;
        let mut encrypted = vec![];
        {
            let mut writer = encryptor.wrap_output(&mut encrypted)
                .map_err(|e| CoreError::Internal(format!("Writer error: {}", e)))?;
            use std::io::Write;
            writer.write_all(master_key.as_bytes())
                .map_err(|e| CoreError::Internal(format!("Write error: {}", e)))?;
            writer.finish()
                .map_err(|e| CoreError::Internal(format!("Finish error: {}", e)))?;
        }
        let ciphertext = general_purpose::STANDARD.encode(&encrypted);

        Ok(Self {
            user_id,
            ciphertext,
            created_at: chrono::Utc::now(),
            rotated_at: None,
        })
    }

    /// Decrypt the envelope using an age identity string (bech32 `AGE-SECRET-KEY-...`)
    pub fn decrypt(&self, age_identity_str: &str) -> Result<MasterKey> {
        let encrypted = general_purpose::STANDARD.decode(&self.ciphertext)?;
        let decryptor = Decryptor::new_buffered(std::io::Cursor::new(&encrypted))
            .map_err(|e| CoreError::Internal(format!("Decryptor error: {}", e)))?;

        let age_identity: x25519::Identity = age_identity_str.parse()
            .map_err(|e| CoreError::Internal(format!("Identity parse error: {}", e)))?;

        let mut decrypted = vec![];
        use std::io::Read;
        decryptor.decrypt(std::iter::once(&age_identity as &dyn age::Identity))
            .map_err(|e| CoreError::Internal(format!("Decrypt error: {}", e)))?
            .read_to_end(&mut decrypted)
            .map_err(|e| CoreError::Internal(format!("Read error: {}", e)))?;
        if decrypted.len() != 32 {
            return Err(CoreError::InvalidInput("Decrypted master key has invalid length".into()));
        }
        Ok(MasterKey::from_bytes(decrypted))
    }
}

/// Secret value encrypted with master key using ChaCha20-Poly1305
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSecret {
    pub nonce: String,    // base64 encoded 12 bytes
    pub ciphertext: String, // base64 encoded
}

impl EncryptedSecret {
    /// Encrypt a secret value with the master key
    pub fn encrypt(value: &str, master_key: &MasterKey) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master_key.as_bytes()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, value.as_bytes())
            .map_err(|_| CoreError::Internal("Encryption failed".into()))?;

        Ok(Self {
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            ciphertext: general_purpose::STANDARD.encode(ciphertext),
        })
    }

    /// Decrypt a secret value with the master key
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecretString> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master_key.as_bytes()));
        let nonce_bytes = general_purpose::STANDARD.decode(&self.nonce)?;
        let ciphertext = general_purpose::STANDARD.decode(&self.ciphertext)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CoreError::Internal("Decryption failed".into()))?;

        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|_| CoreError::Internal("Invalid UTF-8".into()))?;
        Ok(SecretString::new(plaintext_str.into()))
    }
}

/// Password hashing with Argon2id
pub fn hash_password(password: &str) -> Result<String> {
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes())
        .map_err(|e| CoreError::Internal(format!("Argon2 error: {}", e)))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CoreError::Internal(format!("Password hash parse error: {}", e)))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

/// TOTP secret generation and verification (totp-rs 6.0 API)
pub fn generate_totp_secret() -> String {
    let secret = Secret::generate();
    secret.to_base32()
}

pub fn verify_totp(secret_base32: &str, code: &str) -> bool {
    let secret = match Secret::try_from_base32(secret_base32) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let totp = TotpBuilder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .build();
    match totp {
        Ok(t) => t.check_current(code).is_some(),
        Err(_) => false,
    }
}

pub fn totp_uri(email: &str, secret_base32: &str, issuer: &str) -> String {
    let secret = match Secret::try_from_base32(secret_base32) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let totp = TotpBuilder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_step_duration(30)
        .with_secret(secret)
        .with_account_name(email)
        .with_issuer(Some(issuer))
        .build();
    match totp {
        Ok(t) => t.to_url().unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Generate a secure random token (for session tokens, API keys, etc.)
pub fn generate_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Hash a bearer/session token for storage and lookup.
///
/// Deliberately SHA-256, not argon2: tokens are looked up by an exact
/// `WHERE token_hash = ?` match on every request, so the hash must be
/// deterministic. That is safe here because the input is 256 bits of CSPRNG
/// output from [`generate_token`] — there is no low-entropy secret to brute
/// force, and a fast hash is fine. Passwords go through [`hash_password`]
/// (argon2) instead, because those *are* low-entropy.
pub fn hash_token(token: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(token.as_bytes())))
}

/// Constant-time comparison, for anywhere two secrets are compared directly.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn secret_round_trips_through_master_key() {
        let mk = MasterKey::generate();
        let enc = EncryptedSecret::encrypt("s3cr3t-value", &mk).unwrap();
        let dec = enc.decrypt(&mk).unwrap();
        assert_eq!(dec.expose_secret(), "s3cr3t-value");
    }

    #[test]
    fn secret_fails_to_decrypt_with_wrong_key() {
        let mk = MasterKey::generate();
        let other = MasterKey::generate();
        let enc = EncryptedSecret::encrypt("s3cr3t-value", &mk).unwrap();
        // AEAD authentication must reject this, not return garbage.
        assert!(enc.decrypt(&other).is_err());
    }

    #[test]
    fn envelope_round_trips_through_age_identity() {
        let identity = AgeIdentity::generate();
        let public = identity.public_key().unwrap();
        let mk = MasterKey::generate();
        let uid = uuid::Uuid::now_v7();

        let env = Envelope::create(uid, &mk, &public, &SealOptions::default()).unwrap();
        let recovered = env.decrypt(identity.as_str()).unwrap();

        assert_eq!(recovered.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn envelope_rejects_a_foreign_identity() {
        let owner = AgeIdentity::generate();
        let stranger = AgeIdentity::generate();
        let mk = MasterKey::generate();

        let env = Envelope::create(
            uuid::Uuid::now_v7(),
            &mk,
            &owner.public_key().unwrap(),
            &SealOptions::default(),
        )
        .unwrap();
        assert!(env.decrypt(stranger.as_str()).is_err());
    }

    /// The server is addressed alongside the member, so the same envelope
    /// must open with either identity — that is what makes the server-side
    /// `get_secret` path possible without ever holding a plaintext key on disk.
    #[test]
    fn envelope_opens_for_both_member_and_server() {
        let server = AgeIdentity::generate();
        let member = AgeIdentity::generate();
        let mk = MasterKey::generate();
        let env = Envelope::create(
            uuid::Uuid::now_v7(),
            &mk,
            &member.public_key().unwrap(),
            &SealOptions { server: Some(server.public_key().unwrap()) },
        )
        .unwrap();

        assert_eq!(env.decrypt(member.as_str()).unwrap().as_bytes(), mk.as_bytes());
        assert_eq!(env.decrypt(server.as_str()).unwrap().as_bytes(), mk.as_bytes());
    }

    #[test]
    fn envelope_omits_server_when_not_requested() {
        let server = AgeIdentity::generate();
        let member = AgeIdentity::generate();
        let mk = MasterKey::generate();
        let env = Envelope::create(
            uuid::Uuid::now_v7(),
            &mk,
            &member.public_key().unwrap(),
            &SealOptions::default(),
        )
        .unwrap();

        assert!(env.decrypt(server.as_str()).is_err());
    }

    #[test]
    fn identity_survives_string_round_trip() {
        let identity = AgeIdentity::generate();
        // Users store this in ~/.pandapass/age.key; it must reload verbatim.
        let parsed = AgeIdentity::parse(&identity.as_str()).unwrap();
        assert_eq!(parsed.as_str(), identity.as_str());
        assert_eq!(
            parsed.public_key().unwrap().as_str(),
            identity.public_key().unwrap().as_str()
        );
    }

    #[test]
    fn identity_parse_tolerates_trailing_newline() {
        let identity = AgeIdentity::generate();
        let with_newline = format!("{}\n", identity.as_str());
        assert!(AgeIdentity::parse(&with_newline).is_ok());
    }

    #[test]
    fn password_hash_round_trips() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn token_hashing_is_deterministic_so_lookup_by_hash_works() {
        let a = hash_token("tok").unwrap();
        let b = hash_token("tok").unwrap();
        // Must match exactly: the server resolves a bearer token with
        // `WHERE token_hash = ?`, which a salted hash could never satisfy.
        assert_eq!(a, b);
        assert_ne!(a, hash_token("other").unwrap());
        assert_eq!(a.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn generated_tokens_are_distinct_and_url_safe() {
        let a = generate_token(32);
        let b = generate_token(32);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn totp_verifies_a_freshly_generated_code() {
        let secret = generate_totp_secret();
        let totp = TotpBuilder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(6)
            .with_step_duration(30)
            .with_secret(Secret::try_from_base32(&secret).unwrap())
            .build()
            .unwrap();
        let code = totp.generate_current();
        assert!(verify_totp(&secret, &code.to_string()));
        assert!(!verify_totp(&secret, "000000"));
    }
}
