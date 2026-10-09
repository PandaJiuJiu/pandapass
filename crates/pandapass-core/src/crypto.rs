use crate::error::{CoreError, Result};
use age::secrecy::{ExposeSecret, SecretString, SecretBox};
use age::{Encryptor, x25519};
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

/// Trait for the server-side envelope unwrap backend.
///
/// The historical implementation reads a plaintext age identity from a file
/// on disk (`PANDAPASS_SERVER_AGE_IDENTITY_FILE`). That puts the key in the
/// same blast radius as the database — a host compromise is a full
/// compromise. The [`EnvelopeBackend`] seam lets a deployment swap in a
/// remote-attested implementation (AWS KMS, GCP KMS, HashiCorp Vault
/// Transit, PKCS#11 / HSM) without touching the rest of the codebase.
///
/// `unwrap_envelope` returns the 32-byte master key the envelope is
/// sealed to. Backends must be safe to call concurrently from many
/// request handlers.
pub trait EnvelopeBackend: Send + Sync {
    /// Unwrap the envelope ciphertext and return the master key plaintext.
    fn unwrap_envelope<'a>(
        &'a self,
        envelope_ciphertext: &'a str,
    ) -> Result<Vec<u8>>;
}

/// File-based envelope backend: parses the bech32 age identity at
/// construction time and unwraps envelopes in-memory. The identity never
/// leaves the process, but it sits next to the database on disk — see
/// [`EnvelopeBackend`] for the rationale.
pub struct FileAgeBackend {
    identity: x25519::Identity,
}

impl FileAgeBackend {
    /// Parse the bech32 `AGE-SECRET-KEY-1...` form. Returns an error if
    /// the input is empty or malformed.
    pub fn new(identity_str: &str) -> Result<Self> {
        let trimmed = identity_str.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidInput(
                "server age identity is empty".into(),
            ));
        }
        let identity: x25519::Identity = trimmed
            .parse()
            .map_err(|e| CoreError::InvalidInput(format!("Invalid age identity: {e}")))?;
        Ok(Self { identity })
    }
}

impl EnvelopeBackend for FileAgeBackend {
    fn unwrap_envelope<'a>(
        &'a self,
        envelope_ciphertext: &'a str,
    ) -> Result<Vec<u8>> {
        let encrypted = general_purpose::STANDARD.decode(envelope_ciphertext)?;
        let decryptor = age::Decryptor::new_buffered(std::io::Cursor::new(&encrypted))
            .map_err(|e| CoreError::Internal(format!("Decryptor error: {e}")))?;

        let mut decrypted = vec![];
        use std::io::Read;
        decryptor
            .decrypt(std::iter::once(&self.identity as &dyn age::Identity))
            .map_err(|e| CoreError::Internal(format!("Decrypt error: {e}")))?
            .read_to_end(&mut decrypted)
            .map_err(|e| CoreError::Internal(format!("Read error: {e}")))?;

        if decrypted.len() != 32 {
            return Err(CoreError::InvalidInput(
                "Decrypted master key has invalid length".into(),
            ));
        }
        Ok(decrypted)
    }
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

    /// Decrypt the envelope using an [`EnvelopeBackend`]. The same backend
    /// is used by the server to unwrap every envelope, regardless of the
    /// underlying key material (file on disk today, KMS or HSM in a
    /// future deployment).
    pub fn decrypt_with_backend(&self, backend: &dyn EnvelopeBackend) -> Result<MasterKey> {
        let decrypted = backend.unwrap_envelope(&self.ciphertext)?;
        Ok(MasterKey::from_bytes(decrypted))
    }

    /// Decrypt the envelope using an age identity string (bech32 `AGE-SECRET-KEY-...`).
    ///
    /// This is a thin convenience over `decrypt_with_backend` for callers
    /// that already hold an age identity. The server-side code path uses
    /// the backend version so it can be swapped for a KMS without
    /// touching the rest of the codebase.
    pub fn decrypt(&self, age_identity_str: &str) -> Result<MasterKey> {
        let backend = FileAgeBackend::new(age_identity_str)?;
        self.decrypt_with_backend(&backend)
    }
}

/// Secret value encrypted with master key using ChaCha20-Poly1305
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSecret {
    pub nonce: String,    // base64 encoded 12 bytes
    pub ciphertext: String, // base64 encoded
}

/// Encrypt a whole file's content (e.g. a YAML secrets file) with age.
///
/// This is the GitOps sync path: the local `.pandapass/secrets/*.yaml` file is
/// sealed to the operator's age public key (and optionally the server's), so it
/// can sit in a git repository in ciphertext form. Unlike [`Envelope`] there is
/// no master key involved — the file content itself is the plaintext.
///
/// Returns ASCII-armored age ciphertext (a `String`), suitable for storing as a
/// `.yaml.age` file.
pub fn age_encrypt_file(
    content: &str,
    recipients: &[AgePublicKey],
) -> Result<String> {
    if recipients.is_empty() {
        return Err(CoreError::InvalidInput(
            "age_encrypt_file requires at least one recipient".into(),
        ));
    }
    let age_recipients: Vec<Box<dyn age::Recipient>> = recipients
        .iter()
        .map(|r| r.to_recipient())
        .collect::<Result<_>>()?;
    let encryptor = age::Encryptor::with_recipients(age_recipients.iter().map(|r| r.as_ref()))
        .map_err(|e| CoreError::Internal(format!("Encryptor error: {}", e)))?;

    let mut ciphertext = Vec::new();
    {
        use age::armor::Format;
        use std::io::Write;
        let mut writer = encryptor
            .wrap_output(age::armor::ArmoredWriter::wrap_output(
                &mut ciphertext,
                Format::AsciiArmor,
            )?)
            .map_err(|e| CoreError::Internal(format!("Writer error: {}", e)))?;
        writer
            .write_all(content.as_bytes())
            .map_err(|e| CoreError::Internal(format!("Write error: {}", e)))?;
        writer
            .finish()
            .map_err(|e| CoreError::Internal(format!("Finish error: {}", e)))?
            .finish()
            .map_err(|e| CoreError::Internal(format!("Armor finish error: {}", e)))?;
    }
    String::from_utf8(ciphertext)
        .map_err(|_| CoreError::Internal("Armored output is not UTF-8".into()))
}

/// Decrypt an ASCII-armored age file (as produced by [`age_encrypt_file`]).
pub fn age_decrypt_file(ciphertext: &str, identity: &AgeIdentity) -> Result<String> {
    use age::armor::ArmoredReader;
    use std::io::Read;

    let decryptor = age::Decryptor::new_buffered(ArmoredReader::new(ciphertext.as_bytes()))
        .map_err(|e| CoreError::Internal(format!("Decryptor error: {}", e)))?;

    let age_identity: age::x25519::Identity = identity
        .as_str()
        .parse()
        .map_err(|e| CoreError::Internal(format!("Identity parse error: {}", e)))?;

    let mut plaintext = vec![];
    decryptor
        .decrypt(std::iter::once(&age_identity as &dyn age::Identity))
        .map_err(|e| CoreError::Internal(format!("Decrypt error: {}", e)))?
        .read_to_end(&mut plaintext)
        .map_err(|e| CoreError::Internal(format!("Read error: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|_| CoreError::Internal("Decrypted file is not UTF-8".into()))
}

#[cfg(test)]
mod gitops_crypto_tests {
    use super::*;

    #[test]
    fn file_round_trips_through_age() {
        let identity = AgeIdentity::generate();
        let public = identity.public_key().unwrap();
        let content = "API_KEY: super-secret\nDB_URL: postgres://u:p@db/app\n";

        let enc = age_encrypt_file(content, &[public]).unwrap();
        assert!(enc.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let dec = age_decrypt_file(&enc, &identity).unwrap();
        assert_eq!(dec, content);
    }

    #[test]
    fn file_rejects_foreign_identity() {
        let identity = AgeIdentity::generate();
        let stranger = AgeIdentity::generate();
        let public = identity.public_key().unwrap();

        let enc = age_encrypt_file("secret", &[public]).unwrap();
        assert!(age_decrypt_file(&enc, &stranger).is_err());
    }

    #[test]
    fn file_encrypt_requires_recipient() {
        assert!(age_encrypt_file("secret", &[]).is_err());
    }
}

/// Domain-separation info strings for HKDF. Each kind of ciphertext under
/// the master key derives a different subkey, so a leak of one (a TOTP
/// secret, a CA private key) does not let an attacker decrypt any of
/// the others. **Do not** reuse these for new purposes without thinking
/// about the implication: a new caller should add a new variant.
pub mod key_purpose {
    /// Regular secret values (`EncryptedSecret` rows in `secrets`).
    pub const SECRET_VALUE: &[u8] = b"pandapass/v1/secret-value";
    /// TOTP secret encrypted at rest.
    pub const TOTP_SECRET: &[u8] = b"pandapass/v1/totp-secret";
    /// Dynamic-credential password (PostgreSQL / MySQL / Redis).
    pub const DYNAMIC_CRED_PASSWORD: &[u8] = b"pandapass/v1/dynamic-cred-password";
    /// X.509 CA private key (PEM). Also used for OpenSSH-format SSH CA
    /// private keys: the same master-key holder uploads the PEM, and the
    /// path through the API is admin-gated either way.
    pub const CA_X509_KEY: &[u8] = b"pandapass/v1/ca-x509-key";
}

/// Derive a 32-byte subkey from the user's master key for a specific
/// purpose. Domain separation: every kind of data under the master key
/// uses a different subkey, so a subkey compromise cannot be used to
/// decrypt other kinds.
pub fn derive_subkey(master_key: &MasterKey, purpose: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(purpose, &mut out)
        .expect("HKDF expand with 32-byte output never fails");
    out
}

impl EncryptedSecret {
    /// Encrypt a secret value with the master key, deriving the AEAD key
    /// from `purpose` via HKDF-SHA256. The same plaintext encrypted under
    /// two different `purpose` values produces two unrelated ciphertexts.
    pub fn encrypt_with_purpose(
        value: &str,
        master_key: &MasterKey,
        purpose: &[u8],
    ) -> Result<Self> {
        let subkey = derive_subkey(master_key, purpose);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&subkey));
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

    /// Decrypt a secret value with the master key, using the same `purpose`
    /// info that was used at encryption time.
    pub fn decrypt_with_purpose(
        &self,
        master_key: &MasterKey,
        purpose: &[u8],
    ) -> Result<SecretString> {
        let subkey = derive_subkey(master_key, purpose);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&subkey));
        let nonce_bytes = general_purpose::STANDARD.decode(&self.nonce)?;
        let ciphertext = general_purpose::STANDARD.decode(&self.ciphertext)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CoreError::Internal("Decryption failed".into()))?;

        let plaintext_str = String::from_utf8(plaintext)
            .map_err(|_| CoreError::Internal("Invalid UTF-8".into()))?;
        Ok(SecretString::new(plaintext_str.into()))
    }

    /// Encrypt a secret value with the master key using the default
    /// "secret value" purpose. Equivalent to the historical behaviour but
    /// routed through the domain-separated subkey.
    pub fn encrypt(value: &str, master_key: &MasterKey) -> Result<Self> {
        Self::encrypt_with_purpose(value, master_key, key_purpose::SECRET_VALUE)
    }

    /// Decrypt a secret value with the master key using the default
    /// "secret value" purpose.
    pub fn decrypt(&self, master_key: &MasterKey) -> Result<SecretString> {
        self.decrypt_with_purpose(master_key, key_purpose::SECRET_VALUE)
    }
}

/// Validate a password against the deployment's minimum policy.
///
/// Returns `Ok(())` when the password is acceptable, or a
/// human-readable explanation of what is wrong. The policy is deliberately
/// small and immutable for now — the full story (breach-list checks,
/// configurable complexity) is tracked in TODO.md.
pub fn validate_password_policy(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(CoreError::InvalidInput(
            "Password must be at least 12 characters".into(),
        ));
    }
    if password.len() > 1024 {
        return Err(CoreError::InvalidInput(
            "Password must be at most 1024 characters".into(),
        ));
    }
    Ok(())
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
        .with_algorithm(Algorithm::SHA256)
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
        .with_algorithm(Algorithm::SHA256)
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
            .with_algorithm(Algorithm::SHA256)
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

#[cfg(test)]
mod envelope_backend_tests {
    use super::*;

    /// `decrypt_with_backend` and the convenience `decrypt` must produce the
    /// same master key bytes for the same ciphertext. The seam is the
    /// abstraction KMS implementations plug into; if the two paths diverge
    /// every existing envelope would need a re-seal.
    #[test]
    fn backend_and_convenience_decrypt_agree() {
        let member = AgeIdentity::generate();
        let server = AgeIdentity::generate();
        let mk = MasterKey::generate();
        let env = Envelope::create(
            uuid::Uuid::now_v7(),
            &mk,
            &member.public_key().unwrap(),
            &SealOptions { server: Some(server.public_key().unwrap()) },
        )
        .unwrap();

        let backend = FileAgeBackend::new(server.as_str()).unwrap();
        let via_backend = env.decrypt_with_backend(&backend).unwrap();
        let via_convenience = env.decrypt(server.as_str()).unwrap();

        assert_eq!(via_backend.as_bytes(), via_convenience.as_bytes());
        assert_eq!(via_backend.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn file_backend_rejects_malformed_identity() {
        assert!(FileAgeBackend::new("").is_err());
        assert!(FileAgeBackend::new("not an age identity").is_err());
    }

    /// A custom backend can replace the file-based one without changing the
    /// envelope code. We verify the seam with a recording stub that
    /// pretends to be a remote KMS.
    struct RecordingBackend;

    impl EnvelopeBackend for RecordingBackend {
        fn unwrap_envelope<'a>(&'a self, _ciphertext: &'a str) -> Result<Vec<u8>> {
            // A real KMS would call Decrypt here. For the test, we just
            // return a well-formed 32-byte buffer so the rest of the path
            // runs.
            Ok(vec![0u8; 32])
        }
    }

    #[test]
    fn envelope_accepts_a_custom_backend() {
        let member = AgeIdentity::generate();
        let mk = MasterKey::generate();
        let env = Envelope::create(
            uuid::Uuid::now_v7(),
            &mk,
            &member.public_key().unwrap(),
            &SealOptions::default(),
        )
        .unwrap();

        let mk_via_backend = env.decrypt_with_backend(&RecordingBackend).unwrap();
        // We cannot compare to the real key because the recording backend
        // does not actually decrypt — but we can prove the call routes
        // through the trait by verifying the API is callable and returns
        // 32 bytes (the master-key length check).
        assert_eq!(mk_via_backend.as_bytes().len(), 32);
    }
}

#[cfg(test)]
mod domain_separation_tests {
    use super::*;

    /// A plaintext encrypted with one purpose must not decrypt under a
    /// different purpose, even with the same master key. This is the
    /// invariant that keeps a leak of one kind of ciphertext (a TOTP
    /// secret, a CA key) from also leaking any other.
    #[test]
    fn encryption_with_different_purposes_produces_unrelated_ciphertexts() {
        let mk = MasterKey::generate();
        let plaintext = "shared value";

        let enc_a = EncryptedSecret::encrypt_with_purpose(plaintext, &mk, key_purpose::SECRET_VALUE).unwrap();
        let enc_b = EncryptedSecret::encrypt_with_purpose(plaintext, &mk, key_purpose::TOTP_SECRET).unwrap();

        // Both encrypt the same plaintext but the ciphertexts must differ
        // (different AEAD keys via HKDF).
        assert_ne!(enc_a.ciphertext, enc_b.ciphertext);

        // Cross-decrypting must fail — that is the whole point.
        assert!(enc_a.decrypt_with_purpose(&mk, key_purpose::TOTP_SECRET).is_err());
        assert!(enc_b.decrypt_with_purpose(&mk, key_purpose::SECRET_VALUE).is_err());
    }

    /// Subkeys derived for the same purpose with the same MK are equal —
    /// otherwise two ciphertexts under the same purpose would not
    /// decrypt.
    #[test]
    fn derive_subkey_is_deterministic_for_a_purpose() {
        let mk = MasterKey::generate();
        let a = derive_subkey(&mk, key_purpose::SECRET_VALUE);
        let b = derive_subkey(&mk, key_purpose::SECRET_VALUE);
        assert_eq!(a, b);
        // Different purpose must produce a different subkey.
        let c = derive_subkey(&mk, key_purpose::TOTP_SECRET);
        assert_ne!(a, c);
    }
}
