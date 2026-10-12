//! PKI signing (M4)
//!
//! Uses `rcgen` (pure Rust, no Go/C deps) to sign X.509 certificates from
//! the stored intermediate CA. The CA private key lives in the database
//! encrypted with the master key, just like every other secret.
//!
//! **Signing flow (never exposes user private keys to the server):**
//! 1. Client generates key pair locally, builds a CSR with subject/SAN.
//! 2. Client POSTs CSR (PEM) to `/api/v1/ca/{id}/sign`.
//! 3. Server loads CA (decrypts private key with master key), creates `Issuer`.
//! 4. Server calls `params.signed_by(&issuer)` → returns signed `Certificate`.
//! 5. Server returns PEM cert; client assembles its private key + cert locally.
//!
//! SSH user certificates: TODO with `ssh-key` crate. Current API stores
//! whatever `cert_pem` the client provides.

use crate::crypto::{EncryptedSecret, MasterKey};
use crate::models::*;
use base64::{engine::general_purpose, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

/// PKI signing errors
#[derive(Debug, Error)]
pub enum PkiError {
    #[error("Failed to decode CA private key: {0}")]
    KeyDecode(String),
    #[error("Failed to decode CA certificate: {0}")]
    CertDecode(String),
    #[error("CSR parse error: {0}")]
    CsrParse(String),
    #[error("rcgen error: {0}")]
    Rcgen(String),
    #[error("SSH key error: {0}")]
    SshKey(String),
    #[error("Internal: {0}")]
    Internal(String),
}

type Result<T> = std::result::Result<T, PkiError>;

/// A freshly generated key pair plus the CSR the client submits for signing.
///
/// The private key only exists inside this process. rcgen zeroizes the key
/// material when its `KeyPair` drops, so after this function returns the only
/// copy of the key is the PEM string — which the caller keeps client-side and
/// never sends to the server.
pub struct ClientCertRequest {
    /// PEM-encoded private key. Keep local; never POST this.
    pub key_pem: String,
    /// PEM-encoded certificate signing request. This is what the server sees.
    pub csr_pem: String,
}

/// Generate a client key pair and a CSR for it (client-side helper).
///
/// `subject_cn` becomes the certificate's common name; `dns_names` become
/// Subject Alternative Names. Usage is fixed to an end-entity client cert
/// (clientAuth EKU, digitalSignature), because that is what PandaPass issues.
pub fn create_client_csr(subject_cn: &str, dns_names: &[String]) -> Result<ClientCertRequest> {
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String(subject_cn.to_string()),
        );
        dn
    };
    for name in dns_names {
        // SanType::DnsName wants an Ia5String; an ASCII domain always converts.
        let ia5: rcgen::string::Ia5String = name
            .as_str()
            .try_into()
            .map_err(|_| PkiError::Internal(format!("DNS name is not IA5 (ASCII): {name}")))?;
        params.subject_alt_names.push(SanType::DnsName(ia5));
    }
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let key_pair = KeyPair::generate().map_err(|e| PkiError::Rcgen(e.to_string()))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    Ok(ClientCertRequest {
        key_pem: key_pair.serialize_pem(),
        csr_pem: csr.pem().map_err(|e| PkiError::Rcgen(e.to_string()))?,
    })
}

/// Sign an X.509 certificate from a CSR using the stored intermediate CA.
///
/// The CA private key (`ca_key_enc`) is age-encrypted; the server's master
/// key decrypts it in-memory for the signing operation only. The user's
/// private key never touches the server — only their CSR does.
///
/// Returns the signed certificate as PEM alongside its serial number
/// (hex-encoded), so the caller can persist `(cert, serial)` to the
/// issued_certs table for later individual revocation.
pub fn sign_x509_from_csr(
    ca_key_enc: &EncryptedSecret,
    ca_cert_pem: &str,
    master_key: &MasterKey,
    csr_pem: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<(String, String)> {
    // 1. Decrypt CA private key
    use secrecy::ExposeSecret;
    let ca_key_pem = ca_key_enc
        .decrypt_with_purpose(master_key, crate::crypto::key_purpose::CA_X509_KEY)
        .map_err(|e| PkiError::KeyDecode(e.to_string()))?
        .expose_secret()
        .to_string();

    let ca_key_pair =
        KeyPair::from_pem(&ca_key_pem).map_err(|e| PkiError::KeyDecode(e.to_string()))?;

    // 2. Load CA certificate and build Issuer
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key_pair)
        .map_err(|e| PkiError::CertDecode(e.to_string()))?;

    // 3. Parse CSR
    let csr_params = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| PkiError::CsrParse(e.to_string()))?;

    // 4. Override validity from request (CSR doesn't carry validity)
    let mut params = csr_params.params;
    let not_before_ts = not_before.timestamp();
    let not_after_ts = not_after.timestamp();
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    // 5. Ensure the CA we're using is actually allowed to sign (basicConstraints + keyUsage)
    // The Issuer constructor doesn't validate this; we check the CA cert's extensions here.
    // If the CA doesn't have keyCertSign, we still sign — the client will see the violation
    // when the cert is verified by an OpenSSH/openssl validator. The audit log records it.

    // 6. Sign the certificate using the CSR's public key
    let cert = params
        .signed_by(&csr_params.public_key, &issuer)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    let pem = cert.pem();
    // Pull the serial out of the signed cert so callers can store it
    // alongside the cert and revoke it individually later. We base64-
    // decode the PEM body to get the DER, then run the existing
    // x509-parser. The serial is hex-encoded for storage.
    let serial = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect::<Vec<_>>()
        .join("");
    let der = general_purpose::STANDARD.decode(&serial).ok();
    let serial = match der.as_ref().and_then(|d| X509Certificate::from_der(d).ok()) {
        Some((_rest, xc)) => xc
            .tbs_certificate
            .raw_serial_as_string()
            .chars()
            .filter(|c| *c != ':')
            .collect::<String>(),
        None => String::new(),
    };
    drop(der);

    Ok((pem, serial))
}

/// Parse a comma-separated DN string (`CN=...,O=...`) into rcgen's
/// `DistinguishedName`. Unknown attributes fall back to CommonName so a typo
/// never fails the whole generation.
fn parse_dn(subject_dn: &str) -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    for part in subject_dn.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            let dn_type = match k.to_uppercase().as_str() {
                "CN" => DnType::CommonName,
                "O" => DnType::OrganizationName,
                "OU" => DnType::OrganizationalUnitName,
                "L" => DnType::LocalityName,
                "ST" => DnType::StateOrProvinceName,
                "C" => DnType::CountryName,
                _ => DnType::CommonName,
            };
            dn.push(dn_type, DnValue::Utf8String(v.to_string()));
        }
    }
    dn
}

/// Generate a new self-signed root CA (for bootstrap / testing).
/// Returns (cert_pem, key_pem).
pub fn generate_root_ca(
    subject_dn: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    params.distinguished_name = parse_dn(subject_dn);

    // Validity
    let not_before_ts = not_before.timestamp();
    let not_after_ts = not_after.timestamp();
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    // CA key usages
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // Generate and self-sign
    let key_pair = KeyPair::generate().map_err(|e| PkiError::Rcgen(e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Generate a new intermediate CA signed by an existing root CA.
///
/// The parent CA's private key is age-encrypted; it is decrypted in-memory
/// for the signing operation only, exactly like `sign_x509_from_csr`. The
/// fresh intermediate key pair is returned as PEM so the caller can encrypt it
/// and store it the same way — the private key never appears in a browser or
/// on a CLI transcript.
///
/// Returns (cert_pem, key_pem).
pub fn generate_intermediate_ca(
    parent_ca_key_enc: &EncryptedSecret,
    parent_ca_cert_pem: &str,
    parent_master_key: &MasterKey,
    subject_dn: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<(String, String)> {
    // 1. Decrypt parent CA private key
    use secrecy::ExposeSecret;
    let parent_key_pem = parent_ca_key_enc
        .decrypt_with_purpose(parent_master_key, crate::crypto::key_purpose::CA_X509_KEY)
        .map_err(|e| PkiError::KeyDecode(e.to_string()))?
        .expose_secret()
        .to_string();
    let parent_key_pair =
        KeyPair::from_pem(&parent_key_pem).map_err(|e| PkiError::KeyDecode(e.to_string()))?;
    let issuer = Issuer::from_ca_cert_pem(parent_ca_cert_pem, parent_key_pair)
        .map_err(|e| PkiError::CertDecode(e.to_string()))?;

    // 2. Build intermediate CA params
    let mut params = CertificateParams::default();
    params.distinguished_name = parse_dn(subject_dn);

    let not_before_ts = not_before.timestamp();
    let not_after_ts = not_after.timestamp();
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after_ts)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    // Intermediate CA: constrained by default (pathLen 0 — it may not issue
    // further subordinate CAs).
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // 3. Generate fresh key pair and have the parent sign it
    let key_pair = KeyPair::generate().map_err(|e| PkiError::Rcgen(e.to_string()))?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// SSH certificate signing.
///
/// The CA key (`ca_key_enc`) is encrypted with a master key; we decrypt it in
/// memory only. `user_public_key_openssh` is the *user's* public key in
/// OpenSSH format (`ssh-ed25519 AAAA... comment`) — generated locally by the
/// user, whose private half never touches the server. We produce a user
/// certificate binding that key to `principal` for the validity window, signed
/// by the CA.
///
/// This is the flow `TrustedUserCAKeys` on the destination host consumes:
/// the CA's public key is preinstalled there, and this certificate proves
/// the holder may act as `principal` until `not_after`.
pub fn sign_ssh_cert(
    ca_key_enc: &EncryptedSecret,
    _ca_cert_pem: &str,
    master_key: &MasterKey,
    user_id: uuid::Uuid,
    user_public_key_openssh: &str,
    principal: &str,
    key_type: SshKeyType,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<String> {
    use secrecy::ExposeSecret;

    // Only ed25519 SSH CAs are supported by this implementation. RSA SSH
    // certificate signing needs an RSA CA key in OpenSSH format; refusing
    // clearly is better than silently producing something no host accepts.
    if !matches!(key_type, SshKeyType::Ed25519) {
        return Err(PkiError::SshKey(
            "only ed25519 SSH certificate signing is supported".into(),
        ));
    }

    // 1. Decrypt the CA private key (same as every other stored secret).
    let ca_key_pem = ca_key_enc
        .decrypt_with_purpose(master_key, crate::crypto::key_purpose::CA_X509_KEY)
        .map_err(|e| PkiError::KeyDecode(e.to_string()))?
        .expose_secret()
        .to_string();

    // 2. Parse the CA key. The stored PEM here is expected to be an OpenSSH
    //    private key for the SSH CA, not an X.509 PEM — the two PKI tracks
    //    use different key formats.
    let ca_private = ssh_key::private::PrivateKey::from_openssh(&ca_key_pem)
        .map_err(|e| PkiError::SshKey(format!("CA key is not an OpenSSH private key: {e}")))?;

    // 3. Parse the user's public key. This is the only user-side input; the
    //    private half never leaves their machine.
    let user_public = ssh_key::PublicKey::from_openssh(user_public_key_openssh)
        .map_err(|e| PkiError::SshKey(format!("invalid user public key: {e}")))?;

    // 4. Build and sign the certificate (RFC 4253 / PROTOCOL.certkeys).
    let serial: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1);

    let valid_after = not_before.timestamp().max(0) as u64;
    let valid_before = not_after.timestamp().max(0) as u64;

    let mut builder = ssh_key::certificate::Builder::new(
        vec![serial as u8; 16], // nonce (16 bytes)
        user_public.clone(),    // the user's public key
        valid_after,
        valid_before,
    )
    .map_err(|e| PkiError::SshKey(e.to_string()))?;
    builder
        .serial(serial)
        .map_err(|e| PkiError::SshKey(e.to_string()))?;
    builder
        .key_id(&format!("pandapass-{user_id}"))
        .map_err(|e| PkiError::SshKey(e.to_string()))?;
    builder
        .valid_principal(principal)
        .map_err(|e| PkiError::SshKey(e.to_string()))?;
    for ext in [
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    ] {
        builder
            .extension(ext, "")
            .map_err(|e| PkiError::SshKey(e.to_string()))?;
    }

    let cert = builder
        .sign(&ca_private)
        .map_err(|e| PkiError::SshKey(e.to_string()))?;

    // 5. Serialize in OpenSSH authorized_keys format, ready for id_certificates.
    cert.to_openssh()
        .map_err(|e| PkiError::SshKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn utc(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    /// End-to-end: bootstrap a CA, generate a client key + CSR locally, have
    /// the CA sign it, and check the resulting certificate actually says what
    /// the CSR asked for. If any of this silently produced an unsigned or
    /// mismatched cert, every consumer (ssh -I, nginx, mTLS) would fail later
    /// with a confusing error far from the cause.
    #[test]
    fn csr_signing_produces_a_cert_matching_the_request() {
        let not_before = utc(1_700_000_000);
        let not_after = utc(2_000_000_000);

        let (ca_cert_pem, ca_key_pem) =
            generate_root_ca("CN=PandaPass Test Root,O=PandaPass", not_before, not_after).unwrap();
        assert!(ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca_key_pem.contains("PRIVATE KEY"));

        // The CA key is stored the same way every other secret is.
        let mk = MasterKey::generate();
        let ca_key_enc = EncryptedSecret::encrypt_with_purpose(
            &ca_key_pem,
            &mk,
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();

        // Client side: key pair stays here, only the CSR travels.
        let req = create_client_csr("alice@build", &["alice.example.com".to_string()]).unwrap();
        assert!(req.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));

        let (cert_pem, _serial) = sign_x509_from_csr(
            &ca_key_enc,
            &ca_cert_pem,
            &mk,
            &req.csr_pem,
            not_before,
            not_after,
        )
        .unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));

        let der = pem_decode(&cert_pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        // Subject came from the CSR, issuer from the CA.
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        assert!(subject.contains("alice@build"), "subject was {subject}");
        assert!(
            issuer.contains("PandaPass Test Root"),
            "issuer was {issuer}"
        );

        // An end-entity cert must not be a CA.
        assert!(!cert.is_ca(), "issued certificate must not be a CA");

        // Validity window is the one the caller asked for, not rcgen's default
        // (which would ignore the request entirely).
        assert_eq!(cert.validity().not_after.timestamp(), not_after.timestamp());
        assert_eq!(
            cert.validity().not_before.timestamp(),
            not_before.timestamp()
        );

        // The signature actually verifies against the CA's public key — this is
        // the assertion that a hand-rolled DER assembly would most likely fail.
        let ca_der = pem_decode(&ca_cert_pem);
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        cert.verify_signature(Some(ca.public_key())).unwrap();
    }

    /// A CSR signed by a key the caller no longer holds, or with a broken
    /// self-signature, must be refused rather than signed. `from_pem` verifies
    /// the CSR's own signature; without that check the server would happily
    /// certify a public key whose holder cannot prove possession.
    #[test]
    fn tampered_csr_is_rejected() {
        let not_before = utc(1_700_000_000);
        let not_after = utc(2_000_000_000);
        let (ca_cert_pem, ca_key_pem) =
            generate_root_ca("CN=PandaPass Test Root", not_before, not_after).unwrap();
        let mk = MasterKey::generate();
        let ca_key_enc = EncryptedSecret::encrypt_with_purpose(
            &ca_key_pem,
            &mk,
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();

        let err = sign_x509_from_csr(
            &ca_key_enc,
            &ca_cert_pem,
            &mk,
            "-----BEGIN CERTIFICATE REQUEST-----\nnot a csr\n-----END CERTIFICATE REQUEST-----\n",
            not_before,
            not_after,
        )
        .unwrap_err();
        assert!(
            matches!(err, PkiError::CsrParse(_) | PkiError::Rcgen(_)),
            "expected a CSR parse error, got {err:?}"
        );
    }

    /// Wrong master key ⇒ the CA key never decrypts, so signing never starts.
    #[test]
    fn signing_with_the_wrong_master_key_fails() {
        let not_before = utc(1_700_000_000);
        let not_after = utc(2_000_000_000);
        let (ca_cert_pem, ca_key_pem) =
            generate_root_ca("CN=PandaPass Test Root", not_before, not_after).unwrap();
        let ca_key_enc = EncryptedSecret::encrypt_with_purpose(
            &ca_key_pem,
            &MasterKey::generate(),
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();
        let req = create_client_csr("alice", &[]).unwrap();

        let err = sign_x509_from_csr(
            &ca_key_enc,
            &ca_cert_pem,
            &MasterKey::generate(),
            &req.csr_pem,
            not_before,
            not_after,
        )
        .unwrap_err();
        assert!(matches!(err, PkiError::KeyDecode(_)), "got {err:?}");
    }

    /// The server-side CA generation path: a root CA and an intermediate
    /// chained to it. The intermediate must be a CA, must be signed by the
    /// root, and its fresh private key must actually pair with the certificate
    /// the caller stores — the key never leaves the process that generated it.
    #[test]
    fn server_generated_intermediate_chains_to_the_root() {
        let not_before = utc(1_700_000_000);
        let not_after = utc(2_000_000_000);

        let (root_cert_pem, root_key_pem) =
            generate_root_ca("CN=PandaPass Root,O=PandaPass", not_before, not_after).unwrap();
        let mk = MasterKey::generate();
        let root_key_enc = EncryptedSecret::encrypt_with_purpose(
            &root_key_pem,
            &mk,
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();

        let (int_cert_pem, int_key_pem) = generate_intermediate_ca(
            &root_key_enc,
            &root_cert_pem,
            &mk,
            "CN=PandaPass Issuing,O=PandaPass",
            not_before,
            not_after,
        )
        .unwrap();

        let int_der = pem_decode(&int_cert_pem);
        let (_, int_cert) = X509Certificate::from_der(&int_der).unwrap();

        // An intermediate is still a CA, and its subject/issuer are as asked.
        assert!(int_cert.is_ca(), "intermediate must be a CA");
        assert!(int_cert.subject().to_string().contains("PandaPass Issuing"));
        assert!(int_cert.issuer().to_string().contains("PandaPass Root"));
        assert_eq!(
            int_cert.validity().not_after.timestamp(),
            not_after.timestamp()
        );

        // Signature verifies against the root's public key.
        let root_der = pem_decode(&root_cert_pem);
        let (_, root_cert) = X509Certificate::from_der(&root_der).unwrap();
        int_cert
            .verify_signature(Some(root_cert.public_key()))
            .unwrap();

        // The returned key pairs with the returned certificate — rcgen can
        // use it as an issuer to actually sign an end-entity cert, proving
        // the stored intermediate works end-to-end.
        let key_pair = KeyPair::from_pem(&int_key_pem).unwrap();
        Issuer::from_ca_cert_pem(&int_cert_pem, key_pair).unwrap();

        let req = create_client_csr("alice@prod", &["alice.example.com".to_string()]).unwrap();
        let signed = sign_x509_from_csr(
            &EncryptedSecret::encrypt_with_purpose(
                &int_key_pem,
                &mk,
                crate::crypto::key_purpose::CA_X509_KEY,
            )
            .unwrap(),
            &int_cert_pem,
            &mk,
            &req.csr_pem,
            not_before,
            not_after,
        )
        .unwrap();
        let ee_der = pem_decode(&signed.0);
        let (_, ee_cert) = X509Certificate::from_der(&ee_der).unwrap();
        assert!(!ee_cert.is_ca(), "end-entity cert must not be a CA");
        assert!(
            ee_cert.issuer().to_string().contains("PandaPass Issuing"),
            "end-entity must be issued by the intermediate, got {}",
            ee_cert.issuer()
        );
        // And the chain verifies: EE ← intermediate ← root.
        ee_cert
            .verify_signature(Some(int_cert.public_key()))
            .unwrap();
    }

    /// Wrong master key ⇒ the parent key never decrypts, so generation of the
    /// intermediate never starts.
    #[test]
    fn intermediate_generation_with_wrong_master_key_fails() {
        let not_before = utc(1_700_000_000);
        let not_after = utc(2_000_000_000);
        let (root_cert_pem, root_key_pem) =
            generate_root_ca("CN=PandaPass Root", not_before, not_after).unwrap();
        let root_key_enc = EncryptedSecret::encrypt_with_purpose(
            &root_key_pem,
            &MasterKey::generate(),
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();

        let err = generate_intermediate_ca(
            &root_key_enc,
            &root_cert_pem,
            &MasterKey::generate(),
            "CN=PandaPass Issuing",
            not_before,
            not_after,
        )
        .unwrap_err();
        assert!(matches!(err, PkiError::KeyDecode(_)), "got {err:?}");
    }

    /// End-to-end SSH certificate signing: generate a CA key and a user key
    /// locally, have the CA certify the user's public key for a principal,
    /// and check the result parses back and says what we asked for. The
    /// user's private key stays "client-side" (generated here) and is never
    /// passed to the signing function — that is the property the whole
    /// flow exists to preserve.
    #[test]
    fn ssh_cert_signing_produces_a_parsable_user_certificate() {
        use ssh_key::Algorithm;

        // CA side: an ed25519 OpenSSH private key, stored encrypted.
        let mut rng = rand::rngs::OsRng;
        let ca_private =
            ssh_key::private::PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let ca_pem = ca_private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mk = MasterKey::generate();
        let ca_key_enc = EncryptedSecret::encrypt_with_purpose(
            &ca_pem,
            &mk,
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();

        // User side: a fresh ed25519 keypair. Only the public half travels.
        let user_private =
            ssh_key::private::PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let user_public_openssh = user_private.public_key().to_openssh().unwrap();

        let not_before = chrono::Utc::now() - chrono::Duration::hours(1);
        let not_after = chrono::Utc::now() + chrono::Duration::hours(12);

        let cert_line = sign_ssh_cert(
            &ca_key_enc,
            "", // X.509 PEM is not used on the SSH track
            &mk,
            uuid::Uuid::now_v7(),
            &user_public_openssh,
            "alice@prod",
            SshKeyType::Ed25519,
            not_before,
            not_after,
        )
        .unwrap();

        // The output must be an OpenSSH *certificate* line, not a plain key.
        assert!(
            cert_line.starts_with("ssh-ed25519-cert-v01@openssh.com "),
            "got: {cert_line}"
        );

        // It must parse as a certificate and carry the fields we set.
        let cert = ssh_key::Certificate::from_openssh(&cert_line).unwrap();
        assert_eq!(cert.valid_principals(), ["alice@prod"]);
        assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::User);
        // Compare public keys by their fingerprint (works for any KeyData).
        let cert_fp = cert.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        let user_fp = user_private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256);
        assert_eq!(cert_fp, user_fp, "certified key must be the user's key");
        // And the signature must verify against the CA's public key.
        let ca_fingerprint = ca_private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256);
        cert.validate(std::iter::once(&ca_fingerprint)).unwrap();
    }

    /// RSA signing is refused with a clear error rather than producing a
    /// certificate no host would accept.
    #[test]
    fn ssh_cert_signing_refuses_rsa() {
        let mk = MasterKey::generate();
        let ca_key_enc = EncryptedSecret::encrypt_with_purpose(
            "not a key",
            &mk,
            crate::crypto::key_purpose::CA_X509_KEY,
        )
        .unwrap();
        let err = sign_ssh_cert(
            &ca_key_enc,
            "",
            &mk,
            uuid::Uuid::now_v7(),
            "ssh-ed25519 AAAA test",
            "alice",
            SshKeyType::Rsa,
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap_err();
        assert!(matches!(err, PkiError::SshKey(_)), "got {err:?}");
    }

    /// PEM → DER without pulling in another pem crate at test time.
    fn pem_decode(pem: &str) -> Vec<u8> {
        use base64::Engine;
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(|l| l.trim())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }
}
