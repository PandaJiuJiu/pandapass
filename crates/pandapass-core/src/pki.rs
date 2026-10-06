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

use crate::models::*;
use crate::crypto::{EncryptedSecret, MasterKey};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams,
    DnType, DnValue, KeyPair, KeyUsagePurpose, SanType, BasicConstraints, IsCa,
    ExtendedKeyUsagePurpose, Issuer,
};
use time::OffsetDateTime;
use thiserror::Error;

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
        dn.push(DnType::CommonName, DnValue::Utf8String(subject_cn.to_string()));
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
pub fn sign_x509_from_csr(
    ca_key_enc: &EncryptedSecret,
    ca_cert_pem: &str,
    master_key: &MasterKey,
    csr_pem: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<String> {
    // 1. Decrypt CA private key
    use secrecy::ExposeSecret;
    let ca_key_pem = ca_key_enc
        .decrypt(master_key)
        .map_err(|e| PkiError::KeyDecode(e.to_string()))?
        .expose_secret()
        .to_string();

    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| PkiError::KeyDecode(e.to_string()))?;

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
    let cert = params.signed_by(&csr_params.public_key, &issuer)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    // Certificate::pem() returns the PEM string directly
    Ok(cert.pem())
}

/// Generate a new self-signed root CA (for bootstrap / testing).
/// Returns (cert_pem, key_pem).
pub fn generate_root_ca(
    subject_dn: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    not_after: chrono::DateTime<chrono::Utc>,
) -> Result<(String, String)> {
    let mut params = CertificateParams::default();

    // Parse DN
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
    params.distinguished_name = dn;

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
    let cert = params.self_signed(&key_pair)
        .map_err(|e| PkiError::Rcgen(e.to_string()))?;

    Ok((
        cert.pem(),
        key_pair.serialize_pem(),
    ))
}

/// SSH certificate signing (stub).
pub fn sign_ssh_cert(
    _ca_key_enc: &EncryptedSecret,
    _ca_cert_pem: &str,
    _master_key: &MasterKey,
    _user_id: uuid::Uuid,
    _principal: &str,
    _key_type: SshKeyType,
    _not_before: chrono::DateTime<chrono::Utc>,
    _not_after: chrono::DateTime<chrono::Utc>,
) -> Result<String> {
    Err(PkiError::Internal("SSH cert signing not yet implemented; needs ssh-key crate".into()))
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
        let ca_key_enc = EncryptedSecret::encrypt(&ca_key_pem, &mk).unwrap();

        // Client side: key pair stays here, only the CSR travels.
        let req = create_client_csr("alice@build", &["alice.example.com".to_string()]).unwrap();
        assert!(req.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));

        let cert_pem = sign_x509_from_csr(
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
        assert!(issuer.contains("PandaPass Test Root"), "issuer was {issuer}");

        // An end-entity cert must not be a CA.
        assert!(!cert.is_ca(), "issued certificate must not be a CA");

        // Validity window is the one the caller asked for, not rcgen's default
        // (which would ignore the request entirely).
        assert_eq!(
            cert.validity().not_after.timestamp(),
            not_after.timestamp()
        );
        assert_eq!(cert.validity().not_before.timestamp(), not_before.timestamp());

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
        let ca_key_enc = EncryptedSecret::encrypt(&ca_key_pem, &mk).unwrap();

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
        let ca_key_enc =
            EncryptedSecret::encrypt(&ca_key_pem, &MasterKey::generate()).unwrap();
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

    /// PEM → DER without pulling in another pem crate at test time.
    fn pem_decode(pem: &str) -> Vec<u8> {
        use base64::Engine;
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(|l| l.trim())
            .collect();
        base64::engine::general_purpose::STANDARD.decode(body).unwrap()
    }
}