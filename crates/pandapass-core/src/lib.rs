//! PandaPass Core - Shared types, crypto, RBAC, and audit

pub mod audit;
pub mod crypto;
pub mod error;
pub mod gitops;
pub mod models;
pub mod pki;
pub mod policy;
pub mod rbac;
pub mod scanner;

pub use audit::{
    extract_client_ip, generate_request_id, AuditLogger, AuditService, MemoryAuditLogger,
};
pub use crypto::{
    age_decrypt_file, age_encrypt_file, generate_token, generate_totp_secret, hash_password,
    hash_token, totp_uri, verify_password, verify_totp, AgePublicKey, EncryptedSecret, Envelope,
    MasterKey,
};
pub use error::{CoreError, Result};
pub use gitops::{diff_metadata, DiffEntry, DiffReport, SecretDiffState};
pub use models::Permission;
pub use models::*;
pub use pki::{generate_root_ca, sign_ssh_cert, sign_x509_from_csr, PkiError};
pub use policy::{PolicyDecision, PolicyEngine, PolicyError, PolicyInput};
pub use rbac::{AuditContext, Rbac, RbacError, ResourceAccess};
pub use scanner::{builtin_rules, RegexScanner, ScanFinding, ScanRule, ScanSeverity, Scanner};
