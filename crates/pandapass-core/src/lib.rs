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

pub use audit::{AuditLogger, AuditService, MemoryAuditLogger, extract_client_ip, generate_request_id};
pub use crypto::{AgePublicKey, EncryptedSecret, Envelope, MasterKey, hash_password, verify_password, generate_totp_secret, verify_totp, totp_uri, generate_token, hash_token, age_encrypt_file, age_decrypt_file};
pub use error::{CoreError, Result};
pub use gitops::{DiffEntry, DiffReport, SecretDiffState, diff_metadata};
pub use models::*;
pub use pki::{PkiError, sign_x509_from_csr, generate_root_ca, sign_ssh_cert};
pub use policy::{PolicyDecision, PolicyEngine, PolicyError, PolicyInput};
pub use rbac::{Rbac, RbacError, ResourceAccess, AuditContext};
pub use scanner::{RegexScanner, ScanFinding, ScanRule, ScanSeverity, Scanner, builtin_rules};
pub use models::Permission;