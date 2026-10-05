//! PandaPass Core - Shared types, crypto, RBAC, and audit

pub mod audit;
pub mod crypto;
pub mod error;
pub mod models;
pub mod rbac;

pub use audit::{AuditLogger, AuditService, MemoryAuditLogger, extract_client_ip, generate_request_id};
pub use crypto::{AgePublicKey, EncryptedSecret, Envelope, MasterKey, hash_password, verify_password, generate_totp_secret, verify_totp, totp_uri, generate_token, hash_token};
pub use error::{CoreError, Result};
pub use models::*;
pub use rbac::{Rbac, RbacError, ResourceAccess, AuditContext};
pub use models::Permission;