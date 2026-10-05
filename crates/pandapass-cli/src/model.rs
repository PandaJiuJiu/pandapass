//! Request/response shapes that aren't shared with the server crate.
//!
//! Anything both sides agree on lives in `pandapass_core::models`; these are the
//! endpoint-specific envelopes.

use pandapass_core::models::ProjectRole;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// The caller's age public key, sealing this account's master key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_public_key: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginResponse {
    pub user: pandapass_core::models::UserPublic,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub requires_totp: bool,
    /// Whether this account has a sealed master-key envelope. False means it
    /// exists but cannot store or read secrets.
    #[serde(default)]
    pub key_enrolled: bool,
}

#[derive(Deserialize)]
pub struct SecretValueResponse {
    pub key: String,
    pub value: String,
    pub version: i32,
    /// Present so this mirrors the server's response shape; the CLI does not
    /// print it, and dropping the field would hide a version bump from
    /// `secret list` callers that read this struct directly.
    #[allow(dead_code)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct ProjectMemberDetail {
    #[serde(flatten)]
    pub member: pandapass_core::models::ProjectMember,
    pub user: pandapass_core::models::UserPublic,
}

#[derive(Serialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: ProjectRole,
}

#[derive(Serialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
pub struct CreateTokenResponse {
    pub token: pandapass_core::models::ServiceToken,
    pub plain_token: String,
}
