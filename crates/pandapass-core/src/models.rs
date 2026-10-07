use crate::crypto::EncryptedSecret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Global user role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GlobalRole {
    Admin,
    User,
}

impl Default for GlobalRole {
    fn default() -> Self {
        Self::User
    }
}

/// Project-scoped role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectRole {
    Owner,
    Editor,
    Viewer,
}

impl ProjectRole {
    pub fn can_read_secret(&self) -> bool {
        matches!(self, Self::Owner | Self::Editor | Self::Viewer)
    }

    pub fn can_write_secret(&self) -> bool {
        matches!(self, Self::Owner | Self::Editor)
    }

    pub fn can_manage_members(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn can_delete_project(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn can_view_audit(&self) -> bool {
        matches!(self, Self::Owner | Self::Editor)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Editor => "editor",
            Self::Viewer => "viewer",
        }
    }
}

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub totp_secret_enc: Option<EncryptedSecret>,
    pub totp_enabled: bool,
    pub recovery_codes_hash: Vec<String>, // argon2 hashes
    pub global_role: GlobalRole,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
}

/// User for API responses (no sensitive fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: Uuid,
    pub email: String,
    pub global_role: GlobalRole,
    pub totp_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            global_role: u.global_role,
            totp_enabled: u.totp_enabled,
            created_at: u.created_at,
            last_login_at: u.last_login_at,
        }
    }
}

/// Project model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Project with member info for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectWithRole {
    #[serde(flatten)]
    pub project: Project,
    pub user_role: Option<ProjectRole>,
}

/// Project member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMember {
    pub project_id: Uuid,
    pub user_id: Uuid,
    pub role: ProjectRole,
    pub added_by: Uuid,
    pub added_at: DateTime<Utc>,
}

/// Project member with user details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMemberDetail {
    #[serde(flatten)]
    pub member: ProjectMember,
    pub user: UserPublic,
}

/// Environment model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Secret metadata (without value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub id: Uuid,
    pub project_id: Uuid,
    pub env_id: Uuid,
    pub key: String,
    pub version: i32,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Secret with encrypted value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    #[serde(flatten)]
    pub meta: SecretMeta,
    pub value_enc: EncryptedSecret,
}

/// Secret version history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub secret_id: Uuid,
    pub version: i32,
    pub value_enc: EncryptedSecret,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Service token for machine access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceToken {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String, // argon2 hash
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
    pub scopes: Vec<TokenScope>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Token scopes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    /// Read plaintext secret values. Means the holder can see the secret —
    /// never grant this to a token that is supposed to never see one.
    ReadSecret,
    WriteSecret,
    ListSecret,
    ReadAudit,
    ManageProject,
    /// Server-side secret injection: the holder names keys and a command; the
    /// server decrypts and injects into the child process. The values never
    /// reach the agent. Mutually independent of `read:secret` — a token with
    /// only this scope cannot read plaintext, and vice versa.
    RunSecret,
}

impl TokenScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read:secret" => Some(Self::ReadSecret),
            "write:secret" => Some(Self::WriteSecret),
            "list:secret" => Some(Self::ListSecret),
            "read:audit" => Some(Self::ReadAudit),
            "manage:project" => Some(Self::ManageProject),
            "run:secret" => Some(Self::RunSecret),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadSecret => "read:secret",
            Self::WriteSecret => "write:secret",
            Self::ListSecret => "list:secret",
            Self::ReadAudit => "read:audit",
            Self::ManageProject => "manage:project",
            Self::RunSecret => "run:secret",
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
    pub secret_key: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub outcome: AuditOutcome,
    pub meta: Option<serde_json::Value>,
}

/// Audit actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum AuditAction {
    // Auth
    Login,
    Logout,
    TotpSetup,
    TotpVerify,
    TotpDisable,
    PasswordChange,
    Register,
    // Projects
    ProjectCreate,
    ProjectUpdate,
    ProjectDelete,
    ProjectMemberAdd,
    ProjectMemberRemove,
    ProjectMemberUpdate,
    // Environments
    EnvCreate,
    EnvUpdate,
    EnvDelete,
    // Secrets
    SecretCreate,
    SecretRead,
    SecretUpdate,
    SecretDelete,
    SecretList,
    SecretVersionList,
    // Service tokens
    TokenCreate,
    TokenRevoke,
    TokenUse,
    // Agent/CI read paths, invoked over the internal API.
    //
    // These keep their original `mcp_` names even though the MCP stdio server
    // was removed: the strings are already persisted in `audit_log.action`, and
    // renaming the variants would make existing rows unparseable. Renaming the
    // *stored string* would silently rewrite history. Add new actions instead.
    McpGetSecret,
    McpListSecrets,
    McpRunCommand,
    // Admin
    UserDisable,
    UserEnable,
    MkRotate,
    // M2+
    CredIssue,
    CredRevoke,
    // M3+
    PolicyCreate,
    PolicyUpdate,
    PolicyDelete,
    PolicyBind,
    PolicyEvaluate,
    // M4+
    CaCreate,
    CaSign,
    SshCertIssue,
    SshCertRevoke,
    SecretScan,
}

impl AuditAction {
    /// Parse from the snake_case wire representation used in the database
    pub fn as_str(&self) -> &'static str {
        use AuditAction::*;
        match self {
            Login => "login",
            Logout => "logout",
            TotpSetup => "totp_setup",
            TotpVerify => "totp_verify",
            TotpDisable => "totp_disable",
            PasswordChange => "password_change",
            Register => "register",
            ProjectCreate => "project_create",
            ProjectUpdate => "project_update",
            ProjectDelete => "project_delete",
            ProjectMemberAdd => "project_member_add",
            ProjectMemberRemove => "project_member_remove",
            ProjectMemberUpdate => "project_member_update",
            EnvCreate => "env_create",
            EnvUpdate => "env_update",
            EnvDelete => "env_delete",
            SecretCreate => "secret_create",
            SecretRead => "secret_read",
            SecretUpdate => "secret_update",
            SecretDelete => "secret_delete",
            SecretList => "secret_list",
            SecretVersionList => "secret_version_list",
            TokenCreate => "token_create",
            TokenRevoke => "token_revoke",
            TokenUse => "token_use",
            McpGetSecret => "mcp_get_secret",
            McpListSecrets => "mcp_list_secrets",
            McpRunCommand => "mcp_run_command",
            UserDisable => "user_disable",
            UserEnable => "user_enable",
            MkRotate => "mk_rotate",
            CredIssue => "cred_issue",
            CredRevoke => "cred_revoke",
            PolicyCreate => "policy_create",
            PolicyUpdate => "policy_update",
            PolicyDelete => "policy_delete",
            PolicyBind => "policy_bind",
            PolicyEvaluate => "policy_evaluate",
            CaCreate => "ca_create",
            CaSign => "ca_sign",
            SshCertIssue => "ssh_cert_issue",
            SshCertRevoke => "ssh_cert_revoke",
            SecretScan => "secret_scan",
        }
    }

    pub fn from_str(s: &str) -> Self {
        use AuditAction::*;
        match s {
            "logout" => Logout,
            "totp_setup" => TotpSetup,
            "totp_verify" => TotpVerify,
            "totp_disable" => TotpDisable,
            "password_change" => PasswordChange,
            "register" => Register,
            "project_create" => ProjectCreate,
            "project_update" => ProjectUpdate,
            "project_delete" => ProjectDelete,
            "project_member_add" => ProjectMemberAdd,
            "project_member_remove" => ProjectMemberRemove,
            "project_member_update" => ProjectMemberUpdate,
            "env_create" => EnvCreate,
            "env_update" => EnvUpdate,
            "env_delete" => EnvDelete,
            "secret_create" => SecretCreate,
            "secret_read" => SecretRead,
            "secret_update" => SecretUpdate,
            "secret_delete" => SecretDelete,
            "secret_list" => SecretList,
            "secret_version_list" => SecretVersionList,
            "token_create" => TokenCreate,
            "token_revoke" => TokenRevoke,
            "token_use" => TokenUse,
            "mcp_get_secret" => McpGetSecret,
            "mcp_list_secrets" => McpListSecrets,
            "mcp_run_command" => McpRunCommand,
            "user_disable" => UserDisable,
            "user_enable" => UserEnable,
            "mk_rotate" => MkRotate,
            "cred_issue" => CredIssue,
            "cred_revoke" => CredRevoke,
            "policy_create" => PolicyCreate,
            "policy_update" => PolicyUpdate,
            "policy_delete" => PolicyDelete,
            "policy_bind" => PolicyBind,
            "policy_evaluate" => PolicyEvaluate,
            "ca_create" => CaCreate,
            "ca_sign" => CaSign,
            "ssh_cert_issue" => SshCertIssue,
            "ssh_cert_revoke" => SshCertRevoke,
            "secret_scan" => SecretScan,
            _ => Login,
        }
    }
}

/// Audit outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
    Error,
}

/// Session info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Auth context for request handlers
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: UserPublic,
    pub session: Option<Session>,
    pub service_token: Option<ServiceToken>,
    pub project_role: Option<ProjectRole>,
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
}

impl AuthContext {
    pub fn can(&self, action: Permission) -> bool {
        // A service token is *not* its creator. It carries only the scopes it
        // was minted with, and the human's admin rights must not leak through
        // it — otherwise scoping a token to `read:secret` would grant nothing,
        // because the token would still present as the admin who made it.
        if let Some(token) = &self.service_token {
            return self.token_allows(token, action);
        }

        match (self.global_role(), self.project_role) {
            (GlobalRole::Admin, _) => true,
            (GlobalRole::User, Some(ProjectRole::Owner)) => true,
            (GlobalRole::User, Some(ProjectRole::Editor)) => action.is_editor_allowed(),
            (GlobalRole::User, Some(ProjectRole::Viewer)) => action.is_viewer_allowed(),
            (GlobalRole::User, None) => action.is_global_allowed(),
        }
    }

    /// Map a permission to the scope that would grant it.
    ///
    /// `None` means the action cannot be performed by a service token at all.
    /// Session-authenticated humans are unaffected — they go through `can`.
    fn required_scope(action: Permission) -> Option<TokenScope> {
        Some(match action {
            // Plaintext read path. Holds the value briefly but in the clear.
            // Tokens intended to never see a value must use `RunSecret`
            // instead; that path never returns plaintext.
            Permission::ReadSecret => TokenScope::ReadSecret,
            Permission::WriteSecret | Permission::DeleteSecret => TokenScope::WriteSecret,
            Permission::ListSecrets => TokenScope::ListSecret,
            Permission::ReadAudit => TokenScope::ReadAudit,
            // Server-side exec / ciphertext fetch. Independent of `ReadSecret`:
            // a token can hold one without the other, and the test in
            // `rbac::run_scoped_token_cannot_read_plaintext` is the lock.
            Permission::RunSecret => TokenScope::RunSecret,
            Permission::CreateProject
            | Permission::UpdateProject
            | Permission::DeleteProject
            | Permission::ManageMembers
            | Permission::CreateEnv
            | Permission::UpdateEnv
            | Permission::DeleteEnv => TokenScope::ManageProject,

            // Resolving a slug is a metadata read that any scoped caller needs
            // before it can do anything else, so `list:secret` carries it.
            Permission::ReadProject => TokenScope::ListSecret,

            // Minting a token, revoking one, or managing users is how you
            // escalate: a token able to do these could hand itself broader
            // scopes, which would make scoping pointless. No scope grants them.
            Permission::ManageUsers | Permission::CreateToken | Permission::RevokeToken => {
                return None
            }
        })
    }

    fn token_allows(&self, token: &ServiceToken, action: Permission) -> bool {
        // A revoked or expired token grants nothing, regardless of scopes.
        if token.revoked_at.is_some() {
            return false;
        }
        if let Some(exp) = token.expires_at {
            if exp < Utc::now() {
                return false;
            }
        }
        let Some(required) = Self::required_scope(action) else {
            return false;
        };
        token.scopes.contains(&required)
    }

    fn global_role(&self) -> GlobalRole {
        self.user.global_role
    }
}

/// Permission enum for RBAC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    // Project
    CreateProject,
    ReadProject,
    UpdateProject,
    DeleteProject,
    // Members
    ManageMembers,
    // Environments
    CreateEnv,
    UpdateEnv,
    DeleteEnv,
    // Secrets
    ReadSecret,
    WriteSecret,
    DeleteSecret,
    ListSecrets,
    /// Server-side secret injection. Granted by `run:secret` and only by
    /// `run:secret` — independent of `ReadSecret` so a token can hold one
    /// without ever being able to read plaintext.
    RunSecret,
    // Audit
    ReadAudit,
    // Admin
    ManageUsers,
    // Tokens
    CreateToken,
    RevokeToken,
}

impl Permission {
    fn is_editor_allowed(&self) -> bool {
        matches!(
            self,
            Self::ReadProject
                | Self::UpdateProject
                | Self::CreateEnv
                | Self::UpdateEnv
                | Self::ReadSecret
                | Self::WriteSecret
                | Self::ListSecrets
                | Self::ReadAudit
                | Self::RunSecret
        )
    }

    fn is_viewer_allowed(&self) -> bool {
        matches!(
            self,
            Self::ReadProject
                | Self::ReadSecret
                | Self::ListSecrets
                | Self::RunSecret
        )
    }

    fn is_global_allowed(&self) -> bool {
        matches!(self, Self::CreateProject)
    }
}

/// SSH certificates table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshCert {
    pub id: Uuid,
    pub user_id: Uuid,
    pub project_id: Option<Uuid>,
    pub principal: String,
    pub cert_pem: String,
    pub key_type: SshKeyType,
    pub valid_before: DateTime<Utc>,
    pub valid_after: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshKeyType {
    Rsa,
    Ed25519,
}

impl SshKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// Dynamic credentials (M2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCred {
    pub id: Uuid,
    pub project_id: Uuid,
    pub env_id: Uuid,
    pub kind: DynamicCredKind,
    pub username: String,
    pub password_enc: EncryptedSecret,
    pub ttl_seconds: i64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DynamicCredKind {
    PostgreSQL,
    MySQL,
    Redis,
}

impl DynamicCredKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PostgreSQL => "postgresql",
            Self::MySQL => "mysql",
            Self::Redis => "redis",
        }
    }
}

/// Policy engine (M3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub rego_source: String,
    pub enabled: bool,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBinding {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// PKI/CA (M4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaKey {
    pub id: Uuid,
    pub kind: CaKeyType,
    pub key_enc: EncryptedSecret,
    pub cert_pem: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaKeyType {
    Root,
    Intermediate,
}

impl CaKeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Intermediate => "intermediate",
        }
    }
}


/// API request/response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserPublic,
    pub session_token: String,
    pub requires_totp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEnvRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretRequest {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: ProjectRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: ProjectRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub project_id: Option<Uuid>,
    pub env_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub token: ServiceToken,
    pub plain_token: String, // only returned once
}

#[derive(Debug, Deserialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
    pub qr_code_svg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpDisableRequest {
    pub code: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(items: Vec<T>, total: i64, page: i64, per_page: i64) -> Self {
        Self { items, total, page, per_page }
    }
}

/// Result of an ephemeral subprocess run with injected secrets.
/// Note: never contains secret values — only exit status and output streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Names of the secret keys that were injected (never their values)
    pub injected_keys: Vec<String>,
    pub duration_ms: u64,
}