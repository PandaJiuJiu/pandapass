use crate::models::{AuthContext, ProjectRole, GlobalRole};
pub use crate::models::Permission;

/// RBAC service for permission checks
pub struct Rbac;

impl Rbac {
    /// Check if the auth context has the required permission
    pub fn check(ctx: &AuthContext, perm: Permission) -> bool {
        ctx.can(perm)
    }

    /// Check if user can access project (any role)
    pub fn can_access_project(ctx: &AuthContext, project_id: uuid::Uuid) -> bool {
        if ctx.user.global_role == GlobalRole::Admin {
            return true;
        }
        ctx.project_id == Some(project_id) && ctx.project_role.is_some()
    }

    /// Check if user can access environment
    pub fn can_access_env(ctx: &AuthContext, project_id: uuid::Uuid, env_id: uuid::Uuid) -> bool {
        if ctx.user.global_role == GlobalRole::Admin {
            return true;
        }
        ctx.project_id == Some(project_id) && ctx.env_id == Some(env_id) && ctx.project_role.is_some()
    }

    /// Get required permission for secret operations
    pub fn secret_perm(read: bool) -> Permission {
        if read { Permission::ReadSecret } else { Permission::WriteSecret }
    }

    /// Check secret access with project/env validation
    pub fn check_secret_access(
        ctx: &AuthContext,
        project_id: uuid::Uuid,
        env_id: uuid::Uuid,
        read: bool,
    ) -> Result<(), RbacError> {
        Self::check_secret_access_with(ctx, project_id, env_id, Self::secret_perm(read))
    }

    /// Same as [`check_secret_access`], but takes an explicit permission. Use
    /// this when the route handles a permission other than the read/write
    /// pair — e.g. `RunSecret` for the ciphertext-delivery path that an
    /// agent-only `run:secret` token must reach without holding `read:secret`.
    pub fn check_secret_access_with(
        ctx: &AuthContext,
        project_id: uuid::Uuid,
        env_id: uuid::Uuid,
        perm: Permission,
    ) -> Result<(), RbacError> {
        if !Self::can_access_env(ctx, project_id, env_id) {
            return Err(RbacError::NotMember);
        }
        if !ctx.can(perm) {
            return Err(RbacError::InsufficientRole);
        }
        Ok(())
    }

    /// Check if user is project owner
    pub fn is_project_owner(ctx: &AuthContext, project_id: uuid::Uuid) -> bool {
        if ctx.user.global_role == GlobalRole::Admin {
            return true;
        }
        ctx.project_id == Some(project_id) && ctx.project_role == Some(ProjectRole::Owner)
    }

    /// Check if user can manage project members
    pub fn can_manage_members(ctx: &AuthContext, project_id: uuid::Uuid) -> bool {
        Self::is_project_owner(ctx, project_id)
    }

    /// Check if service token has scope
    pub fn token_has_scope(token: &crate::models::ServiceToken, scope: crate::models::TokenScope) -> bool {
        token.scopes.contains(&scope)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RbacError {
    #[error("Not a member of this project")]
    NotMember,
    #[error("Insufficient role for this operation")]
    InsufficientRole,
    #[error("Project not found")]
    ProjectNotFound,
    #[error("Environment not found")]
    EnvironmentNotFound,
}

impl From<RbacError> for crate::error::CoreError {
    fn from(e: RbacError) -> Self {
        match e {
            RbacError::NotMember | RbacError::InsufficientRole => {
                Self::PermissionDenied(e.to_string())
            }
            RbacError::ProjectNotFound | RbacError::EnvironmentNotFound => {
                Self::NotFound(e.to_string())
            }
        }
    }
}

/// Helper trait for extracting project/env IDs from requests
pub trait ResourceAccess {
    fn project_id(&self) -> Option<uuid::Uuid>;
    fn env_id(&self) -> Option<uuid::Uuid>;
}

/// Audit action context for logging
#[derive(Clone)]
pub struct AuditContext<'a> {
    pub auth: &'a AuthContext,
    pub action: crate::models::AuditAction,
    pub project_id: Option<uuid::Uuid>,
    pub env_id: Option<uuid::Uuid>,
    pub secret_key: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub outcome: crate::models::AuditOutcome,
    pub meta: Option<serde_json::Value>,
}

impl<'a> AuditContext<'a> {
    pub fn new(
        auth: &'a AuthContext,
        action: crate::models::AuditAction,
    ) -> Self {
        Self {
            auth,
            action,
            project_id: auth.project_id,
            env_id: auth.env_id,
            secret_key: None,
            ip: auth.client_ip.clone(),
            user_agent: auth.user_agent.clone(),
            outcome: crate::models::AuditOutcome::Success,
            meta: None,
        }
    }

    pub fn with_project(mut self, project_id: uuid::Uuid) -> Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn with_env(mut self, env_id: uuid::Uuid) -> Self {
        self.env_id = Some(env_id);
        self
    }

    pub fn with_secret_key(mut self, key: String) -> Self {
        self.secret_key = Some(key);
        self
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn with_outcome(mut self, outcome: crate::models::AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn with_meta(mut self, meta: serde_json::Value) -> Self {
        self.meta = Some(meta);
        self
    }

    pub fn user_id(&self) -> Option<uuid::Uuid> {
        self.auth.session.as_ref().map(|s| s.user_id)
            .or(self.auth.service_token.as_ref().map(|t| t.created_by))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        GlobalRole, ServiceToken, TokenScope, UserPublic,
    };
    use chrono::{Duration, Utc};

    fn ctx_with_token(
        scopes: Vec<TokenScope>,
        token_project: Option<uuid::Uuid>,
    ) -> AuthContext {
        AuthContext {
            user: UserPublic {
                id: uuid::Uuid::now_v7(),
                email: "admin@example.com".into(),
                // The token's creator is an admin. That is the trap: if the
                // admin role is consulted at all, every token is an admin.
                global_role: GlobalRole::Admin,
                totp_enabled: false,
                created_at: Utc::now(),
                last_login_at: None,
            },
            session: None,
            service_token: Some(ServiceToken {
                id: uuid::Uuid::now_v7(),
                name: "ci".into(),
                token_hash: "hash".into(),
                project_id: token_project,
                env_id: None,
                scopes,
                expires_at: None,
                last_used_at: None,
                created_by: uuid::Uuid::now_v7(),
                created_at: Utc::now(),
                revoked_at: None,
            }),
            project_role: Some(ProjectRole::Owner),
            project_id: None,
            env_id: None,
            client_ip: None,
            user_agent: None,
        }
    }

    /// The regression this exists for: a token minted by an admin with only
    /// `read:secret` used to be able to write, because `can` consulted the
    /// creator's global role and never looked at the token at all. Scoping a
    /// token is the whole control; a read-only CI token must not be able to
    /// rotate a production credential.
    #[test]
    fn read_only_token_cannot_write_even_though_its_creator_is_an_admin() {
        let ctx = ctx_with_token(vec![TokenScope::ReadSecret], None);
        assert!(ctx.can(Permission::ReadSecret), "read should be allowed");
        assert!(!ctx.can(Permission::WriteSecret), "write must be denied");
        assert!(!ctx.can(Permission::DeleteSecret), "delete must be denied");
        assert!(!ctx.can(Permission::ListSecrets), "list needs its own scope");
    }

    /// A write token should not imply read. They are separate scopes on
    /// purpose: CI that can rotate a credential does not need to read any.
    #[test]
    fn write_scope_does_not_imply_read() {
        let ctx = ctx_with_token(vec![TokenScope::WriteSecret], None);
        assert!(ctx.can(Permission::WriteSecret));
        assert!(!ctx.can(Permission::ReadSecret));
    }

    /// `check_secret_access` is what the secret routes actually call, so the
    /// scope fix is only real if the denial surfaces here as `InsufficientRole`
    /// rather than being quietly bypassed by the env check above it.
    #[test]
    fn check_secret_access_rejects_a_write_from_a_read_only_token() {
        let ctx = ctx_with_token(vec![TokenScope::ReadSecret], None);
        let project = uuid::Uuid::now_v7();
        let env = uuid::Uuid::now_v7();

        assert!(Rbac::check_secret_access(&ctx, project, env, true).is_ok());

        let err = Rbac::check_secret_access(&ctx, project, env, false)
            .expect_err("write from a read-only token must be refused");
        assert!(matches!(err, RbacError::InsufficientRole), "got {err:?}");
    }

    /// Revocation and expiry are properties of the token, and must hold even
    /// for a token whose scopes would otherwise allow the action. This is what
    /// makes `token revoke` actually revoke.
    #[test]
    fn revoked_and_expired_tokens_grant_nothing() {
        let mut ctx = ctx_with_token(vec![TokenScope::ReadSecret, TokenScope::WriteSecret], None);

        ctx.service_token.as_mut().unwrap().revoked_at = Some(Utc::now());
        assert!(!ctx.can(Permission::ReadSecret), "revoked token must not read");
        assert!(!ctx.can(Permission::WriteSecret), "revoked token must not write");

        ctx.service_token.as_mut().unwrap().revoked_at = None;
        ctx.service_token.as_mut().unwrap().expires_at = Some(Utc::now() - Duration::seconds(1));
        assert!(!ctx.can(Permission::ReadSecret), "expired token must not read");
        assert!(!ctx.can(Permission::WriteSecret), "expired token must not write");
    }

    /// A token must not be able to widen its own authority. If it could mint or
    /// revoke tokens, or manage users, it could escalate well past its declared
    /// scopes — which would make the whole scope system decorative. `manage:project`
    /// still grants project CRUD, which is what that scope is for.
    #[test]
    fn a_token_cannot_mint_or_revoke_tokens_or_manage_users() {
        let ctx = ctx_with_token(
            vec![
                TokenScope::ReadSecret,
                TokenScope::WriteSecret,
                TokenScope::ListSecret,
                TokenScope::ReadAudit,
                TokenScope::ManageProject,
            ],
            None,
        );
        assert!(!ctx.can(Permission::CreateToken));
        assert!(!ctx.can(Permission::RevokeToken));
        assert!(!ctx.can(Permission::ManageUsers));

        assert!(ctx.can(Permission::CreateProject));
        assert!(ctx.can(Permission::DeleteProject));
    }

    /// `manage:project` alone must not reach secret values or the audit log.
    /// Managing a project's membership is not the same as reading its secrets,
    /// and conflating them would mean one compromised CI token exposes every
    /// credential in the environment.
    #[test]
    fn manage_project_scope_does_not_reach_secret_values() {
        let ctx = ctx_with_token(vec![TokenScope::ManageProject], None);
        assert!(!ctx.can(Permission::ReadSecret));
        assert!(!ctx.can(Permission::WriteSecret));
        assert!(!ctx.can(Permission::ListSecrets));
        assert!(!ctx.can(Permission::ReadAudit));
        assert!(!ctx.can(Permission::RunSecret));
    }

    /// The split this whole feature exists for: a token with only
    /// `run:secret` must be able to inject, and must not be able to read
    /// plaintext. The two scopes are deliberately not the same — `read:secret`
    /// means the holder sees values, `run:secret` means the holder never does.
    /// Conflating them would make the agent-safety story decorative.
    #[test]
    fn run_scoped_token_cannot_read_plaintext() {
        let ctx = ctx_with_token(vec![TokenScope::RunSecret], None);
        assert!(ctx.can(Permission::RunSecret));
        assert!(!ctx.can(Permission::ReadSecret));
        assert!(!ctx.can(Permission::WriteSecret));
        assert!(!ctx.can(Permission::ListSecrets));
        assert!(!ctx.can(Permission::ReadAudit));
    }

    /// The other half of the same split. A read token can take a value back
    /// over the wire; it must not be able to ask the server to run a command
    /// with that value — that requires explicit `run:secret`.
    #[test]
    fn read_scoped_token_cannot_run_server_side_injection() {
        let ctx = ctx_with_token(vec![TokenScope::ReadSecret], None);
        assert!(ctx.can(Permission::ReadSecret));
        assert!(!ctx.can(Permission::RunSecret));
    }

    /// Both scopes are independent and stack when both are granted.
    #[test]
    fn read_and_run_scopes_compose() {
        let ctx = ctx_with_token(
            vec![TokenScope::ReadSecret, TokenScope::RunSecret],
            None,
        );
        assert!(ctx.can(Permission::ReadSecret));
        assert!(ctx.can(Permission::RunSecret));
    }

    /// Human sessions are untouched by the token path. An admin in a browser
    /// keeps every permission; the scope check only applies to tokens.
    #[test]
    fn admin_session_is_unaffected_by_scope_enforcement() {
        let mut ctx = ctx_with_token(vec![TokenScope::ReadSecret], None);
        ctx.service_token = None;
        ctx.session = None;

        assert!(ctx.can(Permission::WriteSecret));
        assert!(ctx.can(Permission::CreateToken));
        assert!(ctx.can(Permission::ManageUsers));
    }
}