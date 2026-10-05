use crate::models::{AuthContext, Permission, ProjectRole, GlobalRole};

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
        if !Self::can_access_env(ctx, project_id, env_id) {
            return Err(RbacError::NotMember);
        }
        let perm = Self::secret_perm(read);
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
            ip: None,
            user_agent: None,
            outcome: crate::models::AuditOutcome::Success,
            meta: None,
        }
    }

    pub fn with_project(&mut self, project_id: uuid::Uuid) -> &mut Self {
        self.project_id = Some(project_id);
        self
    }

    pub fn with_env(&mut self, env_id: uuid::Uuid) -> &mut Self {
        self.env_id = Some(env_id);
        self
    }

    pub fn with_secret_key(&mut self, key: String) -> &mut Self {
        self.secret_key = Some(key);
        self
    }

    pub fn with_ip(&mut self, ip: String) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_user_agent(&mut self, ua: String) -> &mut Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn with_outcome(&mut self, outcome: crate::models::AuditOutcome) -> &mut Self {
        self.outcome = outcome;
        self
    }

    pub fn with_meta(&mut self, meta: serde_json::Value) -> &mut Self {
        self.meta = Some(meta);
        self
    }

    pub fn user_id(&self) -> Option<uuid::Uuid> {
        self.auth.session.as_ref().map(|s| s.user_id)
            .or(self.auth.service_token.as_ref().map(|t| t.created_by))
    }
}