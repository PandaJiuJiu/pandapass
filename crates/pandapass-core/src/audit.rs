use crate::models::{AuditAction, AuditLog, AuditOutcome, AuthContext};
use crate::rbac::AuditContext;
use crate::error::Result;
use crate::crypto::generate_token;
use chrono::Utc;
use http::HeaderMap;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::error;
use uuid::Uuid;

/// Audit logger trait for different backends
#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log(&self, entry: AuditLog) -> Result<()>;
}

/// In-memory audit logger (for testing/dev)
pub struct MemoryAuditLogger {
    logs: Arc<Mutex<Vec<AuditLog>>>,
}

impl MemoryAuditLogger {
    pub fn new() -> Self {
        Self { logs: Arc::new(Mutex::new(Vec::new())) }
    }

    pub async fn get_logs(&self) -> Vec<AuditLog> {
        self.logs.lock().await.clone()
    }
}

#[async_trait::async_trait]
impl AuditLogger for MemoryAuditLogger {
    async fn log(&self, entry: AuditLog) -> Result<()> {
        self.logs.lock().await.push(entry);
        Ok(())
    }
}

/// Audit service - central logging facility
pub struct AuditService {
    logger: Arc<dyn AuditLogger>,
}

impl AuditService {
    pub fn new(logger: Arc<dyn AuditLogger>) -> Self {
        Self { logger }
    }

    /// Log an audit event from context
    pub async fn log(&self, ctx: &AuditContext<'_>) -> Result<()> {
        let entry = AuditLog {
            id: Uuid::now_v7(),
            ts: Utc::now(),
            user_id: ctx.user_id(),
            action: ctx.action,
            project_id: ctx.project_id,
            env_id: ctx.env_id,
            secret_key: ctx.secret_key.clone(),
            ip: ctx.ip.clone(),
            user_agent: ctx.user_agent.clone(),
            outcome: ctx.outcome,
            meta: ctx.meta.clone(),
        };

        if let Err(e) = self.logger.log(entry).await {
            error!("Failed to write audit log: {}", e);
            // Don't fail the request on audit failure
        }

        Ok(())
    }

    /// Convenience method for success
    pub async fn log_success(&self, ctx: &mut AuditContext<'_>) -> Result<()> {
        ctx.with_outcome(AuditOutcome::Success);
        self.log(ctx).await
    }

    /// Convenience method for failure
    pub async fn log_failure(&self, ctx: &mut AuditContext<'_>, err: &str) -> Result<()> {
        ctx.with_outcome(AuditOutcome::Failure)
            .with_meta(json!({ "error": err }));
        self.log(ctx).await
    }

    /// Convenience method for denied
    pub async fn log_denied(&self, ctx: &mut AuditContext<'_>, reason: &str) -> Result<()> {
        ctx.with_outcome(AuditOutcome::Denied)
            .with_meta(json!({ "reason": reason }));
        self.log(ctx).await
    }

    /// Log secret read (used by all read paths)
    pub async fn log_secret_read(
        &self,
        auth: &AuthContext,
        project_id: Uuid,
        env_id: Uuid,
        secret_key: &str,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        let mut ctx = AuditContext::new(auth, AuditAction::SecretRead);
        ctx.with_project(project_id)
            .with_env(env_id)
            .with_secret_key(secret_key.to_string())
            .with_ip(ip.unwrap_or_default())
            .with_user_agent(user_agent.unwrap_or_default());
        self.log(&ctx).await
    }

    /// Log secret list
    pub async fn log_secret_list(
        &self,
        auth: &AuthContext,
        project_id: Uuid,
        env_id: Uuid,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<()> {
        let mut ctx = AuditContext::new(auth, AuditAction::SecretList);
        ctx.with_project(project_id)
            .with_env(env_id)
            .with_ip(ip.unwrap_or_default())
            .with_user_agent(user_agent.unwrap_or_default());
        self.log(&ctx).await
    }

    /// Log MCP get_secret
    pub async fn log_mcp_get_secret(
        &self,
        auth: &AuthContext,
        project_id: Uuid,
        env_id: Uuid,
        secret_key: &str,
        ip: Option<String>,
    ) -> Result<()> {
        let mut ctx = AuditContext::new(auth, AuditAction::McpGetSecret);
        ctx.with_project(project_id)
            .with_env(env_id)
            .with_secret_key(secret_key.to_string())
            .with_ip(ip.unwrap_or_default());
        self.log(&ctx).await
    }

    /// Log MCP run_with_secret
    pub async fn log_mcp_run_command(
        &self,
        auth: &AuthContext,
        project_id: Uuid,
        env_id: Uuid,
        keys: &[String],
        command: &str,
        exit_code: i32,
        ip: Option<String>,
    ) -> Result<()> {
        let mut ctx = AuditContext::new(auth, AuditAction::McpRunCommand);
        ctx.with_project(project_id)
            .with_env(env_id)
            .with_meta(json!({
                "keys": keys,
                "argv0": command,
                "exit_code": exit_code
            }))
            .with_ip(ip.unwrap_or_default());
        self.log(&ctx).await
    }
}

/// Middleware helper to extract client IP
pub fn extract_client_ip(headers: &HeaderMap, remote_addr: Option<std::net::SocketAddr>) -> Option<String> {
    // Check X-Forwarded-For first (for reverse proxy)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            return s.split(',').next().map(|s| s.trim().to_string());
        }
    }
    // Check X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(s) = real_ip.to_str() {
            return Some(s.to_string());
        }
    }
    // Fallback to socket address
    remote_addr.map(|a| a.ip().to_string())
}

/// Generate a request ID for tracing
pub fn generate_request_id() -> String {
    generate_token(16)
}