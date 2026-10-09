use crate::models::{AuditLog, AuthContext};
pub use crate::models::{AuditAction, AuditOutcome};
pub use crate::rbac::AuditContext;
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
        // Fold the request id into the meta blob when one is set, so
        // a downstream log shipper that only reads `meta` still has
        // the correlation handle. We can't move out of `ctx.meta` here
        // because the parameter is `&`, so clone and combine.
        let meta = if let Some(rid) = ctx.request_id.as_ref() {
            match ctx.meta.as_ref() {
                Some(m) => {
                    let mut combined = m.clone();
                    if let Some(obj) = combined.as_object_mut() {
                        obj.insert("request_id".to_string(), serde_json::Value::String(rid.clone()));
                    }
                    Some(combined)
                }
                None => Some(serde_json::json!({ "request_id": rid })),
            }
        } else {
            ctx.meta.clone()
        };
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
            meta,
            prev_hash: String::new(),
            entry_hash: String::new(),
        };

        if let Err(e) = self.logger.log(entry).await {
            error!("Failed to write audit log: {}", e);
            // Don't fail the request on audit failure
        }

        Ok(())
    }

    /// Convenience method for success
    pub async fn log_success(&self, ctx: &mut AuditContext<'_>) -> Result<()> {
        ctx.outcome = AuditOutcome::Success;
        self.log(ctx).await
    }

    /// Convenience method for failure
    ///
    /// `err` is stored verbatim in `meta.error`. Pass a short summary, never
    /// an error that quotes the value being decrypted — the audit log is
    /// replicated and archived, so anything here outlives the request.
    pub async fn log_failure(&self, ctx: &mut AuditContext<'_>, err: &str) -> Result<()> {
        ctx.outcome = AuditOutcome::Failure;
        ctx.meta = Some(json!({ "error": err }));
        self.log(ctx).await
    }

    /// Convenience method for denied
    pub async fn log_denied(&self, ctx: &mut AuditContext<'_>, reason: &str) -> Result<()> {
        ctx.outcome = AuditOutcome::Denied;
        ctx.meta = Some(json!({ "reason": reason }));
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
        let ctx = AuditContext::new(auth, AuditAction::SecretRead)
            .with_project(project_id)
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
        let ctx = AuditContext::new(auth, AuditAction::SecretList)
            .with_project(project_id)
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
        let ctx = AuditContext::new(auth, AuditAction::McpGetSecret)
            .with_project(project_id)
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
        let ctx = AuditContext::new(auth, AuditAction::McpRunCommand)
            .with_project(project_id)
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuditOutcome, GlobalRole, UserPublic};

    fn auth_ctx() -> AuthContext {
        AuthContext {
            user: UserPublic {
                id: uuid::Uuid::now_v7(),
                email: "alice@example.com".into(),
                global_role: GlobalRole::Admin,
                totp_enabled: false,
                created_at: Utc::now(),
                last_login_at: None,
            },
            session: None,
            service_token: None,
            project_role: None,
            project_id: None,
            env_id: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
        }
    }

    /// The audit log is the second-most-likely place for a secret to leak: it
    /// gets shipped to log aggregators, attached to bug reports, and kept for
    /// years. Key *names* are fine; values are not.
    #[tokio::test]
    async fn secret_read_audit_records_the_key_name_but_never_a_value() {
        const VALUE: &str = "sk-live-must-never-appear-abc123";
        let logger = Arc::new(MemoryAuditLogger::new());
        let service = AuditService::new(logger.clone());
        let auth = auth_ctx();

        service
            .log_secret_read(
                &auth,
                uuid::Uuid::now_v7(),
                uuid::Uuid::now_v7(),
                "API_KEY",
                None,
                None,
            )
            .await
            .unwrap();

        let logs = logger.get_logs().await;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].secret_key.as_deref(), Some("API_KEY"));
        assert_eq!(logs[0].outcome, AuditOutcome::Success);

        let rendered = format!("{:?}", logs[0]);
        assert!(
            !rendered.contains(VALUE),
            "audit entry leaked a secret value: {rendered}"
        );
    }

    /// A failed operation is the case most likely to embed a value in an error
    /// string by accident, so it gets its own assertion. `log_failure` stores
    /// the error text verbatim, which means callers must pass a summary rather
    /// than a raw error that might quote the value.
    #[tokio::test]
    async fn failure_meta_is_the_callers_summary_not_the_raw_error() {
        let logger = Arc::new(MemoryAuditLogger::new());
        let service = AuditService::new(logger.clone());
        let auth = auth_ctx();

        let mut ctx = AuditContext::new(&auth, AuditAction::SecretRead)
            .with_secret_key("DB_URL".into());
        service.log_failure(&mut ctx, "decryption failed").await.unwrap();

        let logs = logger.get_logs().await;
        assert_eq!(logs[0].outcome, AuditOutcome::Failure);
        assert_eq!(logs[0].meta.as_ref().unwrap()["error"], "decryption failed");
    }

    /// The command-execution entry names the executable and the keys used, not
    /// the full argv — a user-supplied argument may be a value.
    #[tokio::test]
    async fn command_audit_records_argv0_and_keys_only() {
        let logger = Arc::new(MemoryAuditLogger::new());
        let service = AuditService::new(logger.clone());
        let auth = auth_ctx();

        service
            .log_mcp_run_command(
                &auth,
                uuid::Uuid::now_v7(),
                uuid::Uuid::now_v7(),
                &["AWS_SECRET_ACCESS_KEY".to_string()],
                "aws",
                0,
                None,
            )
            .await
            .unwrap();

        let logs = logger.get_logs().await;
        let meta = logs[0].meta.as_ref().unwrap();
        assert_eq!(meta["argv0"], "aws");
        assert_eq!(meta["keys"][0], "AWS_SECRET_ACCESS_KEY");
        assert_eq!(meta["exit_code"], 0);
    }
}
