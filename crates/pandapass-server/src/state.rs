use crate::middleware::rate_limit::RateLimiter;
use pandapass_core::audit::AuditService;
use pandapass_core::policy::PolicyEngine;
use pandapass_db::Db;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub audit: Arc<AuditService>,
    pub config: Arc<Config>,
    /// Limits concurrent secret-decrypt + subprocess operations
    pub exec_semaphore: Arc<Semaphore>,
    /// Policy evaluation engine (M3)
    pub policy_engine: Arc<PolicyEngine>,
    /// Rate limiter for auth endpoints (login, register)
    pub rate_limiter: Arc<RateLimiter>,
    /// HMAC key for the audit tamper-evidence chain. Derived from the
    /// server's age identity; empty means the chain is disabled (legacy).
    pub audit_chain_key: Arc<Vec<u8>>,
}

impl AppState {
    pub fn new(db: Db, audit: AuditService, config: Config) -> Self {
        let max_concurrent = config.max_concurrent_exec;
        Self {
            db,
            audit: Arc::new(audit),
            config: Arc::new(config.clone()),
            exec_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            policy_engine: Arc::new(PolicyEngine::new()),
            rate_limiter: Arc::new(RateLimiter::new(
                config.auth_rate_limit_max,
                config.auth_rate_limit_window_secs,
            )),
            audit_chain_key: Arc::new(Vec::new()),
        }
    }

    /// Set the audit chain key (called from main after deriving it from the
    /// server's age identity — the key must never live in the database the
    /// chain protects, so it is injected rather than read from config).
    pub fn with_audit_chain_key(mut self, key: Vec<u8>) -> Self {
        self.audit_chain_key = Arc::new(key);
        self
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub public_url: String,
    pub db_url: String,
    pub session_ttl_days: i64,
    /// Idle timeout for sessions in seconds. `None` means "no idle timeout";
    /// only the absolute TTL applies. When set, a session that has been
    /// unused for longer than this is refused on the next request.
    pub session_idle_timeout_secs: Option<i64>,
    pub allowed_origins: Vec<String>,
    pub bootstrap_admin_email: Option<String>,
    /// Must be `1`/`true` for bootstrap to run even when
    /// `PANDAPASS_ADMIN_EMAIL` is set. Guards against accidentally
    /// creating an admin account just by leaving an env var around.
    pub bootstrap_enabled: bool,
    pub require_totp: bool,
    /// Whether `/auth/register` accepts new signups after the bootstrap admin.
    /// Off by default — a secrets vault should not hand accounts to strangers.
    pub allow_registration: bool,
    pub max_concurrent_exec: usize,
    pub command_timeout_secs: u64,
    pub command_allowlist: Vec<String>,
    pub cookie_secure: bool,
    /// The server's own age identity (`AGE-SECRET-KEY-1...`), used to unwrap
    /// user envelopes. Configure via `PANDAPASS_SERVER_AGE_IDENTITY` or
    /// `PANDAPASS_SERVER_AGE_IDENTITY_FILE`.
    pub server_age_identity: Option<String>,
    /// Rate limiter config
    pub auth_rate_limit_max: u32,
    pub auth_rate_limit_window_secs: u64,
    /// Optional dynamic-credential proxy listener, e.g. "127.0.0.1:5433".
    /// `None` (the default) disables the proxy entirely.
    pub dynamic_proxy_listen: Option<String>,
    /// Upstream PostgreSQL address the dynamic-credential proxy forwards to.
    pub dynamic_proxy_upstream: Option<String>,
    /// Comma-separated CIDR ranges of trusted reverse proxies. X-Forwarded-For
    /// and X-Real-IP are only honoured when the immediate peer is in this list.
    /// Empty (the default) means XFF is ignored and only the socket peer is
    /// trusted — which is what you want in a deployment without a proxy.
    pub trusted_proxy_cidrs: Vec<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let listen_addr =
            std::env::var("PANDAPASS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8233".to_string());
        let public_url = std::env::var("PANDAPASS_PUBLIC_URL").unwrap_or_else(|_| {
            format!(
                "http://localhost:{}",
                listen_addr.rsplit(':').next().unwrap_or("8233")
            )
        });
        let db_url = std::env::var("PANDAPASS_DB_URL")
            .unwrap_or_else(|_| "sqlite://data/pandapass.db?mode=rwc".to_string());
        let session_ttl_days = std::env::var("PANDAPASS_SESSION_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let session_idle_timeout_secs = std::env::var("PANDAPASS_SESSION_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok());
        let allowed_origins = std::env::var("PANDAPASS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let bootstrap_enabled = std::env::var("PANDAPASS_BOOTSTRAP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let bootstrap_admin_email = if bootstrap_enabled {
            std::env::var("PANDAPASS_ADMIN_EMAIL").ok()
        } else {
            None
        };
        let require_totp = std::env::var("PANDAPASS_REQUIRE_TOTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let allow_registration = std::env::var("PANDAPASS_ALLOW_REGISTRATION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let max_concurrent_exec = std::env::var("PANDAPASS_MAX_CONCURRENT_EXEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let command_timeout_secs = std::env::var("PANDAPASS_COMMAND_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let command_allowlist = std::env::var("PANDAPASS_COMMAND_ALLOWLIST")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let cookie_secure = std::env::var("PANDAPASS_COOKIE_SECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(public_url.starts_with("https://"));

        // The server's age identity: inline value, or read from a file so the
        // private key never appears in the process environment.
        let server_age_identity = match std::env::var("PANDAPASS_SERVER_AGE_IDENTITY_FILE") {
            Ok(path) if !path.is_empty() => std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string()),
            _ => std::env::var("PANDAPASS_SERVER_AGE_IDENTITY")
                .ok()
                .filter(|s| !s.is_empty()),
        };

        // Rate limiter: default 5 attempts per 15 minutes per IP
        let auth_rate_limit_max = std::env::var("PANDAPASS_AUTH_RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let auth_rate_limit_window_secs = std::env::var("PANDAPASS_AUTH_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900);

        let dynamic_proxy_listen = std::env::var("PANDAPASS_DYNAMIC_PROXY_LISTEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let dynamic_proxy_upstream = std::env::var("PANDAPASS_DYNAMIC_PROXY_UPSTREAM")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let trusted_proxy_cidrs = std::env::var("PANDAPASS_TRUSTED_PROXY_CIDRS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            listen_addr,
            public_url,
            db_url,
            session_ttl_days,
            session_idle_timeout_secs,
            allowed_origins,
            bootstrap_admin_email,
            bootstrap_enabled,
            require_totp,
            allow_registration,
            max_concurrent_exec,
            command_timeout_secs,
            command_allowlist,
            cookie_secure,
            server_age_identity,
            auth_rate_limit_max,
            auth_rate_limit_window_secs,
            dynamic_proxy_listen,
            dynamic_proxy_upstream,
            trusted_proxy_cidrs,
        }
    }
}

/// Startup info logged on boot
pub struct StartupInfo {
    pub admin_bootstrapped: bool,
    pub user_count: i64,
}
