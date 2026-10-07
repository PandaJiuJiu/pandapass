use pandapass_core::audit::AuditService;
use pandapass_core::policy::PolicyEngine;
use pandapass_db::Db;
use crate::middleware::rate_limit::RateLimiter;
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
    pub master_key_cache: Arc<tokio::sync::RwLock<Option<pandapass_core::crypto::MasterKey>>>,
    /// Policy evaluation engine (M3)
    pub policy_engine: Arc<PolicyEngine>,
    /// Rate limiter for auth endpoints (login, register)
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(db: Db, audit: AuditService, config: Config) -> Self {
        let max_concurrent = config.max_concurrent_exec;
        Self {
            db,
            audit: Arc::new(audit),
            config: Arc::new(config.clone()),
            exec_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            master_key_cache: Arc::new(tokio::sync::RwLock::new(None)),
            policy_engine: Arc::new(PolicyEngine::new()),
            rate_limiter: Arc::new(RateLimiter::new(
                config.auth_rate_limit_max,
                config.auth_rate_limit_window_secs,
            )),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub public_url: String,
    pub db_url: String,
    pub session_ttl_days: i64,
    pub allowed_origins: Vec<String>,
    pub bootstrap_admin_email: Option<String>,
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
}

impl Config {
    pub fn from_env() -> Self {
        let listen_addr = std::env::var("PANDAPASS_LISTEN").unwrap_or_else(|_| "0.0.0.0:8233".to_string());
        let public_url = std::env::var("PANDAPASS_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://localhost:{}", listen_addr.rsplit(':').next().unwrap_or("8233")));
        let db_url = std::env::var("PANDAPASS_DB_URL")
            .unwrap_or_else(|_| "sqlite://data/pandapass.db?mode=rwc".to_string());
        let session_ttl_days = std::env::var("PANDAPASS_SESSION_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let allowed_origins = std::env::var("PANDAPASS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let bootstrap_admin_email = std::env::var("PANDAPASS_ADMIN_EMAIL").ok();
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
            Ok(path) if !path.is_empty() => std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string()),
            _ => std::env::var("PANDAPASS_SERVER_AGE_IDENTITY").ok().filter(|s| !s.is_empty()),
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

        Self {
            listen_addr,
            public_url,
            db_url,
            session_ttl_days,
            allowed_origins,
            bootstrap_admin_email,
            require_totp,
            allow_registration,
            max_concurrent_exec,
            command_timeout_secs,
            command_allowlist,
            cookie_secure,
            server_age_identity,
            auth_rate_limit_max,
            auth_rate_limit_window_secs,
        }
    }
}

/// Startup info logged on boot
pub struct StartupInfo {
    pub admin_bootstrapped: bool,
    pub user_count: i64,
}
