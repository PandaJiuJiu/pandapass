use pandapass_core::audit::AuditService;
use pandapass_db::Db;
use std::sync::Arc;
use std::time::Duration;
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
}

impl AppState {
    pub fn new(db: Db, audit: AuditService, config: Config) -> Self {
        let max_concurrent = config.max_concurrent_exec;
        Self {
            db,
            audit: Arc::new(audit),
            config: Arc::new(config),
            exec_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            master_key_cache: Arc::new(tokio::sync::RwLock::new(None)),
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
    pub max_concurrent_exec: usize,
    pub command_timeout_secs: u64,
    pub command_allowlist: Vec<String>,
    pub cookie_secure: bool,
    /// Header name for client-provided master key (age-decrypted)
    pub master_key_header_name: Option<String>,
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

        let master_key_header_name = std::env::var("PANDAPASS_MASTER_KEY_HEADER")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            listen_addr,
            public_url,
            db_url,
            session_ttl_days,
            allowed_origins,
            bootstrap_admin_email,
            require_totp,
            max_concurrent_exec,
            command_timeout_secs,
            command_allowlist,
            cookie_secure,
            master_key_header_name,
        }
    }
}

/// Startup info logged on boot
pub struct StartupInfo {
    pub admin_bootstrapped: bool,
    pub user_count: i64,
}
