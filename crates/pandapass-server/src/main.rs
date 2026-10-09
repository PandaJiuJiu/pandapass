use anyhow::Context;
use pandapass_db::{DbAuditLogger, connect, migrate};
use pandapass_server::dynamic_proxy;
use pandapass_server::state::{AppState, Config};
use pandapass_server::{bootstrap, build_router};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `anyhow`'s Display for a context chain includes the source, which
            // is what tells an operator whether this is a bad path or a bad
            // password. Nothing here quotes secret material: the only inputs
            // are env vars for paths and bind addresses.
            eprintln!("pandapass-server: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    // `--health-check` exists because the runtime image is distroless: it has no
    // shell and no curl, so the conventional `CMD curl -f ...` healthcheck
    // cannot work. The binary checks itself, which also means the check uses
    // the same HTTP client and TLS settings the server actually runs with.
    if std::env::args().any(|a| a == "--health-check") {
        return health_check().await;
    }

    // `--init` generates the server's age identity on first boot, before any
    // config is read. It lives here rather than in a compose entrypoint script
    // because the runtime image is distroless and has no shell to run one.
    if std::env::args().any(|a| a == "--init") {
        init_storage()?;
    }

    // Initialize tracing
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Config::from_env();
    info!("Starting PandaPass server on {}", config.listen_addr);

    if config.server_age_identity.is_none() {
        warn!(
            "PANDAPASS_SERVER_AGE_IDENTITY is not set: TOTP setup and server-side \
             decryption of secret values will be unavailable until it is configured."
        );
    }

    // Connect to database
    let db = connect(&config.db_url).await?;
    migrate(&db).await?;

    // Clone for background cleanup task (must clone before moving into AppState)
    let cleanup_db = db.clone();

    // Audit entries go to SQLite, not memory — a restart must not lose the trail.
    // The chain key is derived from the server's age identity so the HMAC key
    // never lives in the database the log protects.
    let (audit_logger, chain_key) = match &config.server_age_identity {
        Some(identity) => {
            use sha2::{Digest, Sha256};
            let key = Sha256::digest(format!("pandapass-audit-chain:{identity}").as_bytes());
            (
                Arc::new(DbAuditLogger::with_chain_key(db.clone(), key.to_vec()))
                    as Arc<dyn pandapass_core::AuditLogger>,
                key.to_vec(),
            )
        }
        None => (
            Arc::new(DbAuditLogger::new(db.clone())) as Arc<dyn pandapass_core::AuditLogger>,
            Vec::new(),
        ),
    };
    let audit = pandapass_core::AuditService::new(audit_logger);

    // Create app state (consumes db)
    let state = AppState::new(db, audit, config.clone()).with_audit_chain_key(chain_key);

    // Bootstrap admin user
    let startup = bootstrap(&state).await;
    if startup.admin_bootstrapped {
        info!("Admin user bootstrapped");
    }
    info!("Total users: {}", startup.user_count);

    // Load policy engine with enabled policies and bindings
    {
        use pandapass_db::list_policies;
        use pandapass_db::list_policy_bindings;
        let policies = list_policies(&state.db, true).await?;
        for policy in &policies {
            if let Err(e) = state.policy_engine.upsert_policy(policy).await {
                warn!("Failed to load policy {}: {}", policy.id, e);
            }
        }
        let bindings = list_policy_bindings(&state.db, None, None).await?;
        state.policy_engine.rebuild_bindings(&bindings).await;
        info!(
            "Policy engine loaded: {} policies, {} bindings",
            policies.len(),
            bindings.len()
        );
    }

    // Build router
    let app = build_router(state.clone());

    // Start the dynamic credential proxy if configured. It shares the
    // database with the HTTP API, so the TTL and revocation state the proxy
    // enforces at the handshake is the same state the API exposes.
    if let (Some(listen), Some(upstream)) =
        (&config.dynamic_proxy_listen, &config.dynamic_proxy_upstream)
    {
        let listen_addr = listen
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid PANDAPASS_DYNAMIC_PROXY_LISTEN: {listen}"))?;
        let upstream_addr = upstream
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid PANDAPASS_DYNAMIC_PROXY_UPSTREAM: {upstream}"))?;

        // Require server_age_identity for the proxy to decrypt credential passwords.
        let server_age_identity = match config.server_age_identity.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            Some(_) => {
                anyhow::bail!(
                    "PANDAPASS_SERVER_AGE_IDENTITY is set but empty; the dynamic proxy cannot decrypt credentials without a valid age identity"
                );
            }
            None => {
                anyhow::bail!(
                    "PANDAPASS_SERVER_AGE_IDENTITY must be set when PANDAPASS_DYNAMIC_PROXY_LISTEN/UPSTREAM are configured; the dynamic proxy needs it to decrypt credential passwords"
                );
            }
        };

        // Bind first so a port conflict fails fast at startup.
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("bind dynamic proxy listener")?;
        info!("Dynamic credential proxy listening on {listen_addr} (upstream {upstream_addr})");

        let proxy_config = dynamic_proxy::ProxyConfig {
            listen_addr,
            db: state.db.clone(),
            upstream_addr,
            server_age_identity,
        };
        tokio::spawn(dynamic_proxy::run_proxy(listener, proxy_config));
    }

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);

    // Background cleanup: expired sessions and dynamic credentials. A short
    // interval is safe because both queries are single indexed DELETEs; the
    // dynamic-cred sweep is what makes an expired credential actually stop
    // working rather than merely looking expired in the UI.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match pandapass_db::cleanup_expired_sessions(&cleanup_db).await {
                Ok(n) if n > 0 => info!("Cleaned up {} expired sessions", n),
                Err(e) => warn!("Session cleanup failed: {}", e),
                _ => {}
            }
            match pandapass_db::cleanup_expired_dynamic_creds(&cleanup_db).await {
                Ok(n) if n > 0 => info!("Cleaned up {} expired dynamic credentials", n),
                Err(e) => warn!("Dynamic credential cleanup failed: {}", e),
                _ => {}
            }
        }
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server stopped");
    Ok(())
}

/// Create the server's age identity if it does not exist yet.
///
/// Runs before the config is read so it works even on a first boot where
/// `PANDAPASS_SERVER_AGE_IDENTITY` points at a file that has not been written.
/// Idempotent: an existing key is left alone, because regenerating it would
/// make every envelope already sealed to this server unopenable, with no
/// recovery for anyone including the operator.
fn init_storage() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::var("PANDAPASS_SERVER_AGE_IDENTITY_FILE")
        .ok()
        .filter(|p| !p.is_empty());

    let Some(path) = path else {
        // An inline identity was supplied, or there is no storage to manage.
        return Ok(());
    };
    let path = std::path::Path::new(&path);

    if path.exists() {
        return Ok(());
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let identity = pandapass_core::crypto::AgeIdentity::generate();
    // Create with the final permissions rather than writing then chmod-ing:
    // there is no window in which the key is readable by anyone else.
    std::fs::write(path, identity.as_str().as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    info!(
        "Generated a server age identity at {}. BACK THIS UP: without it, secrets \
         sealed to this server cannot be unwrapped by anyone, including you.",
        path.display()
    );
    Ok(())
}

/// Probe `/api/v1/health` on the configured listen address and exit non-zero if
/// it does not answer. Intended for Docker `HEALTHCHECK`, not for humans.
///
/// Written against a raw TCP socket rather than an HTTP client so the server
/// keeps no client dependency it would otherwise never use — the request is
/// three fixed lines against a known endpoint.
async fn health_check() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let config = Config::from_env();
    let (bind_host, port) = config
        .listen_addr
        .rsplit_once(':')
        .map(|(h, p)| (h, p))
        .unwrap_or(("0.0.0.0", "8233"));

    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("listen address has no valid port: {}", config.listen_addr))?;

    // `0.0.0.0` is a bind address, not a destination; probe the loopback.
    let host = if bind_host.is_empty() || bind_host == "0.0.0.0" {
        "127.0.0.1"
    } else {
        bind_host
    };

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to {host}:{port}"))??;

    stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    anyhow::ensure!(
        response.starts_with("HTTP/1.1 2"),
        "health endpoint returned: {}",
        response.lines().next().unwrap_or("<empty>")
    );
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
    }
}
