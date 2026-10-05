use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::state::{AppState, Config};
use pandapass_server::{build_router, bootstrap};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

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

    // Audit entries go to SQLite, not memory — a restart must not lose the trail.
    let audit = pandapass_core::AuditService::new(Arc::new(DbAuditLogger::new(db.clone())));

    // Create app state
    let state = AppState::new(db, audit, config.clone());

    // Bootstrap admin user
    let startup = bootstrap(&state).await;
    if startup.admin_bootstrapped {
        info!("Admin user bootstrapped");
    }
    info!("Total users: {}", startup.user_count);

    // Build router
    let app = build_router(state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server stopped");
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
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
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