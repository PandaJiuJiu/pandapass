use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::state::{AppState, Config};
use pandapass_server::{build_router, bootstrap};
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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