use pandapass_core::audit::MemoryAuditLogger;
use pandapass_db::{connect, migrate};
use pandapass_server::{build_router, bootstrap, AppState, Config};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Config::from_env();
    info!("Starting PandaPass server on {}", config.listen_addr);

    // Connect to database
    let db = connect(&config.db_url).await?;
    migrate(&db).await?;

    // Setup audit logger
    let audit_logger = Arc::new(MemoryAuditLogger::new());
    let audit = pandapass_core::AuditService::new(audit_logger);

    // Create app state
    let state = AppState::new(db, audit, config.clone());

    // Bootstrap admin user
    let info = bootstrap(&state).await;
    if info.admin_bootstrapped {
        info!("Admin user bootstrapped");
    }
    info!("Total users: {}", info.user_count);

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