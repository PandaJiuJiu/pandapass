use anyhow::Context;
use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::dynamic_proxy;
use pandapass_server::dynamic_proxy_redis;
use pandapass_server::state::{AppState, Config};
use pandapass_server::{bootstrap, build_router};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::net::TcpListener;
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

    // `--init` generates the server's age identity on first boot, before any
    // config is read, then falls through into the normal server startup so a
    // fresh container comes up ready to serve. It lives here rather than in a
    // compose entrypoint script because the runtime image is distroless and
    // has no shell to run one.
    //
    // `--init-only` is the same generation step but exits immediately after
    // writing the identity. Local tooling (run.sh, the Playwright e2e setup)
    // uses it to prepare a data directory without starting a server.
    if std::env::args().any(|a| a == "--init-only") {
        init_storage()?;
        return Ok(());
    }
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

    // Startup self-check: if the server age identity is loaded from a file,
    // verify the file's mode is 0600 (or 0400). A world-readable private
    // key is worse than no encryption at all.
    if let Some(path) = std::env::var("PANDAPASS_SERVER_AGE_IDENTITY_FILE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        if let Ok(meta) = std::fs::metadata(&path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    anyhow::bail!(
                        "{path:?} is readable by group/other (mode {:o}). \
                         Refusing to start. chmod 600 or 400 the file and try again.",
                        mode
                    );
                }
            }
            if !meta.is_file() {
                anyhow::bail!("{path:?} is not a regular file");
            }
        }
    }

    // Connect to database
    let db = connect(&config.db_url).await?;
    migrate(&db).await?;

    // Clone for background cleanup task (must clone before moving into AppState)
    let cleanup_db = db.clone();

    // The chain key can come from one of three sources, in priority order:
    //   1. PANDAPASS_AUDIT_CHAIN_KEY_FILE — a hex-encoded 32-byte key
    //      independent of the server's age identity. Recommended path: it
    //      survives age-key rotation and can be backed up on its own.
    //   2. The server's age identity (historical fallback). A SHA-256 of
    //      the identity string is used; rotating the age key therefore
    //      also invalidates the audit chain.
    //   3. None — chain is disabled.
    let (audit_logger, chain_key): (Arc<dyn pandapass_core::AuditLogger>, Vec<u8>) =
        if let Some(path) = &config.audit_chain_key_file {
            let hex_str = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("audit chain key file {path:?}: {e}"))?;
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| anyhow::anyhow!("audit chain key file is not valid hex: {e}"))?;
            if bytes.is_empty() {
                (
                    Arc::new(DbAuditLogger::new(db.clone()))
                        as Arc<dyn pandapass_core::AuditLogger>,
                    Vec::new(),
                )
            } else {
                let key = bytes.clone();
                (
                    Arc::new(DbAuditLogger::with_chain_key(db.clone(), key.clone()))
                        as Arc<dyn pandapass_core::AuditLogger>,
                    key,
                )
            }
        } else if let Some(identity) = &config.server_age_identity {
            use sha2::{Digest, Sha256};
            let key =
                Sha256::digest(format!("pandapass-audit-chain:{identity}").as_bytes()).to_vec();
            (
                Arc::new(DbAuditLogger::with_chain_key(db.clone(), key.clone()))
                    as Arc<dyn pandapass_core::AuditLogger>,
                key,
            )
        } else {
            (
                Arc::new(DbAuditLogger::new(db.clone())) as Arc<dyn pandapass_core::AuditLogger>,
                Vec::new(),
            )
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

    // Start the Redis dynamic credential proxy if configured. It shares the
    // database with the HTTP API, so the TTL and revocation state the proxy
    // enforces at the handshake is the same state the API exposes.
    if let (Some(listen), Some(upstream)) = (
        &config.dynamic_proxy_redis_listen,
        &config.dynamic_proxy_redis_upstream,
    ) {
        let listen_addr = listen.parse().map_err(|_| {
            anyhow::anyhow!("invalid PANDAPASS_DYNAMIC_PROXY_REDIS_LISTEN: {listen}")
        })?;
        let upstream_addr = upstream.parse().map_err(|_| {
            anyhow::anyhow!("invalid PANDAPASS_DYNAMIC_PROXY_REDIS_UPSTREAM: {upstream}")
        })?;

        // Require server_age_identity for the proxy to decrypt credential passwords.
        let server_age_identity = match config.server_age_identity.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            Some(_) => {
                anyhow::bail!(
                    "PANDAPASS_SERVER_AGE_IDENTITY is set but empty; the Redis dynamic proxy cannot decrypt credentials without a valid age identity"
                );
            }
            None => {
                anyhow::bail!(
                    "PANDAPASS_SERVER_AGE_IDENTITY must be set when PANDAPASS_DYNAMIC_PROXY_REDIS_LISTEN/UPSTREAM are configured; the Redis dynamic proxy needs it to decrypt credential passwords"
                );
            }
        };

        // Bind first so a port conflict fails fast at startup.
        let listener = TcpListener::bind(listen_addr)
            .await
            .context("bind Redis dynamic proxy listener")?;
        info!(
            "Dynamic credential Redis proxy listening on {listen_addr} (upstream {upstream_addr})"
        );

        let redis_proxy_config = dynamic_proxy_redis::RedisProxyConfig {
            listen_addr,
            db: state.db.clone(),
            upstream_addr,
            server_age_identity,
        };
        tokio::spawn(dynamic_proxy_redis::run_redis_proxy(
            listener,
            redis_proxy_config,
        ));
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

    // TLS listener setup
    let use_tls = config.tls_cert_file.is_some()
        && config.tls_key_file.is_some()
        && config.tls_ca_file.is_some();

    if use_tls {
        let cert_file = config.tls_cert_file.as_deref().unwrap_or_default();
        let key_file = config.tls_key_file.as_deref().unwrap_or_default();
        let ca_file = config.tls_ca_file.as_deref().unwrap_or_default();
        // Wrap the already-bound listener so the port is reserved exactly once.
        let tls_listener = pandapass_server::tls::TlsListener::from_listener(
            listener,
            cert_file,
            key_file,
            ca_file,
        )
        .await?;

        // `tap_io` keeps the SocketAddr connect-info implementation that axum
        // provides for plain TcpListener, so the client-IP middleware works
        // unchanged over TLS.
        use axum::serve::ListenerExt;
        let tls_listener = tls_listener.tap_io(|_| {});

        axum::serve(
            tls_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    } else {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

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
        return init_tls_storage();
    };
    let path = std::path::Path::new(&path);

    if path.exists() {
        return init_tls_storage();
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
    init_tls_storage()
}

/// Generate the TLS CA and server leaf certificates if TLS is configured and
/// the files do not exist yet. Idempotent: existing files are left alone so a
/// restart never rotates the pinned CA out from under clients.
fn init_tls_storage() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let cert_file = std::env::var("PANDAPASS_TLS_CERT_FILE")
        .ok()
        .filter(|p| !p.is_empty());
    let key_file = std::env::var("PANDAPASS_TLS_KEY_FILE")
        .ok()
        .filter(|p| !p.is_empty());
    let ca_file = std::env::var("PANDAPASS_TLS_CA_FILE")
        .ok()
        .filter(|p| !p.is_empty());

    // TLS is optional; only provision when all three are configured.
    let (Some(cert_file), Some(key_file), Some(ca_file)) = (cert_file, key_file, ca_file) else {
        return Ok(());
    };

    let cert_path = std::path::Path::new(&cert_file);
    let key_path = std::path::Path::new(&key_file);
    let ca_path = std::path::Path::new(&ca_file);

    // All present → nothing to do. Any single missing file → regenerate all
    // three so they never go out of sync (a leaf signed by a different CA
    // than the one served at /api/v1/ca.pem would break every pinned client).
    if cert_path.exists() && key_path.exists() && ca_path.exists() {
        return Ok(());
    }

    if let Some(dir) = cert_path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    // SAN: derive hostnames from PANDAPASS_PUBLIC_URL, falling back to
    // localhost when unset or unparsable.
    let public_url = std::env::var("PANDAPASS_PUBLIC_URL").unwrap_or_default();
    let hostnames = url_hostnames(&public_url);
    let not_before = chrono::Utc::now() - chrono::Duration::days(1);
    let not_after = chrono::Utc::now() + chrono::Duration::days(3650);

    let (ca_pem, leaf_pem, key_pem) = pandapass_core::pki::generate_server_tls_pair(
        &hostnames,
        not_before,
        not_after,
    )
    .map_err(|e| anyhow::anyhow!("failed to generate server TLS pair: {e}"))?;

    std::fs::write(ca_path, ca_pem.as_bytes())?;
    std::fs::set_permissions(ca_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(cert_path, leaf_pem.as_bytes())?;
    std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(key_path, key_pem.as_bytes())?;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;

    info!(
        "Generated server TLS CA + leaf for {hostnames:?} (CA: {}, cert: {}, key: {})",
        ca_path.display(),
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

/// Extract hostname(s) from a URL for use as TLS Subject Alternative Names.
/// Returns `["localhost"]` when the URL is missing or unparsable.
fn url_hostnames(public_url: &str) -> Vec<String> {
    let Some(rest) = public_url.split_once("://") else {
        return vec!["localhost".to_string()];
    };
    let host_port = rest.1.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_port
        .rsplit_once(':')
        .map(|(h, p)| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                h.to_string()
            } else {
                host_port.to_string() // IPv6 literal without port
            }
        })
        .unwrap_or_else(|| host_port.to_string());
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        vec!["localhost".to_string()]
    } else {
        vec![host.to_string()]
    }
}

/// Probe `/api/v1/health` on the configured listen address and exit non-zero if
/// it does not answer. Intended for Docker `HEALTHCHECK`, not for humans.
///
/// When TLS is enabled (all three PANDAPASS_TLS_* files configured), the
/// health check uses HTTPS with the server's CA for verification. Otherwise
/// it uses a raw TCP socket for plain HTTP.
async fn health_check() -> anyhow::Result<()> {
    let config = Config::from_env();
    let (bind_host, port) = config
        .listen_addr
        .rsplit_once(':')
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

    // If TLS is configured, use HTTPS with CA pinning. Otherwise use raw TCP.
    let use_tls = config.tls_cert_file.is_some()
        && config.tls_key_file.is_some()
        && config.tls_ca_file.is_some();

    if use_tls {
        // Read CA for verification
        let ca_pem = std::fs::read_to_string(config.tls_ca_file.as_ref().unwrap())
            .context("read TLS CA file for health check")?;
        let cert = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;

        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let url = format!("https://{host}:{port}/api/v1/health");
        let resp = client.get(&url).send().await?;

        anyhow::ensure!(
            resp.status().is_success(),
            "health endpoint returned: {}",
            resp.status()
        );
        Ok(())
    } else {
        // Original raw TCP implementation for plain HTTP
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
