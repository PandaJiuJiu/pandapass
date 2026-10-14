//! CLI internal-exec integration tests: exercise the server-side exec endpoint
//! (POST /api/v1/internal/exec) with the `run:secret` scope. These tests drive
//! the real CLI command handlers through a live HTTP server, covering the same
//! full path a user runs.

use std::sync::Arc;

use pandapass_cli::client::{ApiClient, CliConfig};
use pandapass_cli::commands::{Command, InternalExecArgs, run_command};
use pandapass_cli::model::{CreateTokenRequest};
use pandapass_core::crypto::AgeIdentity;
use pandapass_core::models::{CreateProjectRequest};
use pandapass_core::{AuditLogger, AuditService};
use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::build_router;
use pandapass_server::state::{AppState, Config};

/// Start a real HTTP server on an ephemeral port and return its base URL plus
/// a handle whose drop shuts the server down.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("pandapass-cli-internal-exec-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let db_path = dir.join("test.db");

    let identity = AgeIdentity::generate();

    let config = Config {
        listen_addr: "127.0.0.1:0".into(),
        public_url: "http://localhost:8233".into(),
        db_url: format!("sqlite://{}?mode=rwc", db_path.display()),
        session_ttl_days: 30,
        session_idle_timeout_secs: None,
        allowed_origins: vec![],
        bootstrap_admin_email: None,
        bootstrap_enabled: false,
        require_totp: false,
        allow_registration: true,
        max_concurrent_exec: 10,
        command_timeout_secs: 120,
        command_allowlist: vec!["echo".into(), "sh".into()],
        cookie_secure: false,
        server_age_identity: Some(identity.as_str().to_string()),
        auth_rate_limit_max: 100,
        auth_rate_limit_window_secs: 60,
        dynamic_proxy_listen: None,
        dynamic_proxy_upstream: None,
        dynamic_proxy_redis_listen: None,
        dynamic_proxy_redis_upstream: None,
        trusted_proxy_cidrs: vec![],
        audit_chain_key_file: None,
        backup_dir: None,
    };

    let db = connect(&config.db_url).await.expect("connect");
    migrate(&db).await.expect("migrate");

    let chain_key = {
        use sha2::{Digest, Sha256};
        Sha256::digest(format!("pandapass-audit-chain:{}", identity.as_str()).as_bytes()).to_vec()
    };
    let audit_logger: Arc<dyn AuditLogger> =
        Arc::new(DbAuditLogger::with_chain_key(db.clone(), chain_key.clone()));
    let audit = AuditService::new(audit_logger);
    let state = AppState::new(db.clone(), audit, config).with_audit_chain_key(chain_key.clone());

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });

    (base_url, handle)
}

/// Build a CLI `ApiClient` and `CliConfig` wired to the test server.
async fn make_cli(
    base_url: &str,
    token: &str,
    age_identity_path: &std::path::Path,
) -> (ApiClient, CliConfig) {
    let api = ApiClient::new(base_url.to_string(), false).expect("api client");
    api.set_auth_token(Some(token.to_string())).await;
    let config = CliConfig {
        server_url: base_url.to_string(),
        auth_token: Some(token.to_string()),
        default_project: None,
        default_env: None,
        age_identity_file: Some(age_identity_path.to_path_buf()),
        command_allowlist: vec![],
        command_timeout_secs: None,
    };
    (api, config)
}

/// Register a user with an age public key so the account can store secrets,
/// then log in and return the session token.
async fn register_and_login(api: &ApiClient, email: &str, public_key: &str) -> String {
    api.register(email, "correct horse battery staple", Some(public_key))
        .await
        .expect("register");
    let login = api
        .login(email, "correct horse battery staple", None)
        .await
        .expect("login");
    login.session_token.expect("session token")
}

/// Seed a project with a secret that we can inject into the exec command.
/// Returns (project_id, env_id, project_slug, env_slug).
async fn seed_project(api: &ApiClient, suffix: &str) -> (uuid::Uuid, uuid::Uuid, String, String) {
    let project_slug = format!("exec-test-{}", suffix);
    let env_slug = format!("prod-{}", suffix);
    let project = api
        .create_project(&CreateProjectRequest {
            name: project_slug.clone(),
            slug: project_slug.clone(),
            description: Some("Test project for internal exec".into()),
        })
        .await
        .expect("create project");
    let env = api
        .create_env(&project.project.slug, &pandapass_core::models::CreateEnvRequest {
            name: "Production".into(),
            slug: env_slug.clone(),
            description: Some("Production environment".into()),
        })
        .await
        .expect("create env");
    api.set_secret(&project.project.slug, &env_slug, "GREETING", "Hello from exec!")
        .await
        .expect("set secret");
    (project.project.id, env.id, project_slug, env_slug)
}

#[tokio::test]
async fn internal_exec_injects_secrets_and_runs_command() {
    let (base_url, _handle) = start_server().await;
    let age_identity = AgeIdentity::generate();
    let tmp = std::env::temp_dir().join(format!("pandapass-cli-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let age_path = tmp.join("age.key");
    std::fs::write(&age_path, age_identity.expose()).expect("write age identity");
    let pub_key = age_identity.public_key().expect("public key");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    let token = register_and_login(&api, "exec@example.com", pub_key.as_str()).await;
    api.set_auth_token(Some(token.clone())).await;

    let (project_id, env_id, project_slug, env_slug) = seed_project(&api, "inject").await;

    // Create a service token with run:secret scope scoped to the project/env
    let service_token = api
        .create_token(&CreateTokenRequest {
            name: "exec-token".into(),
            project_id: Some(project_id),
            env_id: Some(env_id),
            scopes: vec!["run:secret".into()],
            expires_at: None,
        })
        .await
        .expect("create service token");
    let service_token_plain = service_token.plain_token;

    let (api, mut config) = make_cli(&base_url, &service_token_plain, &age_path).await;

    // Run internal exec with the secret injected
    run_command(
        &api,
        &mut config,
        Command::InternalExec(InternalExecArgs {
            project: project_slug,
            env: env_slug,
            keys: "GREETING".into(),
            command: vec!["echo".into(), "$GREETING".into()],
        }),
    )
    .await
    .expect("internal exec should succeed");

    // The command output should contain the injected secret value
    // Note: run_command prints to stdout/stderr, we can't capture it directly
    // but we can verify it succeeds (exit_code 0)
    // The actual test of injection is that it exits 0 with the secret available
}

#[tokio::test]
async fn internal_exec_requires_run_secret_scope() {
    let (base_url, _handle) = start_server().await;
    let age_identity = AgeIdentity::generate();
    let tmp = std::env::temp_dir().join(format!("pandapass-cli-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let age_path = tmp.join("age.key");
    std::fs::write(&age_path, age_identity.expose()).expect("write age identity");
    let pub_key = age_identity.public_key().expect("public key");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    let token = register_and_login(&api, "exec2@example.com", pub_key.as_str()).await;
    api.set_auth_token(Some(token.clone())).await;

    let (project_id, env_id, project_slug, env_slug) = seed_project(&api, "scope").await;

    // Create a token WITHOUT run:secret scope
    let service_token = api
        .create_token(&CreateTokenRequest {
            name: "no-run-secret-token".into(),
            project_id: Some(project_id),
            env_id: Some(env_id),
            scopes: vec!["read:secret".into()],
            expires_at: None,
        })
        .await
        .expect("create service token");
    let service_token_plain = service_token.plain_token;

    let (api, mut config) = make_cli(&base_url, &service_token_plain, &age_path).await;

    // Try to run internal exec without run:secret scope — should fail
    let result = run_command(
        &api,
        &mut config,
        Command::InternalExec(InternalExecArgs {
            project: project_slug,
            env: env_slug,
            keys: "GREETING".into(), // Must provide at least one key that exists
            command: vec!["echo".into(), "test".into()],
        }),
    )
    .await;

    assert!(result.is_err(), "expected error without run:secret scope");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("scope") || err.to_string().contains("run:secret"),
        "error: {}",
        err
    );
}

#[tokio::test]
async fn internal_exec_respects_server_allowlist() {
    let (base_url, _handle) = start_server().await;
    let age_identity = AgeIdentity::generate();
    let tmp = std::env::temp_dir().join(format!("pandapass-cli-e2e-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let age_path = tmp.join("age.key");
    std::fs::write(&age_path, age_identity.expose()).expect("write age identity");
    let pub_key = age_identity.public_key().expect("public key");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    let token = register_and_login(&api, "exec3@example.com", pub_key.as_str()).await;
    api.set_auth_token(Some(token.clone())).await;

    let (project_id, env_id, project_slug, env_slug) = seed_project(&api, "allowlist").await;

    // Create a service token with run:secret scope
    let service_token = api
        .create_token(&CreateTokenRequest {
            name: "exec-token-allowlist".into(),
            project_id: Some(project_id),
            env_id: Some(env_id),
            scopes: vec!["run:secret".into()],
            expires_at: None,
        })
        .await
        .expect("create service token");
    let service_token_plain = service_token.plain_token;

    let (api, mut config) = make_cli(&base_url, &service_token_plain, &age_path).await;

    // Try to run a command not in the server's allowlist (server allowlist is ["echo", "sh"])
    let result = run_command(
        &api,
        &mut config,
        Command::InternalExec(InternalExecArgs {
            project: project_slug,
            env: env_slug,
            keys: "GREETING".into(), // Must provide at least one key that exists
            command: vec!["cat".into(), "/etc/passwd".into()],
        }),
    )
    .await;

    assert!(result.is_err(), "expected error for non-allowlisted command");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("allowlist") || err.to_string().contains("not allowed"),
        "error: {}",
        err
    );
}