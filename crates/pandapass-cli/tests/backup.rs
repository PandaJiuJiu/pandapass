//! Backup/restore integration tests: drive the real CLI command handlers
//! against a live server, then restore the snapshot to a fresh database and
//! verify the data survives. This exercises the full path: admin HTTP fetch,
//! age sealing, payload verification, atomic restore.

use std::path::PathBuf;
use std::sync::Arc;

use pandapass_cli::client::{ApiClient, CliConfig};
use pandapass_cli::commands::run_command;
use pandapass_cli::commands::{BackupArgs, Command, RestoreArgs};
use pandapass_core::crypto::AgeIdentity;
use pandapass_core::{AuditLogger, AuditService};
use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::build_router;
use pandapass_server::state::{AppState, Config};

/// Start a real HTTP server on an ephemeral port and return its base URL plus
/// a handle whose drop shuts the server down.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("pandapass-cli-backup-{}", uuid::Uuid::now_v7()));
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
        command_allowlist: vec![],
        cookie_secure: false,
        server_age_identity: Some(identity.as_str().to_string()),
        auth_rate_limit_max: 100, // high for tests
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
    age_identity_path: &PathBuf,
) -> (ApiClient, CliConfig) {
    let api = ApiClient::new(base_url.to_string(), false).expect("api client");
    api.set_auth_token(Some(token.to_string())).await;
    let config = CliConfig {
        server_url: base_url.to_string(),
        auth_token: Some(token.to_string()),
        default_project: None,
        default_env: None,
        age_identity_file: Some(age_identity_path.clone()),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_then_restore_round_trip() {
    let (base_url, _server) = start_server().await;

    // Operator's age keypair: the backup file is sealed to this key.
    let operator = AgeIdentity::generate();
    let operator_pub = operator.public_key().expect("public key");

    // Seed the server with an account, project, env, and secrets.
    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    let token = register_and_login(&setup, "alice@example.com", operator_pub.as_str()).await;
    setup.set_auth_token(Some(token.clone())).await;

    let project = pandapass_core::models::CreateProjectRequest {
        name: "myapp".into(),
        slug: "myapp".into(),
        description: None,
    };
    setup
        .create_project(&project)
        .await
        .expect("create project");
    setup
        .set_secret("myapp", "prod", "API_KEY", "value-1")
        .await
        .expect("set API_KEY");
    setup
        .set_secret("myapp", "prod", "DB_URL", "postgres://localhost/app")
        .await
        .expect("set DB_URL");

    // Write the operator's age identity to a file the CLI can read.
    let dir = std::env::temp_dir().join(format!("pandapass-backup-cli-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("make cli dir");
    let age_identity_path = dir.join("age.key");
    std::fs::write(&age_identity_path, operator.expose()).expect("write age identity");

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // ── backup ─────────────────────────────────────────────────────────────
    let backup_file = dir.join("backup.age");
    run_command(
        &api,
        &mut config,
        Command::Backup(BackupArgs {
            out: backup_file.clone(),
            recipient: None,
            server_age_identity: None,
            audit_chain_key: None,
            raw: false,
        }),
    )
    .await
    .expect("backup command");

    assert!(backup_file.exists(), "backup file written");
    let backup_bytes = std::fs::read(&backup_file).expect("read backup");
    let backup_str = String::from_utf8_lossy(&backup_bytes);
    assert!(
        backup_str.contains("-----BEGIN AGE ENCRYPTED FILE-----"),
        "backup should be age-encrypted"
    );

    // The backup decrypts to a payload with the db snapshot.
    let ciphertext = String::from_utf8(backup_bytes).expect("utf8 backup");
    let plaintext =
        pandapass_core::crypto::age_decrypt_file(&ciphertext, &operator).expect("decrypt backup");
    let payload: pandapass_cli::commands::BackupPayload =
        serde_json::from_str(&plaintext).expect("parse payload");
    assert_eq!(payload.format, "pandapass-backup-v1");
    assert!(payload.db.size_bytes > 0, "db snapshot present");
    assert!(
        payload.server_age_identity.is_none(),
        "no age identity supplied"
    );

    // ── restore ─────────────────────────────────────────────────────────────
    let restored_db = dir.join("restored.db");
    run_command(
        &api,
        &mut config,
        Command::Restore(RestoreArgs {
            input: backup_file.clone(),
            db_path: restored_db.clone(),
            age_identity_path: None,
            audit_chain_key_path: None,
            yes: true,
        }),
    )
    .await
    .expect("restore command");

    assert!(restored_db.exists(), "restored db written");

    // The restored database contains the secrets.
    let restored_url = format!("sqlite://{}?mode=rwc", restored_db.display());
    let restored = connect(&restored_url).await.expect("connect restored");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secrets")
        .fetch_one(&restored)
        .await
        .expect("count secrets");
    assert!(
        count >= 2,
        "restored db should contain the secrets, got {count}"
    );
    restored.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_includes_server_age_identity_when_supplied() {
    let (base_url, _server) = start_server().await;

    let operator = AgeIdentity::generate();
    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    let token = register_and_login(
        &setup,
        "bob@example.com",
        operator.public_key().unwrap().as_str(),
    )
    .await;
    setup.set_auth_token(Some(token.clone())).await;

    let dir = std::env::temp_dir().join(format!("pandapass-backup-age-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("make dir");
    let age_identity_path = dir.join("age.key");
    std::fs::write(&age_identity_path, operator.expose()).expect("write age identity");
    let server_age_path = dir.join("server-age.key");
    let server_age = AgeIdentity::generate();
    std::fs::write(&server_age_path, server_age.expose()).expect("write server age");
    let chain_key_path = dir.join("chain.key");
    std::fs::write(
        &chain_key_path,
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    )
    .expect("write chain key");

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    let backup_file = dir.join("full.age");
    run_command(
        &api,
        &mut config,
        Command::Backup(BackupArgs {
            out: backup_file.clone(),
            recipient: None,
            server_age_identity: Some(server_age_path.clone()),
            audit_chain_key: Some(chain_key_path.clone()),
            raw: false,
        }),
    )
    .await
    .expect("backup command");

    let ciphertext = std::fs::read_to_string(&backup_file).expect("read backup");
    let plaintext =
        pandapass_core::crypto::age_decrypt_file(&ciphertext, &operator).expect("decrypt backup");
    let payload: pandapass_cli::commands::BackupPayload =
        serde_json::from_str(&plaintext).expect("parse payload");
    assert_eq!(
        payload.server_age_identity.as_deref(),
        Some(server_age.expose()),
        "backup should include the server age identity"
    );
    assert_eq!(
        payload.audit_chain_key.as_deref(),
        Some("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"),
        "backup should include the audit chain key"
    );

    // Restore with the age identity target.
    let restored_db = dir.join("restored.db");
    let restored_age = dir.join("restored-server-age.key");
    let restored_chain = dir.join("restored-chain.key");
    run_command(
        &api,
        &mut config,
        Command::Restore(RestoreArgs {
            input: backup_file.clone(),
            db_path: restored_db.clone(),
            age_identity_path: Some(restored_age.clone()),
            audit_chain_key_path: Some(restored_chain.clone()),
            yes: true,
        }),
    )
    .await
    .expect("restore command");

    assert_eq!(
        std::fs::read_to_string(&restored_age)
            .expect("read restored age")
            .trim(),
        server_age.expose(),
        "restored age identity should match"
    );
    assert_eq!(
        std::fs::read_to_string(&restored_chain)
            .expect("read restored chain")
            .trim(),
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "restored chain key should match"
    );
}
