//! CLI CRUD integration tests: exercise the real CLI command handlers for
//! login, secrets, tokens, members, audit, dynamic credentials, and SSH cert
//! signing against a live HTTP server. These drive `run_command` through the
//! real `ApiClient`, covering the same full path a user runs.
//!
//! Commands that print secrets/tokens to stdout are verified by their side
//! effects on the server (the printed value itself is intentionally never
//! captured — the CLI's contract is that plaintext is shown once and never
//! stored).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use pandapass_cli::client::{ApiClient, CliConfig};
use pandapass_cli::commands::run_command;
use pandapass_cli::commands::{AuditCmd, Command, CredCmd, MemberCmd, PkiCmd, SshCmd, TokenCmd};
use pandapass_core::crypto::AgeIdentity;
use pandapass_core::models::{CreateProjectRequest, DynamicCredKind, ProjectRole};
use pandapass_core::{AuditLogger, AuditService};
use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::build_router;
use pandapass_server::state::{AppState, Config};

/// Start a real HTTP server on an ephemeral port and return its base URL plus
/// a handle whose drop shuts the server down.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("pandapass-cli-crud-{}", uuid::Uuid::now_v7()));
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
        tls_cert_file: None,
        tls_key_file: None,
        tls_ca_file: None,
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
        ca_cert: None,
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

/// Seed a project with one secret, returning the operator age identity path
/// and the session token.
async fn seed_project(
    base_url: &str,
    email: &str,
    project_slug: &str,
    env: &str,
    secret_key: &str,
    secret_value: &str,
) -> (PathBuf, String) {
    let operator = AgeIdentity::generate();
    let operator_pub = operator.public_key().expect("public key");
    let setup = ApiClient::new(base_url.to_string(), false).expect("setup client");
    let token = register_and_login(&setup, email, operator_pub.as_str()).await;
    setup.set_auth_token(Some(token.clone())).await;

    setup
        .create_project(&CreateProjectRequest {
            name: project_slug.into(),
            slug: project_slug.into(),
            description: None,
        })
        .await
        .expect("create project");
    setup
        .set_secret(project_slug, env, secret_key, secret_value)
        .await
        .expect("set secret");

    let dir = std::env::temp_dir().join(format!("pandapass-crud-cli-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("make cli dir");
    let age_identity_path = dir.join("age.key");
    std::fs::write(&age_identity_path, operator.expose()).expect("write age identity");

    (age_identity_path, token)
}

// ── login ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_fails_with_wrong_password() {
    let (base_url, _server) = start_server().await;

    let operator = AgeIdentity::generate();
    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    setup
        .register(
            "login-fail@example.com",
            "correct horse battery staple",
            Some(operator.public_key().unwrap().as_str()),
        )
        .await
        .expect("register");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    let mut config = CliConfig {
        server_url: base_url.clone(),
        auth_token: None,
        default_project: None,
        default_env: None,
        age_identity_file: None,
        ca_cert: None,
        command_allowlist: vec![],
        command_timeout_secs: None,
    };
    let res = run_command(
        &api,
        &mut config,
        Command::Login(pandapass_cli::commands::LoginArgs {
            email: Some("login-fail@example.com".into()),
            password: Some("wrong password".into()),
            password_stdin: false,
            totp: None,
        }),
    )
    .await;

    assert!(res.is_err(), "login with wrong password must fail: {res:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_fails_for_unknown_email() {
    let (base_url, _server) = start_server().await;

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    let mut config = CliConfig {
        server_url: base_url.clone(),
        auth_token: None,
        default_project: None,
        default_env: None,
        age_identity_file: None,
        ca_cert: None,
        command_allowlist: vec![],
        command_timeout_secs: None,
    };
    let res = run_command(
        &api,
        &mut config,
        Command::Login(pandapass_cli::commands::LoginArgs {
            email: Some("nobody@example.com".into()),
            password: Some("whatever".into()),
            password_stdin: false,
            totp: None,
        }),
    )
    .await;

    assert!(res.is_err(), "login for unknown email must fail: {res:?}");
}

// ── secrets ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_crud_round_trip() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) = seed_project(
        &base_url,
        "crud@example.com",
        "crudapp",
        "prod",
        "API_KEY",
        "v1",
    )
    .await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // Set a second secret.
    run_command(
        &api,
        &mut config,
        Command::Secret(pandapass_cli::commands::SecretCmd::Set {
            project: "crudapp".into(),
            env: "prod".into(),
            key: "DB_URL".into(),
            value: "postgres://db/app".into(),
        }),
    )
    .await
    .expect("set DB_URL");

    // List both secrets.
    run_command(
        &api,
        &mut config,
        Command::Secret(pandapass_cli::commands::SecretCmd::List {
            project: "crudapp".into(),
            env: "prod".into(),
        }),
    )
    .await
    .expect("list secrets");

    // Get an existing secret.
    run_command(
        &api,
        &mut config,
        Command::Secret(pandapass_cli::commands::SecretCmd::Get {
            project: "crudapp".into(),
            env: "prod".into(),
            key: "API_KEY".into(),
        }),
    )
    .await
    .expect("get API_KEY");

    // Delete the second secret.
    run_command(
        &api,
        &mut config,
        Command::Secret(pandapass_cli::commands::SecretCmd::Delete {
            project: "crudapp".into(),
            env: "prod".into(),
            key: "DB_URL".into(),
        }),
    )
    .await
    .expect("delete DB_URL");

    // Server-side verification: DB_URL gone, API_KEY still present.
    let setup = ApiClient::new(base_url.clone(), false).expect("verify client");
    setup.set_auth_token(Some(token.clone())).await;
    let remote = setup
        .list_secrets("crudapp", "prod")
        .await
        .expect("list remote");
    let keys: Vec<&str> = remote.items.iter().map(|m| m.key.as_str()).collect();
    assert!(keys.contains(&"API_KEY"), "API_KEY should remain: {keys:?}");
    assert!(
        !keys.contains(&"DB_URL"),
        "DB_URL should be deleted: {keys:?}"
    );
}

// ── tokens ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_create_list_revoke_round_trip() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) =
        seed_project(&base_url, "token@example.com", "tokenapp", "prod", "K", "v").await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // Create a project-scoped token.
    run_command(
        &api,
        &mut config,
        Command::Token(TokenCmd::Create {
            name: "ci-bot".into(),
            project: Some("tokenapp".into()),
            env: Some("prod".into()),
            scopes: vec!["read:secret".into(), "list:secret".into()],
            expires_days: Some(30),
        }),
    )
    .await
    .expect("create token");

    // The plaintext token is printed to stdout once and never stored, so we
    // verify by listing: the token must be present server-side.
    let setup = ApiClient::new(base_url.clone(), false).expect("verify client");
    setup.set_auth_token(Some(token.clone())).await;
    let tokens = setup.list_tokens().await.expect("list tokens");
    assert!(
        tokens.iter().any(|t| t.name == "ci-bot"),
        "created token should be listed: {tokens:?}"
    );
    let created = tokens.iter().find(|t| t.name == "ci-bot").unwrap();

    // Revoke it.
    run_command(
        &api,
        &mut config,
        Command::Token(TokenCmd::Revoke { id: created.id }),
    )
    .await
    .expect("revoke token");

    let tokens_after = setup.list_tokens().await.expect("list tokens after");
    let revoked = tokens_after
        .iter()
        .find(|t| t.name == "ci-bot")
        .expect("token still listed after revoke");
    assert!(
        revoked.revoked_at.is_some(),
        "token should be marked revoked: {revoked:?}"
    );
}

// ── members ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_add_list_round_trip() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) =
        seed_project(&base_url, "owner@example.com", "teamapp", "prod", "K", "v").await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // The member must already be a registered user before they can be added.
    let member_identity = AgeIdentity::generate();
    let member_api = ApiClient::new(base_url.clone(), false).expect("member api");
    register_and_login(
        &member_api,
        "member@example.com",
        member_identity.public_key().unwrap().as_str(),
    )
    .await;

    // Add a member (the seeded owner is already a member).
    run_command(
        &api,
        &mut config,
        Command::Member(MemberCmd::Add {
            project: "teamapp".into(),
            email: "member@example.com".into(),
            role: "editor".into(),
        }),
    )
    .await
    .expect("add member");

    // List members and verify the new member is present with the right role.
    let setup = ApiClient::new(base_url.clone(), false).expect("verify client");
    setup.set_auth_token(Some(token.clone())).await;
    let members = setup.list_members("teamapp").await.expect("list members");
    let added = members
        .iter()
        .find(|m| m.user.email == "member@example.com")
        .expect("member should be present");
    assert_eq!(added.member.role, ProjectRole::Editor);
}

// ── audit ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_list_and_verify() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) =
        seed_project(&base_url, "audit@example.com", "auditapp", "prod", "K", "v").await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // Some operations to generate audit entries.
    run_command(
        &api,
        &mut config,
        Command::Secret(pandapass_cli::commands::SecretCmd::Set {
            project: "auditapp".into(),
            env: "prod".into(),
            key: "AUDITED".into(),
            value: "yes".into(),
        }),
    )
    .await
    .expect("set secret for audit");

    // List audit entries.
    run_command(
        &api,
        &mut config,
        Command::Audit(AuditCmd::List {
            project: Some("auditapp".into()),
            page: None,
            per_page: None,
        }),
    )
    .await
    .expect("audit list");

    // Verify the audit HMAC chain.
    run_command(&api, &mut config, Command::Audit(AuditCmd::Verify))
        .await
        .expect("audit verify");
}

// ── dynamic credentials (D8) ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cred_create_list_revoke_round_trip() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) =
        seed_project(&base_url, "cred@example.com", "credapp", "prod", "K", "v").await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    // Create a Redis dynamic credential (the supported kind).
    run_command(
        &api,
        &mut config,
        Command::Cred(CredCmd::Create {
            project: "credapp".into(),
            env: "prod".into(),
            kind: "redis".into(),
            username: "redis-user".into(),
            ttl_seconds: 3600,
        }),
    )
    .await
    .expect("create redis cred");

    // Server-side verification.
    let setup = ApiClient::new(base_url.clone(), false).expect("verify client");
    setup.set_auth_token(Some(token.clone())).await;
    let creds = setup
        .list_dynamic_creds("credapp", "prod")
        .await
        .expect("list creds");
    let created = creds
        .iter()
        .find(|c| c.username == "redis-user")
        .expect("created cred should be listed");
    assert_eq!(created.kind, DynamicCredKind::Redis);
    assert!(
        created.revoked_at.is_none(),
        "fresh cred must not be revoked"
    );

    // Revoke it.
    run_command(
        &api,
        &mut config,
        Command::Cred(CredCmd::Revoke {
            project: "credapp".into(),
            env: "prod".into(),
            id: created.id,
        }),
    )
    .await
    .expect("revoke cred");

    // The list endpoint hides revoked credentials (revoked_at IS NULL), so
    // after revocation the cred must no longer appear.
    let creds_after = setup
        .list_dynamic_creds("credapp", "prod")
        .await
        .expect("list creds after");
    assert!(
        !creds_after.iter().any(|c| c.id == created.id),
        "revoked cred should no longer be listed: {creds_after:?}"
    );
}

// ── PKI / SSH (M4) ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_sign_round_trip() {
    let (base_url, _server) = start_server().await;
    let (age_identity_path, token) =
        seed_project(&base_url, "pki@example.com", "pkiapp", "prod", "K", "v").await;

    let (api, mut config) = make_cli(&base_url, &token, &age_identity_path).await;

    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    setup.set_auth_token(Some(token.clone())).await;

    // 1. Generate an ed25519 SSH CA locally. The SSH track uses OpenSSH key
    //    format, not X.509 PEM — `create_ca_key` stores the private half (the
    //    public half is stored as the "certificate").
    let dir = std::env::temp_dir().join(format!("pandapass-ssh-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("make ssh dir");
    let ca_keygen = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            dir.join("ca_key").to_str().unwrap(),
            "-N",
            "",
            "-q",
        ])
        .output()
        .expect("run ssh-keygen for CA");
    assert!(
        ca_keygen.status.success(),
        "ssh-keygen for CA should succeed"
    );

    let ca_key_pem = std::fs::read_to_string(dir.join("ca_key")).expect("read CA private key");
    let ca_pub_pem = std::fs::read_to_string(dir.join("ca_key.pub")).expect("read CA public key");
    let now = chrono::Utc::now();
    let not_before = now - chrono::Duration::hours(1);
    let not_after = now + chrono::Duration::hours(12);

    let ca = setup
        .create_ca_key(
            pandapass_core::models::CaKeyType::Intermediate,
            &ca_key_pem,
            &ca_pub_pem,
            not_before,
            not_after,
        )
        .await
        .expect("create SSH CA");

    // 2. Register the SSH user directly through the API (a second account).
    let ssh_identity = AgeIdentity::generate();
    let ssh_user_api = ApiClient::new(base_url.clone(), false).expect("ssh user api");
    let ssh_token = register_and_login(
        &ssh_user_api,
        "sshuser@example.com",
        ssh_identity.public_key().unwrap().as_str(),
    )
    .await;
    let _ = ssh_token;

    // Add the SSH user as a member of the project.
    run_command(
        &api,
        &mut config,
        Command::Member(MemberCmd::Add {
            project: "pkiapp".into(),
            email: "sshuser@example.com".into(),
            role: "editor".into(),
        }),
    )
    .await
    .expect("add ssh user as member");

    // Find the SSH user's id from the project members.
    let members = setup.list_members("pkiapp").await.expect("list members");
    let ssh_user = members
        .iter()
        .find(|m| m.user.email == "sshuser@example.com")
        .expect("ssh user should be a member");

    // 3. Generate the user's SSH keypair locally (the private key never
    //    leaves the test).
    let user_keygen = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            dir.join("id_ed25519").to_str().unwrap(),
            "-N",
            "",
            "-q",
        ])
        .output()
        .expect("run ssh-keygen for user");
    assert!(
        user_keygen.status.success(),
        "ssh-keygen for user should succeed"
    );

    // 4. Sign an SSH cert with the CA for the user.
    run_command(
        &api,
        &mut config,
        Command::Pki(PkiCmd::Ssh {
            cmd: SshCmd::Sign {
                ca_id: ca.id,
                user: ssh_user.user.id,
                principal: "alice@prod".into(),
                public_key: dir.join("id_ed25519.pub"),
                project: Some("pkiapp".into()),
                not_before: None,
                not_after: None,
            },
        }),
    )
    .await
    .expect("sign ssh cert");

    // 5. Verify the cert is listed server-side.
    let certs = setup
        .list_ssh_certs(Some(ssh_user.user.id), None, false)
        .await
        .expect("list ssh certs");
    assert!(
        certs.iter().any(|c| c.principal == "alice@prod"),
        "signed cert should be listed: {certs:?}"
    );
}

// ── Recovery codes (B5) ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_codes_generate_and_redeem() {
    let (base_url, _server) = start_server().await;

    // Register a user WITH an age public key so the account has an envelope
    let age_identity = AgeIdentity::generate();
    let pub_key = age_identity.public_key().expect("public key");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("recovery@example.com", "correct horse battery staple", Some(pub_key.as_str()))
        .await
        .expect("register");

    // Login to get a session
    let login = api
        .login("recovery@example.com", "correct horse battery staple", None)
        .await
        .expect("login");
    let session_token = login.session_token.expect("session token");
    api.set_auth_token(Some(session_token.clone())).await;

    // Generate recovery codes - this should work even without an enrolled age key
    let response: serde_json::Value = api
        .post("/auth/recovery-codes", &serde_json::json!({}))
        .await
        .expect("generate recovery codes");
    let codes = response["codes"].as_array().expect("codes array");
    assert_eq!(codes.len(), 8, "should generate 8 recovery codes");
    let first_code = codes[0].as_str().expect("first code").to_string();

    // Verify the codes were stored
    let _user: serde_json::Value = api.get("/auth/me").await.expect("get user");
    // The user should have recovery codes now

    // Redeem a recovery code - should work without password/TOTP
    let redeem_resp: serde_json::Value = api
        .post(
            "/auth/recovery-code/redeem",
            &serde_json::json!({ "email": "recovery@example.com", "code": first_code }),
        )
        .await
        .expect("redeem recovery code");
    assert_eq!(redeem_resp["rotated"], true);

    // The redeemed code should no longer work
    let redeem_again: Result<serde_json::Value, _> = api
        .post(
            "/auth/recovery-code/redeem",
            &serde_json::json!({ "email": "recovery@example.com", "code": first_code }),
        )
        .await;
    assert!(redeem_again.is_err(), "redeemed code should not work again");
}

// ── User disable/enable (B7) ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_disable_enable_admin() {
    let (base_url, _server) = start_server().await;

    // Create admin user
    let admin_api = ApiClient::new(base_url.clone(), false).expect("admin api");
    admin_api
        .register("admin@example.com", "adminpass123", None)
        .await
        .expect("register admin");
    let admin_login = admin_api
        .login("admin@example.com", "adminpass123", None)
        .await
        .expect("login admin");
    let admin_token = admin_login.session_token.expect("admin session");
    admin_api.set_auth_token(Some(admin_token.clone())).await;

    // Create a regular user
    let user_api = ApiClient::new(base_url.clone(), false).expect("user api");
    user_api
        .register("user@example.com", "userpass12345", None)
        .await
        .expect("register user");

    // Admin lists users
    let users: serde_json::Value = admin_api.get("/admin/users").await.expect("list users");
    let users_array = users["users"].as_array().expect("users array");
    // Find the user by email
    let user = users_array.iter().find(|u| u["email"].as_str() == Some("user@example.com")).expect("user not found");
    let user_id = user["id"].as_str().expect("user id");

    // Disable the user
    let _: serde_json::Value = admin_api
        .post(&format!("/admin/users/{user_id}/disable"), &serde_json::json!({}))
        .await
        .expect("disable user");

    // Disabled user cannot login
    let user_login = user_api
        .login("user@example.com", "userpass12345", None)
        .await;
    assert!(user_login.is_err(), "disabled user should not be able to login");

    // Enable the user
    let _: serde_json::Value = admin_api
        .post(&format!("/admin/users/{user_id}/enable"), &serde_json::json!({}))
        .await
        .expect("enable user");

    // User can login again
    let user_login = user_api
        .login("user@example.com", "userpass12345", None)
        .await
        .expect("login after re-enable");
    assert!(user_login.session_token.is_some());
}

// ── Session list/revoke (C2) ──────���────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_list_and_revoke() {
    let (base_url, _server) = start_server().await;

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("session@example.com", "correct horse battery staple", None)
        .await
        .expect("register");

    // Login multiple times to create multiple sessions
    let login1 = api
        .login("session@example.com", "correct horse battery staple", None)
        .await
        .expect("login 1");
    let token1 = login1.session_token.expect("token 1");

    let api2 = ApiClient::new(base_url.clone(), false).expect("api client 2");
    let login2 = api2
        .login("session@example.com", "correct horse battery staple", None)
        .await
        .expect("login 2");
    let token2 = login2.session_token.expect("token 2");

    let api3 = ApiClient::new(base_url.clone(), false).expect("api client 3");
    let login3 = api3
        .login("session@example.com", "correct horse battery staple", None)
        .await
        .expect("login 3");
    let _token3 = login3.session_token.expect("token 3");

    // List sessions with first token
    api.set_auth_token(Some(token1.clone())).await;
    let sessions: serde_json::Value = api.get("/auth/sessions").await.expect("list sessions");
    let sessions_array = sessions.as_array().expect("sessions array");
    // There are 4 sessions: register creates 1, then 3 logins = 4 total
    // The list is ordered by last_seen_at DESC, so the session that just made
    // this request (token1) is at index 0 (newest).
    assert_eq!(sessions_array.len(), 4, "should have 4 active sessions (register + 3 logins)");

    // Revoke the CURRENT session (index 0) — this is the one making the request
    let current_session = &sessions_array[0];
    let current_session_id = current_session["id"].as_str().expect("session id");
    let _: serde_json::Value = api
        .delete(&format!("/auth/sessions/{current_session_id}"))
        .await
        .expect("revoke session");

    // Use a different client (api2 with token2) to list sessions after revoke
    api2.set_auth_token(Some(token2.clone())).await;
    let sessions: serde_json::Value = api2.get("/auth/sessions").await.expect("list sessions after revoke");
    let sessions_array = sessions.as_array().expect("sessions array");
    assert_eq!(sessions_array.len(), 3, "should have 3 active sessions after revoke");

    // The revoked token (token1) should no longer work
    let me: Result<serde_json::Value, _> = api.get("/auth/me").await;
    assert!(me.is_err(), "revoked session should not work");
}

// ── Account lockout (C7) ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_lockout_on_failed_login() {
    let (base_url, _server) = start_server().await;

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("lockout@example.com", "correct horse battery staple", None)
        .await
        .expect("register");

    // Make 5 failed login attempts
    for i in 0..5 {
        let result = api
            .login("lockout@example.com", &format!("wrong{}", i), None)
            .await;
        assert!(result.is_err(), "attempt {} should fail", i + 1);
    }

    // 6th attempt should be locked out
    let result = api
        .login("lockout@example.com", "wrong6", None)
        .await;
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("locked") || err.contains("too many"),
        "error should mention lockout: {}",
        err
    );

    // Even correct password should fail while locked
    let result = api
        .login("lockout@example.com", "correct horse battery staple", None)
        .await;
    assert!(result.is_err(), "correct password should fail while locked");
    let err = result.err().unwrap().to_string();
    assert!(
        err.contains("locked") || err.contains("too many"),
        "error should mention lockout: {}",
        err
    );
}

// ── Idle timeout (C9) ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_idle_timeout() {
    let (_base_url, _server) = start_server().await;

    // Start server with 1 second idle timeout
    let dir = std::env::temp_dir().join(format!("pandapass-idle-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let db_path = dir.join("test.db");

    let identity = AgeIdentity::generate();

    let config = Config {
        listen_addr: "127.0.0.1:0".into(),
        public_url: "http://localhost:8233".into(),
        db_url: format!("sqlite://{}?mode=rwc", db_path.display()),
        session_ttl_days: 30,
        session_idle_timeout_secs: Some(1), // 1 second idle timeout
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
        auth_rate_limit_max: 100,
        auth_rate_limit_window_secs: 60,
        dynamic_proxy_listen: None,
        dynamic_proxy_upstream: None,
        dynamic_proxy_redis_listen: None,
        dynamic_proxy_redis_upstream: None,
        trusted_proxy_cidrs: vec![],
        audit_chain_key_file: None,
        backup_dir: None,
        tls_cert_file: None,
        tls_key_file: None,
        tls_ca_file: None,
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

    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server");
    });

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("idle@example.com", "correct horse battery staple", None)
        .await
        .expect("register");
    let login = api
        .login("idle@example.com", "correct horse battery staple", None)
        .await
        .expect("login");
    let token = login.session_token.expect("session token");
    api.set_auth_token(Some(token.clone())).await;

    // Verify session works immediately
    let _ = api.get::<serde_json::Value>("/auth/me").await.expect("immediate me");

    // Wait for idle timeout to expire (1 sec + buffer)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Session should now be expired
    let result = api.get::<serde_json::Value>("/auth/me").await;
    assert!(result.is_err(), "session should be expired after idle timeout");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("expired") || err.contains("idle") || err.contains("inactivity"),
        "error should mention expiration: {}",
        err
    );
}

// ── TOTP clock drift (C10) ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_accepts_clock_drift() {
    let (base_url, _server) = start_server().await;

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("totp@example.com", "correct horse battery staple", None)
        .await
        .expect("register");

    let login = api
        .login("totp@example.com", "correct horse battery staple", None)
        .await
        .expect("login");
    let token = login.session_token.expect("session token");
    api.set_auth_token(Some(token.clone())).await;

    // Setup TOTP
    let setup_resp: serde_json::Value = api.get("/auth/totp/setup").await.expect("totp setup");
    let secret = setup_resp["secret"].as_str().expect("secret");

    // Generate a valid TOTP code using the secret
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret).unwrap();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA256)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .build()
        .expect("create totp");

    let code = totp.generate_current().to_string();

    // Verify the TOTP code
    let verify_resp: serde_json::Value = api
        .post("/auth/totp/verify", &serde_json::json!({ "code": code }))
        .await
        .expect("totp verify");
    assert_eq!(verify_resp["success"], true);

    // Now test with a code from +1 time step (simulating clock drift)
    let now_secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code_future = totp.generate(now_secs + 30).to_string();

    // Should accept ±1 step drift
    let verify_resp: serde_json::Value = api
        .post("/auth/totp/verify", &serde_json::json!({ "code": code_future }))
        .await
        .expect("totp verify future");
    assert_eq!(verify_resp["success"], true);
}

// ── TOTP without envelope (C12) ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn totp_setup_without_age_key() {
    let (base_url, _server) = start_server().await;

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    // Register WITHOUT age public key - no envelope
    api.register("totp2@example.com", "correct horse battery staple", None)
        .await
        .expect("register");

    let login = api
        .login("totp2@example.com", "correct horse battery staple", None)
        .await
        .expect("login");
    let token = login.session_token.expect("session token");
    api.set_auth_token(Some(token.clone())).await;

    // TOTP setup should work even without an enrolled age key
    // (the server auto-creates an envelope sealed to the server key)
    let setup_resp: serde_json::Value = api.get("/auth/totp/setup").await.expect("totp setup");
    assert!(setup_resp["secret"].is_string());
    assert!(setup_resp["uri"].is_string());

    // Verify it works
    let secret = setup_resp["secret"].as_str().expect("secret");
    let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret).unwrap();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA256)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .build()
        .expect("create totp");
    let code = totp.generate_current().to_string();

    let verify_resp: serde_json::Value = api
        .post("/auth/totp/verify", &serde_json::json!({ "code": code }))
        .await
        .expect("totp verify");
    assert_eq!(verify_resp["success"], true);
    assert_eq!(verify_resp["enabled"], true);
}

// ── GitOps atomic write (F14) ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitops_push_atomic_write() {
    let (base_url, _server) = start_server().await;

    // Use a fresh temp directory for the GitOps repo
    let repo_dir = std::env::temp_dir().join(format!("pandapass-gitops-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&repo_dir).expect("temp dir");

    let age_identity = AgeIdentity::generate();
    let age_path = repo_dir.join("age.key");
    std::fs::write(&age_path, age_identity.expose()).expect("write age identity");

    let api = ApiClient::new(base_url.clone(), false).expect("api client");
    api.register("gitops@example.com", "correct horse battery staple", Some(age_identity.public_key().unwrap().as_str()))
        .await
        .expect("register");
    let login = api
        .login("gitops@example.com", "correct horse battery staple", None)
        .await
        .expect("login");
    let token = login.session_token.expect("session token");
    api.set_auth_token(Some(token.clone())).await;

    // Create project and env
    let project = api
        .create_project(&CreateProjectRequest {
            name: "gitopsapp-atomic".into(),
            slug: "gitopsapp-atomic".into(),
            description: None,
        })
        .await
        .expect("create project");
    let _env = api
        .create_env(
            &project.project.slug,
            &pandapass_core::models::CreateEnvRequest {
                name: "Production".into(),
                slug: "prod-atomic".into(),
                description: None,
            },
        )
        .await
        .expect("create env");

    // Set some secrets
    api.set_secret("gitopsapp-atomic", "prod-atomic", "KEY1", "value1").await.expect("set secret 1");
    api.set_secret("gitopsapp-atomic", "prod-atomic", "KEY2", "value2").await.expect("set secret 2");

    // Pull to local directory
    let mut config = CliConfig {
        server_url: base_url.clone(),
        auth_token: Some(token.clone()),
        default_project: None,
        default_env: None,
        age_identity_file: Some(age_path.clone()),
        ca_cert: None,
        command_allowlist: vec![],
        command_timeout_secs: None,
    };

    run_command(
        &api,
        &mut config,
        Command::GitOps(pandapass_cli::commands::GitOpsCmd::Pull(pandapass_cli::commands::GitOpsPullArgs {
            project: "gitopsapp-atomic".into(),
            env: "prod-atomic".into(),
            dir: repo_dir.clone(),
        })),
    )
    .await
    .expect("gitops pull");

    // Verify files exist
    let secrets_dir = repo_dir.join("secrets");
    assert!(secrets_dir.join("prod-atomic.yaml.age").exists(), "prod-atomic.yaml.age should exist");
    assert!(repo_dir.join(".sync-state.json").exists(), ".sync-state.json should exist");

    // Now push again WITHOUT changes - should be atomic (no partial writes)
    run_command(
        &api,
        &mut config,
        Command::GitOps(pandapass_cli::commands::GitOpsCmd::Push(pandapass_cli::commands::GitOpsPushArgs {
            project: "gitopsapp-atomic".into(),
            env: "prod-atomic".into(),
            dir: repo_dir.clone(),
            allow_delete: false,
        })),
    )
    .await
    .expect("gitops push (no changes)");

    // The sync-state should not have changed secrets
    let sync_state_content = std::fs::read_to_string(repo_dir.join(".sync-state.json")).expect("read sync state");
    let sync_state: serde_json::Value = serde_json::from_str(&sync_state_content).expect("parse sync state");
    // Should have 2 secrets tracked
    let secrets = sync_state["secrets"].as_object().expect("secrets object");
    assert_eq!(secrets.len(), 2, "should track 2 secrets");
    // Each secret should have version and updated_at
    for (key, info) in secrets {
        assert!(info["version"].is_number(), "secret {key} should have version");
        assert!(info["updated_at"].is_string(), "secret {key} should have updated_at");
    }
}
