//! GitOps integration tests: pull/push/diff against a real server.
//!
//! Unlike the server's own `tests/api.rs` (which drives `build_router` in
//! process), these tests bind a real TCP port and drive the actual CLI command
//! handlers (`run_command`) through the real `ApiClient`. That exercises the
//! full path a user runs: HTTP transport, auth middleware, policy engine, DB
//! soft-delete recovery, local age decryption, and sync-state persistence.

use std::path::PathBuf;
use std::sync::Arc;

use pandapass_cli::client::{ApiClient, CliConfig};
use pandapass_cli::commands::run_command;
use pandapass_cli::commands::{Command, GitOpsCmd, GitOpsPullArgs, GitOpsPushArgs};
use pandapass_core::crypto::AgeIdentity;
use pandapass_core::{AuditLogger, AuditService};
use pandapass_db::{connect, migrate, DbAuditLogger};
use pandapass_server::build_router;
use pandapass_server::state::{AppState, Config};

/// Start a real HTTP server on an ephemeral port and return its base URL plus
/// a handle whose drop shuts the server down.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("pandapass-cli-gitops-{}", uuid::Uuid::now_v7()));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitops_pull_diff_push_round_trip() {
    let (base_url, _server) = start_server().await;

    // Operator's age keypair: the server seals secrets so only this key can
    // open them. The CLI needs the private half for local decryption.
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

    // `create_project` auto-creates dev/staging/prod environments; use prod.
    setup
        .set_secret("myapp", "prod", "API_KEY", "value-1")
        .await
        .expect("set API_KEY");
    setup
        .set_secret("myapp", "prod", "DB_URL", "postgres://localhost/app")
        .await
        .expect("set DB_URL");

    // Write the operator's age identity to a file the CLI can read.
    let dir = std::env::temp_dir().join(format!("pandapass-gitops-cli-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("make cli dir");
    let age_identity_path = dir.join("age.key");
    std::fs::write(&age_identity_path, operator.expose()).expect("write age identity");

    let (api, config) = make_cli(&base_url, &token, &age_identity_path).await;
    let mut config = config;

    // ── pull ──────────────────────────────────────────────────────────────
    let workdir = dir.join("work");
    let pull_args = GitOpsPullArgs {
        project: "myapp".into(),
        env: "prod".into(),
        dir: workdir.clone(),
    };
    run_command(
        &api,
        &mut config,
        Command::GitOps(GitOpsCmd::Pull(pull_args)),
    )
    .await
    .expect("gitops pull");

    // The local file is age-encrypted and decrypts to both secrets.
    let secrets_file = workdir.join("secrets").join("prod.yaml.age");
    assert!(secrets_file.exists(), "secrets file written");
    let ciphertext = std::fs::read_to_string(&secrets_file).expect("read age file");
    let yaml = pandapass_core::crypto::age_decrypt_file(&ciphertext, &operator)
        .expect("decrypt local secrets file");
    assert!(yaml.contains("API_KEY"), "yaml contains API_KEY");
    assert!(yaml.contains("value-1"), "yaml contains value-1");
    assert!(yaml.contains("DB_URL"), "yaml contains DB_URL");

    // Sync state records remote versions.
    let sync_path = workdir.join(".sync-state.json");
    assert!(sync_path.exists(), "sync state written");
    let sync: pandapass_core::models::SyncState =
        serde_json::from_str(&std::fs::read_to_string(&sync_path).expect("read sync"))
            .expect("parse sync");
    assert!(sync.secrets.contains_key("API_KEY"), "sync has API_KEY");
    assert!(sync.secrets.contains_key("DB_URL"), "sync has DB_URL");

    // ── diff: everything in sync ───────────────────────────────────────────
    // diff takes GitOpsDiffArgs; exercise it through the real command path.
    let diff_cmd = Command::GitOps(GitOpsCmd::Diff(pandapass_cli::commands::GitOpsDiffArgs {
        project: "myapp".into(),
        env: "prod".into(),
        dir: workdir.clone(),
    }));
    run_command(&api, &mut config, diff_cmd)
        .await
        .expect("gitops diff");

    // ── push: add a new secret locally, then push ──────────────────────────
    // Simulate an operator editing the local file: decrypt, append, re-seal.
    let mut file: pandapass_core::models::GitOpsSecretFile =
        serde_yaml::from_str(&yaml).expect("parse yaml");
    file.secrets.insert("NEW_KEY".into(), "new-value".into());
    let updated_yaml = serde_yaml::to_string(&file).expect("serialize yaml");
    let updated_ciphertext = pandapass_core::crypto::age_encrypt_file(
        &updated_yaml,
        std::slice::from_ref(&operator.public_key().expect("operator pub")),
    )
    .expect("re-encrypt local file");
    std::fs::write(&secrets_file, updated_ciphertext).expect("update age file");

    let push_args = GitOpsPushArgs {
        project: "myapp".into(),
        env: "prod".into(),
        dir: workdir.clone(),
        allow_delete: false,
    };
    run_command(
        &api,
        &mut config,
        Command::GitOps(GitOpsCmd::Push(push_args)),
    )
    .await
    .expect("gitops push");

    // The server now has NEW_KEY.
    let remote = setup
        .list_secrets("myapp", "prod")
        .await
        .expect("list remote");
    let keys: Vec<&str> = remote.items.iter().map(|m| m.key.as_str()).collect();
    assert!(keys.contains(&"NEW_KEY"), "server has NEW_KEY: {keys:?}");

    // ── pull again: NEW_KEY comes back locally ─────────────────────────────
    run_command(
        &api,
        &mut config,
        Command::GitOps(GitOpsCmd::Pull(GitOpsPullArgs {
            project: "myapp".into(),
            env: "prod".into(),
            dir: workdir.clone(),
        })),
    )
    .await
    .expect("second pull");

    let ciphertext2 = std::fs::read_to_string(&secrets_file).expect("read age file 2");
    let yaml2 = pandapass_core::crypto::age_decrypt_file(&ciphertext2, &operator)
        .expect("decrypt second pull");
    assert!(yaml2.contains("NEW_KEY"), "second pull has NEW_KEY");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitops_pull_requires_age_identity() {
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

    let project = pandapass_core::models::CreateProjectRequest {
        name: "noid".into(),
        slug: "noid".into(),
        description: None,
    };
    setup
        .create_project(&project)
        .await
        .expect("create project");
    // `create_project` auto-creates dev/staging/prod environments; use dev.
    setup
        .set_secret("noid", "dev", "KEY", "value")
        .await
        .expect("set secret");

    let (api, mut config) =
        make_cli(&base_url, &token, &PathBuf::from("/nonexistent/age.key")).await;
    let workdir =
        std::env::temp_dir().join(format!("pandapass-gitops-noid-{}", uuid::Uuid::now_v7()));

    let result = run_command(
        &api,
        &mut config,
        Command::GitOps(GitOpsCmd::Pull(GitOpsPullArgs {
            project: "noid".into(),
            env: "dev".into(),
            dir: workdir.clone(),
        })),
    )
    .await;

    assert!(result.is_err(), "pull without age identity must fail");
}
/// `pandapass run` must refuse to spawn a child when the program name is not
/// in the configured allowlist. Without this guard, a `read:secret` token
/// could chain into arbitrary command execution via the CLI.
#[tokio::test]
async fn run_refuses_command_not_in_allowlist() {
    use pandapass_cli::commands::{Command, RunArgs};

    let (base_url, _handle) = start_server().await;
    let (api, mut config) = make_cli(
        &base_url,
        "no-such-token",
        &PathBuf::from("/nonexistent/age.key"),
    )
    .await;
    // The auth token won't reach the server in this test, but allowlist
    // checking happens before any HTTP call, so we never need it to.
    config.command_allowlist = vec!["/usr/bin/true".to_string()];

    let res = run_command(
        &api,
        &mut config,
        Command::Run(RunArgs {
            project: "anything".into(),
            env: "any".into(),
            only: None,
            command: vec!["/bin/sh".to_string(), "-c".to_string(), "echo".to_string()],
        }),
    )
    .await;

    let err = res.expect_err("allowlist must reject /bin/sh");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("allowlist"),
        "error should mention the allowlist, got: {msg}"
    );
}

/// Empty allowlist means no restriction. The historical behaviour: the
/// operator chose what to run.
#[tokio::test]
async fn run_with_empty_allowlist_does_not_block() {
    use pandapass_cli::commands::{Command, RunArgs};

    let (base_url, _handle) = start_server().await;
    let (api, mut config) = make_cli(
        &base_url,
        "no-such-token",
        &PathBuf::from("/nonexistent/age.key"),
    )
    .await;
    config.command_allowlist = vec![];

    let res = run_command(
        &api,
        &mut config,
        Command::Run(RunArgs {
            project: "no-such-project".into(), // bails before spawn
            env: "no".into(),
            only: None,
            command: vec!["/bin/echo".to_string(), "hi".to_string()],
        }),
    )
    .await;

    // With an empty allowlist the request must pass the allowlist gate and
    // then fail downstream (auth, project not found, …). The point of the test
    // is that it does *not* fail with "not in the command allowlist".
    let msg = format!("{res:?}");
    assert!(
        !msg.contains("not in the command allowlist"),
        "empty allowlist should not block, got: {msg}"
    );
}

/// Without `--force`, `inject` must NOT write to the output path. This is the
/// contract that keeps a substituted template from being persisted to disk
/// by accident.
#[tokio::test]
async fn inject_refuses_disk_write_without_force() {
    use pandapass_cli::commands::{Command, InjectArgs};
    use pandapass_core::models::CreateProjectRequest;

    let (base_url, _handle) = start_server().await;

    let operator = AgeIdentity::generate();
    let operator_pub = operator.public_key().expect("public key");

    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    let token = register_and_login(&setup, "inject-user@example.com", operator_pub.as_str()).await;
    setup.set_auth_token(Some(token.clone())).await;

    setup
        .create_project(&CreateProjectRequest {
            name: "inj".into(),
            slug: "inj".into(),
            description: None,
        })
        .await
        .expect("create project");
    setup
        .set_secret("inj", "dev", "KEY", "value")
        .await
        .expect("set secret");

    let (api, mut config) =
        make_cli(&base_url, &token, &PathBuf::from("/nonexistent/age.key")).await;
    let workdir = std::env::temp_dir().join(format!("pandapass-inject-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&workdir).expect("workdir");
    let input = workdir.join("template.txt");
    let output = workdir.join("out.txt");
    std::fs::write(&input, "before ${KEY} after").expect("write input");

    let res = run_command(
        &api,
        &mut config,
        Command::Inject(InjectArgs {
            input: input.clone(),
            output: output.clone(),
            project: "inj".into(),
            env: "dev".into(),
            force: false,
        }),
    )
    .await;
    // Should succeed (printing to stdout) and the output file must not exist.
    assert!(
        res.is_ok(),
        "inject without --force should succeed: {res:?}"
    );
    assert!(
        !output.exists(),
        "output file must not be created without --force"
    );
}

/// `pandapass run` must propagate a child's exit status to the caller: exit
/// code 0 is a plain `Ok`, and a non-zero code comes back as
/// `ChildExitStatus` so `main` can map it to the CLI process's exit code
/// (rather than `std::process::exit` inside the command handler, which would
/// be untestable in-process).
#[tokio::test]
async fn run_propagates_child_exit_status() {
    use pandapass_cli::commands::{ChildExitStatus, Command, RunArgs};
    use pandapass_core::models::CreateProjectRequest;

    let (base_url, _handle) = start_server().await;

    let operator = AgeIdentity::generate();
    let operator_pub = operator.public_key().expect("public key");

    let setup = ApiClient::new(base_url.clone(), false).expect("setup client");
    let token = register_and_login(&setup, "run-status@example.com", operator_pub.as_str()).await;
    setup.set_auth_token(Some(token.clone())).await;

    setup
        .create_project(&CreateProjectRequest {
            name: "status".into(),
            slug: "status".into(),
            description: None,
        })
        .await
        .expect("create project");
    setup
        .set_secret("status", "dev", "KEY", "value")
        .await
        .expect("set secret");

    let (api, mut config) =
        make_cli(&base_url, &token, &PathBuf::from("/nonexistent/age.key")).await;

    // Exit code 0 -> Ok(())
    let ok_res = run_command(
        &api,
        &mut config,
        Command::Run(RunArgs {
            project: "status".into(),
            env: "dev".into(),
            only: Some("KEY".into()),
            command: vec!["/usr/bin/true".into()],
        }),
    )
    .await;
    assert!(ok_res.is_ok(), "exit 0 should be Ok, got: {ok_res:?}");

    // Non-zero exit code -> Err(ChildExitStatus(code))
    let err_res = run_command(
        &api,
        &mut config,
        Command::Run(RunArgs {
            project: "status".into(),
            env: "dev".into(),
            only: Some("KEY".into()),
            command: vec!["/usr/bin/false".into()],
        }),
    )
    .await;
    let err = err_res.expect_err("exit 1 should be Err");
    let status = err
        .downcast_ref::<ChildExitStatus>()
        .expect("error should be ChildExitStatus");
    assert_eq!(status.0, 1, "child exit code should be 1, got {status:?}");
}
