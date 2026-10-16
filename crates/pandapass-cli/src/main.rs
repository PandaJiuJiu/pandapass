use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::error;

use pandapass_cli::client::{ApiClient, CliConfig};
use pandapass_cli::commands;
use pandapass_cli::commands::run_command;

#[derive(Parser, Debug)]
#[command(name = "pandapass", version, about = "PandaPass - Team secrets management", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Server URL
    #[arg(long, env = "PANDAPASS_SERVER", global = true)]
    server: Option<String>,

    /// Config file path
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Age identity file (private key) for decryption
    #[arg(long, env = "PANDAPASS_AGE_IDENTITY", global = true)]
    age_identity: Option<PathBuf>,

    /// Disable TLS verification (for self-signed certs)
    #[arg(long, global = true)]
    insecure: bool,

    /// PEM file containing the server's CA certificate for CA pinning (TOFU).
    /// The CLI will verify the server's TLS certificate against this CA.
    #[arg(long, global = true)]
    ca_cert: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate with the server
    Login(commands::LoginArgs),
    /// Generate an age keypair for sealing your master key
    Keygen(commands::KeygenArgs),
    /// Logout and clear local session
    Logout,
    /// Show current user info
    Me,

    /// Project management
    #[command(subcommand)]
    Project(commands::ProjectCmd),

    /// Environment management
    #[command(subcommand)]
    Env(commands::EnvCmd),

    /// Secret management
    #[command(subcommand)]
    Secret(commands::SecretCmd),

    /// Team member management
    #[command(subcommand)]
    Member(commands::MemberCmd),

    /// Service token management
    #[command(subcommand)]
    Token(commands::TokenCmd),

    /// Audit log
    #[command(subcommand)]
    Audit(commands::AuditCmd),

    /// Configuration management
    #[command(subcommand)]
    Config(commands::ConfigCmd),

    /// Dynamic credentials (M2)
    #[command(subcommand)]
    Cred(commands::CredCmd),

    /// Policies (M3)
    #[command(subcommand)]
    Policy(commands::PolicyCmd),

    /// PKI/CA and SSH certificates (M4)
    #[command(subcommand)]
    Pki(commands::PkiCmd),

    /// GitOps sync (M3): pull/push/diff secrets to/from a local directory
    #[command(name = "gitops", subcommand)]
    GitOps(commands::GitOpsCmd),

    /// Backup the server database to an age-encrypted local file
    Backup(commands::BackupArgs),

    /// Restore the server database and age identity from a backup file
    Restore(commands::RestoreArgs),

    /// Inject secrets into environment and run command
    Run(commands::RunArgs),

    /// Inject secrets into a template file
    Inject(commands::InjectArgs),
}

impl From<Commands> for commands::Command {
    fn from(c: Commands) -> Self {
        use commands::Command as C;
        match c {
            Commands::Login(a) => C::Login(a),
            Commands::Keygen(a) => C::Keygen(a),
            Commands::Logout => C::Logout,
            Commands::Me => C::Me,
            Commands::Project(x) => C::Project(x),
            Commands::Env(x) => C::Env(x),
            Commands::Secret(x) => C::Secret(x),
            Commands::Cred(x) => C::Cred(x),
            Commands::Member(x) => C::Member(x),
            Commands::Token(x) => C::Token(x),
            Commands::Audit(x) => C::Audit(x),
            Commands::Config(x) => C::Config(x),
            Commands::Policy(x) => C::Policy(x),
            Commands::Pki(x) => C::Pki(x),
            Commands::GitOps(x) => C::GitOps(x),
            Commands::Backup(x) => C::Backup(x),
            Commands::Restore(x) => C::Restore(x),
            Commands::Run(x) => C::Run(x),
            Commands::Inject(x) => C::Inject(x),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // `keygen` is purely local — it must work before any server is configured,
    // and before we try to load a (possibly absent) identity file.
    if let Commands::Keygen(args) = &cli.command {
        return commands::keygen(args);
    }

    // Load config
    let config_path = cli.config.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".pandapass")
            .join("config.json")
    });

    let mut config = if config_path.exists() {
        let content = tokio::fs::read_to_string(&config_path).await?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        CliConfig::default()
    };

    // Override with CLI flags
    if let Some(server) = cli.server {
        config.server_url = server;
    }
    if let Some(age_id) = cli.age_identity {
        config.age_identity_file = Some(age_id);
    }
    if let Some(ca_cert_path) = &cli.ca_cert {
        let pem = tokio::fs::read_to_string(ca_cert_path).await?;
        config.ca_cert = Some(pem);
    }

    // Load age identity if configured. Best-effort only: a stale or unreadable
    // identity file must not block unrelated commands (`config show`,
    // `config set-ca-cert`, etc.). Commands that actually need the identity
    // (gitops sync/encrypt/decrypt) load it lazily and report a precise error.
    // The parse error is a plain &str, so it needs an explicit mapping into anyhow.
    let age_identity = if let Some(path) = &config.age_identity_file {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => Some(
                content
                    .trim()
                    .parse::<age::x25519::Identity>()
                    .map_err(|e| {
                        anyhow::anyhow!("invalid age identity in {}: {}", path.display(), e)
                    })?,
            ),
            Err(e) => {
                eprintln!(
                    "warning: could not read age identity {}: {e} \
                     (only gitops commands need an age identity)",
                    path.display()
                );
                None
            }
        }
    } else {
        None
    };

    // Validate `--insecure` before doing any network I/O: against a
    // non-loopback host it is a hard error, and the TOFU fetch below would
    // otherwise make a connection first.
    if cli.insecure {
        eprintln!(
            "WARNING: TLS certificate verification is disabled (--insecure). \
             Bearer tokens and secret values will travel over an unverified \
             TLS connection. Do not use this flag against any non-loopback host."
        );
        if !config.server_url.starts_with("http://127.0.0.1")
            && !config.server_url.starts_with("http://localhost")
        {
            eprintln!(
                "ERROR: --insecure is not allowed against a non-loopback host ({}). \
                 Use a real certificate or connect over a trusted network.",
                config.server_url
            );
            std::process::exit(2);
        }
    }

    // TOFU: if we are connecting to an HTTPS server and have not pinned its CA
    // yet, fetch the CA certificate from /api/v1/ca.pem *before* building the
    // API client. Without this the very first HTTPS request (e.g. `login`)
    // would fail certificate verification - the CA is needed to establish the
    // connection, so it cannot be fetched after the fact.
    if config.server_url.starts_with("https://") && config.ca_cert.is_none() {
        match commands::fetch_server_ca(&config.server_url).await {
            Ok(pem) => {
                config.ca_cert = Some(pem);
                println!(
                    "Trusted server CA certificate (TOFU). Run `pandapass pki ca fingerprint` to verify it."
                );
            }
            Err(e) => {
                // Do not hard-fail: an `--insecure` user may intentionally skip
                // pinning, and a plain HTTP server URL never reaches this branch.
                eprintln!("Warning: could not fetch server CA for pinning: {e}");
            }
        }
    }

    // Create API client
    let api = ApiClient::with_ca_cert(
        config.server_url.clone(),
        cli.insecure,
        config.ca_cert.clone(),
    )?;
    if let Some(token) = &config.auth_token {
        api.set_auth_token(Some(token.clone())).await;
    }
    if let Some(id) = age_identity {
        api.set_age_identity(Some(id)).await;
    }

    // Run command
    let result = run_command(&api, &mut config, cli.command.into()).await;

    // Persist the session before reporting the command's outcome. A failed
    // `login` may still have minted a usable token, and losing
    // it to a write error would strand the user logged-out with no
    // diagnostic. Write via a temp file and rename, so an interrupted write
    // cannot leave a truncated config that silently resets to defaults.
    let save_result = save_config(&config_path, &config).await;
    if let Err(e) = &save_result {
        eprintln!(
            "warning: could not save config to {}: {}",
            config_path.display(),
            e
        );
        if result.is_ok() {
            // The command the user asked for worked; losing the session is a
            // real problem, but not a reason to report their command as failed.
            eprintln!("The session token was not saved. Re-run `pandapass login` next time.");
        }
    }

    if let Err(e) = result {
        // `pandapass run` 的非零子进程退出码通过 ChildExitStatus 传递，
        // 保持调用方可分支的语义；不视为 CLI 内部错误，因此不打印 error。
        if let Some(status) = e.downcast_ref::<pandapass_cli::commands::ChildExitStatus>() {
            std::process::exit(status.0);
        }
        error!("{}", e);
        std::process::exit(1);
    }

    Ok(())
}

/// Write the CLI config atomically: temp file in the same directory, then
/// rename. A half-written config is worse than a stale one — it would fail to
/// parse and be replaced by defaults, losing the session entirely.
async fn save_config(path: &std::path::Path, config: &CliConfig) -> Result<()> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let content = serde_json::to_string_pretty(config)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, content.as_bytes()).await?;

    // The config holds a live session token: owner-only, like the age key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }

    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}
