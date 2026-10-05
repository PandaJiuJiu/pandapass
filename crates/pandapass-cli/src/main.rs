use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::error;

mod client;
mod commands;
mod model;

use client::{ApiClient, CliConfig};
use commands::run_command;

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
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Authenticate with the server
    Login(commands::LoginArgs),
    /// Register a new account
    Register(commands::RegisterArgs),
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
            Commands::Register(a) => C::Register(a),
            Commands::Keygen(a) => C::Keygen(a),
            Commands::Logout => C::Logout,
            Commands::Me => C::Me,
            Commands::Project(x) => C::Project(x),
            Commands::Env(x) => C::Env(x),
            Commands::Secret(x) => C::Secret(x),
            Commands::Member(x) => C::Member(x),
            Commands::Token(x) => C::Token(x),
            Commands::Audit(x) => C::Audit(x),
            Commands::Config(x) => C::Config(x),
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

    // Load age identity if configured. Its parse error is a plain &str, so it
    // needs an explicit mapping into anyhow.
    let age_identity = if let Some(path) = &config.age_identity_file {
        let content = tokio::fs::read_to_string(path).await?;
        Some(
            content
                .trim()
                .parse::<age::x25519::Identity>()
                .map_err(|e| anyhow::anyhow!("invalid age identity in {}: {}", path.display(), e))?,
        )
    } else {
        None
    };

    // Create API client
    let api = ApiClient::new(config.server_url.clone(), cli.insecure)?;
    if let Some(token) = &config.auth_token {
        api.set_auth_token(Some(token.clone())).await;
    }
    if let Some(id) = age_identity {
        api.set_age_identity(Some(id)).await;
    }

    // Run command
    let result = run_command(&api, &mut config, cli.command.into()).await;

    // Persist the session before reporting the command's outcome. A failed
    // `register` or `login` may still have minted a usable token, and losing
    // it to a write error would strand the user logged-out with no
    // diagnostic. Write via a temp file and rename, so an interrupted write
    // cannot leave a truncated config that silently resets to defaults.
    let save_result = save_config(&config_path, &config).await;
    if let Err(e) = &save_result {
        eprintln!("warning: could not save config to {}: {}", config_path.display(), e);
        if result.is_ok() {
            // The command the user asked for worked; losing the session is a
            // real problem, but not a reason to report their command as failed.
            eprintln!("The session token was not saved. Re-run `pandapass login` next time.");
        }
    }

    if let Err(e) = result {
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