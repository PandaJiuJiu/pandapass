use anyhow::{Context, Result};
use clap::{Parser, Subcommand, Args};
use std::path::PathBuf;
use tracing::{info, warn, error};

mod client;
mod commands;
mod mcp;

use client::{ApiClient, CliConfig};
use commands::{Command, run_command};

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

    /// MCP Server (for Agent integration)
    Mcp(commands::McpArgs),

    /// Inject secrets into environment and run command
    Run(commands::RunArgs),

    /// Inject secrets into a template file
    Inject(commands::InjectArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

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

    // Load age identity if configured
    let age_identity = if let Some(path) = &config.age_identity_file {
        let content = tokio::fs::read_to_string(path).await?;
        Some(content.trim().parse::<age::x25519::Identity>()?)
    } else {
        None
    };

    // Create API client
    let api = ApiClient::new(config.server_url.clone())?;
    if let Some(token) = &config.auth_token {
        api.set_auth_token(Some(token.clone())).await;
    }
    if let Some(id) = age_identity {
        api.set_age_identity(Some(id)).await;
    }

    // Run command
    let result = run_command(&api, &mut config, cli.command).await;

    // Save config if auth token changed
    if let Some(dir) = config_path.parent() {
        tokio::fs::create_dir_all(dir).await.ok();
    }
    let content = serde_json::to_string_pretty(&config)?;
    tokio::fs::write(&config_path, content).await?;

    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }

    Ok(())
}