use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use uuid::Uuid;

use crate::client::ApiClient;

#[derive(Args, Debug)]
pub struct LoginArgs;

#[derive(Args, Debug)]
pub struct RegisterArgs;

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Where to write the age identity. Defaults to ~/.pandapass/age.key
    #[arg(long, default_value = None)]
    pub out: Option<PathBuf>,

    /// Print the public key only, without writing an identity to disk
    #[arg(long)]
    pub print: bool,
}

/// Generate an age keypair. The private half is written to disk with `0600`
/// and is never transmitted; only the public key goes to the server.
pub fn keygen(args: &KeygenArgs) -> Result<()> {
    use pandapass_core::crypto::AgeIdentity;

    let identity = AgeIdentity::generate();    let public = identity.public_key()?.as_str().to_string();

    if args.print {
        println!("{public}");
        return Ok(());
    }

    let path = match &args.out {
        Some(p) => p.clone(),
        None => home_dir()?.join(".pandapass").join("age.key"),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        // Overwriting a private key silently locks the user out of every
        // secret sealed to it, so refuse and make them choose.
        anyhow::bail!(
            "{} already exists. Move it aside first — overwriting it makes every \
             secret sealed to the current key unreadable.",
            path.display()
        );
    }

    // Create with 0600 from the start: a world-readable private key is worse
    // than no encryption at all.
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.create_new(true).write(true).open(&path)?;
    use std::io::Write;
    writeln!(f, "{}", identity.as_str())?;
    drop(f);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("Wrote identity to {}", path.display());
    println!("Public key: {public}");
    println!();
    println!("Back this file up somewhere safe. If you lose it, the secrets sealed");
    println!("to it cannot be recovered by anyone, including the server.");
    Ok(())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("HOME is not set; pass --out explicitly"))
}

#[derive(Subcommand, Debug)]
pub enum ProjectCmd {
    List,
    Create { name: String, slug: String, description: Option<String> },
    Get { slug: String },
    Update { slug: String, name: Option<String>, description: Option<String> },
    Delete { slug: String },
}

#[derive(Subcommand, Debug)]
pub enum EnvCmd {
    List { project: String },
    Create { project: String, name: String, slug: String, description: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    List { project: String, env: String },
    Get { project: String, env: String, key: String },
    Set { project: String, env: String, key: String, value: String },
    Delete { project: String, env: String, key: String },
}

#[derive(Subcommand, Debug)]
pub enum MemberCmd {
    List { project: String },
    Add { project: String, email: String, role: String },
    Update { project: String, user_id: Uuid, role: String },
    Remove { project: String, user_id: Uuid },
}

#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    List,
    Create { name: String, project: Option<String>, env: Option<String>, scopes: Vec<String>, expires_days: Option<u64> },
    Revoke { id: Uuid },
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    List { project: Option<String>, page: Option<i64>, per_page: Option<i64> },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    Show,
    SetServer { url: String },
    SetAgeIdentity { path: PathBuf },
    SetDefaultProject { project: Option<String> },
    SetDefaultEnv { env: Option<String> },
}

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Run as MCP server (stdio)
    #[arg(long)]
    pub stdio: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Project slug
    #[arg(long)]
    project: String,
    /// Environment slug
    #[arg(long)]
    env: String,
    /// Only inject specific keys (comma-separated)
    #[arg(long)]
    only: Option<String>,
    /// Command to run
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct InjectArgs {
    /// Input template file
    #[arg(short, long)]
    input: PathBuf,
    /// Output file
    #[arg(short, long)]
    output: PathBuf,
    /// Project slug
    #[arg(long)]
    project: String,
    /// Environment slug
    #[arg(long)]
    env: String,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Login(LoginArgs),
    Register(RegisterArgs),
    Keygen(KeygenArgs),
    Logout,
    Me,
    #[command(subcommand)]
    Project(ProjectCmd),
    #[command(subcommand)]
    Env(EnvCmd),
    #[command(subcommand)]
    Secret(SecretCmd),
    #[command(subcommand)]
    Member(MemberCmd),
    #[command(subcommand)]
    Token(TokenCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    #[command(subcommand)]
    Config(ConfigCmd),
    Mcp(McpArgs),
    Run(RunArgs),
    Inject(InjectArgs),
}

pub async fn run_command(
    api: &ApiClient,
    config: &mut crate::client::CliConfig,
    cmd: Command,
) -> Result<()> {
    match cmd {
        Command::Login(args) => run_login(api, config, args).await,
        Command::Register(args) => run_register(api, config, args).await,
        // Handled before the client is built; unreachable via this path.
        Command::Keygen(args) => keygen(&args),
        Command::Logout => run_logout(api, config).await,
        Command::Me => run_me(api).await,
        Command::Project(cmd) => run_project(api, cmd).await,
        Command::Env(cmd) => run_env(api, cmd).await,
        Command::Secret(cmd) => run_secret(api, cmd).await,
        Command::Member(cmd) => run_member(api, cmd).await,
        Command::Token(cmd) => run_token(api, cmd).await,
        Command::Audit(cmd) => run_audit(api, cmd).await,
        Command::Config(cmd) => run_config(config, cmd).await,
        Command::Mcp(args) => run_mcp(api, args).await,
        Command::Run(args) => run_run(api, config, args).await,
        Command::Inject(args) => run_inject(api, config, args).await,
    }
}

// ─────────────────────────── Auth ───────────────────────────

async fn run_login(api: &ApiClient, config: &mut crate::client::CliConfig, _args: LoginArgs) -> Result<()> {
    use rpassword::read_password;
    use std::io::{stdout, Write};

    print!("Email: ");
    stdout().flush()?;
    let mut email = String::new();
    std::io::stdin().read_line(&mut email)?;
    let email = email.trim().to_string();

    print!("Password: ");
    stdout().flush()?;
    let password = read_password()?;

    let totp_code = {
        print!("TOTP code (optional): ");
        stdout().flush()?;
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        let code = code.trim();
        if code.is_empty() { None } else { Some(code.to_string()) }
    };

    let resp = api.login(&email, &password, totp_code.as_deref()).await?;
    let session_token = resp.session_token.ok_or_else(|| anyhow::anyhow!("No session token returned"))?;
    config.auth_token = Some(session_token.clone());
    api.set_auth_token(Some(session_token)).await;

    println!("Logged in as {}", resp.user.email);
    Ok(())
}

async fn run_register(api: &ApiClient, config: &mut crate::client::CliConfig, _args: RegisterArgs) -> Result<()> {
    use rpassword::read_password;
    use std::io::{stdout, Write};

    print!("Email: ");
    stdout().flush()?;
    let mut email = String::new();
    std::io::stdin().read_line(&mut email)?;
    let email = email.trim().to_string();

    print!("Password: ");
    stdout().flush()?;
    let password = read_password()?;
    println!();

    print!("Confirm password: ");
    stdout().flush()?;
    let confirm = read_password()?;
    println!();

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    let resp = api.register(&email, &password).await?;
    let session_token = resp.session_token.ok_or_else(|| anyhow::anyhow!("No session token returned"))?;
    config.auth_token = Some(session_token.clone());
    api.set_auth_token(Some(session_token)).await;

    println!("Registered and logged in as {}", resp.user.email);
    Ok(())
}

async fn run_logout(api: &ApiClient, config: &mut crate::client::CliConfig) -> Result<()> {
    api.logout().await?;
    config.auth_token = None;
    println!("Logged out");
    Ok(())
}

async fn run_me(api: &ApiClient) -> Result<()> {
    let user = api.me().await?;
    println!("Email: {}", user.email);
    println!("Role: {:?}", user.global_role);
    println!("TOTP: {}", if user.totp_enabled { "enabled" } else { "disabled" });
    println!("Created: {}", user.created_at);
    Ok(())
}

// ─────────────────────────── Project ───────────────────────────

async fn run_project(api: &ApiClient, cmd: ProjectCmd) -> Result<()> {
    match cmd {
        ProjectCmd::List => {
            let projects = api.list_projects().await?;
            for p in projects {
                println!("{} ({}) - {:?}", p.project.name, p.project.slug, p.user_role);
            }
        }
        ProjectCmd::Create { name, slug, description } => {
            let req = pandapass_core::models::CreateProjectRequest { name, slug, description };
            let proj = api.create_project(&req).await?;
            println!("Created project: {} ({})", proj.project.name, proj.project.slug);
        }
        ProjectCmd::Get { slug } => {
            let proj = api.get_project(&slug).await?;
            println!("Name: {}", proj.project.name);
            println!("Slug: {}", proj.project.slug);
            println!("Description: {:?}", proj.project.description);
            println!("Your role: {:?}", proj.user_role);
        }
        ProjectCmd::Update { slug, name, description } => {
            // TODO: implement
            println!("Update not yet implemented");
        }
        ProjectCmd::Delete { slug } => {
            // TODO: implement
            println!("Delete not yet implemented");
        }
    }
    Ok(())
}

// ─────────────────────────── Env ───────────────────────────

async fn run_env(api: &ApiClient, cmd: EnvCmd) -> Result<()> {
    match cmd {
        EnvCmd::List { project } => {
            let envs = api.list_envs(&project).await?;
            for e in envs {
                println!("{} ({})", e.name, e.slug);
            }
        }
        EnvCmd::Create { project, name, slug, description } => {
            let req = pandapass_core::models::CreateEnvRequest { name, slug, description };
            let env = api.create_env(&project, &req).await?;
            println!("Created environment: {} ({})", env.name, env.slug);
        }
    }
    Ok(())
}

// ─────────────────────────── Secret ───────────────────────────

async fn run_secret(api: &ApiClient, cmd: SecretCmd) -> Result<()> {
    match cmd {
        SecretCmd::List { project, env } => {
            let resp = api.list_secrets(&project, &env).await?;
            for s in resp.items {
                println!("{} (v{}, updated {})", s.key, s.version, s.updated_at);
            }
            println!("Total: {}", resp.total);
        }
        SecretCmd::Get { project, env, key } => {
            let secret = api.get_secret(&project, &env, &key).await?;
            println!("{}", secret.value);
        }
        SecretCmd::Set { project, env, key, value } => {
            let secret = api.set_secret(&project, &env, &key, &value).await?;
            println!("Set {} (v{})", secret.key, secret.version);
        }
        SecretCmd::Delete { project, env, key } => {
            api.delete_secret(&project, &env, &key).await?;
            println!("Deleted {}", key);
        }
    }
    Ok(())
}

// ─────────────────────────── Member ───────────────────────────

async fn run_member(api: &ApiClient, cmd: MemberCmd) -> Result<()> {
    match cmd {
        MemberCmd::List { project } => {
            let members = api.list_members(&project).await?;
            for m in members {
                println!("{} - {:?}", m.user.email, m.member.role);
            }
        }
        MemberCmd::Add { project, email, role } => {
            let role = match role.as_str() {
                "owner" => pandapass_core::models::ProjectRole::Owner,
                "editor" => pandapass_core::models::ProjectRole::Editor,
                "viewer" => pandapass_core::models::ProjectRole::Viewer,
                _ => anyhow::bail!("Invalid role: {}", role),
            };
            let member = api.add_member(&project, &email, role).await?;
            println!("Added {} as {:?}", member.user.email, member.member.role);
        }
        MemberCmd::Update { project, user_id, role } => {
            let role = match role.as_str() {
                "owner" => pandapass_core::models::ProjectRole::Owner,
                "editor" => pandapass_core::models::ProjectRole::Editor,
                "viewer" => pandapass_core::models::ProjectRole::Viewer,
                _ => anyhow::bail!("Invalid role: {}", role),
            };
            api.update_member(&project, user_id, role).await?;
            println!("Updated member role to {:?}", role);
        }
        MemberCmd::Remove { project, user_id } => {
            api.remove_member(&project, user_id).await?;
            println!("Removed member");
        }
    }
    Ok(())
}

// ─────────────────────────── Token ───────────────────────────

async fn run_token(api: &ApiClient, cmd: TokenCmd) -> Result<()> {
    match cmd {
        TokenCmd::List => {
            let tokens = api.list_tokens().await?;
            for t in tokens {
                println!("{} - {} - scopes: {:?}", t.id, t.name, t.scopes);
            }
        }
        TokenCmd::Create { name, project, env, scopes, expires_days } => {
            let project_id = project.map(|s| Uuid::parse_str(&s)).transpose()?;
            let env_id = env.map(|s| Uuid::parse_str(&s)).transpose()?;
            let expires_at = expires_days.map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));

            let req = crate::model::CreateTokenRequest {
                name,
                project_id,
                env_id,
                scopes,
                expires_at,
            };
            let resp = api.create_token(&req).await?;
            println!("Token created: {}", resp.plain_token);
            println!("SAVE THIS TOKEN - it will not be shown again!");
        }
        TokenCmd::Revoke { id } => {
            api.revoke_token(id).await?;
            println!("Token revoked");
        }
    }
    Ok(())
}

// ─────────────────────────── Audit ─────���─────────────────────

async fn run_audit(api: &ApiClient, cmd: AuditCmd) -> Result<()> {
    match cmd {
        AuditCmd::List { project, page, per_page } => {
            let project_id = project.map(|s| Uuid::parse_str(&s)).transpose()?;
            let resp = api.list_audit(project_id, page.unwrap_or(1), per_page.unwrap_or(20)).await?;
            for a in resp.items {
                println!("[{}] {} - {} - {}", a.ts.format("%Y-%m-%d %H:%M:%S"), a.action, a.outcome, a.secret_key.unwrap_or_default());
            }
            println!("Page {} / {} (total: {})", resp.page, (resp.total + resp.per_page - 1) / resp.per_page, resp.total);
        }
    }
    Ok(())
}

// ─────────────────────────── Config ───────────────────────────

async fn run_config(config: &mut crate::client::CliConfig, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            println!("Server: {}", config.server_url);
            println!("Auth token: {}", if config.auth_token.is_some() { "set" } else { "none" });
            println!("Default project: {:?}", config.default_project);
            println!("Default env: {:?}", config.default_env);
            println!("Age identity: {:?}", config.age_identity_file);
        }
        ConfigCmd::SetServer { url } => {
            config.server_url = url;
            println!("Server URL updated");
        }
        ConfigCmd::SetAgeIdentity { path } => {
            config.age_identity_file = Some(path);
            println!("Age identity file set");
        }
        ConfigCmd::SetDefaultProject { project } => {
            config.default_project = project;
            println!("Default project updated");
        }
        ConfigCmd::SetDefaultEnv { env } => {
            config.default_env = env;
            println!("Default env updated");
        }
    }
    Ok(())
}

// ─────────────────────────── MCP / Run / Inject ───────────────────────────

async fn run_mcp(api: &ApiClient, args: McpArgs) -> Result<()> {
    if args.stdio {
        println!("MCP server starting on stdio...");
        // TODO: implement MCP stdio server
        // This would use rmcp to serve tools
    } else {
        println!("Use --stdio to run MCP server");
    }
    Ok(())
}

async fn run_run(api: &ApiClient, config: &crate::client::CliConfig, args: RunArgs) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Get secrets
    let resp = api.list_secrets(&args.project, &args.env).await?;
    let keys: Vec<String> = if let Some(only) = args.only {
        only.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        resp.items.iter().map(|s| s.key.clone()).collect()
    };

    // Decrypt secrets using age identity
    // This requires the age private key to be loaded
    // For now, we'll use the MCP internal endpoint
    println!("Run with secrets not fully implemented - needs age private key for decryption");
    println!("Keys to inject: {:?}", keys);
    println!("Command: {:?}", args.command);

    Ok(())
}

async fn run_inject(api: &ApiClient, _config: &crate::client::CliConfig, args: InjectArgs) -> Result<()> {
    let resp = api.list_secrets(&args.project, &args.env).await?;

    let template = tokio::fs::read_to_string(&args.input).await?;
    let mut output = template;

    for s in resp.items {
        let secret = api.get_secret(&args.project, &args.env, &s.key).await?;
        let placeholder = format!("${{{}}}", s.key);
        output = output.replace(&placeholder, &secret.value);
        let placeholder2 = format!("${}", s.key);
        output = output.replace(&placeholder2, &secret.value);
    }

    tokio::fs::write(&args.output, output).await?;
    println!("Injected secrets into {}", args.output.display());
    Ok(())
}