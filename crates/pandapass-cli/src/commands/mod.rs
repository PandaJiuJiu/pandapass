use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use uuid::Uuid;

use crate::client::ApiClient;

pub struct LoginArgs;
pub struct RegisterArgs;
pub struct ProjectCmd;
pub struct EnvCmd;
pub struct SecretCmd;
pub struct MemberCmd;
pub struct TokenCmd;
pub struct AuditCmd;
pub struct ConfigCmd;
pub struct McpArgs;
pub struct RunArgs;
pub struct InjectArgs;

pub async fn run_command(
    api: &ApiClient,
    config: &mut crate::client::CliConfig,
    cmd: crate::Commands,
) -> Result<()> {
    match cmd {
        crate::Commands::Login(args) => run_login(api, config, args).await,
        crate::Commands::Register(args) => run_register(api, config, args).await,
        crate::Commands::Logout => run_logout(api, config).await,
        crate::Commands::Me => run_me(api).await,
        crate::Commands::Project(cmd) => run_project(api, cmd).await,
        crate::Commands::Env(cmd) => run_env(api, cmd).await,
        crate::Commands::Secret(cmd) => run_secret(api, cmd).await,
        crate::Commands::Member(cmd) => run_member(api, cmd).await,
        crate::Commands::Token(cmd) => run_token(api, cmd).await,
        crate::Commands::Audit(cmd) => run_audit(api, cmd).await,
        crate::Commands::Config(cmd) => run_config(config, cmd).await,
        crate::Commands::Mcp(args) => run_mcp(api, args).await,
        crate::Commands::Run(args) => run_run(api, config, args).await,
        crate::Commands::Inject(args) => run_inject(api, config, args).await,
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

    let totp_code = if true {
        print!("TOTP code (optional): ");
        stdout().flush()?;
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        let code = code.trim();
        if code.is_empty() { None } else { Some(code.to_string()) }
    } else { None };

    let resp = api.login(&email, &password, totp_code.as_deref()).await?;
    config.auth_token = Some(resp.session_token.clone());
    api.set_auth_token(Some(resp.session_token)).await;

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
    config.auth_token = Some(resp.session_token.clone());
    api.set_auth_token(Some(resp.session_token)).await;

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

#[derive(Subcommand, Debug)]
enum ProjectSubcmd {
    List,
    Create { name: String, slug: String, description: Option<String> },
    Get { slug: String },
    Update { slug: String, name: Option<String>, description: Option<String> },
    Delete { slug: String },
}

async fn run_project(api: &ApiClient, cmd: ProjectSubcmd) -> Result<()> {
    match cmd {
        ProjectSubcmd::List => {
            let projects = api.list_projects().await?;
            for p in projects {
                println!("{} ({}) - {:?}", p.project.name, p.project.slug, p.user_role);
            }
        }
        ProjectSubcmd::Create { name, slug, description } => {
            let req = crate::client::CreateProjectRequest { name, slug, description };
            let proj = api.create_project(&req).await?;
            println!("Created project: {} ({})", proj.project.name, proj.project.slug);
        }
        ProjectSubcmd::Get { slug } => {
            let proj = api.get_project(&slug).await?;
            println!("Name: {}", proj.project.name);
            println!("Slug: {}", proj.project.slug);
            println!("Description: {:?}", proj.project.description);
            println!("Your role: {:?}", proj.user_role);
        }
        ProjectSubcmd::Update { slug, name, description } => {
            // TODO: implement
            println!("Update not yet implemented");
        }
        ProjectSubcmd::Delete { slug } => {
            // TODO: implement
            println!("Delete not yet implemented");
        }
    }
    Ok(())
}

// ─────────────────────────── Env ───────────────────────────

#[derive(Subcommand, Debug)]
enum EnvSubcmd {
    List { project: String },
    Create { project: String, name: String, slug: String, description: Option<String> },
}

async fn run_env(api: &ApiClient, cmd: EnvSubcmd) -> Result<()> {
    match cmd {
        EnvSubcmd::List { project } => {
            let envs = api.list_envs(&project).await?;
            for e in envs {
                println!("{} ({})", e.name, e.slug);
            }
        }
        EnvSubcmd::Create { project, name, slug, description } => {
            let req = crate::client::CreateEnvRequest { name, slug, description };
            let env = api.create_env(&project, &req).await?;
            println!("Created environment: {} ({})", env.name, env.slug);
        }
    }
    Ok(())
}

// ─────────────────────────── Secret ───────────────────────────

#[derive(Subcommand, Debug)]
enum SecretSubcmd {
    List { project: String, env: String },
    Get { project: String, env: String, key: String },
    Set { project: String, env: String, key: String, value: String },
    Delete { project: String, env: String, key: String },
}

async fn run_secret(api: &ApiClient, cmd: SecretSubcmd) -> Result<()> {
    match cmd {
        SecretSubcmd::List { project, env } => {
            let resp = api.list_secrets(&project, &env).await?;
            for s in resp.items {
                println!("{} (v{}, updated {})", s.key, s.version, s.updated_at);
            }
            println!("Total: {}", resp.total);
        }
        SecretSubcmd::Get { project, env, key } => {
            let secret = api.get_secret(&project, &env, &key).await?;
            println!("{}", secret.value);
        }
        SecretSubcmd::Set { project, env, key, value } => {
            let req = crate::client::SetSecretRequest { key, value };
            let secret = api.set_secret(&project, &env, &req).await?;
            println!("Set {} (v{})", secret.key, secret.version);
        }
        SecretSubcmd::Delete { project, env, key } => {
            api.delete_secret(&project, &env, &key).await?;
            println!("Deleted {}", key);
        }
    }
    Ok(())
}

// ─────────────────────────── Member ───────────────────────────

#[derive(Subcommand, Debug)]
enum MemberSubcmd {
    List { project: String },
    Add { project: String, email: String, role: String },
}

async fn run_member(api: &ApiClient, cmd: MemberSubcmd) -> Result<()> {
    match cmd {
        MemberSubcmd::List { project } => {
            let members = api.list_members(&project).await?;
            for m in members {
                println!("{} - {:?}", m.user.email, m.member.role);
            }
        }
        MemberSubcmd::Add { project, email, role } => {
            let role = match role.as_str() {
                "owner" => crate::client::ProjectRole::Owner,
                "editor" => crate::client::ProjectRole::Editor,
                "viewer" => crate::client::ProjectRole::Viewer,
                _ => anyhow::bail!("Invalid role: {}", role),
            };
            let req = crate::client::AddMemberRequest { email, role };
            let member = api.add_member(&project, &req).await?;
            println!("Added {} as {:?}", member.user.email, member.member.role);
        }
    }
    Ok(())
}

// ─────────────────────────── Token ───────────────────────────

#[derive(Subcommand, Debug)]
enum TokenSubcmd {
    List,
    Create { name: String, project: Option<String>, env: Option<String>, scopes: Vec<String>, expires_days: Option<u64> },
    Revoke { id: Uuid },
}

async fn run_token(api: &ApiClient, cmd: TokenSubcmd) -> Result<()> {
    match cmd {
        TokenSubcmd::List => {
            let tokens = api.list_tokens().await?;
            for t in tokens {
                println!("{} - {} - scopes: {:?}", t.id, t.name, t.scopes);
            }
        }
        TokenSubcmd::Create { name, project, env, scopes, expires_days } => {
            let project_id = project.map(|s| Uuid::parse_str(&s)).transpose()?;
            let env_id = env.map(|s| Uuid::parse_str(&s)).transpose()?;
            let expires_at = expires_days.map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));

            let req = crate::client::CreateTokenRequest {
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
        TokenSubcmd::Revoke { id } => {
            api.revoke_token(id).await?;
            println!("Token revoked");
        }
    }
    Ok(())
}

// ─────────────────────────── Audit ───────────────────────────

#[derive(Subcommand, Debug)]
enum AuditSubcmd {
    List { project: Option<String>, page: Option<i64>, per_page: Option<i64> },
}

async fn run_audit(api: &ApiClient, cmd: AuditSubcmd) -> Result<()> {
    match cmd {
        AuditSubcmd::List { project, page, per_page } => {
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

#[derive(Subcommand, Debug)]
enum ConfigSubcmd {
    Show,
    SetServer { url: String },
    SetAgeIdentity { path: PathBuf },
    SetDefaultProject { project: Option<String> },
    SetDefaultEnv { env: Option<String> },
}

async fn run_config(config: &mut crate::client::CliConfig, cmd: ConfigSubcmd) -> Result<()> {
    match cmd {
        ConfigSubcmd::Show => {
            println!("Server: {}", config.server_url);
            println!("Auth token: {}", if config.auth_token.is_some() { "set" } else { "none" });
            println!("Default project: {:?}", config.default_project);
            println!("Default env: {:?}", config.default_env);
            println!("Age identity: {:?}", config.age_identity_file);
        }
        ConfigSubcmd::SetServer { url } => {
            config.server_url = url;
            println!("Server URL updated");
        }
        ConfigSubcmd::SetAgeIdentity { path } => {
            config.age_identity_file = Some(path);
            println!("Age identity file set");
        }
        ConfigSubcmd::SetDefaultProject { project } => {
            config.default_project = project;
            println!("Default project updated");
        }
        ConfigSubcmd::SetDefaultEnv { env } => {
            config.default_env = env;
            println!("Default env updated");
        }
    }
    Ok(())
}

// ─────────────────────────── MCP / Run / Inject ───────────��────────��──────

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Run as MCP server (stdio)
    #[arg(long)]
    pub stdio: bool,
}

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