use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use uuid::Uuid;

use crate::client::ApiClient;

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Email address. Prompted for when omitted.
    #[arg(long)]
    email: Option<String>,
    /// Password. Prefer --password-stdin: an argument is visible in `ps` and
    /// in shell history.
    #[arg(long)]
    password: Option<String>,
    /// Read the password from stdin (one line). For scripts and agents.
    #[arg(long)]
    password_stdin: bool,
    /// TOTP code. Prompted for only when the account actually requires it.
    #[arg(long)]
    totp: Option<String>,
}

#[derive(Args, Debug)]
pub struct RegisterArgs {
    /// Email address. Prompted for when omitted.
    #[arg(long)]
    email: Option<String>,
    /// Password. Prefer --password-stdin: an argument is visible in `ps` and
    /// in shell history.
    #[arg(long)]
    password: Option<String>,
    /// Read the password from stdin (one line). For scripts and agents.
    #[arg(long)]
    password_stdin: bool,
    /// Path to the age identity whose public key seals this account's master
    /// key. Without it the account is created but cannot store secrets.
    #[arg(long)]
    age_identity: Option<PathBuf>,
}

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
    /// Delete a project and every secret in it. Irreversible.
    Delete {
        slug: String,
        /// Skip the confirmation prompt. Refused when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum EnvCmd {
    List { project: String },
    Create { project: String, name: String, slug: String, description: Option<String> },
    /// Delete an environment and every secret in it. Irreversible.
    Delete {
        project: String,
        env: String,
        /// Skip the confirmation prompt. Refused when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },
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
    /// Mint a service token. The plaintext is shown once and never stored.
    Create {
        /// A label for this token, so it can be recognised later.
        #[arg(long, required = true)]
        name: String,
        /// Project slug to scope the token to. Omit for a token valid across
        /// all projects — prefer scoping it.
        #[arg(long)]
        project: Option<String>,
        /// Environment slug. Requires --project.
        #[arg(long)]
        env: Option<String>,
        /// Scopes to grant, e.g. --scopes read:secret --scopes list:secret.
        #[arg(long, required = true, num_args = 1..)]
        scopes: Vec<String>,
        /// Expire after this many days. Omit for a non-expiring token.
        #[arg(long)]
        expires_days: Option<u64>,
    },
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
pub struct RunArgs {
    /// Project slug
    #[arg(long)]
    project: String,
    /// Environment slug
    #[arg(long)]
    env: String,
    /// Only inject specific keys (comma-separated). A key named here must
    /// exist, or the command is not run.
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
        Command::Run(args) => run_run(api, config, args).await,
        Command::Inject(args) => run_inject(api, config, args).await,
    }
}

// ─────────────────────────── Auth ───────────────────────────

async fn run_login(api: &ApiClient, config: &mut crate::client::CliConfig, args: LoginArgs) -> Result<()> {
    use rpassword::read_password;
    use std::io::{stdout, Write};

    let email = match args.email {
        Some(e) => e,
        None => {
            print!("Email: ");
            stdout().flush()?;
            let mut e = String::new();
            std::io::stdin().read_line(&mut e)?;
            e.trim().to_string()
        }
    };

    let password = match (&args.password, args.password_stdin) {
        (Some(p), _) => p.clone(),
        (_, true) => {
            let mut p = String::new();
            std::io::stdin().read_line(&mut p)?;
            // Trailing newline is not part of the password.
            p.trim_end_matches(['\n', '\r']).to_string()
        }
        (None, false) => {
            print!("Password: ");
            stdout().flush()?;
            read_password()?
        }
    };

    // Only prompt for TOTP when we have no code and no better option; a script
    // that hangs waiting on a TTY is worse than one that fails clearly.
    let totp_code = match args.totp {
        Some(c) => Some(c),
        None if args.password.is_some() || args.password_stdin => None,
        None => {
            print!("TOTP code (optional): ");
            stdout().flush()?;
            let mut code = String::new();
            std::io::stdin().read_line(&mut code)?;
            let code = code.trim();
            if code.is_empty() { None } else { Some(code.to_string()) }
        }
    };

    let resp = api.login(&email, &password, totp_code.as_deref()).await?;

    // The server accepts the password first and asks for the second factor
    // separately, so this response carries no session token. Reporting it as
    // "No session token returned" would send the user looking for a server
    // fault when the fix is to type their code.
    if resp.requires_totp {
        return Err(anyhow::anyhow!(
            "This account has TOTP enabled and no code was supplied. Re-run with \
             --totp <code>, or run `pandapass login` at a terminal to be prompted."
        ));
    }

    let session_token = resp.session_token.ok_or_else(|| anyhow::anyhow!("No session token returned"))?;
    config.auth_token = Some(session_token.clone());
    api.set_auth_token(Some(session_token)).await;

    if resp.key_enrolled {
        println!("Logged in as {} (master key enrolled)", resp.user.email);
    } else {
        // Without an age key this account exists but cannot store or read a
        // single secret — worth saying before they wonder why writes 403.
        println!("Logged in as {}", resp.user.email);
        println!(
            "Note: no master key enrolled. Run `pandapass keygen`, then register \
             again or POST /api/v1/auth/key/enroll to become able to use secrets."
        );
    }
    Ok(())
}

async fn run_register(api: &ApiClient, config: &mut crate::client::CliConfig, args: RegisterArgs) -> Result<()> {
    use rpassword::read_password;
    use std::io::{stdout, Write};

    let email = match args.email {
        Some(e) => e,
        None => {
            print!("Email: ");
            stdout().flush()?;
            let mut e = String::new();
            std::io::stdin().read_line(&mut e)?;
            e.trim().to_string()
        }
    };

    let interactive = args.password.is_none() && !args.password_stdin;
    let password = match (&args.password, args.password_stdin) {
        (Some(p), _) => p.clone(),
        (_, true) => {
            let mut p = String::new();
            std::io::stdin().read_line(&mut p)?;
            p.trim_end_matches(['\n', '\r']).to_string()
        }
        (None, false) => {
            print!("Password: ");
            stdout().flush()?;
            let p = read_password()?;
            println!();
            print!("Confirm password: ");
            stdout().flush()?;
            let confirm = read_password()?;
            println!();
            if p != confirm {
                anyhow::bail!("Passwords do not match");
            }
            p
        }
    };
    let _ = interactive;

    // Seal the account's master key to this user's age key, if one is
    // available. Without it the account exists but cannot store a single
    // secret, which is a confusing state to be handed silently.
    let age_public_key = match &args.age_identity {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("cannot read age identity {}: {}", path.display(), e))?;
            let identity = pandapass_core::crypto::AgeIdentity::parse(&raw)
                .map_err(|e| anyhow::anyhow!("invalid age identity in {}: {}", path.display(), e))?;
            Some(identity.public_key()?.as_str().to_string())
        }
        None => None,
    };

    let resp = api.register(&email, &password, age_public_key.as_deref()).await?;
    let session_token = resp.session_token.ok_or_else(|| anyhow::anyhow!("No session token returned"))?;
    config.auth_token = Some(session_token.clone());
    api.set_auth_token(Some(session_token)).await;

    if resp.key_enrolled {
        println!("Registered and logged in as {}", resp.user.email);
    } else {
        println!("Registered and logged in as {}", resp.user.email);
        println!(
            "This account has no master key yet, so it cannot store or read secrets.\n\
             Run `pandapass keygen` and re-run with --age-identity <path>."
        );
    }
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
            let proj = api.update_project(&slug, name, description).await?;
            println!("Updated project: {} ({})", proj.project.name, proj.project.slug);
        }
        ProjectCmd::Delete { slug, yes } => {
            let proj = api.get_project(&slug).await?;
            if !yes && !confirm_destructive(&format!(
                "Delete project '{}' and every secret in it?",
                proj.project.name
            ))? {
                println!("Aborted.");
                return Ok(());
            }
            api.delete_project(&slug).await?;
            println!("Deleted project {}", proj.project.name);
        }
    }
    Ok(())
}

/// Ask before an irreversible operation. Refuses to auto-confirm when stdin is
/// not a TTY: a script or agent piping input should get "no", not a silent
/// delete of someone's secrets.
fn confirm_destructive(prompt: &str) -> Result<bool> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        eprintln!("Refusing to proceed without confirmation (stdin is not a terminal). Re-run with --yes.");
        return Ok(false);
    }
    eprint!("{prompt} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
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
        EnvCmd::Delete { project, env, yes } => {
            if !yes && !confirm_destructive(&format!(
                "Delete environment '{project}/{env}' and every secret in it?"
            ))? {
                println!("Aborted.");
                return Ok(());
            }
            api.delete_env(&project, &env).await?;
            println!("Deleted environment {project}/{env}");
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
            // The server already prints the value it received; repeating it
            // would be the only place in this command's output where a secret
            // appears, so the version is the useful part to report back.
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
            // The flags take slugs, matching every other command. The API
            // wants ids, so resolve here rather than making the user look one
            // up — parsing these as UUIDs would have failed on every input.
            let project_id = match &project {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let env_id = match (&project, &env) {
                (Some(project_slug), Some(env_slug)) => {
                    let envs = api.list_envs(project_slug).await?;
                    let found = envs
                        .into_iter()
                        .find(|e| e.slug == *env_slug)
                        .ok_or_else(|| {
                            anyhow::anyhow!("No environment '{env_slug}' in project '{project_slug}'")
                        })?;
                    Some(found.id)
                }
                // An env without a project is meaningless; silently ignoring it
                // would mint a token with wider scope than the user asked for.
                (None, Some(_)) => anyhow::bail!("--env requires --project"),
                _ => None,
            };

            let expires_at = expires_days
                .map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));

            let req = crate::model::CreateTokenRequest {
                name,
                project_id,
                env_id,
                scopes,
                expires_at,
            };
            let resp = api.create_token(&req).await?;
            println!("{}", resp.plain_token);
            eprintln!(
                "\nToken created. Shown once; only a hash is stored.\n\
                 Scopes:  {:?}\n\
                 Project: {}\n\
                 Env:     {}",
                resp.token.scopes,
                project.as_deref().unwrap_or("(all)"),
                env.as_deref().unwrap_or("(all)"),
            );
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
            // --project is a slug, like everywhere else; the API filters by id.
            let project_id = match &project {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let resp = api.list_audit(project_id, page.unwrap_or(1), per_page.unwrap_or(20)).await?;
            if resp.items.is_empty() {
                println!("No audit entries.");
                return Ok(());
            }
            for a in &resp.items {
                println!(
                    "{}  {:<18} {:<8} {}",
                    a.ts.format("%Y-%m-%d %H:%M:%S"),
                    a.action,
                    a.outcome,
                    a.secret_key.as_deref().unwrap_or("-")
                );
            }
            let per_page = resp.per_page.max(1);
            let pages = (resp.total + per_page - 1) / per_page;
            println!("\nPage {} of {} ({} entries)", resp.page, pages, resp.total);
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

/// Inject secrets into a subprocess environment, run a command, and exit with
/// its status.
///
/// This is the path that keeps secrets out of an agent's context: the values
/// exist only in this process's memory and in the child's `environ`, never in
/// anything the model can read. The command is spawned as an argv array, never
/// through a shell, so a key name or value containing shell metacharacters
/// cannot turn into command injection.
///
/// Decryption happens server-side (the age private key never leaves the
/// operator's machine), so a plain `pandapass login` session is enough.
async fn run_run(api: &ApiClient, _config: &crate::client::CliConfig, args: RunArgs) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: pandapass run --project P --env E -- cmd args...");
    }

    let metas = api.list_secrets(&args.project, &args.env).await?;
    let available: Vec<String> = metas.items.iter().map(|m| m.key.clone()).collect();

    // An explicit --only is a contract with the caller: if a named key is
    // missing, run nothing rather than silently starting a command that will
    // fail confusingly halfway through. Injecting "everything" by default is
    // the opposite failure — it hands a subprocess keys it never asked for.
    let keys: Vec<String> = match args.only.as_deref() {
        Some(only) => {
            let requested: Vec<String> = only
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            if requested.is_empty() {
                anyhow::bail!("--only was given but lists no keys");
            }
            let missing: Vec<&String> = requested
                .iter()
                .filter(|k| !available.contains(k))
                .collect();
            if !missing.is_empty() {
                anyhow::bail!(
                    "No such key(s) in {}/{}: {}. Available: {}",
                    args.project,
                    args.env,
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    if available.is_empty() {
                        "(none)".to_string()
                    } else {
                        available.join(", ")
                    }
                );
            }
            requested
        }
        None => {
            if available.is_empty() {
                anyhow::bail!(
                    "{}/{} has no secrets, and running without --only would inject nothing",
                    args.project,
                    args.env
                );
            }
            available
        }
    };

    let mut envs: Vec<(String, String)> = Vec::with_capacity(keys.len());
    for key in &keys {
        let secret = api.get_secret(&args.project, &args.env, key).await?;
        envs.push((key.clone(), secret.value));
    }

    // `args.command[0]` is the program, the rest are its arguments. Spawned
    // directly: no `sh -c`, so nothing in a key name or value is ever parsed
    // as shell syntax.
    let program = &args.command[0];
    let status = tokio::process::Command::new(program)
        .args(&args.command[1..])
        .envs(envs.iter().map(|(k, v)| (k, v)))
        .status()
        .await
        .map_err(|e| {
            anyhow::anyhow!("failed to run `{}`: {}", program, e)
        })?;

    // Drop the values before doing anything else that could log or panic.
    for (_, v) in &mut envs {
        v.clear();
        v.shrink_to_fit();
    }
    drop(envs);

    // Propagate the child's exit status so a caller (or an agent) can branch on
    // success without parsing output.
    std::process::exit(status.code().unwrap_or(1));
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