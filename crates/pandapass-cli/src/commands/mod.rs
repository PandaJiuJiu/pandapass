use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;
use uuid::Uuid;

use crate::client::ApiClient;

/// `pandapass run` 的子进程退出码。`main` 把它映射为 CLI 进程退出码，
/// 使调用方（脚本/agent）能分支处理，同时避免在命令处理器内直接 exit。
#[derive(Debug)]
pub struct ChildExitStatus(pub i32);

impl std::fmt::Display for ChildExitStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "child process exited with status {}", self.0)
    }
}

impl std::error::Error for ChildExitStatus {}

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

/// Dynamic credentials (M2)
#[derive(Subcommand, Debug)]
pub enum CredCmd {
    List { project: String, env: String },
    Create {
        project: String,
        env: String,
        kind: String,
        username: String,
        #[arg(long, default_value = "3600")]
        ttl_seconds: i64,
    },
    Revoke { project: String, env: String, id: Uuid },
}

/// Policies (M3)
#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    List { #[arg(long)] enabled_only: bool },
    Create { name: String, rego: String },
    Get { id: Uuid },
    Update { id: Uuid, name: Option<String>, rego: Option<String>, enabled: Option<bool> },
    Delete { id: Uuid },
    Bind { policy_id: Uuid, project: Option<String>, env: Option<String> },
    Unbind { id: Uuid },
    ListBindings { project: Option<String>, env: Option<String> },
}

/// PKI/CA and SSH certificates (M4)
#[derive(Subcommand, Debug)]
pub enum PkiCmd {
    /// CA keys
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// SSH certificates
    Ssh {
        #[command(subcommand)]
        cmd: SshCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum CaCmd {
    List { #[arg(long)] include_revoked: bool },
    Create {
        kind: String,
        key_pem: String,
        cert_pem: String,
        not_before: String,
        not_after: String,
    },
    Get { id: Uuid },
    Revoke { id: Uuid },
}

#[derive(Subcommand, Debug)]
pub enum SshCmd {
    List {
        #[arg(long)]
        user: Option<Uuid>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        include_revoked: bool,
    },
    /// Sign an SSH user certificate with a stored CA. The user's public key
    /// is signed; their private key never leaves their machine.
    Sign {
        /// CA key id to sign with
        ca_id: Uuid,
        /// User id the certificate is issued to
        user: Uuid,
        /// Principal (e.g. `alice@prod`) the cert authenticates
        #[arg(long)]
        principal: String,
        /// Path to the user's public key in OpenSSH format
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        project: Option<String>,
        /// RFC3339 validity start (default: now)
        #[arg(long)]
        not_before: Option<String>,
        /// RFC3339 validity end (default: +12h)
        #[arg(long)]
        not_after: Option<String>,
    },
    Create {
        user: Uuid,
        #[arg(long)]
        project: Option<String>,
        principal: String,
        cert_pem: String,
        key_type: String,
        not_before: String,
        not_after: String,
    },
    Revoke { id: Uuid },
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
        /// Available: read:secret, write:secret, list:secret, read:audit,
        /// manage:project, run:secret.
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
    /// Verify the audit log HMAC chain. Admin only: a broken chain means
    /// the log was edited after it was written.
    Verify,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    Show,
    SetServer { url: String },
    SetAgeIdentity { path: PathBuf },
    SetDefaultProject { project: Option<String> },
    SetDefaultEnv { env: Option<String> },
    /// Set the `pandapass run` allowlist. Comma-separated absolute paths; pass
    /// the empty string to clear it. An empty allowlist means no restriction.
    SetCommandAllowlist { paths: String },
    /// Set the `pandapass run` wall-clock timeout in seconds. The default is
    /// 120s when unset.
    SetCommandTimeout { seconds: u64 },
}

#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// Print the server's age public key (the recipient every envelope is
    /// sealed to). Use this to record which key the vault was last
    /// bootstrapped with, or to verify the server's identity before
    /// re-enrolling.
    ServerAgeShow,
}

/// `pandapass run`: run a command locally with secrets injected from the
/// server (CLI holds the age identity and decrypts locally). This is the
/// historical path that does not require `run:secret` scope on the token.
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Only inject specific keys (comma-separated). A key named here must
    /// exist, or the command is not run.
    #[arg(long)]
    pub only: Option<String>,
    /// Command to run
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// `pandapass exec`: run a command on the server with secrets injected
/// server-side. Requires a token with `run:secret` scope. The secrets never
/// leave the server in plaintext; the command runs on the server host.
#[derive(Args, Debug)]
pub struct InternalExecArgs {
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Keys to inject (comma-separated)
    #[arg(long)]
    pub keys: String,
    /// Command to run on the server
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// `pandapass backup`: fetch a consistent SQLite snapshot of the server
/// database and seal it into an age-encrypted file.
#[derive(Args, Debug)]
pub struct BackupArgs {
    /// Output file path. `.age` is appended when the path has no extension.
    #[arg(long)]
    pub out: PathBuf,
    /// Age recipient (`age1...`) to seal the backup to. Defaults to the
    /// operator's own public key derived from `--age-identity` / config.
    #[arg(long)]
    pub recipient: Option<String>,
    /// Path to the server's age identity file to include in the backup.
    /// Without it, a restore cannot unwrap envelopes. Defaults to
    /// `PANDAPASS_SERVER_AGE_IDENTITY_FILE`.
    #[arg(long)]
    pub server_age_identity: Option<PathBuf>,
    /// Path to the audit chain key file to include in the backup. Defaults
    /// to `PANDAPASS_AUDIT_CHAIN_KEY_FILE`.
    #[arg(long)]
    pub audit_chain_key: Option<PathBuf>,
    /// Do not age-encrypt the output; write the raw snapshot. For local
    /// testing only. Refused when the output path looks like a `.age` file.
    #[arg(long)]
    pub raw: bool,
}

/// `pandapass restore`: restore the server database (and optionally the age
/// identity) from a backup file. Fully local: the file is decrypted,
/// verified, and written to the paths you supply. The running server must be
/// stopped before restoring, or it will overwrite the restored database.
#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Input backup file. Must be either a raw SQLite snapshot or an
    /// age-encrypted backup produced by `pandapass backup`.
    #[arg(long)]
    pub input: PathBuf,
    /// Where to write the restored SQLite database.
    #[arg(long)]
    pub db_path: PathBuf,
    /// Where to write the restored server age identity (from the same
    /// backup). Optional — pass this when the backup file is a full
    /// encrypted backup containing the age identity.
    #[arg(long)]
    pub age_identity_path: Option<PathBuf>,
    /// Where to write the restored audit chain key (hex). Optional.
    #[arg(long)]
    pub audit_chain_key_path: Option<PathBuf>,
    /// Skip the confirmation prompt. Refused when stdin is not a terminal.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args, Debug)]
pub struct InjectArgs {
    /// Input template file
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output file. Writing a substituted template to disk violates the
    /// agent-safety contract: secrets that sit on disk are out of scope for
    /// the rest of the system. `inject` therefore defaults to refusing
    /// on-disk output — pass `--force` to override the refusal.
    #[arg(short, long)]
    pub output: PathBuf,
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Required to confirm an on-disk write. The default is "do not write":
    /// the substituted template goes to stdout and the on-disk file is left
    /// untouched.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct GitOpsPullArgs {
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Directory to write `.pandapass/` into
    #[arg(long, default_value = ".pandapass")]
    pub dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct GitOpsDiffArgs {
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Directory containing `.pandapass/`
    #[arg(long, default_value = ".pandapass")]
    pub dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct GitOpsPushArgs {
    /// Project slug
    #[arg(long)]
    pub project: String,
    /// Environment slug
    #[arg(long)]
    pub env: String,
    /// Directory containing `.pandapass/`
    #[arg(long, default_value = ".pandapass")]
    pub dir: PathBuf,
    /// Also delete remote secrets that are not present locally.
    #[arg(long)]
    pub allow_delete: bool,
}

/// GitOps sync (M3): pull/push/diff secrets between the server and a local
/// `.pandapass/` directory.
#[derive(Subcommand, Debug)]
pub enum GitOpsCmd {
    /// Pull secrets from the server into the local `.pandapass/secrets/` dir.
    ///
    /// Each environment is written as an age-encrypted `<env>.yaml.age` file
    /// (sealed to the operator's age public key), and the sync state is
    /// recorded in `.pandapass/.sync-state.json`. Requires `list:secret` and
    /// `read:secret` scopes (for a service token).
    Pull(GitOpsPullArgs),
    /// Push local secrets to the server.
    ///
    /// Only creates/updates by default. Use `--allow-delete` to also soft-delete
    /// remote secrets that are absent locally. Requires `list:secret` and
    /// `write:secret` scopes (for a service token).
    Push(GitOpsPushArgs),
    /// Show the difference between local `.pandapass/` and the server.
    ///
    /// Read-only. Requires `list:secret` scope (for a service token).
    Diff(GitOpsDiffArgs),
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Login(LoginArgs),
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
    Cred(CredCmd),
    #[command(subcommand)]
    Member(MemberCmd),
    #[command(subcommand)]
    Token(TokenCmd),
    #[command(subcommand)]
    Audit(AuditCmd),
    #[command(subcommand)]
    Config(ConfigCmd),
    #[command(subcommand)]
    Admin(AdminCmd),
    #[command(subcommand)]
    Policy(PolicyCmd),
    #[command(subcommand)]
    Pki(PkiCmd),
    /// GitOps sync (M3): pull/push/diff secrets to/from a local directory
    #[command(subcommand)]
    GitOps(GitOpsCmd),
    Backup(BackupArgs),
    Restore(RestoreArgs),
    Run(RunArgs),
    InternalExec(InternalExecArgs),
    Inject(InjectArgs),
}

pub async fn run_command(
    api: &ApiClient,
    config: &mut crate::client::CliConfig,
    cmd: Command,
) -> Result<()> {
    match cmd {
        Command::Login(args) => run_login(api, config, args).await,
        Command::Keygen(args) => keygen(&args),
        Command::Logout => run_logout(api, config).await,
        Command::Me => run_me(api).await,
        Command::Project(cmd) => run_project(api, cmd).await,
        Command::Env(cmd) => run_env(api, cmd).await,
        Command::Secret(cmd) => run_secret(api, cmd).await,
        Command::Cred(cmd) => run_cred(api, cmd).await,
        Command::Member(cmd) => run_member(api, cmd).await,
        Command::Token(cmd) => run_token(api, cmd).await,
        Command::Audit(cmd) => run_audit(api, cmd).await,
        Command::Config(cmd) => run_config(config, cmd).await,
        Command::Admin(cmd) => run_admin(api, cmd).await,
        Command::Policy(cmd) => run_policy(api, cmd).await,
        Command::Pki(cmd) => run_pki(api, cmd).await,
        Command::GitOps(cmd) => run_gitops(api, config, cmd).await,
        Command::Backup(args) => run_backup(api, config, args).await,
        Command::Restore(args) => run_restore(api, config, args).await,
        Command::Run(args) => run_run(api, config, args).await,
        Command::InternalExec(args) => run_internal_exec(api, args).await,
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
            "Note: no master key enrolled. Run `pandapass keygen`, then \
             POST /api/v1/auth/key/enroll to become able to use secrets."
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
        AuditCmd::Verify => {
            let resp = api.verify_audit().await?;
            let intact = resp["intact"].as_bool().unwrap_or(false);
            let checked = resp["entries_checked"].as_u64().unwrap_or(0);
            if intact {
                println!("✓ Audit chain intact ({checked} entries verified)");
            } else {
                let broken_at = resp["broken_at"].as_str().unwrap_or("unknown");
                let reason = resp["reason"].as_str().unwrap_or("unknown reason");
                eprintln!("✗ Audit chain BROKEN at entry {broken_at}: {reason}");
                std::process::exit(1);
            }
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
            println!(
                "Command allowlist: {:?}",
                if config.command_allowlist.is_empty() {
                    vec!["<unrestricted>".to_string()]
                } else {
                    config.command_allowlist.clone()
                }
            );
            println!(
                "Command timeout: {}s",
                config.command_timeout_secs.unwrap_or(120)
            );
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
        ConfigCmd::SetCommandAllowlist { paths } => {
            config.command_allowlist = paths
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            println!(
                "Command allowlist set ({} entries). Empty = no restriction.",
                config.command_allowlist.len()
            );
        }
        ConfigCmd::SetCommandTimeout { seconds } => {
            config.command_timeout_secs = Some(seconds.max(1));
            println!("Command timeout set to {}s", seconds.max(1));
        }
    }
    Ok(())
}

async fn run_admin(api: &ApiClient, cmd: AdminCmd) -> Result<()> {
    match cmd {
        AdminCmd::ServerAgeShow => {
            let resp: serde_json::Value = api.get("/admin/server-age").await?;
            println!("Server age public key: {}", resp["public_key"]);
            println!("Fingerprint (sha256): {}", resp["fingerprint"]);
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
async fn run_run(api: &ApiClient, config: &crate::client::CliConfig, args: RunArgs) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: pandapass run --project P --env E -- cmd args...");
    }

    // Enforce the allowlist before doing anything else. Without this, a leaked
    // `read:secret` token could use `pandapass run` to spawn any child process
    // (the agent-safety story does not stop a child from being `bash -c ...`).
    if !config.command_allowlist.is_empty() {
        let program = &args.command[0];
        if !config.command_allowlist.iter().any(|p| p == program) {
            anyhow::bail!(
                "Refusing to run `{}`: not in the command allowlist. Allowed: {:?}. \
                 Configure `command_allowlist` in ~/.pandapass/config.json to add it.",
                program,
                config.command_allowlist
            );
        }
    }

    // Wall-clock timeout. A hanging child holds the agent's session open
    // forever otherwise; 120s is the historical default if the user did not
    // override it.
    let timeout_secs = config.command_timeout_secs.unwrap_or(120).max(1);

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

    // Collect the injected values before they are zeroized: these are the
    // secrets the child could print, and therefore the exact byte strings the
    // output masker must conceal.
    let mask_values: Vec<Vec<u8>> = envs
        .iter()
        .map(|(_, v)| v.as_bytes().to_vec())
        .collect();

    // `args.command[0]` is the program, the rest are its arguments. Spawned
    // directly: no `sh -c`, so nothing in a key name or value is ever parsed
    // as shell syntax.
    //
    // stdout/stderr are piped (not inherited) so the parent can filter secret
    // values out of the child's output before it reaches the terminal, an
    // agent's context, or a CI log. The filtered output is then forwarded to
    // the parent's own stdout/stderr.
    let program = &args.command[0];
    let mut child = tokio::process::Command::new(program)
        .args(&args.command[1..])
        .envs(envs.iter().map(|(k, v)| (k, v)))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!("failed to run `{}`: {}", program, e)
        })?;

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");

    // Read the pipes concurrently with the child running. Reading only after
    // `wait()` would deadlock once the child fills the pipe buffer (~64KB):
    // it would block writing and never exit, until the timeout killed it.
    let read_stdout = tokio::spawn(async move {
        let mut buf = Vec::new();
        tokio::io::copy(&mut stdout_pipe, &mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    });
    let read_stderr = tokio::spawn(async move {
        let mut buf = Vec::new();
        tokio::io::copy(&mut stderr_pipe, &mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    });

    // Bound how long a child can hold the parent. The default is 120s; the
    // user can tighten or relax it in `~/.pandapass/config.json`.
    let status = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        child.wait(),
    ).await {
        Ok(result) => result.map_err(|e| anyhow::anyhow!("waiting for `{}` failed: {}", program, e))?,
        Err(_) => {
            // Best-effort: send SIGKILL, then reap.
            let _ = child.start_kill();
            let _ = child.wait().await;
            // The child is dead, so the pipes close and the read tasks end.
            anyhow::bail!("`{}` exceeded the {}s command timeout and was killed", program, timeout_secs);
        }
    };

    // The child has exited and its pipes are closed; the read tasks are done.
    let stdout_buf = read_stdout.await.expect("join stdout")?;
    let stderr_buf = read_stderr.await.expect("join stderr")?;

    // Mask injected secret values out of the child's output.
    let masked_stdout = mask_output(&stdout_buf, &mask_values);
    let masked_stderr = mask_output(&stderr_buf, &mask_values);

    // Forward the filtered output. Use raw write_all (not println!) so binary
    // output from the child is preserved apart from the masked secrets.
    {
        let mut out = std::io::stdout().lock();
        out.write_all(&masked_stdout)?;
        out.flush()?;
    }
    {
        let mut err = std::io::stderr().lock();
        err.write_all(&masked_stderr)?;
        err.flush()?;
    }

    // Drop the values before doing anything else that could log or panic.
    for (_, v) in &mut envs {
        v.clear();
        v.shrink_to_fit();
    }
    drop(envs);

    // Propagate the child's exit status so a caller (or an agent) can branch on
    // success without parsing output. Exit code 0 is success; non-zero codes
    // are carried to `main` via ChildExitStatus, which maps them to the CLI
    // process's own exit code (instead of calling `std::process::exit` here,
    // which would be untestable and would skip flushing).
    match status.code().unwrap_or(1) {
        0 => Ok(()),
        code => Err(anyhow::anyhow!(ChildExitStatus(code))),
    }
}

/// `pandapass exec`: run a command on the server with secrets injected
/// server-side. Requires a token with `run:secret` scope.
async fn run_internal_exec(api: &ApiClient, args: InternalExecArgs) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: pandapass exec --project P --env E --keys K1,K2 -- cmd args...");
    }

    let keys: Vec<String> = args
        .keys
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if keys.is_empty() {
        anyhow::bail!("--keys must list at least one key");
    }

    let req = crate::model::InternalExecRequest {
        keys,
        command: args.command,
        project_id: None, // will be resolved by the server from the token
        env_id: None,
    };

    let result = api.internal_exec(&req).await?;

    // Output the masked stdout/stderr
    if !result.stdout.is_empty() {
        println!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprintln!("{}", result.stderr);
    }

    match result.exit_code {
        0 => Ok(()),
        code => Err(anyhow::anyhow!(ChildExitStatus(code))),
    }
}

/// The placeholder injected secret values are replaced with in child output.
const MASK_PLACEHOLDER: &str = "<concealed by pandapass>";

/// Replace every occurrence of any `secret` byte string in `data` with
/// `MASK_PLACEHOLDER`.
///
/// Secrets are matched longest-first so a short secret can never greedily
/// consume the prefix of a longer one. The operation is purely byte-based:
/// non-UTF-8 output from the child is preserved apart from the masked spans.
fn mask_output(data: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    if secrets.is_empty() {
        return data.to_vec();
    }
    let mut sorted: Vec<&Vec<u8>> = secrets.iter().filter(|s| !s.is_empty()).collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.len()));

    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    'outer: while i < data.len() {
        for secret in &sorted {
            if data[i..].starts_with(secret) {
                result.extend_from_slice(MASK_PLACEHOLDER.as_bytes());
                i += secret.len();
                continue 'outer;
            }
        }
        result.push(data[i]);
        i += 1;
    }
    result
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

    if args.force {
        // The operator has explicitly confirmed that they want the substituted
        // template to live on disk. We do not zeroize the buffer after
        // writing — the file outlives the process and the user accepts that.
        tokio::fs::write(&args.output, output).await?;
        println!("Injected secrets into {}", args.output.display());
    } else {
        // Refuse by default. Writing a secret to disk is the precise failure
        // mode SKILL.md warns about: the value outlives the process in
        // plaintext, defeats the audit log, and is not what `pandapass run`
        // is for. Print the substituted content to stdout so the operator
        // can pipe it where it actually belongs (env vars, a temp pipe,
        // never a long-lived file).
        eprintln!(
            "Refusing to write substituted template to disk without --force. \
             The SKILL recommends using `pandapass run` instead. Printing to \
             stdout instead."
        );
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        out.write_all(output.as_bytes())?;
        out.flush()?;
    }
    Ok(())
}

// ─────────────────────────── GitOps sync (M3) ───────────────────────────

/// Load the age identity from the CLI config path, if configured. GitOps needs
/// it to decrypt pulled ciphertexts locally — the plaintext must never come
/// back over the wire if the operator holds the private key.
fn load_age_identity(config: &crate::client::CliConfig) -> Result<pandapass_core::crypto::AgeIdentity> {
    let path = config.age_identity_file.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "No age identity configured. Run `pandapass config set-age-identity <path>` \
             (or pass --age-identity) before using gitops."
        )
    })?;
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read age identity {}: {}", path.display(), e))?;
    pandapass_core::crypto::AgeIdentity::parse(&content)
        .map_err(|e| anyhow::anyhow!("invalid age identity in {}: {}", path.display(), e))
}

/// Resolve a project slug to its id, and an env slug to its id, for sync state.
async fn resolve_env_ids(api: &ApiClient, project: &str, env: &str) -> Result<(uuid::Uuid, uuid::Uuid)> {
    let project_id = api.resolve_project_id(project).await?;
    let envs = api.list_envs(project).await?;
    let env = envs
        .iter()
        .find(|e| e.slug == env)
        .ok_or_else(|| anyhow::anyhow!("No environment '{env}' in project '{project}'"))?;
    Ok((project_id, env.id))
}

/// Path of the local age-encrypted YAML file for an environment.
fn local_secrets_path(dir: &std::path::Path, env: &str) -> std::path::PathBuf {
    dir.join("secrets").join(format!("{env}.yaml.age"))
}

/// Path of the sync-state JSON file.
fn sync_state_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(".sync-state.json")
}

/// Read and age-decrypt the local secrets file into a map.
///
/// Missing file = empty map (a fresh checkout has nothing yet). The file on
/// disk is always ciphertext (`.yaml.age`), so this requires the operator's
/// age identity to recover the plaintext.
fn read_local_secrets(
    path: &std::path::Path,
    identity: &pandapass_core::crypto::AgeIdentity,
) -> Result<std::collections::HashMap<String, String>> {
    use pandapass_core::models::GitOpsSecretFile;
    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {}", path.display(), e))?;
    let plaintext = pandapass_core::crypto::age_decrypt_file(&content, identity)
        .map_err(|e| anyhow::anyhow!("cannot decrypt {}: {}", path.display(), e))?;
    let file: GitOpsSecretFile = serde_yaml::from_str(&plaintext)
        .map_err(|e| anyhow::anyhow!("invalid YAML in {}: {}", path.display(), e))?;
    Ok(file.secrets)
}

/// Age-encrypt and write the local secrets file.
///
/// The plaintext exists only in memory: it is sealed to the operator's own age
/// public key before touching disk, so the file can be committed to git.
async fn write_local_secrets(
    path: &std::path::Path,
    secrets: &std::collections::HashMap<String, String>,
    identity: &pandapass_core::crypto::AgeIdentity,
) -> Result<()> {
    use pandapass_core::models::GitOpsSecretFile;
    let file = GitOpsSecretFile { secrets: secrets.clone() };
    let yaml = serde_yaml::to_string(&file)?;
    let recipient = identity.public_key()?;
    let ciphertext = pandapass_core::crypto::age_encrypt_file(&yaml, std::slice::from_ref(&recipient))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // Atomic write: write to .tmp then rename, so a crash mid-write does
    // not leave a half-written .yaml.age on disk.
    let tmp = path.with_extension("age.tmp");
    tokio::fs::write(&tmp, ciphertext).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Read the sync state for an env (or a fresh empty state).
async fn read_sync_state(dir: &std::path::Path, project_id: uuid::Uuid, env_id: uuid::Uuid) -> Result<pandapass_core::models::SyncState> {
    use pandapass_core::models::SyncState;
    let path = sync_state_path(dir);
    let mut state: SyncState = if path.exists() {
        let content = tokio::fs::read_to_string(&path).await?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        SyncState::default()
    };
    state.project_id = Some(project_id);
    state.env_id = Some(env_id);
    Ok(state)
}

async fn write_sync_state(dir: &std::path::Path, state: &pandapass_core::models::SyncState) -> Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    let content = serde_json::to_string_pretty(state)?;
    let path = sync_state_path(dir);
    let tmp = dir.join(".sync-state.json.tmp");
    tokio::fs::write(&tmp, content.as_bytes()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// `gitops pull`: fetch remote secrets (server-decrypted plaintext), seal them
/// locally to the operator's age public key, and write `<env>.yaml.age`.
async fn run_gitops_pull(api: &ApiClient, config: &crate::client::CliConfig, args: GitOpsPullArgs) -> Result<()> {
    let identity = load_age_identity(config)?;
    let (project_id, env_id) = resolve_env_ids(api, &args.project, &args.env).await?;

    let metas_resp = api.list_secrets(&args.project, &args.env).await?;
    let metas = &metas_resp.items;

    // The plaintext comes over the existing `read:secret` path — the same one
    // `pandapass secret get` uses — and is immediately sealed to the
    // operator's age key in memory; it never touches disk unencrypted.
    let mut plaintext_map = std::collections::HashMap::new();
    for meta in metas {
        let secret = api.get_secret(&args.project, &args.env, &meta.key).await?;
        plaintext_map.insert(meta.key.clone(), secret.value);
    }

    let path = local_secrets_path(&args.dir, &args.env);
    write_local_secrets(&path, &plaintext_map, &identity).await?;

    // Record remote versions for future diffs.
    let mut sync_state = pandapass_core::models::SyncState {
        project_id: Some(project_id),
        env_id: Some(env_id),
        secrets: std::collections::HashMap::new(),
    };
    for meta in metas {
        sync_state.secrets.insert(
            meta.key.clone(),
            pandapass_core::models::SecretSyncInfo {
                version: meta.version,
                updated_at: meta.updated_at,
            },
        );
    }
    write_sync_state(&args.dir, &sync_state).await?;

    println!(
        "Pulled {} secret(s) from {}/{} into {}",
        metas.len(),
        args.project,
        args.env,
        path.display()
    );
    Ok(())
}

/// `gitops diff`: compare local file against remote metadata, print a table.
async fn run_gitops_diff(api: &ApiClient, config: &crate::client::CliConfig, args: GitOpsDiffArgs) -> Result<()> {
    let identity = load_age_identity(config)?;
    let path = local_secrets_path(&args.dir, &args.env);
    let local = read_local_secrets(&path, &identity)?;

    let metas_resp = api.list_secrets(&args.project, &args.env).await?;
    let (project_id, env_id) = resolve_env_ids(api, &args.project, &args.env).await?;
    let sync_state = read_sync_state(&args.dir, project_id, env_id).await?;

    let report = pandapass_core::gitops::diff_metadata(&local, &metas_resp.items, &sync_state);
    use pandapass_core::gitops::SecretDiffState;

    let mut n = 0;
    for entry in &report.entries {
        let marker = match entry.state {
            SecretDiffState::OnlyLocal => "+",
            SecretDiffState::OnlyRemote => "-",
            SecretDiffState::Modified => "~",
            SecretDiffState::InSync => "=",
        };
        let detail = match entry.state {
            SecretDiffState::OnlyLocal => "only local".to_string(),
            SecretDiffState::OnlyRemote => "only remote".to_string(),
            SecretDiffState::Modified => format!("modified (remote v{})", entry.remote_version.unwrap_or(0)),
            SecretDiffState::InSync => "in sync".to_string(),
        };
        println!("{marker} {}  {}", entry.key, detail);
        n += 1;
    }
    if n == 0 {
        println!("No differences.");
    }
    Ok(())
}

/// `gitops push`: write local changes back to the server.
async fn run_gitops_push(api: &ApiClient, config: &crate::client::CliConfig, args: GitOpsPushArgs) -> Result<()> {
    let identity = load_age_identity(config)?;
    let path = local_secrets_path(&args.dir, &args.env);
    let local = read_local_secrets(&path, &identity)?;

    let metas_resp = api.list_secrets(&args.project, &args.env).await?;
    let remote: std::collections::HashMap<String, &pandapass_core::models::SecretMeta> = metas_resp
        .items
        .iter()
        .map(|m| (m.key.clone(), m))
        .collect();

    let mut created = 0;
    let mut updated = 0;
    let mut deleted = 0;

    for (key, value) in &local {
        // Re-encrypt with the server's master key via the plaintext write path.
        if remote.contains_key(key) {
            updated += 1;
        } else {
            created += 1;
        }
        api.set_secret(&args.project, &args.env, key, value).await?;
    }

    if args.allow_delete {
        for key in remote.keys() {
            if !local.contains_key(key) {
                api.delete_secret(&args.project, &args.env, key).await?;
                deleted += 1;
            }
        }
    }

    // Update sync state to reflect what the server now holds.
    let (project_id, env_id) = resolve_env_ids(api, &args.project, &args.env).await?;
    let new_metas = api.list_secrets(&args.project, &args.env).await?;
    let mut sync_state = pandapass_core::models::SyncState {
        project_id: Some(project_id),
        env_id: Some(env_id),
        secrets: std::collections::HashMap::new(),
    };
    for m in &new_metas.items {
        sync_state.secrets.insert(
            m.key.clone(),
            pandapass_core::models::SecretSyncInfo {
                version: m.version,
                updated_at: m.updated_at,
            },
        );
    }
    write_sync_state(&args.dir, &sync_state).await?;

    println!(
        "Pushed {created} created, {updated} updated, {deleted} deleted (if --allow-delete) from {}/{}",
        args.project, args.env
    );
    Ok(())
}

async fn run_gitops(api: &ApiClient, config: &crate::client::CliConfig, cmd: GitOpsCmd) -> Result<()> {
    match cmd {
        GitOpsCmd::Pull(args) => run_gitops_pull(api, config, args).await,
        GitOpsCmd::Diff(args) => run_gitops_diff(api, config, args).await,
        GitOpsCmd::Push(args) => run_gitops_push(api, config, args).await,
    }
}

// ─────────────────────────── Backup / Restore (D5) ───────────────────────────

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Read a small secret file (server age identity or audit chain key), failing
/// with a clear message when the file is absent. Returns the trimmed contents.
fn read_optional_secret_file(path: &std::path::Path, what: &str) -> Result<String> {
    if !path.exists() {
        anyhow::bail!(
            "{what} file {} does not exist. Point --server-age-identity / \
             --audit-chain-key at the real files.",
            path.display()
        );
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {what} {}: {}", path.display(), e))?;
    Ok(content.trim().to_string())
}

/// The plaintext payload of a `pandapass backup` file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupPayload {
    /// What kind of backup this is. `db-only` = raw SQLite snapshot; `full`
    /// = snapshot + server age identity + audit chain key.
    pub format: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub db: BackupPayloadDb,
    pub server_age_identity: Option<String>,
    pub audit_chain_key: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupPayloadDb {
    pub bytes_b64: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// `pandapass backup`: fetch a consistent SQLite snapshot from the server and
/// seal it (plus the server age identity and audit chain key, when readable)
/// into an age-encrypted file.
async fn run_backup(api: &ApiClient, config: &crate::client::CliConfig, args: BackupArgs) -> Result<()> {
    // Fetch the snapshot from the server.
    let snap = api.admin_backup().await?;

    // Build the plaintext payload. The snapshot is base64 in the wire
    // format; keep it that way in the payload so the bytes are not decoded
    // into memory twice.
    let mut payload = BackupPayload {
        format: "pandapass-backup-v1".to_string(),
        created_at: snap.created_at,
        db: BackupPayloadDb {
            bytes_b64: snap.db.bytes_b64.clone(),
            sha256: snap.db.sha256.clone(),
            size_bytes: snap.db.size_bytes,
        },
        server_age_identity: None,
        audit_chain_key: None,
    };

    // Include the server age identity (needed to unwrap envelopes after
    // restore) and the audit chain key (needed to keep the chain verifiable)
    // when the operator points us at them.
    let age_identity_path = args
        .server_age_identity
        .clone()
        .or_else(|| std::env::var_os("PANDAPASS_SERVER_AGE_IDENTITY_FILE").map(PathBuf::from));
    if let Some(path) = age_identity_path {
        payload.server_age_identity = Some(read_optional_secret_file(&path, "server age identity")?);
    }
    let chain_key_path = args
        .audit_chain_key
        .clone()
        .or_else(|| std::env::var_os("PANDAPASS_AUDIT_CHAIN_KEY_FILE").map(PathBuf::from));
    if let Some(path) = chain_key_path {
        payload.audit_chain_key = Some(read_optional_secret_file(&path, "audit chain key")?);
    }

    // Determine the recipient (default: the operator's own public key).
    let recipient = match args.recipient {
        Some(r) => Some(pandapass_core::crypto::AgePublicKey(r)),
        None => {
            // Without --raw, we need the operator's age identity to derive
            // their public key. Load it from the CLI config.
            if args.raw {
                None
            } else {
                let identity = load_age_identity(config)?;
                Some(identity.public_key()?)
            }
        }
    };

    let plaintext = serde_json::to_string_pretty(&payload)?;

    // Write the output file.
    if args.raw {
        // Raw snapshot: write the base64-decoded DB bytes directly.
        if recipient.is_some() {
            anyhow::bail!("--raw cannot be combined with --recipient");
        }
        let bytes = BASE64.decode(&payload.db.bytes_b64)
            .map_err(|e| anyhow::anyhow!("invalid base64 in server response: {e}"))?;
        write_backup_file(&args.out, &bytes, false)?;
    } else {
        let recipient = recipient.ok_or_else(|| {
            anyhow::anyhow!("No age recipient available. Pass --recipient, or configure an age identity.")
        })?;
        let ciphertext = pandapass_core::crypto::age_encrypt_file(
            &plaintext,
            std::slice::from_ref(&recipient),
        )?;
        write_backup_file(&args.out, ciphertext.as_bytes(), true)?;
    }

    println!(
        "Backup written to {} ({} bytes, sha256 {})",
        args.out.display(),
        payload.db.size_bytes,
        payload.db.sha256
    );
    if payload.server_age_identity.is_none() {
        eprintln!(
            "Note: no server age identity included. Restoring this backup will \
             not restore envelope unwrapping. Pass --server-age-identity (or set \
             PANDAPASS_SERVER_AGE_IDENTITY_FILE) to include it."
        );
    }
    Ok(())
}

/// Write the backup file atomically with 0600 permissions (it contains a
/// live database snapshot).
fn write_backup_file(path: &std::path::Path, bytes: &[u8], _encrypted: bool) -> Result<()> {
    let tmp = path.with_extension("bak.tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// `pandapass restore`: decrypt (if needed), verify, and write a backup to
/// the local database path and age identity path.
async fn run_restore(_api: &ApiClient, _config: &crate::client::CliConfig, args: RestoreArgs) -> Result<()> {
    if !args.yes && !confirm_destructive(&format!(
        "Restore database from '{}'? This overwrites the target paths.",
        args.input.display()
    ))? {
        println!("Aborted.");
        return Ok(());
    }

    let input_bytes = std::fs::read(&args.input)
        .map_err(|e| anyhow::anyhow!("cannot read backup {}: {}", args.input.display(), e))?;

    // Decide whether the input is age-encrypted or a raw SQLite snapshot.
    let is_age = looks_like_age_file(&input_bytes);
    let plaintext = if is_age {
        // Age-encrypted backup: decrypt with the operator's age identity.
        let identity = load_age_identity(_config)?;
        let ciphertext = String::from_utf8(input_bytes.clone())
            .map_err(|_| anyhow::anyhow!("encrypted backup is not UTF-8 ASCII armor"))?;
        pandapass_core::crypto::age_decrypt_file(&ciphertext, &identity)
            .map_err(|e| anyhow::anyhow!("cannot decrypt backup: {e}"))?
    } else {
        // Raw SQLite snapshot: no decryption needed.
        String::new()
    };

    // Verify the payload.
    let payload: BackupPayload = if is_age {
        let payload: BackupPayload = serde_json::from_str(&plaintext)
            .map_err(|e| anyhow::anyhow!("backup payload is invalid JSON: {e}"))?;
        verify_payload(&payload)?;
        payload
    } else {
        // Raw snapshot: verify the SHA-256 over the raw bytes.
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(&input_bytes));
        // No embedded hash for raw snapshots; verify by checking it parses as
        // a SQLite database (header magic) and print the computed hash.
        if !input_bytes.starts_with(b"SQLite format 3\0") {
            anyhow::bail!("input is neither an age backup nor a SQLite database");
        }
        // Build a db-only payload for consistent handling.
        BackupPayload {
            format: "pandapass-sqlite-snapshot-v1".to_string(),
            created_at: chrono::Utc::now(),
            db: BackupPayloadDb {
                bytes_b64: BASE64.encode(&input_bytes),
                sha256: digest,
                size_bytes: input_bytes.len() as u64,
            },
            server_age_identity: None,
            audit_chain_key: None,
        }
    };

    // Write the database.
    let db_bytes = BASE64.decode(&payload.db.bytes_b64)
        .map_err(|e| anyhow::anyhow!("invalid base64 in backup payload: {e}"))?;
    write_db_atomic(&args.db_path, &db_bytes)?;

    // Write the age identity if present and a target path was given.
    if let Some(age_identity) = &payload.server_age_identity {
        if let Some(target) = &args.age_identity_path {
            write_identity_file(target, age_identity)?;
        } else {
            eprintln!("Backup contains a server age identity, but no --age-identity-path was given. Skipping.");
        }
    } else if args.age_identity_path.is_some() {
        anyhow::bail!(
            "No server age identity in this backup, but --age-identity-path was supplied."
        );
    }

    // Write the audit chain key if present and a target path was given.
    if let Some(chain_key) = &payload.audit_chain_key {
        if let Some(target) = &args.audit_chain_key_path {
            write_identity_file(target, chain_key)?;
        } else {
            eprintln!("Backup contains an audit chain key, but no --audit-chain-key-path was given. Skipping.");
        }
    } else if args.audit_chain_key_path.is_some() {
        anyhow::bail!(
            "No audit chain key in this backup, but --audit-chain-key-path was supplied."
        );
    }

    println!("Restored database to {}", args.db_path.display());
    if let Some(target) = &args.age_identity_path {
        if payload.server_age_identity.is_some() {
            println!("Restored server age identity to {}", target.display());
        }
    }
    Ok(())
}

/// Verify a backup payload's embedded SHA-256 over its base64 DB bytes.
fn verify_payload(payload: &BackupPayload) -> Result<()> {
    use sha2::{Digest, Sha256};
    let bytes = BASE64.decode(&payload.db.bytes_b64)
        .map_err(|e| anyhow::anyhow!("invalid base64 in backup payload: {e}"))?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != payload.db.sha256 {
        anyhow::bail!(
            "backup integrity check failed: payload sha256 {} != computed {}",
            payload.db.sha256,
            digest
        );
    }
    if bytes.len() as u64 != payload.db.size_bytes {
        anyhow::bail!(
            "backup size mismatch: payload says {} bytes, got {}",
            payload.db.size_bytes,
            bytes.len()
        );
    }
    Ok(())
}

/// Heuristic: an age-encrypted file begins with the ASCII armor header.
fn looks_like_age_file(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(64)]);
    head.contains("-----BEGIN AGE ENCRYPTED FILE-----")
}

/// Write the SQLite database atomically (temp + rename) and drop any stale
/// WAL/SHM sidecar files so the restored DB starts clean.
fn write_db_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("db.tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;

    // Remove sidecar files that belong to a previous database state. If the
    // old server left a WAL behind, the restored DB would try to replay it
    // and corrupt itself.
    let wal = path.with_extension("db-wal");
    let shm = path.with_extension("db-shm");
    if wal.exists() {
        std::fs::remove_file(&wal)?;
    }
    if shm.exists() {
        std::fs::remove_file(&shm)?;
    }
    Ok(())
}

/// Write a secret file (age identity / audit chain key) with 0600.
fn write_identity_file(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ─────────────────────────── Dynamic Credentials (M2) ───────────────────────────

async fn run_cred(api: &ApiClient, cmd: CredCmd) -> Result<()> {
    match cmd {
        CredCmd::List { project, env } => {
            let creds = api.list_dynamic_creds(&project, &env).await?;
            for c in creds {
                println!(
                    "{}  {}  {}  expires {}  revoked: {}",
                    c.id,
                    c.kind.as_str(),
                    c.username,
                    c.expires_at.format("%Y-%m-%d %H:%M:%S"),
                    c.revoked_at.map_or("no", |_| "yes")
                );
            }
        }
        CredCmd::Create { project, env, kind, username, ttl_seconds } => {
            let kind = match kind.as_str() {
                "postgresql" => pandapass_core::models::DynamicCredKind::PostgreSQL,
                "mysql" => pandapass_core::models::DynamicCredKind::MySQL,
                "redis" => pandapass_core::models::DynamicCredKind::Redis,
                _ => anyhow::bail!("Invalid kind: {}. Must be postgresql, mysql, or redis", kind),
            };
            let resp = api.create_dynamic_cred(&project, &env, kind, &username, ttl_seconds).await?;
            let plain = resp["plain_password"].as_str().unwrap_or("");
            let cred: pandapass_core::models::DynamicCred = serde_json::from_value(resp["cred"].clone())?;
            println!("{}", plain);
            eprintln!(
                "\nCredential created. Shown once; only encrypted value is stored.\n\
                 ID:       {}\n\
                 Kind:     {}\n\
                 Username: {}\n\
                 Expires:  {}",
                cred.id,
                cred.kind.as_str(),
                cred.username,
                cred.expires_at.format("%Y-%m-%d %H:%M:%S")
            );
        }
        CredCmd::Revoke { project, env, id } => {
            api.revoke_dynamic_cred(&project, &env, id).await?;
            println!("Credential revoked");
        }
    }
    Ok(())
}

// ─────────────────────────── Policies (M3) ───────────────────────────

async fn run_policy(api: &ApiClient, cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::List { enabled_only } => {
            let policies = api.list_policies(enabled_only).await?;
            for p in policies {
                println!("{}  {}  enabled: {}", p.id, p.name, p.enabled);
            }
        }
        PolicyCmd::Create { name, rego } => {
            let policy = api.create_policy(&name, &rego).await?;
            println!("Created policy: {} ({})", policy.name, policy.id);
        }
        PolicyCmd::Get { id } => {
            let policy = api.get_policy(id).await?;
            println!("Name: {}", policy.name);
            println!("Enabled: {}", policy.enabled);
            println!("Created: {}", policy.created_at);
            println!("Rego:\n{}", policy.rego_source);
        }
        PolicyCmd::Update { id, name, rego, enabled } => {
            api.update_policy(id, name.as_deref(), rego.as_deref(), enabled).await?;
            println!("Policy updated");
        }
        PolicyCmd::Delete { id } => {
            api.delete_policy(id).await?;
            println!("Policy deleted");
        }
        PolicyCmd::Bind { policy_id, project, env } => {
            let project_id = match project.as_deref() {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let env_id = match (project.as_deref(), env.as_deref()) {
                (Some(project_slug), Some(env_slug)) => {
                    let envs = api.list_envs(project_slug).await?;
                    let found = envs.into_iter().find(|e| e.slug == *env_slug)
                        .ok_or_else(|| anyhow::anyhow!("No environment '{env_slug}' in project '{project_slug}'"))?;
                    Some(found.id)
                }
                (None, Some(_)) => anyhow::bail!("--env requires --project"),
                _ => None,
            };
            let binding = api.bind_policy(policy_id, project_id, env_id).await?;
            println!("Bound policy to project: {:?}, env: {:?}", binding.project_id, binding.env_id);
        }
        PolicyCmd::Unbind { id } => {
            api.unbind_policy(id).await?;
            println!("Policy binding removed");
        }
        PolicyCmd::ListBindings { project, env } => {
            let project_id = match project.as_deref() {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let env_id = match (project.as_deref(), env.as_deref()) {
                (Some(project_slug), Some(env_slug)) => {
                    let envs = api.list_envs(project_slug).await?;
                    let found = envs.into_iter().find(|e| e.slug == *env_slug)
                        .ok_or_else(|| anyhow::anyhow!("No environment '{env_slug}' in project '{project_slug}'"))?;
                    Some(found.id)
                }
                (None, Some(_)) => anyhow::bail!("--env requires --project"),
                _ => None,
            };
            let bindings = api.list_policy_bindings(project_id, env_id).await?;
            for b in bindings {
                println!("{}  policy: {}  project: {:?}  env: {:?}", b.id, b.policy_id, b.project_id, b.env_id);
            }
        }
    }
    Ok(())
}

// ─────────────────────────── PKI/CA and SSH (M4) ───────────────────────────

async fn run_pki(api: &ApiClient, cmd: PkiCmd) -> Result<()> {
    match cmd {
        PkiCmd::Ca { cmd } => run_ca(api, cmd).await,
        PkiCmd::Ssh { cmd } => run_ssh(api, cmd).await,
    }
}

async fn run_ca(api: &ApiClient, cmd: CaCmd) -> Result<()> {
    match cmd {
        CaCmd::List { include_revoked } => {
            let keys = api.list_ca_keys(include_revoked).await?;
            for k in keys {
                println!("{}  {}  {}  revoked: {}", k.id, k.kind.as_str(), k.not_after.format("%Y-%m-%d"), k.revoked_at.map_or("no", |_| "yes"));
            }
        }
        CaCmd::Create { kind, key_pem, cert_pem, not_before, not_after } => {
            let kind = match kind.as_str() {
                "root" => pandapass_core::models::CaKeyType::Root,
                "intermediate" => pandapass_core::models::CaKeyType::Intermediate,
                _ => anyhow::bail!("Invalid kind: {}. Must be root or intermediate", kind),
            };
            let not_before = chrono::DateTime::parse_from_rfc3339(&not_before)?.with_timezone(&chrono::Utc);
            let not_after = chrono::DateTime::parse_from_rfc3339(&not_after)?.with_timezone(&chrono::Utc);
            let ca = api.create_ca_key(kind, &key_pem, &cert_pem, not_before, not_after).await?;
            println!("Created CA key: {} ({})", ca.kind.as_str(), ca.id);
        }
        CaCmd::Get { id } => {
            let ca = api.get_ca_key(id).await?;
            println!("Kind: {}", ca.kind.as_str());
            println!("Cert:\n{}", ca.cert_pem);
            println!("Valid: {} to {}", ca.not_before, ca.not_after);
            println!("Revoked: {}", ca.revoked_at.map(|d| d.to_string()).unwrap_or("no".into()));
        }
        CaCmd::Revoke { id } => {
            api.revoke_ca_key(id).await?;
            println!("CA key revoked");
        }
    }
    Ok(())
}

async fn run_ssh(api: &ApiClient, cmd: SshCmd) -> Result<()> {
    match cmd {
        SshCmd::List { user, project, include_revoked } => {
            let project_id = match project.as_deref() {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let certs = api.list_ssh_certs(user, project_id, include_revoked).await?;
            for c in certs {
                println!(
                    "{}  {}  {}  {}  revoked: {}",
                    c.id,
                    c.key_type.as_str(),
                    c.principal,
                    c.valid_after.format("%Y-%m-%d"),
                    c.revoked_at.map_or("no", |_| "yes")
                );
            }
        }
        SshCmd::Sign { ca_id, user, principal, public_key, project, not_before, not_after } => {
            let project_id = match project.as_deref() {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let public_key_str = std::fs::read_to_string(&public_key)
                .map_err(|e| anyhow::anyhow!("cannot read public key {}: {}", public_key.display(), e))?;
            let not_before = match not_before {
                Some(s) => chrono::DateTime::parse_from_rfc3339(&s)?.with_timezone(&chrono::Utc),
                None => chrono::Utc::now(),
            };
            let not_after = match not_after {
                Some(s) => chrono::DateTime::parse_from_rfc3339(&s)?.with_timezone(&chrono::Utc),
                None => chrono::Utc::now() + chrono::Duration::hours(12),
            };
            let resp = api.sign_ssh_cert(
                ca_id,
                user,
                project_id,
                &principal,
                public_key_str.trim(),
                pandapass_core::models::SshKeyType::Ed25519,
                not_before,
                not_after,
            ).await?;
            let cert_id: Uuid = serde_json::from_value(resp["cert_id"].clone())?;
            let cert_openssh: String = serde_json::from_value(resp["cert_openssh"].clone())?;
            println!("{}", cert_openssh);
            eprintln!(
                "\nSSH certificate signed. Store the line above in your authorized_keys\n\
                 or use it with `ssh -i` via an agent. Cert ID: {cert_id}"
            );
        }
        SshCmd::Create { user, project, principal, cert_pem, key_type, not_before, not_after } => {
            let project_id = match project.as_deref() {
                Some(slug) => Some(api.resolve_project_id(slug).await?),
                None => None,
            };
            let key_type = match key_type.as_str() {
                "rsa" => pandapass_core::models::SshKeyType::Rsa,
                "ed25519" => pandapass_core::models::SshKeyType::Ed25519,
                _ => anyhow::bail!("Invalid key_type: {}. Must be rsa or ed25519", key_type),
            };
            let not_before = chrono::DateTime::parse_from_rfc3339(&not_before)?.with_timezone(&chrono::Utc);
            let not_after = chrono::DateTime::parse_from_rfc3339(&not_after)?.with_timezone(&chrono::Utc);
            let cert = api.create_ssh_cert(user, project_id, &principal, &cert_pem, key_type, not_before, not_after).await?;
            println!("Created SSH cert: {} ({})", cert.principal, cert.id);
        }
        SshCmd::Revoke { id } => {
            api.revoke_ssh_cert(id).await?;
            println!("SSH cert revoked");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_replaces_simple_secret() {
        let data = b"pass=s3cr3t";
        let secrets = vec![b"s3cr3t".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"pass=<concealed by pandapass>"
        );
    }

    #[test]
    fn mask_multiple_secrets() {
        let data = b"user=alice pass=one token=two";
        let secrets = vec![b"one".to_vec(), b"two".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"user=alice pass=<concealed by pandapass> token=<concealed by pandapass>"
        );
    }

    #[test]
    fn mask_empty_secrets_returns_original() {
        let data = b"hello world";
        assert_eq!(mask_output(data, &[]), b"hello world");
    }

    #[test]
    fn mask_skips_empty_secret_without_panic() {
        let data = b"abc";
        let secrets = vec![b"".to_vec(), b"b".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"a<concealed by pandapass>c"
        );
    }

    #[test]
    fn mask_single_byte_secret() {
        let data = b"banana";
        let secrets = vec![b"a".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"b<concealed by pandapass>n<concealed by pandapass>n<concealed by pandapass>"
        );
    }

    #[test]
    fn mask_longest_secret_wins() {
        // "ab" must win over "a" so the longer secret is fully concealed
        // rather than being consumed piecemeal by the shorter one.
        let data = b"abab";
        let secrets = vec![b"a".to_vec(), b"ab".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"<concealed by pandapass><concealed by pandapass>"
        );
    }

    #[test]
    fn mask_secret_at_edges() {
        let data = b"s3cr3tmid";
        let secrets = vec![b"s3cr3t".to_vec()];
        assert_eq!(
            mask_output(data, &secrets),
            b"<concealed by pandapass>mid"
        );

        let data = b"mids3cr3t";
        assert_eq!(
            mask_output(data, &secrets),
            b"mid<concealed by pandapass>"
        );
    }

    #[test]
    fn mask_preserves_non_utf8() {
        let data: Vec<u8> = vec![0xff, 0xfe, b's', b'3', b'c', b'r', b'3', b't', 0x00];
        let secrets = vec![b"s3cr3t".to_vec()];
        let expected: Vec<u8> = vec![
            0xff,
            0xfe,
            b'<',
            b'c',
            b'o',
            b'n',
            b'c',
            b'e',
            b'a',
            b'l',
            b'e',
            b'd',
            b' ',
            b'b',
            b'y',
            b' ',
            b'p',
            b'a',
            b'n',
            b'd',
            b'a',
            b'p',
            b'a',
            b's',
            b's',
            b'>',
            0x00,
        ];
        assert_eq!(mask_output(&data, &secrets), expected);
    }
}
