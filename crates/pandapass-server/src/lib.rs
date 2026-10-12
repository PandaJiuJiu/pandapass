use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::middleware::auth::{require_csrf, ApiError};
use crate::routes::{auth, backup, dynamic, pki, policies, projects, scan, secrets, tokens};
use crate::state::{AppState, StartupInfo};
use pandapass_core::{AuditAction, AuditContext, CommandResult};

pub mod state;

mod routes {
    pub mod auth;
    pub mod backup;
    pub mod dynamic;
    pub mod pki;
    pub mod policies;
    pub mod projects;
    pub mod scan;
    pub mod secrets;
    pub mod tokens;
}

pub mod middleware {
    pub mod auth;
    pub mod rate_limit;
}

pub mod dynamic_proxy;
pub mod dynamic_proxy_redis;

/// Build the main application router
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            state
                .config
                .allowed_origins
                .clone()
                .into_iter()
                .map(|o| o.parse().unwrap())
                .collect::<Vec<_>>(),
        )
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::PATCH,
            http::Method::DELETE,
            http::Method::OPTIONS,
        ])
        .allow_headers([
            http::header::CONTENT_TYPE,
            http::header::AUTHORIZATION,
            http::header::COOKIE,
            "x-csrf-token".parse().unwrap(),
        ])
        .allow_credentials(true);

    // Truly public: credential exchange itself. Everything that touches an
    // existing session belongs in `protected_routes` so it inherits CSRF
    // enforcement — `SameSite=Lax` is a second line of defence, not the only one.
    let public_routes = Router::new()
        .route("/api/v1/health", get(tokens::health))
        .route("/api/v1/setup/status", get(auth::setup_status))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/login", post(auth::login))
        .route(
            "/api/v1/auth/recovery-code/redeem",
            post(auth::recovery_code_redeem),
        )
        .route("/api/v1/auth/password/reset", post(auth::password_reset))
        .route("/metrics", get(tokens::metrics));

    // Protected routes (require auth)
    let protected_routes = Router::new()
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/totp/setup", get(auth::totp_setup))
        .route("/api/v1/auth/totp/verify", post(auth::totp_verify))
        .route("/api/v1/auth/totp/disable", post(auth::totp_disable))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        .route("/api/v1/auth/logout-all", post(auth::logout_all))
        .route("/api/v1/auth/sessions", get(auth::list_my_sessions))
        .route(
            "/api/v1/auth/sessions/{session_id}",
            delete(auth::revoke_my_session),
        )
        .route("/api/v1/auth/key/enroll", post(auth::enroll_key))
        .route("/api/v1/auth/mk/rotate", post(auth::rotate_master_key))
        .route(
            "/api/v1/auth/recovery-codes",
            post(auth::recovery_codes_generate),
        )
        .route(
            "/api/v1/projects",
            get(projects::list_projects).post(projects::create_project),
        )
        .route(
            "/api/v1/projects/{slug}",
            get(projects::get_project)
                .patch(projects::update_project)
                .delete(projects::delete_project),
        )
        .route(
            "/api/v1/projects/{slug}/members",
            get(projects::list_members).post(projects::add_member),
        )
        .route(
            "/api/v1/projects/{slug}/members/{user_id}",
            patch(projects::update_member).delete(projects::remove_member),
        )
        .route(
            "/api/v1/projects/{slug}/envs",
            get(projects::list_envs).post(projects::create_env),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}",
            delete(projects::delete_env),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/secrets",
            get(secrets::list_secrets).post(secrets::set_secret),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/secrets/batch",
            post(secrets::batch_set_secrets),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/secrets/{key}",
            put(secrets::set_secret_at_path)
                .get(secrets::get_secret)
                .delete(secrets::delete_secret),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/secrets/{key}/ciphertext",
            get(secrets::get_secret_encrypted),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/secrets/{key}/versions",
            get(secrets::list_secret_versions),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/creds",
            get(dynamic::list_dynamic_creds).post(dynamic::create_dynamic_cred),
        )
        .route(
            "/api/v1/projects/{slug}/envs/{env_slug}/creds/{id}",
            delete(dynamic::revoke_dynamic_cred),
        )
        .route(
            "/api/v1/policies",
            get(policies::list_policies).post(policies::create_policy),
        )
        .route(
            "/api/v1/policies/{id}",
            get(policies::get_policy)
                .patch(policies::update_policy)
                .delete(policies::delete_policy),
        )
        .route(
            "/api/v1/policies/bindings",
            get(policies::list_policy_bindings).post(policies::bind_policy),
        )
        .route(
            "/api/v1/policies/bindings/{id}",
            delete(policies::unbind_policy),
        )
        .route(
            "/api/v1/ca",
            get(pki::list_ca_keys).post(pki::create_ca_key),
        )
        .route("/api/v1/ca/generate", post(pki::generate_ca_key))
        .route(
            "/api/v1/ca/{id}",
            get(pki::get_ca_key).delete(pki::revoke_ca_key),
        )
        .route("/api/v1/ca/{id}/sign", post(pki::sign_csr))
        .route("/api/v1/ca/{id}/sign-ssh", post(pki::sign_ssh_cert_route))
        .route("/api/v1/ca/{id}/issued-certs", get(pki::list_issued_certs))
        .route(
            "/api/v1/issued-certs/{id}/revoke",
            post(pki::revoke_issued_cert),
        )
        .route(
            "/api/v1/ssh-certs",
            get(pki::list_ssh_certs).post(pki::create_ssh_cert),
        )
        .route("/api/v1/ssh-certs/{id}", delete(pki::revoke_ssh_cert))
        .route(
            "/api/v1/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route("/api/v1/tokens/{id}", delete(tokens::revoke_token))
        .route("/api/v1/audit", get(tokens::list_audit))
        .route("/api/v1/audit/verify", get(tokens::verify_audit))
        .route("/api/v1/admin/server-age", get(tokens::server_age_show))
        .route("/api/v1/admin/backup", get(backup::create_backup))
        .route(
            "/api/v1/admin/users",
            get(tokens::list_users_admin).post(tokens::create_user_admin),
        )
        .route(
            "/api/v1/admin/users/{user_id}/disable",
            post(tokens::disable_user_admin),
        )
        .route(
            "/api/v1/admin/users/{user_id}/enable",
            post(tokens::enable_user_admin),
        )
        .route("/api/v1/scan", post(scan::trigger_scan))
        .route("/api/v1/scan/results", get(scan::list_results));

    // Internal routes: service token only. Used by agents and CI where the
    // age private key must not leave the operator's machine.
    let internal_routes = Router::new()
        .route("/api/v1/internal/exec", post(internal_exec))
        .route("/api/v1/internal/secret", post(internal_get_secret))
        .route("/api/v1/internal/secrets", post(internal_list_secrets));

    // Merge all with middleware
    Router::new()
        .merge(public_routes)
        .merge(protected_routes.layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        )))
        .merge(internal_routes.layer(axum::middleware::from_fn_with_state(
            state.clone(),
            internal_auth_middleware,
        )))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            client_ip_middleware,
        ))
        .layer(axum::middleware::from_fn(request_id_middleware))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
        .with_state(state)
}

/// Extract the client IP and stash it in the request extensions. Runs on
/// **every** route (public included) so that the per-IP rate limiter on
/// `/auth/login` and `/auth/register` actually sees an IP — without this
/// the rate limiter silently no-ops for the credential-exchange endpoints.
///
/// The peer IP comes from `ConnectInfo<SocketAddr>` (axum provides it when
/// `serve` is configured with `into_make_service_with_connect_info::<SocketAddr>()`).
/// When the peer is in `PANDAPASS_TRUSTED_PROXY_CIDRS`, the leftmost
/// X-Forwarded-For is honoured; otherwise the headers are ignored.
async fn client_ip_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let peer: Option<std::net::SocketAddr> = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);
    let trusted = crate::middleware::auth::parse_trusted_cidrs(&state.config.trusted_proxy_cidrs);
    if let Some(ip) = crate::middleware::auth::extract_client_ip(req.headers(), peer, &trusted) {
        req.extensions_mut()
            .insert(crate::middleware::auth::ClientIp(ip));
    }
    Ok(next.run(req).await)
}

/// Per-request id middleware. Echoes the incoming `x-request-id` header
/// (when present) or generates a fresh one; the id is set on the response
/// header and stashed in the request extensions so handlers can read it.
async fn request_id_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::http::Response<axum::body::Body> {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| pandapass_core::crypto::generate_token(16));
    req.extensions_mut().insert(id.clone());
    let mut resp = next.run(req).await;
    if let Ok(v) = axum::http::HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// Auth middleware for regular routes
async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    // Bearer-token requests skip CSRF entirely; cookie sessions must prove they
    // meant it for mutating verbs.
    require_csrf(req.headers(), req.method()).await?;

    // Force the auth to resolve here. FromRequestParts will hit this again,
    // but if it fails (no bearer / no cookie) we want a 401 before the
    // handler runs, and that resolution is cheap.
    let _ = Auth::from_headers(req.headers(), &state).await?;
    Ok(next.run(req).await)
}

/// Internal-route auth: only service tokens with appropriate scopes
async fn internal_auth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    // Must use Bearer token
    let authz = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized("MCP requires Bearer token".into()))?;

    let token = authz
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized("Invalid token format".into()))?
        .trim();

    let hash = pandapass_core::crypto::hash_token(token).map_err(ApiError::from)?;
    let svc = pandapass_db::get_token_by_hash(&state.db, &hash)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::Unauthorized("Invalid token".into()))?;

    if let Some(exp) = svc.expires_at {
        if exp < chrono::Utc::now() {
            return Err(ApiError::Unauthorized("Token expired".into()));
        }
    }

    // The internal API has two distinct paths now: ciphertext delivery (run:secret)
    // and plain inventory (read/list). Either is enough to enter the API; the
    // route handlers reject what the token doesn't have scope for.
    let has_read = svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::ReadSecret));
    let has_list = svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::ListSecret));
    let has_exec = svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::WriteSecret));
    let has_run = svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::RunSecret));

    if !has_read && !has_list && !has_exec && !has_run {
        return Err(ApiError::Forbidden("Token lacks required scopes".into()));
    }

    let user = pandapass_db::get_user_by_id(&state.db, svc.created_by)
        .await
        .map_err(ApiError::from)?;

    let role = match (svc.project_id, svc.env_id) {
        (Some(pid), _) => pandapass_db::get_member_role(&state.db, pid, user.id)
            .await
            .unwrap_or(None),
        _ => None,
    };

    let svc_id = svc.id;
    let svc_project_id = svc.project_id;
    let svc_env_id = svc.env_id;

    let auth = Auth(pandapass_core::models::AuthContext {
        user: user.into(),
        session: None,
        service_token: Some(svc),
        project_role: role,
        project_id: svc_project_id,
        env_id: svc_env_id,
        client_ip: None,
        user_agent: None,
        request_id: None,
    });

    req.extensions_mut().insert(auth);
    let _ = pandapass_db::touch_token(&state.db, svc_id).await;

    Ok(next.run(req).await)
}

// ───────────────────── internal handlers (service-token only) ─────────────────────

use axum::{extract::State, Json};
use pandapass_db as db;

async fn internal_get_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<InternalGetSecretRequest>,
) -> Result<Json<InternalGetSecretResponse>, ApiError> {
    let svc = auth.service_token.as_ref().unwrap();

    // Ciphertext delivery requires `run:secret` (or `read:secret`, for
    // backwards compatibility — but the read path won't normally go through
    // this endpoint). The point is: the plaintext path requires read:secret,
    // and a token that wants to never see plaintext uses run:secret here.
    if !svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::RunSecret))
        && !svc
            .scopes
            .iter()
            .any(|s| matches!(s, pandapass_core::models::TokenScope::ReadSecret))
    {
        return Err(ApiError::Forbidden(
            "Token lacks run:secret or read:secret scope".into(),
        ));
    }

    let project_id = req
        .project_id
        .or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req
        .env_id
        .or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    let secret = db::get_secret(&state.db, project_id, env_id, &req.key).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::McpGetSecret);
    audit = audit.with_project(project_id);
    audit = audit.with_env(env_id);
    audit = audit.with_secret_key(req.key.clone());
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(InternalGetSecretResponse {
        key: req.key,
        value_enc: secret.value_enc,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

async fn internal_list_secrets(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<InternalListSecretsRequest>,
) -> Result<Json<InternalListSecretsResponse>, ApiError> {
    let svc = auth.service_token.as_ref().unwrap();

    if !svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::ListSecret))
    {
        return Err(ApiError::Forbidden("Token lacks list:secret scope".into()));
    }

    let project_id = req
        .project_id
        .or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req
        .env_id
        .or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    let metas = db::list_secret_metas(&state.db, project_id, env_id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::McpListSecrets);
    audit = audit.with_project(project_id);
    audit = audit.with_env(env_id);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(InternalListSecretsResponse { secrets: metas }))
}

async fn internal_exec(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<InternalExecRequest>,
) -> Result<Json<CommandResult>, ApiError> {
    let svc = auth.service_token.as_ref().unwrap();

    // Server-side secret injection requires `run:secret`
    if !svc
        .scopes
        .iter()
        .any(|s| matches!(s, pandapass_core::models::TokenScope::RunSecret))
    {
        return Err(ApiError::Forbidden("Token lacks run:secret scope".into()));
    }

    let project_id = req
        .project_id
        .or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req
        .env_id
        .or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    // Decrypt the requested secrets using the service account's master key.
    // The token was created by a user; that user's envelope holds the master key.
    let mk = crate::routes::secrets::get_master_key(&state, svc.created_by).await?;

    let mut envs: Vec<(String, String)> = Vec::with_capacity(req.keys.len());
    for key in &req.keys {
        let secret = db::get_secret(&state.db, project_id, env_id, key).await?;
        let value: secrecy::SecretString = secret.value_enc.decrypt(&mk)?;
        envs.push((key.clone(), value.expose_secret().to_string()));
    }

    // Collect the injected values for output masking
    let mask_values: Vec<Vec<u8>> = envs.iter().map(|(_, v)| v.as_bytes().to_vec()).collect();

    // Enforce server-side command allowlist
    if !state.config.command_allowlist.is_empty() {
        let program = req
            .command
            .first()
            .ok_or_else(|| ApiError::BadRequest("No command specified".into()))?;
        if !state.config.command_allowlist.iter().any(|p| p == program) {
            return Err(ApiError::Forbidden(format!(
                "Refusing to run `{}`: not in the server command allowlist",
                program
            )));
        }
    }

    // Wall-clock timeout from server config (default 120s)
    let timeout_secs = state.config.command_timeout_secs.max(1);

    let program = req
        .command
        .first()
        .ok_or_else(|| ApiError::BadRequest("No command specified".into()))?;
    let mut child = tokio::process::Command::new(program)
        .args(&req.command[1..])
        .envs(envs.iter().map(|(k, v)| (k, v)))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| ApiError::Internal(format!("failed to run `{}`: {}", program, e)))?;

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");

    // Read the pipes concurrently with the child running
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

    // Bound how long a child can hold the parent
    let status = match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        child.wait(),
    )
    .await
    {
        Ok(result) => result
            .map_err(|e| ApiError::Internal(format!("waiting for `{}` failed: {}", program, e)))?,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(ApiError::Internal(format!(
                "`{}` exceeded the {}s command timeout and was killed",
                program, timeout_secs
            )));
        }
    };

    // The child has exited; read the output
    let stdout_buf = read_stdout
        .await
        .expect("join stdout")
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let stderr_buf = read_stderr
        .await
        .expect("join stderr")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Mask secret values in output
    let mask = |buf: &[u8]| {
        let mut s = String::from_utf8_lossy(buf).to_string();
        for val in &mask_values {
            if val.is_empty() {
                continue;
            }
            let pat = String::from_utf8_lossy(val);
            if !pat.is_empty() {
                s = s.replace(pat.as_ref(), "***");
            }
        }
        s
    };
    let stdout_masked = mask(&stdout_buf);
    let stderr_masked = mask(&stderr_buf);

    let mut audit = AuditContext::new(&auth, AuditAction::McpRunCommand);
    audit = audit.with_project(project_id);
    audit = audit.with_env(env_id);
    audit = audit.with_meta(serde_json::json!({
        "keys": req.keys,
        "argv0": program,
        "exit_code": status.code(),
    }));
    state.audit.log(&audit).await.ok();

    Ok(Json(CommandResult {
        exit_code: status.code().unwrap_or(-1),
        stdout: stdout_masked,
        stderr: stderr_masked,
        injected_keys: req.keys,
        duration_ms: 0, // We could measure this, but not critical for now
    }))
}

#[derive(Deserialize)]
struct InternalGetSecretRequest {
    key: String,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct InternalGetSecretResponse {
    key: String,
    value_enc: pandapass_core::crypto::EncryptedSecret,
    version: i32,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct InternalListSecretsRequest {
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct InternalListSecretsResponse {
    secrets: Vec<pandapass_core::models::SecretMeta>,
}

#[derive(Deserialize)]
struct InternalExecRequest {
    keys: Vec<String>,
    command: Vec<String>,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

// Re-export Auth for handlers
use crate::middleware::auth::Auth;

/// Startup: create admin user if configured
///
/// The admin password is **never** printed. Operators must either set
/// `PANDAPASS_ADMIN_PASSWORD` in the environment (or pass it via the
/// docker secret mount) or run `pandapass register` after the first boot
/// to set the password interactively. Auto-generating a password and
/// logging it is forbidden: JSON logs are forwarded to log aggregators
/// and would leak the bootstrap credential to anyone with log access.
pub async fn bootstrap(state: &AppState) -> StartupInfo {
    let user_count = db::count_users(&state.db).await.unwrap_or(0);

    if user_count == 0 {
        if let Some(email) = &state.config.bootstrap_admin_email {
            let password = match std::env::var("PANDAPASS_ADMIN_PASSWORD") {
                Ok(p) if !p.is_empty() => p,
                _ => {
                    tracing::error!(
                        "PANDAPASS_ADMIN_EMAIL is set but PANDAPASS_ADMIN_PASSWORD is \
                         not. Refusing to bootstrap — automatic password generation has \
                         been removed because JSON logs are forwarded to log aggregators. \
                         Set PANDAPASS_ADMIN_PASSWORD in the environment, or start without \
                         PANDAPASS_ADMIN_EMAIL and run `pandapass register` to create the \
                         first account interactively."
                    );
                    return StartupInfo {
                        admin_bootstrapped: false,
                        user_count,
                    };
                }
            };
            let hash = pandapass_core::crypto::hash_password(&password).unwrap();
            let _ = db::create_user(
                &state.db,
                email,
                &hash,
                pandapass_core::models::GlobalRole::Admin,
            )
            .await;
            tracing::info!("Bootstrapped admin user: {}", email);
            return StartupInfo {
                admin_bootstrapped: true,
                user_count: 1,
            };
        }
    }

    StartupInfo {
        admin_bootstrapped: false,
        user_count,
    }
}
