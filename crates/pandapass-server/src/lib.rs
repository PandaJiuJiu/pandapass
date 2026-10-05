use axum::{
    routing::{get, post, put, delete, patch},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{CorsLayer, Any},
    trace::TraceLayer,
};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::state::{AppState, StartupInfo};
use crate::middleware::auth::{ApiError, require_csrf};
use crate::routes::{auth, projects, secrets, tokens};
use pandapass_core::audit::{AuditAction, AuditContext};

pub mod state;

mod routes {
    pub mod auth;
    pub mod projects;
    pub mod secrets;
    pub mod tokens;
}

pub mod middleware {
    pub mod auth;
}

/// Build the main application router
pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(state.config.allowed_origins.clone().into_iter().map(|o| o.parse().unwrap()).collect::<Vec<_>>())
        .allow_methods([http::Method::GET, http::Method::POST, http::Method::PUT, http::Method::PATCH, http::Method::DELETE, http::Method::OPTIONS])
        .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION, http::header::COOKIE, "x-csrf-token".parse().unwrap()])
        .allow_credentials(true);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/v1/health", get(tokens::health))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/totp/setup", get(auth::totp_setup))
        .route("/api/v1/auth/totp/verify", post(auth::totp_verify))
        .route("/api/v1/auth/totp/disable", post(auth::totp_disable))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/password", post(auth::change_password))
        .route("/api/v1/auth/logout-all", post(auth::logout_all));

    // Protected routes (require auth)
    let protected_routes = Router::new()
        .route("/api/v1/projects", get(projects::list_projects).post(projects::create_project))
        .route("/api/v1/projects/:slug", get(projects::get_project).patch(projects::update_project).delete(projects::delete_project))
        .route("/api/v1/projects/:slug/members", get(projects::list_members).post(projects::add_member))
        .route("/api/v1/projects/:slug/members/:user_id", patch(projects::update_member).delete(projects::remove_member))
        .route("/api/v1/projects/:slug/envs", get(projects::list_envs).post(projects::create_env))
        .route("/api/v1/projects/:slug/envs/:env_slug", delete(projects::delete_env))
        .route("/api/v1/projects/:slug/envs/:env_slug/secrets", get(secrets::list_secrets).post(secrets::set_secret))
        .route("/api/v1/projects/:slug/envs/:env_slug/secrets/batch", post(secrets::batch_set_secrets))
        .route("/api/v1/projects/:slug/envs/:env_slug/secrets/:key", get(secrets::get_secret).delete(secrets::delete_secret))
        .route("/api/v1/projects/:slug/envs/:env_slug/secrets/:key/versions", get(secrets::list_secret_versions))
        .route("/api/v1/tokens", get(tokens::list_tokens).post(tokens::create_token))
        .route("/api/v1/tokens/:id", delete(tokens::revoke_token))
        .route("/api/v1/audit", get(tokens::list_audit));

    // MCP internal route (service token only)
    let mcp_routes = Router::new()
        .route("/api/v1/internal/exec", post(mcp_exec))
        .route("/api/v1/internal/secret", post(mcp_get_secret))
        .route("/api/v1/internal/secrets", post(mcp_list_secrets));

    // Merge all with middleware
    Router::new()
        .merge(public_routes)
        .merge(
            protected_routes
                .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        )
        .merge(
            mcp_routes
                .layer(axum::middleware::from_fn_with_state(state.clone(), mcp_auth_middleware))
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors)
        )
        .with_state(state)
}

/// Auth middleware for regular routes
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    // Check CSRF for mutating cookie requests
    if req.method() != http::Method::GET
        && req.method() != http::Method::HEAD
        && req.method() != http::Method::OPTIONS
    {
        let _ = require_csrf(&state, req.headers(), req.method()).await;
    }

    // Extract auth
    let auth = Auth::from_request_parts(&mut req.headers_mut(), &state).await?;
    req.extensions_mut().insert(auth);

    Ok(next.run(req).await)
}

/// MCP internal auth - only service tokens with appropriate scopes
async fn mcp_auth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    // Must use Bearer token
    let authz = req.headers().get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized("MCP requires Bearer token".into()))?;

    let token = authz.strip_prefix("Bearer ")
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

    // Verify required scopes
    let has_read = svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::ReadSecret));
    let has_list = svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::ListSecret));
    let has_exec = svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::WriteSecret));

    if !has_read && !has_list && !has_exec {
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

    let auth = Auth(pandapass_core::models::AuthContext {
        user: user.into(),
        session: None,
        service_token: Some(svc),
        project_role: role,
        project_id: svc.project_id,
        env_id: svc.env_id,
    });

    req.extensions_mut().insert(auth);
    let _ = pandapass_db::touch_token(&state.db, auth.0.service_token.as_ref().unwrap().id).await;

    Ok(next.run(req).await)
}

// ─────────────────────────── MCP internal handlers ───────────────────────────

use axum::{extract::State, Json};
use pandapass_db as db;

async fn mcp_get_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<McpGetSecretRequest>,
) -> Result<Json<McpGetSecretResponse>, ApiError> {
    let svc = auth.0.service_token.as_ref().unwrap();

    // Verify scopes
    if !svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::ReadSecret)) {
        return Err(ApiError::Forbidden("Token lacks read:secret scope".into()));
    }

    let project_id = req.project_id.or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req.env_id.or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    let secret = db::get_secret(&state.db, project_id, env_id, &req.key).await?;

    // For MCP, we need to decrypt - but server doesn't have age private key
    // This endpoint is a placeholder; real decryption happens in CLI/MCP client
    // Return encrypted value + metadata

    let audit = AuditContext::new(&auth.0, AuditAction::McpGetSecret)
        .with_project(project_id)
        .with_env(env_id)
        .with_secret_key(req.key.clone());
    state.audit.log_success(&audit).await.ok();

    Ok(Json(McpGetSecretResponse {
        key: req.key,
        value_enc: secret.value_enc,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

async fn mcp_list_secrets(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<McpListSecretsRequest>,
) -> Result<Json<McpListSecretsResponse>, ApiError> {
    let svc = auth.0.service_token.as_ref().unwrap();

    if !svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::ListSecret)) {
        return Err(ApiError::Forbidden("Token lacks list:secret scope".into()));
    }

    let project_id = req.project_id.or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req.env_id.or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    let metas = db::list_secret_metas(&state.db, project_id, env_id).await?;

    let audit = AuditContext::new(&auth.0, AuditAction::McpListSecrets)
        .with_project(project_id)
        .with_env(env_id);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(McpListSecretsResponse { secrets: metas }))
}

async fn mcp_exec(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<McpExecRequest>,
) -> Result<Json<CommandResult>, ApiError> {
    let svc = auth.0.service_token.as_ref().unwrap();

    if !svc.scopes.iter().any(|s| matches!(s, pandapass_core::models::TokenScope::WriteSecret)) {
        return Err(ApiError::Forbidden("Token lacks write:secret scope".into()));
    }

    let project_id = req.project_id.or(svc.project_id)
        .ok_or_else(|| ApiError::BadRequest("Project ID required".into()))?;
    let env_id = req.env_id.or(svc.env_id)
        .ok_or_else(|| ApiError::BadRequest("Environment ID required".into()))?;

    // Decrypt the requested secrets
    // For now, return error - full implementation needs client-side decryption
    // This is a placeholder for the MCP run_with_secret tool

    let audit = AuditContext::new(&auth.0, AuditAction::McpRunCommand)
        .with_project(project_id)
        .with_env(env_id)
        .with_meta(serde_json::json!({
            "keys": req.keys,
            "argv0": req.command.first().unwrap_or(&"".to_string()),
        }));
    state.audit.log(&audit).await.ok();

    Err(ApiError::Internal("MCP exec not fully implemented yet - requires client-side decryption".into()))
}

#[derive(Deserialize)]
struct McpGetSecretRequest {
    key: String,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct McpGetSecretResponse {
    key: String,
    value_enc: pandapass_core::crypto::EncryptedSecret,
    version: i32,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct McpListSecretsRequest {
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

#[derive(Serialize)]
struct McpListSecretsResponse {
    secrets: Vec<pandapass_core::models::SecretMeta>,
}

#[derive(Deserialize)]
struct McpExecRequest {
    keys: Vec<String>,
    command: Vec<String>,
    project_id: Option<uuid::Uuid>,
    env_id: Option<uuid::Uuid>,
}

// Re-export Auth for handlers
use crate::middleware::auth::Auth;

/// Startup: create admin user if configured
pub async fn bootstrap(state: &AppState) -> StartupInfo {
    let user_count = db::count_users(&state.db).await.unwrap_or(0);

    if user_count == 0 {
        if let Some(email) = &state.config.bootstrap_admin_email {
            let password = std::env::var("PANDAPASS_ADMIN_PASSWORD")
                .unwrap_or_else(|_| pandapass_core::crypto::generate_token(16));
            let hash = pandapass_core::crypto::hash_password(&password).unwrap();
            let _ = db::create_user(&state.db, email, &hash, pandapass_core::models::GlobalRole::Admin).await;
            tracing::info!("Bootstrapped admin user: {}", email);
            if std::env::var("PANDAPASS_ADMIN_PASSWORD").is_err() {
                tracing::warn!("Admin password (save this!): {}", password);
            }
            return StartupInfo { admin_bootstrapped: true, user_count: 1 };
        }
    }

    StartupInfo { admin_bootstrapped: false, user_count }
}