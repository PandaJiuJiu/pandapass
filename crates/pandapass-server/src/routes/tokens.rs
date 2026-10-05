use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::crypto::{generate_token, hash_token};
use pandapass_core::models::*;
use pandapass_db as db;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub project_id: Option<uuid::Uuid>,
    pub env_id: Option<uuid::Uuid>,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub token: ServiceToken,
    pub plain_token: String,
}

pub async fn list_tokens(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<Vec<ServiceToken>>, ApiError> {
    let tokens = db::list_tokens(&state.db, auth.user.id).await?;
    Ok(Json(tokens))
}

pub async fn create_token(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, ApiError> {
    // Validate scopes
    let scopes: Vec<TokenScope> = req.scopes.iter()
        .filter_map(|s| TokenScope::from_str(s))
        .collect();
    if scopes.is_empty() {
        return Err(ApiError::BadRequest("At least one valid scope required".into()));
    }

    // A service token must not be able to mint tokens. The scopes requested here
    // are unconstrained, so a token holding `manage:project` could mint one with
    // `manage:project` plus `write:secret` and the scope system would be
    // circular — any token that leaks becomes full compromise of the vault.
    // Only human sessions may issue credentials.
    if auth.service_token.is_some() {
        return Err(ApiError::Forbidden(
            "Service tokens cannot create tokens. Use a logged-in session.".into(),
        ));
    }

    // If project_id provided, verify user has access
    if let Some(project_id) = req.project_id {
        if auth.user.global_role != GlobalRole::Admin {
            let role = db::get_member_role(&state.db, project_id, auth.user.id).await?;
            if role.is_none() {
                return Err(ApiError::NotFound("Project not found".into()));
            }
        }
    }

    // Validate env_id belongs to project
    if let (Some(project_id), Some(env_id)) = (req.project_id, req.env_id) {
        let env = db::get_env(&state.db, env_id).await?;
        if env.project_id != project_id {
            return Err(ApiError::BadRequest("Environment does not belong to project".into()));
        }
    }

    let plain_token = generate_token(32);
    let token_hash = hash_token(&plain_token)?;

    let token = ServiceToken {
        id: uuid::Uuid::now_v7(),
        name: req.name.clone(),
        token_hash,
        project_id: req.project_id,
        env_id: req.env_id,
        scopes,
        expires_at: req.expires_at,
        last_used_at: None,
        created_by: auth.user.id,
        created_at: chrono::Utc::now(),
        revoked_at: None,
    };

    db::create_service_token(&state.db, &token).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::TokenCreate);
    audit = audit.with_meta(serde_json::json!({ "token_id": token.id, "name": token.name, "scopes": req.scopes }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(CreateTokenResponse {
        token,
        plain_token,
    }))
}

pub async fn revoke_token(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // The token table is keyed by creator, and a service token is created *by*
    // its owner — so this ownership check would otherwise let it revoke every
    // token that owner holds, including its own siblings. Revocation is a
    // human action.
    if auth.service_token.is_some() {
        return Err(ApiError::Forbidden(
            "Service tokens cannot revoke tokens. Use a logged-in session.".into(),
        ));
    }

    // Verify ownership
    let tokens = db::list_tokens(&state.db, auth.user.id).await?;
    if !tokens.iter().any(|t| t.id == id) {
        return Err(ApiError::NotFound("Token not found".into()));
    }

    db::revoke_token(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::TokenRevoke);
    audit = audit.with_meta(serde_json::json!({ "token_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

// ─────────────────────────── audit ───────────────────────────

#[derive(Deserialize)]
pub struct AuditQuery {
    pub project_id: Option<uuid::Uuid>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub items: Vec<AuditLog>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

pub async fn list_audit(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, ApiError> {
    // Gating on the global role alone let a service token read the log: the
    // token's creator was usually an admin, and this never asked whether the
    // *token* had `read:audit`. `can` answers that, and a session-only admin
    // still passes.
    if !auth.can(Permission::ReadAudit) {
        return Err(ApiError::Forbidden("Insufficient permissions to view audit".into()));
    }

    // Reading a single project's log additionally requires membership, unless
    // the caller is an admin reading as a human.
    if auth.service_token.is_none() && auth.user.global_role != GlobalRole::Admin {
        if let Some(project_id) = query.project_id {
            let role = db::get_member_role(&state.db, project_id, auth.user.id).await?;
            if !matches!(role, Some(ProjectRole::Owner) | Some(ProjectRole::Editor)) {
                return Err(ApiError::Forbidden("Insufficient permissions to view audit".into()));
            }
        } else {
            return Err(ApiError::Forbidden("Admin access required for global audit".into()));
        }
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50).min(200);
    let offset = (page - 1) * per_page;

    let items = db::query_audit(&state.db, query.project_id, None, per_page, offset).await?;
    let total = db::count_audit(&state.db, query.project_id).await?;

    Ok(Json(AuditResponse {
        items,
        total,
        page,
        per_page,
    }))
}

// ─────────────────────────── health ───────────────────────────

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "pandapass-server" }))
}