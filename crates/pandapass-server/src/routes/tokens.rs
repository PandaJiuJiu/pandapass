use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::crypto::{generate_token, hash_token};
use pandapass_core::models::*;
use pandapass_core::policy::{PolicyDecision, PolicyInput};
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

    // Policy evaluation in the token's scope (global if not project-scoped)
    let project_slug = if let Some(pid) = req.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let input = PolicyInput::for_context(&auth, &project_slug, "", Permission::CreateToken, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(req.project_id, req.env_id, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::TokenCreate);
        if let Some(pid) = req.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

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
    let token = tokens.iter().find(|t| t.id == id)
        .ok_or_else(|| ApiError::NotFound("Token not found".into()))?;

    // Policy evaluation in the token's scope
    let project_slug = if let Some(pid) = token.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let input = PolicyInput::for_context(&auth, &project_slug, "", Permission::RevokeToken, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(token.project_id, token.env_id, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::TokenRevoke);
        if let Some(pid) = token.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
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

    // Policy evaluation for audit access
    let project_slug = if let Some(pid) = query.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let mut ctx = auth.clone();
    if let Some(pid) = query.project_id {
        ctx.project_id = Some(pid);
        ctx.project_role = db::get_member_role(&state.db, pid, auth.user.id)
            .await
            .unwrap_or(None);
    }
    let input = PolicyInput::for_context(&ctx, &project_slug, "", Permission::ReadAudit, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(query.project_id, None, &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::AuditRead);
        if let Some(pid) = query.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
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

// ─────────────────────────── audit chain verification ───────────────────────────

#[derive(Serialize)]
pub struct AuditChainResponse {
    pub intact: bool,
    pub entries_checked: u64,
    /// Present only when the chain is broken: which entry and why.
    pub broken_at: Option<uuid::Uuid>,
    pub reason: Option<String>,
}

/// Verify the audit log's HMAC chain. Admin-only: a broken chain means
/// someone edited the log, which is exactly the moment an attacker may want
/// to quietly re-check whether they were noticed.
pub async fn verify_audit(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<AuditChainResponse>, ApiError> {
    if auth.user.global_role != GlobalRole::Admin {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    if state.audit_chain_key.is_empty() {
        return Ok(Json(AuditChainResponse {
            intact: true,
            entries_checked: 0,
            broken_at: None,
            reason: Some("audit chain disabled: no server age identity".into()),
        }));
    }

    let result = db::verify_audit_chain(&state.db, &state.audit_chain_key).await?;

    Ok(Json(match result {
        db::ChainVerification::Intact { entries_checked } => AuditChainResponse {
            intact: true,
            entries_checked,
            broken_at: None,
            reason: None,
        },
        db::ChainVerification::Broken { at_id, reason } => AuditChainResponse {
            intact: false,
            entries_checked: 0,
            broken_at: Some(at_id),
            reason: Some(reason),
        },
    }))
}