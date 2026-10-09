use axum::{extract::{Path, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::crypto::EncryptedSecret;
use pandapass_core::models::*;
use pandapass_core::policy::{PolicyDecision, PolicyInput};
use pandapass_db as db;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};
use crate::routes::secrets::get_master_key;

#[derive(Deserialize)]
pub struct CreateDynamicCredRequest {
    pub kind: DynamicCredKind,
    pub username: String,
    #[serde(default)]
    pub ttl_seconds: i64,
}

#[derive(Serialize)]
pub struct DynamicCredResponse {
    pub cred: DynamicCred,
    pub plain_password: String,
}

pub async fn list_dynamic_creds(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((project_slug, env_slug)): Path<(String, String)>,
) -> Result<Json<Vec<DynamicCred>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &project_slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    // Scope the auth context to this project+env for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.env_id = Some(env.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    if !ctx.can(Permission::ListSecrets) {
        return Err(ApiError::Forbidden("Insufficient permissions".into()));
    }

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &project_slug, &env_slug, Permission::ListSecrets, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(Some(project.id), Some(env.id), &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::CredList)
            .with_project(project.id)
            .with_env(env.id);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    let creds = db::list_dynamic_creds(&state.db, project.id, env.id, false).await?;
    Ok(Json(creds))
}

pub async fn create_dynamic_cred(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((project_slug, env_slug)): Path<(String, String)>,
    Json(req): Json<CreateDynamicCredRequest>,
) -> Result<Json<DynamicCredResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &project_slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    // Scope the auth context to this project+env for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.env_id = Some(env.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    if !ctx.can(Permission::WriteSecret) {
        return Err(ApiError::Forbidden("Insufficient permissions".into()));
    }

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &project_slug, &env_slug, Permission::WriteSecret, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(Some(project.id), Some(env.id), &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::CredIssue)
            .with_project(project.id)
            .with_env(env.id);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    let ttl = if req.ttl_seconds > 0 { req.ttl_seconds } else { 3600 };
    let plain_password = pandapass_core::crypto::generate_token(32);

    // Get the user's master key to encrypt the password
    let mk = get_master_key(&state, auth.user.id).await?;
    let password_enc = EncryptedSecret::encrypt_with_purpose(
        &plain_password,
        &mk,
        pandapass_core::crypto::key_purpose::DYNAMIC_CRED_PASSWORD,
    )?;

    let cred = db::create_dynamic_cred(
        &state.db,
        project.id,
        env.id,
        req.kind,
        &req.username,
        &password_enc,
        ttl,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CredIssue);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_meta(serde_json::json!({ "cred_id": cred.id, "kind": req.kind.as_str(), "username": req.username }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(DynamicCredResponse {
        cred,
        plain_password,
    }))
}

pub async fn revoke_dynamic_cred(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((project_slug, env_slug, cred_id)): Path<(String, String, uuid::Uuid)>,
) -> Result<(), ApiError> {
    let project = db::get_project_by_slug(&state.db, &project_slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    // Scope the auth context to this project+env for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.env_id = Some(env.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    if !ctx.can(Permission::WriteSecret) {
        return Err(ApiError::Forbidden("Insufficient permissions".into()));
    }

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &project_slug, &env_slug, Permission::WriteSecret, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(Some(project.id), Some(env.id), &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::CredRevoke)
            .with_project(project.id)
            .with_env(env.id);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    // Verify cred belongs to project/env
    let cred = db::get_dynamic_cred(&state.db, cred_id).await?;
    if cred.project_id != project.id || cred.env_id != env.id {
        return Err(ApiError::NotFound("Dynamic credential not found".into()));
    }

    db::revoke_dynamic_cred(&state.db, cred_id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CredRevoke);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_meta(serde_json::json!({ "cred_id": cred_id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}