use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use pandapass_db as db;
use serde::Deserialize;

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};

#[derive(Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub rego_source: String,
}

#[derive(Deserialize)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub rego_source: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ListPoliciesQuery {
    pub enabled_only: Option<bool>,
}

pub async fn list_policies(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<Policy>>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let policies = db::list_policies(&state.db, query.enabled_only.unwrap_or(true)).await?;
    Ok(Json(policies))
}

pub async fn create_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<Policy>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let policy = db::create_policy(&state.db, &req.name, &req.rego_source, auth.user.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PolicyCreate);
    audit = audit.with_meta(serde_json::json!({ "policy_id": policy.id, "name": policy.name }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(policy))
}

pub async fn get_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<Policy>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let policy = db::get_policy(&state.db, id).await?;
    Ok(Json(policy))
}

pub async fn update_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<(), ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    db::update_policy(&state.db, id, req.name.as_deref(), req.rego_source.as_deref(), req.enabled).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PolicyUpdate);
    audit = audit.with_meta(serde_json::json!({ "policy_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}

pub async fn delete_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<(), ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    db::delete_policy(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PolicyDelete);
    audit = audit.with_meta(serde_json::json!({ "policy_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}

#[derive(Deserialize)]
pub struct BindPolicyRequest {
    pub policy_id: uuid::Uuid,
    pub project_id: Option<uuid::Uuid>,
    pub env_id: Option<uuid::Uuid>,
}

pub async fn list_policy_bindings(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ListPolicyBindingsQuery>,
) -> Result<Json<Vec<PolicyBinding>>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let bindings = db::list_policy_bindings(&state.db, query.project_id, query.env_id).await?;
    Ok(Json(bindings))
}

#[derive(Deserialize)]
pub struct ListPolicyBindingsQuery {
    pub project_id: Option<uuid::Uuid>,
    pub env_id: Option<uuid::Uuid>,
}

pub async fn bind_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<BindPolicyRequest>,
) -> Result<Json<PolicyBinding>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let binding = db::bind_policy(&state.db, req.policy_id, req.project_id, req.env_id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PolicyBind);
    audit = audit.with_project(req.project_id.unwrap_or(uuid::Uuid::nil()));
    audit = audit.with_env(req.env_id.unwrap_or(uuid::Uuid::nil()));
    audit = audit.with_meta(serde_json::json!({ "binding_id": binding.id, "policy_id": req.policy_id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(binding))
}

pub async fn unbind_policy(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<(), ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    db::delete_policy_binding(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PolicyDelete);
    audit = audit.with_meta(serde_json::json!({ "binding_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}