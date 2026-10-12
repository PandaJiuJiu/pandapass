use axum::{
    extract::{Path, State},
    Json,
};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use pandapass_core::policy::{PolicyDecision, PolicyInput};
use pandapass_db as db;
use serde::Deserialize;

use crate::middleware::auth::{ApiError, Auth};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: ProjectRole,
}

#[derive(Deserialize)]
pub struct UpdateMemberRequest {
    pub role: ProjectRole,
}

#[derive(Deserialize)]
pub struct CreateEnvRequest {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
}

pub async fn create_project(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<Json<ProjectWithRole>, ApiError> {
    if !req
        .slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::BadRequest(
            "Slug must be lowercase alphanumeric with hyphens".into(),
        ));
    }

    let project = db::create_project(
        &state.db,
        &req.name,
        &req.slug,
        req.description.as_deref(),
        auth.user.id,
    )
    .await?;

    // Add creator as owner
    db::add_member(
        &state.db,
        project.id,
        auth.user.id,
        ProjectRole::Owner,
        auth.user.id,
    )
    .await?;

    // Create default environments
    let _ = db::create_env(&state.db, project.id, "Development", "dev", None).await;
    let _ = db::create_env(&state.db, project.id, "Staging", "staging", None).await;
    let _ = db::create_env(&state.db, project.id, "Production", "prod", None).await;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectCreate);
    audit = audit.with_project(project.id);
    audit = audit.with_meta(serde_json::json!({ "name": project.name, "slug": project.slug }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(ProjectWithRole {
        project,
        user_role: Some(ProjectRole::Owner),
    }))
}

pub async fn list_projects(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<Vec<ProjectWithRole>>, ApiError> {
    let projects = db::list_projects_for_user(
        &state.db,
        auth.user.id,
        auth.user.global_role == GlobalRole::Admin,
    )
    .await?;
    Ok(Json(projects))
}

pub async fn get_project(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<ProjectWithRole>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;

    if auth.user.global_role != GlobalRole::Admin {
        let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;
        if role.is_none() {
            return Err(ApiError::NotFound("Project not found".into()));
        }
    }

    let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;
    Ok(Json(ProjectWithRole {
        project,
        user_role: role,
    }))
}

pub async fn update_project(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<UpdateProjectRequest>,
) -> Result<Json<Project>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;

    if auth.user.global_role != GlobalRole::Admin && role != Some(ProjectRole::Owner) {
        return Err(ApiError::Forbidden("Only project owner can update".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = role;

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::UpdateProject, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied =
            AuditContext::new(&ctx, AuditAction::ProjectUpdate).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    db::update_project(
        &state.db,
        project.id,
        req.name.as_deref(),
        req.description.as_deref(),
    )
    .await?;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectUpdate);
    audit = audit.with_project(project.id);
    audit = audit.with_meta(
        serde_json::json!({ "name": req.name, "description_changed": req.description.is_some() }),
    );
    state.audit.log_success(&mut audit).await.ok();

    let updated = db::get_project(&state.db, project.id).await?;
    Ok(Json(updated))
}

pub async fn delete_project(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;

    if auth.user.global_role != GlobalRole::Admin && role != Some(ProjectRole::Owner) {
        return Err(ApiError::Forbidden("Only project owner can delete".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = role;

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::DeleteProject, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied =
            AuditContext::new(&ctx, AuditAction::ProjectDelete).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    db::delete_project(&state.db, project.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectDelete);
    audit = audit.with_project(project.id);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

// ─────────────────────────── members ───────────────────────────

pub async fn list_members(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<ProjectMemberDetail>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;

    if auth.user.global_role != GlobalRole::Admin {
        let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;
        if role.is_none() {
            return Err(ApiError::NotFound("Project not found".into()));
        }
    }

    let members = db::list_members(&state.db, project.id).await?;
    Ok(Json(members))
}

/// Check that the caller owns the project (or is a global admin).
async fn require_owner(
    state: &AppState,
    auth: &AuthContext,
    project_id: uuid::Uuid,
) -> Result<(), ApiError> {
    if auth.user.global_role == GlobalRole::Admin {
        return Ok(());
    }
    let role = db::get_member_role(&state.db, project_id, auth.user.id).await?;
    if role != Some(ProjectRole::Owner) {
        return Err(ApiError::Forbidden(
            "Only project owner can manage members".into(),
        ));
    }
    Ok(())
}

pub async fn add_member(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<ProjectMemberDetail>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    require_owner(&state, &auth, project.id).await?;

    let user = db::get_user_by_email(&state.db, &req.email)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".into()))?;

    if db::get_member_role(&state.db, project.id, user.id)
        .await?
        .is_some()
    {
        return Err(ApiError::Conflict("User is already a member".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::ManageMembers, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied =
            AuditContext::new(&ctx, AuditAction::ProjectMemberAdd).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    db::add_member(&state.db, project.id, user.id, req.role, auth.user.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectMemberAdd);
    audit = audit.with_project(project.id);
    audit = audit.with_meta(serde_json::json!({ "user_id": user.id, "role": req.role }));
    state.audit.log_success(&mut audit).await.ok();

    let member = db::list_members(&state.db, project.id)
        .await?
        .into_iter()
        .find(|m| m.member.user_id == user.id)
        .ok_or_else(|| ApiError::Internal("Member not found after creation".into()))?;

    Ok(Json(member))
}

pub async fn update_member(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, user_id)): Path<(String, uuid::Uuid)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<ProjectMemberDetail>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    require_owner(&state, &auth, project.id).await?;

    let current_role = db::get_member_role(&state.db, project.id, user_id).await?;
    if current_role == Some(ProjectRole::Owner) {
        return Err(ApiError::Forbidden("Cannot change owner role".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::ManageMembers, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied =
            AuditContext::new(&ctx, AuditAction::ProjectMemberUpdate).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    db::update_member_role(&state.db, project.id, user_id, req.role).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectMemberUpdate);
    audit = audit.with_project(project.id);
    audit = audit.with_meta(serde_json::json!({ "user_id": user_id, "new_role": req.role }));
    state.audit.log_success(&mut audit).await.ok();

    let member = db::list_members(&state.db, project.id)
        .await?
        .into_iter()
        .find(|m| m.member.user_id == user_id)
        .ok_or_else(|| ApiError::Internal("Member not found".into()))?;

    Ok(Json(member))
}

pub async fn remove_member(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, user_id)): Path<(String, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    require_owner(&state, &auth, project.id).await?;

    let role = db::get_member_role(&state.db, project.id, user_id).await?;
    if role == Some(ProjectRole::Owner) {
        return Err(ApiError::Forbidden("Cannot remove project owner".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::ManageMembers, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied =
            AuditContext::new(&ctx, AuditAction::ProjectMemberRemove).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    db::remove_member(&state.db, project.id, user_id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::ProjectMemberRemove);
    audit = audit.with_project(project.id);
    audit = audit.with_meta(serde_json::json!({ "user_id": user_id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

// ─────────────────────────── environments ───────────────────────────

pub async fn list_envs(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Environment>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;

    if auth.user.global_role != GlobalRole::Admin {
        let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;
        if role.is_none() {
            return Err(ApiError::NotFound("Project not found".into()));
        }
    }

    let envs = db::list_envs(&state.db, project.id).await?;
    Ok(Json(envs))
}

pub async fn create_env(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Json(req): Json<CreateEnvRequest>,
) -> Result<Json<Environment>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;

    if auth.user.global_role != GlobalRole::Admin
        && !matches!(role, Some(ProjectRole::Owner | ProjectRole::Editor))
    {
        return Err(ApiError::Forbidden("Insufficient permissions".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = role;

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, "", Permission::CreateEnv, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), None, &input)
        .await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::EnvCreate).with_project(project.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    if !req
        .slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ApiError::BadRequest(
            "Slug must be lowercase alphanumeric with hyphens".into(),
        ));
    }

    let env = db::create_env(
        &state.db,
        project.id,
        &req.name,
        &req.slug,
        req.description.as_deref(),
    )
    .await?;

    let mut audit = AuditContext::new(&auth, AuditAction::EnvCreate);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_meta(serde_json::json!({ "name": req.name, "slug": req.slug }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(env))
}

pub async fn delete_env(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let role = db::get_member_role(&state.db, project.id, auth.user.id).await?;

    if auth.user.global_role != GlobalRole::Admin
        && !matches!(role, Some(ProjectRole::Owner | ProjectRole::Editor))
    {
        return Err(ApiError::Forbidden("Insufficient permissions".into()));
    }

    // Scope the auth context to this project for RBAC and policy evaluation
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.project_role = role;

    // Policy evaluation
    let input = PolicyInput::for_context(&ctx, &slug, &env_slug, Permission::DeleteEnv, None);
    if let PolicyDecision::Deny { policy_id, message } = state
        .policy_engine
        .evaluate(Some(project.id), Some(env.id), &input)
        .await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::EnvDelete)
            .with_project(project.id)
            .with_env(env.id);
        state
            .audit
            .log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message))
            .await
            .ok();
        return Err(ApiError::Forbidden(format!(
            "Policy {}: {}",
            policy_id, message
        )));
    }

    // Prevent deleting if there are secrets
    let metas = db::list_secret_metas(&state.db, project.id, env.id).await?;
    if !metas.is_empty() {
        return Err(ApiError::Conflict(
            "Environment has secrets. Delete them first.".into(),
        ));
    }

    db::delete_env(&state.db, env.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::EnvDelete);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}
