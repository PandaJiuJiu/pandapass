use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::crypto::{EncryptedSecret, MasterKey};
use pandapass_core::models::*;
use pandapass_core::rbac::Rbac;
use pandapass_db as db;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};

#[derive(Deserialize)]
pub struct SetSecretRequest {
    /// Secret name. Required for `POST .../secrets`; ignored when the request
    /// uses `PUT .../secrets/{key}`, where the path is authoritative.
    #[serde(default)]
    pub key: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct BatchSetSecretsRequest {
    pub secrets: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct ListSecretsQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

#[derive(Serialize)]
pub struct SecretValueResponse {
    pub key: String,
    pub value: String,
    pub version: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Ciphertext only — the caller holds the master key and decrypts locally.
#[derive(Serialize)]
pub struct SecretEncryptedResponse {
    pub key: String,
    pub value_enc: EncryptedSecret,
    pub version: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Resolve the caller into an auth context scoped to a project + environment.
///
/// `AuthContext.project_role` is always `None` on a freshly-extracted context, so
/// every handler has to look the membership up itself before any RBAC check.
async fn scope_auth(
    state: &AppState,
    auth: &AuthContext,
    project: &Project,
    env: &Environment,
) -> AuthContext {
    let mut ctx = auth.clone();
    ctx.project_id = Some(project.id);
    ctx.env_id = Some(env.id);
    ctx.project_role = db::get_member_role(&state.db, project.id, auth.user.id)
        .await
        .unwrap_or(None);
    ctx
}

/// Unwrap the caller's master key from their age envelope.
///
/// The server holds its own age identity, so it can open any envelope that was
/// sealed to it as well as to the member. This is the deliberate trade-off
/// documented in `docs/SECURITY.md`: the database at rest yields only
/// ciphertext, but a root-level compromise of the running server can still
/// decrypt. The MCP `run_with_secret` path is what keeps secrets out of the
/// agent's context.
async fn get_master_key(state: &AppState, user_id: uuid::Uuid) -> Result<MasterKey, ApiError> {
    let Some(identity) = state.config.server_age_identity.as_deref().filter(|s| !s.is_empty())
    else {
        // Not a server fault: this deployment simply cannot decrypt on a
        // member's behalf. Say so in a way the caller can act on, rather than
        // surfacing a 500 that reads like a bug.
        return Err(ApiError::Forbidden(
            "This server has no age identity, so it cannot encrypt or decrypt on \
             your behalf. Configure PANDAPASS_SERVER_AGE_IDENTITY, then re-seal your \
             key with POST /api/v1/auth/key/enroll (rotate=true)."
                .into(),
        ));
    };

    let envelope = db::get_envelope(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Forbidden("No master-key envelope for this account".into()))?;

    envelope.decrypt(identity).map_err(|_| {
        // The envelope is sealed to the member's key but not to the server's —
        // an ordinary state for accounts enrolled before the server had an
        // identity. The action is the same either way.
        ApiError::Forbidden(
            "Your master key is not sealed to this server. Re-enrol it with \
             POST /api/v1/auth/key/enroll (rotate=true)."
                .into(),
        )
    })
}

/// List secret metadata (keys and versions) — never values.
pub async fn list_secrets(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
    Query(query): Query<ListSecretsQuery>,
) -> Result<Json<PaginatedResponse<SecretMeta>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, true)?;

    let metas = db::list_secret_metas(&state.db, project.id, env.id).await?;

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretList);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    state.audit.log_success(&mut audit).await.ok();

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let total = metas.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(metas.len());

    Ok(Json(PaginatedResponse::new(
        metas[start..end].to_vec(),
        total,
        page,
        per_page,
    )))
}

/// Read a secret's plaintext value.
pub async fn get_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<SecretValueResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, true)?;

    let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;
    let mk = get_master_key(&state, ctx.user.id).await?;
    let value = secret.value_enc.decrypt(&mk)?.expose_secret().to_string();

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretRead);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_secret_key(key.clone());
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SecretValueResponse {
        key,
        value,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

/// Read a secret's ciphertext so the caller can decrypt it with its own MK.
///
/// This is the path CLI and MCP clients use: the value never crosses the wire
/// in plaintext, so it never enters an agent's context.
pub async fn get_secret_encrypted(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<SecretEncryptedResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, true)?;

    let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretRead);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_secret_key(key.clone());
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SecretEncryptedResponse {
        key,
        value_enc: secret.value_enc,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

/// `POST .../secrets` — the key comes from the request body.
pub async fn set_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
    Json(req): Json<SetSecretRequest>,
) -> Result<Json<SecretValueResponse>, ApiError> {
    write_secret(&state, &auth, &slug, &env_slug, req.key, req.value).await
}

/// `PUT .../secrets/{key}` — the key comes from the path, and the body is only
/// the value. A `key` in the body is ignored, so a client that sends both
/// cannot write to a name the URL didn't ask for.
pub async fn set_secret_at_path(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
    Json(req): Json<SetSecretRequest>,
) -> Result<Json<SecretValueResponse>, ApiError> {
    write_secret(&state, &auth, &slug, &env_slug, key, req.value).await
}

async fn write_secret(
    state: &AppState,
    auth: &AuthContext,
    slug: &str,
    env_slug: &str,
    key: String,
    value: String,
) -> Result<Json<SecretValueResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, env_slug).await?;
    let ctx = scope_auth(state, auth, &project, &env).await;

    // A refused write is the single most interesting event in a vault's audit
    // log: it is what a credential-rolling attacker looks like. Record it
    // before returning. Only the key *name* is stored — the rejected value is
    // never written anywhere.
    if let Err(e) = Rbac::check_secret_access(&ctx, project.id, env.id, false) {
        let mut denied = AuditContext::new(&ctx, AuditAction::SecretUpdate)
            .with_project(project.id)
            .with_env(env.id)
            .with_secret_key(key.clone());
        state.audit.log_denied(&mut denied, &e.to_string()).await.ok();
        return Err(e.into());
    }

    if key.is_empty() || key.len() > 256 {
        return Err(ApiError::BadRequest("Key must be 1-256 characters".into()));
    }

    let existed = db::get_secret(&state.db, project.id, env.id, &key).await.is_ok();

    let mk = get_master_key(state, ctx.user.id).await?;
    let value_enc = EncryptedSecret::encrypt(&value, &mk)?;

    db::upsert_secret(&state.db, project.id, env.id, &key, &value_enc, ctx.user.id).await?;

    let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;

    let action = if existed { AuditAction::SecretUpdate } else { AuditAction::SecretCreate };
    let mut audit = AuditContext::new(&ctx, action)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(key.clone());
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SecretValueResponse {
        key,
        value,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

pub async fn batch_set_secrets(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
    Json(req): Json<BatchSetSecretsRequest>,
) -> Result<Json<Vec<SecretValueResponse>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, false)?;

    let mk = get_master_key(&state, ctx.user.id).await?;
    let mut results = Vec::new();

    for (key, value) in req.secrets {
        if key.is_empty() || key.len() > 256 {
            continue;
        }
        let value_enc = EncryptedSecret::encrypt(&value, &mk)?;
        db::upsert_secret(&state.db, project.id, env.id, &key, &value_enc, ctx.user.id).await?;
        let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;
        results.push(SecretValueResponse {
            key,
            value,
            version: secret.meta.version,
            updated_at: secret.meta.updated_at,
        });
    }

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretCreate);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_meta(serde_json::json!({ "count": results.len() }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(results))
}

pub async fn delete_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, false)?;

    db::soft_delete_secret(&state.db, project.id, env.id, &key).await?;

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretDelete);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_secret_key(key);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn list_secret_versions(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<Vec<SecretVersion>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;
    let ctx = scope_auth(&state, &auth, &project, &env).await;

    Rbac::check_secret_access(&ctx, project.id, env.id, true)?;

    let versions = db::list_secret_versions(&state.db, project.id, env.id, &key).await?;

    let mut audit = AuditContext::new(&ctx, AuditAction::SecretVersionList);
    audit = audit.with_project(project.id);
    audit = audit.with_env(env.id);
    audit = audit.with_secret_key(key);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(versions))
}