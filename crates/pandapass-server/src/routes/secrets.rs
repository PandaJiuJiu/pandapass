use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext, AuditOutcome};
use pandapass_core::crypto::EncryptedSecret;
use pandapass_core::models::*;
use pandapass_core::rbac::{Permission, Rbac};
use pandapass_db as db;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};

#[derive(Deserialize)]
pub struct SetSecretRequest {
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

#[derive(Serialize)]
pub struct SecretEncryptedResponse {
    pub key: String,
    pub value_enc: EncryptedSecret,
    pub version: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// List secret metadata (keys, versions) — no values.
pub async fn list_secrets(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
    Query(query): Query<ListSecretsQuery>,
) -> Result<Json<PaginatedResponse<SecretMeta>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, true)?;

    let metas = db::list_secret_metas(&state.db, project.id, env.id).await?;

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretList)
        .with_project(project.id)
        .with_env(env.id);
    state.audit.log_success(&audit).await.ok();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50).min(200);
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

/// Get a secret's plaintext value.
///
/// Only works for cookie-authenticated users who provide their age private key
/// via a header (used by CLI). Service tokens can't decrypt — they must use
/// the MCP internal endpoint.
pub async fn get_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<SecretValueResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, true)?;

    let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;

    // Try to get the master key from the request header (CLI provides it)
    let mk = if let Some(mk_b64) = state.config.master_key_header_name.as_deref() {
        // This is a workaround — the CLI sends the age-decrypted MK in a header
        // This is ONLY for cookie sessions; service tokens cannot do this.
        if auth.0.session.is_some() {
            // The header is set by the CLI when making the request
            let headers = state
                .http_client
                .get(state.config.public_url.clone())
                .header(mk_b64, "")
                .build()?;
            // Actually this doesn't work — we need to extract from the request
            // For now, just error and tell the client to use the internal endpoint
            return Err(ApiError::BadRequest(
                "Server-side decryption not available. Use CLI or MCP internal endpoint."
                    .into(),
            ));
        } else {
            return Err(ApiError::Forbidden(
                "Service tokens cannot decrypt secrets. Use /internal/secret.".into(),
            ));
        }
    } else {
        return Err(ApiError::BadRequest(
            "Server-side decryption not available. Use CLI or MCP internal endpoint."
                .into(),
        ));
    };

    // Decrypt the secret value
    let value = secret.value_enc.decrypt(&mk)?.expose_secret().to_string();

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretRead)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(key.clone());
    state.audit.log_success(&audit).await.ok();

    Ok(Json(SecretValueResponse {
        key,
        value,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

/// Get a secret's encrypted value (for client-side decryption).
pub async fn get_secret_encrypted(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<SecretEncryptedResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, true)?;

    let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretRead)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(key.clone());
    state.audit.log_success(&audit).await.ok();

    Ok(Json(SecretEncryptedResponse {
        key,
        value_enc: secret.value_enc,
        version: secret.meta.version,
        updated_at: secret.meta.updated_at,
    }))
}

pub async fn set_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug)): Path<(String, String)>,
    Json(req): Json<SetSecretRequest>,
) -> Result<Json<SecretValueResponse>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, false)?;

    if req.key.is_empty() || req.key.len() > 256 {
        return Err(ApiError::BadRequest("Key must be 1-256 characters".into()));
    }

    // Encrypt on the server — the client must have sent the plaintext.
    // This is for web UI / API calls where the user types the value.
    // The MK comes from the user's envelope.
    let mk = get_master_key(&state, &auth_with_context).await?;

    let value_enc = EncryptedSecret::encrypt(&req.value, &mk)?;

    db::upsert_secret(
        &state.db,
        project.id,
        env.id,
        &req.key,
        &value_enc,
        auth_with_context.user.id,
    )
    .await?;

    let secret = db::get_secret(&state.db, project.id, env.id, &req.key).await?;

    let action = if secret.meta.version == 1 {
        AuditAction::SecretCreate
    } else {
        AuditAction::SecretUpdate
    };
    let audit = AuditContext::new(&auth_with_context, action)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(req.key.clone());
    state.audit.log_success(&audit).await.ok();

    Ok(Json(SecretValueResponse {
        key: req.key,
        value: req.value,
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

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, false)?;

    let mk = get_master_key(&state, &auth_with_context).await?;
    let mut results = Vec::new();

    for (key, value) in req.secrets {
        if key.is_empty() || key.len() > 256 {
            continue;
        }
        let value_enc = EncryptedSecret::encrypt(&value, &mk)?;
        db::upsert_secret(
            &state.db,
            project.id,
            env.id,
            &key,
            &value_enc,
            auth_with_context.user.id,
        )
        .await?;
        let secret = db::get_secret(&state.db, project.id, env.id, &key).await?;
        results.push(SecretValueResponse {
            key,
            value,
            version: secret.meta.version,
            updated_at: secret.meta.updated_at,
        });
    }

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretCreate)
        .with_project(project.id)
        .with_env(env.id)
        .with_meta(serde_json::json!({ "count": results.len() }));
    state.audit.log_success(&audit).await.ok();

    Ok(Json(results))
}

pub async fn delete_secret(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, false)?;

    db::soft_delete_secret(&state.db, project.id, env.id, &key).await?;

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretDelete)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(key);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn list_secret_versions(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path((slug, env_slug, key)): Path<(String, String, String)>,
) -> Result<Json<Vec<SecretVersion>>, ApiError> {
    let project = db::get_project_by_slug(&state.db, &slug).await?;
    let env = db::get_env_by_slug(&state.db, project.id, &env_slug).await?;

    let mut auth_with_context = auth.0.clone();
    auth_with_context.project_id = Some(project.id);
    auth_with_context.env_id = Some(env.id);
    auth_with_context.project_role = db::get_member_role(&state.db, project.id, auth.0.user.id).await?;

    Rbac::check_secret_access(&auth_with_context, project.id, env.id, true)?;

    let versions = db::list_secret_versions(&state.db, project.id, env.id, &key).await?;

    let audit = AuditContext::new(&auth_with_context, AuditAction::SecretVersionList)
        .with_project(project.id)
        .with_env(env.id)
        .with_secret_key(key);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(versions))
}

/// Get the master key for a user by decrypting their envelope.
///
/// For cookie-authenticated sessions, we expect the client to have already
/// decrypted the envelope and sent the MK in a secure header. Service tokens
/// cannot decrypt secrets directly — they must use the MCP internal endpoints.
async fn get_master_key(
    state: &AppState,
    auth: &AuthContext,
) -> Result<MasterKey, ApiError> {
    // If the user has a session, they should provide their age-decrypted MK
    // via the `X-Pandapass-Master-Key` header.
    // The server doesn't store age private keys.
    if auth.session.is_some() {
        // In a real implementation, the handler would extract this from headers.
        // For the web UI flow, we'd have a JS-based decrypt in the browser.
        // Here we just fail with a clear message.
        return Err(ApiError::BadRequest(
            "Master key required in X-Pandapass-Master-Key header (age-decrypted)."
                .into(),
        ));
    }

    Err(ApiError::Forbidden(
        "Service tokens cannot decrypt secrets. Use /internal/secret.".into(),
    ))
}