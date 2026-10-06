use axum::{extract::{Path, Query, State}, Json};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use pandapass_core::pki::{sign_x509_from_csr, PkiError};
use pandapass_db as db;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::middleware::auth::{Auth, ApiError};

#[derive(Deserialize)]
pub struct CreateCaKeyRequest {
    pub kind: CaKeyType,
    pub key_pem: String,
    pub cert_pem: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct ListCaKeysQuery {
    pub include_revoked: Option<bool>,
}

pub async fn list_ca_keys(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ListCaKeysQuery>,
) -> Result<Json<Vec<CaKey>>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let keys = db::list_ca_keys(&state.db, query.include_revoked.unwrap_or(false)).await?;
    Ok(Json(keys))
}

pub async fn create_ca_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<CreateCaKeyRequest>,
) -> Result<Json<CaKey>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    // Get the user's master key to encrypt the CA private key
    let mk = crate::routes::secrets::get_master_key(&state, auth.user.id).await?;
    let key_enc = pandapass_core::crypto::EncryptedSecret::encrypt(&req.key_pem, &mk)?;

    let ca_key = db::create_ca_key(
        &state.db,
        req.kind,
        &key_enc,
        &req.cert_pem,
        req.not_before,
        req.not_after,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaCreate);
    audit = audit.with_meta(serde_json::json!({ "ca_id": ca_key.id, "kind": req.kind.as_str() }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(ca_key))
}

pub async fn get_ca_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<CaKey>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let ca_key = db::get_ca_key(&state.db, id).await?;
    Ok(Json(ca_key))
}

pub async fn revoke_ca_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<(), ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    db::revoke_ca_key(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaCreate);
    audit = audit.with_meta(serde_json::json!({ "ca_id": id, "action": "revoke" }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}

#[derive(Deserialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct SignCsrResponse {
    pub cert_pem: String,
}

/// Sign a certificate from a CSR using a stored CA.
/// Admin only — the CA private key is decryptable by the server.
pub async fn sign_csr(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(ca_id): Path<uuid::Uuid>,
    Json(req): Json<SignCsrRequest>,
) -> Result<Json<SignCsrResponse>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    // Load CA key
    let ca_key = db::get_ca_key(&state.db, ca_id).await?;
    if ca_key.revoked_at.is_some() {
        return Err(ApiError::BadRequest("CA has been revoked".into()));
    }

    // Get master key to decrypt CA private key
    let mk = crate::routes::secrets::get_master_key(&state, auth.user.id).await?;

    // Sign. A malformed CSR is the caller's bug (400); anything after that —
    // an unusable CA key, an rcgen failure — is ours (500).
    let cert_pem = sign_x509_from_csr(
        &ca_key.key_enc,
        &ca_key.cert_pem,
        &mk,
        &req.csr_pem,
        req.not_before,
        req.not_after,
    ).map_err(|e| match e {
        PkiError::CsrParse(m) => ApiError::BadRequest(format!("Invalid CSR: {m}")),
        other => ApiError::Internal(format!("PKI signing failed: {other}")),
    })?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaSign);
    audit = audit.with_meta(serde_json::json!({
        "ca_id": ca_id,
        "action": "sign_csr",
        "not_before": req.not_before,
        "not_after": req.not_after,
    }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SignCsrResponse { cert_pem }))
}

#[derive(Deserialize)]
pub struct CreateSshCertRequest {
    pub user_id: uuid::Uuid,
    pub project_id: Option<uuid::Uuid>,
    pub principal: String,
    pub cert_pem: String,
    pub key_type: SshKeyType,
    pub valid_before: chrono::DateTime<chrono::Utc>,
    pub valid_after: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
pub struct ListSshCertsQuery {
    pub user_id: Option<uuid::Uuid>,
    pub project_id: Option<uuid::Uuid>,
    pub include_revoked: Option<bool>,
}

pub async fn list_ssh_certs(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Query(query): Query<ListSshCertsQuery>,
) -> Result<Json<Vec<SshCert>>, ApiError> {
    // Only admins (session or service token with manage:users scope) can list.
    // Service tokens never have ManageUsers (required_scope returns None),
    // so they are rejected here.
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    let certs = db::list_ssh_certs(
        &state.db,
        query.user_id,
        query.project_id,
        query.include_revoked.unwrap_or(false),
    ).await?;
    Ok(Json(certs))
}

pub async fn create_ssh_cert(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<CreateSshCertRequest>,
) -> Result<Json<SshCert>, ApiError> {
    // Only admins or the user themselves can request certs for a user
    if !auth.can(Permission::ManageUsers) && req.user_id != auth.user.id {
        return Err(ApiError::Forbidden("Cannot create SSH cert for another user".into()));
    }

    // Verify project access if provided
    if let Some(project_id) = req.project_id {
        let role = db::get_member_role(&state.db, project_id, req.user_id).await?;
        if role.is_none() && !auth.can(Permission::ManageUsers) {
            return Err(ApiError::Forbidden("User is not a member of this project".into()));
        }
    }

    let ssh_cert = db::create_ssh_cert(
        &state.db,
        req.user_id,
        req.project_id,
        &req.principal,
        &req.cert_pem,
        req.key_type,
        req.valid_before,
        req.valid_after,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::SshCertIssue);
    audit = audit.with_meta(serde_json::json!({
        "ssh_cert_id": ssh_cert.id,
        "user_id": req.user_id,
        "principal": req.principal,
        "key_type": req.key_type.as_str(),
    }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(ssh_cert))
}

pub async fn revoke_ssh_cert(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<(), ApiError> {
    let cert = db::get_ssh_cert(&state.db, id).await?;

    // Only admins or the cert owner can revoke
    if !auth.can(Permission::ManageUsers) && cert.user_id != auth.user.id {
        return Err(ApiError::Forbidden("Cannot revoke another user's SSH cert".into()));
    }

    db::revoke_ssh_cert(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::SshCertRevoke);
    audit = audit.with_meta(serde_json::json!({ "ssh_cert_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}