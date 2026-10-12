use axum::{extract::{Path, Query, State}, Json};
use base64::{engine::general_purpose, Engine};
use pandapass_core::audit::{AuditAction, AuditContext};
use pandapass_core::models::*;
use pandapass_core::pki::{sign_x509_from_csr, sign_ssh_cert, generate_root_ca, generate_intermediate_ca, PkiError};
use pandapass_core::policy::{PolicyDecision, PolicyInput};
use pandapass_db as db;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::{FromDer, X509Certificate};

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
pub struct GenerateCaKeyRequest {
    pub kind: CaKeyType,
    pub subject_dn: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Required when `kind == intermediate`: the id of an existing,
    /// non-revoked root CA to chain the new intermediate to.
    pub parent_ca_id: Option<uuid::Uuid>,
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

    // Policy evaluation (global scope — CA keys are not project-bound)
    let input = PolicyInput::for_context(&auth, "", "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(None, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::CaCreate);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    // Get the user's master key to encrypt the CA private key
    let mk = crate::routes::secrets::get_master_key(&state, auth.user.id).await?;
    let key_enc = pandapass_core::crypto::EncryptedSecret::encrypt_with_purpose(
        &req.key_pem,
        &mk,
        pandapass_core::crypto::key_purpose::CA_X509_KEY,
    )?;

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

/// Server-side CA generation (D9): the CA key pair is created inside the
/// server process and the private key is encrypted at rest immediately — it
/// never passes through a browser textarea or a CLI transcript. The client
/// only supplies the subject DN and validity window.
pub async fn generate_ca_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<GenerateCaKeyRequest>,
) -> Result<Json<CaKey>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    if req.subject_dn.trim().is_empty() {
        return Err(ApiError::BadRequest("subject_dn is required".into()));
    }

    // Policy evaluation (global scope — CA keys are not project-bound)
    let input = PolicyInput::for_context(&auth, "", "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(None, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::CaCreate);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    // Get the user's master key to encrypt the CA private key
    let mk = crate::routes::secrets::get_master_key(&state, auth.user.id).await?;

    let (cert_pem, key_pem) = match req.kind {
        CaKeyType::Root => {
            generate_root_ca(&req.subject_dn, req.not_before, req.not_after)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        }
        CaKeyType::Intermediate => {
            let parent_id = req.parent_ca_id
                .ok_or_else(|| ApiError::BadRequest("parent_ca_id is required for an intermediate CA".into()))?;
            let parent = db::get_ca_key(&state.db, parent_id).await?;
            if parent.revoked_at.is_some() {
                return Err(ApiError::BadRequest("parent CA is revoked".into()));
            }
            generate_intermediate_ca(
                &parent.key_enc,
                &parent.cert_pem,
                &mk,
                &req.subject_dn,
                req.not_before,
                req.not_after,
            )
            .map_err(|e| ApiError::Internal(e.to_string()))?
        }
    };

    let key_enc = pandapass_core::crypto::EncryptedSecret::encrypt_with_purpose(
        &key_pem,
        &mk,
        pandapass_core::crypto::key_purpose::CA_X509_KEY,
    )?;

    let ca_key = db::create_ca_key(
        &state.db,
        req.kind,
        &key_enc,
        &cert_pem,
        req.not_before,
        req.not_after,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaCreate);
    audit = audit.with_meta(serde_json::json!({ "ca_id": ca_key.id, "kind": req.kind.as_str(), "generated": true }));
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

    // Policy evaluation (global scope)
    let input = PolicyInput::for_context(&auth, "", "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(None, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::CaRevoke);
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    db::revoke_ca_key(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaRevoke);
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

    // Policy evaluation (global scope)
    let input = PolicyInput::for_context(&auth, "", "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(None, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::CaSign)
            .with_meta(serde_json::json!({ "ca_id": ca_id }));
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
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
    let (cert_pem, _serial) = sign_x509_from_csr(
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

    // Persist the issued cert so it can be revoked individually later.
    // The subject is the CSR's distinguished name; x509-parser's `subject`
    // string is "CN=..., O=...". Fall back to the CA's own subject if
    // we cannot extract.
    let body_b64 = req
        .csr_pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.is_empty())
        .collect::<Vec<_>>()
        .join("");
    let der = general_purpose::STANDARD.decode(&body_b64).ok();
    let subject = match der.as_ref().and_then(|d| X509Certificate::from_der(d).ok()) {
        Some((_r, xc)) => xc.subject().to_string(),
        None => ca_key.cert_pem.clone(),
    };
    drop(der);
    let _issued_id = db::record_issued_cert(
        &state.db,
        ca_id,
        &_serial,
        &subject,
        req.not_before,
        req.not_after,
        &cert_pem,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaSign);
    audit = audit.with_meta(serde_json::json!({
        "ca_id": ca_id,
        "action": "sign_csr",
        "serial": _serial,
        "not_before": req.not_before,
        "not_after": req.not_after,
    }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SignCsrResponse { cert_pem }))
}

#[derive(Deserialize)]
pub struct SignSshCertRequest {
    pub user_id: uuid::Uuid,
    #[serde(default)]
    pub project_id: Option<uuid::Uuid>,
    pub principal: String,
    /// The user's public key in OpenSSH format (`ssh-ed25519 AAAA... comment`).
    /// The private half never leaves the user's machine; only this is signed.
    pub user_public_key_openssh: String,
    pub key_type: SshKeyType,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct SignSshCertResponse {
    pub cert_openssh: String,
    pub cert_id: uuid::Uuid,
}

/// Sign an SSH user certificate using a stored CA.
///
/// The user's private key never touches the server — they keep it locally.
/// We sign their CA's assertion that `principal` may connect until `not_after`.
/// The signed cert is stored in the `ssh_certs` table for tracking/revocation,
/// and returned once in OpenSSH format for the user's `.ssh` directory.
pub async fn sign_ssh_cert_route(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(ca_id): Path<uuid::Uuid>,
    Json(req): Json<SignSshCertRequest>,
) -> Result<Json<SignSshCertResponse>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }

    // Policy evaluation. SSH certs can be scoped to a project (for member-only
    // access rules), so pass project_id if present; otherwise global scope.
    let project_slug = if let Some(pid) = req.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let input = PolicyInput::for_context(&auth, &project_slug, "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(req.project_id, None, &input).await?
    {
        let mut denied = AuditContext::new(&auth, AuditAction::SshCertIssue)
            .with_meta(serde_json::json!({ "ca_id": ca_id, "user_id": req.user_id }));
        if let Some(pid) = req.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    // Load CA key
    let ca_key = db::get_ca_key(&state.db, ca_id).await?;
    if ca_key.revoked_at.is_some() {
        return Err(ApiError::BadRequest("CA has been revoked".into()));
    }

    // Get master key to decrypt CA private key
    let mk = crate::routes::secrets::get_master_key(&state, auth.user.id).await?;

    let cert_openssh = sign_ssh_cert(
        &ca_key.key_enc,
        &ca_key.cert_pem,
        &mk,
        req.user_id,
        &req.user_public_key_openssh,
        &req.principal,
        req.key_type,
        req.not_before,
        req.not_after,
    ).map_err(|e| ApiError::Internal(format!("SSH signing failed: {e}")))?;

    // Store the signed certificate for tracking and later revocation
    let ssh_cert = db::create_ssh_cert(
        &state.db,
        req.user_id,
        req.project_id,
        &req.principal,
        &cert_openssh,
        req.key_type,
        req.not_after,
        req.not_before,
        auth.user.id,
    ).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::SshCertIssue);
    audit = audit.with_meta(serde_json::json!({
        "ssh_cert_id": ssh_cert.id,
        "ca_id": ca_id,
        "user_id": req.user_id,
        "principal": req.principal,
        "key_type": req.key_type.as_str(),
    }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(SignSshCertResponse {
        cert_openssh,
        cert_id: ssh_cert.id,
    }))
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

    // Policy evaluation — scoped to project if provided
    let project_slug = if let Some(pid) = req.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let mut ctx = auth.clone();
    if let Some(pid) = req.project_id {
        ctx.project_id = Some(pid);
        ctx.project_role = db::get_member_role(&state.db, pid, auth.user.id)
            .await
            .unwrap_or(None);
    }
    let input = PolicyInput::for_context(&ctx, &project_slug, "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(req.project_id, None, &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::SshCertIssue)
            .with_meta(serde_json::json!({ "user_id": req.user_id }));
        if let Some(pid) = req.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
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

    // Policy evaluation — scoped to the cert's project if any
    let project_slug = if let Some(pid) = cert.project_id {
        db::get_project(&state.db, pid).await.map(|p| p.slug).ok().unwrap_or_default()
    } else {
        String::new()
    };
    let mut ctx = auth.clone();
    if let Some(pid) = cert.project_id {
        ctx.project_id = Some(pid);
        ctx.project_role = db::get_member_role(&state.db, pid, auth.user.id)
            .await
            .unwrap_or(None);
    }
    let input = PolicyInput::for_context(&ctx, &project_slug, "", Permission::ManageUsers, None);
    if let PolicyDecision::Deny { policy_id, message } =
        state.policy_engine.evaluate(cert.project_id, None, &input).await?
    {
        let mut denied = AuditContext::new(&ctx, AuditAction::SshCertRevoke)
            .with_meta(serde_json::json!({ "ssh_cert_id": id }));
        if let Some(pid) = cert.project_id {
            denied = denied.with_project(pid);
        }
        state.audit.log_denied(&mut denied, &format!("Policy {}: {}", policy_id, message)).await.ok();
        return Err(ApiError::Forbidden(format!("Policy {}: {}", policy_id, message)));
    }

    db::revoke_ssh_cert(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::SshCertRevoke);
    audit = audit.with_meta(serde_json::json!({ "ssh_cert_id": id }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(())
}
/// List the certs a given CA has issued. Admin-only.
pub async fn list_issued_certs(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(ca_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    let certs = db::list_issued_certs(&state.db, ca_id, true).await?;
    Ok(Json(serde_json::json!({ "certs": certs })))
}

/// Revoke a single previously-issued certificate. Admin-only. The CA
/// itself stays valid; the per-cert serial is the revocation handle.
pub async fn revoke_issued_cert(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !auth.can(Permission::ManageUsers) {
        return Err(ApiError::Forbidden("Admin only".into()));
    }
    db::revoke_issued_cert(&state.db, id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::CaRevoke)
        .with_meta(serde_json::json!({ "issued_cert_id": id.to_string() }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}
