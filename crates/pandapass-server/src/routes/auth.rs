use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use pandapass_core::audit::{AuditContext, AuditAction, AuditOutcome};
use pandapass_core::crypto::{generate_token, hash_password, hash_token, verify_password, totp_uri, generate_totp_secret, verify_totp};
use pandapass_core::models::*;
use pandapass_core::rbac::{Permission, Rbac};
use pandapass_db as db;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::state::AppState;
use crate::middleware::auth::{Auth, issue_session, ApiError, SESSION_COOKIE, CSRF_COOKIE, require_csrf};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user: UserPublic,
    pub session_token: String,
    pub requires_totp: bool,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    let user = db::get_user_by_email(&state.db, &req.email)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".into()))?;

    if user.disabled_at.is_some() {
        return Err(ApiError::Unauthorized("User disabled".into()));
    }

    let valid = verify_password(&req.password, &user.password_hash)?;
    if !valid {
        return Err(ApiError::Unauthorized("Invalid credentials".into()));
    }

    // TOTP check
    if user.totp_enabled {
        let code = req.totp_code.ok_or_else(|| ApiError::Unauthorized("TOTP required".into()))?;
        if !verify_totp(user.totp_secret_enc.as_ref().map(|s| s.expose_secret()).unwrap_or(""), &code) {
            return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
        }
    } else if state.config.require_totp {
        // TOTP not set up but required
        return Err(ApiError::Unauthorized("TOTP setup required".into()));
    }

    db::touch_last_login(&state.db, user.id).await?;

    let (session_token, csrf) = issue_session(&state, user.id, None, None).await?;

    let mut jar = jar;
    jar = jar.add(Cookie::build((SESSION_COOKIE, session_token.clone()))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .finish());
    jar = jar.add(Cookie::build((CSRF_COOKIE, csrf))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .finish());

    let audit = AuditContext::new(&AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
    }, AuditAction::Login)
    .with_ip("".into())
    .with_user_agent("".into());
    state.audit.log_success(&audit).await.ok();

    Ok((
        jar,
        Json(LoginResponse {
            user: user.into(),
            session_token,
            requires_totp: false,
        }),
    ))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<RegisterRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    // Check if registration is allowed (first user becomes admin, or admin exists)
    let user_count = db::count_users(&state.db).await?;
    let is_first = user_count == 0;

    // If not first user, only allow if configured or existing admin
    if !is_first {
        // Check if there's an admin - if so, registration is closed by default
        // For now, we allow registration but make them regular users
    }

    let global_role = if is_first { GlobalRole::Admin } else { GlobalRole::User };
    let password_hash = hash_password(&req.password)?;

    let user = db::create_user(&state.db, &req.email, &password_hash, global_role).await?;

    db::touch_last_login(&state.db, user.id).await?;

    let (session_token, csrf) = issue_session(&state, user.id, None, None).await?;

    let mut jar = jar;
    jar = jar.add(Cookie::build((SESSION_COOKIE, session_token.clone()))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .finish());
    jar = jar.add(Cookie::build((CSRF_COOKIE, csrf))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .finish());

    let audit = AuditContext::new(&AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
    }, AuditAction::Register)
    .with_ip("".into())
    .with_user_agent("".into());
    state.audit.log_success(&audit).await.ok();

    Ok((
        jar,
        Json(LoginResponse {
            user: user.into(),
            session_token,
            requires_totp: false,
        }),
    ))
}

pub async fn logout(
    Auth(auth): Auth,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    if let Some(session) = &auth.0.session {
        db::delete_session(&state.db, session.id).await?;
    }

    let mut jar = jar;
    jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/").finish());
    jar = jar.remove(Cookie::build(CSRF_COOKIE).path("/").finish());

    let audit = AuditContext::new(&auth.0, AuditAction::Logout);
    state.audit.log_success(&audit).await.ok();

    Ok((jar, Json(serde_json::json!({ "success": true }))))
}

pub async fn logout_all(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    db::delete_all_sessions(&state.db, auth.0.user.id).await?;

    let audit = AuditContext::new(&auth.0, AuditAction::Logout)
        .with_meta(serde_json::json!({ "all_devices": true }));
    state.audit.log_success(&audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
    pub qr_code_svg: String,
}

pub async fn totp_setup(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<TotpSetupResponse>, ApiError> {
    // Generate new TOTP secret
    let secret = generate_totp_secret();
    let uri = totp_uri(&auth.0.user.email, &secret, "PandaPass");
    let qr_code_svg = qr_code_svg(&uri);

    // Encrypt the secret with master key
    // For now, we'll store it as-is (user will verify before enabling)
    // In production, encrypt with user's envelope

    Ok(Json(TotpSetupResponse { secret, uri, qr_code_svg }))
}

fn qr_code_svg(uri: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::svg;
    let code = QrCode::new(uri).unwrap();
    code.render::<svg::Color>().min_dimensions(200, 200).dark_color(svg::Color("#000")).light_color(svg::Color("#fff")).build()
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

pub async fn totp_verify(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = db::get_user_by_id(&state.db, auth.0.user.id).await?;

    // The secret was generated in setup - we need to verify against it
    // For now, we expect the secret to be stored (encrypted) in the user record
    // This is a simplified flow - in reality we'd store the pending secret temporarily

    let secret_enc = user.totp_secret_enc.as_ref()
        .ok_or_else(|| ApiError::BadRequest("TOTP not set up".into()))?;

    let secret = secret_enc.expose_secret();

    if !verify_totp(secret, &req.code) {
        let audit = AuditContext::new(&auth.0, AuditAction::TotpVerify)
            .with_outcome(AuditOutcome::Failure);
        state.audit.log(&audit).await.ok();
        return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
    }

    // TOTP verified - mark as enabled
    // The secret is already encrypted and stored
    db::set_user_totp(&state.db, user.id, Some(secret_enc), true).await?;

    let audit = AuditContext::new(&auth.0, AuditAction::TotpSetup);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true, "enabled": true })))
}

#[derive(Deserialize)]
pub struct TotpDisableRequest {
    pub code: String,
    pub password: String,
}

pub async fn totp_disable(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<TotpDisableRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = db::get_user_by_id(&state.db, auth.0.user.id).await?;

    // Verify password
    if !verify_password(&req.password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Invalid password".into()));
    }

    // Verify TOTP
    let secret_enc = user.totp_secret_enc.as_ref()
        .ok_or_else(|| ApiError::BadRequest("TOTP not enabled".into()))?;

    if !verify_totp(secret_enc.expose_secret(), &req.code) {
        let audit = AuditContext::new(&auth.0, AuditAction::TotpDisable)
            .with_outcome(AuditOutcome::Failure);
        state.audit.log(&audit).await.ok();
        return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
    }

    // Disable TOTP
    db::set_user_totp(&state.db, user.id, None, false).await?;
    db::set_recovery_codes(&state.db, user.id, &[]).await?;

    let audit = AuditContext::new(&auth.0, AuditAction::TotpDisable);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn me(Auth(auth): Auth) -> Json<UserPublic> {
    Json(auth.0.user.clone())
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = db::get_user_by_id(&state.db, auth.0.user.id).await?;

    if !verify_password(&req.current_password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Current password incorrect".into()));
    }

    let new_hash = hash_password(&req.new_password)?;
    // Update password (need to add this to db module)
    sqlx::query("UPDATE users SET password_hash = ?2 WHERE id = ?1")
        .bind(user.id.to_string())
        .bind(new_hash)
        .execute(&state.db)
        .await?;

    // Invalidate all other sessions
    db::delete_all_sessions(&state.db, user.id).await?;

    let audit = AuditContext::new(&auth.0, AuditAction::PasswordChange);
    state.audit.log_success(&audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}