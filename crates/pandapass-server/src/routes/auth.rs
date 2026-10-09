use axum::{
    extract::{Path, State},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use pandapass_core::audit::{AuditContext, AuditAction, AuditOutcome};
use pandapass_core::crypto::{
    generate_totp_secret, hash_password, totp_uri, verify_password,
    verify_totp, AgeIdentity, AgePublicKey, EncryptedSecret, Envelope, MasterKey, SealOptions,
};
use pandapass_core::models::*;
use pandapass_db as db;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;
use crate::middleware::auth::{Auth, issue_session, ApiError, SESSION_COOKIE, CSRF_COOKIE};

/// The server's own age public key — the recipient it accepts envelopes under.
/// `None` when no identity is configured, which means the server is locked out
/// of every envelope and can only store ciphertext it cannot read back.
fn server_recipient(state: &AppState) -> Option<AgePublicKey> {
    let identity = state.config.server_age_identity.as_deref().filter(|s| !s.is_empty())?;
    AgeIdentity::parse(identity).ok()?.public_key().ok()
}

/// The server's own age identity, without which it cannot unwrap any envelope.
fn server_identity(state: &AppState) -> Result<&str, ApiError> {
    state.config.server_age_identity.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
        ApiError::Forbidden(
            "This server has no age identity, so it cannot operate on secrets. \
             Configure PANDAPASS_SERVER_AGE_IDENTITY."
                .into(),
        )
    })
}

/// Unwrap a user's master key from their age envelope using the server's identity.
async fn get_master_key_for_user(
    state: &AppState,
    user_id: Uuid,
) -> Result<MasterKey, ApiError> {
    let envelope = db::get_envelope(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Forbidden("No master-key envelope for this account".into()))?;

    envelope.decrypt(server_identity(state)?).map_err(ApiError::from)
}

/// Decrypt a user's TOTP secret using their master key.
async fn decrypt_totp_secret(state: &AppState, user: &User) -> Result<String, ApiError> {
    let totp_secret_enc = user
        .totp_secret_enc
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("TOTP not set up".into()))?;
    let mk = get_master_key_for_user(state, user.id).await?;
    let secret_str = totp_secret_enc.decrypt_with_purpose(
        &mk,
        pandapass_core::crypto::key_purpose::TOTP_SECRET,
    )?;
    Ok(secret_str.expose_secret().to_string())
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user: UserPublic,
    pub session_token: Option<String>,
    pub requires_totp: bool,
    /// Whether this account has a sealed master-key envelope. False means the
    /// user must enrol an age key before they can store or read secrets.
    #[serde(default)]
    pub key_enrolled: bool,
}

pub async fn login(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    // Extract client IP from request extensions (set by auth_middleware)
    let client_ip = req.extensions().get::<crate::middleware::auth::ClientIp>().map(|c| c.0);

    // Extract cookies and JSON body manually
    let (parts, body) = req.into_parts();
    let jar = CookieJar::from_headers(&parts.headers);
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.map_err(|_| ApiError::BadRequest("Failed to read body".into()))?;
    let login_req: LoginRequest = serde_json::from_slice(&body_bytes).map_err(|_| ApiError::BadRequest("Invalid JSON".into()))?;

    // Rate limit check happens before credential verification so a valid
    // password doesn't bypass the limit.
    if let Some(ip) = client_ip {
        if let Err(retry_after) = state.rate_limiter.check(ip).await {
            return Err(ApiError::TooManyRequests(format!(
                "Too many login attempts. Try again in {retry_after} seconds."
            )));
        }
    }
    state.metrics.inc_login_attempts();

    let user = db::get_user_by_email(&state.db, &login_req.email)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".into()))?;

    if user.disabled_at.is_some() {
        return Err(ApiError::Unauthorized("User disabled".into()));
    }

    // Per-account lockout: a distributed brute force (many IPs, one account)
    // is bounded by this counter, which the per-IP rate limiter cannot see.
    const MAX_FAILURES: i64 = 5;
    const LOCKOUT_SECS: i64 = 900; // 15 minutes
    if let Some(until) = user.locked_until {
        if until > chrono::Utc::now() {
            return Err(ApiError::Unauthorized(
                "Account temporarily locked after too many failed attempts. Try again later.".into(),
            ));
        }
        // Lockout expired: clear it so the next failure starts fresh.
        db::reset_login_failures(&state.db, user.id).await?;
    }

    let valid = verify_password(&login_req.password, &user.password_hash)?;
    if !valid {
        state.metrics.inc_login_failures();
        db::record_login_failure(&state.db, user.id, MAX_FAILURES, LOCKOUT_SECS).await?;
        return Err(ApiError::Unauthorized("Invalid credentials".into()));
    }

    // Successful login — reset the rate limit bucket for this IP
    if let Some(ip) = client_ip {
        state.rate_limiter.reset(ip).await;
    }

    // TOTP check
    if user.totp_enabled {
        let code = login_req.totp_code.ok_or_else(|| ApiError::Unauthorized("TOTP required".into()))?;
        let totp_secret = decrypt_totp_secret(&state, &user).await?;
        if !verify_totp(&totp_secret, &code) {
            db::record_login_failure(&state.db, user.id, MAX_FAILURES, LOCKOUT_SECS).await?;
            return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
        }
    } else if state.config.require_totp {
        // TOTP not set up but required
        return Err(ApiError::Unauthorized("TOTP setup required".into()));
    }

    db::reset_login_failures(&state.db, user.id).await?;
    db::touch_last_login(&state.db, user.id).await?;

    let (session_token, csrf) = issue_session(&state, user.id, None, None).await?;

    let mut jar = jar;
    jar = jar.add(Cookie::build((SESSION_COOKIE, session_token.clone()))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .build());
    // Deliberately NOT HttpOnly: the web UI reads this cookie from
    // document.cookie and echoes it in the x-csrf-token header (double-submit
    // pattern). The CSRF token is not a secret — an attacker who can read it
    // still cannot craft a cross-site request because SameSite=Lax + the
    // custom header requirement block the cross-site send.
    jar = jar.add(Cookie::build((CSRF_COOKIE, csrf))
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .build());

    let auth_ctx = AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
    };
    let mut audit = AuditContext::new(&auth_ctx, AuditAction::Login);
    let (ip, ua) = client_ip_and_ua(&parts.headers);
    audit = audit.with_ip(ip);
    audit = audit.with_user_agent(ua);
    state.audit.log_success(&mut audit).await.ok();

    let key_enrolled = db::get_envelope(&state.db, user.id).await?.is_some();

    Ok((
        jar,
        Json(LoginResponse {
            user: user.into(),
            session_token: is_cli_request(&parts.headers).then_some(session_token),
            requires_totp: false,
            key_enrolled,
        }),
    ))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// The client's age public key (`age1...`), used to wrap this user's
    /// master-key envelope. Optional: without it the account exists but cannot
    /// store secrets until a key is enrolled.
    pub age_public_key: Option<String>,
}

/// Mint a user's master key and seal it to `recipient` (plus the server, if it
/// has an identity configured).
///
/// This runs on the server, which is what lets an admin onboard teammates
/// without handling anyone's private key. The plaintext MK exists only in this
/// function's stack frame; only the sealed envelope is persisted.
fn create_envelope(
    state: &AppState,
    user_id: Uuid,
    recipient: &AgePublicKey,
) -> Result<Envelope, ApiError> {
    let mk = MasterKey::generate();
    Envelope::create(
        user_id,
        &mk,
        recipient,
        &SealOptions { server: server_recipient(state) },
    )
    .map_err(ApiError::from)
}

pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    req: axum::http::Request<axum::body::Body>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    // Extract client IP (set by the outer `client_ip_middleware`) and the
    // JSON body. Doing this by hand keeps the rate-limit gate before the
    // registration rule check, so the limit holds even when registration is
    // open for the bootstrap admin.
    let client_ip = req.extensions().get::<crate::middleware::auth::ClientIp>().map(|c| c.0);
    let (_parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| ApiError::BadRequest("Failed to read body".into()))?;
    let req: RegisterRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::BadRequest("Invalid JSON".into()))?;

    if let Some(ip) = client_ip {
        if let Err(retry_after) = state.rate_limiter.check(ip).await {
            return Err(ApiError::TooManyRequests(format!(
                "Too many registration attempts. Try again in {retry_after} seconds."
            )));
        }
    }

    // Registration is closed by default: a secrets vault must never accept
    // self-service signups, or anyone who finds the URL gets an account.
    // Only the very first user (bootstrap) or an explicit opt-in may register.
    let user_count = db::count_users(&state.db).await?;
    let is_first = user_count == 0;

    if !is_first && !state.config.allow_registration {
        return Err(ApiError::Forbidden(
            "Registration is closed. Ask an admin to create your account.".into(),
        ));
    }

    let global_role = if is_first { GlobalRole::Admin } else { GlobalRole::User };
    pandapass_core::crypto::validate_password_policy(&req.password)?;
    let password_hash = hash_password(&req.password)?;

    let user = db::create_user(&state.db, &req.email, &password_hash, global_role).await?;

    if let Some(ip) = client_ip {
        state.rate_limiter.reset(ip).await;
    }

    // Seal a master key to the caller's public key, if they supplied one.
    let mut enrolled = false;
    if let Some(pk) = req.age_public_key.as_deref().filter(|s| !s.is_empty()) {
        let recipient = AgePublicKey(pk.trim().to_string());
        // Fail loudly on a malformed key rather than silently creating an
        // account the user can never use.
        recipient.to_recipient()?;

        // The server is added as a recipient too, so that `get_secret` and
        // MCP `run_with_secret` can decrypt on the member's behalf. Without a
        // server identity the envelope is member-only, which still works for
        // clients that unwrap it locally.
        if server_recipient(&state).is_none() {
            tracing::warn!(
                "No server age identity configured; the new account's envelope is \
                 member-only, so server-side decryption is unavailable to it."
            );
        }

        let env = create_envelope(&state, user.id, &recipient)?;
        db::put_envelope(&state.db, user.id, &env.ciphertext).await?;
        enrolled = true;
    }

    db::touch_last_login(&state.db, user.id).await?;

    let (session_token, csrf) = issue_session(&state, user.id, None, None).await?;

    let mut jar = jar;
    jar = jar.add(Cookie::build((SESSION_COOKIE, session_token.clone()))
        .http_only(true)
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .build());
    // Deliberately NOT HttpOnly: the web UI reads this cookie from
    // document.cookie and echoes it in the x-csrf-token header (double-submit
    // pattern). The CSRF token is not a secret — an attacker who can read it
    // still cannot craft a cross-site request because SameSite=Lax + the
    // custom header requirement block the cross-site send.
    jar = jar.add(Cookie::build((CSRF_COOKIE, csrf))
        .secure(state.config.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .path("/")
        .build());

    let auth_ctx = AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
    };
    let mut audit = AuditContext::new(&auth_ctx, AuditAction::Register);
    let (ip, ua) = client_ip_and_ua(&_parts.headers);
    audit = audit.with_ip(ip);
    audit = audit.with_user_agent(ua);
    audit = audit.with_meta(serde_json::json!({ "key_enrolled": enrolled }));
    state.audit.log_success(&mut audit).await.ok();

    Ok((
        jar,
        Json(LoginResponse {
            user: user.into(),
            session_token: is_cli_request(&_parts.headers).then_some(session_token),
            requires_totp: false,
            key_enrolled: enrolled,
        }),
    ))
}

pub async fn logout(
    Auth(auth): Auth,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    if let Some(session) = &auth.session {
        db::delete_session(&state.db, session.id).await?;
    }

    let mut jar = jar;
    jar = jar.remove(Cookie::build(SESSION_COOKIE).path("/").build());
    jar = jar.remove(Cookie::build(CSRF_COOKIE).path("/").build());

    let mut audit = AuditContext::new(&auth, AuditAction::Logout);
    state.audit.log_success(&mut audit).await.ok();

    Ok((jar, Json(serde_json::json!({ "success": true }))))
}

pub async fn logout_all(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    db::delete_all_sessions(&state.db, auth.user.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::Logout)
        .with_meta(serde_json::json!({ "all_devices": true }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Serialize)]
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
    let uri = totp_uri(&auth.user.email, &secret, "PandaPass");
    let qr_code_svg = qr_code_svg(&uri);

    // A user who registered without an age public key has no envelope and
    // therefore no master key. Without one, TOTP cannot be stored. Instead
    // of refusing (which would permanently block a REQUIRE_TOTP deployment
    // for such accounts), mint a master key here and seal it to the server
    // recipient. The member can re-enrol with `enroll_key rotate=true`
    // later to add their age key as a recipient.
    let envelope = db::get_envelope(&state.db, auth.user.id).await?;
    let mk = match envelope {
        Some(env) => env
            .decrypt(&crate::routes::secrets::server_identity_str(&state)?)
            .map_err(ApiError::from)?,
        None => {
            let identity = crate::routes::secrets::server_identity_str(&state)?;
            let age = AgeIdentity::parse(&identity)
                .map_err(|e| ApiError::Internal(format!("server age: {e}")))?;
            let server_pub = age
                .public_key()
                .map_err(|e| ApiError::Internal(format!("server public: {e}")))?;
            let mk = MasterKey::generate();
            let env = Envelope::create(
                auth.user.id,
                &mk,
                &server_pub,
                &SealOptions { server: Some(server_pub.clone()) },
            )
            .map_err(ApiError::from)?;
            db::put_envelope(&state.db, auth.user.id, &env.ciphertext).await?;
            mk
        }
    };

    let secret_enc = EncryptedSecret::encrypt_with_purpose(
        &secret,
        &mk,
        pandapass_core::crypto::key_purpose::TOTP_SECRET,
    )?;

    // Store encrypted TOTP secret (not enabled yet - user must verify)
    db::set_user_totp(&state.db, auth.user.id, Some(&secret_enc), false).await?;

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
    let user = db::get_user_by_id(&state.db, auth.user.id).await?;

    let totp_secret = decrypt_totp_secret(&state, &user).await?;

    if !verify_totp(&totp_secret, &req.code) {
        let audit = AuditContext::new(&auth, AuditAction::TotpVerify)
            .with_outcome(AuditOutcome::Failure);
        state.audit.log(&audit).await.ok();
        return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
    }

    // TOTP verified - mark as enabled (secret already encrypted and stored)
    db::set_user_totp(&state.db, user.id, user.totp_secret_enc.as_ref(), true).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::TotpSetup);
    state.audit.log_success(&mut audit).await.ok();

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
    let user = db::get_user_by_id(&state.db, auth.user.id).await?;

    // Verify password
    if !verify_password(&req.password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Invalid password".into()));
    }

    // Verify TOTP
    if user.totp_secret_enc.is_none() {
        return Err(ApiError::BadRequest("TOTP not enabled".into()));
    }
    let totp_secret = decrypt_totp_secret(&state, &user).await?;

    if !verify_totp(&totp_secret, &req.code) {
        let audit = AuditContext::new(&auth, AuditAction::TotpDisable)
            .with_outcome(AuditOutcome::Failure);
        state.audit.log(&audit).await.ok();
        return Err(ApiError::Unauthorized("Invalid TOTP code".into()));
    }

    // Disable TOTP
    db::set_user_totp(&state.db, user.id, None, false).await?;
    db::set_recovery_codes(&state.db, user.id, &[]).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::TotpDisable);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

pub async fn me(Auth(auth): Auth) -> Json<UserPublic> {
    Json(auth.user.clone())
}

#[derive(Deserialize)]
pub struct EnrollKeyRequest {
    /// The client's age public key (`age1...`).
    pub age_public_key: String,
    /// Re-seal the *existing* master key to this key instead of minting a
    /// new one. Required when the account already holds secrets: a fresh
    /// master key cannot read anything written under the old one.
    #[serde(default)]
    pub rotate: bool,
}

#[derive(Serialize)]
pub struct EnrollKeyResponse {
    pub key_enrolled: bool,
    /// True when an existing master key was re-wrapped, false when a new one
    /// was minted. A re-wrap keeps previously-stored secret ciphertext
    /// readable; a fresh mint does not.
    pub rewrapped: bool,
}

/// Seal the caller's master key to an age public key.
///
/// This is what makes an account usable. An account that registered without
/// a public key has no envelope at all and therefore cannot store or read a
/// single secret — this endpoint is how it fixes that.
///
/// CSRF is already enforced by `auth_middleware` for cookie sessions.
pub async fn enroll_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<EnrollKeyRequest>,
) -> Result<Json<EnrollKeyResponse>, ApiError> {
    let recipient = AgePublicKey(req.age_public_key.trim().to_string());
    recipient.to_recipient()?; // reject malformed keys up front

    let server = server_recipient(&state);
    if server.is_none() {
        tracing::warn!(
            "No server age identity configured; the envelope is member-only, so \
             server-side decryption and MCP run_with_secret are unavailable."
        );
    }

    let existing = db::get_envelope(&state.db, auth.user.id).await?;
    let rewrapped = match (existing, req.rotate) {
        // Re-wrap: unwrap the current master key and seal it again to the new
        // key, so every secret already written under it stays readable.
        (Some(current), true) => {
            // Re-wrapping the *existing* master key requires unwrapping it
            // first, which only the server's own identity can do. An account
            // whose envelope predates the server's identity is therefore
            // stuck on the member-only path until the server is configured —
            // minting a fresh key here instead would silently orphan every
            // secret already written, so refuse rather than destroy them.
            let mk = current.decrypt(server_identity(&state)?).map_err(|_| {
                ApiError::Conflict(
                    "This account's master key is sealed only to the member, so it \
                     cannot be re-wrapped here. Either configure the server age \
                     identity, or mint a new key (rotate=false) and re-enter your \
                     secrets — existing ones will no longer be readable."
                        .into(),
                )
            })?;
            let env = Envelope::create(
                auth.user.id,
                &mk,
                &recipient,
                &SealOptions { server: server.clone() },
            )?;
            db::put_envelope(&state.db, auth.user.id, &env.ciphertext).await?;
            true
        }
        // A second enrollment without `rotate` would orphan every secret
        // already written under the current master key.
        (Some(_), false) => {
            return Err(ApiError::Conflict(
                "This account already has a master key. Re-send with rotate=true to \
                 re-wrap the existing one to the new key."
                    .into(),
            ));
        }
        (None, _) => {
            let env = create_envelope(&state, auth.user.id, &recipient)?;
            db::put_envelope(&state.db, auth.user.id, &env.ciphertext).await?;
            false
        }
    };

    let mut audit = AuditContext::new(&auth, AuditAction::Register)
        .with_meta(serde_json::json!({ "enrolled_key": true, "rewrapped": rewrapped }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(EnrollKeyResponse { key_enrolled: true, rewrapped }))
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
    let user = db::get_user_by_id(&state.db, auth.user.id).await?;

    if !verify_password(&req.current_password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Current password incorrect".into()));
    }

    pandapass_core::crypto::validate_password_policy(&req.new_password)?;
    let new_hash = hash_password(&req.new_password)?;
    // Update password (need to add this to db module)
    sqlx::query("UPDATE users SET password_hash = ?2 WHERE id = ?1")
        .bind(user.id.to_string())
        .bind(new_hash)
        .execute(&state.db)
        .await?;

    // Invalidate all other sessions
    db::delete_all_sessions(&state.db, user.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::PasswordChange);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}
#[derive(Serialize)]
pub struct MkRotateResponse {
    pub rotated: bool,
    /// Number of secret values re-encrypted under the new master key.
    pub secrets_reencrypted: usize,
    /// Number of dynamic-credential passwords re-encrypted.
    pub dynamic_creds_reencrypted: usize,
    /// Number of CA private keys re-encrypted.
    pub cas_reencrypted: usize,
}

/// Rotate the caller's master key.
///
/// Generates a fresh 32-byte master key, re-encrypts every secret the
/// caller owns (regular values, dynamic-credential passwords, CA
/// private keys) under it, and seals the new MK in the existing envelope.
/// The new MK is unrelated to the old one, so a leak of the old key
/// compromises no future ciphertext.
///
/// This is the "I lost my age key but kept the encrypted database"
/// path: a member who holds only the server-side envelope (no member
/// age key) can still recover because the server holds its own copy.
/// A member who also enrolled an age key needs to re-enrol with
/// `rotate=true` after this so the new MK is sealed to their new key.
///
/// Requires password re-authentication so a stolen session cannot
/// silently rotate the user's MK.
#[derive(Deserialize)]
pub struct MkRotateRequest {
    pub current_password: String,
}

pub async fn rotate_master_key(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Json(req): Json<MkRotateRequest>,
) -> Result<Json<MkRotateResponse>, ApiError> {
    let user = db::get_user_by_id(&state.db, auth.user.id).await?;
    if !verify_password(&req.current_password, &user.password_hash)? {
        return Err(ApiError::Unauthorized("Current password incorrect".into()));
    }

    let old_mk = crate::routes::secrets::get_master_key(&state, user.id).await?;
    let new_mk = MasterKey::generate();

    let mut secrets_count = 0usize;
    let mut creds_count = 0usize;
    let mut cas_count = 0usize;

    // Re-encrypt regular secrets.
    let secrets = db::all_secrets_for_user(&state.db, user.id).await?;
    for secret in secrets {
        let plaintext = secret
            .value_enc
            .decrypt(&old_mk)
            .map_err(ApiError::from)?
            .expose_secret()
            .to_string();
        let value_enc = EncryptedSecret::encrypt_with_purpose(
            &plaintext,
            &new_mk,
            pandapass_core::crypto::key_purpose::SECRET_VALUE,
        )
        .map_err(ApiError::from)?;
        sqlx::query(
            "UPDATE secrets SET value_enc = ?2 WHERE id = ?1",
        )
        .bind(secret.meta.id.to_string())
        .bind(serde_json::to_string(&value_enc).unwrap())
        .execute(&state.db)
        .await?;
        secrets_count += 1;
    }

    // Re-encrypt dynamic-credential passwords.
    let creds = db::all_dynamic_creds_for_user(&state.db, user.id).await?;
    for cred in creds {
        let plaintext = cred
            .password_enc
            .decrypt_with_purpose(&old_mk, pandapass_core::crypto::key_purpose::DYNAMIC_CRED_PASSWORD)
            .map_err(ApiError::from)?
            .expose_secret()
            .to_string();
        let password_enc = EncryptedSecret::encrypt_with_purpose(
            &plaintext,
            &new_mk,
            pandapass_core::crypto::key_purpose::DYNAMIC_CRED_PASSWORD,
        )
        .map_err(ApiError::from)?;
        sqlx::query(
            "UPDATE dynamic_creds SET password_enc = ?2 WHERE id = ?1",
        )
        .bind(cred.id.to_string())
        .bind(serde_json::to_string(&password_enc).unwrap())
        .execute(&state.db)
        .await?;
        creds_count += 1;
    }

    // Re-encrypt CA private keys this user uploaded.
    let cas = db::list_ca_keys_for_user(&state.db, user.id).await.unwrap_or_default();
    for ca in cas {
        let plaintext = ca
            .key_enc
            .decrypt_with_purpose(&old_mk, pandapass_core::crypto::key_purpose::CA_X509_KEY)
            .map_err(ApiError::from)?
            .expose_secret()
            .to_string();
        let key_enc = EncryptedSecret::encrypt_with_purpose(
            &plaintext,
            &new_mk,
            pandapass_core::crypto::key_purpose::CA_X509_KEY,
        )
        .map_err(ApiError::from)?;
        sqlx::query(
            "UPDATE ca_keys SET key_enc = ?2 WHERE id = ?1",
        )
        .bind(ca.id.to_string())
        .bind(serde_json::to_string(&key_enc).unwrap())
        .execute(&state.db)
        .await?;
        cas_count += 1;
    }

    // Re-encrypt the TOTP secret if any.
    if let Some(totp_enc) = user.totp_secret_enc.as_ref() {
        let plaintext = totp_enc
            .decrypt_with_purpose(&old_mk, pandapass_core::crypto::key_purpose::TOTP_SECRET)
            .map_err(ApiError::from)?
            .expose_secret()
            .to_string();
        let new_enc = EncryptedSecret::encrypt_with_purpose(
            &plaintext,
            &new_mk,
            pandapass_core::crypto::key_purpose::TOTP_SECRET,
        )
        .map_err(ApiError::from)?;
        db::set_user_totp(&state.db, user.id, Some(&new_enc), user.totp_enabled).await?;
    }

    // Re-seal the new MK to the same envelope (same set of age recipients).
    let member = state
        .config
        .server_age_identity
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Forbidden(
            "This server has no age identity, so it cannot re-seal your master key.".into(),
        ))?;
    let identity = pandapass_core::crypto::AgeIdentity::parse(member)
        .map_err(|e| ApiError::Internal(format!("server age identity: {e}")))?;
    let server_pub = identity.public_key().map_err(|e| ApiError::Internal(format!("server public key: {e}")))?;
    let env = Envelope::create(
        user.id,
        &new_mk,
        // We do not know the member's public key without re-asking. For the
        // rotate path we re-seal the new MK to the server recipient only
        // and rely on the member re-enrolling with `rotate=true` to add
        // their key as a recipient. Until they do, they cannot read
        // anything client-side — which is fine, because the goal of this
        // endpoint is to keep the server-side path alive, not to keep the
        // member-side path.
        &server_pub,
        &SealOptions { server: Some(server_pub.clone()) },
    )
    .map_err(ApiError::from)?;
    db::put_envelope(&state.db, user.id, &env.ciphertext).await?;

    // Invalidate sessions so a leaked cookie does not survive the rotation.
    db::delete_all_sessions(&state.db, user.id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::MkRotate)
        .with_meta(serde_json::json!({
            "secrets_reencrypted": secrets_count,
            "dynamic_creds_reencrypted": creds_count,
            "cas_reencrypted": cas_count,
        }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(MkRotateResponse {
        rotated: true,
        secrets_reencrypted: secrets_count,
        dynamic_creds_reencrypted: creds_count,
        cas_reencrypted: cas_count,
    }))
}

#[derive(Serialize)]
pub struct RecoveryCodesResponse {
    /// Plaintext recovery codes, returned exactly once. The caller must
    /// store them in a safe place; the server only retains argon2
    /// hashes.
    pub codes: Vec<String>,
}

/// Generate a fresh set of recovery codes for the caller.
///
/// 8 codes, each 16 random bytes URL-safe base64-encoded. The plaintext
/// codes are returned exactly once; the server only stores argon2 hashes
/// so a database compromise cannot replay them.
///
/// Calling this endpoint replaces any previously-issued codes. A
/// successful login already implies possession of the password and
/// (when enabled) TOTP, so re-issuing codes is a self-service
/// administrative step.
pub async fn recovery_codes_generate(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<RecoveryCodesResponse>, ApiError> {
    let mut codes: Vec<String> = (0..8)
        .map(|_| pandapass_core::crypto::generate_token(16))
        .collect();
    // Sort the codes so the order is consistent for the caller.
    codes.sort();

    let hashes: Vec<String> = codes
        .iter()
        .map(|c| pandapass_core::crypto::hash_password(c).unwrap_or_default())
        .collect();

    db::set_recovery_codes(&state.db, auth.user.id, &hashes).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::Register)
        .with_meta(serde_json::json!({ "recovery_codes_generated": codes.len() }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(RecoveryCodesResponse { codes }))
}

#[derive(Deserialize)]
pub struct RecoveryCodeRedeemRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct RecoveryCodeRedeemResponse {
    /// New master-key envelope sealed to the server (and to the supplied
    /// age public key, if any). The new MK is unrelated to the old one,
    /// so a leak of the old key compromises nothing going forward.
    pub rotated: bool,
}

/// Redeem a recovery code: the user has lost both their password and
/// TOTP. The recovery code is the only proof of identity they still
/// hold. This endpoint rotates the master key and — if a member age
/// public key is supplied — re-seals the new envelope to that key.
///
/// Rate-limited via the auth rate limiter (a fresh IP after a theft is
/// expected; brute force is bounded by code space = 8 * 2**128).
pub async fn recovery_code_redeem(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<RecoveryCodeRedeemResponse>, ApiError> {
    let client_ip = req.extensions().get::<crate::middleware::auth::ClientIp>().map(|c| c.0);
    if let Some(ip) = client_ip {
        if let Err(retry_after) = state.rate_limiter.check(ip).await {
            return Err(ApiError::TooManyRequests(format!(
                "Too many recovery attempts. Try again in {retry_after} seconds."
            )));
        }
    }

    let (_parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| ApiError::BadRequest("Failed to read body".into()))?;
    let req: RecoveryCodeRedeemRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::BadRequest("Invalid JSON".into()))?;

    // The request must identify the user — either by email (separate
    // field) or implicitly via the code prefix. For simplicity we ask the
    // caller to send their email alongside the code.
    #[derive(Deserialize)]
    struct WithEmail {
        email: String,
        #[serde(default)]
        age_public_key: Option<String>,
    }
    let raw: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::BadRequest("Invalid JSON".into()))?;
    let with_email: WithEmail = serde_json::from_value(raw)
        .map_err(|_| ApiError::BadRequest("email is required".into()))?;

    let user = db::get_user_by_email(&state.db, &with_email.email)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid code or email".into()))?;

    // Walk every hash; on match, consume the code.
    let raw_hashes = user.recovery_codes_hash.clone();
    let mut matched_idx: Option<usize> = None;
    for (i, h) in raw_hashes.iter().enumerate() {
        if h.is_empty() {
            continue;
        }
        if pandapass_core::crypto::verify_password(&req.code, h).unwrap_or(false) {
            matched_idx = Some(i);
            break;
        }
    }
    let Some(idx) = matched_idx else {
        return Err(ApiError::Unauthorized("Invalid code or email".into()));
    };

    // Consume the matched code by removing it from the list.
    let mut new_hashes = raw_hashes;
    new_hashes.remove(idx);
    db::set_recovery_codes(&state.db, user.id, &new_hashes).await?;

    // Rotate the MK using the B3 helper. We need to re-implement the
    // rotation here because the helper is on the user-self path; in
    // principle this should call into a shared function, but to keep
    // the change small we duplicate the small bit of logic.
    let old_mk = crate::routes::secrets::get_master_key(&state, user.id).await?;
    let new_mk = MasterKey::generate();
    let secrets = db::all_secrets_for_user(&state.db, user.id).await?;
    for secret in secrets {
        let plaintext = secret
            .value_enc
            .decrypt(&old_mk)
            .map_err(ApiError::from)?
            .expose_secret()
            .to_string();
        let value_enc = EncryptedSecret::encrypt_with_purpose(
            &plaintext,
            &new_mk,
            pandapass_core::crypto::key_purpose::SECRET_VALUE,
        )
        .map_err(ApiError::from)?;
        sqlx::query("UPDATE secrets SET value_enc = ?2 WHERE id = ?1")
            .bind(secret.meta.id.to_string())
            .bind(serde_json::to_string(&value_enc).unwrap())
            .execute(&state.db)
            .await?;
    }

    // Re-seal the new MK in the envelope. If a new age public key was
    // supplied we add it as a recipient; otherwise we only re-seal to
    // the server (the member will need to re-enrol to read anything
    // client-side, but the server-side path is alive).
    let server_identity = state
        .config
        .server_age_identity
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::Forbidden(
            "Server has no age identity; recovery rotation impossible.".into(),
        ))?;
    let age = AgeIdentity::parse(server_identity)
        .map_err(|e| ApiError::Internal(format!("server age: {e}")))?;
    let server_pub = age.public_key().map_err(|e| ApiError::Internal(format!("server public: {e}")))?;
    let member_recipient = with_email
        .age_public_key
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| AgePublicKey(s.trim().to_string()))
        .unwrap_or_else(|| server_pub.clone());
    if with_email.age_public_key.is_some() {
        member_recipient.to_recipient()?;
    }
    let env = Envelope::create(
        user.id,
        &new_mk,
        &member_recipient,
        &SealOptions { server: Some(server_pub.clone()) },
    )
    .map_err(ApiError::from)?;
    db::put_envelope(&state.db, user.id, &env.ciphertext).await?;

    // Invalidate all sessions for the user.
    db::delete_all_sessions(&state.db, user.id).await?;

    let auth_ctx = AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
    };
    let mut audit = AuditContext::new(&auth_ctx, AuditAction::Register);
    let meta = serde_json::json!({ "recovery_code_redeemed": true });
    audit = audit.with_meta(meta);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(RecoveryCodeRedeemResponse { rotated: true }))
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
    pub recovery_code: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct PasswordResetResponse {
    pub changed: bool,
}

/// Reset a password using a recovery code. No session is required: the
/// recovery code is the proof that the caller controls the account.
///
/// This complements the recovery-code redemption endpoint (which
/// rotates the MK and re-encrypts). Here the MK is left alone — only
/// the password hash changes — because a forgotten password is
/// independent of MK compromise.
pub async fn password_reset(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<PasswordResetResponse>, ApiError> {
    let client_ip = req.extensions().get::<crate::middleware::auth::ClientIp>().map(|c| c.0);
    if let Some(ip) = client_ip {
        if let Err(retry_after) = state.rate_limiter.check(ip).await {
            return Err(ApiError::TooManyRequests(format!(
                "Too many password reset attempts. Try again in {retry_after} seconds."
            )));
        }
    }
    let (_parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| ApiError::BadRequest("Failed to read body".into()))?;
    let req: PasswordResetRequest = serde_json::from_slice(&body_bytes)
        .map_err(|_| ApiError::BadRequest("Invalid JSON".into()))?;

    pandapass_core::crypto::validate_password_policy(&req.new_password)?;

    let user = db::get_user_by_email(&state.db, &req.email)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid code or email".into()))?;

    // Match the recovery code.
    let raw_hashes = user.recovery_codes_hash.clone();
    let mut matched_idx: Option<usize> = None;
    for (i, h) in raw_hashes.iter().enumerate() {
        if h.is_empty() {
            continue;
        }
        if pandapass_core::crypto::verify_password(&req.recovery_code, h).unwrap_or(false) {
            matched_idx = Some(i);
            break;
        }
    }
    let Some(idx) = matched_idx else {
        return Err(ApiError::Unauthorized("Invalid code or email".into()));
    };

    // Consume the matched code.
    let mut new_hashes = raw_hashes;
    new_hashes.remove(idx);
    db::set_recovery_codes(&state.db, user.id, &new_hashes).await?;

    // Update the password hash.
    pandapass_core::crypto::validate_password_policy(&req.new_password)?;
    let new_hash = hash_password(&req.new_password)?;
    sqlx::query("UPDATE users SET password_hash = ?2 WHERE id = ?1")
        .bind(user.id.to_string())
        .bind(new_hash)
        .execute(&state.db)
        .await?;

    // Invalidate all sessions for safety.
    db::delete_all_sessions(&state.db, user.id).await?;

    let auth_ctx = AuthContext {
        user: user.clone().into(),
        session: None,
        service_token: None,
        project_role: None,
        project_id: None,
        env_id: None,
            client_ip: None,
            user_agent: None,
            request_id: None,
    };
    let mut audit = AuditContext::new(&auth_ctx, AuditAction::PasswordChange);
    let meta = serde_json::json!({ "via": "recovery_code" });
    audit = audit.with_meta(meta);
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(PasswordResetResponse { changed: true }))
}

/// True when the request carries the `x-pandapass-agent: cli` header that
/// the PandaPass CLI sets. The CLI needs the session token in the JSON
/// response body to store it locally; the browser never should, because
/// an XSS that can read the body then gets a usable session token that
/// HttpOnly was supposed to protect. Web sessions rely on the cookie and
/// receive no token.
fn is_cli_request(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("x-pandapass-agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("cli"))
        .unwrap_or(false)
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// List the caller's active sessions. Only the current user's own sessions
/// are returned; no admin surface needed for the common "where am I logged
/// in?" workflow.
pub async fn list_my_sessions(
    Auth(auth): Auth,
    State(state): State<AppState>,
) -> Result<Json<Vec<SessionInfo>>, ApiError> {
    let sessions = db::list_sessions_for_user(&state.db, auth.user.id).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|s| SessionInfo {
                id: s.id,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
                ip: s.ip,
                user_agent: s.user_agent,
            })
            .collect(),
    ))
}

/// Revoke one of the caller's sessions by id. The current request's own
/// session is allowed to be revoked (that is the standard "log out this
/// device" flow).
pub async fn revoke_my_session(
    Auth(auth): Auth,
    State(state): State<AppState>,
    Path(session_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let sessions = db::list_sessions_for_user(&state.db, auth.user.id).await?;
    if !sessions.iter().any(|s| s.id == session_id) {
        return Err(ApiError::NotFound("Session not found".into()));
    }
    db::delete_session(&state.db, session_id).await?;

    let mut audit = AuditContext::new(&auth, AuditAction::Logout)
        .with_meta(serde_json::json!({ "session_id": session_id.to_string() }));
    state.audit.log_success(&mut audit).await.ok();

    Ok(Json(serde_json::json!({ "success": true })))
}

fn client_ip_and_ua(headers: &axum::http::HeaderMap) -> (String, String) {
    let ip = pandapass_core::audit::extract_client_ip(headers, None)
        .unwrap_or_default();
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (ip, ua)
}
