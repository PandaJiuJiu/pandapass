use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use pandapass_core::models::*;
use pandapass_db as db;
use pandapass_core::crypto::{generate_token, hash_token};
use pandapass_core::CoreError;

use crate::state::AppState;

pub const SESSION_COOKIE: &str = "pandapass_session";
pub const CSRF_COOKIE: &str = "pandapass_csrf";

/// Extracted auth context from a request
#[derive(Clone, Debug)]
pub struct Auth(pub AuthContext);

impl Auth {
    /// Resolve the caller from request headers.
    ///
    /// Accepts a service token via `Authorization: Bearer`, or a session cookie.
    /// The resulting context carries no project scope — handlers that need one
    /// resolve it from the URL path.
    pub async fn from_headers(
        headers: &axum::http::HeaderMap,
        state: &AppState,
    ) -> Result<AuthContext, ApiError> {
        // 1. Try service token (Authorization: Bearer <token>)
        if let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = authz.strip_prefix("Bearer ") {
                let token = token.trim();
                let hash = hash_token(token).map_err(ApiError::from)?;
                let svc = db::get_token_by_hash(&state.db, &hash)
                    .await
                    .map_err(ApiError::from)?
                    .ok_or_else(|| ApiError::Unauthorized("Invalid token".into()))?;

                if let Some(exp) = svc.expires_at {
                    if exp < chrono::Utc::now() {
                        return Err(ApiError::Unauthorized("Token expired".into()));
                    }
                }

                let user = db::get_user_by_id(&state.db, svc.created_by)
                    .await
                    .map_err(ApiError::from)?;
                if user.disabled_at.is_some() {
                    return Err(ApiError::Unauthorized("User disabled".into()));
                }
                let _ = db::touch_token(&state.db, svc.id).await;

                let role = match (svc.project_id, svc.env_id) {
                    (Some(pid), _) => db::get_member_role(&state.db, pid, user.id)
                        .await
                        .unwrap_or(None),
                    _ => None,
                };

                return Ok(AuthContext {
                    user: user.into(),
                    session: None,
                    service_token: Some(svc),
                    project_role: role,
                    project_id: None,
                    env_id: None,
                });
            }
        }

        // 2. Try session cookie
        let cookies = axum_extra::extract::cookie::CookieJar::from_headers(headers);
        let session_token = cookies
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .or_else(|| {
                headers
                    .get("x-pandapass-session")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .ok_or_else(|| ApiError::Unauthorized("Not authenticated".into()))?;

        let hash = hash_token(&session_token).map_err(ApiError::from)?;
        let session = db::get_session_by_hash(&state.db, &hash)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::Unauthorized("Invalid or expired session".into()))?;

        let user = db::get_user_by_id(&state.db, session.user_id)
            .await
            .map_err(ApiError::from)?;
        if user.disabled_at.is_some() {
            return Err(ApiError::Unauthorized("User disabled".into()));
        }

        Ok(AuthContext {
            user: user.into(),
            session: Some(session),
            service_token: None,
            project_role: None,
            project_id: None,
            env_id: None,
        })
    }
}

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let ctx = Auth::from_headers(&parts.headers, &app_state).await?;
        Ok(Auth(ctx))
    }
}

/// Helper trait to pull AppState out of router state
pub trait FromRef<S> {
    fn from_ref(state: &S) -> Self;
}

impl FromRef<AppState> for AppState {
    fn from_ref(state: &AppState) -> Self {
        state.clone()
    }
}

/// CSRF validation for cookie-authenticated mutating requests
pub async fn require_csrf(
    headers: &axum::http::HeaderMap,
    method: &http::Method,
) -> Result<(), ApiError> {
    if method == http::Method::GET || method == http::Method::HEAD || method == http::Method::OPTIONS {
        return Ok(());
    }

    // Bearer-token requests are immune to CSRF
    if headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.starts_with("Bearer "))
        .unwrap_or(false)
    {
        return Ok(());
    }

    let cookies = axum_extra::extract::cookie::CookieJar::from_headers(headers);
    let cookie_token = cookies.get(CSRF_COOKIE).map(|c| c.value().to_string());
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match (cookie_token, header_token) {
        (Some(a), Some(b)) if a == b && !a.is_empty() => Ok(()),
        _ => Err(ApiError::Forbidden("CSRF token missing or mismatched".into())),
    }
}

/// Generate a new session and set cookies
pub async fn issue_session(
    state: &AppState,
    user_id: uuid::Uuid,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<(String, String), ApiError> {
    let plain = generate_token(32);
    let hash = hash_token(&plain).map_err(ApiError::from)?;
    db::create_session(
        &state.db,
        user_id,
        &hash,
        ip.as_deref(),
        user_agent.as_deref(),
        state.config.session_ttl_days,
    )
    .await
    .map_err(ApiError::from)?;
    let csrf = generate_token(24);
    Ok((plain, csrf))
}

// ─────────────────────────── API error ───────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    TooManyRequests(String),
    #[error("{0}")]
    Internal(String),
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::InvalidInput(m) => ApiError::BadRequest(m),
            CoreError::NotFound(m) => ApiError::NotFound(m),
            CoreError::PermissionDenied(m) => ApiError::Forbidden(m),
            CoreError::Conflict(m) => ApiError::Conflict(m),
            CoreError::RateLimited => ApiError::TooManyRequests("Rate limited".into()),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<pandapass_core::rbac::RbacError> for ApiError {
    fn from(e: pandapass_core::rbac::RbacError) -> Self {
        match e {
            pandapass_core::rbac::RbacError::NotMember | pandapass_core::rbac::RbacError::InsufficientRole => {
                ApiError::Forbidden(e.to_string())
            }
            pandapass_core::rbac::RbacError::ProjectNotFound | pandapass_core::rbac::RbacError::EnvironmentNotFound => {
                ApiError::NotFound(e.to_string())
            }
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => ApiError::NotFound("Resource not found".into()),
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                ApiError::Conflict("Resource already exists".into())
            }
            _ => ApiError::Internal(format!("Database error: {}", e)),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            ApiError::BadRequest(_) => (http::StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized(_) => (http::StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (http::StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound(_) => (http::StatusCode::NOT_FOUND, "not_found"),
            ApiError::Conflict(_) => (http::StatusCode::CONFLICT, "conflict"),
            ApiError::TooManyRequests(_) => (http::StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Internal(_) => (http::StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = serde_json::json!({
            "error": { "code": code, "message": self.to_string() }
        });
        (status, axum::Json(body)).into_response()
    }
}
