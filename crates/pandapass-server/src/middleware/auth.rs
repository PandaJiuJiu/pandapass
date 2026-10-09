use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::IntoResponse;
use pandapass_core::models::*;
use pandapass_db as db;
use pandapass_core::crypto::{generate_token, hash_token};
use pandapass_core::CoreError;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use crate::state::AppState;

pub const SESSION_COOKIE: &str = "pandapass_session";
pub const CSRF_COOKIE: &str = "pandapass_csrf";

/// Request extension key for client IP
#[derive(Clone)]
pub struct ClientIp(pub IpAddr);

/// Parse a comma-separated list of CIDR ranges. Anything that does not parse
/// is logged and skipped — a typo in the trusted-proxy list should not crash
/// the server on startup.
pub fn parse_trusted_cidrs(raw: &[String]) -> Vec<(IpAddr, u8)> {
    raw.iter()
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            match s.parse::<ipnet::IpNet>() {
                Ok(n) => Some((n.network(), n.prefix_len())),
                Err(e) => {
                    tracing::warn!("PANDAPASS_TRUSTED_PROXY_CIDRS: ignoring bad entry {:?}: {}", s, e);
                    None
                }
            }
        })
        .collect()
}

/// Test whether `ip` is inside any of the trusted CIDR blocks.
fn ip_in_trusted(ip: IpAddr, trusted: &[(IpAddr, u8)]) -> bool {
    for (net, prefix) in trusted {
        let mask = match prefix {
            0 => return true, // /0 covers the whole address space
            n if *n <= 32 => {
                if ip.is_ipv4() && net.is_ipv4() {
                    let ip_v = u32::from(ip.to_string().parse::<std::net::Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));
                    let net_v = u32::from(net.to_string().parse::<std::net::Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED));
                    let mask_v = if *prefix == 0 { 0u32 } else { !0u32 << (32 - *prefix) };
                    (ip_v & mask_v) == (net_v & mask_v)
                } else if ip.is_ipv6() && net.is_ipv6() {
                    let ip_v = u128::from_str(&ip.to_string()).unwrap_or(0);
                    let net_v = u128::from_str(&net.to_string()).unwrap_or(0);
                    let mask_v = if *prefix == 0 { 0u128 } else { !0u128 << (128 - *prefix) };
                    (ip_v & mask_v) == (net_v & mask_v)
                } else {
                    false
                }
            }
            _ => false,
        };
        if mask {
            return true;
        }
    }
    false
}

/// Extract client IP from headers, but **only** trust X-Forwarded-For /
/// X-Real-IP when the immediate peer (the connection's source IP, if
/// available) is in `trusted_cidrs`. Without a trusted proxy in front,
/// the headers are attacker-controlled and the function falls back to a
/// best-effort of the leftmost header value (still logged but not
/// authoritative for rate-limit / audit decisions — handlers that care
/// must call this with the real peer IP).
pub fn extract_client_ip_from_headers(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    extract_client_ip(headers, None, &[])
}

/// Strict variant used by the live router: takes a `ConnectInfo<SocketAddr>`
/// peer and a list of trusted CIDRs. XFF is honoured only when the peer
/// matches.
pub fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trusted_cidrs: &[(IpAddr, u8)],
) -> Option<IpAddr> {
    // Decide if we trust the proxy chain.
    let trust_xff = match peer {
        Some(addr) => ip_in_trusted(addr.ip(), trusted_cidrs),
        None => false, // no peer = no way to know the proxy is trusted
    };

    if trust_xff {
        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                if let Some(first) = s.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
        if let Some(real_ip) = headers.get("x-real-ip") {
            if let Ok(s) = real_ip.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    peer.map(|a| a.ip())
}

/// Extract client IP from request parts (handles X-Forwarded-For for proxied setups)
pub fn extract_client_ip_from_parts(parts: &Parts) -> Option<IpAddr> {
    extract_client_ip_from_headers(&parts.headers)
}

/// Extracted auth context from a request
#[derive(Clone, Debug)]
pub struct Auth(pub AuthContext);

impl Auth {
    /// Resolve the caller from request headers.
    ///
    /// A `Bearer` credential is tried first as a service token, then as a
    /// session token — the CLI sends its session token as Bearer, so a failed
    /// service-token lookup must fall through rather than reject. Cookies are
    /// the fallback for the web UI.
    ///
    /// The resulting context carries no project scope; handlers that need one
    /// resolve it from the URL path.
    pub async fn from_headers(
        headers: &axum::http::HeaderMap,
        state: &AppState,
    ) -> Result<AuthContext, ApiError> {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.trim().to_string());

        if let Some(token) = bearer.as_deref() {
            if let Some(ctx) = Self::from_service_token(token, state).await? {
                return Ok(ctx);
            }
            if let Some(ctx) = Self::from_session_token(token, state).await? {
                return Ok(ctx);
            }
            return Err(ApiError::Unauthorized("Invalid token".into()));
        }

        let cookies = axum_extra::extract::cookie::CookieJar::from_headers(headers);
        let cookie_token = cookies.get(SESSION_COOKIE).map(|c| c.value().to_string());
        let header_token = headers
            .get("x-pandapass-session")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        match cookie_token.or(header_token) {
            Some(token) => Self::from_session_token(&token, state)
                .await?
                .ok_or_else(|| ApiError::Unauthorized("Invalid or expired session".into())),
            None => Err(ApiError::Unauthorized("Not authenticated".into())),
        }
    }

    /// Resolve a service token. `Ok(None)` means "no such token", not an error,
    /// so the caller can fall through to trying it as a session token.
    async fn from_service_token(
        token: &str,
        state: &AppState,
    ) -> Result<Option<AuthContext>, ApiError> {
        let hash = hash_token(token).map_err(ApiError::from)?;
        let Some(svc) = db::get_token_by_hash(&state.db, &hash).await.map_err(ApiError::from)? else {
            return Ok(None);
        };

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

        Ok(Some(AuthContext {
            user: user.into(),
            session: None,
            service_token: Some(svc),
            project_role: role,
            project_id: None,
            env_id: None,
            client_ip: None,
            user_agent: None,
        }))
    }

    /// Resolve a session token. `Ok(None)` means "no such session".
    async fn from_session_token(
        token: &str,
        state: &AppState,
    ) -> Result<Option<AuthContext>, ApiError> {
        let hash = hash_token(token).map_err(ApiError::from)?;
        let Some(session) = db::get_session_by_hash(&state.db, &hash).await.map_err(ApiError::from)? else {
            return Ok(None);
        };

        // Idle timeout: a session that has been unused for longer than the
        // configured window is expired. We do not delete it here — the
        // periodic cleanup does that — but we refuse to authenticate with it.
        if let Some(idle_secs) = state.config.session_idle_timeout_secs {
            let idle = chrono::Utc::now() - session.last_seen_at;
            if idle.num_seconds() > idle_secs {
                return Err(ApiError::Unauthorized(
                    "Session expired due to inactivity. Please log in again.".into(),
                ));
            }
        }

        // Bump last_seen_at so a long-lived session does not go stale while
        // the user is actively working.
        let _ = db::touch_session(&state.db, session.id).await;

        let user = db::get_user_by_id(&state.db, session.user_id)
            .await
            .map_err(ApiError::from)?;
        if user.disabled_at.is_some() {
            return Err(ApiError::Unauthorized("User disabled".into()));
        }

        Ok(Some(AuthContext {
            user: user.into(),
            session: Some(session),
            service_token: None,
            project_role: None,
            project_id: None,
            env_id: None,
            client_ip: None,
            user_agent: None,
        }))
    }
}

impl<S> FromRequestParts<S> for Auth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Resolve the auth from the request headers, then populate the
        // client_ip and user_agent fields so every AuditContext built
        // from this Auth carries them. The ClientIp extension was
        // inserted earlier by the outer client_ip_middleware.
        let app_state = AppState::from_ref(state);
        let mut ctx = Auth::from_headers(&parts.headers, &app_state).await?;
        ctx.client_ip = parts
            .extensions
            .get::<ClientIp>()
            .map(|c| c.0.to_string());
        ctx.user_agent = parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
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
    /// A route that exists but has no implementation yet. Distinct from
    /// `Internal`: the request was well-formed, the feature just isn't built.
    #[error("{0}")]
    NotImplemented(String),
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

impl From<pandapass_core::policy::PolicyError> for ApiError {
    fn from(e: pandapass_core::policy::PolicyError) -> Self {
        match e {
            pandapass_core::policy::PolicyError::Compile(m) => ApiError::Internal(format!("Policy compile error: {}", m)),
            pandapass_core::policy::PolicyError::Engine(m) => ApiError::Internal(format!("Policy engine error: {}", m)),
            pandapass_core::policy::PolicyError::NotInitialized => ApiError::Internal("Policy engine not initialized".into()),
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
            ApiError::NotImplemented(_) => (http::StatusCode::NOT_IMPLEMENTED, "not_implemented"),
            ApiError::Internal(_) => (http::StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = serde_json::json!({
            "error": { "code": code, "message": self.to_string() }
        });
        (status, axum::Json(body)).into_response()
    }
}
