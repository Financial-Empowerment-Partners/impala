//! Browser cookie-session logic: token generation, cookie construction,
//! CSRF synchronizer-token checks, and TTL math.
//!
//! Pure logic lives here (unit-testable without Redis); the fail-closed Redis
//! IO lives in `redis_helpers.rs` per the repo convention. The session id is
//! never stored verbatim — Redis keys use `sha256(sid)` so a Redis dump never
//! yields usable cookies.

use axum::http::{HeaderMap, HeaderValue, Method};
use log::error;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::constants::{
    CSRF_HEADER_NAME, CSRF_TOKEN_BYTES, SESSION_ABSOLUTE_TTL_SECS, SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME_INSECURE, SESSION_IDLE_TTL_SECS, SESSION_ID_BYTES,
};
use crate::error::AppError;
use crate::redis_helpers::{self, SessionRecord};

/// Runtime cookie policy, threaded to handlers via `Extension<Arc<SessionConfig>>`.
///
/// `cookie_secure` defaults to true; the local plain-HTTP compose stack sets
/// `SESSION_COOKIE_SECURE=false`, which also drops the `__Host-` name prefix
/// (the prefix is only valid on `Secure` cookies).
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub cookie_secure: bool,
}

/// Generate `n_bytes` of CSPRNG entropy, hex-encoded. Uses aws-lc-rs — the
/// same CSPRNG already trusted for card-auth challenges.
pub fn generate_token(n_bytes: usize) -> Result<String, AppError> {
    let mut buf = vec![0u8; n_bytes];
    aws_lc_rs::rand::fill(&mut buf).map_err(|e| {
        error!("session: CSPRNG failure generating token: {e:?}");
        AppError::InternalError("Internal error".to_string())
    })?;
    Ok(hex::encode(buf))
}

/// Redis key component for a session id: hex(sha256(sid)).
pub fn hash_sid(sid: &str) -> String {
    hex::encode(Sha256::digest(sid.as_bytes()))
}

/// Cookie name under the given policy (`__Host-` requires `Secure`).
pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        SESSION_COOKIE_NAME
    } else {
        SESSION_COOKIE_NAME_INSECURE
    }
}

/// `Set-Cookie` value establishing the session cookie. Deliberately no
/// Max-Age/Expires: a browser-session cookie, with the real lifetime enforced
/// server-side (sliding idle TTL + absolute cap).
pub fn build_session_cookie(sid: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/",
        cookie_name(secure),
        sid
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// `Set-Cookie` value clearing the session cookie (logout).
pub fn build_clear_cookie(secure: bool) -> String {
    let mut cookie = format!(
        "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        cookie_name(secure)
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Extract the session id from a request's `Cookie` headers, if present.
pub fn extract_session_cookie(headers: &HeaderMap, secure: bool) -> Option<String> {
    let wanted = cookie_name(secure);
    for value in headers.get_all(axum::http::header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((name, val)) = pair.trim().split_once('=') {
                if name == wanted && !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Is this an HTTP method that mutates state (and therefore needs CSRF
/// protection on the cookie path)?
fn is_unsafe_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// CSRF synchronizer-token check for cookie-authenticated requests:
/// unsafe methods must carry `X-CSRF-Token` matching the session's stored
/// token (constant-time compare). Safe methods pass through.
pub fn check_csrf(method: &Method, headers: &HeaderMap, expected: &str) -> Result<(), AppError> {
    if !is_unsafe_method(method) {
        return Ok(());
    }
    let presented = headers
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    if presented.as_bytes().ct_eq(expected.as_bytes()).into() {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Has the session outlived its absolute cap?
pub fn record_expired(created_at: u64, now: u64) -> bool {
    now.saturating_sub(created_at) >= SESSION_ABSOLUTE_TTL_SECS as u64
}

/// Sliding TTL to apply on activity: the idle window, clamped so the key
/// can never outlive the absolute cap.
pub fn sliding_ttl(created_at: u64, now: u64) -> usize {
    let absolute_remaining =
        (created_at + SESSION_ABSOLUTE_TTL_SECS as u64).saturating_sub(now) as usize;
    SESSION_IDLE_TTL_SECS.min(absolute_remaining)
}

/// Create a server-side session for `account_id` and return the `Set-Cookie`
/// header value plus the CSRF token for the response body. Fail-closed: any
/// Redis or CSPRNG failure means no cookie is issued.
pub async fn establish_session(
    redis_pool: &deadpool_redis::Pool,
    account_id: &str,
    is_admin: bool,
    secure: bool,
) -> Result<(HeaderValue, String), AppError> {
    let sid = generate_token(SESSION_ID_BYTES)?;
    let csrf = generate_token(CSRF_TOKEN_BYTES)?;
    let now = chrono::Utc::now().timestamp() as u64;

    let record = SessionRecord {
        account_id: account_id.to_string(),
        csrf: csrf.clone(),
        created_at: now,
        is_admin,
    };

    redis_helpers::create_session(redis_pool, &hash_sid(&sid), &record, sliding_ttl(now, now))
        .await?;

    let cookie = HeaderValue::from_str(&build_session_cookie(&sid, secure)).map_err(|e| {
        error!("session: invalid cookie header value: {e}");
        AppError::InternalError("Internal error".to_string())
    })?;

    Ok((cookie, csrf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_hex_and_unique() {
        let a = generate_token(SESSION_ID_BYTES).unwrap();
        let b = generate_token(SESSION_ID_BYTES).unwrap();
        assert_eq!(a.len(), SESSION_ID_BYTES * 2);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_sid_is_deterministic_and_distinct() {
        assert_eq!(hash_sid("abc"), hash_sid("abc"));
        assert_ne!(hash_sid("abc"), hash_sid("abd"));
        assert_eq!(hash_sid("abc").len(), 64);
    }

    #[test]
    fn secure_cookie_uses_host_prefix_and_secure_flag() {
        let c = build_session_cookie("sid123", true);
        assert!(c.starts_with("__Host-impala_session=sid123;"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Path=/"));
        assert!(c.contains("Secure"));
        assert!(!c.contains("Max-Age"), "browser-session cookie");
    }

    #[test]
    fn insecure_cookie_drops_prefix_and_secure() {
        let c = build_session_cookie("sid123", false);
        assert!(c.starts_with("impala_session=sid123;"));
        assert!(!c.contains("__Host-"));
        assert!(!c.contains("Secure"));
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        let c = build_clear_cookie(true);
        assert!(c.contains("Max-Age=0"));
        assert!(c.starts_with("__Host-impala_session=;"));
    }

    #[test]
    fn extract_session_cookie_finds_the_right_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=1; impala_session=mysid; another=2"),
        );
        assert_eq!(
            extract_session_cookie(&headers, false).as_deref(),
            Some("mysid")
        );
        assert_eq!(extract_session_cookie(&headers, true), None);
    }

    #[test]
    fn csrf_exempts_safe_methods() {
        let headers = HeaderMap::new();
        assert!(check_csrf(&Method::GET, &headers, "tok").is_ok());
        assert!(check_csrf(&Method::HEAD, &headers, "tok").is_ok());
        assert!(check_csrf(&Method::OPTIONS, &headers, "tok").is_ok());
    }

    #[test]
    fn csrf_required_on_unsafe_methods() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            check_csrf(&Method::POST, &headers, "tok"),
            Err(AppError::Forbidden)
        ));
        headers.insert(CSRF_HEADER_NAME, HeaderValue::from_static("wrong"));
        assert!(matches!(
            check_csrf(&Method::PUT, &headers, "tok"),
            Err(AppError::Forbidden)
        ));
        headers.insert(CSRF_HEADER_NAME, HeaderValue::from_static("tok"));
        assert!(check_csrf(&Method::DELETE, &headers, "tok").is_ok());
    }

    #[test]
    fn record_expiry_boundaries() {
        let created = 1_000_000;
        let cap = SESSION_ABSOLUTE_TTL_SECS as u64;
        assert!(!record_expired(created, created));
        assert!(!record_expired(created, created + cap - 1));
        assert!(record_expired(created, created + cap));
    }

    #[test]
    fn sliding_ttl_clamps_to_absolute_remaining() {
        let created = 1_000_000;
        // Fresh session: full idle window.
        assert_eq!(sliding_ttl(created, created), SESSION_IDLE_TTL_SECS);
        // Near the absolute cap: only the remainder.
        let near_end = created + SESSION_ABSOLUTE_TTL_SECS as u64 - 60;
        assert_eq!(sliding_ttl(created, near_end), 60);
        // Past the cap: zero.
        let past = created + SESSION_ABSOLUTE_TTL_SECS as u64 + 1;
        assert_eq!(sliding_ttl(created, past), 0);
    }
}
