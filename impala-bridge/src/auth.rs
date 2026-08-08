use crate::constants::{
    API_RATE_LIMIT_MAX_REQUESTS, API_RATE_LIMIT_WINDOW_SECS, ROLE_ADMIN, ROLE_VIEW_ONLY,
    TOKEN_TYPE_TEMPORAL,
};
use crate::error::AppError;
use crate::jwt::JwtKeys;
use crate::session::{self, SessionConfig};
use crate::telemetry::AppMetrics;
use axum::extract::{Extension, FromRequestParts};
use axum::http::request::Parts;
use std::sync::Arc;

/// How a request authenticated.
#[derive(Debug, Clone)]
#[allow(dead_code)] // bearer metadata (jti/fid/exp) carried for future revocation hooks
pub enum AuthSource {
    /// Bearer temporal JWT (mobile/SDK/API clients).
    Bearer {
        jti: String,
        fid: String,
        exp: usize,
    },
    /// HttpOnly session cookie (browser clients). `sid_hash` is the Redis key
    /// component — the raw sid never leaves the request.
    Session { sid_hash: String },
}

/// Validated request identity, shared by every auth extractor so the bearer
/// and session paths cannot diverge in their security checks.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub account_id: String,
    /// Server-side role. Bearer path: the JWT `role` claim (stamped at
    /// issuance). Session path: admin when the account is on the live
    /// ADMIN_ACCOUNT_IDS allowlist, otherwise least privilege.
    pub role: String,
    pub source: AuthSource,
}

impl AuthContext {
    fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }
}

/// Narrow authentication policy carried as shared state.
///
/// Deliberately a small struct rather than the whole `Config` (same reasoning
/// as `SessionConfig` and `LdapConfig`): handlers get the one flag they need
/// and no credentials ride along into a broadly-shared extension.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    /// Whether `POST /authenticate` may set a password on an existing account
    /// that has no credentials yet. Off by default — turning it on makes any
    /// credential-less account claimable by whoever knows its id.
    pub allow_open_registration: bool,
}

/// Represents an authenticated user (bearer JWT or cookie session).
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub account_id: String,
    pub role: String,
}

impl AuthenticatedUser {
    /// True if the user holds the server-side admin role.
    pub fn is_admin(&self) -> bool {
        self.role == ROLE_ADMIN
    }
}

/// Represents an authenticated **admin** user. Extraction additionally
/// requires admin privilege — the `role` claim on the bearer path (stamped at
/// issuance from the DB role and the ADMIN_ACCOUNT_IDS allowlist), live
/// allowlist membership on the session path — so admin-only routes that take
/// this extractor are gated at the type level.
#[derive(Debug, Clone)]
pub struct AdminUser {
    pub account_id: String,
}

/// A user authenticated specifically via a cookie session (`/session/*`
/// endpoints that operate on the session itself).
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub account_id: String,
    pub is_admin: bool,
    pub sid_hash: String,
    pub csrf: String,
}

/// Verify that the authenticated user owns the specified account.
/// Returns `Err(AppError::Forbidden)` if `user.account_id` does not match.
pub fn require_owner(user: &AuthenticatedUser, account_id: &str) -> Result<(), AppError> {
    if user.account_id != account_id {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Verify that the authenticated user holds the admin role.
/// Returns `Err(AppError::Forbidden)` otherwise. Tokens minted before role
/// support lack the claim and default to `view-only`, so they fail closed here.
pub fn require_admin(user: &AuthenticatedUser) -> Result<(), AppError> {
    if user.role != ROLE_ADMIN {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

/// Resolve the role to stamp into freshly-minted tokens: the account's DB
/// role (defaulting to least privilege when the row or column read fails),
/// with the ADMIN_ACCOUNT_IDS allowlist overriding to admin. Shared by every
/// token-issuance path so the role semantics cannot diverge.
pub async fn issuance_role(
    pool: &sqlx::PgPool,
    admin_ids: &std::collections::HashSet<String>,
    account_id: &str,
) -> String {
    if admin_ids.contains(account_id) {
        return ROLE_ADMIN.to_string();
    }
    sqlx::query_scalar::<_, String>("SELECT role FROM impala_account WHERE payala_account_id = $1")
        .bind(account_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(crate::models::default_role)
}

/// Validate a request's authentication and return its [`AuthContext`].
///
/// Precedence is strict: when an `Authorization` header is present it MUST
/// validate as a temporal bearer JWT — there is no fallback to the cookie
/// path on a bad bearer (that would let an attacker downgrade a targeted
/// bearer check into a cookie check). Only header-less requests take the
/// session-cookie path.
///
/// Both paths are fail-closed on Redis (revocation/epoch/session lookups) and
/// finish with the per-account API rate limit, so only fully-validated
/// requests consume quota.
async fn validate_request_auth<S>(parts: &mut Parts, state: &S) -> Result<AuthContext, AppError>
where
    S: Send + Sync,
{
    let Extension(redis_pool) =
        Extension::<Arc<deadpool_redis::Pool>>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized)?;

    let auth_header = parts
        .headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let context = if let Some(auth_header) = auth_header {
        // ── Bearer path ────────────────────────────────────────────────
        let Extension(jwt_keys) = Extension::<Arc<JwtKeys>>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::InternalError("JWT keys not configured".to_string()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        // HS256 + issuer + audience + key selection + temporal type.
        let claims = crate::jwt::decode_claims(&jwt_keys, token, TOKEN_TYPE_TEMPORAL)?;

        // Revoked JTI (logout), revoked family (refresh reuse), and
        // logout-everywhere epoch — one pipelined round trip, fail-closed.
        crate::redis_helpers::check_bearer_token_validity(
            &redis_pool,
            &claims.jti,
            &claims.fid,
            &claims.sub,
            claims.iat,
        )
        .await?;

        AuthContext {
            account_id: claims.sub,
            role: claims.role,
            source: AuthSource::Bearer {
                jti: claims.jti,
                fid: claims.fid,
                exp: claims.exp,
            },
        }
    } else {
        // ── Session-cookie path ────────────────────────────────────────
        let Extension(session_config) =
            Extension::<Arc<SessionConfig>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized)?;
        let Extension(admin_ids) =
            Extension::<Arc<std::collections::HashSet<String>>>::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized)?;

        let sid = session::extract_session_cookie(&parts.headers, session_config.cookie_secure)
            .ok_or(AppError::Unauthorized)?;
        let sid_hash = session::hash_sid(&sid);

        let record = crate::redis_helpers::get_session(&redis_pool, &sid_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let now = chrono::Utc::now().timestamp() as u64;
        if session::record_expired(record.created_at, now) {
            return Err(AppError::Unauthorized);
        }

        // Logout-everywhere kills sessions too: a session created at or
        // before the epoch bump is dead. Fail-closed read.
        let epoch = crate::redis_helpers::get_auth_epoch(&redis_pool, &record.account_id).await?;
        if crate::redis_helpers::is_iat_revoked(record.created_at as usize, epoch) {
            return Err(AppError::Unauthorized);
        }

        // CSRF binds to the cookie path only: bearer requests carry no
        // ambient credential, so the header requirement applies exactly to
        // requests a cross-site attacker could ride.
        if let Err(e) = session::check_csrf(&parts.method, &parts.headers, &record.csrf) {
            if let Ok(Extension(metrics)) =
                Extension::<Arc<AppMetrics>>::from_request_parts(parts, state).await
            {
                metrics.csrf_rejections.add(1, &[]);
            }
            return Err(e);
        }

        // Slide the idle window (fire-and-forget — failure only shortens).
        crate::redis_helpers::touch_session(
            &redis_pool,
            &sid_hash,
            session::sliding_ttl(record.created_at, now),
        )
        .await;

        // Admin is re-derived from the live allowlist on every session
        // request: removal takes effect immediately (vs ≤1h on the JWT path).
        // Cookie sessions don't carry a JWT role claim, so non-allowlisted
        // session users act at least privilege; granular DB roles ride the
        // bearer path.
        let role = if admin_ids.contains(&record.account_id) {
            ROLE_ADMIN.to_string()
        } else {
            ROLE_VIEW_ONLY.to_string()
        };

        AuthContext {
            account_id: record.account_id,
            role,
            source: AuthSource::Session { sid_hash },
        }
    };

    // Light per-account rate limit across all authenticated endpoints.
    // Placed after full validation so only valid credentials consume quota.
    // Fail-closed like every Redis-backed check.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "api",
        &context.account_id,
        API_RATE_LIMIT_MAX_REQUESTS,
        API_RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    Ok(context)
}

impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        validate_request_auth(parts, state).await
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = validate_request_auth(parts, state).await?;
        Ok(AuthenticatedUser {
            account_id: context.account_id,
            role: context.role,
        })
    }
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = validate_request_auth(parts, state).await?;
        if !context.is_admin() {
            return Err(AppError::Forbidden);
        }
        Ok(AdminUser {
            account_id: context.account_id,
        })
    }
}

impl<S> FromRequestParts<S> for SessionUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = validate_request_auth(parts, state).await?;
        let is_admin = context.is_admin();
        match context.source {
            AuthSource::Session { sid_hash } => {
                // The CSRF token is needed by /session/me; re-read is avoided
                // by fetching it from the record during validation — but the
                // context deliberately doesn't carry secrets, so look it up.
                let Extension(redis_pool) =
                    Extension::<Arc<deadpool_redis::Pool>>::from_request_parts(parts, state)
                        .await
                        .map_err(|_| AppError::Unauthorized)?;
                let record = crate::redis_helpers::get_session(&redis_pool, &sid_hash)
                    .await?
                    .ok_or(AppError::Unauthorized)?;
                Ok(SessionUser {
                    account_id: context.account_id,
                    is_admin,
                    sid_hash,
                    csrf: record.csrf,
                })
            }
            AuthSource::Bearer { .. } => Err(AppError::Unauthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::JWT_ISSUER;
    use crate::jwt::{encode_token_pair, JwtKeys};
    use crate::models::Claims;
    use axum::http::Request;

    const TEST_SECRET: &str = "test-secret-key-for-unit-tests-32ch";

    fn parts_with_extensions(builder: axum::http::request::Builder) -> Parts {
        let (mut parts, ()) = builder.body(()).unwrap().into_parts();
        // A lazily-created pool pointing nowhere: connection acquisition fails,
        // which must be treated as fail-closed by every auth path.
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:1/")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy pool creation");
        parts.extensions.insert(Arc::new(pool));
        parts.extensions.insert(Arc::new(
            JwtKeys::new(TEST_SECRET.to_string(), None).unwrap(),
        ));
        parts.extensions.insert(Arc::new(SessionConfig {
            cookie_secure: false,
        }));
        parts
            .extensions
            .insert(Arc::new(std::collections::HashSet::<String>::new()));
        parts
    }

    #[tokio::test]
    async fn no_credentials_is_unauthorized() {
        let mut parts = parts_with_extensions(Request::builder().uri("/account"));
        let result = AuthenticatedUser::from_request_parts(&mut parts, &()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn malformed_bearer_rejected_without_cookie_fallback() {
        // Even with a session cookie present, a bad Authorization header must
        // fail the request outright (no downgrade to the cookie path).
        let mut parts = parts_with_extensions(
            Request::builder()
                .uri("/account")
                .header("Authorization", "Bearer not-a-jwt")
                .header("Cookie", "impala_session=somesid"),
        );
        let result = AuthenticatedUser::from_request_parts(&mut parts, &()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn valid_bearer_fails_closed_when_redis_unreachable() {
        // The JWT itself is valid, but the revocation check cannot run — the
        // request must be rejected, never silently allowed.
        //
        // It must ALSO not be rejected as 401: clients treat 401 as "this
        // credential is dead" and discard it, so answering a Redis outage that
        // way makes them throw away tokens that are still valid once Redis
        // recovers (impalactl deletes its stored refresh token on 401).
        let keys = JwtKeys::new(TEST_SECRET.to_string(), None).unwrap();
        let (_refresh, temporal) = encode_token_pair(&keys, "alice", ROLE_VIEW_ONLY).unwrap();
        let mut parts = parts_with_extensions(
            Request::builder()
                .uri("/account")
                .header("Authorization", format!("Bearer {temporal}")),
        );
        let result = AuthenticatedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err(), "must fail closed");
        assert!(
            matches!(result, Err(AppError::InternalError(_))),
            "an infrastructure outage must not be reported as an auth failure"
        );
    }

    #[tokio::test]
    async fn refresh_token_rejected_on_protected_route() {
        let keys = JwtKeys::new(TEST_SECRET.to_string(), None).unwrap();
        let (refresh, _temporal) = encode_token_pair(&keys, "alice", ROLE_VIEW_ONLY).unwrap();
        let mut parts = parts_with_extensions(
            Request::builder()
                .uri("/account")
                .header("Authorization", format!("Bearer {refresh}")),
        );
        let result = AuthenticatedUser::from_request_parts(&mut parts, &()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn session_cookie_fails_closed_when_redis_unreachable() {
        let mut parts = parts_with_extensions(
            Request::builder()
                .uri("/account")
                .header("Cookie", "impala_session=somesid"),
        );
        let result = AuthenticatedUser::from_request_parts(&mut parts, &()).await;
        assert!(result.is_err(), "must fail closed");
        assert!(
            matches!(result, Err(AppError::InternalError(_))),
            "an infrastructure outage must not be reported as an auth failure"
        );
    }

    #[test]
    fn test_require_admin_allows_admin() {
        let user = super::AuthenticatedUser {
            account_id: "alice".to_string(),
            role: crate::constants::ROLE_ADMIN.to_string(),
        };
        assert!(super::require_admin(&user).is_ok());
        assert!(user.is_admin());
    }

    #[test]
    fn test_require_admin_denies_non_admin() {
        for role in [
            crate::constants::ROLE_VIEW_ONLY,
            crate::constants::ROLE_DEVICE,
            crate::constants::ROLE_TOKEN,
        ] {
            let user = super::AuthenticatedUser {
                account_id: "bob".to_string(),
                role: role.to_string(),
            };
            assert!(super::require_admin(&user).is_err());
            assert!(!user.is_admin());
        }
    }

    #[test]
    fn test_old_token_without_role_defaults_view_only() {
        // A token JSON minted before role support (but after the aud/fid
        // rollout — anything older fails decoding outright) omits `role`;
        // serde default must yield least privilege.
        let json = serde_json::json!({
            "sub": "legacy",
            "token_type": "temporal",
            "iat": 1000usize,
            "exp": 9999999999usize,
            "jti": "abc",
            "iss": JWT_ISSUER,
            "aud": crate::constants::JWT_AUDIENCE,
            "fid": "legacy-fid"
        });
        let claims: Claims = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(claims.role, crate::constants::ROLE_VIEW_ONLY);
    }
}
