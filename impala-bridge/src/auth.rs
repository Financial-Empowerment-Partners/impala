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

/// A privileged capability — one slice of what used to be the monolithic
/// admin surface. The role → capability mapping lives in ONE place,
/// [`role_has_capability`], so the authorization matrix can be exhaustively
/// unit-tested and can never diverge between handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Mutate reserve & replenishment state: disburse, refund, write off,
    /// record ledger entries, edit policy. Money-moving.
    ManageReserve,
    /// Read reserve & replenishment state, including cross-account
    /// reserve-provider exchange orders (the disbursement work queues).
    ReadReserve,
    /// Mutate bridge credentials and custodial seeds. Spend authority itself.
    ManageKeys,
    /// Read the key inventory (fingerprints and metadata only — the handlers
    /// never return secret bytes).
    ReadKeys,
    /// Read the cross-account accounts list and account detail surfaces.
    ReadAccounts,
    /// Read transactions across accounts (listing and detail) — the auditor's
    /// reconciliation surface.
    ReadTransactions,
    /// Read the admin event feed and webhook registrations.
    ReadEvents,
}

impl Capability {
    /// Every capability. A new variant fails the exhaustive `match` in
    /// [`role_has_capability`] until it gets a row, and the matrix tests
    /// iterate this so they cannot silently go stale.
    #[allow(dead_code)] // consumed by the test-side matrix/invariant loops
    pub const ALL: [Capability; 7] = [
        Capability::ManageReserve,
        Capability::ReadReserve,
        Capability::ManageKeys,
        Capability::ReadKeys,
        Capability::ReadAccounts,
        Capability::ReadTransactions,
        Capability::ReadEvents,
    ];
}

/// THE authorization matrix. Fail-closed by construction: any role not
/// explicitly listed — unknown, empty, legacy — holds nothing.
///
/// admin holds every capability (the unchanged superset); treasurer,
/// key-custodian and auditor are lateral: none includes another's surface.
/// key-custodian carries ReadAccounts because seed provisioning is keyed by
/// account id, so the custodian must be able to resolve the account they are
/// provisioning.
pub fn role_has_capability(role: &str, cap: Capability) -> bool {
    use crate::constants::{ROLE_AUDITOR, ROLE_KEY_CUSTODIAN, ROLE_TREASURER};
    match cap {
        Capability::ManageReserve => matches!(role, ROLE_ADMIN | ROLE_TREASURER),
        Capability::ReadReserve => matches!(role, ROLE_ADMIN | ROLE_TREASURER | ROLE_AUDITOR),
        Capability::ManageKeys => matches!(role, ROLE_ADMIN | ROLE_KEY_CUSTODIAN),
        Capability::ReadKeys => matches!(role, ROLE_ADMIN | ROLE_KEY_CUSTODIAN | ROLE_AUDITOR),
        Capability::ReadAccounts => {
            matches!(role, ROLE_ADMIN | ROLE_AUDITOR | ROLE_KEY_CUSTODIAN)
        }
        Capability::ReadTransactions => matches!(role, ROLE_ADMIN | ROLE_AUDITOR),
        Capability::ReadEvents => matches!(role, ROLE_ADMIN | ROLE_AUDITOR),
    }
}

/// The capability check as a Result, for handlers and the extractor.
pub fn authorize_capability(role: &str, cap: Capability) -> Result<(), AppError> {
    if role_has_capability(role, cap) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Marker-type contract for [`Privileged`]: each zero-sized marker names the
/// capability its extractor requires.
pub trait RequiredCapability: Send + Sync + 'static {
    const CAPABILITY: Capability;
}

/// Marker types, one per capability.
pub struct ManageReserve;
pub struct ReadReserve;
pub struct ManageKeys;
pub struct ReadKeys;
pub struct ReadAccounts;
pub struct ReadEvents;

impl RequiredCapability for ManageReserve {
    const CAPABILITY: Capability = Capability::ManageReserve;
}
impl RequiredCapability for ReadReserve {
    const CAPABILITY: Capability = Capability::ReadReserve;
}
impl RequiredCapability for ManageKeys {
    const CAPABILITY: Capability = Capability::ManageKeys;
}
impl RequiredCapability for ReadKeys {
    const CAPABILITY: Capability = Capability::ReadKeys;
}
impl RequiredCapability for ReadAccounts {
    const CAPABILITY: Capability = Capability::ReadAccounts;
}
impl RequiredCapability for ReadEvents {
    const CAPABILITY: Capability = Capability::ReadEvents;
}

/// An authenticated user holding a specific capability — the granular
/// successor to [`AdminUser`], gated at the type level the same way: a route
/// taking `Privileged<ManageReserve>` cannot be reached without that
/// capability. Runs the full [`validate_request_auth`] pipeline (bearer or
/// session), then [`authorize_capability`]; rejection is the same Forbidden
/// the AdminUser extractor produces, so clients cannot distinguish the two
/// gates. Session-cookie users carry admin or view-only only (granular roles
/// ride the bearer path), which composes correctly here: a session admin
/// passes every capability, everyone else on the session path fails closed.
pub struct Privileged<C: RequiredCapability> {
    pub account_id: String,
    /// The concrete role that satisfied the capability — for handlers that
    /// log or branch on it; most only need the account id.
    #[allow(dead_code)]
    pub role: String,
    _marker: std::marker::PhantomData<fn() -> C>,
}

impl<S, C> FromRequestParts<S> for Privileged<C>
where
    S: Send + Sync,
    C: RequiredCapability,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let context = validate_request_auth(parts, state).await?;
        authorize_capability(&context.role, C::CAPABILITY)?;
        Ok(Privileged {
            account_id: context.account_id,
            role: context.role,
            _marker: std::marker::PhantomData,
        })
    }
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

    // ── Capability matrix ──────────────────────────────────────────────

    /// The exact matrix, spelled out. Kept as data so the loop below cannot
    /// miss a row the author forgot: every (role, capability) pair is checked
    /// in both directions.
    fn expected_capability_roles(cap: Capability) -> &'static [&'static str] {
        use crate::constants::*;
        match cap {
            Capability::ManageReserve => &[ROLE_ADMIN, ROLE_TREASURER],
            Capability::ReadReserve => &[ROLE_ADMIN, ROLE_TREASURER, ROLE_AUDITOR],
            Capability::ManageKeys => &[ROLE_ADMIN, ROLE_KEY_CUSTODIAN],
            Capability::ReadKeys => &[ROLE_ADMIN, ROLE_KEY_CUSTODIAN, ROLE_AUDITOR],
            Capability::ReadAccounts => &[ROLE_ADMIN, ROLE_AUDITOR, ROLE_KEY_CUSTODIAN],
            Capability::ReadTransactions => &[ROLE_ADMIN, ROLE_AUDITOR],
            Capability::ReadEvents => &[ROLE_ADMIN, ROLE_AUDITOR],
        }
    }

    #[test]
    fn capability_matrix_is_exactly_as_specified() {
        for cap in Capability::ALL {
            let expected = expected_capability_roles(cap);
            for role in crate::constants::ALL_ROLES {
                assert_eq!(
                    role_has_capability(role, cap),
                    expected.contains(role),
                    "role {:?} capability {:?}",
                    role,
                    cap
                );
            }
        }
    }

    #[test]
    fn admin_holds_every_capability() {
        // Forgetting admin in a new capability row would brick the admin
        // console for that surface — a lockout, not a hardening.
        for cap in Capability::ALL {
            assert!(
                role_has_capability(crate::constants::ROLE_ADMIN, cap),
                "admin must hold {:?}",
                cap
            );
        }
    }

    #[test]
    fn unknown_roles_hold_nothing() {
        for role in [
            "",
            "bogus",
            "Admin",
            "ADMIN",
            "treasurer ",
            "root",
            "superuser",
        ] {
            for cap in Capability::ALL {
                assert!(
                    !role_has_capability(role, cap),
                    "unknown role {:?} must fail closed for {:?}",
                    role,
                    cap
                );
            }
        }
    }

    #[test]
    fn auditor_holds_no_mutation_capability() {
        // The auditor is the read-only oversight role; a Manage* grant to it
        // is a security incident, not a tweak.
        for cap in [Capability::ManageReserve, Capability::ManageKeys] {
            assert!(
                !role_has_capability(crate::constants::ROLE_AUDITOR, cap),
                "auditor must not hold {:?}",
                cap
            );
        }
    }

    #[test]
    fn lateral_roles_do_not_cross_surfaces() {
        use crate::constants::{ROLE_KEY_CUSTODIAN, ROLE_TREASURER};
        assert!(!role_has_capability(ROLE_TREASURER, Capability::ManageKeys));
        assert!(!role_has_capability(ROLE_TREASURER, Capability::ReadKeys));
        assert!(!role_has_capability(
            ROLE_KEY_CUSTODIAN,
            Capability::ManageReserve
        ));
        assert!(!role_has_capability(
            ROLE_KEY_CUSTODIAN,
            Capability::ReadReserve
        ));
    }

    #[test]
    fn original_ladder_roles_hold_no_privileged_capability() {
        use crate::constants::{ROLE_DEVICE, ROLE_TOKEN, ROLE_VIEW_ONLY};
        for role in [ROLE_VIEW_ONLY, ROLE_DEVICE, ROLE_TOKEN] {
            for cap in Capability::ALL {
                assert!(
                    !role_has_capability(role, cap),
                    "ladder role {:?} must not hold {:?}",
                    role,
                    cap
                );
            }
        }
    }

    #[test]
    fn authorize_capability_matches_the_predicate() {
        assert!(authorize_capability(crate::constants::ROLE_ADMIN, Capability::ManageKeys).is_ok());
        assert!(matches!(
            authorize_capability(crate::constants::ROLE_AUDITOR, Capability::ManageKeys),
            Err(AppError::Forbidden)
        ));
    }

    // ── Cross-stack contract fixture ───────────────────────────────────

    /// The role→capability matrix is mirrored by the UI's permission table
    /// (impala-ui/html/js/roles.js). Both stacks assert against the same
    /// checked-in fixture so they cannot drift apart silently — the bug class
    /// this prevents already shipped once (the token role's review
    /// permission).
    #[test]
    fn capability_matrix_matches_shared_fixture() {
        let raw = include_str!("../../impala-ui/tests/fixtures/role-capabilities.json");
        let fixture: serde_json::Value = serde_json::from_str(raw).expect("fixture parses");
        let caps = fixture["capabilities"]
            .as_object()
            .expect("capabilities object");
        assert_eq!(
            caps.len(),
            Capability::ALL.len(),
            "fixture capability count must match Capability::ALL"
        );
        for cap in Capability::ALL {
            let name = format!("{:?}", cap);
            let allowed: Vec<&str> = caps[&name]
                .as_array()
                .unwrap_or_else(|| panic!("fixture missing capability {}", name))
                .iter()
                .map(|v| v.as_str().expect("role string"))
                .collect();
            for role in crate::constants::ALL_ROLES {
                assert_eq!(
                    role_has_capability(role, cap),
                    allowed.contains(role),
                    "fixture drift: role {:?} capability {}",
                    role,
                    name
                );
            }
        }
        let roles: Vec<&str> = fixture["roles"]
            .as_array()
            .expect("roles array")
            .iter()
            .map(|v| v.as_str().expect("role string"))
            .collect();
        assert_eq!(
            roles,
            crate::constants::ALL_ROLES,
            "fixture role list drift"
        );
    }

    // ── Tripwires ──────────────────────────────────────────────────────

    /// Migration 035 must carry every role in ALL_ROLES, quoted, in the same
    /// CHECK constraint name migration 023 created. A drifted literal (e.g.
    /// key_custodian for key-custodian) would make validate_role accept a
    /// grant the DB then rejects with a bare 500 — a runtime governance-path
    /// failure the compiler cannot see.
    #[test]
    fn migration_035_matches_all_roles() {
        let sql = include_str!("../migrations/035_add_privileged_roles.sql");
        assert!(
            sql.contains("DROP CONSTRAINT chk_impala_account_role"),
            "must drop the 023 constraint by its exact name"
        );
        assert!(
            sql.contains("ADD CONSTRAINT chk_impala_account_role"),
            "must re-add under the same name"
        );
        for role in crate::constants::ALL_ROLES {
            assert!(
                sql.contains(&format!("'{}'", role)),
                "migration CHECK missing role literal '{}'",
                role
            );
        }
        // Count quoted literals on the SQL lines only (comment prose carries
        // apostrophes): the CHECK must name exactly the ALL_ROLES set.
        let quoted: usize = sql
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .map(|l| l.matches('\'').count())
            .sum();
        assert_eq!(
            quoted,
            crate::constants::ALL_ROLES.len() * 2,
            "migration must quote exactly the ALL_ROLES set"
        );
    }

    /// The extractor swap must be all-or-nothing per module: a handler
    /// accidentally left on AdminUser is a treasurer/custodian lockout, one
    /// accidentally converted to the wrong capability is an escalation. The
    /// fully-converted modules must not mention AdminUser at all; the files
    /// allowed to keep it are pinned here so a future /admin route makes a
    /// conscious choice.
    #[test]
    fn extractor_swap_is_complete_per_module() {
        for (name, src) in [
            (
                "admin_reserve.rs",
                include_str!("handlers/admin_reserve.rs"),
            ),
            (
                "admin_replenish.rs",
                include_str!("handlers/admin_replenish.rs"),
            ),
            ("admin_keys.rs", include_str!("handlers/admin_keys.rs")),
        ] {
            assert!(
                !src.contains("AdminUser"),
                "{} still references AdminUser — the capability swap is incomplete",
                name
            );
        }
        // admin_webhook keeps AdminUser for its three mutating handlers
        // (register/delete/test) and Privileged<ReadEvents> for the reads.
        let webhook = include_str!("handlers/admin_webhook.rs");
        assert_eq!(
            webhook.matches(": AdminUser").count(),
            3,
            "admin_webhook.rs must have exactly its three mutating handlers on AdminUser"
        );
        assert_eq!(
            webhook.matches(": Privileged<ReadEvents>").count(),
            2,
            "admin_webhook.rs must have exactly its two read handlers on ReadEvents"
        );
    }

    /// The extractor slice of a handler's signature: from `pub async fn name(`
    /// to the return arrow. Panics if the handler is missing — a renamed
    /// handler must update this test consciously.
    fn signature_of<'a>(src: &'a str, name: &str) -> &'a str {
        let needle = format!("pub async fn {}(", name);
        let start = src
            .find(&needle)
            .unwrap_or_else(|| panic!("handler {} not found", name));
        let rest = &src[start..];
        let end = rest
            .find("->")
            .unwrap_or_else(|| panic!("{}: no return arrow", name));
        &rest[..end]
    }

    /// Per-handler capability pinning. The module-level absence check above
    /// proves nothing about WHICH marker each handler took: a mutating
    /// handler accidentally on a Read capability compiles, passes every other
    /// test, and hands the read-only auditor a money mutation (verified by
    /// mutation before this test existed). Every privileged handler's
    /// extractor is therefore pinned by name.
    #[test]
    fn every_privileged_handler_takes_its_exact_capability() {
        let reserve = include_str!("handlers/admin_reserve.rs");
        let replenish = include_str!("handlers/admin_replenish.rs");
        let keys = include_str!("handlers/admin_keys.rs");
        let webhook = include_str!("handlers/admin_webhook.rs");
        let admin = include_str!("handlers/admin.rs");

        let table: &[(&str, &str, &str)] = &[
            // admin_reserve.rs — reads
            (reserve, "get_status", "Privileged<ReadReserve>"),
            (reserve, "list_entries", "Privileged<ReadReserve>"),
            (reserve, "list_unmatched", "Privileged<ReadReserve>"),
            (reserve, "list_refunds", "Privileged<ReadReserve>"),
            (reserve, "get_forecast", "Privileged<ReadReserve>"),
            // admin_reserve.rs — money mutations
            (reserve, "update_policy", "Privileged<ManageReserve>"),
            (reserve, "update_bucket", "Privileged<ManageReserve>"),
            (reserve, "create_entry", "Privileged<ManageReserve>"),
            (reserve, "update_settings", "Privileged<ManageReserve>"),
            (reserve, "create_refund", "Privileged<ManageReserve>"),
            (reserve, "resolve_refund", "Privileged<ManageReserve>"),
            (reserve, "disburse_order", "Privileged<ManageReserve>"),
            (reserve, "resolve_order", "Privileged<ManageReserve>"),
            // admin_replenish.rs
            (replenish, "get_status", "Privileged<ReadReserve>"),
            (replenish, "update_policy", "Privileged<ManageReserve>"),
            (replenish, "run_now", "Privileged<ManageReserve>"),
            (replenish, "confirm_fiat", "Privileged<ManageReserve>"),
            (replenish, "write_off", "Privileged<ManageReserve>"),
            // admin_keys.rs
            (keys, "list_keys", "Privileged<ReadKeys>"),
            (keys, "import_key", "Privileged<ManageKeys>"),
            (keys, "merge_key", "Privileged<ManageKeys>"),
            (keys, "revoke_key", "Privileged<ManageKeys>"),
            (keys, "generate_seed", "Privileged<ManageKeys>"),
            (keys, "import_seed", "Privileged<ManageKeys>"),
            // admin_webhook.rs — mutations stay admin, reads are auditable
            (webhook, "register_webhook", "AdminUser"),
            (webhook, "delete_webhook", "AdminUser"),
            (webhook, "test_webhook", "AdminUser"),
            (webhook, "list_webhooks", "Privileged<ReadEvents>"),
            (webhook, "list_events", "Privileged<ReadEvents>"),
            // admin.rs
            (admin, "list_accounts", "Privileged<ReadAccounts>"),
        ];

        for (src, name, expected) in table {
            let sig = signature_of(src, name);
            assert!(
                sig.contains(&format!(": {}", expected)),
                "handler {} must take {} — its signature is:\n{}",
                name,
                expected,
                sig
            );
        }
        // Both files sharing handler names must have exactly the handlers the
        // table expects — a count guard so a NEW privileged handler cannot
        // ship ungated without touching this test.
        assert_eq!(reserve.matches("pub async fn ").count(), 13);
        assert_eq!(replenish.matches("pub async fn ").count(), 5);
        assert_eq!(keys.matches("pub async fn ").count(), 6);
        assert_eq!(webhook.matches("pub async fn ").count(), 5);
    }
}
