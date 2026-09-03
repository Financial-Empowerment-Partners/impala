use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::client_source::ClientSource;
use crate::constants::{
    LOCKOUT_DURATION_SECS, LOCKOUT_THRESHOLD, PREAUTH_SOURCE_MAX_REQUESTS,
    PREAUTH_SOURCE_WINDOW_SECS, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
    REFRESH_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH,
};
use crate::error::AppError;
use crate::jwt::JwtKeys;
use crate::models::{TokenRequest, TokenResponse};
use crate::telemetry::AppMetrics;

/// Why a local credential check was refused.
///
/// Internal only: every variant produces the **same** wire response and the
/// same argon2 cost, so nothing here is observable to a caller. The
/// distinction exists for exactly one decision — whether the attempt counts
/// toward the `(identity, source)` lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialFailure {
    /// No local password exists for this username: the account is unknown or
    /// belongs to a federated provider. Nothing was guessed against, so this
    /// must not count — counting it let anyone pre-lock an identity that had
    /// not been provisioned yet (a not-yet-created SSO operator), or lock a
    /// federated account's SSO path with passwords it does not have.
    NoLocalCredential,
    /// A stored local password was checked and did not match: a real guess.
    WrongPassword,
}

impl CredentialFailure {
    /// Only a real guess against a stored password spends the lockout budget.
    pub(crate) fn counts_toward_lockout(self) -> bool {
        matches!(self, CredentialFailure::WrongPassword)
    }
}

/// Verify a local username/password credential pair against `impala_auth`.
///
/// Shared by `POST /token` (flow 2) and `POST /session/login` so the two
/// login paths cannot diverge. Outcomes:
/// - `Ok(Ok(()))` — credentials valid for a `local`-provider account
/// - `Ok(Err(CredentialFailure))` — refused; the reason is for the caller's
///   lockout accounting only and must never change the response
/// - `Err(InternalError | Retryable)` — infrastructure failure / load shed
///
/// A federated account is refused like an unknown one (the legacy
/// derived-password path is one-way disabled, see SECURITY.md), at the same
/// argon2 cost, so neither existence nor provider is observable.
pub(crate) async fn verify_local_credentials(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Result<Result<(), CredentialFailure>, AppError> {
    let stored = sqlx::query_as::<_, (String, String)>(
        "SELECT password_hash, auth_provider FROM impala_auth WHERE account_id = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("verify_local_credentials: database error: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    let (stored_hash, auth_provider) = match stored {
        Some((hash, provider)) => (hash, provider),
        None => {
            // Equalize timing with the verification path below so a missing
            // account is indistinguishable from a wrong password.
            crate::password::dummy_verify().await?;
            warn!(
                "verify_local_credentials: no credentials found for username={}",
                username
            );
            return Ok(Err(CredentialFailure::NoLocalCredential));
        }
    };

    if auth_provider != crate::constants::AUTH_PROVIDER_LOCAL {
        // Same cost and same generic outcome as a wrong password: a distinct
        // (and cheaper) reply here told a caller which usernames are
        // federated accounts.
        crate::password::dummy_verify().await?;
        warn!(
            "verify_local_credentials: external auth user {} attempted password login",
            username
        );
        return Ok(Err(CredentialFailure::NoLocalCredential));
    }

    if !crate::password::verify_password_async(password.to_string(), stored_hash).await? {
        warn!(
            "verify_local_credentials: invalid password for username={}",
            username
        );
        return Ok(Err(CredentialFailure::WrongPassword));
    }

    Ok(Ok(()))
}

/// Issue JWT tokens (`POST /token`).
///
/// Two flows:
/// - Refresh token -> rotated refresh + temporal pair (strict single-use
///   rotation with family-revocation reuse detection)
/// - Username + password -> fresh refresh + temporal pair
pub async fn token(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /token: request received");

    // Flow 1: refresh_token provided -> rotated refresh + temporal pair
    if let Some(ref refresh_token) = payload.refresh_token {
        // 1. Signature/issuer/audience/expiry/type validation.
        let claims = crate::jwt::decode_claims(&jwt_keys, refresh_token, TOKEN_TYPE_REFRESH)
            .inspect_err(|_| {
                warn!("token: invalid refresh token presented");
            })?;

        // 2. Revoked JTI / revoked family / logout-everywhere epoch.
        crate::redis_helpers::check_bearer_token_validity(
            &redis_pool,
            &claims.jti,
            &claims.fid,
            &claims.sub,
            claims.iat,
        )
        .await?;

        // 3. Strict rotation + reuse detection, as ONE atomic claim: burn the
        // presented token before minting, and let the outcome of that burn be
        // the reuse signal. Splitting this into a read followed by a write let
        // concurrent presentations of the same token all observe "not yet
        // rotated" and each mint a live pair, forking a stolen token into
        // several lineages without ever tripping the alarm.
        //
        // If the claim fails outright we mint nothing (two live refresh tokens
        // must never coexist); if minting fails after a won claim, the user
        // re-logs in — the safe failure direction.
        let now = chrono::Utc::now().timestamp() as usize;
        let remaining = claims.exp.saturating_sub(now).max(1);
        let won_claim =
            crate::redis_helpers::claim_refresh_rotation(&redis_pool, &claims.jti, remaining)
                .await?;
        if !won_claim {
            // Someone already burned this jti — either a genuine replay or the
            // loser of a race against the legitimate holder. Both are treated
            // as theft: revoke the entire family and reject.
            crate::redis_helpers::revoke_token_family(
                &redis_pool,
                &claims.fid,
                REFRESH_TOKEN_TTL_SECS,
            )
            .await?;
            metrics.token_reuse_detected.add(1, &[]);
            warn!(
                "token: REUSE of rotated refresh token detected for sub={} — family revoked",
                claims.sub
            );
            return Err(AppError::Unauthorized);
        }

        // 4. Mint the replacement pair inside the same token family.
        // The role is re-derived at every rotation (never trusted from the
        // presented token) via the shared issuance path: current DB role,
        // ADMIN_ACCOUNT_IDS overriding to admin — so grants/revocations take
        // effect within one temporal-token lifetime regardless of
        // refresh-token age. Fail-closed like every issuance: a missing row
        // or a DB error mints least privilege, never the presented token's
        // role — a deleted treasurer must not keep re-minting treasury power
        // off a 14-day refresh family.
        let role = crate::auth::issuance_role(&pool, &admin_ids, &claims.sub).await;
        let (new_refresh_token, temporal_token) =
            crate::jwt::encode_token_pair_with_family(&jwt_keys, &claims.sub, &role, &claims.fid)?;

        info!(
            "token: tokens issued (with refresh rotation) for sub={}",
            claims.sub
        );
        return Ok(Json(TokenResponse {
            success: true,
            message: "Tokens issued".to_string(),
            refresh_token: Some(new_refresh_token),
            temporal_token: Some(temporal_token),
        }));
    }

    // Flow 2: username + password -> fresh refresh + temporal pair
    let username = payload.username.as_deref().unwrap_or("");
    let password = payload.password.as_deref().unwrap_or("");

    if username.is_empty() || password.is_empty() {
        warn!("token: missing username or password");
        return Ok(Json(TokenResponse {
            success: false,
            message: "Either username/password or refresh_token must be provided".to_string(),
            refresh_token: None,
            temporal_token: None,
        }));
    }

    // Per-source budget first (password flow only — refresh rotation above
    // is bounded by the token it presents): bounds how many usernames one
    // source can touch, before that source spends any per-identity budget.
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "preauth_src",
        &source,
        PREAUTH_SOURCE_MAX_REQUESTS,
        PREAUTH_SOURCE_WINDOW_SECS,
    )
    .await?;

    // Rate limiting check
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "token",
        username,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Account lockout — the SAME gate `POST /authenticate` and
    // `POST /session/login` enforce. Without it this password flow was an
    // unthrottled password-guessing oracle against the identical credential
    // store (the per-minute rate limit alone allows sustained guessing).
    // Keyed on (username, source): a guesser locks the name only for itself.
    crate::redis_helpers::check_lockout(&redis_pool, username, &source, LOCKOUT_THRESHOLD).await?;

    match verify_local_credentials(&pool, username, password).await? {
        Ok(()) => {
            crate::redis_helpers::clear_lockout(&redis_pool, username, &source).await;
        }
        // Preserve the wire contract: invalid credentials are a 200 with
        // success=false (matching the historical behavior of this endpoint).
        // A federated or unknown account gets the byte-identical reply — it
        // used to be a 400, an enumeration oracle for SSO-provisioned
        // usernames — but only a wrong password against a stored one counts
        // toward lockout.
        Err(failure) => {
            if failure.counts_toward_lockout() {
                crate::redis_helpers::increment_lockout(
                    &redis_pool,
                    username,
                    &source,
                    LOCKOUT_DURATION_SECS,
                )
                .await;
            }
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }
    }

    // Embed the account's server-side role in the token (defaults to
    // view-only), with the ADMIN_ACCOUNT_IDS allowlist overriding to admin.
    let role = crate::auth::issuance_role(&pool, &admin_ids, username).await;

    // Mint a fresh family; also return a temporal token (additive — saves
    // well-behaved clients an immediate refresh round trip).
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, username, &role)?;

    info!("token: refresh token issued for username={}", username);
    Ok(Json(TokenResponse {
        success: true,
        message: "Refresh token issued".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one decision the failure reason exists for: only a real guess
    /// against a stored password spends the lockout budget. An unknown or
    /// federated username must never count, or anyone can pre-lock an
    /// identity that has not been provisioned yet.
    #[test]
    fn only_a_wrong_password_counts_toward_lockout() {
        assert!(CredentialFailure::WrongPassword.counts_toward_lockout());
        assert!(!CredentialFailure::NoLocalCredential.counts_toward_lockout());
    }

    /// Both login paths must keep reacting to the shared verifier's outcome
    /// the same way; pin the source so a future edit that counts
    /// `NoLocalCredential` (or stops gating on the reason) is caught.
    #[test]
    fn login_paths_gate_lockout_on_the_failure_reason() {
        // Assembled at runtime so this test's own text does not match itself.
        let bare_unauthorized_arm = ["Err(AppError::", "Unauthorized) =>"].concat();
        for (name, src) in [
            ("token.rs", include_str!("token.rs")),
            ("session.rs", include_str!("session.rs")),
        ] {
            assert!(
                src.contains("failure.counts_toward_lockout()"),
                "{name} must increment the lockout only for a counted failure"
            );
            assert!(
                !src.contains(&bare_unauthorized_arm),
                "{name} must match the verifier's CredentialFailure, not a bare Unauthorized"
            );
        }
    }
}
