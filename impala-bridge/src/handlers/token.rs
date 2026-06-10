use axum::extract::Extension;
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS, REFRESH_TOKEN_TTL_SECS, TOKEN_TYPE_REFRESH,
};
use crate::error::AppError;
use crate::jwt::JwtKeys;
use crate::models::{TokenRequest, TokenResponse};
use crate::telemetry::AppMetrics;

/// Verify a local username/password credential pair against `impala_auth`.
///
/// Shared by `POST /token` (flow 2) and `POST /session/login` so the two
/// login paths cannot diverge. Outcomes:
/// - `Ok(())` — credentials valid for a `local`-provider account
/// - `Err(Unauthorized)` — unknown account or wrong password
/// - `Err(BadRequest)` — account exists but belongs to a federated provider
///   (the legacy derived-password path is one-way disabled, see SECURITY.md)
/// - `Err(InternalError)` — infrastructure failure
pub(crate) async fn verify_local_credentials(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> Result<(), AppError> {
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
            crate::password::dummy_verify().await;
            warn!(
                "verify_local_credentials: no credentials found for username={}",
                username
            );
            return Err(AppError::Unauthorized);
        }
    };

    if auth_provider != crate::constants::AUTH_PROVIDER_LOCAL {
        warn!(
            "verify_local_credentials: external auth user {} attempted password login",
            username
        );
        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }

    if !crate::password::verify_password_async(password.to_string(), stored_hash).await? {
        warn!(
            "verify_local_credentials: invalid password for username={}",
            username
        );
        return Err(AppError::Unauthorized);
    }

    Ok(())
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

        // 3. Reuse detection: a rotated-out refresh token presented again is
        // the theft signal — revoke the entire family and reject.
        if crate::redis_helpers::is_refresh_rotated(&redis_pool, &claims.jti).await? {
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

        // 4. Strict rotation: burn the presented token BEFORE minting. If the
        // marker write fails we mint nothing (two live refresh tokens must
        // never coexist); if minting fails after the burn, the user re-logs
        // in — the safe failure direction.
        let now = chrono::Utc::now().timestamp() as usize;
        let remaining = claims.exp.saturating_sub(now).max(1);
        crate::redis_helpers::mark_refresh_rotated(&redis_pool, &claims.jti, remaining).await?;

        // 5. Mint the replacement pair inside the same token family.
        // Admin is re-derived from the allowlist (never trusted from the
        // presented token) so grants/revocations take effect within one
        // temporal-token lifetime regardless of refresh-token age.
        let is_admin = admin_ids.contains(&claims.sub);
        let (new_refresh_token, temporal_token) = crate::jwt::encode_token_pair_with_family(
            &jwt_keys,
            &claims.sub,
            is_admin,
            &claims.fid,
        )?;

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

    // Rate limiting check
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "token",
        username,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    match verify_local_credentials(&pool, username, password).await {
        Ok(()) => {}
        // Preserve the wire contract: invalid credentials are a 200 with
        // success=false (matching the historical behavior of this endpoint),
        // while the federated-account rejection stays a 400.
        Err(AppError::Unauthorized) => {
            return Ok(Json(TokenResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                refresh_token: None,
                temporal_token: None,
            }));
        }
        Err(e) => return Err(e),
    }

    let is_admin = admin_ids.contains(username);
    // Mint a fresh family; also return a temporal token (additive — saves
    // well-behaved clients an immediate refresh round trip).
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, username, is_admin)?;

    info!("token: refresh token issued for username={}", username);
    Ok(Json(TokenResponse {
        success: true,
        message: "Refresh token issued".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
}
