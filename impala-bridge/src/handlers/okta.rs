use axum::extract::Extension;
use axum::response::IntoResponse;
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    AUTH_PROVIDER_OKTA, LOCKOUT_THRESHOLD, MAX_EMAIL_LENGTH, RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{OktaConfigResponse, OktaTokenExchangeRequest, TokenResponse};
use crate::okta::{self, OktaProvider};
use crate::telemetry::{token_exchange_outcome, AppMetrics};

/// Normalize and validate an account id derived from a federated identity
/// (Okta/Google/GitHub claims). Shared across all token-exchange handlers.
pub(crate) fn normalize_federated_account_id(
    raw: &str,
    provider: &'static str,
) -> Result<String, AppError> {
    let account_id = raw.trim().to_lowercase();
    if account_id.is_empty() {
        warn!("{}: empty account_id derived from token", provider);
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.len() > MAX_EMAIL_LENGTH {
        warn!(
            "{}: account_id exceeds max length: {}",
            provider,
            account_id.len()
        );
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.chars().any(|c| c.is_control()) {
        warn!("{}: account_id contains control characters", provider);
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    Ok(account_id)
}

/// Auto-provision an account + auth record for a federated identity inside a
/// single transaction (the okta pattern, shared by Google/GitHub).
///
/// The auth record gets a random argon2 hash (federated users never log in
/// with a password) and `auth_provider = <provider>`. For a pre-existing
/// account this **flips** `auth_provider` away from `local`, which one-way
/// disables the legacy derived-password login path (see SECURITY.md).
pub(crate) async fn provision_federated_account(
    pool: &PgPool,
    account_id: &str,
    provider: &'static str,
) -> Result<(), AppError> {
    let placeholder_stellar_id = format!(
        "G{}",
        uuid::Uuid::new_v4()
            .to_string()
            .replace('-', "0")
            .chars()
            .take(55)
            .collect::<String>()
    );

    let mut tx = pool.begin().await.map_err(|e| {
        error!("{}: failed to begin transaction: {}", provider, e);
        AppError::InternalError("Database error".to_string())
    })?;

    sqlx::query(
        "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name)
         VALUES ($1, $2, $3, '')
         ON CONFLICT (payala_account_id) DO NOTHING",
    )
    .bind(&placeholder_stellar_id)
    .bind(account_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("{}: failed to upsert account: {}", provider, e);
        AppError::InternalError("Failed to provision account".to_string())
    })?;

    // Upsert into impala_auth with auth_provider = <provider>.
    // Use a random password hash since federated users don't use password login.
    let random_hash = crate::password::hash_password(uuid::Uuid::new_v4().to_string()).await?;

    sqlx::query(
        "INSERT INTO impala_auth (account_id, password_hash, auth_provider)
         VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE SET auth_provider = $3",
    )
    .bind(account_id)
    .bind(&random_hash)
    .bind(provider)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("{}: failed to upsert auth record: {}", provider, e);
        AppError::InternalError("Failed to provision authentication".to_string())
    })?;

    tx.commit().await.map_err(|e| {
        error!("{}: failed to commit transaction: {}", provider, e);
        AppError::InternalError("Database error".to_string())
    })?;

    Ok(())
}

/// `POST /auth/okta` — Exchange an Okta access token for local JWT tokens.
///
/// Validates the Okta token, auto-provisions the user if needed, and issues
/// a local refresh + temporal token pair — or, with `cookie_mode: true`, an
/// HttpOnly cookie session. Rate-limited per account.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an Extension
pub async fn okta_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(session_config): Extension<Arc<crate::session::SessionConfig>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    okta_provider: Option<Extension<Arc<OktaProvider>>>,
    Json(payload): Json<OktaTokenExchangeRequest>,
) -> Result<axum::response::Response, AppError> {
    let result = okta_token_exchange_inner(
        pool,
        jwt_keys,
        redis_pool,
        admin_ids,
        session_config,
        &metrics,
        okta_provider,
        payload,
    )
    .await;
    metrics.record_token_exchange("okta", token_exchange_outcome(&result));
    result
}

#[allow(clippy::too_many_arguments)] // mirrors the handler's extension list
async fn okta_token_exchange_inner(
    pool: PgPool,
    jwt_keys: Arc<crate::jwt::JwtKeys>,
    redis_pool: Arc<deadpool_redis::Pool>,
    admin_ids: Arc<std::collections::HashSet<String>>,
    session_config: Arc<crate::session::SessionConfig>,
    metrics: &AppMetrics,
    okta_provider: Option<Extension<Arc<OktaProvider>>>,
    payload: OktaTokenExchangeRequest,
) -> Result<axum::response::Response, AppError> {
    debug!("POST /auth/okta: token exchange request received");

    let provider = okta_provider
        .map(|Extension(p)| p)
        .ok_or_else(|| AppError::BadRequest("Okta authentication is not configured".to_string()))?;

    // Validate the Okta access token
    let claims = okta::validate_okta_token(&provider, &payload.okta_token).await?;

    // Determine account ID from claims (email > preferred_username > okta:{sub})
    let account_id = claims
        .email
        .clone()
        .or_else(|| claims.preferred_username.clone())
        .unwrap_or_else(|| format!("okta:{}", claims.sub));

    // Validate and normalize the account ID
    let account_id = normalize_federated_account_id(&account_id, "okta")?;

    info!("okta: token exchange for account_id={}", account_id);

    // Rate limiting and lockout checks
    crate::redis_helpers::check_lockout(&redis_pool, &account_id, LOCKOUT_THRESHOLD).await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "okta",
        &account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Auto-provision using a database transaction
    provision_federated_account(&pool, &account_id, AUTH_PROVIDER_OKTA).await?;

    let is_admin = admin_ids.contains(&account_id);

    // Server-side role for the token claims: the account's DB role with the
    // ADMIN_ACCOUNT_IDS allowlist overriding to admin
    // (provision_federated_account defaults new accounts to view-only).
    let role = crate::auth::issuance_role(&pool, &admin_ids, &account_id).await;

    // Browser clients opt into a cookie session instead of bearer tokens
    // (the impala-ui Okta flow sends cookie_mode: true).
    if payload.cookie_mode {
        let (cookie, csrf_token) = crate::session::establish_session(
            &redis_pool,
            &account_id,
            is_admin,
            session_config.cookie_secure,
        )
        .await?;
        metrics.sessions_created.add(1, &[]);
        info!(
            "okta: cookie session established for account_id={}",
            account_id
        );
        return Ok((
            axum::response::AppendHeaders([(axum::http::header::SET_COOKIE, cookie)]),
            Json(super::session::SessionResponse {
                success: true,
                message: "Okta authentication successful".to_string(),
                account_id,
                is_admin,
                csrf_token,
            }),
        )
            .into_response());
    }

    // Issue local JWT tokens (role derived from DB + allowlist at issuance)
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, &account_id, &role)?;

    info!("okta: tokens issued for account_id={}", account_id);

    Ok(Json(TokenResponse {
        success: true,
        message: "Okta authentication successful".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    })
    .into_response())
}

/// `GET /auth/okta/config` — Return Okta client configuration.
///
/// No auth required. Returns `{ enabled: false }` if Okta is not configured.
pub async fn okta_config(
    okta_provider: Option<Extension<Arc<OktaProvider>>>,
) -> Json<OktaConfigResponse> {
    match okta_provider {
        Some(Extension(provider)) => {
            debug!("GET /auth/okta/config: returning Okta configuration");
            Json(OktaConfigResponse {
                enabled: true,
                issuer: Some(provider.issuer_url.clone()),
                client_id: Some(provider.client_id.clone()),
                authorization_endpoint: Some(provider.discovery.authorization_endpoint.clone()),
                token_endpoint: Some(provider.discovery.token_endpoint.clone()),
                scopes: Some(provider.discovery.scopes_supported.clone()),
            })
        }
        None => {
            debug!("GET /auth/okta/config: Okta not configured");
            Json(OktaConfigResponse {
                enabled: false,
                issuer: None,
                client_id: None,
                authorization_endpoint: None,
                token_endpoint: None,
                scopes: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_and_lowercases() {
        assert_eq!(
            normalize_federated_account_id("  User@Example.COM ", "okta").unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(normalize_federated_account_id("   ", "okta").is_err());
    }

    #[test]
    fn normalize_rejects_overlong() {
        let long = "a".repeat(MAX_EMAIL_LENGTH + 1);
        assert!(normalize_federated_account_id(&long, "okta").is_err());
    }

    #[test]
    fn normalize_rejects_control_characters() {
        assert!(normalize_federated_account_id("user\n@example.com", "okta").is_err());
    }
}
