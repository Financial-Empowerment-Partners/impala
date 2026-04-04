use axum::extract::Extension;
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

/// `POST /auth/okta` — Exchange an Okta access token for local JWT tokens.
///
/// Validates the Okta token, auto-provisions the user if needed, and issues
/// a local refresh + temporal token pair. Rate-limited per account.
pub async fn okta_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_secret): Extension<Arc<String>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    okta_provider: Option<Extension<Arc<OktaProvider>>>,
    Json(payload): Json<OktaTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
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
    let account_id = account_id.trim().to_lowercase();
    if account_id.is_empty() {
        warn!("okta: empty account_id derived from token");
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.len() > MAX_EMAIL_LENGTH {
        warn!("okta: account_id exceeds max length: {}", account_id.len());
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.chars().any(|c| c.is_control()) {
        warn!("okta: account_id contains control characters");
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }

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
        error!("okta: failed to begin transaction: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    sqlx::query(
        "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name)
         VALUES ($1, $2, $3, '')
         ON CONFLICT (payala_account_id) DO NOTHING",
    )
    .bind(&placeholder_stellar_id)
    .bind(&account_id)
    .bind(&account_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("okta: failed to upsert account: {}", e);
        AppError::InternalError("Failed to provision account".to_string())
    })?;

    // Upsert into impala_auth with auth_provider = 'okta'
    // Use a random password hash since Okta users don't use password login
    let random_hash = password_auth::generate_hash(uuid::Uuid::new_v4().to_string());

    sqlx::query(
        "INSERT INTO impala_auth (account_id, password_hash, auth_provider)
         VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE SET auth_provider = $3",
    )
    .bind(&account_id)
    .bind(&random_hash)
    .bind(AUTH_PROVIDER_OKTA)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("okta: failed to upsert auth record: {}", e);
        AppError::InternalError("Failed to provision authentication".to_string())
    })?;

    tx.commit().await.map_err(|e| {
        error!("okta: failed to commit transaction: {}", e);
        AppError::InternalError("Database error".to_string())
    })?;

    // Issue local JWT tokens
    let key = jwt_secret.as_bytes();
    let (refresh_token, temporal_token) = crate::jwt::encode_token_pair(key, &account_id)?;

    info!("okta: tokens issued for account_id={}", account_id);

    Ok(Json(TokenResponse {
        success: true,
        message: "Okta authentication successful".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
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
