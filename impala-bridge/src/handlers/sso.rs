use axum::extract::{Extension, Path};
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::TokenKind;
use crate::constants::{
    LOCKOUT_THRESHOLD, MAX_EMAIL_LENGTH, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{SsoConfigResponse, SsoTokenExchangeRequest, TokenResponse};
use crate::oidc::{self, ProviderRegistry};

/// `POST /auth/sso/:provider` — Exchange an OIDC token for local JWT tokens.
///
/// Looks the provider up in the registry, validates the token it expects
/// (access token, or id token for `token_kind = id`), auto-provisions the user
/// if needed, and issues a local refresh + temporal token pair. Rate-limited
/// per account and scoped by provider name.
pub async fn sso_token_exchange(
    Path(provider_name): Path<String>,
    Extension(pool): Extension<PgPool>,
    Extension(jwt_secret): Extension<Arc<String>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(registry): Extension<Arc<ProviderRegistry>>,
    Json(payload): Json<SsoTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let provider_name = provider_name.to_lowercase();
    debug!("POST /auth/sso/{}: token exchange request received", provider_name);

    let provider = registry.get(&provider_name).ok_or_else(|| {
        AppError::BadRequest(format!("SSO provider '{}' is not configured", provider_name))
    })?;

    // Select the token to validate based on what this provider issues.
    let token = match provider.token_kind {
        TokenKind::Access => payload.token.as_deref(),
        // id-token providers (e.g. Duo SSO); tolerate the access-token field too.
        TokenKind::Id => payload.id_token.as_deref().or(payload.token.as_deref()),
    }
    .map(str::trim)
    .filter(|t| !t.is_empty())
    .ok_or_else(|| AppError::BadRequest("Missing OIDC token".to_string()))?;

    // Validate the OIDC token against the provider's JWKS (RS256, iss, aud).
    let claims = oidc::validate_token(&provider, token).await?;

    // Derive the account id. Only unify on email when the IdP has not marked it
    // unverified — otherwise a user at one IdP could take over an account keyed
    // by the same email at another. When email is absent or explicitly
    // unverified, fall back to a provider-namespaced subject. (Configured IdPs
    // are treated as one trust domain; to harden, require `email_verified ==
    // Some(true)` here.)
    let account_id = match claims.email.as_deref() {
        Some(email) if !email.trim().is_empty() && claims.email_verified != Some(false) => {
            email.trim().to_lowercase()
        }
        _ => format!("{}:{}", provider.name, claims.sub).to_lowercase(),
    };

    if account_id.is_empty() {
        warn!("sso[{}]: empty account_id derived from token", provider.name);
        return Err(AppError::BadRequest("Invalid account identifier".to_string()));
    }
    if account_id.len() > MAX_EMAIL_LENGTH {
        warn!("sso[{}]: account_id exceeds max length: {}", provider.name, account_id.len());
        return Err(AppError::BadRequest("Invalid account identifier".to_string()));
    }
    if account_id.chars().any(|c| c.is_control()) {
        warn!("sso[{}]: account_id contains control characters", provider.name);
        return Err(AppError::BadRequest("Invalid account identifier".to_string()));
    }

    info!("sso[{}]: token exchange for account_id={}", provider.name, account_id);

    // Rate limiting and lockout checks. Rate limit is scoped per provider;
    // lockout is per account across all providers/local (locking the human).
    crate::redis_helpers::check_lockout(&redis_pool, &account_id, LOCKOUT_THRESHOLD).await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        &provider.name,
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
        error!("sso[{}]: failed to begin transaction: {}", provider.name, e);
        AppError::InternalError("Database error".to_string())
    })?;

    sqlx::query(
        "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name, profile_source)
         VALUES ($1, $2, $3, '', $4)
         ON CONFLICT (payala_account_id) DO NOTHING",
    )
    .bind(&placeholder_stellar_id)
    .bind(&account_id)
    .bind(&account_id)
    .bind(&provider.name)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("sso[{}]: failed to upsert account: {}", provider.name, e);
        AppError::InternalError("Failed to provision account".to_string())
    })?;

    // Upsert into impala_auth with auth_provider = the provider name.
    // Use a random password hash since SSO users don't use password login.
    let random_hash = password_auth::generate_hash(uuid::Uuid::new_v4().to_string());

    sqlx::query(
        "INSERT INTO impala_auth (account_id, password_hash, auth_provider)
         VALUES ($1, $2, $3)
         ON CONFLICT (account_id) DO UPDATE SET auth_provider = $3",
    )
    .bind(&account_id)
    .bind(&random_hash)
    .bind(&provider.name)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("sso[{}]: failed to upsert auth record: {}", provider.name, e);
        AppError::InternalError("Failed to provision authentication".to_string())
    })?;

    tx.commit().await.map_err(|e| {
        error!("sso[{}]: failed to commit transaction: {}", provider.name, e);
        AppError::InternalError("Database error".to_string())
    })?;

    // Issue local JWT tokens, embedding the account's server-side role.
    let key = jwt_secret.as_bytes();
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM impala_account WHERE payala_account_id = $1",
    )
    .bind(&account_id)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(crate::models::default_role);
    let (refresh_token, temporal_token) = crate::jwt::encode_token_pair(key, &account_id, &role)?;

    info!("sso[{}]: tokens issued for account_id={}", provider.name, account_id);

    Ok(Json(TokenResponse {
        success: true,
        message: "SSO authentication successful".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
}

/// `GET /auth/sso/:provider/config` — Return an SSO provider's client config.
///
/// No auth required. Returns `{ enabled: false }` if the named provider is not
/// configured, so the dashboard can hide the button.
pub async fn sso_config(
    Path(provider_name): Path<String>,
    Extension(registry): Extension<Arc<ProviderRegistry>>,
) -> Json<SsoConfigResponse> {
    let provider_name = provider_name.to_lowercase();
    match registry.get(&provider_name) {
        Some(provider) => {
            debug!("GET /auth/sso/{}/config: returning configuration", provider_name);
            Json(SsoConfigResponse {
                enabled: true,
                provider: Some(provider.name.clone()),
                issuer: Some(provider.issuer_url.clone()),
                client_id: Some(provider.client_id.clone()),
                audience: Some(provider.audience.clone()),
                authorization_endpoint: Some(provider.discovery.authorization_endpoint.clone()),
                token_endpoint: Some(provider.discovery.token_endpoint.clone()),
                scopes: Some(provider.discovery.scopes_supported.clone()),
            })
        }
        None => {
            debug!("GET /auth/sso/{}/config: provider not configured", provider_name);
            Json(SsoConfigResponse {
                enabled: false,
                provider: None,
                issuer: None,
                client_id: None,
                audience: None,
                authorization_endpoint: None,
                token_endpoint: None,
                scopes: None,
            })
        }
    }
}

/// `GET /auth/providers` — List the names of all configured SSO providers,
/// so the dashboard can render one button per provider without hardcoding.
pub async fn sso_providers(Extension(registry): Extension<Arc<ProviderRegistry>>) -> Json<Vec<String>> {
    Json(registry.names())
}
