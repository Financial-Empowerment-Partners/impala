use axum::extract::Extension;
use axum::Json;
use log::{debug, info};
use sqlx::PgPool;
use std::sync::Arc;

use crate::constants::{
    AUTH_PROVIDER_GOOGLE, LOCKOUT_THRESHOLD, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::google::{self, GoogleIdTokenClaims, GoogleProvider};
use crate::handlers::okta::{normalize_federated_account_id, provision_federated_account};
use crate::models::{GoogleConfigResponse, GoogleTokenExchangeRequest, TokenResponse};
use crate::telemetry::{token_exchange_outcome, AppMetrics};

/// Derive the bridge account id from validated Google ID-token claims.
///
/// The email is used as the account id ONLY when Google asserts
/// `email_verified == true`; otherwise (unverified or missing email) the
/// stable `google:{sub}` form is used so an attacker-controlled unverified
/// email can never claim an existing email-keyed account.
fn derive_google_account_id(claims: &GoogleIdTokenClaims) -> String {
    if claims.email_verified {
        if let Some(email) = claims.email.as_deref() {
            if !email.trim().is_empty() {
                return email.to_string();
            }
        }
    }
    format!("google:{}", claims.sub)
}

/// `POST /auth/google` — Exchange a Google ID token for local JWT tokens.
///
/// Validates the ID token against Google's JWKS (RS256, issuer, audience =
/// `GOOGLE_CLIENT_ID`, expiry), auto-provisions the user if needed, and
/// issues a local refresh + temporal token pair. Rate-limited per account.
pub async fn google_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    google_provider: Option<Extension<Arc<GoogleProvider>>>,
    Json(payload): Json<GoogleTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let result = google_token_exchange_inner(
        pool,
        jwt_keys,
        redis_pool,
        admin_ids,
        google_provider,
        payload,
    )
    .await;
    metrics.record_token_exchange("google", token_exchange_outcome(&result));
    result
}

async fn google_token_exchange_inner(
    pool: PgPool,
    jwt_keys: Arc<crate::jwt::JwtKeys>,
    redis_pool: Arc<deadpool_redis::Pool>,
    admin_ids: Arc<std::collections::HashSet<String>>,
    google_provider: Option<Extension<Arc<GoogleProvider>>>,
    payload: GoogleTokenExchangeRequest,
) -> Result<Json<TokenResponse>, AppError> {
    debug!("POST /auth/google: token exchange request received");

    let provider = google_provider.map(|Extension(p)| p).ok_or_else(|| {
        AppError::BadRequest("Google authentication is not configured".to_string())
    })?;

    // Validate the Google ID token
    let claims = google::validate_google_id_token(&provider, &payload.id_token).await?;

    // Determine account ID (verified email, else google:{sub})
    let account_id = derive_google_account_id(&claims);
    let account_id = normalize_federated_account_id(&account_id, "google")?;

    info!("google: token exchange for account_id={}", account_id);

    // Rate limiting and lockout checks (fail-closed on Redis errors)
    crate::redis_helpers::check_lockout(&redis_pool, &account_id, LOCKOUT_THRESHOLD).await?;
    crate::redis_helpers::check_rate_limit(
        &redis_pool,
        "google",
        &account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Auto-provision using a database transaction
    provision_federated_account(&pool, &account_id, AUTH_PROVIDER_GOOGLE).await?;

    // Issue local JWT tokens (admin derived from the allowlist at issuance)
    let is_admin = admin_ids.contains(&account_id);
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, &account_id, is_admin)?;

    info!("google: tokens issued for account_id={}", account_id);

    Ok(Json(TokenResponse {
        success: true,
        message: "Google authentication successful".to_string(),
        refresh_token: Some(refresh_token),
        temporal_token: Some(temporal_token),
    }))
}

/// `GET /auth/google/config` — Return Google client configuration.
///
/// No auth required. Returns `{ enabled: false }` if Google is not configured.
pub async fn google_config(
    google_provider: Option<Extension<Arc<GoogleProvider>>>,
) -> Json<GoogleConfigResponse> {
    match google_provider {
        Some(Extension(provider)) => {
            debug!("GET /auth/google/config: returning Google configuration");
            Json(GoogleConfigResponse {
                enabled: true,
                client_id: Some(provider.client_id.clone()),
            })
        }
        None => {
            debug!("GET /auth/google/config: Google not configured");
            Json(GoogleConfigResponse {
                enabled: false,
                client_id: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(email: Option<&str>, verified: bool) -> GoogleIdTokenClaims {
        GoogleIdTokenClaims {
            sub: "110169484474386276334".to_string(),
            iss: "https://accounts.google.com".to_string(),
            aud: serde_json::Value::Null,
            exp: 0,
            iat: 0,
            email: email.map(str::to_string),
            email_verified: verified,
            name: None,
        }
    }

    #[test]
    fn verified_email_becomes_account_id() {
        let c = claims(Some("User@Example.com"), true);
        assert_eq!(derive_google_account_id(&c), "User@Example.com");
        // normalize_federated_account_id lowercases downstream
        assert_eq!(
            normalize_federated_account_id(&derive_google_account_id(&c), "google").unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn unverified_email_falls_back_to_sub() {
        let c = claims(Some("user@example.com"), false);
        assert_eq!(derive_google_account_id(&c), "google:110169484474386276334");
    }

    #[test]
    fn missing_email_falls_back_to_sub() {
        let c = claims(None, true);
        assert_eq!(derive_google_account_id(&c), "google:110169484474386276334");
    }

    #[test]
    fn blank_verified_email_falls_back_to_sub() {
        let c = claims(Some("   "), true);
        assert_eq!(derive_google_account_id(&c), "google:110169484474386276334");
    }
}
