use axum::extract::{Extension, Path};
use axum::Json;
use log::{debug, error, info, warn};
use sqlx::PgPool;
use std::sync::Arc;

use crate::client_source::ClientSource;
use crate::config::TokenKind;
use crate::constants::{
    LOCKOUT_THRESHOLD, MAX_EMAIL_LENGTH, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::models::{SsoConfigResponse, SsoTokenExchangeRequest, TokenResponse};
use crate::oidc::{self, ProviderRegistry};

/// Derive the local account id for an SSO subject.
///
/// Unifies on email ONLY when the IdP positively asserts the address is
/// verified; anything else falls back to a provider-namespaced subject.
///
/// The bar is `Some(true)`, not "not explicitly false": every configured IdP
/// shares one account namespace, so an *absent* `email_verified` — the norm
/// for providers that let a subject self-assert the claim — would let a token
/// from the weakest configured IdP claim `victim@corp.com` and land on the
/// victim's bridge account, ADMIN_ACCOUNT_IDS matching included. This mirrors
/// `handlers::google::derive_google_account_id`.
fn derive_sso_account_id(provider_name: &str, claims: &oidc::OidcTokenClaims) -> String {
    match claims.email.as_deref() {
        Some(email) if !email.trim().is_empty() && claims.email_verified == Some(true) => {
            email.trim().to_lowercase()
        }
        _ => format!("{}:{}", provider_name, claims.sub).to_lowercase(),
    }
}

/// `POST /auth/sso/:provider` — Exchange an OIDC token for local JWT tokens.
///
/// Looks the provider up in the registry, validates the token it expects
/// (access token, or id token for `token_kind = id`), auto-provisions the user
/// if needed, and issues a local refresh + temporal token pair. Rate-limited
/// per account and scoped by provider name.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an extractor
pub async fn sso_token_exchange(
    Path(provider_name): Path<String>,
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(registry): Extension<Arc<ProviderRegistry>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<SsoTokenExchangeRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let provider_name = provider_name.to_lowercase();
    debug!(
        "POST /auth/sso/{}: token exchange request received",
        provider_name
    );

    let provider = registry.get(&provider_name).ok_or_else(|| {
        AppError::BadRequest(format!(
            "SSO provider '{}' is not configured",
            provider_name
        ))
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

    let account_id = derive_sso_account_id(&provider.name, &claims);

    if account_id.is_empty() {
        warn!(
            "sso[{}]: empty account_id derived from token",
            provider.name
        );
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.len() > MAX_EMAIL_LENGTH {
        warn!(
            "sso[{}]: account_id exceeds max length: {}",
            provider.name,
            account_id.len()
        );
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }
    if account_id.chars().any(|c| c.is_control()) {
        warn!(
            "sso[{}]: account_id contains control characters",
            provider.name
        );
        return Err(AppError::BadRequest(
            "Invalid account identifier".to_string(),
        ));
    }

    info!(
        "sso[{}]: token exchange for account_id={}",
        provider.name, account_id
    );

    // Rate limiting and lockout checks. Rate limit is scoped per provider;
    // lockout is per (account, source) across all providers/local — locking
    // the human, but only from the source that earned it.
    crate::redis_helpers::check_lockout(&redis_pool, &account_id, &source, LOCKOUT_THRESHOLD)
        .await?;
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
        error!(
            "sso[{}]: failed to upsert auth record: {}",
            provider.name, e
        );
        AppError::InternalError("Failed to provision authentication".to_string())
    })?;

    tx.commit().await.map_err(|e| {
        error!(
            "sso[{}]: failed to commit transaction: {}",
            provider.name, e
        );
        AppError::InternalError("Database error".to_string())
    })?;

    // Issue local JWT tokens, embedding the account's server-side role
    // (the ADMIN_ACCOUNT_IDS allowlist overrides to admin, matching every
    // other issuance path).
    let role = crate::auth::issuance_role(&pool, &admin_ids, &account_id).await;
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(&jwt_keys, &account_id, &role)?;

    info!(
        "sso[{}]: tokens issued for account_id={}",
        provider.name, account_id
    );

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
/// configured, so the dashboard can hide the button — and
/// `{ enabled: false, pending: true }` while a configured provider is still
/// waiting on its IdP (discovery/JWKS), so the button stays hidden until a
/// token exchange could actually succeed.
pub async fn sso_config(
    Path(provider_name): Path<String>,
    Extension(registry): Extension<Arc<ProviderRegistry>>,
) -> Json<SsoConfigResponse> {
    let provider_name = provider_name.to_lowercase();
    let Some(provider) = registry.get(&provider_name) else {
        debug!(
            "GET /auth/sso/{}/config: provider not configured",
            provider_name
        );
        return Json(SsoConfigResponse {
            enabled: false,
            provider: None,
            issuer: None,
            client_id: None,
            audience: None,
            authorization_endpoint: None,
            token_endpoint: None,
            scopes: None,
            pending: false,
        });
    };
    match provider.discovery().await {
        Some(discovery) => {
            debug!(
                "GET /auth/sso/{}/config: returning configuration",
                provider_name
            );
            Json(SsoConfigResponse {
                enabled: true,
                provider: Some(provider.name.clone()),
                issuer: Some(provider.issuer_url.clone()),
                client_id: Some(provider.client_id.clone()),
                audience: Some(provider.audience.clone()),
                authorization_endpoint: Some(discovery.authorization_endpoint),
                token_endpoint: Some(discovery.token_endpoint),
                scopes: Some(discovery.scopes_supported),
                pending: false,
            })
        }
        None => {
            debug!(
                "GET /auth/sso/{}/config: provider configured but PENDING",
                provider_name
            );
            Json(SsoConfigResponse {
                enabled: false,
                provider: Some(provider.name.clone()),
                issuer: None,
                client_id: None,
                audience: None,
                authorization_endpoint: None,
                token_endpoint: None,
                scopes: None,
                pending: true,
            })
        }
    }
}

/// `GET /auth/providers` — List the names of all configured SSO providers,
/// so the dashboard can render one button per provider without hardcoding.
pub async fn sso_providers(
    Extension(registry): Extension<Arc<ProviderRegistry>>,
) -> Json<Vec<String>> {
    Json(registry.names())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(email: Option<&str>, verified: Option<bool>) -> oidc::OidcTokenClaims {
        oidc::OidcTokenClaims {
            sub: "00u1abcdEFGH".to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: serde_json::json!("impala"),
            exp: 0,
            iat: 0,
            uid: None,
            email: email.map(str::to_string),
            email_verified: verified,
            preferred_username: None,
        }
    }

    #[test]
    fn verified_email_keys_the_shared_account() {
        let id = derive_sso_account_id("okta", &claims(Some("User@Example.com"), Some(true)));
        assert_eq!(id, "user@example.com");
    }

    /// The load-bearing case: a missing `email_verified` must NOT be trusted.
    /// Configured IdPs share one account namespace, so treating "absent" as
    /// "verified" would let a token from any provider that lets its subject
    /// set the claim take over an email-keyed account at another.
    #[test]
    fn absent_email_verified_falls_back_to_namespaced_subject() {
        let id = derive_sso_account_id("duo", &claims(Some("victim@corp.com"), None));
        assert_eq!(id, "duo:00u1abcdefgh");
    }

    #[test]
    fn explicitly_unverified_email_falls_back_to_namespaced_subject() {
        let id = derive_sso_account_id("auth0", &claims(Some("victim@corp.com"), Some(false)));
        assert_eq!(id, "auth0:00u1abcdefgh");
    }

    #[test]
    fn missing_or_blank_email_falls_back_to_namespaced_subject() {
        assert_eq!(
            derive_sso_account_id("okta", &claims(None, Some(true))),
            "okta:00u1abcdefgh"
        );
        assert_eq!(
            derive_sso_account_id("okta", &claims(Some("   "), Some(true))),
            "okta:00u1abcdefgh"
        );
    }

    /// Two providers asserting the same verified email intentionally collapse
    /// onto one account; the namespaced fallback must stay per-provider.
    #[test]
    fn namespaced_fallback_is_per_provider() {
        let a = derive_sso_account_id("okta", &claims(None, None));
        let b = derive_sso_account_id("duo", &claims(None, None));
        assert_ne!(a, b);
    }
}
