//! Google ID-token validation (mirrors `okta.rs`, reusing its
//! provider-agnostic JWKS types).
//!
//! Google publishes its RS256 signing keys at a fixed JWKS endpoint
//! (`GOOGLE_JWKS_URL`), so no OIDC discovery round-trip is needed. Tokens are
//! validated for signature, expiry, audience (`GOOGLE_CLIENT_ID`) and issuer
//! (both `https://accounts.google.com` and `accounts.google.com` — Google
//! emits either form).

use log::{debug, error, info, warn};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::constants::{GOOGLE_JWKS_URL, GOOGLE_TOKEN_ISSUERS};
use crate::error::AppError;
use crate::okta::{fetch_jwks, JwksResponse};

/// Claims from a validated Google ID token.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // claims validated by the JWT library during decode; not all read here
pub struct GoogleIdTokenClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub email: Option<String>,
    /// Google asserts this only for emails it has verified; the bridge uses
    /// the email as account id ONLY when this is `true`.
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Shared Google provider state.
pub struct GoogleProvider {
    pub jwks: Arc<RwLock<JwksResponse>>,
    pub client_id: String,
    pub http_client: reqwest::Client,
    /// Debounce for the unauthenticated on-demand JWKS refetch path.
    pub refresh_cooldown: crate::oidc::RefreshCooldown,
}

/// Initialize the Google provider if configured. Returns `None` if
/// `GOOGLE_CLIENT_ID` is not set (or the initial JWKS fetch fails).
pub async fn init_google_provider(config: &Config) -> Option<Arc<GoogleProvider>> {
    let client_id = config.google_client_id.as_ref()?;
    if client_id.is_empty() {
        return None;
    }

    info!("google: initializing provider for client_id={}", client_id);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_secs,
        ))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to create HTTP client");

    let jwks = match fetch_jwks(&http_client, GOOGLE_JWKS_URL).await {
        Ok(j) => j,
        Err(e) => {
            error!("google: failed to fetch initial JWKS: {}", e);
            return None;
        }
    };

    Some(Arc::new(GoogleProvider {
        jwks: Arc::new(RwLock::new(jwks)),
        client_id: client_id.clone(),
        http_client,
        refresh_cooldown: crate::oidc::RefreshCooldown::new(),
    }))
}

/// Background task that periodically refreshes the Google JWKS key set.
/// Same backoff/staleness behavior as `okta::jwks_refresh_task`.
pub async fn jwks_refresh_task(
    provider: Arc<GoogleProvider>,
    interval_secs: u64,
    cancel: tokio_util::sync::CancellationToken,
) {
    use tokio::time::{Duration, Instant};

    let mut consecutive_failures: u32 = 0;
    let mut last_success = Instant::now();

    // Skip the first immediate tick since we already fetched during init
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
        _ = cancel.cancelled() => {
            info!("google: jwks_refresh_task shutting down");
            return;
        }
    }

    loop {
        debug!("google: refreshing JWKS keys");
        match fetch_jwks(&provider.http_client, GOOGLE_JWKS_URL).await {
            Ok(new_jwks) => {
                consecutive_failures = 0;
                last_success = Instant::now();
                let mut jwks = provider.jwks.write().await;
                *jwks = new_jwks;
                info!("google: JWKS keys refreshed successfully");
            }
            Err(e) => {
                consecutive_failures += 1;
                let stale_secs = last_success.elapsed().as_secs();
                if stale_secs > interval_secs * 2 {
                    error!("google: JWKS keys are {} seconds stale", stale_secs);
                } else {
                    warn!("google: failed to refresh JWKS keys: {}", e);
                }
            }
        }

        let wait_secs = if consecutive_failures > 0 {
            std::cmp::min(
                interval_secs.saturating_mul(2u64.saturating_pow(consecutive_failures)),
                300,
            )
        } else {
            interval_secs
        };
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait_secs)) => {}
            _ = cancel.cancelled() => {
                info!("google: jwks_refresh_task shutting down");
                return;
            }
        }
    }
}

/// Validate a Google ID token and return its claims.
///
/// Same flow as `okta::validate_okta_token`: cached JWKS first, then a
/// one-shot refresh when the `kid` is unknown (key rotation).
pub async fn validate_google_id_token(
    provider: &GoogleProvider,
    token: &str,
) -> Result<GoogleIdTokenClaims, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        warn!("google: failed to decode token header: {}", e);
        AppError::Unauthorized
    })?;

    let kid = header.kid.as_deref().unwrap_or("");

    // Try to find the key in the cached JWKS
    let claims = {
        let jwks = provider.jwks.read().await;
        try_validate_with_jwks(&jwks, token, kid, provider)
    };

    match claims {
        Ok(c) => Ok(c),
        Err(_) if !kid.is_empty() => {
            // Key not found or validation failed — try refreshing JWKS once,
            // subject to the cooldown (see crate::oidc::RefreshCooldown): this
            // path is reachable unauthenticated with an attacker-chosen kid.
            if !provider
                .refresh_cooldown
                .try_acquire(std::time::Duration::from_secs(
                    crate::constants::JWKS_ON_DEMAND_COOLDOWN_SECS,
                ))
            {
                debug!("google: skipping JWKS refresh for kid={} (cooldown)", kid);
                return Err(AppError::Unauthorized);
            }
            debug!(
                "google: key kid={} not found in cache, refreshing JWKS",
                kid
            );
            match fetch_jwks(&provider.http_client, GOOGLE_JWKS_URL).await {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    let mut cached = provider.jwks.write().await;
                    *cached = new_jwks;
                    result
                }
                Err(_) => {
                    warn!("google: JWKS refresh failed during token validation");
                    Err(AppError::Unauthorized)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Attempt to validate a token against a JWKS key set.
/// Requires exact `kid` match with `kty == "RSA"`, compatible `alg`, and `use == "sig"`.
fn try_validate_with_jwks(
    jwks: &JwksResponse,
    token: &str,
    kid: &str,
    provider: &GoogleProvider,
) -> Result<GoogleIdTokenClaims, AppError> {
    let jwk = jwks
        .keys
        .iter()
        .find(|k| {
            k.kid.as_deref() == Some(kid)
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        })
        .ok_or_else(|| {
            warn!("google: no matching JWK found for kid={}", kid);
            AppError::Unauthorized
        })?;

    let decoding_key =
        jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            warn!("google: failed to construct decoding key: {}", e);
            AppError::Unauthorized
        })?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&GOOGLE_TOKEN_ISSUERS);
    validation.set_audience(&[&provider.client_id]);

    let token_data = jsonwebtoken::decode::<GoogleIdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| {
            warn!("google: token validation failed: {}", e);
            AppError::Unauthorized
        })?;

    debug!("google: token validated for sub={}", token_data.claims.sub);
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_claims_deserialize_verified_email() {
        let json = r#"{
            "sub": "110169484474386276334",
            "iss": "https://accounts.google.com",
            "aud": "1234567890-abc.apps.googleusercontent.com",
            "exp": 1700000000,
            "iat": 1699996400,
            "email": "User@Example.com",
            "email_verified": true,
            "name": "Test User"
        }"#;

        let claims: GoogleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "110169484474386276334");
        assert!(claims.email_verified);
        assert_eq!(claims.email.as_deref(), Some("User@Example.com"));
    }

    #[test]
    fn test_google_claims_email_verified_defaults_false() {
        // A token without the email_verified claim must never be treated as
        // verified (the email would otherwise become the account id).
        let json = r#"{
            "sub": "s",
            "iss": "accounts.google.com",
            "exp": 1700000000,
            "iat": 1699996400,
            "email": "user@example.com"
        }"#;

        let claims: GoogleIdTokenClaims = serde_json::from_str(json).unwrap();
        assert!(!claims.email_verified);
    }

    #[test]
    fn test_google_issuer_list_pins_both_forms() {
        assert_eq!(
            GOOGLE_TOKEN_ISSUERS,
            ["https://accounts.google.com", "accounts.google.com"]
        );
    }
}
