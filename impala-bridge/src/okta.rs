use log::{debug, error, info, warn};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::AppError;

/// OIDC discovery document from the authorization server.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// JWKS key set response.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Individual JSON Web Key (RSA public key).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub n: String,
    pub e: String,
}

/// Claims from a validated Okta access token.
#[derive(Debug, Deserialize)]
pub struct OktaAccessTokenClaims {
    pub sub: String,
    pub iss: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    pub exp: usize,
    pub iat: usize,
    pub uid: Option<String>,
    pub email: Option<String>,
    pub preferred_username: Option<String>,
}

/// Shared Okta provider state.
pub struct OktaProvider {
    pub discovery: OidcDiscovery,
    pub jwks: Arc<RwLock<JwksResponse>>,
    pub client_id: String,
    pub issuer_url: String,
    pub http_client: reqwest::Client,
}

/// Fetch the OIDC discovery document from the authorization server.
/// Tries `.well-known/oauth-authorization-server` first, then falls back
/// to `.well-known/openid-configuration`.
pub async fn fetch_discovery(
    client: &reqwest::Client,
    issuer_url: &str,
) -> Result<OidcDiscovery, AppError> {
    let base = issuer_url.trim_end_matches('/');

    let oauth_url = format!("{}/.well-known/oauth-authorization-server", base);
    debug!("okta: fetching discovery from {}", oauth_url);

    match client.get(&oauth_url).send().await {
        Ok(res) if res.status().is_success() => {
            let discovery: OidcDiscovery = res.json().await.map_err(|e| {
                error!("okta: failed to parse discovery document: {}", e);
                AppError::InternalError("Failed to parse Okta discovery document".to_string())
            })?;
            info!("okta: discovery loaded from oauth-authorization-server");
            return Ok(discovery);
        }
        _ => {
            debug!("okta: oauth-authorization-server not found, trying openid-configuration");
        }
    }

    let oidc_url = format!("{}/.well-known/openid-configuration", base);
    let res = client.get(&oidc_url).send().await.map_err(|e| {
        error!("okta: failed to fetch openid-configuration: {}", e);
        AppError::InternalError("Failed to fetch Okta discovery document".to_string())
    })?;

    if !res.status().is_success() {
        error!("okta: discovery endpoint returned {}", res.status());
        return Err(AppError::InternalError(
            "Okta discovery endpoint returned an error".to_string(),
        ));
    }

    let discovery: OidcDiscovery = res.json().await.map_err(|e| {
        error!("okta: failed to parse openid-configuration: {}", e);
        AppError::InternalError("Failed to parse Okta discovery document".to_string())
    })?;

    info!("okta: discovery loaded from openid-configuration");
    Ok(discovery)
}

/// Fetch the JWKS key set from the provider.
pub async fn fetch_jwks(
    client: &reqwest::Client,
    jwks_uri: &str,
) -> Result<JwksResponse, AppError> {
    debug!("okta: fetching JWKS from {}", jwks_uri);
    let res = client.get(jwks_uri).send().await.map_err(|e| {
        error!("okta: failed to fetch JWKS: {}", e);
        AppError::InternalError("Failed to fetch JWKS".to_string())
    })?;

    if !res.status().is_success() {
        error!("okta: JWKS endpoint returned {}", res.status());
        return Err(AppError::InternalError(
            "JWKS endpoint returned an error".to_string(),
        ));
    }

    let jwks: JwksResponse = res.json().await.map_err(|e| {
        error!("okta: failed to parse JWKS: {}", e);
        AppError::InternalError("Failed to parse JWKS".to_string())
    })?;

    info!("okta: loaded {} keys from JWKS", jwks.keys.len());
    Ok(jwks)
}

/// Initialize the Okta provider if configured. Returns `None` if
/// `okta_issuer_url` is not set.
pub async fn init_okta_provider(config: &Config) -> Option<Arc<OktaProvider>> {
    let issuer_url = config.okta_issuer_url.as_ref()?;
    let client_id = config.okta_client_id.clone().unwrap_or_default();

    if issuer_url.is_empty() {
        return None;
    }

    // Validate that issuer URL uses HTTPS
    if !issuer_url.starts_with("https://") {
        error!("okta: issuer URL must use HTTPS: {}", issuer_url);
        return None;
    }

    info!("okta: initializing provider for issuer {}", issuer_url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_secs,
        ))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to create HTTP client");

    let discovery = match fetch_discovery(&http_client, issuer_url).await {
        Ok(d) => d,
        Err(e) => {
            error!("okta: failed to initialize provider: {}", e);
            return None;
        }
    };

    let jwks = match fetch_jwks(&http_client, &discovery.jwks_uri).await {
        Ok(j) => j,
        Err(e) => {
            error!("okta: failed to fetch initial JWKS: {}", e);
            return None;
        }
    };

    let provider = OktaProvider {
        discovery,
        jwks: Arc::new(RwLock::new(jwks)),
        client_id,
        issuer_url: issuer_url.clone(),
        http_client,
    };

    Some(Arc::new(provider))
}

/// Background task that periodically refreshes the JWKS key set.
/// Uses exponential backoff on failure (capped at 5 minutes).
/// Respects cancellation for graceful shutdown.
pub async fn jwks_refresh_task(
    provider: Arc<OktaProvider>,
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
            info!("okta: jwks_refresh_task shutting down");
            return;
        }
    }

    loop {
        debug!("okta: refreshing JWKS keys");
        match fetch_jwks(&provider.http_client, &provider.discovery.jwks_uri).await {
            Ok(new_jwks) => {
                consecutive_failures = 0;
                last_success = Instant::now();
                let mut jwks = provider.jwks.write().await;
                *jwks = new_jwks;
                info!("okta: JWKS keys refreshed successfully");
            }
            Err(e) => {
                consecutive_failures += 1;
                let stale_secs = last_success.elapsed().as_secs();
                if stale_secs > interval_secs * 2 {
                    error!("okta: JWKS keys are {} seconds stale", stale_secs);
                } else {
                    warn!("okta: failed to refresh JWKS keys: {}", e);
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
                info!("okta: jwks_refresh_task shutting down");
                return;
            }
        }
    }
}

/// Validate an Okta access token and return its claims.
///
/// 1. Decodes the JWT header to extract the `kid`.
/// 2. Finds the matching key in the cached JWKS.
/// 3. If not found, triggers a one-shot JWKS refresh before failing.
/// 4. Validates the token signature (RS256), issuer, and audience.
pub async fn validate_okta_token(
    provider: &OktaProvider,
    token: &str,
) -> Result<OktaAccessTokenClaims, AppError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        warn!("okta: failed to decode token header: {}", e);
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
            // Key not found or validation failed — try refreshing JWKS once
            debug!("okta: key kid={} not found in cache, refreshing JWKS", kid);
            match fetch_jwks(&provider.http_client, &provider.discovery.jwks_uri).await {
                Ok(new_jwks) => {
                    let result = try_validate_with_jwks(&new_jwks, token, kid, provider);
                    // Update the cache with the refreshed keys
                    let mut cached = provider.jwks.write().await;
                    *cached = new_jwks;
                    result
                }
                Err(_) => {
                    warn!("okta: JWKS refresh failed during token validation");
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
    provider: &OktaProvider,
) -> Result<OktaAccessTokenClaims, AppError> {
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
            warn!("okta: no matching JWK found for kid={}", kid);
            AppError::Unauthorized
        })?;

    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e);

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.iss = Some(provider.issuer_url.clone());
    validation.set_audience(&[&provider.client_id]);

    let token_data =
        jsonwebtoken::decode::<OktaAccessTokenClaims>(token, &decoding_key, &validation).map_err(
            |e| {
                warn!("okta: token validation failed: {}", e);
                AppError::Unauthorized
            },
        )?;

    debug!("okta: token validated for sub={}", token_data.claims.sub);
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_discovery_deserialize() {
        let json = r#"{
            "issuer": "https://dev-12345.okta.com/oauth2/default",
            "authorization_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/authorize",
            "token_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/token",
            "jwks_uri": "https://dev-12345.okta.com/oauth2/default/v1/keys",
            "scopes_supported": ["openid", "profile", "email"]
        }"#;

        let discovery: OidcDiscovery = serde_json::from_str(json).unwrap();
        assert_eq!(
            discovery.issuer,
            "https://dev-12345.okta.com/oauth2/default"
        );
        assert_eq!(discovery.scopes_supported.len(), 3);
    }

    #[test]
    fn test_jwks_deserialize() {
        let json = r#"{
            "keys": [{
                "kty": "RSA",
                "kid": "test-key-id",
                "alg": "RS256",
                "use": "sig",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }]
        }"#;

        let jwks: JwksResponse = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-key-id"));
        assert_eq!(jwks.keys[0].kty, "RSA");
    }

    #[test]
    fn test_okta_claims_deserialize() {
        let json = r#"{
            "sub": "user123",
            "iss": "https://dev-12345.okta.com/oauth2/default",
            "aud": "0oa1234567890",
            "exp": 1700000000,
            "iat": 1699996400,
            "uid": "00u1234",
            "email": "user@example.com",
            "preferred_username": "user@example.com"
        }"#;

        let claims: OktaAccessTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn test_jwk_key_lookup_exact_kid() {
        let jwks = JwksResponse {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: "test_n".to_string(),
                    e: "test_e".to_string(),
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key2".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: "test_n2".to_string(),
                    e: "test_e2".to_string(),
                },
            ],
        };

        // Exact kid match works
        let found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("key2")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(found.is_some());
        assert_eq!(found.unwrap().n, "test_n2");

        // Non-existent kid returns None (no fallback)
        let not_found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("key3")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(not_found.is_none());
    }

    #[test]
    fn test_jwk_rejects_enc_key() {
        let jwks = JwksResponse {
            keys: vec![Jwk {
                kty: "RSA".to_string(),
                kid: Some("enc-key".to_string()),
                alg: Some("RS256".to_string()),
                use_: Some("enc".to_string()),
                n: "test_n".to_string(),
                e: "test_e".to_string(),
            }],
        };

        let found = jwks.keys.iter().find(|k| {
            k.kid.as_deref() == Some("enc-key")
                && k.kty == "RSA"
                && k.alg.as_deref().is_none_or(|a| a == "RS256")
                && k.use_.as_deref().is_none_or(|u| u == "sig")
        });
        assert!(found.is_none());
    }
}
