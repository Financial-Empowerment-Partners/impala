//! Firebase Cloud Messaging (HTTP v1) authentication for the worker.
//!
//! FCM v1 sends require a Google OAuth2 access token minted from a service
//! account: sign a short-lived RS256 assertion JWT with the account's private
//! key, exchange it at the account's `token_uri` for a bearer token, and cache
//! that token for a little under its lifetime. The service-account JSON is
//! read once at worker startup from the path in `FCM_SERVICE_ACCOUNT_KEY`;
//! its private key never leaves this module and is never logged.
//!
//! Failure model: a key file that is missing or unusable at startup is logged
//! ONCE at ERROR and every push job then fails permanently with a clear
//! message — the job is not retried into the DLQ over a configuration
//! problem. Token-endpoint failures at send time are transient (retried).

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use crate::constants::{FCM_ASSERTION_TTL_SECS, FCM_OAUTH_SCOPE, FCM_TOKEN_REFRESH_MARGIN_SECS};

/// OAuth2 grant type for a service-account assertion (RFC 7523).
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The fields of a Google service-account JSON key the worker uses. The file
/// carries more (project_id, key ids, cert URLs); they are ignored.
#[derive(Deserialize, Clone)]
pub struct ServiceAccountKey {
    pub client_email: String,
    /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`). Secret.
    pub private_key: String,
    pub token_uri: String,
}

/// Redacts the private key: `Config` is Debug-logged under `DEBUG_MODE`, and
/// this must never be one `{:?}` away from syslog.
impl std::fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

impl ServiceAccountKey {
    /// Parse and sanity-check a service-account JSON document. Error strings
    /// describe the shape problem only; they never echo field contents.
    pub fn parse(json: &str) -> Result<Self, String> {
        let key: ServiceAccountKey = serde_json::from_str(json)
            .map_err(|e| format!("not a service-account JSON document: {}", e))?;
        if key.client_email.trim().is_empty() {
            return Err("client_email is empty".to_string());
        }
        if key.private_key.trim().is_empty() {
            return Err("private_key is empty".to_string());
        }
        if !key.token_uri.starts_with("https://") {
            return Err("token_uri must be an https:// URL".to_string());
        }
        Ok(key)
    }
}

/// Claims of the OAuth2 JWT-bearer assertion (Google's service-account
/// flow): the account asserts its own identity to the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionClaims {
    pub iss: String,
    pub scope: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
}

/// Build the assertion claims for `now_unix`. Pure, so the exact claim set
/// Google requires (issuer = the account, audience = its token endpoint,
/// the FCM scope, ≤ 1h life) is pinned by a test rather than by a live call.
pub fn build_assertion_claims(
    client_email: &str,
    token_uri: &str,
    now_unix: u64,
) -> AssertionClaims {
    AssertionClaims {
        iss: client_email.to_string(),
        scope: FCM_OAUTH_SCOPE.to_string(),
        aud: token_uri.to_string(),
        iat: now_unix,
        exp: now_unix + FCM_ASSERTION_TTL_SECS,
    }
}

/// How long a token with the given `expires_in` may be served from cache:
/// the lifetime minus a safety margin, so a send never goes out with a token
/// that expires mid-flight. A token shorter than the margin is not cached.
pub fn cache_lifetime(expires_in_secs: u64) -> Duration {
    Duration::from_secs(expires_in_secs.saturating_sub(FCM_TOKEN_REFRESH_MARGIN_SECS))
}

/// A cached access token and the instant it stops being served.
#[derive(Debug, Clone)]
pub struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

impl CachedToken {
    pub fn new(access_token: String, expires_in_secs: u64, now: Instant) -> Self {
        CachedToken {
            access_token,
            expires_at: now + cache_lifetime(expires_in_secs),
        }
    }

    /// True while the token may still be handed to a send.
    pub fn usable_at(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// Google token-endpoint response (the subset used).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

/// Service-account signer + token cache. Shared by every push job through
/// `WorkerContext`; the mutex serializes minting so a burst of jobs after a
/// token expires produces one exchange, not one per job.
pub struct FcmAuth {
    client_email: String,
    token_uri: String,
    encoding_key: jsonwebtoken::EncodingKey,
    http: reqwest::Client,
    cache: Mutex<Option<CachedToken>>,
}

impl FcmAuth {
    /// Build from a parsed key. The PEM is consumed into an `EncodingKey`
    /// here and not retained.
    pub fn new(key: ServiceAccountKey, http: reqwest::Client) -> Result<Self, String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| format!("private_key is not a usable RSA PEM: {}", e))?;
        Ok(FcmAuth {
            client_email: key.client_email,
            token_uri: key.token_uri,
            encoding_key,
            http,
            cache: Mutex::new(None),
        })
    }

    /// Read + parse + build from the JSON key file at `path`.
    pub fn from_key_file(path: &str, http: reqwest::Client) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read key file '{}': {}", path, e))?;
        let key = ServiceAccountKey::parse(&raw)?;
        Self::new(key, http)
    }

    pub fn client_email(&self) -> &str {
        &self.client_email
    }

    /// Sign the assertion JWT for `now_unix`.
    fn mint_assertion(&self, now_unix: u64) -> Result<String, String> {
        let claims = build_assertion_claims(&self.client_email, &self.token_uri, now_unix);
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| format!("failed to sign assertion: {}", e))
    }

    /// A bearer token for FCM: from cache while fresh, otherwise minted via
    /// the token endpoint. Errors are transient from the caller's view
    /// (the endpoint or network misbehaved); the message never carries the
    /// assertion or the token.
    pub async fn access_token(&self) -> Result<String, String> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.usable_at(Instant::now()) {
                return Ok(cached.access_token.clone());
            }
        }

        let assertion = self.mint_assertion(unix_now())?;
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", JWT_BEARER_GRANT),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("token request failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            // Google's error bodies name the failure class (invalid_grant,
            // invalid_scope…) and contain no secret; keep a bounded slice.
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            return Err(format!(
                "token endpoint returned HTTP {}: {}",
                status, snippet
            ));
        }
        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("token response parse error: {}", e))?;
        if body.access_token.is_empty() {
            return Err("token endpoint returned an empty access_token".to_string());
        }

        let token = CachedToken::new(body.access_token.clone(), body.expires_in, Instant::now());
        *cache = Some(token);
        Ok(body.access_token)
    }

    /// Forget the cached token, e.g. after FCM answered 401 with it, so the
    /// next send mints a fresh one instead of replaying a revoked token.
    pub async fn invalidate(&self) {
        *self.cache.lock().await = None;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Worker-wide FCM readiness, resolved once at startup.
pub enum FcmAuthState {
    /// `FCM_SERVICE_ACCOUNT_KEY` is unset: push jobs fail permanently with a
    /// configuration message.
    Unconfigured,
    /// The variable is set but the key could not be loaded. Logged once at
    /// startup; push jobs fail permanently until the worker is restarted
    /// with a usable key.
    Unavailable(String),
    Ready(Arc<FcmAuth>),
}

impl FcmAuthState {
    pub fn load(key_path: Option<&str>, http: reqwest::Client) -> Self {
        let Some(path) = key_path.map(str::trim).filter(|p| !p.is_empty()) else {
            return FcmAuthState::Unconfigured;
        };
        match FcmAuth::from_key_file(path, http) {
            Ok(auth) => {
                info!(
                    "worker: FCM push delivery enabled (service account {})",
                    auth.client_email()
                );
                FcmAuthState::Ready(Arc::new(auth))
            }
            Err(reason) => {
                error!(
                    "worker: FCM_SERVICE_ACCOUNT_KEY could not be loaded — {}. Push \
                     notifications are DISABLED for this process: every mobile_push job \
                     will fail permanently (not retried) until the worker restarts with a \
                     readable service-account key.",
                    reason
                );
                FcmAuthState::Unavailable(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMAIL: &str = "impala-push@impala-demo.iam.gserviceaccount.com";
    const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

    #[test]
    fn assertion_claims_match_google_service_account_flow() {
        let claims = build_assertion_claims(EMAIL, TOKEN_URI, 1_700_000_000);
        assert_eq!(claims.iss, EMAIL, "issuer is the service account");
        assert_eq!(claims.aud, TOKEN_URI, "audience is the token endpoint");
        assert_eq!(
            claims.scope,
            "https://www.googleapis.com/auth/firebase.messaging"
        );
        assert_eq!(claims.iat, 1_700_000_000);
        assert_eq!(claims.exp, 1_700_000_000 + 3600);
        assert!(
            claims.exp - claims.iat <= 3600,
            "Google rejects assertions living longer than one hour"
        );
    }

    #[test]
    fn assertion_claims_serialize_with_the_wire_field_names() {
        let claims = build_assertion_claims(EMAIL, TOKEN_URI, 10);
        let json = serde_json::to_value(&claims).unwrap();
        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for required in ["iss", "scope", "aud", "iat", "exp"] {
            assert!(keys.contains(&required), "missing claim {}", required);
        }
        assert_eq!(keys.len(), 5, "no extra claims leak into the assertion");
    }

    #[test]
    fn token_cache_serves_until_margin_then_expires() {
        let now = Instant::now();
        let token = CachedToken::new("tok".to_string(), 3600, now);
        assert!(token.usable_at(now));
        assert!(
            token.usable_at(now + Duration::from_secs(55 * 60 - 1)),
            "a 3600s token is reused for ~55 minutes"
        );
        assert!(
            !token.usable_at(now + Duration::from_secs(55 * 60)),
            "…and not past the margin"
        );
        assert!(!token.usable_at(now + Duration::from_secs(3600)));
    }

    #[test]
    fn token_shorter_than_margin_is_never_served_from_cache() {
        let now = Instant::now();
        assert_eq!(cache_lifetime(120), Duration::ZERO);
        let token = CachedToken::new("tok".to_string(), 120, now);
        assert!(!token.usable_at(now));
        // A missing expires_in (deserialized as 0) behaves the same way.
        assert!(!CachedToken::new("tok".to_string(), 0, now).usable_at(now));
    }

    #[test]
    fn service_account_key_parses_the_three_used_fields_and_ignores_the_rest() {
        let json = r#"{
            "type": "service_account",
            "project_id": "impala-demo",
            "private_key_id": "abc123",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
            "client_email": "impala-push@impala-demo.iam.gserviceaccount.com",
            "client_id": "1234567890",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "universe_domain": "googleapis.com"
        }"#;
        let key = ServiceAccountKey::parse(json).unwrap();
        assert_eq!(key.client_email, EMAIL);
        assert_eq!(key.token_uri, TOKEN_URI);
        assert!(key.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn service_account_key_rejects_missing_fields_and_plain_http_token_uri() {
        assert!(ServiceAccountKey::parse("{}").is_err());
        assert!(ServiceAccountKey::parse("not json").is_err());
        let http_uri = format!(
            r#"{{"client_email":"{}","private_key":"x","token_uri":"http://oauth2.googleapis.com/token"}}"#,
            EMAIL
        );
        assert!(ServiceAccountKey::parse(&http_uri).is_err());
        let empty_key = format!(
            r#"{{"client_email":"{}","private_key":"  ","token_uri":"{}"}}"#,
            EMAIL, TOKEN_URI
        );
        assert!(ServiceAccountKey::parse(&empty_key).is_err());
    }

    #[test]
    fn debug_output_redacts_the_private_key() {
        let key = ServiceAccountKey {
            client_email: EMAIL.to_string(),
            private_key: "SECRET-PEM-MATERIAL".to_string(),
            token_uri: TOKEN_URI.to_string(),
        };
        let dbg = format!("{:?}", key);
        assert!(!dbg.contains("SECRET-PEM-MATERIAL"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn unusable_pem_is_a_build_error_not_a_panic() {
        let key = ServiceAccountKey {
            client_email: EMAIL.to_string(),
            private_key: "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"
                .to_string(),
            token_uri: TOKEN_URI.to_string(),
        };
        let err = FcmAuth::new(key, reqwest::Client::new())
            .err()
            .expect("an unusable PEM must be rejected");
        assert!(err.contains("RSA PEM"), "{}", err);
        assert!(
            !err.contains("bm90IGEga2V5"),
            "error must not echo key material"
        );
    }

    /// Missing key file: the state is Unavailable with the reason, so the
    /// worker can log once and fail pushes permanently.
    #[test]
    fn missing_key_file_yields_unavailable_state() {
        let state = FcmAuthState::load(
            Some("/nonexistent/impala-fcm-key.json"),
            reqwest::Client::new(),
        );
        match state {
            FcmAuthState::Unavailable(reason) => assert!(reason.contains("cannot read key file")),
            _ => panic!("expected Unavailable"),
        }
        assert!(matches!(
            FcmAuthState::load(None, reqwest::Client::new()),
            FcmAuthState::Unconfigured
        ));
        assert!(matches!(
            FcmAuthState::load(Some("   "), reqwest::Client::new()),
            FcmAuthState::Unconfigured
        ));
    }

    /// End-to-end signing with a throwaway RSA key generated in the test:
    /// the minted assertion must be RS256, verify under the account's public
    /// key, and carry exactly the claims Google's token endpoint checks.
    #[test]
    fn minted_assertion_is_rs256_and_verifies_with_the_account_public_key() {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;
        use base64::Engine;

        let keypair = KeyPair::generate(KeySize::Rsa2048).expect("rsa keygen");
        let pkcs8: Pkcs8V1Der<'_> = keypair.as_der().expect("pkcs8 der");
        let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );

        let auth = FcmAuth::new(
            ServiceAccountKey {
                client_email: EMAIL.to_string(),
                private_key: pem,
                token_uri: TOKEN_URI.to_string(),
            },
            reqwest::Client::new(),
        )
        .expect("build signer from generated PKCS#8 PEM");

        let now = unix_now();
        let jwt = auth.mint_assertion(now).expect("sign assertion");

        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);

        // Verify against the RSAPublicKey (RFC 8017) DER aws-lc-rs exposes.
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_der(keypair.public_key().as_ref());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[TOKEN_URI]);
        validation.set_issuer(&[EMAIL]);
        let decoded =
            jsonwebtoken::decode::<AssertionClaims>(&jwt, &decoding_key, &validation).unwrap();
        assert_eq!(
            decoded.claims,
            build_assertion_claims(EMAIL, TOKEN_URI, now)
        );
    }
}
