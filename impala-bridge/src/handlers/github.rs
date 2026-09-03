use axum::extract::Extension;
use axum::Json;
use log::{debug, info, warn};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;

use crate::client_source::ClientSource;
use crate::config::Config;
use crate::constants::{
    AUTH_PROVIDER_GITHUB, LOCKOUT_THRESHOLD, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECS,
};
use crate::error::AppError;
use crate::handlers::okta::{normalize_federated_account_id, provision_federated_account};
use crate::models::{GitHubTokenExchangeRequest, TokenResponse};
use crate::telemetry::{token_exchange_outcome, AppMetrics};

/// Maximum accepted GitHub access-token length (tokens are well under this).
const MAX_GITHUB_TOKEN_LENGTH: usize = 512;

/// Shared GitHub provider state (present as an Extension only when
/// `GITHUB_AUTH_ENABLED` is set).
pub struct GitHubProvider {
    pub api_url: String,
    pub http_client: reqwest::Client,
    /// OAuth app credentials for the server-side code→token exchange. When
    /// absent, only the legacy `{access_token}` request shape is accepted.
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub oauth_token_url: String,
}

impl GitHubProvider {
    pub fn new(config: &Config) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                config.http_client_timeout_secs,
            ))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");
        Self {
            api_url: config.github_api_url.trim_end_matches('/').to_string(),
            http_client,
            oauth_client_id: config.github_client_id.clone(),
            oauth_client_secret: config.github_client_secret.clone(),
            oauth_token_url: config.github_oauth_token_url.clone(),
        }
    }
}

/// GitHub's response to the OAuth code→token exchange (JSON via the Accept
/// header). Errors arrive as 200s with an `error` field.
#[derive(Debug, Deserialize)]
struct GitHubCodeExchangeResponse {
    access_token: Option<String>,
    error: Option<String>,
}

/// The subset of `GET /user` the bridge needs.
#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: Option<String>,
}

/// Rate-limit key for a raw GitHub access token: `hex(sha256(token))[..16]`.
/// Hashing keeps the token itself out of Redis keys/logs while still binding
/// the pre-call limit to the credential (relay/DoS guard for the upstream
/// GitHub API call).
fn github_token_rate_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// `POST /auth/github` — Exchange a GitHub access token for local JWT tokens.
///
/// Verifies the token by calling `GET {GITHUB_API_URL}/user`, derives the
/// account id `github:{id}`, auto-provisions the user if needed, and issues
/// a local refresh + temporal token pair. A pre-call rate limit keyed on the
/// token hash guards the upstream API call; per-account rate limiting and
/// lockout apply after identification.
#[allow(clippy::too_many_arguments)] // axum handler: each arg is an extractor
pub async fn github_token_exchange(
    Extension(pool): Extension<PgPool>,
    Extension(jwt_keys): Extension<Arc<crate::jwt::JwtKeys>>,
    Extension(redis_pool): Extension<Arc<deadpool_redis::Pool>>,
    Extension(admin_ids): Extension<Arc<std::collections::HashSet<String>>>,
    Extension(metrics): Extension<Arc<AppMetrics>>,
    github_provider: Option<Extension<Arc<GitHubProvider>>>,
    ClientSource(source): ClientSource,
    Json(payload): Json<GitHubTokenExchangeRequest>,
) -> Result<Json<GitHubExchangeResponse>, AppError> {
    let result = github_token_exchange_inner(
        pool,
        jwt_keys,
        redis_pool,
        admin_ids,
        github_provider,
        &source,
        payload,
    )
    .await;
    metrics.record_token_exchange("github", token_exchange_outcome(&result));
    result
}

async fn github_token_exchange_inner(
    pool: PgPool,
    jwt_keys: Arc<crate::jwt::JwtKeys>,
    redis_pool: Arc<deadpool_redis::Pool>,
    admin_ids: Arc<std::collections::HashSet<String>>,
    github_provider: Option<Extension<Arc<GitHubProvider>>>,
    source: &str,
    payload: GitHubTokenExchangeRequest,
) -> Result<Json<GitHubExchangeResponse>, AppError> {
    debug!("POST /auth/github: token exchange request received");

    let provider = github_provider.map(|Extension(p)| p).ok_or_else(|| {
        AppError::BadRequest("GitHub authentication is not configured".to_string())
    })?;

    // Two request shapes: `{code, redirect_uri}` (server-side OAuth exchange —
    // the client secret lives only here) or legacy `{access_token}`.
    let token = match (&payload.code, &payload.access_token) {
        (Some(code), _) => {
            let credential = sanitize_github_credential(code)?;
            // Pre-call rate limit keyed on the code hash — bounds how often
            // any one credential can make the bridge call out to GitHub.
            crate::redis_helpers::check_rate_limit(
                &redis_pool,
                "github_token",
                &github_token_rate_key(credential),
                RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_WINDOW_SECS,
            )
            .await?;
            exchange_github_code(&provider, credential, payload.redirect_uri.as_deref()).await?
        }
        (None, Some(access_token)) => {
            let token = sanitize_github_credential(access_token)?.to_string();
            crate::redis_helpers::check_rate_limit(
                &redis_pool,
                "github_token",
                &github_token_rate_key(&token),
                RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_WINDOW_SECS,
            )
            .await?;
            // A raw access token carries no audience: GET /user would accept a
            // token issued to ANY GitHub OAuth app for the victim and log the
            // caller in as that victim. Verify the token was issued to THIS
            // app via POST /applications/{client_id}/token (app-authenticated),
            // which also returns the bound user. Without configured OAuth
            // credentials the audience cannot be checked at all, so the legacy
            // shape is refused — use the code exchange.
            let user = verify_github_app_token(&provider, &token).await?;
            return finish_github_login(user, &pool, &redis_pool, &jwt_keys, &admin_ids, source)
                .await;
        }
        (None, None) => {
            return Err(AppError::BadRequest(
                "Either code or access_token must be provided".to_string(),
            ));
        }
    };

    // The code-exchange path yields a token freshly minted for this app, so
    // its audience is already ours; GET /user identifies the caller.
    let user = fetch_github_user(&provider, &token).await?;
    finish_github_login(user, &pool, &redis_pool, &jwt_keys, &admin_ids, source).await
}

/// Shared tail for both GitHub auth shapes: turn an app-verified GitHub user
/// into a provisioned local account and a JWT pair. Both callers must have
/// already established that the token was issued to THIS app (code exchange
/// mints such a token; the legacy path validates it via the app-token check),
/// so the identity here is trustworthy.
async fn finish_github_login(
    user: GitHubUser,
    pool: &PgPool,
    redis_pool: &Arc<deadpool_redis::Pool>,
    jwt_keys: &Arc<crate::jwt::JwtKeys>,
    admin_ids: &Arc<std::collections::HashSet<String>>,
    source: &str,
) -> Result<Json<GitHubExchangeResponse>, AppError> {
    let account_id = normalize_federated_account_id(&format!("github:{}", user.id), "github")?;

    info!(
        "github: token exchange for account_id={} (login={})",
        account_id,
        user.login.as_deref().unwrap_or("-")
    );

    // Rate limiting and lockout checks (fail-closed on Redis errors; the
    // lockout is the password paths' (account, source) counter).
    crate::redis_helpers::check_lockout(redis_pool, &account_id, source, LOCKOUT_THRESHOLD).await?;
    crate::redis_helpers::check_rate_limit(
        redis_pool,
        "github",
        &account_id,
        RATE_LIMIT_MAX_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
    )
    .await?;

    // Auto-provision using a database transaction
    provision_federated_account(pool, &account_id, AUTH_PROVIDER_GITHUB).await?;

    // Issue local JWT tokens (role derived from DB + allowlist at issuance)
    let role = crate::auth::issuance_role(pool, admin_ids, &account_id).await;
    let (refresh_token, temporal_token) =
        crate::jwt::encode_token_pair(jwt_keys, &account_id, &role)?;

    info!("github: tokens issued for account_id={}", account_id);

    Ok(Json(GitHubExchangeResponse {
        base: TokenResponse {
            success: true,
            message: "GitHub authentication successful".to_string(),
            refresh_token: Some(refresh_token),
            temporal_token: Some(temporal_token),
        },
        login: user.login.clone(),
        display_name: user.login,
    }))
}

/// `TokenResponse` plus the GitHub identity fields clients used to fetch
/// on-device (the demo shows the login as the display name). Wire-compatible
/// superset of the legacy response.
#[derive(serde::Serialize)]
pub struct GitHubExchangeResponse {
    #[serde(flatten)]
    pub base: TokenResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Validate a GitHub credential (access token or authorization code):
/// non-empty printable ASCII, bounded length (it is forwarded upstream).
fn sanitize_github_credential(raw: &str) -> Result<&str, AppError> {
    let credential = raw.trim();
    if credential.is_empty()
        || credential.len() > MAX_GITHUB_TOKEN_LENGTH
        || !credential.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(AppError::BadRequest("Invalid access token".to_string()));
    }
    Ok(credential)
}

/// Server-side OAuth code→token exchange at the configured token endpoint.
/// Requires GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET; the secret never leaves
/// the bridge. GitHub reports errors as 200s with an `error` field.
async fn exchange_github_code(
    provider: &GitHubProvider,
    code: &str,
    redirect_uri: Option<&str>,
) -> Result<String, AppError> {
    let (client_id, client_secret) = match (
        provider.oauth_client_id.as_deref(),
        provider.oauth_client_secret.as_deref(),
    ) {
        (Some(id), Some(secret)) => (id, secret),
        _ => {
            warn!("github: code exchange requested but GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET are not configured");
            return Err(AppError::BadRequest(
                "GitHub code exchange is not configured".to_string(),
            ));
        }
    };

    let mut form = vec![
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
    ];
    if let Some(uri) = redirect_uri {
        form.push(("redirect_uri", uri));
    }

    let res = provider
        .http_client
        .post(&provider.oauth_token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::USER_AGENT, "impala-bridge")
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            warn!("github: code exchange request failed: {}", e);
            AppError::InternalError("Failed to exchange GitHub code".to_string())
        })?;

    if !res.status().is_success() {
        warn!("github: code exchange returned {}", res.status());
        return Err(AppError::Unauthorized);
    }

    let body = res
        .json::<GitHubCodeExchangeResponse>()
        .await
        .map_err(|e| {
            warn!("github: failed to parse code exchange response: {}", e);
            AppError::InternalError("Failed to exchange GitHub code".to_string())
        })?;

    if let Some(err) = body.error {
        warn!("github: code exchange rejected: {}", err);
        return Err(AppError::Unauthorized);
    }

    body.access_token.ok_or_else(|| {
        warn!("github: code exchange response missing access_token");
        AppError::Unauthorized
    })
}

/// Validate that a raw access token was issued to THIS OAuth app, and return
/// the user it is bound to. Uses GitHub's app-authenticated token check
/// (`POST {api_url}/applications/{client_id}/token`, Basic auth with the
/// app's client_id:client_secret, body `{"access_token": ...}`), which
/// returns 200 with the authorization (including its `user`) only when the
/// token belongs to this app — closing the cross-app confusion where a token
/// minted for any other GitHub app would otherwise authenticate its bearer.
///
/// Requires configured OAuth credentials; without them a raw token's audience
/// cannot be checked, so the legacy shape is refused (the code exchange, which
/// also needs the secret, is the supported path).
async fn verify_github_app_token(
    provider: &GitHubProvider,
    token: &str,
) -> Result<GitHubUser, AppError> {
    let (client_id, client_secret) = match (
        provider.oauth_client_id.as_deref(),
        provider.oauth_client_secret.as_deref(),
    ) {
        (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => (id, secret),
        _ => {
            warn!("github: legacy access_token shape used without configured OAuth app");
            return Err(AppError::BadRequest(
                "Raw GitHub access tokens are not accepted without a configured OAuth app; \
                     use the authorization-code exchange instead"
                    .to_string(),
            ));
        }
    };

    let url = format!("{}/applications/{}/token", provider.api_url, client_id);
    #[derive(serde::Deserialize)]
    struct AppTokenCheck {
        user: Option<GitHubUser>,
    }
    let res = provider
        .http_client
        .post(&url)
        .basic_auth(client_id, Some(client_secret))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "impala-bridge")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&serde_json::json!({ "access_token": token }))
        .send()
        .await
        .map_err(|e| {
            warn!("github: app-token check request failed: {}", e);
            AppError::InternalError("Failed to verify GitHub token".to_string())
        })?;

    let status = res.status();
    // 404 (token not for this app / invalid) and 422 (bad token) both mean
    // "not a token this app issued" — reject without leaking which.
    if status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        || status == reqwest::StatusCode::UNAUTHORIZED
    {
        warn!("github: access token not issued to this app ({})", status);
        return Err(AppError::Unauthorized);
    }
    if !status.is_success() {
        warn!("github: app-token check returned {}", status);
        return Err(AppError::InternalError(
            "Failed to verify GitHub token".to_string(),
        ));
    }
    let check: AppTokenCheck = res.json().await.map_err(|e| {
        warn!("github: failed to parse app-token check response: {}", e);
        AppError::InternalError("Failed to verify GitHub token".to_string())
    })?;
    check.user.ok_or_else(|| {
        warn!("github: app-token check returned no user");
        AppError::Unauthorized
    })
}

/// Call `GET {api_url}/user` with the presented token. 401/403 map to
/// `Unauthorized`; transport errors map to a generic internal error.
async fn fetch_github_user(provider: &GitHubProvider, token: &str) -> Result<GitHubUser, AppError> {
    let url = format!("{}/user", provider.api_url);
    let res = provider
        .http_client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "impala-bridge")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(|e| {
            warn!("github: GET /user request failed: {}", e);
            AppError::InternalError("Failed to verify GitHub token".to_string())
        })?;

    let status = res.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        warn!("github: token rejected by GitHub ({})", status);
        return Err(AppError::Unauthorized);
    }
    if !status.is_success() {
        warn!("github: GET /user returned {}", status);
        return Err(AppError::InternalError(
            "Failed to verify GitHub token".to_string(),
        ));
    }

    res.json::<GitHubUser>().await.map_err(|e| {
        warn!("github: failed to parse /user response: {}", e);
        AppError::InternalError("Failed to verify GitHub token".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rate_key_is_first_16_hex_of_sha256() {
        // sha256("gho_exampletoken123") =
        //   f1de51658e33f39effe148f62f8cd48ec26c70afbeaa78d3c498fee6629acb51
        assert_eq!(
            github_token_rate_key("gho_exampletoken123"),
            "f1de51658e33f39e"
        );
    }

    #[test]
    fn token_rate_key_never_contains_token_material() {
        let token = "ghp_secretsecretsecret";
        let key = github_token_rate_key(token);
        assert_eq!(key.len(), 16);
        assert!(!token.contains(&key));
    }

    #[test]
    fn github_user_deserializes() {
        let user: GitHubUser =
            serde_json::from_str(r#"{"id": 583231, "login": "octocat", "type": "User"}"#).unwrap();
        assert_eq!(user.id, 583231);
        assert_eq!(user.login.as_deref(), Some("octocat"));
    }

    #[test]
    fn github_account_id_shape() {
        let account_id =
            normalize_federated_account_id(&format!("github:{}", 583231), "github").unwrap();
        assert_eq!(account_id, "github:583231");
    }
}
