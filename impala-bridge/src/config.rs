use crate::constants::*;
use std::collections::HashSet;
use std::env;
use std::fs;

#[derive(Debug, Clone, PartialEq)]
pub enum StellarNetwork {
    Testnet,
    Pubnet,
}

impl StellarNetwork {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pubnet" | "mainnet" | "public" => StellarNetwork::Pubnet,
            _ => StellarNetwork::Testnet,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StellarNetwork::Testnet => "testnet",
            StellarNetwork::Pubnet => "pubnet",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StellarConfig {
    pub network: StellarNetwork,
    pub horizon_url: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub contract_id: Option<String>,
}

/// Which token the bridge JWKS-validates for an OIDC provider.
///
/// Most providers (Okta, Auth0) hand the browser a JWT **access token** that
/// carries the identity claims. Some (e.g. Duo SSO) reliably carry the identity
/// only in the **id token**, so those are configured with `TokenKind::Id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Access,
    Id,
}

impl TokenKind {
    pub fn from_str_opt(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "id" | "id_token" | "idtoken" => TokenKind::Id,
            _ => TokenKind::Access,
        }
    }
}

/// Configuration for a single OIDC SSO provider (Okta / Auth0 / Duo / …).
///
/// Providers are declared via `SSO_PROVIDERS=okta,auth0,duo` (or the
/// `sso_providers` config-file key — a comma-list *string*, not an array) and
/// each is configured through prefixed env vars: `{NAME}_ISSUER_URL`,
/// `{NAME}_CLIENT_ID`, `{NAME}_AUDIENCE`, `{NAME}_JWKS_REFRESH_SECS`,
/// `{NAME}_TOKEN_KIND`, `{NAME}_INTERNAL_ISSUER_URL`, `{NAME}_ALLOW_HTTP`.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    /// Validated as the JWT `aud`. Defaults to `client_id` when unset (Okta);
    /// set to the API identifier for Auth0.
    pub audience: String,
    pub jwks_refresh_secs: u64,
    pub token_kind: TokenKind,
    /// Optional server-side base URL used ONLY for discovery/JWKS fetches when
    /// the public issuer is not reachable from the bridge (split-horizon dev
    /// setups, e.g. the docker-compose OpenBao test IdP). `iss` validation and
    /// the `/auth/sso/:provider/config` passthrough always use `issuer_url`.
    pub internal_issuer_url: Option<String>,
    /// Dev-only opt-in permitting plain-HTTP issuer URLs. Default false.
    pub allow_http: bool,
}

/// Build the SSO provider list from a lookup function mapping
/// `(provider name, KEY)` to a configured value (env var or config file).
/// Extracted from `load_config` so tests can drive it with a plain closure
/// instead of mutating process-wide env vars.
pub(crate) fn parse_sso_providers<F>(names: &[String], provider_var: F) -> Vec<ProviderConfig>
where
    F: Fn(&str, &str) -> Option<String>,
{
    names
        .iter()
        .filter_map(|name| {
            let issuer_url = provider_var(name, "ISSUER_URL")?;
            if issuer_url.trim().is_empty() {
                return None;
            }
            let client_id = provider_var(name, "CLIENT_ID").unwrap_or_default();
            let audience = provider_var(name, "AUDIENCE")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| client_id.clone());
            let jwks_refresh_secs = provider_var(name, "JWKS_REFRESH_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);
            let token_kind = provider_var(name, "TOKEN_KIND")
                .map(|v| TokenKind::from_str_opt(&v))
                .unwrap_or(TokenKind::Access);
            let internal_issuer_url =
                provider_var(name, "INTERNAL_ISSUER_URL").filter(|s| !s.trim().is_empty());
            let allow_http = provider_var(name, "ALLOW_HTTP")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            Some(ProviderConfig {
                name: name.clone(),
                issuer_url,
                client_id,
                audience,
                jwks_refresh_secs,
                token_kind,
                internal_issuer_url,
                allow_http,
            })
        })
        .collect()
}

#[derive(Clone)]
#[allow(dead_code)] // config surface; several fields are populated from env but not yet read
pub struct Config {
    #[allow(dead_code)] // loaded config, not currently read in code paths
    pub public_endpoint: String,
    pub service_address: String,
    #[allow(dead_code)] // loaded config, not currently read in code paths
    pub log_file: String,
    pub debug_mode: bool,
    pub twilio_sid: Option<String>,
    pub twilio_token: Option<String>,
    pub twilio_number: Option<String>,
    pub ldap_url: Option<String>,
    pub ldap_bind_dn: Option<String>,
    pub ldap_bind_password: Option<String>,
    pub ldap_base_dn: Option<String>,
    pub ldap_search_filter: Option<String>,
    pub db_max_connections: u32,
    pub cors_allowed_origins: String,
    pub http_client_timeout_secs: u64,
    /// Legacy single-provider Okta config (the `/auth/okta` cookie-capable
    /// flow); the multi-provider SSO registry below supersedes it for bearer
    /// clients but the UI cookie flow still rides this provider.
    pub okta_issuer_url: Option<String>,
    pub okta_client_id: Option<String>,
    pub okta_jwks_refresh_secs: u64,
    /// OAuth client ID accepted as `aud` on Google ID tokens; enables /auth/google.
    pub google_client_id: Option<String>,
    pub google_jwks_refresh_secs: u64,
    /// Enables /auth/github (GitHub access-token exchange).
    pub github_auth_enabled: bool,
    /// GitHub REST API base URL (override for GitHub Enterprise Server).
    pub github_api_url: String,
    /// OAuth app client id for the server-side code→token exchange.
    pub github_client_id: Option<String>,
    /// OAuth app client secret (server-side only — never ships in clients).
    pub github_client_secret: Option<String>,
    /// GitHub OAuth token endpoint (override for GHES/tests).
    pub github_oauth_token_url: String,
    /// Configured OIDC SSO providers (Okta / Auth0 / Duo / …). Empty when SSO is off.
    pub sso_providers: Vec<ProviderConfig>,
    pub sqs_queue_url: Option<String>,
    pub sns_topic_arn: Option<String>,
    pub worker_concurrency: usize,
    pub sqs_wait_time_seconds: i32,
    pub sqs_visibility_timeout: i32,
    pub ses_from_address: Option<String>,
    pub fcm_project_id: Option<String>,
    #[allow(dead_code)] // loaded config, not currently read in code paths
    pub fcm_service_account_key: Option<String>,
    pub otel_exporter_endpoint: Option<String>,
    pub otel_service_name: Option<String>,
    pub otel_environment: Option<String>,
    pub stellar_network: StellarNetwork,
    pub stellar_horizon_url: String,
    pub stellar_rpc_url: String,
    pub stellar_network_passphrase: String,
    pub soroban_contract_id: Option<String>,
    /// Account IDs (JWT `sub`) granted admin; overrides the DB role to `admin`
    /// when the `role` claim is stamped at token issuance.
    pub admin_account_ids: HashSet<String>,
    /// Max delivery attempts before an admin-webhook delivery is marked failed.
    pub admin_webhook_max_attempts: u32,
    /// Consecutive-failure count after which a webhook is auto-disabled.
    pub admin_webhook_disable_threshold: i64,
    /// Poll interval (seconds) for the admin-webhook delivery worker.
    pub admin_webhook_poll_secs: u64,
    /// Mark session cookies `Secure` (+ `__Host-` name prefix). Default true;
    /// the plain-HTTP local compose stack sets SESSION_COOKIE_SECURE=false.
    pub session_cookie_secure: bool,
    /// Whether `POST /authenticate` may set a password on an existing account
    /// that has no credentials yet. Default **false** (fail closed) — see the
    /// account-claiming note in `handlers::authenticate`.
    pub allow_open_registration: bool,
    /// deadpool-redis pool size (REDIS_POOL_SIZE).
    pub redis_pool_size: usize,
    /// Global HTTP request timeout in seconds (REQUEST_TIMEOUT_SECS).
    pub request_timeout_secs: u64,
    /// Postgres pool acquire timeout in seconds (DB_ACQUIRE_TIMEOUT_SECS).
    pub db_acquire_timeout_secs: u64,
    // Custodial Stellar seed protection. Non-secret config only — auth secrets
    // (VAULT_TOKEN / VAULT_SECRET_ID) are read directly from the environment so
    // they never land in this `Debug`-logged struct.
    pub seed_protection_backend: String,
    pub kms_seed_key_id: Option<String>,
    pub vault_addr: Option<String>,
    pub vault_transit_key: Option<String>,
    // Exchange providers (OwlPay / Changelly). Non-secret config only — API
    // keys and signing keys (OWLPAY_API_KEY, CHANGELLY_PRIVATE_KEY, …) are read
    // directly from the environment by the provider init fns so they never
    // land in this `Debug`-logged struct.
    /// OwlPay Harbor API base URL (sandbox default; production is per-tenant).
    pub owlpay_api_url: String,
    /// Changelly Exchange API v2 (crypto swap) base URL.
    pub changelly_api_url: String,
    /// Changelly Fiat API base URL.
    pub changelly_fiat_api_url: String,
    /// Poll interval (seconds) for the exchange-order reconcile loop.
    pub exchange_poll_secs: u64,

    // Conversion reserve (bridge service reserve for small exchange orders).
    // None of these are secrets — the reserve's signing seed stays in
    // managed_seed behind the seed protector; thresholds/enablement live in
    // the conversion_reserve_policy DB table (admin-editable at runtime).
    /// payala_account_id of the managed-seed account designated as the
    /// reserve. Presence enables the subsystem (init fails closed if the
    /// account has no seed). This account is quarantined from user-facing
    /// custodial endpoints.
    pub reserve_account_id: Option<String>,
    /// Stellar issuer (`G...`) of the USDC asset the reserve pays out and
    /// recognizes as deposits. Required when the reserve is enabled.
    pub reserve_usdc_issuer: Option<String>,
    /// Asset code of that asset. ["USDC"]
    pub reserve_usdc_code: String,
    /// Deposit window for reserve orders (seconds) — also the price-validity
    /// window (a long TTL is a free price option on the pool). Clamped to
    /// [300, 7200]. [1800]
    pub reserve_deposit_ttl_secs: u64,
    /// Reserve deposit-watcher cadence (seconds), clamped to >= 5. [30]
    pub reserve_watch_secs: u64,
}

/// Render an optional secret as its presence, never its value.
fn secret_state(value: &Option<String>) -> &'static str {
    match value {
        Some(_) => "<set:redacted>",
        None => "<unset>",
    }
}

/// Hand-written so that `{:?}` on a `Config` can never print a credential.
///
/// This was a derive, and `main.rs` logs `Config: {:?}` at startup under
/// `DEBUG_MODE` — which wrote `ldap_bind_password`, `twilio_token`,
/// `github_client_secret` and `fcm_service_account_key` verbatim into syslog
/// and, when OTEL is configured, into a centrally-readable trace pipeline.
/// Seed-protection and exchange credentials were already kept out of this
/// struct for exactly that reason; these four had been left in.
///
/// Listing fields explicitly also makes the safe direction the default: a
/// secret added to `Config` later is invisible here until someone opts it in,
/// rather than being logged the moment it is introduced.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("public_endpoint", &self.public_endpoint)
            .field("service_address", &self.service_address)
            .field("debug_mode", &self.debug_mode)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("stellar_network", &self.stellar_network)
            .field("stellar_horizon_url", &self.stellar_horizon_url)
            .field("stellar_rpc_url", &self.stellar_rpc_url)
            .field("soroban_contract_id", &self.soroban_contract_id)
            .field("db_max_connections", &self.db_max_connections)
            .field("db_acquire_timeout_secs", &self.db_acquire_timeout_secs)
            .field("redis_pool_size", &self.redis_pool_size)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("http_client_timeout_secs", &self.http_client_timeout_secs)
            .field("session_cookie_secure", &self.session_cookie_secure)
            .field("admin_account_ids", &self.admin_account_ids.len())
            .field("seed_protection_backend", &self.seed_protection_backend)
            .field("sso_providers", &self.sso_providers.len())
            .field("okta_issuer_url", &self.okta_issuer_url)
            .field("github_auth_enabled", &self.github_auth_enabled)
            .field("worker_concurrency", &self.worker_concurrency)
            .field("otel_exporter_endpoint", &self.otel_exporter_endpoint)
            .field("exchange_poll_secs", &self.exchange_poll_secs)
            .field("reserve_account_id", &self.reserve_account_id)
            .field("reserve_usdc_issuer", &self.reserve_usdc_issuer)
            .field("reserve_usdc_code", &self.reserve_usdc_code)
            .field("reserve_deposit_ttl_secs", &self.reserve_deposit_ttl_secs)
            .field("reserve_watch_secs", &self.reserve_watch_secs)
            // Presence only — never the value.
            .field("twilio_sid", &secret_state(&self.twilio_sid))
            .field("twilio_token", &secret_state(&self.twilio_token))
            .field(
                "ldap_bind_password",
                &secret_state(&self.ldap_bind_password),
            )
            .field(
                "github_client_secret",
                &secret_state(&self.github_client_secret),
            )
            .field(
                "fcm_service_account_key",
                &secret_state(&self.fcm_service_account_key),
            )
            .finish_non_exhaustive()
    }
}

/// Hard policy gate: wildcard CORS is forbidden on pubnet. `Ok(())` otherwise.
pub fn validate_cors_policy(
    network: &StellarNetwork,
    cors_allowed_origins: &str,
) -> Result<(), String> {
    if *network == StellarNetwork::Pubnet && cors_allowed_origins.trim() == "*" {
        return Err(
            "CORS_ALLOWED_ORIGINS='*' is not allowed when STELLAR_NETWORK=pubnet; set explicit origins"
                .to_string(),
        );
    }
    Ok(())
}

/// Return the first environment variable that is set among `keys`, in order.
///
/// Used to accept OpenBao-native `BAO_*` names while falling back to the
/// historical `VAULT_*` names (OpenBao is an API-compatible Vault fork).
pub fn env_any(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| env::var(k).ok())
}

/// Load configuration from a JSON config file (if present) and environment variables.
/// Environment variables take precedence over config file values.
///
/// Config file path is read from `CONFIG_FILE` env var (default: `config.json`).
pub fn load_config() -> Config {
    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "config.json".to_string());
    let file_values: serde_json::Value = fs::read_to_string(&config_path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or(serde_json::Value::Null);

    let from_file = |key: &str| -> Option<String> {
        file_values
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let public_endpoint = env::var("PUBLIC_ENDPOINT")
        .ok()
        .or_else(|| from_file("public_endpoint"))
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let service_address = env::var("SERVICE_ADDRESS")
        .ok()
        .or_else(|| from_file("service_address"))
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    let log_file = env::var("LOG_FILE")
        .ok()
        .or_else(|| from_file("log_file"))
        .unwrap_or_else(|| "impala-bridge.log".to_string());

    let debug_mode = env::var("DEBUG_MODE")
        .ok()
        .or_else(|| from_file("debug_mode").map(|v| v.to_string()))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let twilio_sid = env::var("TWILIO_SID")
        .ok()
        .or_else(|| from_file("twilio_sid"));

    let twilio_token = env::var("TWILIO_TOKEN")
        .ok()
        .or_else(|| from_file("twilio_token"));

    let twilio_number = env::var("TWILIO_NUMBER")
        .ok()
        .or_else(|| from_file("twilio_number"));

    let ldap_url = env::var("LDAP_URL").ok().or_else(|| from_file("ldap_url"));

    let ldap_bind_dn = env::var("LDAP_BIND_DN")
        .ok()
        .or_else(|| from_file("ldap_bind_dn"));

    let ldap_bind_password = env::var("LDAP_BIND_PASSWORD")
        .ok()
        .or_else(|| from_file("ldap_bind_password"));

    let ldap_base_dn = env::var("LDAP_BASE_DN")
        .ok()
        .or_else(|| from_file("ldap_base_dn"));

    let ldap_search_filter = env::var("LDAP_SEARCH_FILTER")
        .ok()
        .or_else(|| from_file("ldap_search_filter"));

    let db_max_connections = env::var("DB_MAX_CONNECTIONS")
        .ok()
        .or_else(|| from_file("db_max_connections"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DB_MAX_CONNECTIONS);

    let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
        .ok()
        .or_else(|| from_file("cors_allowed_origins"))
        .unwrap_or_else(|| "*".to_string());

    let http_client_timeout_secs = env::var("HTTP_CLIENT_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("http_client_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_HTTP_CLIENT_TIMEOUT_SECS);

    // OIDC SSO providers (multi-provider registry). Declare the set via
    // `SSO_PROVIDERS=okta,auth0,duo` (or an `sso_providers` comma-list string
    // in the config file); each provider is then configured with prefixed
    // vars. For backward compatibility, if `SSO_PROVIDERS` is unset but
    // `OKTA_ISSUER_URL` is set we synthesize a single `okta` provider.
    let provider_var = |name: &str, key: &str| -> Option<String> {
        let env_key = format!("{}_{}", name.to_uppercase(), key);
        let file_key = format!("{}_{}", name.to_lowercase(), key.to_lowercase());
        env::var(&env_key).ok().or_else(|| from_file(&file_key))
    };

    let provider_names: Vec<String> = match env::var("SSO_PROVIDERS")
        .ok()
        .or_else(|| from_file("sso_providers"))
    {
        Some(list) if !list.trim().is_empty() => list
            .split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect(),
        _ => {
            if env::var("OKTA_ISSUER_URL")
                .ok()
                .or_else(|| from_file("okta_issuer_url"))
                .is_some()
            {
                vec!["okta".to_string()]
            } else {
                Vec::new()
            }
        }
    };

    let sso_providers = parse_sso_providers(&provider_names, provider_var);

    // Legacy single-provider Okta config, still consumed by the `/auth/okta`
    // cookie-capable flow (okta::init_okta_provider). The same variables also
    // feed the SSO registry's back-compat synthesis above.
    let okta_issuer_url = env::var("OKTA_ISSUER_URL")
        .ok()
        .or_else(|| from_file("okta_issuer_url"));

    let okta_client_id = env::var("OKTA_CLIENT_ID")
        .ok()
        .or_else(|| from_file("okta_client_id"));

    let okta_jwks_refresh_secs = env::var("OKTA_JWKS_REFRESH_SECS")
        .ok()
        .or_else(|| from_file("okta_jwks_refresh_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);

    let google_client_id = env::var("GOOGLE_CLIENT_ID")
        .ok()
        .or_else(|| from_file("google_client_id"));

    let google_jwks_refresh_secs = env::var("GOOGLE_JWKS_REFRESH_SECS")
        .ok()
        .or_else(|| from_file("google_jwks_refresh_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_JWKS_REFRESH_SECS);

    let github_auth_enabled = env::var("GITHUB_AUTH_ENABLED")
        .ok()
        .or_else(|| from_file("github_auth_enabled"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let github_client_id = env::var("GITHUB_CLIENT_ID")
        .ok()
        .or_else(|| from_file("github_client_id"));

    let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
        .ok()
        .or_else(|| from_file("github_client_secret"));

    let github_oauth_token_url = env::var("GITHUB_OAUTH_TOKEN_URL")
        .ok()
        .or_else(|| from_file("github_oauth_token_url"))
        .unwrap_or_else(|| crate::constants::DEFAULT_GITHUB_OAUTH_TOKEN_URL.to_string());

    let github_api_url = env::var("GITHUB_API_URL")
        .ok()
        .or_else(|| from_file("github_api_url"))
        .filter(|v| !v.is_empty()) // compose passes "" when unset
        .unwrap_or_else(|| crate::constants::DEFAULT_GITHUB_API_URL.to_string());

    let sqs_queue_url = env::var("SQS_QUEUE_URL")
        .ok()
        .or_else(|| from_file("sqs_queue_url"));

    let sns_topic_arn = env::var("SNS_TOPIC_ARN")
        .ok()
        .or_else(|| from_file("sns_topic_arn"));

    let worker_concurrency = env::var("WORKER_CONCURRENCY")
        .ok()
        .or_else(|| from_file("worker_concurrency"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_WORKER_CONCURRENCY);

    let sqs_wait_time_seconds = env::var("SQS_WAIT_TIME_SECONDS")
        .ok()
        .or_else(|| from_file("sqs_wait_time_seconds"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_SQS_WAIT_TIME_SECONDS);

    let sqs_visibility_timeout = env::var("SQS_VISIBILITY_TIMEOUT")
        .ok()
        .or_else(|| from_file("sqs_visibility_timeout"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_SQS_VISIBILITY_TIMEOUT);

    let ses_from_address = env::var("SES_FROM_ADDRESS")
        .ok()
        .or_else(|| from_file("ses_from_address"));

    let fcm_project_id = env::var("FCM_PROJECT_ID")
        .ok()
        .or_else(|| from_file("fcm_project_id"));

    let fcm_service_account_key = env::var("FCM_SERVICE_ACCOUNT_KEY")
        .ok()
        .or_else(|| from_file("fcm_service_account_key"));

    let otel_exporter_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .or_else(|| from_file("otel_exporter_endpoint"));

    let otel_service_name = env::var("OTEL_SERVICE_NAME")
        .ok()
        .or_else(|| from_file("otel_service_name"));

    let otel_environment = env::var("OTEL_ENVIRONMENT")
        .ok()
        .or_else(|| from_file("otel_environment"));

    let stellar_network_str = env::var("STELLAR_NETWORK")
        .ok()
        .or_else(|| from_file("stellar_network"))
        .unwrap_or_else(|| "testnet".to_string());
    let stellar_network = StellarNetwork::from_str(&stellar_network_str);

    let (default_horizon, default_rpc, default_passphrase) = match stellar_network {
        StellarNetwork::Testnet => (
            STELLAR_TESTNET_HORIZON_URL,
            STELLAR_TESTNET_RPC_URL,
            STELLAR_TESTNET_PASSPHRASE,
        ),
        StellarNetwork::Pubnet => (
            STELLAR_PUBNET_HORIZON_URL,
            STELLAR_PUBNET_RPC_URL,
            STELLAR_PUBNET_PASSPHRASE,
        ),
    };

    let stellar_horizon_url = env::var("STELLAR_HORIZON_URL")
        .ok()
        .or_else(|| from_file("stellar_horizon_url"))
        .unwrap_or_else(|| default_horizon.to_string());

    let stellar_rpc_url = env::var("STELLAR_RPC_URL")
        .ok()
        .or_else(|| from_file("stellar_rpc_url"))
        .unwrap_or_else(|| default_rpc.to_string());

    let stellar_network_passphrase = env::var("STELLAR_NETWORK_PASSPHRASE")
        .ok()
        .or_else(|| from_file("stellar_network_passphrase"))
        .unwrap_or_else(|| default_passphrase.to_string());

    let soroban_contract_id = env::var("SOROBAN_CONTRACT_ID")
        .ok()
        .or_else(|| from_file("soroban_contract_id"));

    let admin_account_ids = env::var("ADMIN_ACCOUNT_IDS")
        .ok()
        .or_else(|| from_file("admin_account_ids"))
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<HashSet<String>>()
        })
        .unwrap_or_default();

    let admin_webhook_max_attempts = env::var("ADMIN_WEBHOOK_MAX_ATTEMPTS")
        .ok()
        .or_else(|| from_file("admin_webhook_max_attempts"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_MAX_ATTEMPTS);

    let admin_webhook_disable_threshold = env::var("ADMIN_WEBHOOK_DISABLE_THRESHOLD")
        .ok()
        .or_else(|| from_file("admin_webhook_disable_threshold"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_DISABLE_THRESHOLD);

    let admin_webhook_poll_secs = env::var("ADMIN_WEBHOOK_POLL_SECS")
        .ok()
        .or_else(|| from_file("admin_webhook_poll_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ADMIN_WEBHOOK_POLL_SECS);

    let session_cookie_secure = env::var("SESSION_COOKIE_SECURE")
        .ok()
        .or_else(|| from_file("session_cookie_secure"))
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    // Defaults to false: first-touch registration on an existing account is a
    // way to claim one, so it has to be turned on deliberately.
    let allow_open_registration = env::var("ALLOW_OPEN_REGISTRATION")
        .ok()
        .or_else(|| from_file("allow_open_registration"))
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let redis_pool_size = env::var("REDIS_POOL_SIZE")
        .ok()
        .or_else(|| from_file("redis_pool_size"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DEFAULT_REDIS_POOL_SIZE);

    let request_timeout_secs = env::var("REQUEST_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("request_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::REQUEST_TIMEOUT_SECS);

    let db_acquire_timeout_secs = env::var("DB_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .or_else(|| from_file("db_acquire_timeout_secs"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(crate::constants::DB_ACQUIRE_TIMEOUT_SECS);

    let seed_protection_backend = env::var("SEED_PROTECTION_BACKEND")
        .ok()
        .or_else(|| from_file("seed_protection_backend"))
        .unwrap_or_else(|| "none".to_string());

    let kms_seed_key_id = env::var("KMS_SEED_KEY_ID")
        .ok()
        .or_else(|| from_file("kms_seed_key_id"));

    // Vault/OpenBao: accept the OpenBao-native name first, then the Vault name,
    // then the config file. The internal field names stay `vault_*`.
    let vault_addr = env_any(&["BAO_ADDR", "VAULT_ADDR"]).or_else(|| from_file("vault_addr"));

    let vault_transit_key = env_any(&["BAO_TRANSIT_KEY", "VAULT_TRANSIT_KEY"])
        .or_else(|| from_file("vault_transit_key"));

    // Exchange providers. Secrets (OWLPAY_API_KEY, OWLPAY_WEBHOOK_SECRET,
    // CHANGELLY_API_KEY, CHANGELLY_PRIVATE_KEY, CHANGELLY_FIAT_API_KEY, …) are
    // deliberately NOT loaded here — the provider init fns read them straight
    // from the environment (see the seed-protection rule above).
    // The empty-string filter runs BEFORE the file fallback: compose always
    // injects `VAR: ${VAR:-}`, and a set-but-empty env var must fall through
    // to CONFIG_FILE rather than shadow it (docker-compose.yml warns about
    // exactly this shadowing for the SSO bootstrap config).
    let owlpay_api_url = env::var("OWLPAY_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("owlpay_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_OWLPAY_API_URL.to_string());

    let changelly_api_url = env::var("CHANGELLY_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("changelly_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CHANGELLY_API_URL.to_string());

    let changelly_fiat_api_url = env::var("CHANGELLY_FIAT_API_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("changelly_fiat_api_url"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CHANGELLY_FIAT_API_URL.to_string());

    // Clamped to >= 1s: a zero tick would spin the reconcile loop against the
    // database with no delay (poll_backoff_secs applies the same 1s floor).
    let exchange_poll_secs = env::var("EXCHANGE_POLL_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("exchange_poll_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_EXCHANGE_POLL_SECS)
        .max(1);

    let reserve_account_id = env::var("RESERVE_ACCOUNT_ID")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_account_id"))
        .filter(|v| !v.is_empty());

    let reserve_usdc_issuer = env::var("RESERVE_USDC_ISSUER")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdc_issuer"))
        .filter(|v| !v.is_empty());

    let reserve_usdc_code = env::var("RESERVE_USDC_CODE")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_usdc_code"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "USDC".to_string());

    // Clamped: too short races real deposits, too long hands out a free
    // price option on the pool (the quote is honored for the whole window).
    let reserve_deposit_ttl_secs = env::var("RESERVE_DEPOSIT_TTL_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_deposit_ttl_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESERVE_DEPOSIT_TTL_SECS)
        .clamp(RESERVE_DEPOSIT_TTL_MIN_SECS, RESERVE_DEPOSIT_TTL_MAX_SECS);

    let reserve_watch_secs = env::var("RESERVE_WATCH_SECS")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| from_file("reserve_watch_secs"))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RESERVE_WATCH_SECS)
        .max(5);

    Config {
        public_endpoint,
        service_address,
        log_file,
        debug_mode,
        twilio_sid,
        twilio_token,
        twilio_number,
        ldap_url,
        ldap_bind_dn,
        ldap_bind_password,
        ldap_base_dn,
        ldap_search_filter,
        db_max_connections,
        cors_allowed_origins,
        http_client_timeout_secs,
        okta_issuer_url,
        okta_client_id,
        okta_jwks_refresh_secs,
        google_client_id,
        google_jwks_refresh_secs,
        github_auth_enabled,
        github_api_url,
        github_client_id,
        github_client_secret,
        github_oauth_token_url,
        sso_providers,
        sqs_queue_url,
        sns_topic_arn,
        worker_concurrency,
        sqs_wait_time_seconds,
        sqs_visibility_timeout,
        ses_from_address,
        fcm_project_id,
        fcm_service_account_key,
        otel_exporter_endpoint,
        otel_service_name,
        otel_environment,
        stellar_network,
        stellar_horizon_url,
        stellar_rpc_url,
        stellar_network_passphrase,
        soroban_contract_id,
        admin_account_ids,
        admin_webhook_max_attempts,
        admin_webhook_disable_threshold,
        admin_webhook_poll_secs,
        session_cookie_secure,
        allow_open_registration,
        redis_pool_size,
        request_timeout_secs,
        db_acquire_timeout_secs,
        seed_protection_backend,
        kms_seed_key_id,
        vault_addr,
        vault_transit_key,
        owlpay_api_url,
        changelly_api_url,
        changelly_fiat_api_url,
        exchange_poll_secs,
        reserve_account_id,
        reserve_usdc_issuer,
        reserve_usdc_code,
        reserve_deposit_ttl_secs,
        reserve_watch_secs,
    }
}

/// Minimal `Config` for unit tests (all integrations off, testnet defaults).
/// Tests mutate only the fields they exercise.
#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config {
        public_endpoint: String::new(),
        service_address: String::new(),
        log_file: String::new(),
        debug_mode: false,
        twilio_sid: None,
        twilio_token: None,
        twilio_number: None,
        ldap_url: None,
        ldap_bind_dn: None,
        ldap_bind_password: None,
        ldap_base_dn: None,
        ldap_search_filter: None,
        db_max_connections: 5,
        cors_allowed_origins: String::new(),
        http_client_timeout_secs: 30,
        okta_issuer_url: None,
        okta_client_id: None,
        okta_jwks_refresh_secs: DEFAULT_JWKS_REFRESH_SECS,
        google_client_id: None,
        google_jwks_refresh_secs: DEFAULT_JWKS_REFRESH_SECS,
        github_auth_enabled: false,
        github_api_url: DEFAULT_GITHUB_API_URL.to_string(),
        github_client_id: None,
        github_client_secret: None,
        github_oauth_token_url: DEFAULT_GITHUB_OAUTH_TOKEN_URL.to_string(),
        sso_providers: Vec::new(),
        sqs_queue_url: None,
        sns_topic_arn: None,
        worker_concurrency: 10,
        sqs_wait_time_seconds: 20,
        sqs_visibility_timeout: 300,
        ses_from_address: None,
        fcm_project_id: None,
        fcm_service_account_key: None,
        otel_exporter_endpoint: None,
        otel_service_name: None,
        otel_environment: None,
        stellar_network: StellarNetwork::Testnet,
        stellar_horizon_url: "https://horizon-testnet.stellar.org".to_string(),
        stellar_rpc_url: "https://soroban-testnet.stellar.org".to_string(),
        stellar_network_passphrase: "Test SDF Network ; September 2015".to_string(),
        soroban_contract_id: None,
        admin_account_ids: HashSet::new(),
        admin_webhook_max_attempts: DEFAULT_ADMIN_WEBHOOK_MAX_ATTEMPTS,
        admin_webhook_disable_threshold: DEFAULT_ADMIN_WEBHOOK_DISABLE_THRESHOLD,
        admin_webhook_poll_secs: DEFAULT_ADMIN_WEBHOOK_POLL_SECS,
        session_cookie_secure: false,
        allow_open_registration: false,
        redis_pool_size: DEFAULT_REDIS_POOL_SIZE,
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
        db_acquire_timeout_secs: DB_ACQUIRE_TIMEOUT_SECS,
        seed_protection_backend: "none".to_string(),
        kms_seed_key_id: None,
        vault_addr: None,
        vault_transit_key: None,
        owlpay_api_url: DEFAULT_OWLPAY_API_URL.to_string(),
        changelly_api_url: DEFAULT_CHANGELLY_API_URL.to_string(),
        changelly_fiat_api_url: DEFAULT_CHANGELLY_FIAT_API_URL.to_string(),
        exchange_poll_secs: DEFAULT_EXCHANGE_POLL_SECS,
        reserve_account_id: None,
        reserve_usdc_issuer: None,
        reserve_usdc_code: "USDC".to_string(),
        reserve_deposit_ttl_secs: DEFAULT_RESERVE_DEPOSIT_TTL_SECS,
        reserve_watch_secs: DEFAULT_RESERVE_WATCH_SECS,
    }
}

impl Config {
    pub fn stellar_config(&self) -> StellarConfig {
        StellarConfig {
            network: self.stellar_network.clone(),
            horizon_url: self.stellar_horizon_url.clone(),
            rpc_url: self.stellar_rpc_url.clone(),
            network_passphrase: self.stellar_network_passphrase.clone(),
            contract_id: self.soroban_contract_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `main.rs` logs `Config: {:?}` at startup under DEBUG_MODE, so the
    /// `Debug` impl is a log sink for anything it prints. Pin that no secret
    /// value can reach it — a derived `Debug` used to print all of these.
    #[test]
    fn debug_never_prints_secret_values() {
        let mut config = test_config();
        config.twilio_sid = Some("AC-sid-must-not-appear".to_string());
        config.twilio_token = Some("twilio-token-must-not-appear".to_string());
        config.ldap_bind_password = Some("ldap-password-must-not-appear".to_string());
        config.github_client_secret = Some("gh-secret-must-not-appear".to_string());
        config.fcm_service_account_key = Some("{\"private_key\":\"must-not-appear\"}".to_string());

        let rendered = format!("{:?}", config);

        for secret in [
            "AC-sid-must-not-appear",
            "twilio-token-must-not-appear",
            "ldap-password-must-not-appear",
            "gh-secret-must-not-appear",
            "must-not-appear",
        ] {
            assert!(
                !rendered.contains(secret),
                "Config Debug leaked a secret value: {rendered}"
            );
        }

        // Presence is still reported, so the log stays operationally useful.
        assert!(rendered.contains("<set:redacted>"));
        assert!(rendered.contains("service_address"));
    }

    #[test]
    fn debug_reports_absent_secrets_as_unset() {
        let mut config = test_config();
        config.twilio_token = None;
        config.ldap_bind_password = None;
        let rendered = format!("{:?}", config);
        assert!(rendered.contains("<unset>"), "{rendered}");
    }

    #[test]
    fn cors_wildcard_rejected_on_pubnet() {
        assert!(validate_cors_policy(&StellarNetwork::Pubnet, "*").is_err());
        assert!(validate_cors_policy(&StellarNetwork::Pubnet, "  *  ").is_err());
    }

    #[test]
    fn cors_wildcard_allowed_on_testnet() {
        assert!(validate_cors_policy(&StellarNetwork::Testnet, "*").is_ok());
    }

    #[test]
    fn cors_explicit_origins_allowed_on_pubnet() {
        assert!(
            validate_cors_policy(&StellarNetwork::Pubnet, "https://admin.impala.example.com")
                .is_ok()
        );
    }

    #[test]
    fn test_stellar_network_from_str_testnet() {
        assert_eq!(StellarNetwork::from_str("testnet"), StellarNetwork::Testnet);
    }

    #[test]
    fn test_stellar_network_from_str_pubnet() {
        assert_eq!(StellarNetwork::from_str("pubnet"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_mainnet() {
        assert_eq!(StellarNetwork::from_str("mainnet"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_public() {
        assert_eq!(StellarNetwork::from_str("public"), StellarNetwork::Pubnet);
    }

    #[test]
    fn test_stellar_network_from_str_unknown_defaults_testnet() {
        assert_eq!(
            StellarNetwork::from_str("anything"),
            StellarNetwork::Testnet
        );
    }

    #[test]
    fn test_stellar_network_from_str_case_insensitive() {
        assert_eq!(StellarNetwork::from_str("PUBNET"), StellarNetwork::Pubnet);
        assert_eq!(StellarNetwork::from_str("Testnet"), StellarNetwork::Testnet);
    }

    #[test]
    fn test_stellar_network_as_str_testnet() {
        assert_eq!(StellarNetwork::Testnet.as_str(), "testnet");
    }

    #[test]
    fn test_stellar_network_as_str_pubnet() {
        assert_eq!(StellarNetwork::Pubnet.as_str(), "pubnet");
    }

    #[test]
    fn test_token_kind_from_str() {
        assert_eq!(TokenKind::from_str_opt("id"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("id_token"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("ID"), TokenKind::Id);
        assert_eq!(TokenKind::from_str_opt("access"), TokenKind::Access);
        assert_eq!(TokenKind::from_str_opt(""), TokenKind::Access);
        assert_eq!(TokenKind::from_str_opt("anything"), TokenKind::Access);
    }

    #[test]
    fn test_stellar_config_from_config() {
        // Verify stellar_config() correctly copies fields
        // Note: we can't easily test load_config() since it reads env vars,
        // but we can test the Config -> StellarConfig conversion
        let mut config = test_config();
        config.soroban_contract_id = Some("CONTRACT123".to_string());
        let sc = config.stellar_config();
        assert_eq!(sc.network, StellarNetwork::Testnet);
        assert_eq!(sc.horizon_url, "https://horizon-testnet.stellar.org");
        assert_eq!(sc.rpc_url, "https://soroban-testnet.stellar.org");
        assert_eq!(sc.contract_id, Some("CONTRACT123".to_string()));
    }

    /// Build a `provider_var`-shaped lookup from `("NAME", "KEY", "value")`
    /// triples, mirroring the env-var naming used by `load_config`.
    fn lookup<'a>(
        entries: &'a [(&'a str, &'a str, &'a str)],
    ) -> impl Fn(&str, &str) -> Option<String> + 'a {
        move |name: &str, key: &str| {
            entries
                .iter()
                .find(|(n, k, _)| n.eq_ignore_ascii_case(name) && *k == key)
                .map(|(_, _, v)| v.to_string())
        }
    }

    #[test]
    fn sso_provider_parses_internal_issuer_and_allow_http() {
        let names = vec!["openbao".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                (
                    "openbao",
                    "ISSUER_URL",
                    "http://localhost:8200/v1/identity/oidc/provider/openbao",
                ),
                ("openbao", "CLIENT_ID", "generated-id"),
                (
                    "openbao",
                    "INTERNAL_ISSUER_URL",
                    "http://openbao:8200/v1/identity/oidc/provider/openbao",
                ),
                ("openbao", "ALLOW_HTTP", "true"),
                ("openbao", "TOKEN_KIND", "id"),
            ]),
        );
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        assert_eq!(
            p.internal_issuer_url.as_deref(),
            Some("http://openbao:8200/v1/identity/oidc/provider/openbao")
        );
        assert!(p.allow_http);
        assert_eq!(p.token_kind, TokenKind::Id);
        assert_eq!(p.audience, "generated-id");
    }

    #[test]
    fn sso_provider_new_keys_default_backward_compatible() {
        let names = vec!["okta".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                (
                    "okta",
                    "ISSUER_URL",
                    "https://example.okta.com/oauth2/default",
                ),
                ("okta", "CLIENT_ID", "abc123"),
            ]),
        );
        assert_eq!(providers.len(), 1);
        let p = &providers[0];
        assert_eq!(p.internal_issuer_url, None);
        assert!(!p.allow_http);
        assert_eq!(p.audience, "abc123");
        assert_eq!(p.token_kind, TokenKind::Access);
        assert_eq!(
            p.jwks_refresh_secs,
            crate::constants::DEFAULT_JWKS_REFRESH_SECS
        );
    }

    #[test]
    fn sso_provider_allow_http_accepts_true_and_1_only() {
        for (value, expected) in [
            ("true", true),
            ("1", true),
            ("false", false),
            ("yes", false),
            ("TRUE", false),
            ("", false),
        ] {
            let names = vec!["dev".to_string()];
            let providers = parse_sso_providers(
                &names,
                lookup(&[
                    ("dev", "ISSUER_URL", "https://idp.example.com"),
                    ("dev", "ALLOW_HTTP", value),
                ]),
            );
            assert_eq!(providers[0].allow_http, expected, "value {value:?}");
        }
    }

    #[test]
    fn sso_provider_blank_internal_issuer_treated_as_unset() {
        let names = vec!["dev".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[
                ("dev", "ISSUER_URL", "https://idp.example.com"),
                ("dev", "INTERNAL_ISSUER_URL", "   "),
            ]),
        );
        assert_eq!(providers[0].internal_issuer_url, None);
    }

    #[test]
    fn sso_provider_missing_issuer_drops_provider() {
        let names = vec!["ghost".to_string(), "real".to_string()];
        let providers = parse_sso_providers(
            &names,
            lookup(&[("real", "ISSUER_URL", "https://idp.example.com")]),
        );
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "real");
    }
}
