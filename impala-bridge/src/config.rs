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
/// `sso_providers` config-file array) and each is configured through prefixed
/// env vars: `{NAME}_ISSUER_URL`, `{NAME}_CLIENT_ID`, `{NAME}_AUDIENCE`,
/// `{NAME}_JWKS_REFRESH_SECS`, `{NAME}_TOKEN_KIND`.
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
}

#[derive(Debug, Clone)]
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
    // `SSO_PROVIDERS=okta,auth0,duo` (or a `sso_providers` array in the config
    // file); each provider is then configured with prefixed vars. For backward
    // compatibility, if `SSO_PROVIDERS` is unset but `OKTA_ISSUER_URL` is set we
    // synthesize a single `okta` provider.
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

    let sso_providers: Vec<ProviderConfig> = provider_names
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
            Some(ProviderConfig {
                name: name.clone(),
                issuer_url,
                client_id,
                audience,
                jwks_refresh_secs,
                token_kind,
            })
        })
        .collect();

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
        redis_pool_size,
        request_timeout_secs,
        db_acquire_timeout_secs,
        seed_protection_backend,
        kms_seed_key_id,
        vault_addr,
        vault_transit_key,
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
        redis_pool_size: DEFAULT_REDIS_POOL_SIZE,
        request_timeout_secs: REQUEST_TIMEOUT_SECS,
        db_acquire_timeout_secs: DB_ACQUIRE_TIMEOUT_SECS,
        seed_protection_backend: "none".to_string(),
        kms_seed_key_id: None,
        vault_addr: None,
        vault_transit_key: None,
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
}
