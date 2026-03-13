/// Minimum password length for authentication.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum length for name fields (first_name, last_name, etc.).
pub const MAX_NAME_LENGTH: usize = 64;

/// Refresh token time-to-live: 14 days in seconds.
pub const REFRESH_TOKEN_TTL_SECS: usize = 14 * 24 * 3600;

/// Temporal token time-to-live: 1 hour in seconds.
pub const TEMPORAL_TOKEN_TTL_SECS: usize = 3600;

/// Default database connection pool size.
pub const DEFAULT_DB_MAX_CONNECTIONS: u32 = 20;

/// Database pool: acquire timeout in seconds.
pub const DB_ACQUIRE_TIMEOUT_SECS: u64 = 5;

/// Database pool: idle connection timeout in seconds (10 minutes).
pub const DB_IDLE_TIMEOUT_SECS: u64 = 600;

/// Database pool: maximum connection lifetime in seconds (30 minutes).
pub const DB_MAX_LIFETIME_SECS: u64 = 1800;

/// Default Redis connection pool size.
pub const DEFAULT_REDIS_POOL_SIZE: usize = 16;

/// Request timeout in seconds (applied globally via middleware).
pub const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Rate limit: maximum requests per window.
pub const RATE_LIMIT_MAX_REQUESTS: u64 = 10;

/// Rate limit: window duration in seconds.
pub const RATE_LIMIT_WINDOW_SECS: usize = 60;

/// Account lockout: number of failed login attempts before lockout.
pub const LOCKOUT_THRESHOLD: u64 = 5;

/// Account lockout: duration in seconds (15 minutes).
pub const LOCKOUT_DURATION_SECS: usize = 15 * 60;

/// Maximum Stellar account ID length.
pub const STELLAR_ACCOUNT_ID_LENGTH: usize = 56;

/// Maximum SSE buffer size in bytes (1 MB).
pub const MAX_SSE_BUFFER_SIZE: usize = 1_048_576;

/// Cron sync polling interval in seconds.
pub const CRON_SYNC_INTERVAL_SECS: u64 = 60;

/// Default HTTP client timeout in seconds.
pub const DEFAULT_HTTP_CLIENT_TIMEOUT_SECS: u64 = 30;

/// Maximum email address length per RFC 5321.
pub const MAX_EMAIL_LENGTH: usize = 254;

/// Token type string for refresh tokens.
pub const TOKEN_TYPE_REFRESH: &str = "refresh";

/// Token type string for temporal tokens.
pub const TOKEN_TYPE_TEMPORAL: &str = "temporal";

/// Default JWKS refresh interval in seconds (1 hour).
pub const DEFAULT_JWKS_REFRESH_SECS: u64 = 3600;

/// Auth provider identifier for Okta users.
pub const AUTH_PROVIDER_OKTA: &str = "okta";

/// Auth provider identifier for local (password-based) users.
pub const AUTH_PROVIDER_LOCAL: &str = "local";

/// Minimum length for JWT_SECRET (256 bits).
pub const JWT_SECRET_MIN_LENGTH: usize = 32;

/// JWT issuer claim value for locally-issued tokens.
pub const JWT_ISSUER: &str = "impala-bridge";

/// Default worker concurrency (max in-flight SQS messages).
pub const DEFAULT_WORKER_CONCURRENCY: usize = 10;

/// Default SQS long-poll wait time in seconds.
pub const DEFAULT_SQS_WAIT_TIME_SECONDS: i32 = 20;

/// Default SQS visibility timeout in seconds (5 minutes).
pub const DEFAULT_SQS_VISIBILITY_TIMEOUT: i32 = 300;

/// Stellar testnet Horizon API URL.
pub const STELLAR_TESTNET_HORIZON_URL: &str = "https://horizon-testnet.stellar.org";

/// Stellar testnet Soroban RPC URL.
pub const STELLAR_TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Stellar testnet network passphrase.
pub const STELLAR_TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Stellar public network (mainnet) Horizon API URL.
pub const STELLAR_PUBNET_HORIZON_URL: &str = "https://horizon.stellar.org";

/// Stellar public network (mainnet) Soroban RPC URL.
pub const STELLAR_PUBNET_RPC_URL: &str = "https://soroban-rpc.stellar.org";

/// Stellar public network (mainnet) passphrase.
pub const STELLAR_PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
