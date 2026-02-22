/// Minimum password length for authentication.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum length for name fields (first_name, last_name, etc.).
pub const MAX_NAME_LENGTH: usize = 64;

/// Refresh token time-to-live: 30 days in seconds.
pub const REFRESH_TOKEN_TTL_SECS: usize = 30 * 24 * 3600;

/// Temporal token time-to-live: 1 hour in seconds.
pub const TEMPORAL_TOKEN_TTL_SECS: usize = 3600;

/// Default database connection pool size.
pub const DEFAULT_DB_MAX_CONNECTIONS: u32 = 5;

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
