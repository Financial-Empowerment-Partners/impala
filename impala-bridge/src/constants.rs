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

/// Per-account API rate limit on authenticated endpoints (requests per window).
pub const API_RATE_LIMIT_MAX_REQUESTS: u64 = 100;

/// Per-account API rate limit window in seconds.
pub const API_RATE_LIMIT_WINDOW_SECS: usize = 60;

/// Cron sync: max callback rows fetched per tick.
pub const CRON_SYNC_BATCH_LIMIT: i64 = 500;

/// Cron sync: max concurrent in-flight callback deliveries.
pub const CRON_SYNC_CONCURRENCY: usize = 10;

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

/// SSE stream: max seconds without receiving any bytes before the
/// connection is considered stale and torn down for reconnect.
/// Horizon emits a ledger roughly every 5–6 seconds, so 90s of silence
/// means the connection is dead even if TCP hasn't noticed.
pub const SSE_READ_TIMEOUT_SECS: u64 = 90;

/// Payala TCP listener: max seconds an accepted connection may stay
/// silent before it is closed (prevents idle-socket leaks).
pub const PAYALA_READ_TIMEOUT_SECS: u64 = 300;

/// Stream supervisor: initial reconnect backoff in seconds.
pub const STREAM_BACKOFF_INITIAL_SECS: u64 = 1;

/// Stream supervisor: maximum reconnect backoff in seconds.
pub const STREAM_BACKOFF_MAX_SECS: u64 = 300;

/// Stream supervisor: a connection that stayed healthy for at least this
/// long resets the exponential backoff to its initial value.
pub const STREAM_HEALTHY_RESET_SECS: u64 = 60;

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

/// Auth provider identifier for Google users.
pub const AUTH_PROVIDER_GOOGLE: &str = "google";

/// Auth provider identifier for GitHub users.
pub const AUTH_PROVIDER_GITHUB: &str = "github";

/// Auth provider identifier for local (password-based) users.
pub const AUTH_PROVIDER_LOCAL: &str = "local";

/// Google ID-token JWKS endpoint (RS256 signing keys).
pub const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Accepted `iss` values for Google ID tokens. Google emits both forms.
pub const GOOGLE_TOKEN_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

/// Default GitHub REST API base URL (override with GITHUB_API_URL for GHES).
pub const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// Default GitHub OAuth token endpoint for the server-side code exchange
/// (override with GITHUB_OAUTH_TOKEN_URL for GHES or tests).
pub const DEFAULT_GITHUB_OAUTH_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// Card-auth signed-message domain prefix (pinned cross-stream contract).
///
/// ASCII "IMPALA-AUTH:" — 12 bytes: 49 4D 50 41 4C 41 2D 41 55 54 48 3A.
/// Must match `AUTH_DOMAIN_TAG` in
/// `impala-card/applet/src/jvmMain/java/com/impala/applet/ImpalaApplet.java`.
/// The applet signs ECDSA-SHA256 (secp256r1, ASN.1 DER) over exactly
/// `CARD_AUTH_DOMAIN_PREFIX || accountId(16, RFC-4122 big-endian) ||
/// challenge(8..=64)`, so an auth signature can never be replayed as a
/// transfer signature.
pub const CARD_AUTH_DOMAIN_PREFIX: &[u8; 12] = b"IMPALA-AUTH:";

/// Card-auth challenge size in raw bytes (64 hex chars on the wire).
pub const CARD_CHALLENGE_BYTES: usize = 32;

/// Card-auth challenge time-to-live in seconds (also `expires_in` on the wire).
pub const CARD_CHALLENGE_TTL_SECS: usize = 60;

/// Maximum DER-encoded ECDSA P-256 signature length in bytes (144 hex chars).
pub const CARD_SIGNATURE_MAX_BYTES: usize = 72;

/// Minimum length for JWT_SECRET (256 bits).
pub const JWT_SECRET_MIN_LENGTH: usize = 32;

/// JWT issuer claim value for locally-issued tokens.
pub const JWT_ISSUER: &str = "impala-bridge";

/// JWT audience claim value, stamped at issuance and validated on decode.
pub const JWT_AUDIENCE: &str = "impala-bridge-api";

/// Length of the `kid` header fingerprint (hex chars of sha256(secret)).
pub const JWT_KID_LEN: usize = 16;

// ── Browser cookie sessions ────────────────────────────────────────────

/// Session id entropy in raw bytes (hex-encoded on the wire).
pub const SESSION_ID_BYTES: usize = 32;

/// CSRF synchronizer-token entropy in raw bytes (hex-encoded on the wire).
pub const CSRF_TOKEN_BYTES: usize = 32;

/// Session sliding idle TTL in seconds (30 minutes).
pub const SESSION_IDLE_TTL_SECS: usize = 30 * 60;

/// Session absolute lifetime cap in seconds (12 hours).
pub const SESSION_ABSOLUTE_TTL_SECS: usize = 12 * 3600;

/// Session cookie name when `SESSION_COOKIE_SECURE` is on (the `__Host-`
/// prefix requires `Secure` + `Path=/` and pins the cookie to the host).
pub const SESSION_COOKIE_NAME: &str = "__Host-impala_session";

/// Session cookie name for plain-HTTP local development.
pub const SESSION_COOKIE_NAME_INSECURE: &str = "impala_session";

/// Header carrying the CSRF synchronizer token on cookie-authenticated
/// unsafe-method requests.
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

/// Default worker concurrency (max in-flight SQS messages).
pub const DEFAULT_WORKER_CONCURRENCY: usize = 10;

/// Default SQS long-poll wait time in seconds.
pub const DEFAULT_SQS_WAIT_TIME_SECONDS: i32 = 20;

/// Default SQS visibility timeout in seconds (5 minutes).
pub const DEFAULT_SQS_VISIBILITY_TIMEOUT: i32 = 300;

/// Admin webhook: max delivery attempts before a delivery is marked failed.
pub const DEFAULT_ADMIN_WEBHOOK_MAX_ATTEMPTS: u32 = 6;

/// Admin webhook: consecutive failures before a webhook is auto-disabled.
pub const DEFAULT_ADMIN_WEBHOOK_DISABLE_THRESHOLD: i64 = 10;

/// Admin webhook: delivery worker poll interval in seconds.
pub const DEFAULT_ADMIN_WEBHOOK_POLL_SECS: u64 = 5;

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
