/// Minimum password length for authentication.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum length for name fields (first_name, last_name, etc.).
pub const MAX_NAME_LENGTH: usize = 64;

/// Refresh token time-to-live: 14 days in seconds.
///
/// This value is the source of truth for the refresh-token lifetime. Any
/// documentation (README, SECURITY.md, client SDK kdoc) that quotes a
/// different duration is stale — update the docs, not this constant,
/// unless you mean to change the actual TTL. The compile-time assert below
/// prevents silent drift of the multiplier.
pub const REFRESH_TOKEN_TTL_SECS: usize = 14 * 24 * 3600;
const _: () = assert!(REFRESH_TOKEN_TTL_SECS == 1_209_600);

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
#[allow(dead_code)] // documents the default; pool size is configured elsewhere
pub const DEFAULT_REDIS_POOL_SIZE: usize = 16;

/// Request timeout in seconds (applied globally via middleware).
pub const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Maximum time (seconds) to wait for in-flight requests to drain after a
/// SIGTERM / Ctrl-C. If exceeded the process force-exits so the container
/// orchestrator doesn't have to SIGKILL us. Must fit inside the typical ECS
/// / Kubernetes stop timeout (30s default), so keep this below 30.
pub const SHUTDOWN_DRAIN_DEADLINE_SECS: u64 = 25;

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

/// Rate limit for the custodial sign+submit endpoint: max requests per window.
/// Deliberately tighter than the default `RATE_LIMIT_MAX_REQUESTS` because each
/// call decrypts a seed and moves real funds.
pub const SIGN_RATE_LIMIT_MAX_REQUESTS: u64 = 5;

/// Rate-limit window (seconds) for the custodial sign+submit endpoint.
pub const SIGN_RATE_LIMIT_WINDOW_SECS: usize = 60;

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

// Canonical OIDC provider identifiers. Provider names are config-driven
// (`SSO_PROVIDERS`), so the SSO handler binds the configured name directly;
// these constants document the well-known vocabulary and are referenced by the
// Duo 2FA path and docs.
/// Auth provider identifier for Okta users.
#[allow(dead_code)]
pub const AUTH_PROVIDER_OKTA: &str = "okta";

/// Auth provider identifier for Google users.
pub const AUTH_PROVIDER_GOOGLE: &str = "google";

/// Auth provider identifier for GitHub users.
pub const AUTH_PROVIDER_GITHUB: &str = "github";

/// Auth provider identifier for Auth0 users.
#[allow(dead_code)]
pub const AUTH_PROVIDER_AUTH0: &str = "auth0";

/// Auth provider identifier for Duo (SSO) users.
#[allow(dead_code)]
pub const AUTH_PROVIDER_DUO: &str = "duo";

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

/// Account role: read-only access. Default for any account without an explicit role.
pub const ROLE_VIEW_ONLY: &str = "view-only";

/// Account role: device — can create transactions and manage cards.
pub const ROLE_DEVICE: &str = "device";

/// Account role: token — can manage accounts and MFA.
pub const ROLE_TOKEN: &str = "token";

/// Account role: admin — full access including role management and the admin console.
pub const ROLE_ADMIN: &str = "admin";

/// All valid account roles. The hyphenated `view-only` mirrors the UI's role keys
/// (`impala-ui/html/js/roles.js`) so the UI can read the role straight from the JWT.
pub const ALL_ROLES: &[&str] = &[ROLE_VIEW_ONLY, ROLE_DEVICE, ROLE_TOKEN, ROLE_ADMIN];

/// Valid transaction review statuses (mirrors the `chk_review_status` DB CHECK).
pub const VALID_REVIEW_STATUSES: &[&str] = &["unreviewed", "cleared", "flagged", "escalated"];

/// Payala sync mode: batches are aggregated into a single per-currency
/// reserve-balance update.
pub const SYNC_MODE_RESERVE: &str = "reserve";

/// Payala sync mode: every batch item is mirrored 1:1 as a `transaction` row.
pub const SYNC_MODE_MIRROR: &str = "mirror";

/// Valid per-account Payala sync modes (mirrors the `chk_impala_account_sync_mode` DB CHECK).
pub const VALID_SYNC_MODES: &[&str] = &[SYNC_MODE_RESERVE, SYNC_MODE_MIRROR];

/// Max items per `POST /sync/payala` batch. The effective ceilings are the 30s
/// request timeout and the 60s per-statement timeout, not the 1 MB body limit.
pub const MAX_SYNC_BATCH_ITEMS: usize = 500;

/// Max distinct currencies per `POST /sync/payala` batch (bounds junk reserve rows).
pub const MAX_SYNC_BATCH_CURRENCIES: usize = 10;

/// Max length for a Payala currency code (mirrors the VARCHAR(16) columns).
pub const MAX_PAYALA_CURRENCY_LENGTH: usize = 16;

/// `transaction.origin` for rows created via `POST /transaction`. Applied by
/// the column's DB default rather than bound in an INSERT; documents the
/// vocabulary alongside `TX_ORIGIN_PAYALA_SYNC`.
#[allow(dead_code)]
pub const TX_ORIGIN_MANUAL: &str = "manual";

/// `transaction.origin` for rows created by mirror-mode Payala sync.
/// Server-set only — never accepted from a request body.
pub const TX_ORIGIN_PAYALA_SYNC: &str = "payala_sync";

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

// ── Exchange (OwlPay / Changelly) ──────────────────────────────────────

/// Exchange provider identifier: OwlPay Harbor (fiat<->USDC on/off-ramp).
pub const EXCHANGE_PROVIDER_OWLPAY: &str = "owlpay";

/// Exchange provider identifier: Changelly Exchange API v2 (crypto->crypto
/// swaps, e.g. XLM -> usdcxlm).
pub const EXCHANGE_PROVIDER_CHANGELLY_CRYPTO: &str = "changelly_crypto";

/// Exchange provider identifier: Changelly Fiat API (fiat<->crypto through
/// aggregated on/off-ramp providers such as MoonPay).
pub const EXCHANGE_PROVIDER_CHANGELLY_FIAT: &str = "changelly_fiat";

/// Valid exchange providers (mirrors the `chk_exchange_order_provider` DB CHECK).
pub const VALID_EXCHANGE_PROVIDERS: &[&str] = &[
    EXCHANGE_PROVIDER_OWLPAY,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
    EXCHANGE_PROVIDER_CHANGELLY_FIAT,
];

/// Exchange direction: fiat in, crypto out (on-ramp).
pub const EXCHANGE_DIRECTION_FIAT_TO_CRYPTO: &str = "fiat_to_crypto";

/// Exchange direction: crypto in, fiat out (off-ramp).
pub const EXCHANGE_DIRECTION_CRYPTO_TO_FIAT: &str = "crypto_to_fiat";

/// Exchange direction: crypto in, crypto out (swap).
pub const EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO: &str = "crypto_to_crypto";

/// Valid exchange directions (mirrors the `chk_exchange_order_direction` DB CHECK).
pub const VALID_EXCHANGE_DIRECTIONS: &[&str] = &[
    EXCHANGE_DIRECTION_FIAT_TO_CRYPTO,
    EXCHANGE_DIRECTION_CRYPTO_TO_FIAT,
    EXCHANGE_DIRECTION_CRYPTO_TO_CRYPTO,
];

// Internal exchange-order lifecycle vocabulary. Provider-specific raw statuses
// are mapped onto these eight (the map_* fns in src/exchange/) and the raw
// string is preserved in exchange_order.provider_status.
/// Order accepted by the provider; nothing has moved yet.
pub const EXCHANGE_STATUS_CREATED: &str = "created";

/// Waiting for the customer's pay-in (crypto deposit / wire) to arrive.
pub const EXCHANGE_STATUS_AWAITING_DEPOSIT: &str = "awaiting_deposit";

/// Provider is confirming / exchanging / sending.
pub const EXCHANGE_STATUS_PROCESSING: &str = "processing";

/// Held by the provider (KYC/AML review); may still complete or refund.
pub const EXCHANGE_STATUS_ON_HOLD: &str = "on_hold";

/// Terminal: payout delivered.
pub const EXCHANGE_STATUS_COMPLETED: &str = "completed";

/// Terminal: order failed.
pub const EXCHANGE_STATUS_FAILED: &str = "failed";

/// Terminal: pay-in returned to the customer.
pub const EXCHANGE_STATUS_REFUNDED: &str = "refunded";

/// Terminal: pay-in window elapsed without a deposit.
pub const EXCHANGE_STATUS_EXPIRED: &str = "expired";

/// Valid exchange-order statuses (mirrors the `chk_exchange_order_status` DB
/// CHECK, in DDL order).
pub const VALID_EXCHANGE_STATUSES: &[&str] = &[
    EXCHANGE_STATUS_CREATED,
    EXCHANGE_STATUS_AWAITING_DEPOSIT,
    EXCHANGE_STATUS_PROCESSING,
    EXCHANGE_STATUS_ON_HOLD,
    EXCHANGE_STATUS_COMPLETED,
    EXCHANGE_STATUS_FAILED,
    EXCHANGE_STATUS_REFUNDED,
    EXCHANGE_STATUS_EXPIRED,
];

/// Terminal exchange-order statuses. Webhooks and the reconcile poller must
/// never regress an order out of these (guard: `AND NOT (status = ANY(...))`).
pub const TERMINAL_EXCHANGE_STATUSES: &[&str] = &[
    EXCHANGE_STATUS_COMPLETED,
    EXCHANGE_STATUS_FAILED,
    EXCHANGE_STATUS_REFUNDED,
    EXCHANGE_STATUS_EXPIRED,
];

/// Default OwlPay Harbor API base URL (sandbox). Production base URLs are
/// issued per-tenant by OwlPay — set OWLPAY_API_URL to yours.
pub const DEFAULT_OWLPAY_API_URL: &str = "https://harbor-sandbox.owlpay.com";

/// Default Changelly Exchange API v2 (crypto swap) base URL.
pub const DEFAULT_CHANGELLY_API_URL: &str = "https://api.changelly.com/v2";

/// Default Changelly Fiat API base URL.
pub const DEFAULT_CHANGELLY_FIAT_API_URL: &str = "https://fiat-api.changelly.com/v1";

/// Default poll interval (seconds) for the exchange-order reconcile loop.
pub const DEFAULT_EXCHANGE_POLL_SECS: u64 = 60;

/// Reconcile loop: max due orders refreshed per tick.
pub const EXCHANGE_POLL_BATCH_LIMIT: i64 = 50;

/// Inbound exchange webhooks: max signed-timestamp skew (seconds) before a
/// delivery is rejected as a replay.
pub const EXCHANGE_WEBHOOK_REPLAY_WINDOW_SECS: i64 = 300;

/// Inbound exchange webhooks: max requests per `RATE_LIMIT_WINDOW_SECS`.
/// Global scope per provider — the webhook endpoints are unauthenticated.
pub const EXCHANGE_WEBHOOK_RATE_LIMIT_MAX: u64 = 120;

/// Max length for an exchange currency/ticker code (mirrors the VARCHAR(24) columns).
pub const MAX_EXCHANGE_CURRENCY_LEN: usize = 24;

/// Max length for a decimal amount string (mirrors the VARCHAR(40) columns).
pub const MAX_EXCHANGE_AMOUNT_LEN: usize = 40;

/// Max length for a payout/refund address.
pub const MAX_EXCHANGE_ADDRESS_LEN: usize = 128;

/// Max length for a payout/refund extra id (destination tag / memo).
pub const MAX_EXCHANGE_EXTRA_ID_LEN: usize = 64;
