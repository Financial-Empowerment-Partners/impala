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

/// Minimum spacing between *on-demand* JWKS refetches (the "unknown kid" path).
///
/// That path is reachable unauthenticated: the `kid` comes from an unverified
/// JWT header, and federated token validation runs before any rate limit (the
/// per-account limit keys on an account id that a bogus token never yields).
/// Without spacing, each junk token forces one outbound fetch to the IdP —
/// amplification that can get the bridge throttled by the IdP and take down
/// SSO for everyone. Scheduled rotations are still picked up by the background
/// refresh task, so a short cooldown costs nothing operationally.
pub const JWKS_ON_DEMAND_COOLDOWN_SECS: u64 = 60;

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

// ── Conversion reserve (bridge service reserve for small orders) ───────

/// Internal exchange "provider" for orders fulfilled from the bridge's own
/// conversion reserve instead of an external provider. Row/filter vocabulary
/// only — never accepted in create/quote requests.
pub const EXCHANGE_PROVIDER_RESERVE: &str = "reserve";

/// Every provider value an `exchange_order` ROW may carry (mirrors the
/// `chk_exchange_order_provider` DB CHECK after 031). Superset of
/// [`VALID_EXCHANGE_PROVIDERS`], which stays request-side only so clients
/// cannot request `reserve` directly.
pub const EXCHANGE_ORDER_ROW_PROVIDERS: &[&str] = &[
    EXCHANGE_PROVIDER_OWLPAY,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
    EXCHANGE_PROVIDER_CHANGELLY_FIAT,
    EXCHANGE_PROVIDER_RESERVE,
];

/// Providers whose orders have a buildable reserve-fulfillment path and may
/// therefore have their policy enabled: changelly_crypto (automatic on-chain
/// USDC payout) and owlpay (USDC pay-in + admin fiat disbursement queue).
/// changelly_fiat orders carry no payout coordinates the bridge could serve
/// (bank details live on the provider's hosted page), so enabling it is
/// refused rather than silently doing nothing.
pub const RESERVE_SUPPORTED_POLICY_PROVIDERS: &[&str] =
    &[EXCHANGE_PROVIDER_CHANGELLY_CRYPTO, EXCHANGE_PROVIDER_OWLPAY];

/// Reserve threshold band in USD cents — the "$20 to $200" requirement.
/// Mirrors the `threshold_usd_cents` CHECK in 031.
pub const RESERVE_THRESHOLD_MIN_USD_CENTS: i64 = 2_000;
/// Upper bound of the reserve threshold band (USD cents).
pub const RESERVE_THRESHOLD_MAX_USD_CENTS: i64 = 20_000;

/// Reserve bucket keys (canonical uppercase; mirrors the 031 seed rows).
pub const RESERVE_CURRENCY_USDC: &str = "USDC";
/// USD float bucket for admin fiat disbursements.
pub const RESERVE_CURRENCY_USD: &str = "USD";
/// Accumulated pay-in inventory bucket (native XLM).
pub const RESERVE_CURRENCY_XLM: &str = "XLM";

/// Minor-unit scale for Stellar-native asset buckets (USDC/XLM, 7 dp).
pub const RESERVE_SCALE_STELLAR: u8 = 7;
/// Minor-unit scale for the USD bucket (cents).
pub const RESERVE_SCALE_USD: u8 = 2;

/// Exchange ticker for native XLM pay-ins (compared case-insensitively).
pub const RESERVE_TICKER_XLM: &str = "xlm";
/// Exchange tickers meaning "USDC on Stellar" — the only USDC forms the
/// reserve can serve. Bare "usdc" is deliberately absent: on Changelly it
/// commonly denotes ERC-20 USDC with a non-Stellar payout address.
pub const RESERVE_STELLAR_USDC_TICKERS: &[&str] = &["usdcxlm"];
/// Exchange tickers meaning US dollars for the owlpay disbursement path.
pub const RESERVE_USD_TICKERS: &[&str] = &["usd"];

/// Conversion-reserve journal entry kinds (mirrors
/// `chk_conversion_reserve_entry_kind` after 032, in DDL order).
///
/// `kind` is VARCHAR(24): an over-long name fails at RUNTIME (SQLSTATE
/// 22001) on a money path, not at compile time. A models.rs drift test
/// asserts both the exact list and the length bound.
pub const VALID_RESERVE_ENTRY_KINDS: &[&str] = &[
    "hold",
    "hold_release",
    "deposit",
    "unmatched_deposit",
    "payout_attempt",
    "fulfillment",
    "disbursement",
    "topup",
    "withdrawal",
    "adjustment",
    "held_adjustment",
    // Reserved price quotes (032).
    "quote_hold",
    "quote_release",
    "quote_consume",
    // Automated replenishment (032).
    "replenish_hold",
    "replenish_attempt",
    "replenish_sent",
    "replenish_credit",
    "replenish_refund",
    "replenish_release",
    "offramp_hold",
    "offramp_attempt",
    "offramp_sent",
    "offramp_refund",
    "fiat_in_transit",
    "fiat_confirmed",
    "fiat_written_off",
    // Automated refunds (032).
    "refund_intent",
    "refund_sent",
    "refund_reversal",
];

/// Max length of a journal `kind` (mirrors the VARCHAR(24) column).
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const MAX_RESERVE_ENTRY_KIND_LEN: usize = 24;

/// Treasury entry kinds: the bridge moving its OWN inventory between assets,
/// never customer flow.
///
/// These are excluded from the utilization/forecast aggregates. Including
/// them would be a runaway loop: `offramp_sent` (USDC leaving to be sold for
/// fiat) reads as USDC outflow, which inflates the EWMA, which inflates the
/// suggested top-up, which buys USDC to replace the USDC the bridge
/// deliberately spent. The same applies to `replenish_sent` on XLM.
pub const RESERVE_INTERNAL_ENTRY_KINDS: &[&str] = &[
    "replenish_hold",
    "replenish_attempt",
    "replenish_sent",
    "replenish_credit",
    "replenish_refund",
    "replenish_release",
    "offramp_hold",
    "offramp_attempt",
    "offramp_sent",
    "offramp_refund",
    "fiat_in_transit",
    "fiat_confirmed",
    "fiat_written_off",
];

/// Entry kinds an admin may write via POST /admin/exchange-reserve/entries.
pub const RESERVE_ADMIN_ENTRY_KINDS: &[&str] =
    &["topup", "withdrawal", "adjustment", "held_adjustment"];

/// Stray-inflow reasons (mirrors `chk_conversion_reserve_unmatched_reason`).
/// Vocabulary-only: values are written as literals by the watcher and pinned
/// against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const VALID_RESERVE_UNMATCHED_REASONS: &[&str] =
    &["late", "underpaid", "wrong_asset", "no_match"];

/// Default deposit window for reserve orders (seconds). Doubles as the
/// price-validity window: the order-time quote is honored only within it, so
/// a long TTL would hand out a free price option on the whole pool (deposit
/// only when the market moved your way, walk away otherwise). 30 minutes
/// mirrors provider payTill windows; clamped to [300, 7200] at load.
pub const DEFAULT_RESERVE_DEPOSIT_TTL_SECS: u64 = 1_800;
/// Lower clamp for RESERVE_DEPOSIT_TTL_SECS.
pub const RESERVE_DEPOSIT_TTL_MIN_SECS: u64 = 300;
/// Upper clamp for RESERVE_DEPOSIT_TTL_SECS.
pub const RESERVE_DEPOSIT_TTL_MAX_SECS: u64 = 7_200;

/// Default reserve watcher cadence (seconds); clamped to >= 5 at load.
pub const DEFAULT_RESERVE_WATCH_SECS: u64 = 30;

/// Max Horizon payment records per watcher page.
pub const RESERVE_WATCH_PAGE_LIMIT: u32 = 200;

/// Max concurrently open (non-terminal) reserve orders per account — with
/// the hold-fraction guard, bounds how much of the pool one actor can lock.
pub const RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT: i64 = 3;

/// Max on-chain payout submissions per order under one write-ahead intent.
/// Only definitively-rejected submissions (Horizon 400 with result codes —
/// the tx provably did not land) are retried; ambiguous outcomes freeze the
/// order for admin resolution instead.
pub const RESERVE_MAX_PAYOUT_ATTEMPTS: i32 = 5;

/// Min age of a payout_attempt intent before `resolve {action: fail}` is
/// accepted: the signed tx is valid for 300s (signer TX_TIMEOUT_SECS), so an
/// earlier fail could release a hold that an in-flight payment then spends.
pub const RESERVE_RESOLVE_FAIL_MIN_INTENT_AGE_SECS: i64 = 600;

/// Admin fat-finger bound: a fiat disbursement may not exceed this multiple
/// of the order's recorded hold.
pub const RESERVE_DISBURSE_MAX_MULTIPLE: i64 = 2;

/// Advisory-lock key serializing the reserve watcher tick across instances
/// (pg_try_advisory_lock; losers skip the tick). Arbitrary but stable.
pub const RESERVE_WATCHER_LOCK_KEY: i64 = 0x494d_5052_5352_5645;

// ── Reserved price quotes (032) ────────────────────────────────────────

/// Quote lifecycle statuses (mirrors `chk_conversion_reserve_quote_status`).
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const VALID_RESERVE_QUOTE_STATUSES: &[&str] = &["open", "consumed", "expired"];

/// Divertable order shapes (mirrors `chk_conversion_reserve_quote_shape` and
/// the `provider_payload.shape` literals the reserve writes).
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const RESERVE_QUOTE_SHAPES: &[&str] = &["auto_swap", "disburse"];

/// Default price-lock window (seconds).
///
/// Deliberately an order of magnitude shorter than the deposit window: a
/// quote hold delivers nothing to the customer while it waits (no pay-in is
/// in flight), so it is pure optionality against the pool and earns the
/// tightest window of the three.
pub const DEFAULT_RESERVE_QUOTE_TTL_SECS: u64 = 300;
/// Lower clamp for RESERVE_QUOTE_TTL_SECS (below this a lock is useless).
pub const RESERVE_QUOTE_TTL_MIN_SECS: u64 = 60;
/// Upper clamp for RESERVE_QUOTE_TTL_SECS.
pub const RESERVE_QUOTE_TTL_MAX_SECS: u64 = 900;

/// Ceiling on TOTAL price-option exposure: the quote lock plus the deposit
/// window. A client holds a fixed `amount_to` for that whole span and may
/// walk away for free, so this is a free at-the-money option written against
/// the pool. Capped at the value 031 already sanctioned for the deposit
/// window alone, so adding locks cannot widen the option beyond what was
/// reviewed. Enforced at startup against the CONFIGURED pair — the maxima
/// alone would sum to 8100.
pub const RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS: u64 = 7_200;

/// Max reserve quotes expired per watcher tick.
pub const RESERVE_QUOTE_EXPIRE_BATCH: i64 = 100;

// ── Automated replenishment (032) ──────────────────────────────────────

/// Replenishment cycle kinds (mirrors `chk_crr_kind`).
pub const VALID_REPLENISH_KINDS: &[&str] = &["xlm_to_usdc", "usdc_to_usd"];

/// Cycle states (mirrors `chk_crr_state`, in DDL order).
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const VALID_REPLENISH_STATES: &[&str] = &[
    "planned",
    "creating",
    "created",
    "sending",
    "sent",
    "settled",
    "in_transit",
    "completed",
    "refunded",
    "failed",
    "frozen",
];

/// States that free the single-in-flight slot. MUST stay identical to the
/// `uq_crr_inflight` partial-index predicate in 032 — a drift test asserts
/// it, because a mismatch silently breaks the one-cycle-at-a-time guarantee.
/// Note `frozen` and `in_transit` are deliberately absent: unknown on-chain
/// state and unverified fiat must both keep blocking new spending.
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const RESERVE_TERMINAL_CYCLE_STATES: &[&str] = &["completed", "failed", "refunded"];

/// Reference notional (whole XLM) used to price a cycle before its real size
/// is known, and to detect slippage once it is.
pub const RESERVE_REPLENISH_REFERENCE_XLM: &str = "100";

/// Max cycles advanced per watcher tick (each is provider + chain I/O held
/// under the tick's advisory lock).
pub const RESERVE_REPLENISH_MAX_PER_TICK: i64 = 2;

/// Age at which a cycle stuck mid-submit is frozen for admin resolution.
/// Must exceed the signed transaction's validity window (signer
/// TX_TIMEOUT_SECS = 300) so "still in flight" is never mistaken for
/// "crashed".
pub const RESERVE_REPLENISH_STALE_SECS: i64 = 600;
const _: () = assert!(RESERVE_REPLENISH_STALE_SECS >= 2 * 300);

// ── Automated refunds (032) ────────────────────────────────────────────

/// Refund obligation statuses (mirrors `chk_crr_refund_status`).
pub const VALID_RESERVE_REFUND_STATUSES: &[&str] = &[
    "needs_review",
    "queued",
    "inflight",
    "sent",
    "failed",
    "frozen",
    "cancelled",
];

/// Refund reasons (mirrors `chk_crr_refund_reason`).
/// Vocabulary-only: values are written as literals by the code that owns
/// them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const VALID_RESERVE_REFUND_REASONS: &[&str] = &["late", "underpaid", "order_failed", "manual"];

/// Reasons the driver queues WITHOUT a human. `manual` is excluded by
/// construction, and so are `no_match`/`wrong_asset` stray inflows: an
/// unmemoed deposit is exactly how ops tops the pool up, so auto-refunding
/// one would wire the float back to ops.
pub const RESERVE_AUTO_REFUND_REASONS: &[&str] = &["late", "underpaid", "order_failed"];

/// Max on-chain refund submissions per obligation. Only definitive
/// rejections are retried; ambiguous outcomes freeze instead.
pub const RESERVE_REFUND_MAX_ATTEMPTS: i32 = 3;

/// Grace before a queued refund becomes eligible — an ops window to cancel a
/// wrong auto-refund before value leaves the pool.
pub const RESERVE_REFUND_COOLDOWN_SECS: i64 = 300;

/// Refunds attempted per watcher tick. Small on purpose: each is two Horizon
/// round-trips under the tick's advisory lock.
pub const RESERVE_REFUND_MAX_PER_TICK: i64 = 5;

/// Dust floor (0.1 unit at 7dp). Below it a refund is parked for review —
/// never silently absorbed.
pub const RESERVE_REFUND_MIN_MINOR: i64 = 1_000_000;

/// Refund memo prefix.
///
/// The refund memo MUST NOT equal an order ref: `find_onchain_payout` treats
/// any outgoing payment carrying the order ref as proof the payout landed,
/// so a refund wearing that memo would make `resolve fail` refuse and
/// `resolve complete` record the refund's hash as the fulfillment.
pub const RESERVE_REFUND_MEMO_PREFIX: &str = "RF";
const _: () = assert!(RESERVE_REFUND_MEMO_PREFIX.len() + 8 <= 28);

// ── Admin key import ──────────────────────────────────────────────────

/// Credential sets an admin can import. Deliberately the same vocabulary as
/// [`VALID_EXCHANGE_PROVIDERS`] — a credential set exists to build exactly one
/// provider client — and pinned to it by a test so the two cannot drift.
pub const VALID_CREDENTIAL_KINDS: &[&str] = &[
    EXCHANGE_PROVIDER_OWLPAY,
    EXCHANGE_PROVIDER_CHANGELLY_CRYPTO,
    EXCHANGE_PROVIDER_CHANGELLY_FIAT,
];

/// States of a `bridge_credential` row (mirrors `chk_bridge_credential_state`).
/// Vocabulary-only: the states are written as literals by the statements that
/// own them and pinned against the DDL by a models.rs drift-guard test.
#[allow(dead_code)]
pub const VALID_CREDENTIAL_STATES: &[&str] = &["active", "superseded", "revoked"];

/// Where an effective credential came from, as reported by `GET /admin/keys`.
pub const CREDENTIAL_SOURCE_DB: &str = "db";
pub const CREDENTIAL_SOURCE_ENV: &str = "env";
pub const CREDENTIAL_SOURCE_UNCONFIGURED: &str = "unconfigured";

/// Domain separator for credential fingerprints. Changing it invalidates every
/// stored fingerprint, so it is versioned rather than edited.
pub const CREDENTIAL_FP_DOMAIN: &str = "impala-key-fp-v1";

/// Displayed/compared fingerprint length in hex characters (80 bits). Long
/// enough that two live credentials never collide, short enough to read aloud.
pub const CREDENTIAL_FP_HEX_LEN: usize = 20;

/// Bound-header magic sealed inside a credential ciphertext. Verified on
/// decrypt so a blob cannot be replayed into a different row.
pub const CREDENTIAL_HEADER_MAGIC: &str = "impala-cred-v1";

/// Bound-header magic sealed inside a custodial seed ciphertext
/// (`managed_seed.format_version = 1`).
pub const SEED_HEADER_MAGIC: &str = "impala-seed-v1";

/// `managed_seed.format_version` for a ciphertext carrying the bound header.
pub const SEED_FORMAT_BOUND: i16 = 1;

/// How long a superseded credential stays decryptable before it is scrubbed.
/// The window exists so inbound webhooks signed with the previous secret still
/// verify and in-flight orders can still be reconciled; past it, keeping the
/// old key recoverable only grows the blast radius of a database compromise.
pub const CREDENTIAL_SUPERSEDE_GRACE_SECS: i64 = 604_800;
// Long enough for provider webhook retries and in-flight reconciliation, short
// enough that a database snapshot does not hand over every key the bridge has
// ever held. Never unbounded.
const _: () = assert!(CREDENTIAL_SUPERSEDE_GRACE_SECS > 0);
const _: () = assert!(CREDENTIAL_SUPERSEDE_GRACE_SECS <= 30 * 86_400);

/// Max length of an operator note on a credential row.
pub const CREDENTIAL_NOTE_MAX_LEN: usize = 256;

/// Max accepted length of a single imported secret part. Comfortably fits a
/// 4096-bit RSA PEM; anything larger is a paste error, not a key.
pub const CREDENTIAL_PART_MAX_LEN: usize = 16_384;

/// Rate-limit scope for the mutating key-management endpoints. They reuse the
/// tighter custodial-sign budget (`SIGN_RATE_LIMIT_*`) because each one can
/// re-point a money path.
pub const KEY_IMPORT_RATE_LIMIT_SCOPE: &str = "keyimport";
