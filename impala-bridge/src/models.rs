use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── JWT Claims ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub token_type: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub iss: String,
    /// Audience, always `JWT_AUDIENCE`. Deliberately NOT serde-defaulted:
    /// tokens minted before the aud/fid rollout fail to decode (hard cutover,
    /// one forced re-login) rather than bypassing audience validation.
    pub aud: String,
    /// Refresh-token family id. Minted at credential login and inherited across
    /// refresh rotations, so reuse of a rotated-out refresh token can revoke
    /// every descendant token in one operation. NOT serde-defaulted (see `aud`).
    pub fid: String,
    /// Server-side role claim, stamped at every token issuance (the account's
    /// DB role, with the ADMIN_ACCOUNT_IDS allowlist overriding to `admin`).
    /// Admin privilege is derived from this claim — there is no separate
    /// `is_admin` claim. Absent in tokens minted before role support, so it
    /// defaults to least privilege (`view-only`) — fail closed; clients cannot
    /// set it (HS256-signed).
    #[serde(default = "default_role")]
    pub role: String,
}

/// Default role for tokens/accounts without an explicit role. Least privilege.
pub(crate) fn default_role() -> String {
    crate::constants::ROLE_VIEW_ONLY.to_string()
}

// ── Pagination ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

pub(crate) fn default_page() -> u64 {
    1
}

pub(crate) fn default_per_page() -> u64 {
    20
}

impl PaginationParams {
    /// Return clamped `(per_page, offset)` suitable for SQL LIMIT/OFFSET.
    /// `per_page` is clamped to `[1, 100]`, `page` to `[1, ..)`.
    pub fn clamped(&self) -> (i64, i64) {
        let per_page = self.per_page.clamp(1, 100) as i64;
        let page = self.page.max(1) as i64;
        let offset = (page - 1) * per_page;
        (per_page, offset)
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
}

// ── Account ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub stellar_account_id: String,
    pub payala_account_id: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
}

#[derive(Serialize)]
pub struct CreateAccountResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct GetAccountQuery {
    pub stellar_account_id: String,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct GetAccountResponse {
    pub payala_account_id: String,
    pub stellar_account_id: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
    pub role: String,
    pub sync_mode: String,
    pub profile_source: String,
    pub profile_synced_at: Option<String>,
    pub created_at: Option<String>,
}

// ── Admin: account management ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListAccountsQuery {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
    pub search: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AdminAccountListItem {
    pub payala_account_id: String,
    pub stellar_account_id: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
    pub role: String,
    pub sync_mode: String,
    pub profile_source: String,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Serialize)]
pub struct SetRoleResponse {
    pub success: bool,
    pub message: String,
    pub account_id: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct DeleteAccountResponse {
    pub success: bool,
    pub message: String,
    pub rows_affected: u64,
}

#[derive(Serialize)]
pub struct SyncProfileResponse {
    pub success: bool,
    pub message: String,
    pub profile_source: String,
    pub profile_synced_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::ldap::SyncedProfile>,
}

#[derive(Deserialize)]
pub struct UpdateAccountRequest {
    pub stellar_account_id: Option<String>,
    pub payala_account_id: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateAccountResponse {
    pub success: bool,
    pub message: String,
    pub rows_affected: u64,
}

// ── Managed Seed (custodial Stellar accounts) ──────────────────────────
// NB: request types carrying a `secret_seed` are Deserialize-only and never
// derive Debug, so seed material cannot be echoed or accidentally logged.

#[derive(Deserialize)]
pub struct GenerateManagedAccountRequest {
    pub payala_account_id: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
}

#[derive(Deserialize)]
pub struct ImportManagedAccountRequest {
    pub payala_account_id: String,
    pub secret_seed: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
}

#[derive(Serialize)]
pub struct ManagedAccountResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_account_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SignSubmitRequest {
    pub payala_account_id: String,
    pub destination: String,
    pub amount: String,
    pub memo: Option<String>,
    pub fee: Option<u32>,
}

#[derive(Serialize)]
pub struct SignSubmitResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btxid: Option<Uuid>,
}

// ── Authenticate ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuthenticateRequest {
    pub account_id: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthenticateResponse {
    pub success: bool,
    pub message: String,
    pub action: String,
}

// ── Sync ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SyncRequest {
    pub account_id: String,
}

#[derive(Serialize)]
pub struct SyncResponse {
    pub success: bool,
    pub message: String,
    pub timestamp: String,
}

// ── Payala Sync (reserve / mirror modes) ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PayalaSyncItemInput {
    pub payala_tx_id: String,
    /// Signed amount in minor units; sign = direction (+incoming / -outgoing).
    pub amount: i64,
    pub currency: String,
    pub memo: Option<String>,
    pub payala_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PayalaSyncRequest {
    /// The Payala account id (== JWT sub), NOT a Stellar G-address.
    pub account_id: String,
    pub transactions: Vec<PayalaSyncItemInput>,
}

#[derive(Serialize)]
pub struct PayalaSyncResponse {
    pub success: bool,
    pub message: String,
    pub batch_id: Uuid,
    pub sync_mode: String,
    pub received: usize,
    pub applied: usize,
    pub duplicates: usize,
    /// Previously-seen ids whose stored (amount, currency) differ from this
    /// submission — a ledger-integrity signal, not routine idempotency.
    pub conflicting: usize,
    /// Per-currency net delta over APPLIED items (BTreeMap → stable key order).
    pub net_deltas: std::collections::BTreeMap<String, i64>,
    /// Current reserve balances for the batch's currencies (reserve mode only;
    /// lets an idempotent replay after a timed-out response reconcile state).
    pub reserve_balances: Vec<ReserveBalance>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveBalance {
    pub currency: String,
    pub balance: i64,
    pub updated_at: Option<String>,
}

#[derive(Serialize)]
pub struct ReserveBalancesResponse {
    pub account_id: String,
    pub sync_mode: String,
    pub reserves: Vec<ReserveBalance>,
}

#[derive(Deserialize)]
pub struct SetSyncModeRequest {
    pub sync_mode: String,
    /// Required (true) to leave reserve mode while a nonzero balance remains.
    pub force: Option<bool>,
}

#[derive(Serialize)]
pub struct SetSyncModeResponse {
    pub success: bool,
    pub message: String,
    pub account_id: String,
    pub sync_mode: String,
}

// ── Token ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_token: Option<String>,
}

// ── Subscribe ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubscribeRequest {
    pub network: String,
    pub listen_endpoint: Option<String>,
}

#[derive(Serialize)]
pub struct SubscribeResponse {
    pub success: bool,
    pub message: String,
}

// ── Transaction ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTransactionRequest {
    pub stellar_tx_id: Option<String>,
    pub payala_tx_id: Option<String>,
    pub stellar_hash: Option<String>,
    pub source_account: Option<String>,
    pub stellar_fee: Option<i64>,
    pub stellar_max_fee: Option<i64>,
    pub memo: Option<String>,
    pub signatures: Option<String>,
    pub preconditions: Option<String>,
    pub payala_currency: Option<String>,
    pub payala_digest: Option<String>,
}

#[derive(Serialize)]
pub struct CreateTransactionResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btxid: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ListTransactionsQuery {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
    /// Review status filter (unreviewed/cleared/flagged/escalated).
    pub status: Option<String>,
    /// Flag filter.
    pub flagged: Option<bool>,
    /// Exact Stellar G-address (source_account) filter.
    pub source_account: Option<String>,
    /// created_at >= this RFC3339 timestamp.
    pub from: Option<String>,
    /// created_at < this RFC3339 timestamp.
    pub to: Option<String>,
    /// Free-text search over memo / tx ids / hash / source account.
    pub q: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TransactionListItem {
    pub btxid: Uuid,
    pub stellar_tx_id: Option<String>,
    pub payala_tx_id: Option<String>,
    pub stellar_hash: Option<String>,
    pub source_account: Option<String>,
    pub stellar_fee: Option<i64>,
    pub stellar_max_fee: Option<i64>,
    pub memo: Option<String>,
    pub payala_currency: Option<String>,
    pub payala_amount: Option<i64>,
    pub origin: String,
    pub created_at: String,
    pub flagged: bool,
    pub status: String,
    pub note: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TransactionDetail {
    pub btxid: Uuid,
    pub stellar_tx_id: Option<String>,
    pub payala_tx_id: Option<String>,
    pub stellar_hash: Option<String>,
    pub source_account: Option<String>,
    pub stellar_fee: Option<i64>,
    pub stellar_max_fee: Option<i64>,
    pub memo: Option<String>,
    pub signatures: Option<String>,
    pub preconditions: Option<String>,
    pub payala_currency: Option<String>,
    pub payala_digest: Option<String>,
    pub payala_amount: Option<i64>,
    pub origin: String,
    pub created_at: String,
    pub flagged: bool,
    pub status: String,
    pub note: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReviewTransactionRequest {
    pub flagged: Option<bool>,
    pub status: Option<String>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct ReviewTransactionResponse {
    pub success: bool,
    pub message: String,
    pub btxid: Uuid,
    pub flagged: bool,
    pub status: String,
}

// ── Card ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateCardRequest {
    pub account_id: String,
    pub card_id: String,
    pub ec_pubkey: String,
    pub rsa_pubkey: String,
}

#[derive(Serialize)]
pub struct CardResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct DeleteCardRequest {
    pub card_id: String,
}

// ── MFA ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EnrollMfaRequest {
    pub account_id: String,
    pub mfa_type: String,
    #[allow(dead_code)] // accepted in the request body; TOTP secret is generated server-side
    pub secret: Option<String>,
    pub phone_number: Option<String>,
}

#[derive(Serialize)]
pub struct MfaResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_uri: Option<String>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaEnrollment {
    pub account_id: String,
    pub mfa_type: String,
    pub secret: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct MfaQuery {
    pub account_id: String,
}

#[derive(Deserialize)]
pub struct VerifyMfaRequest {
    pub account_id: String,
    pub mfa_type: String,
    pub code: String,
}

// ── Notify ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateNotifyRequest {
    pub account_id: String,
    pub medium: String,
    pub mobile: Option<String>,
    pub wa: Option<String>,
    pub signal: Option<String>,
    pub tel: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
    pub app: Option<String>,
}

#[derive(Serialize)]
pub struct NotifyResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
}

#[derive(Deserialize)]
pub struct UpdateNotifyRequest {
    pub id: i32,
    pub medium: Option<String>,
    pub mobile: Option<String>,
    pub wa: Option<String>,
    pub signal: Option<String>,
    pub tel: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
    pub app: Option<String>,
}

// ── Notification Subscription ──────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSubscriptionRequest {
    pub event_type: String,
    pub medium: String,
}

#[derive(Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct SubscriptionResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SubscriptionListItem {
    pub id: i32,
    pub event_type: String,
    pub medium: String,
    pub enabled: bool,
}

// ── Device Token ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterDeviceTokenRequest {
    pub token: String,
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    "android".to_string()
}

#[derive(Deserialize)]
pub struct DeleteDeviceTokenRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct DeviceTokenResponse {
    pub success: bool,
    pub message: String,
}

// ── Notify List ───────────────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
pub struct NotifyListItem {
    pub id: i32,
    pub account_id: String,
    pub medium: String,
    pub mobile: Option<String>,
    pub wa: Option<String>,
    pub signal: Option<String>,
    pub tel: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
    pub app: Option<String>,
}

// ── Version ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct VersionResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub build_date: &'static str,
    pub rustc_version: &'static str,
    pub schema_version: Option<String>,
}

// ── Health ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub redis: String,
    pub stellar_network: String,
}

// ── Network Info ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NetworkInfoResponse {
    pub stellar_network: String,
    pub stellar_horizon_url: String,
    pub stellar_rpc_url: String,
    pub network_passphrase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soroban_contract_id: Option<String>,
}

// ── SSO (OIDC) ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OktaTokenExchangeRequest {
    pub okta_token: String,
    /// Browser clients set this to receive an HttpOnly cookie session (plus
    /// CSRF token) instead of bearer tokens. Defaults off for API clients.
    #[serde(default)]
    pub cookie_mode: bool,
}

#[derive(Deserialize)]
pub struct SsoTokenExchangeRequest {
    /// Access token (Okta / Auth0). Legacy clients send it as `okta_token`.
    #[serde(default, alias = "okta_token")]
    pub token: Option<String>,
    /// ID token, for providers configured with `token_kind = id` (e.g. Duo SSO).
    #[serde(default)]
    pub id_token: Option<String>,
}

#[derive(Serialize)]
pub struct OktaConfigResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct SsoConfigResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

// ── Google ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GoogleTokenExchangeRequest {
    pub id_token: String,
}

#[derive(Serialize)]
pub struct GoogleConfigResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

// ── GitHub ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GitHubTokenExchangeRequest {
    /// Direct access-token exchange (legacy clients; the token was obtained
    /// on-device). Mutually exclusive with `code`.
    #[serde(default)]
    pub access_token: Option<String>,
    /// OAuth authorization code — the bridge performs the code→token
    /// exchange server-side so the GitHub client secret never ships in a
    /// client binary.
    #[serde(default)]
    pub code: Option<String>,
    /// Redirect URI used in the authorization request (forwarded to GitHub
    /// during the code exchange).
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

// ── Card auth ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CardChallengeRequest {
    pub card_id: String,
}

#[derive(Serialize)]
pub struct CardChallengeResponse {
    pub success: bool,
    /// 32 random bytes, hex-encoded (64 chars). The card signs the raw bytes.
    pub challenge: String,
    /// Challenge TTL in seconds.
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct CardTokenExchangeRequest {
    pub card_id: String,
    /// Hex-encoded ASN.1 DER ECDSA-SHA256 signature from the card (INS_SIGN_AUTH).
    pub signature: String,
}

// ── Admin webhook feed ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    /// Event types to deliver; omit/empty for all.
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct RegisterWebhookResponse {
    pub id: i64,
    pub url: String,
    /// HMAC-SHA256 signing secret. Returned ONCE — store it on the receiver to
    /// verify the `X-Impala-Signature` header.
    pub secret: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct WebhookInfo {
    pub id: i64,
    pub url: String,
    pub event_types: Option<Vec<String>>,
    pub enabled: bool,
    pub failure_count: i32,
    pub last_error: Option<String>,
    pub last_delivery_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct EventFeedItem {
    pub id: i64,
    pub event_type: String,
    pub account_id: String,
    pub payload: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct EventFeedResponse {
    pub events: Vec<EventFeedItem>,
}

#[derive(Debug, Deserialize)]
pub struct EventFeedQuery {
    /// Return events with `id` strictly greater than this cursor.
    #[serde(default)]
    pub since: i64,
    #[serde(default = "default_event_limit")]
    pub limit: i64,
}

fn default_event_limit() -> i64 {
    100
}

// ── Exchange ───────────────────────────────────────────────────────────
// OwlPay / Changelly fiat<->USDC on/off-ramp and crypto->USDC swaps. All
// amounts are provider-quoted decimal STRINGS (heterogeneous precisions;
// never parsed into floats).

#[derive(Debug, Deserialize)]
pub struct ExchangeQuoteRequest {
    pub provider: String,
    pub direction: String,
    pub from_currency: String,
    pub to_currency: String,
    pub amount_from: String,
    /// changelly_crypto: "float" | "fixed".
    #[serde(default)]
    pub rate_type: Option<String>,
    /// changelly_fiat.
    #[serde(default)]
    pub country: Option<String>,
    /// changelly_fiat, US only.
    #[serde(default)]
    pub state: Option<String>,
    /// changelly_fiat offers `ip`.
    #[serde(default)]
    pub user_ip: Option<String>,
    /// owlpay.
    #[serde(default)]
    pub source_country: Option<String>,
    /// owlpay.
    #[serde(default)]
    pub destination_country: Option<String>,
    /// owlpay (crypto source).
    #[serde(default)]
    pub source_chain: Option<String>,
    /// owlpay (crypto destination, e.g. "stellar").
    #[serde(default)]
    pub destination_chain: Option<String>,
    /// owlpay "individual" | "business" (default individual).
    #[serde(default)]
    pub customer_type: Option<String>,
}

#[derive(Serialize)]
pub struct ExchangeQuoteResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotes: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateExchangeOrderRequest {
    /// The Payala account id (== JWT sub); require_owner-gated.
    pub account_id: String,
    pub provider: String,
    pub direction: String,
    pub from_currency: String,
    pub to_currency: String,
    pub amount_from: String,
    #[serde(default)]
    pub payout_address: Option<String>,
    #[serde(default)]
    pub payout_extra_id: Option<String>,
    #[serde(default)]
    pub refund_address: Option<String>,
    #[serde(default)]
    pub refund_extra_id: Option<String>,
    #[serde(default)]
    pub rate_type: Option<String>,
    /// changelly_crypto fixed-rate quotes.
    #[serde(default)]
    pub rate_id: Option<String>,
    /// owlpay v2.
    #[serde(default)]
    pub quote_id: Option<String>,
    /// changelly_fiat (e.g. "moonpay").
    #[serde(default)]
    pub provider_code: Option<String>,
    /// changelly_fiat.
    #[serde(default)]
    pub payment_method: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub user_ip: Option<String>,
    /// changelly_fiat buy.
    #[serde(default)]
    pub return_success_url: Option<String>,
    #[serde(default)]
    pub return_failed_url: Option<String>,
    /// owlpay on_behalf_of ("cus_...").
    #[serde(default)]
    pub customer_uuid: Option<String>,
    /// owlpay.
    #[serde(default)]
    pub transfer_purpose: Option<String>,
    /// owlpay.
    #[serde(default)]
    pub is_self_transfer: Option<bool>,
    /// owlpay destination.beneficiary_info passthrough.
    #[serde(default)]
    pub beneficiary: Option<serde_json::Value>,
    /// owlpay destination.payout_instrument passthrough.
    #[serde(default)]
    pub payout_instrument: Option<serde_json::Value>,
    /// owlpay source.payment_instrument (off-ramp).
    #[serde(default)]
    pub source_payment_instrument: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ExchangeOrderResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<ExchangeOrderDetail>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ExchangeOrderDetail {
    pub order_id: Uuid,
    pub payala_account_id: String,
    pub provider: String,
    pub direction: String,
    pub from_currency: String,
    pub to_currency: String,
    pub amount_from: String,
    pub amount_to: Option<String>,
    pub status: String,
    pub provider_status: Option<String>,
    pub provider_order_id: String,
    pub payin_address: Option<String>,
    pub payin_extra_id: Option<String>,
    pub payout_address: Option<String>,
    pub payout_extra_id: Option<String>,
    pub redirect_url: Option<String>,
    pub transfer_instructions: Option<serde_json::Value>,
    pub btxid: Option<Uuid>,
    pub last_error: Option<String>,
    /// Rendered in SQL via to_char(... TS_FMT).
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListExchangeOrdersQuery {
    #[serde(default = "default_page_i64")]
    pub page: i64,
    #[serde(default = "default_per_page_i64")]
    pub per_page: i64,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    /// Admin-only filter.
    #[serde(default)]
    pub account_id: Option<String>,
}

fn default_page_i64() -> i64 {
    1
}

fn default_per_page_i64() -> i64 {
    20
}

#[derive(Debug, Deserialize)]
pub struct GetExchangeOrderQuery {
    /// When true, refresh a non-terminal order from the provider before returning.
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Serialize)]
pub struct ExchangeProviderStatus {
    pub provider: String,
    pub enabled: bool,
    pub directions: Vec<String>,
}

#[derive(Serialize)]
pub struct ExchangeProvidersResponse {
    pub providers: Vec<ExchangeProviderStatus>,
}

/// Query for `GET /exchange/reference` — read-only provider reference data
/// (currency/network tickers, tradable pairs, aggregated fiat sub-providers).
#[derive(Debug, Deserialize)]
pub struct ExchangeReferenceQuery {
    pub provider: String,
    /// `currencies` (default) | `pairs` (changelly_crypto) | `providers`
    /// (changelly_fiat).
    #[serde(default)]
    pub kind: Option<String>,
    /// changelly_fiat currencies filter: `crypto` | `fiat`.
    #[serde(default, rename = "type")]
    pub currency_type: Option<String>,
    /// changelly_fiat currencies filter: `buy` | `sell`.
    #[serde(default)]
    pub flow: Option<String>,
    /// changelly_crypto pairs filter (source ticker).
    #[serde(default)]
    pub from: Option<String>,
    /// changelly_crypto pairs filter (destination ticker).
    #[serde(default)]
    pub to: Option<String>,
}

/// Provider-payload passthrough envelope shared by `GET /exchange/reference`
/// and `GET /exchange/owlpay/quotes/{quote_id}/requirements`.
#[derive(Serialize)]
pub struct ExchangeReferenceResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_defaults() {
        let p = PaginationParams {
            page: 1,
            per_page: 20,
        };
        let (per_page, offset) = p.clamped();
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_pagination_clamps_per_page_upper() {
        let p = PaginationParams {
            page: 1,
            per_page: 500,
        };
        let (per_page, _) = p.clamped();
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_clamps_per_page_lower() {
        let p = PaginationParams {
            page: 1,
            per_page: 0,
        };
        let (per_page, _) = p.clamped();
        assert_eq!(per_page, 1);
    }

    #[test]
    fn test_pagination_clamps_page_lower() {
        let p = PaginationParams {
            page: 0,
            per_page: 20,
        };
        let (_, offset) = p.clamped();
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let p = PaginationParams {
            page: 3,
            per_page: 25,
        };
        let (per_page, offset) = p.clamped();
        assert_eq!(per_page, 25);
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_authenticate_request_deserialize() {
        let json = r#"{"account_id":"user1","password":"secret123"}"#;
        let req: AuthenticateRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.account_id, "user1");
        assert_eq!(req.password, "secret123");
    }

    #[test]
    fn test_token_request_deserialize_refresh_flow() {
        let json = r#"{"refresh_token":"eyJ..."}"#;
        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.refresh_token.is_some());
        assert!(req.username.is_none());
        assert!(req.password.is_none());
    }

    #[test]
    fn test_token_request_deserialize_password_flow() {
        let json = r#"{"username":"admin","password":"pass123"}"#;
        let req: TokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.refresh_token.is_none());
        assert_eq!(req.username.as_deref(), Some("admin"));
        assert_eq!(req.password.as_deref(), Some("pass123"));
    }

    #[test]
    fn test_token_response_skips_none_tokens() {
        let resp = TokenResponse {
            success: true,
            message: "ok".to_string(),
            refresh_token: None,
            temporal_token: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("temporal_token"));
    }

    #[test]
    fn test_token_response_includes_present_tokens() {
        let resp = TokenResponse {
            success: true,
            message: "ok".to_string(),
            refresh_token: Some("rt".to_string()),
            temporal_token: Some("tt".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("refresh_token"));
        assert!(json.contains("temporal_token"));
    }

    #[test]
    fn test_create_account_request_with_optionals() {
        let json = r#"{
            "stellar_account_id": "GABCDEF",
            "payala_account_id": "payala1",
            "first_name": "John",
            "last_name": "Doe",
            "middle_name": "M",
            "nickname": "johnny",
            "affiliation": "Corp",
            "gender": "male"
        }"#;
        let req: CreateAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.first_name, "John");
        assert_eq!(req.middle_name, Some("M".to_string()));
        assert_eq!(req.nickname, Some("johnny".to_string()));
    }

    #[test]
    fn test_create_account_request_without_optionals() {
        let json = r#"{
            "stellar_account_id": "GABCDEF",
            "payala_account_id": "payala1",
            "first_name": "John",
            "last_name": "Doe"
        }"#;
        let req: CreateAccountRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.first_name, "John");
        assert!(req.middle_name.is_none());
        assert!(req.nickname.is_none());
    }

    #[test]
    fn test_subscribe_request_deserialize() {
        let json = r#"{"network":"stellar"}"#;
        let req: SubscribeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.network, "stellar");
        assert!(req.listen_endpoint.is_none());
    }

    #[test]
    fn test_subscribe_request_with_endpoint() {
        let json = r#"{"network":"payala","listen_endpoint":"127.0.0.1:9000"}"#;
        let req: SubscribeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.network, "payala");
        assert_eq!(req.listen_endpoint, Some("127.0.0.1:9000".to_string()));
    }

    #[test]
    fn test_register_device_token_default_platform() {
        let json = r#"{"token":"fcm-token-abc"}"#;
        let req: RegisterDeviceTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.token, "fcm-token-abc");
        assert_eq!(req.platform, "android");
    }

    #[test]
    fn test_create_transaction_response_skips_none_btxid() {
        let resp = CreateTransactionResponse {
            success: true,
            message: "ok".to_string(),
            btxid: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("btxid"));
    }

    #[test]
    fn test_notification_subscription_request_deserialize() {
        let json = r#"{"event_type":"login_success","medium":"sms"}"#;
        let req: CreateSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.event_type, "login_success");
        assert_eq!(req.medium, "sms");
    }

    #[test]
    fn test_mfa_response_skips_none_provisioning_uri() {
        let resp = MfaResponse {
            success: true,
            message: "ok".to_string(),
            provisioning_uri: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("provisioning_uri"));
    }

    #[test]
    fn test_sso_config_response_disabled() {
        let resp = SsoConfigResponse {
            enabled: false,
            provider: None,
            issuer: None,
            client_id: None,
            audience: None,
            authorization_endpoint: None,
            token_endpoint: None,
            scopes: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"enabled\":false"));
        assert!(!json.contains("issuer"));
    }

    #[test]
    fn test_sso_token_exchange_request_legacy_alias() {
        // Legacy clients send `okta_token`; it maps onto the generic `token`.
        let req: SsoTokenExchangeRequest = serde_json::from_str(r#"{"okta_token":"abc"}"#).unwrap();
        assert_eq!(req.token.as_deref(), Some("abc"));
        assert_eq!(req.id_token, None);

        let req2: SsoTokenExchangeRequest = serde_json::from_str(r#"{"id_token":"xyz"}"#).unwrap();
        assert_eq!(req2.id_token.as_deref(), Some("xyz"));
        assert_eq!(req2.token, None);
    }

    // ── Exchange ───────────────────────────────────────────────────────

    #[test]
    fn test_exchange_reference_query_defaults_and_type_rename() {
        let q: ExchangeReferenceQuery =
            serde_json::from_str(r#"{"provider": "changelly_crypto"}"#).unwrap();
        assert_eq!(q.provider, "changelly_crypto");
        assert!(q.kind.is_none());
        assert!(q.currency_type.is_none());
        assert!(q.flow.is_none());
        assert!(q.from.is_none());
        assert!(q.to.is_none());

        // `type` is a Rust keyword — the field rides a serde rename.
        let q: ExchangeReferenceQuery = serde_json::from_str(
            r#"{"provider": "changelly_fiat", "kind": "currencies", "type": "crypto", "flow": "sell"}"#,
        )
        .unwrap();
        assert_eq!(q.currency_type.as_deref(), Some("crypto"));
        assert_eq!(q.flow.as_deref(), Some("sell"));
    }

    #[test]
    fn test_exchange_reference_response_skips_none_data() {
        let resp = ExchangeReferenceResponse {
            success: true,
            message: "OK".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("data"));
    }

    #[test]
    fn test_exchange_quote_request_minimal() {
        let json = r#"{
            "provider": "changelly_crypto",
            "direction": "crypto_to_crypto",
            "from_currency": "xlm",
            "to_currency": "usdcxlm",
            "amount_from": "125.5"
        }"#;
        let req: ExchangeQuoteRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.provider, "changelly_crypto");
        assert_eq!(req.direction, "crypto_to_crypto");
        assert_eq!(req.amount_from, "125.5");
        assert!(req.rate_type.is_none());
        assert!(req.country.is_none());
        assert!(req.state.is_none());
        assert!(req.user_ip.is_none());
        assert!(req.source_country.is_none());
        assert!(req.destination_country.is_none());
        assert!(req.source_chain.is_none());
        assert!(req.destination_chain.is_none());
        assert!(req.customer_type.is_none());
    }

    #[test]
    fn test_exchange_quote_request_fiat_fields() {
        let json = r#"{
            "provider": "changelly_fiat",
            "direction": "fiat_to_crypto",
            "from_currency": "USD",
            "to_currency": "USDC",
            "amount_from": "100",
            "rate_type": "fixed",
            "country": "US",
            "state": "AZ",
            "user_ip": "203.0.113.9"
        }"#;
        let req: ExchangeQuoteRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.rate_type.as_deref(), Some("fixed"));
        assert_eq!(req.country.as_deref(), Some("US"));
        assert_eq!(req.state.as_deref(), Some("AZ"));
        assert_eq!(req.user_ip.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn test_exchange_quote_response_skips_none_quotes() {
        let resp = ExchangeQuoteResponse {
            success: false,
            message: "changelly_fiat is not configured".to_string(),
            quotes: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("quotes"));

        let resp = ExchangeQuoteResponse {
            success: true,
            message: "ok".to_string(),
            quotes: Some(serde_json::json!([{"rate": "0.35"}])),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"quotes\""));
    }

    #[test]
    fn test_create_exchange_order_request_minimal() {
        let json = r#"{
            "account_id": "payala1",
            "provider": "changelly_crypto",
            "direction": "crypto_to_crypto",
            "from_currency": "xlm",
            "to_currency": "usdcxlm",
            "amount_from": "125.5"
        }"#;
        let req: CreateExchangeOrderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.account_id, "payala1");
        assert!(req.payout_address.is_none());
        assert!(req.refund_address.is_none());
        assert!(req.rate_id.is_none());
        assert!(req.quote_id.is_none());
        assert!(req.provider_code.is_none());
        assert!(req.customer_uuid.is_none());
        assert!(req.is_self_transfer.is_none());
        assert!(req.beneficiary.is_none());
        assert!(req.payout_instrument.is_none());
        assert!(req.source_payment_instrument.is_none());
    }

    #[test]
    fn test_create_exchange_order_request_owlpay_passthrough() {
        // OwlPay beneficiary/instrument objects ride through untyped.
        let json = r#"{
            "account_id": "payala1",
            "provider": "owlpay",
            "direction": "fiat_to_crypto",
            "from_currency": "USD",
            "to_currency": "USDC",
            "amount_from": "250",
            "quote_id": "quote_123",
            "customer_uuid": "cus_abc",
            "is_self_transfer": true,
            "beneficiary": {"name": "Jane"},
            "payout_instrument": {"chain": "stellar", "wallet_address": "GABC"}
        }"#;
        let req: CreateExchangeOrderRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.quote_id.as_deref(), Some("quote_123"));
        assert_eq!(req.customer_uuid.as_deref(), Some("cus_abc"));
        assert_eq!(req.is_self_transfer, Some(true));
        assert_eq!(req.beneficiary, Some(serde_json::json!({"name": "Jane"})));
        assert_eq!(
            req.payout_instrument.as_ref().and_then(|v| v.get("chain")),
            Some(&serde_json::json!("stellar"))
        );
    }

    #[test]
    fn test_exchange_order_response_skips_none_order() {
        let resp = ExchangeOrderResponse {
            success: true,
            message: "ok".to_string(),
            order: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("\"order\""));
    }

    #[test]
    fn test_exchange_order_detail_serializes() {
        let order_id = Uuid::new_v4();
        let detail = ExchangeOrderDetail {
            order_id,
            payala_account_id: "payala1".to_string(),
            provider: "changelly_crypto".to_string(),
            direction: "crypto_to_crypto".to_string(),
            from_currency: "xlm".to_string(),
            to_currency: "usdcxlm".to_string(),
            amount_from: "125.5".to_string(),
            amount_to: None,
            status: "awaiting_deposit".to_string(),
            provider_status: Some("waiting".to_string()),
            provider_order_id: "abc123".to_string(),
            payin_address: Some("GABC".to_string()),
            payin_extra_id: None,
            payout_address: Some("GDEF".to_string()),
            payout_extra_id: None,
            redirect_url: None,
            transfer_instructions: None,
            btxid: None,
            last_error: None,
            created_at: "2026-08-03T12:00:00Z".to_string(),
            updated_at: None,
        };
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["order_id"], serde_json::json!(order_id.to_string()));
        assert_eq!(json["status"], "awaiting_deposit");
        assert_eq!(json["provider_status"], "waiting");
        assert_eq!(json["amount_from"], "125.5");
        assert_eq!(json["amount_to"], serde_json::Value::Null);
        assert_eq!(json["created_at"], "2026-08-03T12:00:00Z");
    }

    #[test]
    fn test_list_exchange_orders_query_defaults() {
        let q: ListExchangeOrdersQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.page, 1);
        assert_eq!(q.per_page, 20);
        assert!(q.status.is_none());
        assert!(q.provider.is_none());
        assert!(q.account_id.is_none());
    }

    #[test]
    fn test_get_exchange_order_query_default_refresh_false() {
        let q: GetExchangeOrderQuery = serde_json::from_str("{}").unwrap();
        assert!(!q.refresh);
        let q: GetExchangeOrderQuery = serde_json::from_str(r#"{"refresh":true}"#).unwrap();
        assert!(q.refresh);
    }

    #[test]
    fn test_exchange_providers_response_shape() {
        let resp = ExchangeProvidersResponse {
            providers: vec![ExchangeProviderStatus {
                provider: "owlpay".to_string(),
                enabled: false,
                directions: vec!["fiat_to_crypto".to_string(), "crypto_to_fiat".to_string()],
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["providers"][0]["provider"], "owlpay");
        assert_eq!(json["providers"][0]["enabled"], false);
        assert_eq!(json["providers"][0]["directions"][1], "crypto_to_fiat");
    }

    // ── Exchange constants ↔ migration 029 DDL drift guards ────────────

    #[test]
    fn test_valid_exchange_providers_match_ddl() {
        // Mirrors chk_exchange_order_provider in 029_create_exchange_order.sql.
        assert_eq!(
            crate::constants::VALID_EXCHANGE_PROVIDERS,
            &["owlpay", "changelly_crypto", "changelly_fiat"]
        );
    }

    #[test]
    fn test_valid_exchange_directions_match_ddl() {
        // Mirrors chk_exchange_order_direction in 029_create_exchange_order.sql.
        assert_eq!(
            crate::constants::VALID_EXCHANGE_DIRECTIONS,
            &["fiat_to_crypto", "crypto_to_fiat", "crypto_to_crypto"]
        );
    }

    #[test]
    fn test_valid_exchange_statuses_match_ddl() {
        // Mirrors chk_exchange_order_status in 029_create_exchange_order.sql,
        // in DDL order.
        assert_eq!(
            crate::constants::VALID_EXCHANGE_STATUSES,
            &[
                "created",
                "awaiting_deposit",
                "processing",
                "on_hold",
                "completed",
                "failed",
                "refunded",
                "expired"
            ]
        );
    }

    #[test]
    fn test_terminal_exchange_statuses_partition_valid_set() {
        assert_eq!(crate::constants::TERMINAL_EXCHANGE_STATUSES.len(), 4);
        for s in crate::constants::TERMINAL_EXCHANGE_STATUSES {
            assert!(
                crate::constants::VALID_EXCHANGE_STATUSES.contains(s),
                "terminal status {} must be a valid status",
                s
            );
        }
        // The remaining four are the non-terminal set scanned by the reconcile
        // poller (idx_exchange_order_pending's WHERE list in migration 029).
        for s in ["created", "awaiting_deposit", "processing", "on_hold"] {
            assert!(
                !crate::constants::TERMINAL_EXCHANGE_STATUSES.contains(&s),
                "status {} must not be terminal",
                s
            );
        }
    }
}
