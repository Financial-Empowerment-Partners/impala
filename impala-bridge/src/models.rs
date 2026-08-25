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

/// Upper bound on `page`, chosen so `(page - 1) * per_page` cannot come close
/// to overflowing `i64` at the maximum `per_page` of 100. Paging this deep is
/// already pathological — the client wants a filter, not page ten million.
pub(crate) const MAX_PAGE: u64 = 10_000_000;

impl PaginationParams {
    /// Return clamped `(per_page, offset)` suitable for SQL LIMIT/OFFSET.
    /// `per_page` is clamped to `[1, 100]`, `page` to `[1, MAX_PAGE]`.
    ///
    /// The page bound is load-bearing, not cosmetic: `page` is a client-
    /// supplied `u64`, and casting an unbounded one to `i64` wraps negative
    /// (`u64::MAX as i64 == -1`), which produced a negative OFFSET that
    /// Postgres rejects — turning a query parameter into a 500. Clamping in
    /// the `u64` domain before the cast keeps the arithmetic in range.
    pub fn clamped(&self) -> (i64, i64) {
        let per_page = self.per_page.clamp(1, 100) as i64;
        let page = self.page.clamp(1, MAX_PAGE) as i64;
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

/// Internal enrollment row, including the TOTP shared secret. Used only by the
/// verification path — deliberately NOT `Serialize`, so it cannot be returned
/// from a handler by accident.
#[derive(Deserialize, sqlx::FromRow)]
#[allow(dead_code)] // full row shape; the verify path reads only `secret`
pub struct MfaEnrollment {
    pub account_id: String,
    pub mfa_type: String,
    pub secret: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: bool,
}

/// What `GET /mfa` returns: enrollment state without the second factor itself.
///
/// The TOTP secret is write-once — it is shown at enrollment (inside the
/// provisioning URI) and never again. Returning it from a readable endpoint
/// would let anyone holding a token for the account, including a stolen
/// short-lived one or a least-privilege role, clone the second factor
/// permanently and survive a password reset.
#[derive(Serialize, sqlx::FromRow)]
pub struct MfaEnrollmentView {
    pub account_id: String,
    pub mfa_type: String,
    pub enabled: bool,
    /// Whether a shared secret is on file, without disclosing it.
    pub configured: bool,
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
    /// Present when the write left an SMS number awaiting confirmation. The
    /// client should collect the code and submit it to `POST /notify/verify`;
    /// until then no SMS is delivered to this row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_required: Option<bool>,
    /// Whether a code was actually sent. `false` means the row is pending but
    /// nothing went out (SMS delivery unconfigured, or the send failed) — the
    /// client should offer `POST /notify/verify/send`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_sent: Option<bool>,
}

impl NotifyResponse {
    /// A response that says nothing about verification (non-SMS writes, and
    /// every rejection path).
    pub fn plain(success: bool, message: impl Into<String>, id: Option<i32>) -> Self {
        NotifyResponse {
            success,
            message: message.into(),
            id,
            verification_required: None,
            verification_sent: None,
        }
    }
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

/// `POST /notify/verify/send` — (re)issue a code to a row's `mobile`.
#[derive(Deserialize)]
pub struct SendNotifyVerificationRequest {
    pub notify_id: i32,
}

/// `POST /notify/verify` — confirm a code the recipient received.
#[derive(Deserialize)]
pub struct VerifyNotifyRequest {
    pub notify_id: i32,
    pub code: String,
}

#[derive(Serialize)]
pub struct NotifyVerificationResponse {
    pub success: bool,
    pub message: String,
    /// The row's verification state after this call. Lets a client refresh its
    /// view without a follow-up `GET /notify`.
    pub verified: bool,
}

/// The row fields the verification flow needs, and nothing else.
///
/// `mobile_verified` is computed as `mobile_verified_at IS NOT NULL`: the flow
/// only ever asks whether the number is confirmed, never when.
#[derive(sqlx::FromRow)]
pub struct NotifyVerificationTarget {
    pub account_id: String,
    pub medium: String,
    pub mobile: Option<String>,
    pub mobile_verified: bool,
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
    /// When the recipient confirmed `mobile`, RFC3339. Absent means SMS for
    /// this row is inert — `dispatch_event` skips it.
    pub mobile_verified_at: Option<String>,
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
    /// `ok` | `degraded` — `degraded` means at least one imported provider
    /// credential could not be used at startup, so that provider is disabled
    /// for this process. Deliberately NOT reflected in `/readyz`: the
    /// orchestrator acts on readiness, and one unreadable credential row must
    /// degrade a provider rather than cycle every task in the fleet.
    pub key_resolution: String,
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
    /// Ask the bridge to LOCK this price and reserve the pool capacity behind
    /// it (conversion reserve only). Best-effort: when no lock is available
    /// the response is exactly what it is today.
    #[serde(default)]
    pub reserve_lock: Option<bool>,
    /// Required with `reserve_lock` for crypto->crypto shapes: the trustline
    /// check and the lock are both bound to THIS address.
    #[serde(default)]
    pub payout_address: Option<String>,
    #[serde(default)]
    pub payout_extra_id: Option<String>,
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
    /// Present only when the bridge issued a price lock. Absent means "no
    /// lock available" and nothing more — a reason string would leak pool
    /// state, so reasons go to metrics instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserve_quote: Option<ReserveQuoteView>,
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
    /// A bridge-issued conversion-reserve quote id.
    ///
    /// Deliberately NOT `rate_id`: that is an opaque PROVIDER contract, and
    /// `divert_shape` refuses any order carrying one. Parsed explicitly so a
    /// malformed value yields the house 400 rather than a serde rejection.
    #[serde(default)]
    pub reserve_quote_id: Option<String>,
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

// ── Conversion reserve (admin API) ─────────────────────────────────────
//
// Same Serialize/Deserialize asymmetry as the exchange models: admin
// request bodies are Deserialize-only, ledger/status projections are
// Serialize-only (+ FromRow), so clients can never inject server-set fields.
// All amounts are i64 minor units of the named currency (migration 031).

/// `PUT /admin/exchange-reserve/policies/{provider}` body.
#[derive(Debug, Deserialize)]
pub struct ReservePolicyUpdateRequest {
    pub enabled: bool,
    /// USD cents; validated against [2000, 20000] (the $20-$200 band).
    pub threshold_usd_cents: i64,
}

/// `PUT /admin/exchange-reserve/buckets/{currency}` body.
#[derive(Debug, Deserialize)]
pub struct ReserveBucketUpdateRequest {
    pub low_water_minor: i64,
    /// Per-refund ceiling; 0 disables automatic refunds for this bucket.
    /// Absent leaves the current value (backward compatible).
    #[serde(default)]
    pub refund_max_minor: Option<i64>,
    /// Rolling-24h refund ceiling; 0 disables. There is deliberately no way
    /// to express "unlimited".
    #[serde(default)]
    pub refund_daily_max_minor: Option<i64>,
}

/// `POST /admin/exchange-reserve/entries` body (manual ledger operation).
#[derive(Debug, Deserialize)]
pub struct ReserveEntryRequest {
    pub currency: String,
    /// One of RESERVE_ADMIN_ENTRY_KINDS.
    pub kind: String,
    /// Positive magnitude for topup/withdrawal; signed for adjustments.
    pub amount_minor: i64,
    #[serde(default)]
    pub note: Option<String>,
}

/// `POST /admin/exchange-reserve/orders/{order_id}/disburse` body.
#[derive(Debug, Deserialize)]
pub struct ReserveDisburseRequest {
    /// Actual USD amount disbursed (cents).
    pub amount_usd_cents: i64,
    #[serde(default)]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// `POST /admin/exchange-reserve/orders/{order_id}/resolve` body.
#[derive(Debug, Deserialize)]
pub struct ReserveResolveRequest {
    /// "complete" (payout verified on-chain) or "fail" (release the hold).
    pub action: String,
    #[serde(default)]
    pub stellar_tx_hash: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// `GET /admin/exchange-reserve/forecast` query.
#[derive(Debug, Deserialize)]
pub struct ReserveForecastQuery {
    #[serde(default = "default_forecast_window")]
    pub window_days: i64,
    #[serde(default = "default_forecast_window")]
    pub target_days: i64,
}

pub(crate) fn default_forecast_window() -> i64 {
    30
}

/// One reserve bucket in the status view.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveBucketView {
    pub currency: String,
    pub minor_scale: i16,
    pub available_minor: i64,
    pub held_minor: i64,
    pub low_water_minor: i64,
    pub refund_max_minor: i64,
    pub refund_daily_max_minor: i64,
    /// Live on-chain balance of the matching asset (best-effort; None when
    /// Horizon is unreachable). Lets admins see ledger-vs-chain drift.
    #[sqlx(skip)]
    pub onchain_balance: Option<String>,
}

/// One provider policy in the status view.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReservePolicyView {
    pub provider: String,
    pub enabled: bool,
    pub threshold_usd_cents: i64,
    /// False for providers with no buildable fulfillment path
    /// (changelly_fiat) — enabling them is refused.
    #[sqlx(skip)]
    pub supported: bool,
    pub updated_at: String,
}

/// Non-terminal reserve order counts (the admin work queues).
#[derive(Debug, Default, Serialize)]
pub struct ReservePendingCounts {
    pub awaiting_deposit: i64,
    pub processing: i64,
    pub on_hold: i64,
    /// processing orders waiting on an admin fiat disbursement.
    pub awaiting_disbursement: i64,
    /// Refund obligations waiting on the driver or on an admin.
    pub refunds_queued: i64,
    pub refunds_needs_review: i64,
    pub refunds_frozen: i64,
}

/// `GET /admin/exchange-reserve` response.
#[derive(Debug, Serialize)]
pub struct ReserveStatusResponse {
    pub configured: bool,
    /// Master switch for automatic refunds (DB-backed, default false).
    pub refunds_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_ttl_secs: Option<u64>,
    pub buckets: Vec<ReserveBucketView>,
    pub policies: Vec<ReservePolicyView>,
    pub pending: ReservePendingCounts,
}

/// One journal row (`GET /admin/exchange-reserve/entries`).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveEntryView {
    pub entry_id: Uuid,
    pub currency: String,
    pub kind: String,
    pub delta: i64,
    pub held_delta: i64,
    pub balance_after: i64,
    pub held_after: i64,
    pub order_id: Option<Uuid>,
    pub diverted_provider: Option<String>,
    pub stellar_tx_hash: Option<String>,
    pub admin_account_id: Option<String>,
    pub note: Option<String>,
    pub created_at: String,
}

/// `PUT /admin/exchange-reserve/replenishment/policies/{kind}`.
#[derive(Debug, Deserialize)]
pub struct ReplenishPolicyUpdateRequest {
    pub enabled: bool,
    pub target_days: i32,
    pub window_days: i32,
    pub min_need_minor: i64,
    /// 0 means unconfigured — the cycle refuses to run. Not "unlimited".
    pub max_spend_minor: i64,
    pub daily_spend_cap_minor: i64,
    pub cooldown_secs: i32,
    /// Float never spent: fees and the Stellar base reserve, or the payout
    /// buffer.
    pub min_float_minor: i64,
    pub min_price_minor: i64,
    pub max_slippage_bps: i32,
}

/// One replenishment policy as shown to admins.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReplenishPolicyView {
    pub kind: String,
    pub enabled: bool,
    pub target_days: i32,
    pub window_days: i32,
    pub min_need_minor: i64,
    pub max_spend_minor: i64,
    pub daily_spend_cap_minor: i64,
    pub cooldown_secs: i32,
    pub min_float_minor: i64,
    pub min_price_minor: i64,
    pub max_slippage_bps: i32,
    pub updated_at: String,
}

/// One replenishment cycle.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReplenishCycleView {
    pub cycle_id: Uuid,
    pub kind: String,
    pub state: String,
    pub trigger_source: String,
    pub spend_currency: String,
    pub spend_minor: i64,
    pub recv_currency: String,
    pub quoted_recv_minor: i64,
    pub actual_recv_minor: Option<i64>,
    pub quote_pricing: Option<String>,
    pub provider: String,
    pub provider_ref: Option<String>,
    pub send_tx_hash: Option<String>,
    /// USD cents booked in transit, awaiting an admin's confirmation that
    /// the bank credit actually arrived.
    pub fiat_minor: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: String,
}

/// `GET /admin/exchange-reserve/replenishment` response.
#[derive(Debug, Serialize)]
pub struct ReplenishStatusResponse {
    pub policies: Vec<ReplenishPolicyView>,
    pub cycles: Vec<ReplenishCycleView>,
}

/// `POST /admin/exchange-reserve/replenishment/run`.
#[derive(Debug, Deserialize)]
pub struct ReplenishRunRequest {
    pub kind: String,
}

/// `POST /admin/exchange-reserve/replenishment/{cycle_id}/confirm-fiat`.
#[derive(Debug, Deserialize)]
pub struct ReplenishConfirmFiatRequest {
    /// Actual cents received, when it differs from what the provider
    /// reported. Bounded against the in-transit amount.
    #[serde(default)]
    pub amount_usd_cents: Option<i64>,
    #[serde(default)]
    pub external_ref: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// A bridge-issued locked price.
///
/// Deliberately carries NO pool internals (hold currency/amount, pricing
/// method): pool capacity is bridge-private, and echoing it would let a
/// caller probe the reserve's size.
#[derive(Debug, Serialize)]
pub struct ReserveQuoteView {
    pub quote_id: Uuid,
    pub from_currency: String,
    pub to_currency: String,
    pub amount_from: String,
    /// The locked payout. Creating an order with
    /// `reserve_quote_id = quote_id` honors exactly this.
    pub amount_to: String,
    pub expires_in_secs: i64,
}

/// One refund obligation (`GET /admin/exchange-reserve/refunds`).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveRefundView {
    pub refund_id: Uuid,
    pub source_tx_hash: String,
    pub order_id: Option<Uuid>,
    pub currency: String,
    pub amount_minor: i64,
    pub refund_minor: i64,
    pub destination: String,
    pub reason: String,
    pub status: String,
    pub attempts: i32,
    pub stellar_tx_hash: Option<String>,
    pub last_error: Option<String>,
    pub skip_reason: Option<String>,
    pub resolved_by: Option<String>,
    pub created_at: String,
}

/// `POST /admin/exchange-reserve/refunds` — mint an obligation by hand for a
/// stray inflow the driver will not touch (unknown memo, wrong asset, muxed
/// or missing sender, or a pre-032 row). The destination is explicit
/// precisely because the bridge could not infer a safe one.
#[derive(Debug, Deserialize)]
pub struct ReserveRefundCreateRequest {
    pub paging_token: String,
    pub destination: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// `POST /admin/exchange-reserve/refunds/{refund_id}/resolve`.
#[derive(Debug, Deserialize)]
pub struct ReserveRefundResolveRequest {
    /// approve | cancel | sent | reverse
    pub action: String,
    /// Required for `sent`: the hash proving the refund landed.
    #[serde(default)]
    pub stellar_tx_hash: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// `PUT /admin/exchange-reserve/settings` — subsystem master switches.
#[derive(Debug, Deserialize)]
pub struct ReserveSettingsUpdateRequest {
    pub refunds_enabled: bool,
}

/// `GET /admin/exchange-reserve/refunds` query.
#[derive(Debug, Deserialize)]
pub struct ReserveRefundListQuery {
    #[serde(flatten)]
    pub page: PaginationParams,
    #[serde(default)]
    pub status: Option<String>,
}

/// One stray-inflow row (`GET /admin/exchange-reserve/unmatched`).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveUnmatchedView {
    pub paging_token: String,
    pub tx_hash: String,
    pub op_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    pub amount: String,
    pub amount_minor: Option<i64>,
    pub memo: Option<String>,
    pub matched_order_id: Option<Uuid>,
    pub reason: String,
    pub sender_address: Option<String>,
    pub sender_muxed: Option<String>,
    pub refund_id: Option<Uuid>,
    pub refund_skip_reason: Option<String>,
    pub seen_at: String,
}

/// One day of net flow for the utilization chart.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReserveDailyFlow {
    /// ISO date (UTC day bucket).
    pub day: String,
    pub outflow_minor: i64,
    pub inflow_minor: i64,
}

/// Per-currency utilization forecast. All projections are integer minor
/// units / whole days — floats never touch money here.
#[derive(Debug, Serialize)]
pub struct ReserveCurrencyForecast {
    pub currency: String,
    pub minor_scale: i16,
    pub available_minor: i64,
    pub held_minor: i64,
    pub low_water_minor: i64,
    pub low_water_breached: bool,
    pub avg_daily_outflow_minor: i64,
    /// Exponentially weighted (alpha 0.3) daily outflow — the depletion basis.
    pub ewma_daily_outflow_minor: i64,
    /// Least-squares slope of daily outflow (minor units per day): positive
    /// means utilization is growing.
    pub trend_minor_per_day: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_days_to_depletion: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_depletion_date: Option<String>,
    /// Top-up needed to sustain `target_days` of EWMA outflow.
    pub suggested_topup_minor: i64,
    pub daily: Vec<ReserveDailyFlow>,
}

/// Per-provider diversion attribution over the window.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReserveProviderUtilization {
    pub provider: String,
    pub orders: i64,
    pub volume_minor: i64,
}

/// `GET /admin/exchange-reserve/forecast` response.
#[derive(Debug, Serialize)]
pub struct ReserveForecastResponse {
    pub window_days: i64,
    pub target_days: i64,
    pub as_of: String,
    pub currencies: Vec<ReserveCurrencyForecast>,
    pub provider_utilization: Vec<ReserveProviderUtilization>,
}

// ── Admin key import ──────────────────────────────────────────────────
//
// None of these types carry secret material in the OUTBOUND direction. The
// request types do (that is the point) and are scrubbed by the handler; none
// of them derive `Debug`, so a request cannot be logged by accident.

/// Import or replace a provider credential set.
#[derive(Deserialize)]
pub struct ImportKeyRequest {
    /// Secret parts keyed by part name (`api_key`, `private_key`, …).
    /// `GET /admin/keys` lists the names each kind expects.
    #[serde(default)]
    pub parts: std::collections::BTreeMap<String, String>,
    /// Must be `true` to overwrite a credential already in effect. Default
    /// false: imports ADD by default.
    #[serde(default)]
    pub replace: bool,
    /// The fingerprint currently in effect, echoed back. A compare-and-swap
    /// token: it stops two admins clobbering each other and stops a blind
    /// replace of something never looked at. It is NOT access control — an
    /// admin can read it from `GET /admin/keys`.
    pub expected_fingerprint: Option<String>,
    /// Typed confirmation: `replace {kind} {network}`. Deliberately not the
    /// fingerprint, which is on screen and copyable — naming the network is
    /// what catches the right key in the wrong environment.
    pub confirm_phrase: Option<String>,
    /// Accept that in-flight orders/cycles may be stranded if the replacement
    /// belongs to a different provider account.
    #[serde(default)]
    pub strand_in_flight: bool,
    /// Store without proving the credential against the provider first.
    #[serde(default)]
    pub skip_verify: bool,
    /// Operator note. Stored in plaintext and shown in listings; rejected if
    /// it looks like key material.
    pub note: Option<String>,
}

/// Rotate part of a stored set without re-supplying the rest.
#[derive(Deserialize)]
pub struct MergeKeyRequest {
    #[serde(default)]
    pub set_parts: std::collections::BTreeMap<String, String>,
    /// Parts to remove. Explicit because removing one is a capability change.
    #[serde(default)]
    pub drop_parts: Vec<String>,
    pub expected_fingerprint: Option<String>,
    pub confirm_phrase: Option<String>,
    #[serde(default)]
    pub strand_in_flight: bool,
    #[serde(default)]
    pub skip_verify: bool,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeKeyRequest {
    /// The stored credential's fingerprint, echoed back.
    pub expected_fingerprint: String,
    pub confirm_phrase: Option<String>,
    /// Acknowledge what the provider falls back to after the next restart —
    /// the environment credential, or nothing at all.
    #[serde(default)]
    pub confirm_next_source: bool,
    /// Accept that in-flight orders and cycles will have nothing able to
    /// reconcile them once this credential stops being used.
    #[serde(default)]
    pub strand_in_flight: bool,
}

#[derive(Serialize)]
pub struct KeyActionResponse {
    pub success: bool,
    pub message: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_fingerprint: Option<String>,
    /// Always `rolling_restart` for credential changes: stored credentials are
    /// resolved once per process, so nothing changes until every task restarts.
    pub effective_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_shadow_note: Option<String>,
}

/// One credential kind as seen by `GET /admin/keys`: what this instance is
/// running, what is stored, and whether they differ.
#[derive(Serialize)]
pub struct KeyView {
    pub kind: &'static str,
    pub parts: Vec<&'static str>,
    pub required_parts: Vec<&'static str>,
    /// `env` | `db` | `unconfigured` — for THIS instance, fixed at startup.
    pub effective_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_version: Option<i32>,
    /// Whether the provider client was actually built and is serving requests.
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadowed_env_fingerprint: Option<String>,
    pub env_vars_set: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_fingerprint: Option<String>,
    pub per_part_fingerprints: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imported_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The fingerprint a replacement would supersede: the stored credential if
    /// there is one, otherwise whatever this instance is running. This is the
    /// value `expected_fingerprint` must equal — clients read it from here
    /// rather than choosing between the other two fingerprints themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_target_fingerprint: Option<String>,
    /// The exact phrase a replacement must echo, present whenever a
    /// replacement or revoke is possible — including for a stored credential
    /// this instance failed to resolve, which is the row most likely to need
    /// recovering.
    ///
    /// Served rather than reconstructed by clients: the admin UI and
    /// `impalactl` both need to show it, and a client that built the string
    /// itself could drift from the server and hand operators a phrase that is
    /// always rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm_phrase: Option<String>,
    /// True when a stored credential differs from the one this instance is
    /// running — the normal state between an import and the deploy that
    /// activates it.
    pub pending_restart: bool,
    /// Non-terminal orders and replenishment cycles riding this credential.
    pub in_flight_count: i64,
    pub history: Vec<crate::keys::store::CredentialRow>,
}

#[derive(Serialize)]
pub struct KeyListResponse {
    /// Whether `KEY_IMPORT_ENABLED` is on for this instance.
    pub enabled: bool,
    pub protection_backend: String,
    /// True when some kind has a stored credential that failed to resolve.
    pub degraded: bool,
    pub keys: Vec<KeyView>,
}

/// Provision a bridge-generated custodial seed.
#[derive(Deserialize)]
pub struct AdminSeedRequest {
    pub payala_account_id: String,
    /// Display name for the account record created alongside the seed.
    pub label: Option<String>,
}

/// Bring an existing secret seed under custody (non-reserve accounts only).
#[derive(Deserialize)]
pub struct AdminImportSeedRequest {
    pub payala_account_id: String,
    pub secret_seed: String,
    #[serde(default)]
    pub replace: bool,
    /// The address the stored seed currently derives, echoed back.
    pub expected_stellar_account_id: Option<String>,
    pub confirm_phrase: Option<String>,
    /// Store even when the on-chain probe says the key cannot authorize.
    #[serde(default)]
    pub skip_verify: bool,
}

/// What Horizon says about the account a submitted seed derives.
#[derive(Serialize, Clone)]
pub struct SeedProbe {
    pub exists: bool,
    /// Weight of the account's own master key. `Some(0)` means the key was
    /// disabled on chain and can authorize nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_key_weight: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_balance: Option<String>,
    pub non_native_balances: i64,
}

#[derive(Serialize)]
pub struct AdminSeedResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stellar_account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_chain: Option<SeedProbe>,
    pub effective_after: String,
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

    /// A client-supplied `page` is a `u64`; casting an unbounded one to `i64`
    /// wraps negative and Postgres rejects the resulting OFFSET, turning a
    /// query parameter into a 500. The offset must stay non-negative and in
    /// range for every input, including the extremes.
    #[test]
    fn test_pagination_extreme_page_cannot_wrap_offset() {
        for page in [u64::MAX, u64::MAX - 1, i64::MAX as u64, i64::MAX as u64 + 1] {
            let p = PaginationParams {
                page,
                per_page: 100,
            };
            let (per_page, offset) = p.clamped();
            assert_eq!(per_page, 100);
            assert!(
                offset >= 0,
                "page {page} produced a negative offset {offset}"
            );
            assert_eq!(offset, (MAX_PAGE as i64 - 1) * 100);
        }
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
            reserve_quote: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("quotes"));

        let resp = ExchangeQuoteResponse {
            success: true,
            message: "ok".to_string(),
            quotes: Some(serde_json::json!([{"rate": "0.35"}])),
            reserve_quote: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"quotes\""));
        // Backward compatibility: with no lock issued the response is
        // byte-identical to what every existing client already parses.
        assert!(!json.contains("reserve_quote"));
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
    fn test_valid_exchange_providers_match_request_vocabulary() {
        // The REQUEST vocabulary: what create/quote accept. Deliberately
        // narrower than the DB CHECK — clients can never request 'reserve'.
        assert_eq!(
            crate::constants::VALID_EXCHANGE_PROVIDERS,
            &["owlpay", "changelly_crypto", "changelly_fiat"]
        );
    }

    #[test]
    fn test_exchange_order_row_providers_match_ddl() {
        // Mirrors chk_exchange_order_provider after 031 (029 base + the
        // internal 'reserve' provider). Rows and list filters use this set.
        assert_eq!(
            crate::constants::EXCHANGE_ORDER_ROW_PROVIDERS,
            &["owlpay", "changelly_crypto", "changelly_fiat", "reserve"]
        );
        for p in crate::constants::VALID_EXCHANGE_PROVIDERS {
            assert!(
                crate::constants::EXCHANGE_ORDER_ROW_PROVIDERS.contains(p),
                "row vocabulary must be a superset of the request vocabulary"
            );
        }
        // Reserve policies may only cover providers whose orders can
        // actually be reserve-fulfilled, and never the reserve itself.
        for p in crate::constants::RESERVE_SUPPORTED_POLICY_PROVIDERS {
            assert!(crate::constants::VALID_EXCHANGE_PROVIDERS.contains(p));
        }
    }

    #[test]
    fn test_reserve_entry_kinds_match_ddl() {
        // Mirrors chk_conversion_reserve_entry_kind after
        // 032_reserve_replenish_quote_refund.sql, in DDL order.
        assert_eq!(
            crate::constants::VALID_RESERVE_ENTRY_KINDS,
            &[
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
                "quote_hold",
                "quote_release",
                "quote_consume",
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
                "refund_intent",
                "refund_sent",
                "refund_reversal"
            ]
        );
        // Admin-writable kinds are a strict subset: order-linked lifecycle
        // kinds may only ever be written by the diversion/watcher flows.
        for k in crate::constants::RESERVE_ADMIN_ENTRY_KINDS {
            assert!(crate::constants::VALID_RESERVE_ENTRY_KINDS.contains(k));
        }
        for lifecycle in ["hold", "deposit", "payout_attempt", "fulfillment"] {
            assert!(!crate::constants::RESERVE_ADMIN_ENTRY_KINDS.contains(&lifecycle));
        }
    }

    #[test]
    fn test_reserve_entry_kinds_fit_the_column() {
        // `kind` is VARCHAR(24): an over-long name fails at RUNTIME (22001)
        // on a money path, not at compile time.
        for k in crate::constants::VALID_RESERVE_ENTRY_KINDS {
            assert!(
                k.len() <= crate::constants::MAX_RESERVE_ENTRY_KIND_LEN,
                "entry kind {} exceeds VARCHAR({})",
                k,
                crate::constants::MAX_RESERVE_ENTRY_KIND_LEN
            );
        }
    }

    #[test]
    fn test_reserve_internal_kinds_are_treasury_only() {
        // Internal kinds are the bridge moving its own inventory. They are
        // excluded from utilization: counting them would inflate the EWMA
        // that sizes the next replenishment cycle, so an off-ramp would buy
        // USDC to replace the USDC it deliberately spent — a runaway loop.
        for k in crate::constants::RESERVE_INTERNAL_ENTRY_KINDS {
            assert!(
                crate::constants::VALID_RESERVE_ENTRY_KINDS.contains(k),
                "{} is not a valid entry kind",
                k
            );
            assert!(
                !crate::constants::RESERVE_ADMIN_ENTRY_KINDS.contains(k),
                "{} must not be admin-writable",
                k
            );
        }
        // Customer-facing kinds must NEVER be excluded from utilization, or
        // the forecast stops seeing real demand.
        for customer in [
            "hold",
            "deposit",
            "unmatched_deposit",
            "fulfillment",
            "disbursement",
            "refund_intent",
        ] {
            assert!(!crate::constants::RESERVE_INTERNAL_ENTRY_KINDS.contains(&customer));
        }
    }

    #[test]
    fn test_reserve_quote_vocabularies_match_ddl() {
        // Mirrors chk_conversion_reserve_quote_status / _shape in 032.
        assert_eq!(
            crate::constants::VALID_RESERVE_QUOTE_STATUSES,
            &["open", "consumed", "expired"]
        );
        // Also the provider_payload.shape literals the reserve writes.
        assert_eq!(
            crate::constants::RESERVE_QUOTE_SHAPES,
            &["auto_swap", "disburse"]
        );
    }

    #[test]
    fn test_reserve_quote_ttl_band_and_total_price_window() {
        assert_eq!(crate::constants::DEFAULT_RESERVE_QUOTE_TTL_SECS, 300);
        assert_eq!(crate::constants::RESERVE_QUOTE_TTL_MIN_SECS, 60);
        assert_eq!(crate::constants::RESERVE_QUOTE_TTL_MAX_SECS, 900);
        // The ceiling is the deposit window's own maximum: adding a lock must
        // not widen total price exposure beyond what 031 sanctioned.
        assert_eq!(
            crate::constants::RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS,
            crate::constants::RESERVE_DEPOSIT_TTL_MAX_SECS
        );
        // The maxima alone exceed the ceiling, which is why the check must
        // run at startup against the CONFIGURED pair rather than as a const
        // assert. Compared through runtime values so the assertion is not
        // constant-folded away.
        let max_pair = [
            crate::constants::RESERVE_QUOTE_TTL_MAX_SECS,
            crate::constants::RESERVE_DEPOSIT_TTL_MAX_SECS,
        ];
        assert!(
            max_pair.iter().sum::<u64>() > crate::constants::RESERVE_TOTAL_PRICE_WINDOW_MAX_SECS
        );
    }

    #[test]
    fn test_replenish_vocabularies_match_ddl() {
        // Mirrors chk_crr_kind / chk_crr_state in 032, in DDL order.
        assert_eq!(
            crate::constants::VALID_REPLENISH_KINDS,
            &["xlm_to_usdc", "usdc_to_usd"]
        );
        assert_eq!(
            crate::constants::VALID_REPLENISH_STATES,
            &[
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
                "frozen"
            ]
        );
    }

    #[test]
    fn test_terminal_cycle_states_match_inflight_index() {
        // MUST equal the uq_crr_inflight partial-index predicate in 032:
        // that index is what enforces one cycle in flight per kind, so a
        // mismatch silently breaks the guarantee.
        assert_eq!(
            crate::constants::RESERVE_TERMINAL_CYCLE_STATES,
            &["completed", "failed", "refunded"]
        );
        for s in crate::constants::RESERVE_TERMINAL_CYCLE_STATES {
            assert!(crate::constants::VALID_REPLENISH_STATES.contains(s));
        }
        // Unknown on-chain state and unverified fiat must keep blocking.
        for blocking in ["frozen", "in_transit", "sending", "sent"] {
            assert!(
                !crate::constants::RESERVE_TERMINAL_CYCLE_STATES.contains(&blocking),
                "{} must continue to occupy the in-flight slot",
                blocking
            );
        }
    }

    #[test]
    fn test_bridge_credential_vocabularies_match_ddl() {
        // Mirrors chk_bridge_credential_state in
        // 033_bridge_credential_import.sql.
        assert_eq!(
            crate::constants::VALID_CREDENTIAL_STATES,
            &["active", "superseded", "revoked"]
        );
        // The partial unique index uq_bridge_credential_active keys on
        // state = 'active'; if that literal ever leaves this vocabulary the
        // one-active-row-per-kind guarantee silently disappears.
        assert!(crate::constants::VALID_CREDENTIAL_STATES.contains(&"active"));
        // Every importable kind must be a provider the resolver can build a
        // client for, or an admin could store a credential nothing reads.
        assert_eq!(
            crate::constants::VALID_CREDENTIAL_KINDS,
            crate::constants::VALID_EXCHANGE_PROVIDERS
        );
        // Both header magics are versioned, not edited: changing one in place
        // would make every existing ciphertext fail its binding check.
        assert!(crate::constants::CREDENTIAL_HEADER_MAGIC.ends_with("-v1"));
        assert!(crate::constants::SEED_HEADER_MAGIC.ends_with("-v1"));
        assert_ne!(
            crate::constants::CREDENTIAL_HEADER_MAGIC,
            crate::constants::SEED_HEADER_MAGIC,
            "a seed blob must not open as a credential blob, or vice versa"
        );
    }

    #[test]
    fn test_reserve_refund_vocabularies_match_ddl() {
        // Mirrors chk_crr_refund_status / chk_crr_refund_reason in 032.
        assert_eq!(
            crate::constants::VALID_RESERVE_REFUND_STATUSES,
            &[
                "needs_review",
                "queued",
                "inflight",
                "sent",
                "failed",
                "frozen",
                "cancelled"
            ]
        );
        assert_eq!(
            crate::constants::VALID_RESERVE_REFUND_REASONS,
            &["late", "underpaid", "order_failed", "manual"]
        );
    }

    #[test]
    fn test_auto_refund_reasons_are_a_strict_subset() {
        for r in crate::constants::RESERVE_AUTO_REFUND_REASONS {
            assert!(crate::constants::VALID_RESERVE_REFUND_REASONS.contains(r));
        }
        // A human must name the destination for these.
        assert!(!crate::constants::RESERVE_AUTO_REFUND_REASONS.contains(&"manual"));
        // Stray-inflow reasons that are NOT auto-refundable: an unmemoed
        // deposit is how ops tops the pool up.
        for manual_only in ["no_match", "wrong_asset"] {
            assert!(!crate::constants::RESERVE_AUTO_REFUND_REASONS.contains(&manual_only));
        }
    }

    #[test]
    fn test_reserve_unmatched_reasons_match_ddl() {
        // Mirrors chk_conversion_reserve_unmatched_reason in 031.
        assert_eq!(
            crate::constants::VALID_RESERVE_UNMATCHED_REASONS,
            &["late", "underpaid", "wrong_asset", "no_match"]
        );
    }

    #[test]
    fn test_reserve_threshold_band_matches_ddl_and_requirement() {
        // Mirrors the threshold_usd_cents CHECK in 031 — the "$20 to $200"
        // band from the product requirement.
        assert_eq!(crate::constants::RESERVE_THRESHOLD_MIN_USD_CENTS, 2000);
        assert_eq!(crate::constants::RESERVE_THRESHOLD_MAX_USD_CENTS, 20000);
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
