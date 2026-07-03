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
}
