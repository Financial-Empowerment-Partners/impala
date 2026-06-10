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
    /// Admin privilege, server-derived from the ADMIN_ACCOUNT_IDS allowlist at
    /// every token issuance. `#[serde(default)]` so any non-admin path decodes
    /// as `false`; clients cannot set it (HS256-signed).
    #[serde(default)]
    pub is_admin: bool,
}

// ── Pagination ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

fn default_page() -> u64 {
    1
}

fn default_per_page() -> u64 {
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

#[derive(Serialize)]
pub struct GetAccountResponse {
    pub payala_account_id: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub nickname: Option<String>,
    pub affiliation: Option<String>,
    pub gender: Option<String>,
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

// ── Okta ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OktaTokenExchangeRequest {
    pub okta_token: String,
    /// Browser clients set this to receive an HttpOnly cookie session (plus
    /// CSRF token) instead of bearer tokens. Defaults off for API clients.
    #[serde(default)]
    pub cookie_mode: bool,
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
}
