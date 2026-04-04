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
        let per_page = (self.per_page.max(1).min(100)) as i64;
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
    pub active: bool,
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
    fn test_okta_config_response_disabled() {
        let resp = OktaConfigResponse {
            enabled: false,
            issuer: None,
            client_id: None,
            authorization_endpoint: None,
            token_endpoint: None,
            scopes: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"enabled\":false"));
        assert!(!json.contains("issuer"));
    }
}
