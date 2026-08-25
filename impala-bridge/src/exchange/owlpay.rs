//! OwlPay Harbor API client: fiat<->USDC on/off-ramp via the quote-first v2
//! transfer flow (`POST /api/v2/transfers/quotes` → `POST /api/v2/transfers`).
//!
//! Auth is a static `X-API-KEY` header on every request; transfer-creating
//! POSTs additionally carry an `X-Idempotency-Key`. Responses arrive wrapped
//! in a `{"data": {...}}` envelope (quotes: `data` is an array). Webhook
//! deliveries are signed Stripe-style — `harbor-signature: t=<unix>,v1=<hex>`
//! with `v1 = hex(HMAC_SHA256(secret, "{t}.{raw body}"))` — verified in
//! constant time with a replay window (see [`OwlPayProvider::verify_webhook`]).

use hmac::{Hmac, KeyInit, Mac};
use log::{error, warn};
use serde_json::Value;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::constants::{
    EXCHANGE_STATUS_AWAITING_DEPOSIT, EXCHANGE_STATUS_COMPLETED, EXCHANGE_STATUS_EXPIRED,
    EXCHANGE_STATUS_FAILED, EXCHANGE_STATUS_ON_HOLD, EXCHANGE_STATUS_PROCESSING,
    EXCHANGE_STATUS_REFUNDED, EXCHANGE_WEBHOOK_REPLAY_WINDOW_SECS,
};
use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;

/// Longest provider `message` we echo back to clients in a `BadRequest`.
const MAX_PROVIDER_MESSAGE_CHARS: usize = 200;

/// Longest provider-issued id ("quote_...", "transfer_...") we interpolate
/// into a URL path (matches the exchange_order.provider_order_id column).
const MAX_PROVIDER_REF_LEN: usize = 128;

/// Shared OwlPay Harbor state (present as an Extension only when
/// `OWLPAY_API_KEY` is set). Holds the API key and optional webhook signing
/// secret — deliberately NO `Debug` derive so key material can never be
/// formatted into logs or errors.
pub struct OwlPayProvider {
    http_client: reqwest::Client,
    /// Harbor base URL without trailing slash. Default is the public sandbox;
    /// the production host is issued by OwlPay after sandbox integration.
    base_url: String,
    /// Harbor `X-API-KEY` value (OWLPAY_API_KEY).
    api_key: String,
    /// Webhook signing secret `whs_...` (OWLPAY_WEBHOOK_SECRET). When absent,
    /// webhook deliveries are rejected and order state advances by poll only.
    webhook_secret: Option<String>,
    /// The secret from the previous credential version, accepted alongside the
    /// current one for the duration of the rotation overlap. Never used to
    /// SIGN anything — only to verify a delivery already in flight.
    previous_webhook_secret: Option<String>,
}

/// Build the shared OwlPay provider from an already-resolved credential set.
///
/// The set comes from [`crate::keys::store::resolve_all`] — the environment by
/// default, or an admin-imported `bridge_credential` row. `Err` is reserved for
/// configured-but-nonsensical state so startup fails closed on the money path.
///
/// `previous_webhook_secret` is the secret from the most recently superseded
/// credential version, still inside the overlap grace. Without it, rotating the
/// webhook secret would reject every delivery OwlPay signed before the cutover
/// and is still retrying — the same reason `JWT_SECRET_PREVIOUS` exists.
///
/// It is resolved once, at startup, like every other credential: this process
/// accepts it until this process restarts. Scrubbing the superseded credential
/// bounds how long a FUTURE process can load it; it does not shorten the
/// overlap for one already running.
pub fn build_owlpay_provider(
    config: &Config,
    parts: &crate::keys::CredentialParts,
    previous: Option<&crate::keys::CredentialParts>,
) -> Result<Arc<OwlPayProvider>, String> {
    let api_key = parts
        .get("api_key")
        .ok_or_else(|| "owlpay: credential set has no api_key".to_string())?
        .to_string();
    let webhook_secret = parts.get("webhook_secret").map(str::to_string);
    if webhook_secret.is_none() {
        warn!("owlpay: no webhook secret configured; webhook deliveries will be rejected (poll-only order updates)");
    }
    // Only carried forward when the CURRENT secret differs, so a rotation that
    // did not touch this part cannot leave a stale duplicate accepted.
    let previous_webhook_secret = previous
        .and_then(|p| p.get("webhook_secret"))
        .filter(|prev| Some(*prev) != webhook_secret.as_deref())
        .map(str::to_string);
    if previous_webhook_secret.is_some() {
        warn!(
            "owlpay: honouring the previous webhook secret during the rotation overlap. \
             It was loaded at startup and this process keeps accepting it until IT \
             restarts — scrubbing the superseded credential stops a FUTURE process \
             loading it, not this one. Restart the fleet to end the overlap early."
        );
    }

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.http_client_timeout_secs))
        .build()
        .map_err(|e| format!("owlpay: failed to build HTTP client: {}", e))?;

    Ok(Arc::new(OwlPayProvider {
        http_client,
        base_url: config.owlpay_api_url.trim_end_matches('/').to_string(),
        api_key,
        webhook_secret,
        previous_webhook_secret,
    }))
}

/// Recompute the Harbor signature under one secret and compare in constant time.
///
/// Both sides are 64-char lowercase hex (the header parser normalizes case),
/// so `ct_eq` compares equal-length buffers.
fn signature_matches(secret: &str, t: i64, body: &[u8], presented_hex: &str) -> bool {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected_hex = hex::encode(mac.finalize().into_bytes());
    expected_hex
        .as_bytes()
        .ct_eq(presented_hex.as_bytes())
        .into()
}

impl OwlPayProvider {
    /// `POST /api/v2/transfers/quotes` — lock FX pricing, fees, settlement
    /// route and expiry for a prospective transfer. Harbor returns `data` as
    /// an ARRAY of quotes; the raw envelope is passed through to the caller.
    pub async fn create_quote(&self, body: &Value) -> Result<Value, AppError> {
        let url = format!("{}/api/v2/transfers/quotes", self.base_url);
        self.send_json(
            self.request(reqwest::Method::POST, &url).json(body),
            "create_quote",
        )
        .await
    }

    /// `GET /api/v2/transfers/quotes/{quote_id}/requirements` — the JSON
    /// Schema describing the corridor-specific create-transfer body for a
    /// quote (beneficiary_info, payout_instrument, transfer_purpose, ...).
    pub async fn get_quote_requirements(&self, quote_id: &str) -> Result<Value, AppError> {
        if !is_valid_provider_ref(quote_id) {
            return Err(AppError::BadRequest("Invalid quote id".to_string()));
        }
        let url = format!(
            "{}/api/v2/transfers/quotes/{}/requirements",
            self.base_url, quote_id
        );
        self.send_json(
            self.request(reqwest::Method::GET, &url),
            "get_quote_requirements",
        )
        .await
    }

    /// `POST /api/v2/transfers` — create the on/off-ramp transfer from a
    /// valid quote. `idempotency_key` (our exchange_order UUID) is sent as
    /// `X-Idempotency-Key` so retries can never double-create a transfer.
    pub async fn create_transfer(
        &self,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<OwlPayTransfer, AppError> {
        let url = format!("{}/api/v2/transfers", self.base_url);
        let value = self
            .send_json(
                self.request(reqwest::Method::POST, &url)
                    .header("X-Idempotency-Key", idempotency_key)
                    .json(body),
                "create_transfer",
            )
            .await?;
        OwlPayTransfer::from_response(value).map_err(|e| {
            error!(
                "owlpay: create_transfer: malformed transfer response: {}",
                e
            );
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `GET /api/v2/transfers/{transfer_uuid}` — poll transfer state.
    pub async fn get_transfer(&self, transfer_uuid: &str) -> Result<OwlPayTransfer, AppError> {
        if !is_valid_provider_ref(transfer_uuid) {
            return Err(AppError::BadRequest("Invalid transfer id".to_string()));
        }
        let url = format!("{}/api/v2/transfers/{}", self.base_url, transfer_uuid);
        let value = self
            .send_json(self.request(reqwest::Method::GET, &url), "get_transfer")
            .await?;
        OwlPayTransfer::from_response(value).map_err(|e| {
            error!("owlpay: get_transfer: malformed transfer response: {}", e);
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// Verify a Harbor webhook delivery.
    ///
    /// Header shape: `harbor-signature: t=<unix>,v1=<hex>` where
    /// `v1 = hex(HMAC_SHA256(webhook_secret, "{t}.{raw request body}"))` —
    /// the same construction as `events::sign`. The digest comparison is
    /// constant-time, and the timestamp must satisfy
    /// `|now - t| <= EXCHANGE_WEBHOOK_REPLAY_WINDOW_SECS`. The window is
    /// INCLUSIVE: a delivery exactly at the ±300s edge is accepted; one
    /// second beyond it is rejected.
    ///
    /// Returns `Unauthorized` on any verification failure (no detail leaks to
    /// the caller) and `BadRequest` when no webhook secret is configured.
    pub fn verify_webhook(
        &self,
        signature_header: &str,
        body: &[u8],
        now_unix: i64,
    ) -> Result<(), AppError> {
        let secret = self
            .webhook_secret
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("OwlPay webhook is not configured".to_string()))?;

        let (t, presented_hex) = match parse_harbor_signature(signature_header) {
            Some(parsed) => parsed,
            None => {
                warn!("owlpay: verify_webhook: malformed harbor-signature header");
                return Err(AppError::Unauthorized);
            }
        };

        // Replay guard before any HMAC work; checked_sub fails closed on
        // pathological timestamps instead of wrapping.
        let skew = match now_unix.checked_sub(t) {
            Some(s) => s,
            None => return Err(AppError::Unauthorized),
        };
        if skew.abs() > EXCHANGE_WEBHOOK_REPLAY_WINDOW_SECS {
            warn!(
                "owlpay: verify_webhook: timestamp outside replay window (skew {}s)",
                skew
            );
            return Err(AppError::Unauthorized);
        }

        // Try the active secret, then — only if it does not match — the
        // previous one from an in-progress rotation. Both comparisons are
        // constant-time and unconditional (no early return between them), so
        // the overlap does not turn signature checking into a timing oracle
        // for which secret matched.
        let matched = signature_matches(secret, t, body, &presented_hex)
            | self
                .previous_webhook_secret
                .as_deref()
                .map(|prev| signature_matches(prev, t, body, &presented_hex))
                .unwrap_or(false);

        if matched {
            Ok(())
        } else {
            warn!("owlpay: verify_webhook: signature mismatch");
            Err(AppError::Unauthorized)
        }
    }

    /// Start a request with the headers every Harbor call carries.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.http_client
            .request(method, url)
            .header("X-API-KEY", self.api_key.as_str())
            .header(reqwest::header::USER_AGENT, "impala-bridge")
    }

    /// Send a Harbor request and map the response per the house error policy:
    /// 401/403 = our key problem (log loudly, generic internal error — never
    /// leak auth detail to clients); 400/422 = provider validation error
    /// (surface its sanitized `message`); 429 = rate limited; anything else
    /// (incl. transport) = generic internal error.
    async fn send_json(
        &self,
        request: reqwest::RequestBuilder,
        context: &'static str,
    ) -> Result<Value, AppError> {
        let res = request.send().await.map_err(|e| {
            error!("owlpay: {}: request failed: {}", context, e);
            AppError::InternalError("Exchange provider error".to_string())
        })?;

        let status = res.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            error!(
                "owlpay: {}: request rejected ({}); check OWLPAY_API_KEY",
                context, status
            );
            return Err(AppError::InternalError(
                "Exchange provider error".to_string(),
            ));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("owlpay: {}: rate limited by provider", context);
            return Err(AppError::RateLimited { retry_after: 1 });
        }
        if status == reqwest::StatusCode::BAD_REQUEST
            || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        {
            let body = res.json::<Value>().await.unwrap_or(Value::Null);
            let message = provider_error_message(&body);
            warn!(
                "owlpay: {}: provider rejected request ({}): {}",
                context, status, message
            );
            return Err(AppError::BadRequest(message));
        }
        if !status.is_success() {
            error!("owlpay: {}: unexpected status {}", context, status);
            return Err(AppError::InternalError(
                "Exchange provider error".to_string(),
            ));
        }

        res.json::<Value>().await.map_err(|e| {
            error!("owlpay: {}: failed to parse response: {}", context, e);
            AppError::InternalError("Exchange provider error".to_string())
        })
    }
}

/// The subset of a Harbor transfer object the bridge tracks, plus the full
/// raw object for the `provider_payload` JSONB column.
#[derive(Debug, Clone)]
pub struct OwlPayTransfer {
    /// Harbor transfer id (`transfer_...`).
    pub uuid: String,
    /// Raw OwlPay status (map with [`map_owlpay_status`]).
    pub status: String,
    /// `"on-ramp"` | `"off-ramp"` when present.
    pub transfer_type: Option<String>,
    /// On-ramp: wire-in bank details (incl. the mandatory `narrative` memo);
    /// off-ramp: `instruction_chain`/`instruction_address`/`instruction_memo`.
    pub transfer_instructions: Option<Value>,
    /// `destination.amount` (falling back to `receipt.final_amount`) as a
    /// decimal string — never parsed into a float.
    pub destination_amount: Option<String>,
    /// The full (envelope-unwrapped) transfer object.
    pub raw: Value,
}

impl OwlPayTransfer {
    /// Parse a Harbor transfer from an API response or webhook payload.
    /// Tolerates both the documented `{"data": {...}}` envelope and a bare
    /// transfer object (webhook handlers may pass the already-unwrapped
    /// `data`). `raw` holds the unwrapped object either way.
    ///
    /// Pure and infallible on I/O; the error string names the missing field
    /// only (safe to log — callers map it to a generic client error).
    pub fn from_response(value: Value) -> Result<Self, String> {
        let obj = match value.get("data") {
            Some(data) if data.is_object() => data,
            _ => &value,
        };

        let uuid = obj
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| "transfer object missing uuid".to_string())?
            .to_string();
        let status = obj
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "transfer object missing status".to_string())?
            .to_string();
        let transfer_type = obj.get("type").and_then(Value::as_str).map(str::to_string);
        let transfer_instructions = obj
            .get("transfer_instructions")
            .filter(|v| !v.is_null())
            .cloned();
        let destination_amount = amount_field(obj.get("destination"), "amount")
            .or_else(|| amount_field(obj.get("receipt"), "final_amount"));

        Ok(OwlPayTransfer {
            uuid,
            status,
            transfer_type,
            transfer_instructions,
            destination_amount,
            raw: obj.clone(),
        })
    }
}

/// Map a raw OwlPay transfer status (lowercase, per the Harbor docs) onto the
/// internal exchange_order status vocabulary. Unknown statuses map to
/// `processing` so a new provider state never strands an order terminally
/// (callers may `warn!` on unknowns).
pub fn map_owlpay_status(s: &str) -> &'static str {
    match s {
        "pending_customer_transfer_start" => EXCHANGE_STATUS_AWAITING_DEPOSIT,
        "pending_customer_transfer_complete" | "pending_external" | "pending_harbor" => {
            EXCHANGE_STATUS_PROCESSING
        }
        "on_hold" | "request_for_information" | "pending_customer" => EXCHANGE_STATUS_ON_HOLD,
        "completed" => EXCHANGE_STATUS_COMPLETED,
        "refunded" => EXCHANGE_STATUS_REFUNDED,
        "expired" => EXCHANGE_STATUS_EXPIRED,
        "cancelled" | "reject" | "rejected" | "error" => EXCHANGE_STATUS_FAILED,
        _ => EXCHANGE_STATUS_PROCESSING,
    }
}

/// Parse a `harbor-signature` header: strictly `t=<unix>,v1=<hex>` (Harbor
/// sends exactly these two fields in this order; anything else — missing,
/// reordered, or extra parts — fails closed). Returns the timestamp and the
/// signature hex normalized to lowercase (64 chars, i.e. HMAC-SHA256).
pub(crate) fn parse_harbor_signature(header: &str) -> Option<(i64, String)> {
    let mut parts = header.split(',');
    let t_part = parts.next()?.trim();
    let v1_part = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }

    let t_str = t_part.strip_prefix("t=")?;
    let sig = v1_part.strip_prefix("v1=")?;

    // Digits only (rejects sign/whitespace); parse catches overflow.
    if t_str.is_empty() || !t_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let t: i64 = t_str.parse().ok()?;

    if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((t, sig.to_ascii_lowercase()))
}

/// Extract the provider's human-readable error `message` (top-level or nested
/// under `error`) for a client-facing `BadRequest`. Control characters are
/// replaced with spaces and the result is truncated to
/// `MAX_PROVIDER_MESSAGE_CHARS` on a char boundary.
fn provider_error_message(body: &Value) -> String {
    let msg = body
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
        })
        .unwrap_or("Exchange provider rejected the request");
    msg.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_PROVIDER_MESSAGE_CHARS)
        .collect()
}

/// Read `container[key]` as a decimal-string amount. Amounts stay strings
/// end-to-end; a JSON number is kept via its literal serialization only
/// (display data — never arithmetic).
fn amount_field(container: Option<&Value>, key: &str) -> Option<String> {
    match container?.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Provider-issued ids (`quote_...`, `transfer_...`) are interpolated into
/// URL paths; restrict them to a safe charset so a corrupted or malicious id
/// can never alter the request path. Handlers validate earlier — this is
/// defense in depth.
fn is_valid_provider_ref(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_PROVIDER_REF_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Pinned webhook vector: the expected hex was computed independently with
    // Python's hmac + hashlib (hmac.new(secret, f"{t}.{body}".encode(),
    // hashlib.sha256).hexdigest()). It pins the wire format byte-identically
    // across sha2/hmac crate upgrades; the test itself never shells out.
    const VECTOR_SECRET: &str = "whs_9f8c1f2ab34d56e7";
    const VECTOR_T: i64 = 1_700_000_000;
    const VECTOR_BODY: &str =
        r#"{"data":{"object":"transfer","uuid":"transfer_01hx5k9q","status":"completed"}}"#;
    const VECTOR_HEX: &str = "ce81da9200c6cd964a79c4f8ae604098bd50f9021442d5ddd936561898fb832f";

    fn test_provider(webhook_secret: Option<&str>) -> OwlPayProvider {
        test_provider_with_previous(webhook_secret, None)
    }

    fn test_provider_with_previous(
        webhook_secret: Option<&str>,
        previous: Option<&str>,
    ) -> OwlPayProvider {
        OwlPayProvider {
            http_client: reqwest::Client::new(),
            base_url: "https://harbor-sandbox.owlpay.com".to_string(),
            api_key: "test_api_key".to_string(),
            webhook_secret: webhook_secret.map(str::to_string),
            previous_webhook_secret: previous.map(str::to_string),
        }
    }

    /// Recompute a harbor `v1` signature so window-boundary tests can build
    /// valid headers at arbitrary timestamps.
    fn sign(secret: &str, t: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn header_for(secret: &str, t: i64, body: &[u8]) -> String {
        format!("t={},v1={}", t, sign(secret, t, body))
    }

    // ── parse_harbor_signature ──

    #[test]
    fn parses_well_formed_header() {
        let sig = "ab".repeat(32);
        let parsed = parse_harbor_signature(&format!("t=1700000000,v1={}", sig)).unwrap();
        assert_eq!(parsed, (1_700_000_000, sig));
    }

    #[test]
    fn parse_tolerates_surrounding_whitespace_and_normalizes_case() {
        let parsed = parse_harbor_signature(&format!(" t=42 , v1={} ", "AB".repeat(32))).unwrap();
        assert_eq!(parsed, (42, "ab".repeat(32)));
    }

    #[test]
    fn parse_rejects_missing_parts() {
        assert_eq!(parse_harbor_signature(""), None);
        assert_eq!(parse_harbor_signature("t=1700000000"), None);
        assert_eq!(
            parse_harbor_signature(&format!("v1={}", "ab".repeat(32))),
            None
        );
        assert_eq!(parse_harbor_signature("t=,v1="), None);
        assert_eq!(
            parse_harbor_signature(&format!("t=,v1={}", "ab".repeat(32))),
            None
        );
    }

    #[test]
    fn parse_rejects_extra_parts() {
        let sig = "ab".repeat(32);
        assert_eq!(
            parse_harbor_signature(&format!("t=1,v1={},v2={}", sig, sig)),
            None
        );
        assert_eq!(parse_harbor_signature(&format!("t=1,v1={},", sig)), None);
    }

    #[test]
    fn parse_rejects_reordered_parts() {
        // Harbor sends t first; anything else fails closed.
        assert_eq!(
            parse_harbor_signature(&format!("v1={},t=1", "ab".repeat(32))),
            None
        );
    }

    #[test]
    fn parse_rejects_malformed_timestamp() {
        let sig = "ab".repeat(32);
        assert_eq!(parse_harbor_signature(&format!("t=abc,v1={}", sig)), None);
        assert_eq!(parse_harbor_signature(&format!("t=-5,v1={}", sig)), None);
        assert_eq!(parse_harbor_signature(&format!("t=1.5,v1={}", sig)), None);
        // i64 overflow
        assert_eq!(
            parse_harbor_signature(&format!("t=99999999999999999999,v1={}", sig)),
            None
        );
    }

    #[test]
    fn parse_rejects_malformed_signature() {
        // wrong length
        assert_eq!(parse_harbor_signature("t=1,v1=abcd"), None);
        assert_eq!(
            parse_harbor_signature(&format!("t=1,v1={}", "ab".repeat(33))),
            None
        );
        // right length, non-hex
        assert_eq!(
            parse_harbor_signature(&format!("t=1,v1={}", "zz".repeat(32))),
            None
        );
        // missing key prefixes entirely
        assert_eq!(
            parse_harbor_signature(&format!("1,{}", "ab".repeat(32))),
            None
        );
    }

    // ── verify_webhook ──

    #[test]
    fn verify_matches_pinned_python_vector() {
        let provider = test_provider(Some(VECTOR_SECRET));
        let header = format!("t={},v1={}", VECTOR_T, VECTOR_HEX);
        provider
            .verify_webhook(&header, VECTOR_BODY.as_bytes(), VECTOR_T)
            .expect("pinned vector must verify");
        // and our test signer agrees with the independent Python computation
        assert_eq!(
            sign(VECTOR_SECRET, VECTOR_T, VECTOR_BODY.as_bytes()),
            VECTOR_HEX
        );
    }

    #[test]
    fn verify_matches_second_pinned_vector() {
        // hmac.new(b"whs_test", b"1.{}", hashlib.sha256).hexdigest()
        let provider = test_provider(Some("whs_test"));
        let header = "t=1,v1=ea8ac856c9ac780184bcac46bbb2f5f44244013bf4f900207e4d24b095a934d8";
        provider
            .verify_webhook(header, b"{}", 1)
            .expect("second pinned vector must verify");
    }

    #[test]
    fn verify_accepts_uppercase_hex() {
        let provider = test_provider(Some(VECTOR_SECRET));
        let header = format!("t={},v1={}", VECTOR_T, VECTOR_HEX.to_ascii_uppercase());
        assert!(provider
            .verify_webhook(&header, VECTOR_BODY.as_bytes(), VECTOR_T)
            .is_ok());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let provider = test_provider(Some(VECTOR_SECRET));
        let header = format!("t={},v1={}", VECTOR_T, VECTOR_HEX);
        let tampered = VECTOR_BODY.replace("completed", "refunded");
        assert!(matches!(
            provider.verify_webhook(&header, tampered.as_bytes(), VECTOR_T),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let provider = test_provider(Some("whs_other_secret"));
        let header = format!("t={},v1={}", VECTOR_T, VECTOR_HEX);
        assert!(matches!(
            provider.verify_webhook(&header, VECTOR_BODY.as_bytes(), VECTOR_T),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_rejects_resigned_timestamp_mismatch() {
        // Signature valid for t but header claims t+1: MAC must fail.
        let provider = test_provider(Some(VECTOR_SECRET));
        let header = format!("t={},v1={}", VECTOR_T + 1, VECTOR_HEX);
        assert!(matches!(
            provider.verify_webhook(&header, VECTOR_BODY.as_bytes(), VECTOR_T),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_rejects_malformed_header() {
        let provider = test_provider(Some(VECTOR_SECRET));
        for header in ["", "garbage", "t=abc,v1=def", VECTOR_HEX] {
            assert!(
                matches!(
                    provider.verify_webhook(header, VECTOR_BODY.as_bytes(), VECTOR_T),
                    Err(AppError::Unauthorized)
                ),
                "header {:?} must be rejected",
                header
            );
        }
    }

    #[test]
    fn verify_replay_window_is_inclusive_at_exact_edges() {
        // Documented rule: |now - t| <= window passes; one second past fails.
        let provider = test_provider(Some(VECTOR_SECRET));
        let body = VECTOR_BODY.as_bytes();
        let header = header_for(VECTOR_SECRET, VECTOR_T, body);
        let w = EXCHANGE_WEBHOOK_REPLAY_WINDOW_SECS;

        // delivery from exactly `window` seconds ago: accepted
        assert!(provider.verify_webhook(&header, body, VECTOR_T + w).is_ok());
        // clock skew: timestamp exactly `window` seconds in the future: accepted
        assert!(provider.verify_webhook(&header, body, VECTOR_T - w).is_ok());
        // one second beyond the window either way: rejected
        assert!(matches!(
            provider.verify_webhook(&header, body, VECTOR_T + w + 1),
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            provider.verify_webhook(&header, body, VECTOR_T - w - 1),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn verify_without_secret_is_bad_request() {
        let provider = test_provider(None);
        let header = format!("t={},v1={}", VECTOR_T, VECTOR_HEX);
        match provider.verify_webhook(&header, VECTOR_BODY.as_bytes(), VECTOR_T) {
            Err(AppError::BadRequest(msg)) => {
                assert_eq!(msg, "OwlPay webhook is not configured")
            }
            other => panic!("expected BadRequest, got {:?}", other.err()),
        }
    }

    #[test]
    fn verify_errors_never_leak_the_secret() {
        let provider = test_provider(Some(VECTOR_SECRET));
        let err = provider
            .verify_webhook("t=1,v1=bad", VECTOR_BODY.as_bytes(), VECTOR_T)
            .unwrap_err();
        assert!(!format!("{}", err).contains(VECTOR_SECRET));
    }

    // ── map_owlpay_status ──

    #[test]
    fn maps_every_documented_transfer_status() {
        // Full lifecycle list from the Harbor docs (GET /api/v2/transfers),
        // plus "rejected" (defensive alias for "reject").
        let cases = [
            (
                "pending_customer_transfer_start",
                EXCHANGE_STATUS_AWAITING_DEPOSIT,
            ),
            (
                "pending_customer_transfer_complete",
                EXCHANGE_STATUS_PROCESSING,
            ),
            ("pending_external", EXCHANGE_STATUS_PROCESSING),
            ("pending_harbor", EXCHANGE_STATUS_PROCESSING),
            ("on_hold", EXCHANGE_STATUS_ON_HOLD),
            ("request_for_information", EXCHANGE_STATUS_ON_HOLD),
            ("pending_customer", EXCHANGE_STATUS_ON_HOLD),
            ("completed", EXCHANGE_STATUS_COMPLETED),
            ("refunded", EXCHANGE_STATUS_REFUNDED),
            ("expired", EXCHANGE_STATUS_EXPIRED),
            ("cancelled", EXCHANGE_STATUS_FAILED),
            ("reject", EXCHANGE_STATUS_FAILED),
            ("rejected", EXCHANGE_STATUS_FAILED),
            ("error", EXCHANGE_STATUS_FAILED),
        ];
        for (raw, want) in cases {
            assert_eq!(map_owlpay_status(raw), want, "status {:?}", raw);
        }
    }

    #[test]
    fn unknown_status_maps_to_processing() {
        assert_eq!(
            map_owlpay_status("some_future_status"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(map_owlpay_status(""), EXCHANGE_STATUS_PROCESSING);
        // provider statuses are lowercase; the mapper is deliberately exact-match
        assert_eq!(map_owlpay_status("COMPLETED"), EXCHANGE_STATUS_PROCESSING);
    }

    // ── OwlPayTransfer::from_response ──

    fn transfer_json() -> Value {
        json!({
            "object": "transfer",
            "uuid": "transfer_01hx5k9q",
            "status": "pending_customer_transfer_start",
            "type": "on-ramp",
            "transfer_instructions": {
                "account_number": "123456789",
                "routing_number": "021000021",
                "narrative": "HARBOR-REF-42"
            },
            "destination": { "asset": "USDC", "chain": "stellar", "amount": "99.50" }
        })
    }

    #[test]
    fn from_response_unwraps_data_envelope() {
        let t = OwlPayTransfer::from_response(json!({ "data": transfer_json() })).unwrap();
        assert_eq!(t.uuid, "transfer_01hx5k9q");
        assert_eq!(t.status, "pending_customer_transfer_start");
        assert_eq!(t.transfer_type.as_deref(), Some("on-ramp"));
        assert_eq!(t.destination_amount.as_deref(), Some("99.50"));
        assert_eq!(
            t.transfer_instructions.as_ref().unwrap()["narrative"],
            "HARBOR-REF-42"
        );
        // raw is the unwrapped object, not the envelope
        assert_eq!(t.raw["uuid"], "transfer_01hx5k9q");
        assert!(t.raw.get("data").is_none());
    }

    #[test]
    fn from_response_accepts_bare_object() {
        let t = OwlPayTransfer::from_response(transfer_json()).unwrap();
        assert_eq!(t.uuid, "transfer_01hx5k9q");
        assert_eq!(t.raw["uuid"], "transfer_01hx5k9q");
    }

    #[test]
    fn from_response_rejects_missing_fields() {
        let err = OwlPayTransfer::from_response(json!({ "status": "completed" })).unwrap_err();
        assert!(err.contains("uuid"));
        let err = OwlPayTransfer::from_response(json!({ "uuid": "transfer_x" })).unwrap_err();
        assert!(err.contains("status"));
        // a non-object `data` (quotes return arrays) is not a transfer
        assert!(OwlPayTransfer::from_response(json!({ "data": [1, 2] })).is_err());
    }

    #[test]
    fn from_response_amount_accepts_number_and_falls_back_to_receipt() {
        let mut v = transfer_json();
        v["destination"]["amount"] = json!(100.5);
        let t = OwlPayTransfer::from_response(v).unwrap();
        assert_eq!(t.destination_amount.as_deref(), Some("100.5"));

        let mut v = transfer_json();
        v["destination"] = json!({ "asset": "USDC" });
        v["receipt"] = json!({ "final_asset": "USDC", "final_amount": "98.76" });
        let t = OwlPayTransfer::from_response(v).unwrap();
        assert_eq!(t.destination_amount.as_deref(), Some("98.76"));
    }

    #[test]
    fn from_response_treats_null_and_empty_as_absent() {
        let mut v = transfer_json();
        v["transfer_instructions"] = Value::Null;
        v["destination"] = json!({ "amount": "" });
        let t = OwlPayTransfer::from_response(v).unwrap();
        assert!(t.transfer_instructions.is_none());
        assert!(t.destination_amount.is_none());
    }

    // ── provider_error_message ──

    #[test]
    fn error_message_prefers_top_level_then_nested() {
        assert_eq!(
            provider_error_message(&json!({ "message": "Quote has expired" })),
            "Quote has expired"
        );
        assert_eq!(
            provider_error_message(&json!({ "error": { "message": "Invalid corridor" } })),
            "Invalid corridor"
        );
    }

    #[test]
    fn error_message_falls_back_when_absent_or_non_string() {
        let fallback = "Exchange provider rejected the request";
        assert_eq!(provider_error_message(&Value::Null), fallback);
        assert_eq!(provider_error_message(&json!({})), fallback);
        assert_eq!(provider_error_message(&json!({ "message": 42 })), fallback);
    }

    #[test]
    fn error_message_truncates_and_sanitizes() {
        let long = "x".repeat(300);
        let out = provider_error_message(&json!({ "message": long }));
        assert_eq!(out.chars().count(), MAX_PROVIDER_MESSAGE_CHARS);

        // multi-byte chars truncate on a char boundary
        let long = "é".repeat(300);
        let out = provider_error_message(&json!({ "message": long }));
        assert_eq!(out.chars().count(), MAX_PROVIDER_MESSAGE_CHARS);

        // control characters become spaces (no log/header injection)
        let out = provider_error_message(&json!({ "message": "bad\nvalue\u{7}" }));
        assert_eq!(out, "bad value ");
    }

    // ── is_valid_provider_ref ──

    #[test]
    fn provider_ref_accepts_harbor_id_shapes() {
        assert!(is_valid_provider_ref("transfer_01HX5K9Q"));
        assert!(is_valid_provider_ref("quote_abc-123"));
        assert!(is_valid_provider_ref(&"a".repeat(MAX_PROVIDER_REF_LEN)));
    }

    #[test]
    fn provider_ref_rejects_path_altering_input() {
        assert!(!is_valid_provider_ref(""));
        assert!(!is_valid_provider_ref(
            &"a".repeat(MAX_PROVIDER_REF_LEN + 1)
        ));
        assert!(!is_valid_provider_ref("../transfers"));
        assert!(!is_valid_provider_ref("a/b"));
        assert!(!is_valid_provider_ref("a?refresh=true"));
        assert!(!is_valid_provider_ref("a b"));
        assert!(!is_valid_provider_ref("transfer_ünicode"));
    }
}
