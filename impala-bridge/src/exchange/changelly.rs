//! Changelly exchange clients: crypto->crypto swaps (Exchange API v2, JSON-RPC
//! 2.0 over a single POST endpoint) and fiat<->crypto on/off-ramp (Fiat API,
//! REST). Both APIs authenticate with detached RSA PKCS#1 v1.5 + SHA-256
//! signatures over the exact bytes transmitted, so every request body / URL is
//! serialized exactly once and those same bytes are signed and sent.
//!
//! Secrets (API keys and RSA private keys) are read directly from the
//! environment at init time — never from the Debug-logged `Config` struct
//! (config.rs:203-205 rule) — and the provider structs deliberately do NOT
//! derive `Debug`.

use log::{error, info, warn};
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config::Config;
use crate::constants::{
    EXCHANGE_STATUS_AWAITING_DEPOSIT, EXCHANGE_STATUS_COMPLETED, EXCHANGE_STATUS_CREATED,
    EXCHANGE_STATUS_EXPIRED, EXCHANGE_STATUS_FAILED, EXCHANGE_STATUS_ON_HOLD,
    EXCHANGE_STATUS_PROCESSING, EXCHANGE_STATUS_REFUNDED,
};
use crate::error::AppError;

// ── Shared RSA / DER helpers ──────────────────────────────────────────────────

/// Read a secret env var, treating empty values as unset. Secrets deliberately
/// bypass `Config` so they never land in the Debug-logged struct.
fn env_secret(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Read a secret from `var`, falling back to the file named by `file_var`
/// (mounted-secret pattern, cf. FCM_SERVICE_ACCOUNT_KEY). `Ok(None)` when
/// neither is set; `Err` when the file is named but unreadable.
fn env_secret_or_file(var: &str, file_var: &str) -> Result<Option<String>, String> {
    if let Some(v) = env_secret(var) {
        return Ok(Some(v));
    }
    match env_secret(file_var) {
        Some(path) => std::fs::read_to_string(&path)
            .map(|s| Some(s.trim().to_string()))
            .map_err(|e| format!("failed to read {} ({}): {}", file_var, path, e)),
        None => Ok(None),
    }
}

/// Parse a hex-encoded PKCS#8 DER RSA private key (Changelly Exchange API v2
/// key format: PKCS#8 DER, hex-encoded). Error strings never echo key bytes.
pub(crate) fn parse_private_key_hex_pkcs8(hex_str: &str) -> Result<RsaKeyPair, String> {
    let der = hex::decode(hex_str.trim()).map_err(|_| "invalid hex encoding".to_string())?;
    RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("invalid PKCS#8 RSA private key: {}", e))
}

/// Parse a PEM RSA private key: `BEGIN RSA PRIVATE KEY` (PKCS#1) or
/// `BEGIN PRIVATE KEY` (PKCS#8). Encrypted keys are rejected.
pub(crate) fn parse_private_key_pem(pem: &str) -> Result<RsaKeyPair, String> {
    if pem.contains("ENCRYPTED") || pem.contains("Proc-Type: 4,ENCRYPTED") {
        return Err("encrypted private keys are not supported".to_string());
    }
    if pem.contains("-----BEGIN RSA PRIVATE KEY-----") {
        let der = pem_body(pem, "RSA PRIVATE KEY")?;
        RsaKeyPair::from_der(&der).map_err(|e| format!("invalid PKCS#1 RSA private key: {}", e))
    } else if pem.contains("-----BEGIN PRIVATE KEY-----") {
        let der = pem_body(pem, "PRIVATE KEY")?;
        RsaKeyPair::from_pkcs8(&der).map_err(|e| format!("invalid PKCS#8 private key: {}", e))
    } else {
        Err("expected a PEM 'RSA PRIVATE KEY' or 'PRIVATE KEY' block".to_string())
    }
}

/// Parse an RSA public key into PKCS#1 `RSAPublicKey` DER bytes (the form
/// `aws_lc_rs`' RFC 8017 verifier consumes). Accepts an SPKI PEM
/// (`BEGIN PUBLIC KEY`) or raw base64 DER in either SPKI or PKCS#1 form.
pub(crate) fn parse_public_key(input: &str) -> Result<Vec<u8>, String> {
    let der = if input.contains("-----BEGIN PUBLIC KEY-----") {
        pem_body(input, "PUBLIC KEY")?
    } else {
        let b64: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        STANDARD
            .decode(b64)
            .map_err(|e| format!("invalid base64 public key: {}", e))?
    };
    // Both encodings open with a SEQUENCE; SPKI nests an AlgorithmIdentifier
    // SEQUENCE first, while PKCS#1 RSAPublicKey starts with an INTEGER
    // (the modulus). Peek the first inner tag to tell them apart.
    let (body, _) = der_read_tlv(&der, 0x30)?;
    match body.first() {
        Some(0x30) => spki_to_pkcs1(&der),
        Some(0x02) => Ok(der),
        _ => Err("unrecognized public key DER structure".to_string()),
    }
}

/// Extract and base64-decode the body of a PEM block with the given label.
fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {}-----", label);
    let end = format!("-----END {}-----", label);
    let start = pem
        .find(&begin)
        .ok_or_else(|| format!("missing '{}' header", begin))?
        + begin.len();
    let stop = pem[start..]
        .find(&end)
        .map(|i| start + i)
        .ok_or_else(|| format!("missing '{}' footer", end))?;
    let b64: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(b64)
        .map_err(|e| format!("invalid base64 in PEM body: {}", e))
}

/// Split one DER TLV element: returns `(content, rest_after_element)`.
/// Supports definite short and long (up to 4-byte) length forms only.
fn der_read_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), String> {
    if input.len() < 2 {
        return Err("DER element truncated".to_string());
    }
    if input[0] != expected_tag {
        return Err(format!(
            "unexpected DER tag 0x{:02x} (wanted 0x{:02x})",
            input[0], expected_tag
        ));
    }
    let first = input[1] as usize;
    let (len, header_len) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return Err("unsupported DER length encoding".to_string());
        }
        if input.len() < 2 + n {
            return Err("DER length truncated".to_string());
        }
        let mut len = 0usize;
        for byte in &input[2..2 + n] {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + n)
    };
    if input.len() < header_len + len {
        return Err("DER content truncated".to_string());
    }
    Ok((
        &input[header_len..header_len + len],
        &input[header_len + len..],
    ))
}

/// Unwrap an SPKI (RFC 5280 `SubjectPublicKeyInfo`) DER into the inner PKCS#1
/// `RSAPublicKey` DER: SEQUENCE -> skip AlgorithmIdentifier SEQUENCE ->
/// BIT STRING -> skip the unused-bits byte.
fn spki_to_pkcs1(der: &[u8]) -> Result<Vec<u8>, String> {
    let (spki_body, _) = der_read_tlv(der, 0x30)?; // SubjectPublicKeyInfo
    let (_algorithm, rest) = der_read_tlv(spki_body, 0x30)?; // AlgorithmIdentifier (skipped)
    let (bit_string, _) = der_read_tlv(rest, 0x03)?; // subjectPublicKey
    match bit_string.split_first() {
        Some((0, inner)) => Ok(inner.to_vec()),
        _ => Err("SPKI BIT STRING has unexpected unused-bits prefix".to_string()),
    }
}

/// RSA PKCS#1 v1.5 + SHA-256 detached signature over `msg`, base64-encoded.
/// `msg` must be the EXACT bytes transmitted to Changelly.
fn sign_pkcs1_sha256_b64(
    key_pair: &RsaKeyPair,
    rng: &SystemRandom,
    msg: &[u8],
) -> Result<String, String> {
    let mut signature = vec![0u8; key_pair.public_modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, rng, msg, &mut signature)
        .map_err(|_| "RSA signing failed".to_string())?;
    Ok(STANDARD.encode(signature))
}

/// Verify an RSA PKCS#1 v1.5 + SHA-256 signature against a PKCS#1
/// `RSAPublicKey` DER public key.
fn verify_pkcs1_sha256(pkcs1_der: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pkcs1_der)
        .verify(msg, signature)
        .is_ok()
}

/// Strip a provider-supplied error message down to printable ASCII and at most
/// 200 chars so it is safe to return to clients verbatim.
fn sanitize_provider_message(msg: &str) -> String {
    let cleaned: String = msg
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .take(200)
        .collect();
    if cleaned.is_empty() {
        "Exchange provider rejected the request".to_string()
    } else {
        cleaned
    }
}

// ── Changelly crypto (Exchange API v2, JSON-RPC 2.0) ─────────────────────────

/// Changelly Exchange API v2 client (crypto->crypto swaps, e.g. xlm->usdcxlm).
/// Holds the partner API key and RSA signing key — intentionally NO `Debug`.
pub struct ChangellyCrypto {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    key_pair: RsaKeyPair,
    rng: SystemRandom,
}

/// Initialize the Changelly crypto client from the environment.
///
/// `Ok(None)` = unconfigured (CHANGELLY_API_KEY unset/empty). `Err(msg)` =
/// configured but invalid — the orchestrator exits so the money path fails
/// closed rather than running half-configured.
pub fn init_changelly_crypto(config: &Config) -> Result<Option<Arc<ChangellyCrypto>>, String> {
    let api_key = match env_secret("CHANGELLY_API_KEY") {
        Some(k) => k,
        None => return Ok(None),
    };
    let key_hex = env_secret_or_file("CHANGELLY_PRIVATE_KEY", "CHANGELLY_PRIVATE_KEY_FILE")?
        .ok_or_else(|| {
            "CHANGELLY_API_KEY is set but CHANGELLY_PRIVATE_KEY / CHANGELLY_PRIVATE_KEY_FILE is not"
                .to_string()
        })?;
    let key_pair = parse_private_key_hex_pkcs8(&key_hex)
        .map_err(|e| format!("CHANGELLY_PRIVATE_KEY: {}", e))?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_secs,
        ))
        .build()
        .map_err(|e| format!("failed to build Changelly HTTP client: {}", e))?;

    info!("changelly: crypto exchange provider initialized");
    Ok(Some(Arc::new(ChangellyCrypto {
        http,
        base_url: config.changelly_api_url.trim_end_matches('/').to_string(),
        api_key,
        key_pair,
        rng: SystemRandom::new(),
    })))
}

/// Serialize the JSON-RPC 2.0 envelope once; the returned string is both
/// signed and transmitted byte-for-byte.
fn jsonrpc_envelope(id: &str, method: &str, params: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

/// Map a JSON-RPC error object to an `AppError`. `-32603` doubles as
/// Changelly's rate-limit signal; the reserved server-error range stays
/// generic; everything else (invalid params, business errors like an expired
/// rateId) is client-actionable.
fn map_jsonrpc_error(code: i64, message: &str) -> AppError {
    match code {
        -32603 => AppError::RateLimited { retry_after: 1 },
        -32700 | -32600 | -32601 | -32602 => {
            AppError::BadRequest(sanitize_provider_message(message))
        }
        // JSON-RPC reserved server-error range: don't leak provider internals.
        -32768..=-32000 => AppError::InternalError("Exchange provider error".to_string()),
        _ => AppError::BadRequest(sanitize_provider_message(message)),
    }
}

/// Params for the estimation methods, which require the ARRAY-of-objects form
/// (a bare object is rejected by the API).
fn estimation_params(from: &str, to: &str, amount_from: &str) -> Value {
    json!([{ "from": from, "to": to, "amountFrom": amount_from }])
}

impl ChangellyCrypto {
    /// Execute one JSON-RPC call: serialize the envelope once, sign those
    /// exact bytes (X-Api-Signature), send those bytes, then correlate the
    /// response id and map any JSON-RPC error.
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, AppError> {
        let id = Uuid::new_v4().to_string();
        let body = jsonrpc_envelope(&id, method, &params);
        let signature =
            sign_pkcs1_sha256_b64(&self.key_pair, &self.rng, body.as_bytes()).map_err(|e| {
                error!("changelly: {}: RSA signing failed: {}", method, e);
                AppError::InternalError("Exchange provider error".to_string())
            })?;

        let res = self
            .http
            .post(&self.base_url)
            .header(reqwest::header::USER_AGENT, "impala-bridge")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Api-Key", &self.api_key)
            .header("X-Api-Signature", &signature)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                error!("changelly: {} request failed: {}", method, e);
                AppError::InternalError("Exchange provider error".to_string())
            })?;

        let status = res.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("changelly: {} rate-limited (HTTP 429)", method);
            return Err(AppError::RateLimited { retry_after: 1 });
        }
        if !status.is_success() {
            error!("changelly: {} returned HTTP {}", method, status);
            return Err(AppError::InternalError(
                "Exchange provider error".to_string(),
            ));
        }

        let envelope: Value = res.json().await.map_err(|e| {
            error!("changelly: {} returned unparseable body: {}", method, e);
            AppError::InternalError("Exchange provider error".to_string())
        })?;

        // The id is client-generated per request; a mismatch means the
        // response does not belong to this call.
        if envelope.get("id").and_then(Value::as_str) != Some(id.as_str()) {
            error!("changelly: {} response id mismatch", method);
            return Err(AppError::InternalError(
                "Exchange provider error".to_string(),
            ));
        }

        if let Some(err) = envelope.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err.get("message").and_then(Value::as_str).unwrap_or("");
            let mapped = map_jsonrpc_error(code, message);
            match &mapped {
                AppError::InternalError(_) => {
                    error!("changelly: {} error code={}: {}", method, code, message);
                }
                _ => warn!("changelly: {} error code={}: {}", method, code, message),
            }
            return Err(mapped);
        }

        envelope.get("result").cloned().ok_or_else(|| {
            error!("changelly: {} response missing result", method);
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `getCurrenciesFull` — full currency metadata (network variants,
    /// extraIdName, enabled flags). Used to discover e.g. usdcxlm.
    pub async fn get_currencies_full(&self) -> Result<Value, AppError> {
        self.rpc("getCurrenciesFull", json!({})).await
    }

    /// `getPairs` — enabled trading pairs, optionally filtered by side.
    pub async fn get_pairs(&self, from: Option<&str>, to: Option<&str>) -> Result<Value, AppError> {
        let mut params = serde_json::Map::new();
        if let Some(f) = from {
            params.insert("from".to_string(), json!(f));
        }
        if let Some(t) = to {
            params.insert("to".to_string(), json!(t));
        }
        self.rpc("getPairs", Value::Object(params)).await
    }

    /// `getExchangeAmount` — float-rate estimation. Params are the required
    /// array-of-one-object form; the result array is returned as-is.
    pub async fn get_exchange_amount(
        &self,
        from: &str,
        to: &str,
        amount_from: &str,
    ) -> Result<Value, AppError> {
        self.rpc(
            "getExchangeAmount",
            estimation_params(from, to, amount_from),
        )
        .await
    }

    /// `getFixRateForAmount` — fixed-rate quote yielding a short-lived rateId.
    /// Array-of-one-object params, result array returned as-is.
    pub async fn get_fix_rate_for_amount(
        &self,
        from: &str,
        to: &str,
        amount_from: &str,
    ) -> Result<Value, AppError> {
        self.rpc(
            "getFixRateForAmount",
            estimation_params(from, to, amount_from),
        )
        .await
    }

    /// `createTransaction` — create a FLOAT-rate swap.
    pub async fn create_transaction(&self, p: &ChangellyCreateTx) -> Result<ChangellyTx, AppError> {
        let params = build_create_tx_params(p, false)?;
        let result = self.rpc("createTransaction", params).await?;
        parse_changelly_tx(&result).map_err(|e| {
            error!(
                "changelly: createTransaction returned malformed result: {}",
                e
            );
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `createFixTransaction` — create a FIXED-rate swap; requires `rate_id`
    /// and `refund_address` (auto-refund target on rate miss/timeout).
    pub async fn create_fix_transaction(
        &self,
        p: &ChangellyCreateTx,
    ) -> Result<ChangellyTx, AppError> {
        let params = build_create_tx_params(p, true)?;
        let result = self.rpc("createFixTransaction", params).await?;
        parse_changelly_tx(&result).map_err(|e| {
            error!(
                "changelly: createFixTransaction returned malformed result: {}",
                e
            );
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `getStatus` — poll a transaction; the result is a bare status string.
    pub async fn get_status(&self, id: &str) -> Result<String, AppError> {
        let result = self.rpc("getStatus", json!({ "id": id })).await?;
        result.as_str().map(str::to_string).ok_or_else(|| {
            error!("changelly: getStatus returned non-string result");
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `getTransactions` filtered by id — rich detail (amountTo, payinHash,
    /// payoutHash, ...) for reconciliation. Returns the result array as-is.
    pub async fn get_transactions_by_id(&self, id: &str) -> Result<Value, AppError> {
        self.rpc("getTransactions", json!({ "id": id })).await
    }

    /// `validateAddress` — validate a payout/refund address (and memo) before
    /// creating a transaction. Returns `(valid, provider_reason)`.
    pub async fn validate_address(
        &self,
        currency: &str,
        address: &str,
        extra_id: Option<&str>,
    ) -> Result<(bool, Option<String>), AppError> {
        let mut params = serde_json::Map::new();
        params.insert("currency".to_string(), json!(currency));
        params.insert("address".to_string(), json!(address));
        if let Some(memo) = extra_id {
            params.insert("extraId".to_string(), json!(memo));
        }
        let result = self.rpc("validateAddress", Value::Object(params)).await?;
        let valid = result
            .get("result")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let message = result
            .get("message")
            .and_then(Value::as_str)
            .map(sanitize_provider_message);
        Ok((valid, message))
    }
}

/// Inputs for `createTransaction` / `createFixTransaction`.
#[derive(Debug, Clone)]
pub struct ChangellyCreateTx {
    pub from: String,
    pub to: String,
    pub amount_from: String,
    pub address: String,
    pub extra_id: Option<String>,
    pub refund_address: Option<String>,
    pub refund_extra_id: Option<String>,
    /// Fixed-rate only (from `getFixRateForAmount`).
    pub rate_id: Option<String>,
}

/// Normalized createTransaction/createFixTransaction result. `payin_extra_id`,
/// when non-null, is MANDATORY for the user to include with the payin (e.g.
/// the Stellar memo) — funds sent without it can be lost or delayed.
#[derive(Debug, Clone)]
pub struct ChangellyTx {
    pub id: String,
    pub status: String,
    pub payin_address: String,
    pub payin_extra_id: Option<String>,
    pub amount_expected_from: Option<String>,
    pub amount_expected_to: Option<String>,
    /// Fixed-rate payin deadline; a late payin expires the transaction.
    pub pay_till: Option<String>,
    pub raw: Value,
}

/// Build the single-object params for createTransaction (float) or
/// createFixTransaction (fixed). Fixed requires rateId AND refundAddress.
fn build_create_tx_params(p: &ChangellyCreateTx, fixed: bool) -> Result<Value, AppError> {
    let mut params = serde_json::Map::new();
    params.insert("from".to_string(), json!(p.from));
    params.insert("to".to_string(), json!(p.to));
    params.insert("amountFrom".to_string(), json!(p.amount_from));
    params.insert("address".to_string(), json!(p.address));
    if let Some(extra_id) = &p.extra_id {
        params.insert("extraId".to_string(), json!(extra_id));
    }
    if let Some(refund_address) = &p.refund_address {
        params.insert("refundAddress".to_string(), json!(refund_address));
    }
    if let Some(refund_extra_id) = &p.refund_extra_id {
        params.insert("refundExtraId".to_string(), json!(refund_extra_id));
    }
    if fixed {
        let rate_id = p.rate_id.as_deref().ok_or_else(|| {
            AppError::BadRequest("rate_id is required for fixed-rate exchanges".to_string())
        })?;
        if p.refund_address.is_none() {
            return Err(AppError::BadRequest(
                "refund_address is required for fixed-rate exchanges".to_string(),
            ));
        }
        params.insert("rateId".to_string(), json!(rate_id));
    }
    Ok(Value::Object(params))
}

/// Amounts are documented as decimal strings; tolerate a bare JSON number by
/// taking its literal display form (never routed through f64 arithmetic).
fn value_as_decimal_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Extract the fields the bridge persists from a create-transaction result.
fn parse_changelly_tx(result: &Value) -> Result<ChangellyTx, String> {
    let id = result
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing id".to_string())?
        .to_string();
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing status".to_string())?
        .to_string();
    let payin_address = result
        .get("payinAddress")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing payinAddress".to_string())?
        .to_string();
    Ok(ChangellyTx {
        id,
        status,
        payin_address,
        payin_extra_id: result
            .get("payinExtraId")
            .and_then(Value::as_str)
            .map(str::to_string),
        amount_expected_from: result
            .get("amountExpectedFrom")
            .and_then(value_as_decimal_string),
        amount_expected_to: result
            .get("amountExpectedTo")
            .and_then(value_as_decimal_string),
        pay_till: result
            .get("payTill")
            .and_then(Value::as_str)
            .map(str::to_string),
        raw: result.clone(),
    })
}

/// Map a Changelly Exchange API v2 status to the internal exchange_order
/// status vocabulary. Unknown values map to `processing` (callers may warn!).
pub fn map_changelly_crypto_status(s: &str) -> &'static str {
    match s {
        "new" => EXCHANGE_STATUS_CREATED,
        "waiting" => EXCHANGE_STATUS_AWAITING_DEPOSIT,
        "confirming" | "exchanging" | "sending" => EXCHANGE_STATUS_PROCESSING,
        "finished" => EXCHANGE_STATUS_COMPLETED,
        "failed" => EXCHANGE_STATUS_FAILED,
        "refunded" => EXCHANGE_STATUS_REFUNDED,
        "hold" => EXCHANGE_STATUS_ON_HOLD,
        "overdue" | "expired" => EXCHANGE_STATUS_EXPIRED,
        _ => EXCHANGE_STATUS_PROCESSING,
    }
}

// ── Changelly fiat (Fiat API, REST) ───────────────────────────────────────────

/// Changelly Fiat API client (fiat<->crypto via aggregated providers).
/// Holds the API key and RSA signing key — intentionally NO `Debug`.
pub struct ChangellyFiat {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
    key_pair: RsaKeyPair,
    rng: SystemRandom,
    /// Changelly's callback public key as PKCS#1 `RSAPublicKey` DER, used to
    /// verify `x-callback-signature` on webhooks. `None` = webhooks rejected.
    callback_public_key: Option<Vec<u8>>,
}

/// Initialize the Changelly Fiat client from the environment.
///
/// `Ok(None)` = unconfigured (CHANGELLY_FIAT_API_KEY unset/empty). `Err(msg)` =
/// configured but invalid (the orchestrator exits — money path fails closed).
pub fn init_changelly_fiat(config: &Config) -> Result<Option<Arc<ChangellyFiat>>, String> {
    let api_key = match env_secret("CHANGELLY_FIAT_API_KEY") {
        Some(k) => k,
        None => return Ok(None),
    };
    let key_pem = env_secret_or_file(
        "CHANGELLY_FIAT_PRIVATE_KEY",
        "CHANGELLY_FIAT_PRIVATE_KEY_FILE",
    )?
    .ok_or_else(|| {
        "CHANGELLY_FIAT_API_KEY is set but CHANGELLY_FIAT_PRIVATE_KEY / CHANGELLY_FIAT_PRIVATE_KEY_FILE is not"
            .to_string()
    })?;
    let key_pair = parse_private_key_pem(&key_pem)
        .map_err(|e| format!("CHANGELLY_FIAT_PRIVATE_KEY: {}", e))?;

    let callback_public_key = match env_secret("CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY") {
        Some(k) => Some(
            parse_public_key(&k)
                .map_err(|e| format!("CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY: {}", e))?,
        ),
        None => {
            warn!(
                "changelly_fiat: CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY not set; \
                 webhook signature verification will fail closed"
            );
            None
        }
    };

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_secs,
        ))
        .build()
        .map_err(|e| format!("failed to build Changelly Fiat HTTP client: {}", e))?;

    info!("changelly_fiat: fiat exchange provider initialized");
    Ok(Some(Arc::new(ChangellyFiat {
        http,
        base_url: config
            .changelly_fiat_api_url
            .trim_end_matches('/')
            .to_string(),
        api_key,
        key_pair,
        rng: SystemRandom::new(),
        callback_public_key,
    })))
}

/// Offer-query inputs shared by `GET /v1/offers` and `GET /v1/sell/offers`.
#[derive(Debug, Clone, Default)]
pub struct FiatOfferQuery {
    pub currency_from: String,
    pub currency_to: String,
    pub amount_from: String,
    pub country: String,
    /// Required when `country == "US"`.
    pub state: Option<String>,
    pub ip: String,
    pub provider_code: Option<String>,
    pub payment_method: Option<String>,
    pub external_user_id: Option<String>,
}

/// Normalized create-order response (buy and sell share the shape).
#[derive(Debug, Clone)]
pub struct FiatOrder {
    pub order_id: String,
    pub status: Option<String>,
    pub redirect_url: Option<String>,
    pub raw: Value,
}

/// Build the request URL once; `Url::as_str()` is then byte-identical for
/// both the signature payload and the request line.
fn build_url(base_url: &str, path: &str, query: &[(&str, String)]) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(&format!("{}{}", base_url, path))
        .map_err(|e| format!("invalid URL {}{}: {}", base_url, path, e))?;
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

/// Signature payload = full URL exactly as sent + compact JSON body, with the
/// literal `{}` standing in for bodyless (GET) requests — per the official
/// Node SDK (`signatureUrl.toString() + JSON.stringify(data || {})`).
fn fiat_signature_payload(url_as_sent: &str, body: Option<&str>) -> String {
    format!("{}{}", url_as_sent, body.unwrap_or("{}"))
}

/// Ordered query pairs for the offer endpoints. Required params first, then
/// optionals; the ordering only needs to be consistent because the signature
/// and the request are built from the same `Url`.
///
/// `sell` selects the off-ramp variant: only `/v1/sell/offers` accepts a
/// payment-method filter, and it names it `paymentMethodCode` (the unadorned
/// `paymentMethod` spelling is a create-order *body* field). Sending the wrong
/// spelling is silently ignored by the API, which would return offers for
/// every payout method instead of the requested one.
fn offer_query_pairs(q: &FiatOfferQuery, sell: bool) -> Vec<(&'static str, String)> {
    let mut pairs = vec![
        ("currencyFrom", q.currency_from.clone()),
        ("currencyTo", q.currency_to.clone()),
        ("amountFrom", q.amount_from.clone()),
        ("country", q.country.clone()),
    ];
    if let Some(state) = &q.state {
        pairs.push(("state", state.clone()));
    }
    pairs.push(("ip", q.ip.clone()));
    if let Some(provider_code) = &q.provider_code {
        pairs.push(("providerCode", provider_code.clone()));
    }
    if sell {
        if let Some(payment_method) = &q.payment_method {
            pairs.push(("paymentMethodCode", payment_method.clone()));
        }
    }
    if let Some(external_user_id) = &q.external_user_id {
        pairs.push(("externalUserId", external_user_id.clone()));
    }
    pairs
}

/// Extract the provider's human-readable error message from a Fiat API error
/// body (`errorMessage` per the docs, `message` as a fallback).
fn fiat_error_message(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("errorMessage")
        .or_else(|| v.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Map a non-2xx Fiat API response to an `AppError`. 401/403 indicate a key
/// problem on our side — never leaked to clients.
fn map_fiat_http_error(status: u16, body: &str) -> AppError {
    match status {
        401 | 403 => AppError::InternalError("Exchange provider error".to_string()),
        429 => AppError::RateLimited { retry_after: 1 },
        400..=499 => AppError::BadRequest(sanitize_provider_message(
            &fiat_error_message(body).unwrap_or_default(),
        )),
        _ => AppError::InternalError("Exchange provider error".to_string()),
    }
}

/// The entry of a `GET /v1/orders` response (`{orders: [...], total, ...}`)
/// whose `orderId` equals `want`.
///
/// Selecting by identity rather than position is load-bearing: if the server
/// ever ignores the filter parameter it answers with the partner's whole
/// order list, and taking `orders[0]` would apply an unrelated order's status
/// to the order being reconciled.
fn find_order(v: &Value, want: &str) -> Option<Value> {
    v.get("orders")
        .and_then(Value::as_array)?
        .iter()
        .find(|o| o.get("orderId").and_then(Value::as_str) == Some(want))
        .cloned()
}

/// Extract the fields the bridge persists from a create-order response.
fn parse_fiat_order(v: &Value) -> Result<FiatOrder, String> {
    let order_id = v
        .get("orderId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing orderId".to_string())?
        .to_string();
    Ok(FiatOrder {
        order_id,
        status: v.get("status").and_then(Value::as_str).map(str::to_string),
        redirect_url: v
            .get("redirectUrl")
            .and_then(Value::as_str)
            .map(str::to_string),
        raw: v.clone(),
    })
}

impl ChangellyFiat {
    /// Execute one signed Fiat API request. The URL is built once and
    /// `url.as_str()` feeds both the signature payload and the request; the
    /// body (when present) is serialized once and those bytes are signed and
    /// sent via `.body(..)`.
    async fn request_json(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
        body: Option<&Value>,
    ) -> Result<Value, AppError> {
        let label = url.path().to_string();
        let body_str = match body {
            Some(b) => Some(serde_json::to_string(b).map_err(|e| {
                error!("changelly_fiat: {}: failed to serialize body: {}", label, e);
                AppError::InternalError("Exchange provider error".to_string())
            })?),
            None => None,
        };
        let payload = fiat_signature_payload(url.as_str(), body_str.as_deref());
        let signature = sign_pkcs1_sha256_b64(&self.key_pair, &self.rng, payload.as_bytes())
            .map_err(|e| {
                error!("changelly_fiat: {}: RSA signing failed: {}", label, e);
                AppError::InternalError("Exchange provider error".to_string())
            })?;

        let mut req = self
            .http
            .request(method, url)
            .header(reqwest::header::USER_AGENT, "impala-bridge")
            .header("X-Api-Key", &self.api_key)
            .header("X-Api-Signature", &signature);
        if let Some(body_str) = body_str {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_str);
        }

        let res = req.send().await.map_err(|e| {
            error!("changelly_fiat: {} request failed: {}", label, e);
            AppError::InternalError("Exchange provider error".to_string())
        })?;

        let status = res.status();
        let text = res.text().await.map_err(|e| {
            error!("changelly_fiat: {}: failed to read response: {}", label, e);
            AppError::InternalError("Exchange provider error".to_string())
        })?;
        if !status.is_success() {
            let mapped = map_fiat_http_error(status.as_u16(), &text);
            match &mapped {
                AppError::InternalError(_) => {
                    error!("changelly_fiat: {} returned HTTP {}", label, status);
                }
                _ => warn!("changelly_fiat: {} returned HTTP {}", label, status),
            }
            return Err(mapped);
        }

        serde_json::from_str(&text).map_err(|e| {
            error!("changelly_fiat: {} returned unparseable body: {}", label, e);
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `GET /v1/providers` — on/off-ramp provider dictionary.
    pub async fn get_providers(&self) -> Result<Value, AppError> {
        let url = build_url(&self.base_url, "/providers", &[]).map_err(internal_url_error)?;
        self.request_json(reqwest::Method::GET, url, None).await
    }

    /// `GET /v1/currencies` — supported crypto/fiat currencies, optionally
    /// filtered by `type` (crypto|fiat) and `supportedFlow` (buy|sell).
    pub async fn get_currencies(
        &self,
        r#type: Option<&str>,
        supported_flow: Option<&str>,
    ) -> Result<Value, AppError> {
        let mut query: Vec<(&str, String)> = Vec::new();
        if let Some(t) = r#type {
            query.push(("type", t.to_string()));
        }
        if let Some(flow) = supported_flow {
            query.push(("supportedFlow", flow.to_string()));
        }
        let url = build_url(&self.base_url, "/currencies", &query).map_err(internal_url_error)?;
        self.request_json(reqwest::Method::GET, url, None).await
    }

    /// `GET /v1/offers` — compare buy (fiat->crypto) quotes across providers.
    pub async fn get_offers(&self, q: &FiatOfferQuery) -> Result<Value, AppError> {
        let url = build_url(&self.base_url, "/offers", &offer_query_pairs(q, false))
            .map_err(internal_url_error)?;
        self.request_json(reqwest::Method::GET, url, None).await
    }

    /// `GET /v1/sell/offers` — compare sell (crypto->fiat) quotes.
    pub async fn get_sell_offers(&self, q: &FiatOfferQuery) -> Result<Value, AppError> {
        let url = build_url(&self.base_url, "/sell/offers", &offer_query_pairs(q, true))
            .map_err(internal_url_error)?;
        self.request_json(reqwest::Method::GET, url, None).await
    }

    /// `POST /v1/orders` — create a buy (fiat->crypto) order; the user
    /// completes KYC and payment on the returned redirect URL.
    pub async fn create_order(&self, body: &Value) -> Result<FiatOrder, AppError> {
        let url = build_url(&self.base_url, "/orders", &[]).map_err(internal_url_error)?;
        let res = self
            .request_json(reqwest::Method::POST, url, Some(body))
            .await?;
        parse_fiat_order(&res).map_err(|e| {
            error!(
                "changelly_fiat: create order returned malformed body: {}",
                e
            );
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `POST /v1/sell/orders` — create a sell (crypto->fiat) order; deposit
    /// instructions live on the provider's redirect page.
    pub async fn create_sell_order(&self, body: &Value) -> Result<FiatOrder, AppError> {
        let url = build_url(&self.base_url, "/sell/orders", &[]).map_err(internal_url_error)?;
        let res = self
            .request_json(reqwest::Method::POST, url, Some(body))
            .await?;
        parse_fiat_order(&res).map_err(|e| {
            error!(
                "changelly_fiat: create sell order returned malformed body: {}",
                e
            );
            AppError::InternalError("Exchange provider error".to_string())
        })
    }

    /// `GET /v1/orders?orderId[]=..` — fetch one order's authoritative state.
    /// `Ok(None)` when Changelly does not know the order.
    ///
    /// The documented filter is the bracketed array form; the response is then
    /// matched on `orderId` so a server-side filter miss can never hand back
    /// some other order's state.
    pub async fn get_order_by_id(&self, order_id: &str) -> Result<Option<Value>, AppError> {
        let url = build_url(
            &self.base_url,
            "/orders",
            &[("orderId[]", order_id.to_string())],
        )
        .map_err(internal_url_error)?;
        let res = self.request_json(reqwest::Method::GET, url, None).await?;
        let found = find_order(&res, order_id);
        if found.is_none()
            && res
                .get("orders")
                .and_then(Value::as_array)
                .is_some_and(|o| !o.is_empty())
        {
            error!(
                "changelly_fiat: order lookup returned {} order(s), none matching the requested id",
                res["orders"].as_array().map(Vec::len).unwrap_or(0)
            );
        }
        Ok(found)
    }

    /// `POST /v1/validate-address` — validate a destination (buy) or refund
    /// (sell) address. Returns `(valid, rejected_field)` where the field is
    /// `walletAddress` or `walletExtraId`.
    pub async fn validate_address(
        &self,
        currency: &str,
        wallet_address: &str,
        wallet_extra_id: Option<&str>,
    ) -> Result<(bool, Option<String>), AppError> {
        let mut body = serde_json::Map::new();
        body.insert("currency".to_string(), json!(currency));
        body.insert("walletAddress".to_string(), json!(wallet_address));
        if let Some(memo) = wallet_extra_id {
            body.insert("walletExtraId".to_string(), json!(memo));
        }
        let url =
            build_url(&self.base_url, "/validate-address", &[]).map_err(internal_url_error)?;
        let res = self
            .request_json(reqwest::Method::POST, url, Some(&Value::Object(body)))
            .await?;
        let valid = res.get("result").and_then(Value::as_bool).unwrap_or(false);
        let cause = res.get("cause").and_then(Value::as_str).map(str::to_string);
        Ok((valid, cause))
    }

    /// Verify a webhook's `x-callback-signature`: RSA PKCS#1 v1.5 + SHA-256
    /// over the EXACT compact string `{"orderId":"<id>"}`, signed with
    /// Changelly's callback private key. Only the orderId is signed — the
    /// rest of the payload is unauthenticated and callers must re-fetch order
    /// state. Fails closed (`Unauthorized`) when no callback key is
    /// configured.
    pub fn verify_callback(&self, order_id: &str, signature_b64: &str) -> Result<(), AppError> {
        let public_key = self.callback_public_key.as_deref().ok_or_else(|| {
            warn!("changelly_fiat: webhook received but CHANGELLY_FIAT_CALLBACK_PUBLIC_KEY is not configured");
            AppError::Unauthorized
        })?;
        let signature = STANDARD.decode(signature_b64).map_err(|_| {
            warn!("changelly_fiat: webhook signature is not valid base64");
            AppError::Unauthorized
        })?;
        // json! escapes the id, matching JSON.stringify({orderId}) exactly.
        let message = json!({ "orderId": order_id }).to_string();
        if !verify_pkcs1_sha256(public_key, message.as_bytes(), &signature) {
            warn!("changelly_fiat: webhook signature verification failed");
            return Err(AppError::Unauthorized);
        }
        Ok(())
    }

    /// The partner public API key, for constant-time comparison against the
    /// webhook's `x-callback-api-key` header (use `subtle::ct_eq` at the call
    /// site).
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

/// A malformed base URL is an operator configuration problem, not client input.
fn internal_url_error(e: String) -> AppError {
    error!("changelly_fiat: {}", e);
    AppError::InternalError("Exchange provider error".to_string())
}

/// Map a Changelly Fiat API order status to the internal exchange_order
/// status vocabulary. Unknown values map to `processing` (callers may warn!).
///
/// Only `expired`, `failed` and `complete` are final in the Fiat API. In
/// particular `refunded` ("the provider could not match the transfer to the
/// order") is mid-lifecycle and can still advance to `complete` once support
/// reconciles it, so it must NOT land on an internally terminal status — a
/// terminal row stops being polled and can never be corrected. It maps to
/// `on_hold`, which keeps reconciliation alive; the raw value is preserved in
/// `provider_status` for operators.
pub fn map_changelly_fiat_status(s: &str) -> &'static str {
    match s {
        "created" => EXCHANGE_STATUS_CREATED,
        "pending" => EXCHANGE_STATUS_PROCESSING,
        "hold" | "refunded" => EXCHANGE_STATUS_ON_HOLD,
        "expired" => EXCHANGE_STATUS_EXPIRED,
        "failed" => EXCHANGE_STATUS_FAILED,
        "complete" => EXCHANGE_STATUS_COMPLETED,
        _ => EXCHANGE_STATUS_PROCESSING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway 2048-bit RSA test keypair generated once with openssl for
    // these tests (never used anywhere else). All encodings below are the
    // SAME key: PKCS#8 PEM, PKCS#1 PEM, hex PKCS#8 DER, SPKI public PEM, and
    // base64 SPKI / PKCS#1 public DER.
    const TEST_RSA_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCpDMy/ik1mnh4u\n\
wg+qjziAxUT8zAfVwEaVHBCnfhTnWng1pYMtvLa/cD1dy6g2eESHho+nicRTQCLg\n\
gAIT8l0Cbl3Z7pEglA1ctZWesciNSxGXIfvIjhLQwPZQFUCleSGdYgxYs2DbuuGt\n\
THKMmAJaGabr2n4EvklsxKqwQXqxKIkgr9l8Ahvf0WQNuezqsf9/S08YWxY5msID\n\
Vldgc62xTkP92ukyR76MlRW3fwI+/fyALDz/W9QplSPatVX7+7Qx10z2Ya4aytS2\n\
PLSTs/HlpVQ4dyoiRXr42tI/mTXqzT39jWB81vGIZqpzMUnaD5BLKRb5TdWu6KHn\n\
sw1AMA2VAgMBAAECggEAATh7p2vV32HjClWI0LXR47JthphW1wA0xtYjHO8RMtvi\n\
lnbc+/oPgJrMgzU5m6TLGU+0ftbXLdnaD8LISjOU4H0d86b3H3G9qGM2+//cfTb5\n\
6AoatRnyF4yAkambVj+ulxj5W7SauzknAwKLOzMVgLEwlSYa8mkbVVU5WN0svtW4\n\
BLb29IrMa0TRTNMkcVDKbOgYEFHkwPxoQErJCxduw0Tkn0nQK1jJUFLeuEk6/4Dj\n\
tuMqSeCTjIe8PEjTOnO7HyqEKXQqBFegCM3s40wQV0+uInr1xdezs5ybLdTNIROS\n\
tnAdWQqUmyD6xFsyar7L/m6Y6aURsimZvfArcRWzewKBgQDVWLkAJGncfwTPhxDC\n\
S0Akuy/uaVRHlyIjolFU54aG/bx4hTgBtez+lUjhbDLVbDgV5KnlqtOdjcNWRWLT\n\
LcSgfALM7iRZjIwu3zFw1VY9+tZ5Vb+03Ky8oDOHnaUOo5U8nWKqfrGYfD4cBaef\n\
UD63BBoN0esfPKgpk0xYrM/hqwKBgQDK2O/g/U6KYi2cQS0Fbw4lHxjhyvzMOg1M\n\
gXVt9l6kkEhlZe4fn2M9zOyorNsImwkYsQ8YIN051eYF/Tw1N85HqVn70TE2c0/f\n\
EUxtFepIe+8cfUUir5C4iPGE5jSNNA8e7jDHELGnGyTJhbVMl+uTQFMNMjcOgDv2\n\
R7KB+OMNvwKBgQC59mUDd7oCpYDm978m7HrTyYoFETCSWm06jFDCZjE/10oB73Ub\n\
IJ2cZzmorCw/Fd5pTvC8rUNZkOkUeNSkaL98d7vlLyrmF3lVndy1km9jBRMPnivF\n\
FZlHrYhdDI+EDBiYRkNrg5V/6cQlntQ2LLcNxfiD1VdR2ghmfOtOXAuzkwKBgQCC\n\
BXv9I2DsovHJbp2FFiJi+QPh91MDNVLA71puGbWgljtRg3yXGHtsaaZomCPt6DJ0\n\
eUnLlYU4RTskK6YkFplKperf1r9Mv606tsPeSGXcAFTMVh+ylAaXwm/NWCHnQK9Q\n\
jC0H7FNzYZq68dG8PsTpphmWI9HWoavNuTdayEYB0QKBgQDKlBSuAv5yPAVO4VEK\n\
eR+q9THTFwubXg7M1TRu3lPgfJ731CQsdYz0iygPOu4K4sO1tAMe+kVekNMJxP90\n\
a+zuoQKSJIn81AWG6fSJnTjbc4GMbqV9STG82bFLS0fJRjD0p80wtFmBLPY5Pc50\n\
XLoUSc2x5XIbvt7Hn1i1ehMZ9Q==\n\
-----END PRIVATE KEY-----\n";

    const TEST_RSA_PKCS1_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpQIBAAKCAQEAqQzMv4pNZp4eLsIPqo84gMVE/MwH1cBGlRwQp34U51p4NaWD\n\
Lby2v3A9XcuoNnhEh4aPp4nEU0Ai4IACE/JdAm5d2e6RIJQNXLWVnrHIjUsRlyH7\n\
yI4S0MD2UBVApXkhnWIMWLNg27rhrUxyjJgCWhmm69p+BL5JbMSqsEF6sSiJIK/Z\n\
fAIb39FkDbns6rH/f0tPGFsWOZrCA1ZXYHOtsU5D/drpMke+jJUVt38CPv38gCw8\n\
/1vUKZUj2rVV+/u0MddM9mGuGsrUtjy0k7Px5aVUOHcqIkV6+NrSP5k16s09/Y1g\n\
fNbxiGaqczFJ2g+QSykW+U3Vruih57MNQDANlQIDAQABAoIBAAE4e6dr1d9h4wpV\n\
iNC10eOybYaYVtcANMbWIxzvETLb4pZ23Pv6D4CazIM1OZukyxlPtH7W1y3Z2g/C\n\
yEozlOB9HfOm9x9xvahjNvv/3H02+egKGrUZ8heMgJGpm1Y/rpcY+Vu0mrs5JwMC\n\
izszFYCxMJUmGvJpG1VVOVjdLL7VuAS29vSKzGtE0UzTJHFQymzoGBBR5MD8aEBK\n\
yQsXbsNE5J9J0CtYyVBS3rhJOv+A47bjKkngk4yHvDxI0zpzux8qhCl0KgRXoAjN\n\
7ONMEFdPriJ69cXXs7Ocmy3UzSETkrZwHVkKlJsg+sRbMmq+y/5umOmlEbIpmb3w\n\
K3EVs3sCgYEA1Vi5ACRp3H8Ez4cQwktAJLsv7mlUR5ciI6JRVOeGhv28eIU4AbXs\n\
/pVI4Wwy1Ww4FeSp5arTnY3DVkVi0y3EoHwCzO4kWYyMLt8xcNVWPfrWeVW/tNys\n\
vKAzh52lDqOVPJ1iqn6xmHw+HAWnn1A+twQaDdHrHzyoKZNMWKzP4asCgYEAytjv\n\
4P1OimItnEEtBW8OJR8Y4cr8zDoNTIF1bfZepJBIZWXuH59jPczsqKzbCJsJGLEP\n\
GCDdOdXmBf08NTfOR6lZ+9ExNnNP3xFMbRXqSHvvHH1FIq+QuIjxhOY0jTQPHu4w\n\
xxCxpxskyYW1TJfrk0BTDTI3DoA79keygfjjDb8CgYEAufZlA3e6AqWA5ve/Jux6\n\
08mKBREwklptOoxQwmYxP9dKAe91GyCdnGc5qKwsPxXeaU7wvK1DWZDpFHjUpGi/\n\
fHe75S8q5hd5VZ3ctZJvYwUTD54rxRWZR62IXQyPhAwYmEZDa4OVf+nEJZ7UNiy3\n\
DcX4g9VXUdoIZnzrTlwLs5MCgYEAggV7/SNg7KLxyW6dhRYiYvkD4fdTAzVSwO9a\n\
bhm1oJY7UYN8lxh7bGmmaJgj7egydHlJy5WFOEU7JCumJBaZSqXq39a/TL+tOrbD\n\
3khl3ABUzFYfspQGl8JvzVgh50CvUIwtB+xTc2GauvHRvD7E6aYZliPR1qGrzbk3\n\
WshGAdECgYEAypQUrgL+cjwFTuFRCnkfqvUx0xcLm14OzNU0bt5T4Hye99QkLHWM\n\
9IsoDzruCuLDtbQDHvpFXpDTCcT/dGvs7qECkiSJ/NQFhun0iZ0423OBjG6lfUkx\n\
vNmxS0tHyUYw9KfNMLRZgSz2OT3OdFy6FEnNseVyG77ex59YtXoTGfU=\n\
-----END RSA PRIVATE KEY-----\n";

    const TEST_RSA_PKCS8_DER_HEX: &str = "308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100a90cccbf8a4d669e1e2ec20faa8f3880c544fccc07d5c046951c10a77e14e75a7835a5832dbcb6bf703d5dcba836784487868fa789c4534022e0800213f25d026e5dd9ee9120940d5cb5959eb1c88d4b119721fbc88e12d0c0f6501540a579219d620c58b360dbbae1ad4c728c98025a19a6ebda7e04be496cc4aab0417ab1288920afd97c021bdfd1640db9eceab1ff7f4b4f185b16399ac20356576073adb14e43fddae93247be8c9515b77f023efdfc802c3cff5bd4299523dab555fbfbb431d74cf661ae1acad4b63cb493b3f1e5a55438772a22457af8dad23f9935eacd3dfd8d607cd6f18866aa733149da0f904b2916f94dd5aee8a1e7b30d40300d9502030100010282010001387ba76bd5df61e30a5588d0b5d1e3b26d869856d70034c6d6231cef1132dbe29676dcfbfa0f809acc8335399ba4cb194fb47ed6d72dd9da0fc2c84a3394e07d1df3a6f71f71bda86336fbffdc7d36f9e80a1ab519f2178c8091a99b563fae9718f95bb49abb392703028b3b331580b13095261af2691b55553958dd2cbed5b804b6f6f48acc6b44d14cd3247150ca6ce8181051e4c0fc68404ac90b176ec344e49f49d02b58c95052deb8493aff80e3b6e32a49e0938c87bc3c48d33a73bb1f2a8429742a0457a008cdece34c10574fae227af5c5d7b3b39c9b2dd4cd211392b6701d590a949b20fac45b326abecbfe6e98e9a511b22999bdf02b7115b37b02818100d558b9002469dc7f04cf8710c24b4024bb2fee695447972223a25154e78686fdbc78853801b5ecfe9548e16c32d56c3815e4a9e5aad39d8dc3564562d32dc4a07c02ccee24598c8c2edf3170d5563dfad67955bfb4dcacbca033879da50ea3953c9d62aa7eb1987c3e1c05a79f503eb7041a0dd1eb1f3ca829934c58accfe1ab02818100cad8efe0fd4e8a622d9c412d056f0e251f18e1cafccc3a0d4c81756df65ea490486565ee1f9f633dcceca8acdb089b0918b10f1820dd39d5e605fd3c3537ce47a959fbd13136734fdf114c6d15ea487bef1c7d4522af90b888f184e6348d340f1eee30c710b1a71b24c985b54c97eb9340530d32370e803bf647b281f8e30dbf02818100b9f6650377ba02a580e6f7bf26ec7ad3c98a051130925a6d3a8c50c266313fd74a01ef751b209d9c6739a8ac2c3f15de694ef0bcad435990e91478d4a468bf7c77bbe52f2ae61779559ddcb5926f6305130f9e2bc5159947ad885d0c8f840c189846436b83957fe9c4259ed4362cb70dc5f883d55751da08667ceb4e5c0bb3930281810082057bfd2360eca2f1c96e9d85162262f903e1f753033552c0ef5a6e19b5a0963b51837c97187b6c69a6689823ede832747949cb958538453b242ba62416994aa5eadfd6bf4cbfad3ab6c3de4865dc0054cc561fb2940697c26fcd5821e740af508c2d07ec5373619abaf1d1bc3ec4e9a6199623d1d6a1abcdb9375ac84601d102818100ca9414ae02fe723c054ee1510a791faaf531d3170b9b5e0eccd5346ede53e07c9ef7d4242c758cf48b280f3aee0ae2c3b5b4031efa455e90d309c4ff746beceea102922489fcd40586e9f4899d38db73818c6ea57d4931bcd9b14b4b47c94630f4a7cd30b459812cf6393dce745cba1449cdb1e5721bbedec79f58b57a1319f5";

    const TEST_RSA_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQzMv4pNZp4eLsIPqo84\n\
gMVE/MwH1cBGlRwQp34U51p4NaWDLby2v3A9XcuoNnhEh4aPp4nEU0Ai4IACE/Jd\n\
Am5d2e6RIJQNXLWVnrHIjUsRlyH7yI4S0MD2UBVApXkhnWIMWLNg27rhrUxyjJgC\n\
Whmm69p+BL5JbMSqsEF6sSiJIK/ZfAIb39FkDbns6rH/f0tPGFsWOZrCA1ZXYHOt\n\
sU5D/drpMke+jJUVt38CPv38gCw8/1vUKZUj2rVV+/u0MddM9mGuGsrUtjy0k7Px\n\
5aVUOHcqIkV6+NrSP5k16s09/Y1gfNbxiGaqczFJ2g+QSykW+U3Vruih57MNQDAN\n\
lQIDAQAB\n\
-----END PUBLIC KEY-----\n";

    const TEST_RSA_SPKI_DER_B64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqQzMv4pNZp4eLsIPqo84gMVE/MwH1cBGlRwQp34U51p4NaWDLby2v3A9XcuoNnhEh4aPp4nEU0Ai4IACE/JdAm5d2e6RIJQNXLWVnrHIjUsRlyH7yI4S0MD2UBVApXkhnWIMWLNg27rhrUxyjJgCWhmm69p+BL5JbMSqsEF6sSiJIK/ZfAIb39FkDbns6rH/f0tPGFsWOZrCA1ZXYHOtsU5D/drpMke+jJUVt38CPv38gCw8/1vUKZUj2rVV+/u0MddM9mGuGsrUtjy0k7Px5aVUOHcqIkV6+NrSP5k16s09/Y1gfNbxiGaqczFJ2g+QSykW+U3Vruih57MNQDANlQIDAQAB";

    const TEST_RSA_PKCS1_PUB_DER_B64: &str = "MIIBCgKCAQEAqQzMv4pNZp4eLsIPqo84gMVE/MwH1cBGlRwQp34U51p4NaWDLby2v3A9XcuoNnhEh4aPp4nEU0Ai4IACE/JdAm5d2e6RIJQNXLWVnrHIjUsRlyH7yI4S0MD2UBVApXkhnWIMWLNg27rhrUxyjJgCWhmm69p+BL5JbMSqsEF6sSiJIK/ZfAIb39FkDbns6rH/f0tPGFsWOZrCA1ZXYHOtsU5D/drpMke+jJUVt38CPv38gCw8/1vUKZUj2rVV+/u0MddM9mGuGsrUtjy0k7Px5aVUOHcqIkV6+NrSP5k16s09/Y1gfNbxiGaqczFJ2g+QSykW+U3Vruih57MNQDANlQIDAQAB";

    // Pinned with `openssl dgst -sha256 -sign` — PKCS#1 v1.5 is deterministic,
    // so our signer must reproduce these bytes exactly.
    const TEST_MESSAGE: &str = "impala-bridge changelly signing test vector";
    const TEST_MESSAGE_SIG_B64: &str = "m3U5cS0qQIlXA4T/svogUjDMBPsyeO9BFRHc5qoP6rneTeboEVlaqIKalAe3wEOUxBr2QZfYiEWdXm4nD0drooazBAO0a+vDudx7FKOrKIPsCnet3w2Zp4J7KtoJltTHeV5N+AadCtVV59W7vT/xPfQxxeZaoUBIKfvwOCkJG+sfjisHetxJ7Q8sDp+mEYwkuyKNeCu1YvoHHG6OgjVpV5Kow13pvh1sAXJrmKhKc2K2JM4+ty5VxM6zfh88MwjfnX6grLWYyYnjTiMqU8OdyCa0O3HfM8TnpLJArf7vcSCm75HIVvo2xyi2NqDFPkTmvlkdKxc+Y/deswvn5Jd9vg==";

    // openssl signature over the exact compact string {"orderId":"ord_test_123"}.
    const TEST_CALLBACK_ORDER_ID: &str = "ord_test_123";
    const TEST_CALLBACK_SIG_B64: &str = "ckABda6j0FDf8FGENo23iprUPHkdXknMuExzGGswoF1t9l3gjmhdltLZp3PadbOpw5f1Nz1QOpluA5m7bQ/i87Kw7pJoY+l2RgO965ApxB5UdMJPgCzGPxyaGNp/O/oCDwH0Hj4NaF7tb/iYeFz/V/5WrLuUmXICmlBF/EPMfLJ3IBvZC/71CRrxQnUyl8I8Z7epLq/+gmWBPzfTtM2I1EVwwAUALAw4VTaIhuoD+jV/PH78PFV14JgVIwe7Nh+y0juosX1e7bqolj9RLeZvQ50ETwqgDrDJxU2rqFydwrdC6T+/ctaBOaHEzunNHrRqo9xUSyOq9k/FdQLYr7ub7Q==";

    fn test_pkcs1_pub_der() -> Vec<u8> {
        STANDARD.decode(TEST_RSA_PKCS1_PUB_DER_B64).unwrap()
    }

    fn test_fiat(callback_public_key: Option<Vec<u8>>) -> ChangellyFiat {
        ChangellyFiat {
            http: reqwest::Client::new(),
            base_url: "https://fiat-api.changelly.com/v1".to_string(),
            api_key: "test-public-api-key".to_string(),
            key_pair: parse_private_key_pem(TEST_RSA_PKCS8_PEM).unwrap(),
            rng: SystemRandom::new(),
            callback_public_key,
        }
    }

    // ── key parsing ──

    #[test]
    fn test_parse_private_key_hex_pkcs8() {
        let key = parse_private_key_hex_pkcs8(TEST_RSA_PKCS8_DER_HEX).unwrap();
        assert_eq!(key.public_modulus_len(), 256); // 2048-bit key
    }

    #[test]
    fn test_parse_private_key_hex_pkcs8_rejects_invalid_hex() {
        let err = parse_private_key_hex_pkcs8("zznothex").unwrap_err();
        assert!(err.contains("invalid hex"));
    }

    #[test]
    fn test_parse_private_key_hex_pkcs8_rejects_non_key_der() {
        assert!(parse_private_key_hex_pkcs8("deadbeef").is_err());
    }

    #[test]
    fn test_parse_private_key_pem_pkcs8() {
        let key = parse_private_key_pem(TEST_RSA_PKCS8_PEM).unwrap();
        assert_eq!(key.public_modulus_len(), 256);
    }

    #[test]
    fn test_parse_private_key_pem_pkcs1() {
        let key = parse_private_key_pem(TEST_RSA_PKCS1_PEM).unwrap();
        assert_eq!(key.public_modulus_len(), 256);
    }

    #[test]
    fn test_parse_private_key_pem_rejects_garbage() {
        assert!(parse_private_key_pem("not a pem at all").is_err());
        assert!(parse_private_key_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
        assert!(parse_private_key_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
        )
        .is_err());
    }

    #[test]
    fn test_parse_public_key_spki_pem_unwraps_to_pkcs1() {
        let der = parse_public_key(TEST_RSA_SPKI_PEM).unwrap();
        assert_eq!(der, test_pkcs1_pub_der());
    }

    #[test]
    fn test_parse_public_key_raw_base64_spki() {
        let der = parse_public_key(TEST_RSA_SPKI_DER_B64).unwrap();
        assert_eq!(der, test_pkcs1_pub_der());
    }

    #[test]
    fn test_parse_public_key_raw_base64_pkcs1_passthrough() {
        let der = parse_public_key(TEST_RSA_PKCS1_PUB_DER_B64).unwrap();
        assert_eq!(der, test_pkcs1_pub_der());
    }

    #[test]
    fn test_parse_public_key_rejects_garbage() {
        assert!(parse_public_key("!!!not base64!!!").is_err());
        // Valid base64, but not a DER SEQUENCE.
        assert!(parse_public_key(&STANDARD.encode(b"hello world")).is_err());
    }

    #[test]
    fn test_spki_to_pkcs1_rejects_truncated_der() {
        let spki = STANDARD.decode(TEST_RSA_SPKI_DER_B64).unwrap();
        assert!(spki_to_pkcs1(&spki[..10]).is_err());
        // Corrupt the outer tag.
        let mut bad = spki.clone();
        bad[0] = 0x31;
        assert!(spki_to_pkcs1(&bad).is_err());
    }

    #[test]
    fn test_der_read_tlv_long_form_and_bounds() {
        let spki = STANDARD.decode(TEST_RSA_SPKI_DER_B64).unwrap();
        // 294-byte SPKI uses the 2-byte long length form; content + empty rest.
        let (content, rest) = der_read_tlv(&spki, 0x30).unwrap();
        assert_eq!(content.len(), spki.len() - 4);
        assert!(rest.is_empty());
        assert!(der_read_tlv(&[], 0x30).is_err());
        assert!(der_read_tlv(&[0x30], 0x30).is_err());
        // Declared length exceeds the buffer.
        assert!(der_read_tlv(&[0x30, 0x05, 0x01], 0x30).is_err());
    }

    // ── signing / verification ──

    #[test]
    fn test_sign_matches_openssl_pinned_vector() {
        // PKCS#1 v1.5 is deterministic: the signer must reproduce openssl's
        // output byte-for-byte for the same key and message.
        let key = parse_private_key_hex_pkcs8(TEST_RSA_PKCS8_DER_HEX).unwrap();
        let sig =
            sign_pkcs1_sha256_b64(&key, &SystemRandom::new(), TEST_MESSAGE.as_bytes()).unwrap();
        assert_eq!(sig, TEST_MESSAGE_SIG_B64);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let key = parse_private_key_pem(TEST_RSA_PKCS1_PEM).unwrap();
        let msg = br#"{"id":"abc","jsonrpc":"2.0","method":"getStatus","params":{}}"#;
        let sig_b64 = sign_pkcs1_sha256_b64(&key, &SystemRandom::new(), msg).unwrap();
        let sig = STANDARD.decode(sig_b64).unwrap();
        assert!(verify_pkcs1_sha256(&test_pkcs1_pub_der(), msg, &sig));
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        let sig = STANDARD.decode(TEST_MESSAGE_SIG_B64).unwrap();
        assert!(verify_pkcs1_sha256(
            &test_pkcs1_pub_der(),
            TEST_MESSAGE.as_bytes(),
            &sig
        ));
        let tampered = format!("{}!", TEST_MESSAGE);
        assert!(!verify_pkcs1_sha256(
            &test_pkcs1_pub_der(),
            tampered.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn test_tampered_signature_fails_verification() {
        let mut sig = STANDARD.decode(TEST_MESSAGE_SIG_B64).unwrap();
        sig[0] ^= 0x01;
        assert!(!verify_pkcs1_sha256(
            &test_pkcs1_pub_der(),
            TEST_MESSAGE.as_bytes(),
            &sig
        ));
    }

    // ── fiat webhook verification ──

    #[test]
    fn test_verify_callback_accepts_valid_signature() {
        let fiat = test_fiat(Some(test_pkcs1_pub_der()));
        assert!(fiat
            .verify_callback(TEST_CALLBACK_ORDER_ID, TEST_CALLBACK_SIG_B64)
            .is_ok());
    }

    #[test]
    fn test_verify_callback_rejects_wrong_order_id() {
        let fiat = test_fiat(Some(test_pkcs1_pub_der()));
        let result = fiat.verify_callback("ord_other_456", TEST_CALLBACK_SIG_B64);
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn test_verify_callback_rejects_bad_base64() {
        let fiat = test_fiat(Some(test_pkcs1_pub_der()));
        let result = fiat.verify_callback(TEST_CALLBACK_ORDER_ID, "!!not-base64!!");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn test_verify_callback_without_key_is_unauthorized() {
        let fiat = test_fiat(None);
        let result = fiat.verify_callback(TEST_CALLBACK_ORDER_ID, TEST_CALLBACK_SIG_B64);
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn test_verify_callback_message_matches_sdk_stringify() {
        // The signed string must be the exact compact JSON.stringify output.
        assert_eq!(
            json!({ "orderId": TEST_CALLBACK_ORDER_ID }).to_string(),
            r#"{"orderId":"ord_test_123"}"#
        );
    }

    // ── status mapping ──

    #[test]
    fn test_map_changelly_crypto_status_covers_documented_lifecycle() {
        // Every status documented for createTransaction/getStatus.
        assert_eq!(map_changelly_crypto_status("new"), EXCHANGE_STATUS_CREATED);
        assert_eq!(
            map_changelly_crypto_status("waiting"),
            EXCHANGE_STATUS_AWAITING_DEPOSIT
        );
        assert_eq!(
            map_changelly_crypto_status("confirming"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(
            map_changelly_crypto_status("exchanging"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(
            map_changelly_crypto_status("sending"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(
            map_changelly_crypto_status("finished"),
            EXCHANGE_STATUS_COMPLETED
        );
        assert_eq!(
            map_changelly_crypto_status("failed"),
            EXCHANGE_STATUS_FAILED
        );
        assert_eq!(
            map_changelly_crypto_status("refunded"),
            EXCHANGE_STATUS_REFUNDED
        );
        assert_eq!(map_changelly_crypto_status("hold"), EXCHANGE_STATUS_ON_HOLD);
        assert_eq!(
            map_changelly_crypto_status("overdue"),
            EXCHANGE_STATUS_EXPIRED
        );
        assert_eq!(
            map_changelly_crypto_status("expired"),
            EXCHANGE_STATUS_EXPIRED
        );
    }

    #[test]
    fn test_map_changelly_crypto_status_unknown_is_processing() {
        assert_eq!(
            map_changelly_crypto_status("some_future_status"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(map_changelly_crypto_status(""), EXCHANGE_STATUS_PROCESSING);
    }

    #[test]
    fn test_map_changelly_fiat_status_covers_documented_lifecycle() {
        use crate::constants::TERMINAL_EXCHANGE_STATUSES;
        // Every status in the Fiat API transaction-statuses dictionary.
        assert_eq!(
            map_changelly_fiat_status("created"),
            EXCHANGE_STATUS_CREATED
        );
        assert_eq!(
            map_changelly_fiat_status("pending"),
            EXCHANGE_STATUS_PROCESSING
        );
        assert_eq!(map_changelly_fiat_status("hold"), EXCHANGE_STATUS_ON_HOLD);
        // 'refunded' is NOT final in the Fiat API (only expired/failed/
        // complete are), so it must map to a non-terminal status or the row
        // would stop being polled and could never be corrected.
        assert_eq!(
            map_changelly_fiat_status("refunded"),
            EXCHANGE_STATUS_ON_HOLD
        );
        assert!(!TERMINAL_EXCHANGE_STATUSES.contains(&map_changelly_fiat_status("refunded")));
        assert_eq!(
            map_changelly_fiat_status("expired"),
            EXCHANGE_STATUS_EXPIRED
        );
        assert_eq!(map_changelly_fiat_status("failed"), EXCHANGE_STATUS_FAILED);
        assert_eq!(
            map_changelly_fiat_status("complete"),
            EXCHANGE_STATUS_COMPLETED
        );
    }

    #[test]
    fn test_map_changelly_fiat_status_unknown_is_processing() {
        assert_eq!(
            map_changelly_fiat_status("brand_new_status"),
            EXCHANGE_STATUS_PROCESSING
        );
    }

    // ── JSON-RPC plumbing ──

    #[test]
    fn test_jsonrpc_envelope_shape() {
        let body = jsonrpc_envelope("test-id", "getStatus", &json!({ "id": "tx1" }));
        // Compact (no whitespace) — these exact bytes are signed and sent.
        assert!(!body.contains(' '));
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], "test-id");
        assert_eq!(parsed["method"], "getStatus");
        assert_eq!(parsed["params"]["id"], "tx1");
    }

    #[test]
    fn test_estimation_params_are_array_form() {
        // Bare-object params are rejected by the estimation methods.
        let params = estimation_params("xlm", "usdcxlm", "100.5");
        let arr = params.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["from"], "xlm");
        assert_eq!(arr[0]["to"], "usdcxlm");
        assert_eq!(arr[0]["amountFrom"], "100.5");
    }

    #[test]
    fn test_map_jsonrpc_error_rate_limit() {
        let err = map_jsonrpc_error(-32603, "request limit exceeded");
        assert!(matches!(err, AppError::RateLimited { retry_after: 1 }));
    }

    #[test]
    fn test_map_jsonrpc_error_invalid_params_is_bad_request() {
        match map_jsonrpc_error(-32602, "invalid amount: minimal amount is 1.5") {
            AppError::BadRequest(m) => assert!(m.contains("minimal amount is 1.5")),
            other => panic!("expected BadRequest, got {}", other),
        }
        assert!(matches!(
            map_jsonrpc_error(-32601, "method not found"),
            AppError::BadRequest(_)
        ));
    }

    #[test]
    fn test_map_jsonrpc_error_server_range_stays_generic() {
        // Reserved server-error range must not leak provider internals.
        match map_jsonrpc_error(-32050, "pool wallet xyz is offline") {
            AppError::InternalError(m) => assert_eq!(m, "Exchange provider error"),
            other => panic!("expected InternalError, got {}", other),
        }
    }

    #[test]
    fn test_map_jsonrpc_error_business_code_is_bad_request() {
        match map_jsonrpc_error(1001, "rateId was expired or already used") {
            AppError::BadRequest(m) => assert!(m.contains("rateId was expired")),
            other => panic!("expected BadRequest, got {}", other),
        }
    }

    #[test]
    fn test_sanitize_provider_message_truncates_and_strips() {
        let long = "x".repeat(500);
        assert_eq!(sanitize_provider_message(&long).len(), 200);
        assert_eq!(
            sanitize_provider_message("bad\r\namount\x00!"),
            "badamount!"
        );
        assert_eq!(
            sanitize_provider_message(""),
            "Exchange provider rejected the request"
        );
    }

    // ── create-transaction params / response parsing ──

    fn sample_create_tx() -> ChangellyCreateTx {
        ChangellyCreateTx {
            from: "xlm".to_string(),
            to: "usdcxlm".to_string(),
            amount_from: "150.5".to_string(),
            address: "GDEST".to_string(),
            extra_id: None,
            refund_address: None,
            refund_extra_id: None,
            rate_id: None,
        }
    }

    #[test]
    fn test_build_create_tx_params_float() {
        let params = build_create_tx_params(&sample_create_tx(), false).unwrap();
        assert_eq!(params["from"], "xlm");
        assert_eq!(params["to"], "usdcxlm");
        assert_eq!(params["amountFrom"], "150.5");
        assert_eq!(params["address"], "GDEST");
        // Optionals omitted entirely rather than sent as null.
        assert!(params.get("extraId").is_none());
        assert!(params.get("refundAddress").is_none());
        assert!(params.get("rateId").is_none());
    }

    #[test]
    fn test_build_create_tx_params_float_with_optionals() {
        let mut p = sample_create_tx();
        p.extra_id = Some("memo123".to_string());
        p.refund_address = Some("GREFUND".to_string());
        p.refund_extra_id = Some("memo456".to_string());
        let params = build_create_tx_params(&p, false).unwrap();
        assert_eq!(params["extraId"], "memo123");
        assert_eq!(params["refundAddress"], "GREFUND");
        assert_eq!(params["refundExtraId"], "memo456");
    }

    #[test]
    fn test_build_create_tx_params_fixed_requires_rate_id_and_refund() {
        let mut p = sample_create_tx();
        p.refund_address = Some("GREFUND".to_string());
        assert!(matches!(
            build_create_tx_params(&p, true),
            Err(AppError::BadRequest(_))
        ));

        let mut p = sample_create_tx();
        p.rate_id = Some("rate123".to_string());
        assert!(matches!(
            build_create_tx_params(&p, true),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn test_build_create_tx_params_fixed_full() {
        let mut p = sample_create_tx();
        p.rate_id = Some("rate123".to_string());
        p.refund_address = Some("GREFUND".to_string());
        let params = build_create_tx_params(&p, true).unwrap();
        assert_eq!(params["rateId"], "rate123");
        assert_eq!(params["refundAddress"], "GREFUND");
    }

    #[test]
    fn test_parse_changelly_tx_full() {
        let result = json!({
            "id": "tx_abc",
            "status": "new",
            "payinAddress": "GPAYIN",
            "payinExtraId": "10101",
            "amountExpectedFrom": "150.5",
            "amountExpectedTo": "149.2",
            "payTill": "2026-08-03T12:00:00.000Z",
            "currencyFrom": "xlm",
            "currencyTo": "usdcxlm"
        });
        let tx = parse_changelly_tx(&result).unwrap();
        assert_eq!(tx.id, "tx_abc");
        assert_eq!(tx.status, "new");
        assert_eq!(tx.payin_address, "GPAYIN");
        assert_eq!(tx.payin_extra_id.as_deref(), Some("10101"));
        assert_eq!(tx.amount_expected_from.as_deref(), Some("150.5"));
        assert_eq!(tx.amount_expected_to.as_deref(), Some("149.2"));
        assert_eq!(tx.pay_till.as_deref(), Some("2026-08-03T12:00:00.000Z"));
        assert_eq!(tx.raw["currencyFrom"], "xlm");
    }

    #[test]
    fn test_parse_changelly_tx_null_extra_id_and_missing_fields() {
        let result = json!({
            "id": "tx_abc",
            "status": "new",
            "payinAddress": "GPAYIN",
            "payinExtraId": null
        });
        let tx = parse_changelly_tx(&result).unwrap();
        assert!(tx.payin_extra_id.is_none());
        assert!(tx.amount_expected_from.is_none());
        assert!(tx.pay_till.is_none());

        assert!(parse_changelly_tx(&json!({ "status": "new" })).is_err());
        assert!(parse_changelly_tx(&json!({ "id": "x", "status": "new" })).is_err());
    }

    #[test]
    fn test_value_as_decimal_string_never_drops_string_form() {
        assert_eq!(
            value_as_decimal_string(&json!("123.456000000000000001")).as_deref(),
            Some("123.456000000000000001")
        );
        assert_eq!(value_as_decimal_string(&json!(42)).as_deref(), Some("42"));
        assert!(value_as_decimal_string(&json!(null)).is_none());
        assert!(value_as_decimal_string(&json!({"a": 1})).is_none());
    }

    // ── fiat URL / signature payload ──

    #[test]
    fn test_build_url_and_get_signature_payload() {
        let q = FiatOfferQuery {
            currency_from: "USD".to_string(),
            currency_to: "USDCXLM".to_string(),
            amount_from: "100".to_string(),
            country: "US".to_string(),
            state: Some("AZ".to_string()),
            ip: "203.0.113.7".to_string(),
            provider_code: None,
            payment_method: None,
            external_user_id: None,
        };
        let url = build_url(
            "https://fiat-api.changelly.com/v1",
            "/offers",
            &offer_query_pairs(&q, false),
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "https://fiat-api.changelly.com/v1/offers?currencyFrom=USD&currencyTo=USDCXLM\
             &amountFrom=100&country=US&state=AZ&ip=203.0.113.7"
        );
        // Bodyless requests append the literal "{}" per the official SDK.
        assert_eq!(
            fiat_signature_payload(url.as_str(), None),
            format!("{}{}", url.as_str(), "{}")
        );
    }

    #[test]
    fn test_post_signature_payload_uses_exact_body_bytes() {
        let url = build_url("https://fiat-api.changelly.com/v1", "/orders", &[]).unwrap();
        let body = json!({ "externalOrderId": "o1", "providerCode": "moonpay" });
        let body_str = serde_json::to_string(&body).unwrap();
        let payload = fiat_signature_payload(url.as_str(), Some(&body_str));
        assert_eq!(
            payload,
            format!("https://fiat-api.changelly.com/v1/orders{}", body_str)
        );
        // Compact serialization: what is signed is exactly what is sent.
        assert!(!body_str.contains(": "));
    }

    #[test]
    fn test_offer_query_pairs_includes_optionals_in_order() {
        let q = FiatOfferQuery {
            currency_from: "USDCXLM".to_string(),
            currency_to: "EUR".to_string(),
            amount_from: "50".to_string(),
            country: "DE".to_string(),
            state: None,
            ip: "203.0.113.7".to_string(),
            provider_code: Some("moonpay".to_string()),
            payment_method: Some("sepa_bank_transfer".to_string()),
            external_user_id: Some("acct1".to_string()),
        };
        // Sell (off-ramp) carries the payment-method filter under its
        // documented name.
        let keys: Vec<&str> = offer_query_pairs(&q, true)
            .iter()
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(
            keys,
            vec![
                "currencyFrom",
                "currencyTo",
                "amountFrom",
                "country",
                "ip",
                "providerCode",
                "paymentMethodCode",
                "externalUserId"
            ]
        );

        // Buy (on-ramp) has no payment-method filter at all — sending one
        // would be silently ignored, so it is omitted.
        let keys: Vec<&str> = offer_query_pairs(&q, false)
            .iter()
            .map(|(k, _)| *k)
            .collect();
        assert!(!keys.iter().any(|k| k.starts_with("paymentMethod")));
        assert_eq!(keys.len(), 7);
    }

    #[test]
    fn test_parse_fiat_order() {
        let v = json!({
            "orderId": "uuid-1",
            "redirectUrl": "https://sell.moonpay.com/changelly?x=1",
            "type": "buy"
        });
        let order = parse_fiat_order(&v).unwrap();
        assert_eq!(order.order_id, "uuid-1");
        assert!(order.status.is_none());
        assert_eq!(
            order.redirect_url.as_deref(),
            Some("https://sell.moonpay.com/changelly?x=1")
        );
        assert_eq!(order.raw["type"], "buy");

        assert!(parse_fiat_order(&json!({ "redirectUrl": "x" })).is_err());
    }

    #[test]
    fn test_find_order_matches_by_id() {
        let v = json!({ "orders": [{ "orderId": "a" }, { "orderId": "b" }], "total": 2 });
        assert_eq!(find_order(&v, "a").unwrap()["orderId"], "a");
        // Selection is by identity, never by position: a server-side filter
        // miss must not hand back the first unrelated order.
        assert_eq!(find_order(&v, "b").unwrap()["orderId"], "b");
        assert!(find_order(&v, "c").is_none());
        assert!(find_order(&json!({ "orders": [], "total": 0 }), "a").is_none());
        assert!(find_order(&json!({}), "a").is_none());
    }

    #[test]
    fn test_map_fiat_http_error() {
        // Key problems are ours — never surfaced to clients.
        match map_fiat_http_error(401, r#"{"errorType":"unauthorized"}"#) {
            AppError::InternalError(m) => assert_eq!(m, "Exchange provider error"),
            other => panic!("expected InternalError, got {}", other),
        }
        assert!(matches!(
            map_fiat_http_error(429, ""),
            AppError::RateLimited { retry_after: 1 }
        ));
        match map_fiat_http_error(
            400,
            r#"{"errorType":"validation","errorMessage":"country is not supported"}"#,
        ) {
            AppError::BadRequest(m) => assert!(m.contains("country is not supported")),
            other => panic!("expected BadRequest, got {}", other),
        }
        // 4xx with an unparseable body still gets a safe fallback message.
        match map_fiat_http_error(422, "<html>oops</html>") {
            AppError::BadRequest(m) => {
                assert_eq!(m, "Exchange provider rejected the request");
            }
            other => panic!("expected BadRequest, got {}", other),
        }
        assert!(matches!(
            map_fiat_http_error(500, "boom"),
            AppError::InternalError(_)
        ));
    }

    #[test]
    fn test_fiat_error_message_extraction() {
        assert_eq!(
            fiat_error_message(r#"{"errorMessage":"nope"}"#).as_deref(),
            Some("nope")
        );
        assert_eq!(
            fiat_error_message(r#"{"message":"other"}"#).as_deref(),
            Some("other")
        );
        assert!(fiat_error_message("not json").is_none());
    }
}
