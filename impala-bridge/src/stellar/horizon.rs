//! Horizon payments paging for the conversion-reserve deposit watcher.
//!
//! Pages `GET /accounts/{id}/payments?join=transactions` forward from a
//! cursor. The memo the watcher matches on lives on the *transaction*, not
//! the payment operation — `join=transactions` embeds it per record. The
//! parser is split from the I/O (account.rs precedent) so matching logic is
//! unit-testable from canned Horizon JSON.

use log::error;
use serde_json::Value;

use crate::error::AppError;

/// One payment-ish operation on the reserve account's feed. Covers
/// `payment`, `path_payment_strict_send/receive` (what deposits look like)
/// and `create_account` (the account's initial funding — surfaces as an
/// inflow so the ledger/chain drift stays visible).
#[derive(Debug, Clone, PartialEq)]
pub struct HorizonPayment {
    pub paging_token: String,
    pub tx_hash: String,
    pub op_type: String,
    /// Receiving account (`to`, or `account` for create_account).
    pub to: String,
    /// `native` or `credit_alphanum4/12`.
    pub asset_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    /// Horizon 7-dp decimal string (`starting_balance` for create_account).
    pub amount: String,
    /// Joined transaction memo, only when `memo_type == "text"`.
    pub memo_text: Option<String>,
}

/// One fetched page, with RAW feed accounting kept separate from the parsed
/// records: the cursor must advance past skipped records (account_merge and
/// friends appear on the /payments feed) or a run of them would stall the
/// scan forever, and page-fullness must count raw records or a partly-parsed
/// full page would end the drain early.
#[derive(Debug, Default, PartialEq)]
pub struct PaymentsPage {
    pub records: Vec<HorizonPayment>,
    /// Raw record count as returned by Horizon (>= records.len()).
    pub raw_count: usize,
    /// paging_token of the LAST raw record — the cursor to advance to.
    pub last_token: Option<String>,
}

/// Pure parser over a Horizon payments-page body (`_embedded.records`).
/// Records that don't look like value inflows/outflows (missing fields,
/// unknown shapes) are skipped from `records` but still counted and
/// cursor-tracked — the watcher must never crash or stall on feed noise.
pub fn parse_payments_page(body: &Value) -> PaymentsPage {
    let raw = match body["_embedded"]["records"].as_array() {
        Some(r) => r,
        None => return PaymentsPage::default(),
    };
    PaymentsPage {
        records: raw.iter().filter_map(parse_payment_record).collect(),
        raw_count: raw.len(),
        last_token: raw
            .last()
            .and_then(|r| r["paging_token"].as_str())
            .map(|s| s.to_string()),
    }
}

fn parse_payment_record(r: &Value) -> Option<HorizonPayment> {
    let op_type = r["type"].as_str()?;
    let (to, asset_type, asset_code, asset_issuer, amount) = match op_type {
        "payment" | "path_payment_strict_send" | "path_payment_strict_receive" => (
            r["to"].as_str()?.to_string(),
            r["asset_type"].as_str().unwrap_or("").to_string(),
            r["asset_code"].as_str().map(|s| s.to_string()),
            r["asset_issuer"].as_str().map(|s| s.to_string()),
            r["amount"].as_str()?.to_string(),
        ),
        "create_account" => (
            r["account"].as_str()?.to_string(),
            "native".to_string(),
            None,
            None,
            r["starting_balance"].as_str()?.to_string(),
        ),
        _ => return None,
    };
    // Joined transaction (join=transactions). Only text memos participate in
    // matching; other memo types read as "no memo".
    let memo_text = match r["transaction"]["memo_type"].as_str() {
        Some("text") => r["transaction"]["memo"].as_str().map(|s| s.to_string()),
        _ => None,
    };
    Some(HorizonPayment {
        paging_token: r["paging_token"].as_str()?.to_string(),
        tx_hash: r["transaction_hash"].as_str()?.to_string(),
        op_type: op_type.to_string(),
        to,
        asset_type,
        asset_code,
        asset_issuer,
        amount,
        memo_text,
    })
}

/// Fetch one ascending payments page after `cursor`. A 404 (account not yet
/// funded) is an empty page, not an error.
pub async fn fetch_payments_page(
    http: &reqwest::Client,
    horizon_url: &str,
    stellar_account_id: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<PaymentsPage, AppError> {
    let mut url = format!(
        "{}/accounts/{}/payments?order=asc&limit={}&join=transactions",
        horizon_url.trim_end_matches('/'),
        stellar_account_id,
        limit
    );
    if let Some(c) = cursor {
        url.push_str("&cursor=");
        url.push_str(c);
    }
    let body = horizon_get(http, &url, "fetch_payments_page").await?;
    Ok(body.map(|b| parse_payments_page(&b)).unwrap_or_default())
}

/// Latest paging token on the account's payments feed, for initializing the
/// watcher cursor to "now" (history before enablement is deliberately not
/// scanned). `None` when the feed is empty or the account is unfunded —
/// paging from the beginning is then equivalent and safe.
pub async fn fetch_latest_cursor(
    http: &reqwest::Client,
    horizon_url: &str,
    stellar_account_id: &str,
) -> Result<Option<String>, AppError> {
    let url = format!(
        "{}/accounts/{}/payments?order=desc&limit=1",
        horizon_url.trim_end_matches('/'),
        stellar_account_id
    );
    let body = horizon_get(http, &url, "fetch_latest_cursor").await?;
    Ok(body.and_then(|b| {
        b["_embedded"]["records"]
            .as_array()
            .and_then(|r| r.first())
            .and_then(|rec| rec["paging_token"].as_str())
            .map(|s| s.to_string())
    }))
}

/// Shared GET with the module's error taxonomy: 404 -> Ok(None), other
/// failures -> InternalError with server-side logging only.
async fn horizon_get(
    http: &reqwest::Client,
    url: &str,
    context: &'static str,
) -> Result<Option<Value>, AppError> {
    let resp = http.get(url).send().await.map_err(|e| {
        error!("{}: horizon request error: {}", context, e);
        AppError::InternalError("Horizon request failed".to_string())
    })?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        error!("{}: horizon HTTP {}", context, resp.status());
        return Err(AppError::InternalError("Horizon error".to_string()));
    }
    let body: Value = resp.json().await.map_err(|e| {
        error!("{}: horizon response parse error: {}", context, e);
        AppError::InternalError("Horizon response error".to_string())
    })?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page(records: Value) -> Value {
        json!({ "_embedded": { "records": records } })
    }

    #[test]
    fn parses_payment_with_text_memo() {
        let body = page(json!([{
            "type": "payment",
            "paging_token": "12885913602",
            "transaction_hash": "abc123",
            "to": "GRESERVE",
            "from": "GUSER",
            "asset_type": "native",
            "amount": "25.0000000",
            "transaction": { "memo_type": "text", "memo": "05Z8W1K9T2" }
        }]));
        let p = parse_payments_page(&body).records;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].to, "GRESERVE");
        assert_eq!(p[0].asset_type, "native");
        assert_eq!(p[0].amount, "25.0000000");
        assert_eq!(p[0].memo_text.as_deref(), Some("05Z8W1K9T2"));
        assert_eq!(p[0].tx_hash, "abc123");
    }

    #[test]
    fn parses_credit_asset_and_path_payment() {
        let body = page(json!([{
            "type": "path_payment_strict_send",
            "paging_token": "2",
            "transaction_hash": "h2",
            "to": "GRESERVE",
            "asset_type": "credit_alphanum4",
            "asset_code": "USDC",
            "asset_issuer": "GISSUER",
            "amount": "10.5000000",
            "transaction": { "memo_type": "none" }
        }]));
        let p = parse_payments_page(&body).records;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].asset_code.as_deref(), Some("USDC"));
        assert_eq!(p[0].asset_issuer.as_deref(), Some("GISSUER"));
        // memo_type != text reads as no memo.
        assert!(p[0].memo_text.is_none());
    }

    #[test]
    fn parses_create_account_as_native_inflow() {
        let body = page(json!([{
            "type": "create_account",
            "paging_token": "3",
            "transaction_hash": "h3",
            "account": "GRESERVE",
            "funder": "GOPS",
            "starting_balance": "100.0000000",
            "transaction": { "memo_type": "text", "memo": "fund" }
        }]));
        let p = parse_payments_page(&body).records;
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].op_type, "create_account");
        assert_eq!(p[0].to, "GRESERVE");
        assert_eq!(p[0].asset_type, "native");
        assert_eq!(p[0].amount, "100.0000000");
    }

    #[test]
    fn skips_unknown_and_malformed_records_but_keeps_raw_accounting() {
        let body = page(json!([
            { "type": "manage_offer", "paging_token": "4" },
            { "type": "payment", "paging_token": "5" },
            { "not": "an op" }
        ]));
        let p = parse_payments_page(&body);
        assert!(p.records.is_empty());
        // Raw accounting still covers skipped records — the cursor must
        // advance past them or a run of non-payment ops stalls the scan.
        assert_eq!(p.raw_count, 3);
        assert!(p.last_token.is_none()); // malformed last record: no token
        let body = page(json!([
            { "type": "manage_offer", "paging_token": "4" },
            { "type": "account_merge", "paging_token": "6" }
        ]));
        let p = parse_payments_page(&body);
        assert!(p.records.is_empty());
        assert_eq!(p.raw_count, 2);
        assert_eq!(p.last_token.as_deref(), Some("6"));
    }

    #[test]
    fn empty_and_missing_pages_parse_to_nothing() {
        let p = parse_payments_page(&page(json!([])));
        assert!(p.records.is_empty());
        assert_eq!(p.raw_count, 0);
        assert!(p.last_token.is_none());
        assert_eq!(parse_payments_page(&json!({})), PaymentsPage::default());
    }

    #[test]
    fn non_text_memo_types_are_ignored() {
        for (mt, memo) in [
            ("id", json!("123")),
            ("hash", json!("aGFzaA==")),
            ("none", Value::Null),
        ] {
            let body = page(json!([{
                "type": "payment", "paging_token": "6", "transaction_hash": "h6",
                "to": "G", "asset_type": "native", "amount": "1.0000000",
                "transaction": { "memo_type": mt, "memo": memo }
            }]));
            assert!(parse_payments_page(&body).records[0].memo_text.is_none());
        }
    }
}
