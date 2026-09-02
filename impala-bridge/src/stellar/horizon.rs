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
    /// Sending account: `from` for payments, `funder` for create_account.
    ///
    /// This is where a refund goes back to, so it is the only reason the
    /// bridge can return money it cannot use. Optional because the parser's
    /// contract is never to drop a record on feed noise — a missing sender
    /// must not stall the CREDIT path, only make the payment unrefundable.
    pub from: Option<String>,
    /// Horizon `from_muxed` (M-strkey) when the sender used a muxed account.
    ///
    /// Its presence means `from` is a SHARED base address and the real payer
    /// identity is the muxed id, so refunding `from` would strand the money
    /// again. The signer takes only G-addresses, so this is a hard stop for
    /// automatic refunds.
    pub from_muxed: Option<String>,
    /// `native` or `credit_alphanum4/12`.
    pub asset_type: String,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
    /// Horizon 7-dp decimal string (`starting_balance` for create_account).
    pub amount: String,
    /// Joined transaction memo, only when `memo_type == "text"`.
    pub memo_text: Option<String>,
    /// Ledger close time (`created_at`), RFC3339 as Horizon returns it. Lets a
    /// backward feed walk stop once records predate the event it is looking
    /// for, so an on-chain search can be exhaustive over a bounded window
    /// instead of only the newest page. `None` if Horizon omitted or
    /// malformed it (never on a real payment) — a missing bound just makes the
    /// walk continue, never stop short.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
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
    let (to, from, asset_type, asset_code, asset_issuer, amount) = match op_type {
        "payment" | "path_payment_strict_send" | "path_payment_strict_receive" => (
            r["to"].as_str()?.to_string(),
            r["from"].as_str().map(|s| s.to_string()),
            r["asset_type"].as_str().unwrap_or("").to_string(),
            r["asset_code"].as_str().map(|s| s.to_string()),
            r["asset_issuer"].as_str().map(|s| s.to_string()),
            r["amount"].as_str()?.to_string(),
        ),
        "create_account" => (
            r["account"].as_str()?.to_string(),
            // The funder is captured for the audit trail only: a
            // create_account inflow IS the account's base reserve and is
            // never refundable.
            r["funder"].as_str().map(|s| s.to_string()),
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
        from,
        from_muxed: r["from_muxed"].as_str().map(|s| s.to_string()),
        asset_type,
        asset_code,
        asset_issuer,
        amount,
        memo_text,
        created_at: r["created_at"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
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

/// Outcome of an exhaustive backward walk of the reserve's payments feed
/// looking for one specific outgoing payment.
#[derive(Debug, PartialEq)]
pub enum FeedSearch {
    /// A matching payment was found; carries its transaction hash.
    Found(String),
    /// The walk completed — it reached records older than `not_before`, or
    /// exhausted the feed — and no match exists. Trustworthy absence.
    VerifiedAbsent,
    /// The walk could NOT be completed within `max_pages` without crossing
    /// `not_before`. Absence is NOT proven; the caller must fail closed.
    Inconclusive,
}

/// Per-page decision of the descending walk, factored out so the money-safe
/// stop logic is unit-testable without network I/O.
#[derive(Debug, PartialEq)]
enum PageScan {
    Found(String),
    /// A record older than the floor was seen — nothing older can match, so
    /// absence over the window is proven.
    CrossedFloor,
    /// No match and no floor crossing on this page; keep walking older pages.
    Continue,
}

/// Scan one page (newest-first) for a match or a floor crossing. Pure.
fn scan_page_desc<F>(
    records: &[HorizonPayment],
    not_before: chrono::DateTime<chrono::Utc>,
    matches: &mut F,
) -> PageScan
where
    F: FnMut(&HorizonPayment) -> bool,
{
    for p in records {
        if matches(p) {
            return PageScan::Found(p.tx_hash.clone());
        }
        if let Some(ts) = p.created_at {
            if ts < not_before {
                return PageScan::CrossedFloor;
            }
        }
    }
    PageScan::Continue
}

/// Walk the account's payments feed newest-first, applying `matches` to each
/// record, until a match is found, a record older than `not_before` is seen
/// (proving nothing older can match), or the feed is exhausted. `max_pages`
/// bounds the work: hitting it without crossing `not_before` yields
/// `Inconclusive` so a money-path caller fails closed rather than treating a
/// scrolled-past record as absent.
///
/// This is the money-safe replacement for a single-page scan: a settled
/// payout/refund that has scrolled past the newest page is still found (or,
/// if genuinely absent, absence is *proven* over the window rather than
/// assumed). Any Horizon error propagates and the caller fails closed.
pub async fn search_payments_desc<F>(
    http: &reqwest::Client,
    horizon_url: &str,
    account_id: &str,
    not_before: chrono::DateTime<chrono::Utc>,
    max_pages: usize,
    limit: u32,
    mut matches: F,
) -> Result<FeedSearch, AppError>
where
    F: FnMut(&HorizonPayment) -> bool,
{
    let base = horizon_url.trim_end_matches('/');
    let mut cursor: Option<String> = None;
    for _ in 0..max_pages {
        let mut url = format!(
            "{}/accounts/{}/payments?order=desc&limit={}&join=transactions",
            base, account_id, limit
        );
        if let Some(c) = &cursor {
            url.push_str("&cursor=");
            url.push_str(c);
        }
        // 404 (unfunded account) means the feed cannot hold the payment.
        let Some(body) = horizon_get(http, &url, "search_payments_desc").await? else {
            return Ok(FeedSearch::VerifiedAbsent);
        };
        let page = parse_payments_page(&body);
        if page.raw_count == 0 {
            return Ok(FeedSearch::VerifiedAbsent); // reached the start of the feed
        }
        match scan_page_desc(&page.records, not_before, &mut matches) {
            PageScan::Found(hash) => return Ok(FeedSearch::Found(hash)),
            PageScan::CrossedFloor => return Ok(FeedSearch::VerifiedAbsent),
            PageScan::Continue => {}
        }
        // A short page is the end of the feed.
        if page.raw_count < limit as usize {
            return Ok(FeedSearch::VerifiedAbsent);
        }
        cursor = page.last_token;
        if cursor.is_none() {
            return Ok(FeedSearch::VerifiedAbsent);
        }
    }
    Ok(FeedSearch::Inconclusive)
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
        assert_eq!(p[0].from.as_deref(), Some("GUSER"));
        assert!(p[0].from_muxed.is_none());
    }

    #[test]
    fn captures_muxed_sender() {
        // `from` is the SHARED base address when the payer used a muxed
        // account — refunding it would strand the money again, so the muxed
        // marker has to survive parsing.
        let body = page(json!([{
            "type": "payment",
            "paging_token": "7",
            "transaction_hash": "h7",
            "to": "GRESERVE",
            "from": "GBASE",
            "from_muxed": "MBASEXXXXXXXX",
            "from_muxed_id": "1234",
            "asset_type": "native",
            "amount": "5.0000000",
            "transaction": { "memo_type": "none" }
        }]));
        let p = parse_payments_page(&body).records;
        assert_eq!(p[0].from.as_deref(), Some("GBASE"));
        assert_eq!(p[0].from_muxed.as_deref(), Some("MBASEXXXXXXXX"));
    }

    #[test]
    fn payment_without_sender_still_parses() {
        // Dropping the record would stall the credit path, not just the
        // refund path — the money still has to reach the ledger.
        let body = page(json!([{
            "type": "payment",
            "paging_token": "8",
            "transaction_hash": "h8",
            "to": "GRESERVE",
            "asset_type": "native",
            "amount": "3.0000000",
            "transaction": { "memo_type": "none" }
        }]));
        let p = parse_payments_page(&body).records;
        assert_eq!(p.len(), 1);
        assert!(p[0].from.is_none());
        assert_eq!(p[0].amount, "3.0000000");
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
        // Funder captured for audit; create_account is never refundable.
        assert_eq!(p[0].from.as_deref(), Some("GOPS"));
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

    #[test]
    fn parses_created_at() {
        let body = page(json!([{
            "type": "payment", "paging_token": "9", "transaction_hash": "h9",
            "to": "G", "asset_type": "native", "amount": "1.0000000",
            "created_at": "2026-01-15T12:00:00Z",
            "transaction": { "memo_type": "none" }
        }]));
        let p = &parse_payments_page(&body).records[0];
        assert_eq!(
            p.created_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            )
        );
    }

    fn rec(hash: &str, to: &str, created_at: Option<&str>) -> HorizonPayment {
        HorizonPayment {
            paging_token: hash.to_string(),
            tx_hash: hash.to_string(),
            op_type: "payment".to_string(),
            to: to.to_string(),
            from: Some("GRESERVE".to_string()),
            from_muxed: None,
            asset_type: "native".to_string(),
            asset_code: None,
            asset_issuer: None,
            amount: "1.0000000".to_string(),
            memo_text: None,
            created_at: created_at.map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            }),
        }
    }

    fn floor(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn scan_page_finds_match_before_floor_crossing() {
        // The target sits on this page above a below-floor record; it must be
        // found, not stopped short — the exact fail-open a single-page scan
        // had once records scrolled past the newest page.
        let recs = [
            rec("newer", "GDEST", Some("2026-01-15T12:00:05Z")),
            rec("target", "GDEST", Some("2026-01-15T12:00:03Z")),
            rec("older", "GX", Some("2026-01-15T11:00:00Z")), // below floor
        ];
        let mut m = |p: &HorizonPayment| p.tx_hash == "target";
        assert_eq!(
            scan_page_desc(&recs, floor("2026-01-15T12:00:00Z"), &mut m),
            PageScan::Found("target".to_string())
        );
    }

    #[test]
    fn scan_page_crosses_floor_proves_absence() {
        // No match, and a record older than the floor: absence is proven over
        // the window, so the walk stops with CrossedFloor (VerifiedAbsent).
        let recs = [
            rec("a", "GX", Some("2026-01-15T12:00:05Z")),
            rec("b", "GX", Some("2026-01-15T11:59:00Z")), // below floor
            rec("target", "GDEST", Some("2026-01-15T10:00:00Z")), // older than floor: unreachable
        ];
        let mut m = |p: &HorizonPayment| p.tx_hash == "target";
        assert_eq!(
            scan_page_desc(&recs, floor("2026-01-15T12:00:00Z"), &mut m),
            PageScan::CrossedFloor
        );
    }

    #[test]
    fn scan_page_continues_when_all_within_window() {
        // No match and every record is at/after the floor — the target may be
        // on an older page, so keep walking (the single-page scan's bug was
        // treating this as absence).
        let recs = [
            rec("a", "GX", Some("2026-01-15T12:00:05Z")),
            rec("b", "GX", Some("2026-01-15T12:00:01Z")),
        ];
        let mut m = |p: &HorizonPayment| p.tx_hash == "target";
        assert_eq!(
            scan_page_desc(&recs, floor("2026-01-15T12:00:00Z"), &mut m),
            PageScan::Continue
        );
    }

    #[test]
    fn scan_page_missing_created_at_never_stops_short() {
        // A record with no created_at cannot cross the floor: the walk must
        // continue rather than falsely proving absence.
        let recs = [rec("a", "GX", None)];
        let mut m = |p: &HorizonPayment| p.tx_hash == "target";
        assert_eq!(
            scan_page_desc(&recs, floor("2026-01-15T12:00:00Z"), &mut m),
            PageScan::Continue
        );
    }
}
