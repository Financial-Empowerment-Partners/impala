//! Pure reconciliation arithmetic and the positions report schema.
//!
//! DB- and HTTP-free by design: everything here is a function of values the
//! gatherer (`super::build_positions`) already read, so the drift rule, the
//! tolerance boundary, the invariant verdicts and the day-boundary logic of
//! the snapshot job are unit-tested without infrastructure.
//!
//! Money is `i64` minor units throughout; every derivation is checked and an
//! overflow reads as "not asserted" (`None`) plus a warning — never as a
//! clean invariant.

use chrono::{DateTime, NaiveDate, Timelike, Utc};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::constants::RECONCILIATION_SCHEMA_VERSION;
use crate::exchange::reserve::parse_decimal_to_minor;

// ── Schema (append-only; schema_version 1) ─────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PositionsResponse {
    pub schema_version: i32,
    pub as_of: String,
    /// Every custodial address in scope was read within budget.
    pub complete: bool,
    pub horizon: HorizonView,
    pub reserve: ReserveView,
    pub custodial: CustodialView,
    pub payala: PayalaView,
    pub card: CardView,
    pub invariants: Vec<Invariant>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HorizonView {
    pub url: String,
    pub head_closed_at: Option<String>,
    pub lag_secs: Option<i64>,
    pub fresh: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReserveView {
    pub configured: bool,
    pub stellar_address: Option<String>,
    pub buckets: Vec<BucketPosition>,
    pub obligations: Obligations,
}

#[derive(Debug, Clone, Serialize)]
pub struct BucketPosition {
    pub currency: String,
    pub minor_scale: i16,
    /// `CODE:ISSUER` for a configured stablecoin; null for XLM/USD and for an
    /// inert (unconfigured) stablecoin bucket.
    pub asset: Option<String>,
    /// Whether this bucket has an on-chain counterpart to reconcile against
    /// (false for USD, and for an unconfigured stablecoin).
    pub chain_leg: bool,
    pub available_minor: i64,
    pub held_minor: i64,
    pub ledger_total_minor: Option<i64>,
    pub journal_available_minor: i64,
    pub journal_held_minor: i64,
    pub journal_replay_ok: bool,
    pub onchain_minor: Option<i64>,
    pub onchain_raw: Option<String>,
    pub trustline: Option<bool>,
    /// `onchain - ledger_total`; null when unverifiable.
    pub drift_minor: Option<i64>,
    pub drift_tolerance_minor: i64,
    pub drift_ok: Option<bool>,
    /// Σ held_delta of the offline journal kinds (0 before 038).
    pub offline_held_minor: i64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RefundsByStatus {
    pub queued: BTreeMap<String, i64>,
    pub needs_review: BTreeMap<String, i64>,
    pub frozen: BTreeMap<String, i64>,
    pub inflight: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Obligations {
    pub refunds_minor: RefundsByStatus,
    pub order_holds_minor: BTreeMap<String, i64>,
    pub quote_holds_minor: BTreeMap<String, i64>,
    pub payout_intents_open: i64,
    pub cycles_in_flight: i64,
    pub cycle_holds_minor: BTreeMap<String, i64>,
    pub fiat_in_transit_cents: i64,
    pub offline_outstanding_minor: BTreeMap<String, i64>,
    pub offline_issuances_open: i64,
    pub offline_redemptions_pending: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodialView {
    pub source: &'static str,
    pub accounts_total: i64,
    pub page: u64,
    pub per_page: u64,
    pub checked: usize,
    pub positions: Vec<CustodialPosition>,
    pub totals: CustodialTotals,
    pub policy: CustodialPolicySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodialPosition {
    pub payala_account_id: String,
    pub stellar_account_id: String,
    pub origin: String,
    pub format_version: i16,
    pub onchain: Option<CustodialOnchain>,
    pub unreachable: bool,
    pub open_intents: i64,
    pub open_intents_minor: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodialOnchain {
    pub exists: bool,
    pub xlm_stroops: Option<i64>,
    pub balances: Vec<CustodialBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodialBalance {
    pub asset_code: String,
    pub asset_issuer: Option<String>,
    /// 7-dp minor units; null when Horizon's string does not parse.
    pub minor: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CustodialTotals {
    pub addresses_checked: usize,
    pub addresses_unreachable: usize,
    pub xlm_stroops: i64,
    pub intents_prepared: i64,
    pub intents_submitted: i64,
    pub intents_ambiguous: i64,
    /// `submitted`/`ambiguous` rows past the stale window (the sweep's
    /// backlog).
    pub intents_stale: i64,
    pub intents_settled_24h_minor: i64,
    /// The custodial walk stopped at the account or time budget.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustodialPolicySummary {
    pub paused: bool,
    pub configured: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayalaView {
    pub source: &'static str,
    pub accounts_with_reserve: i64,
    pub net_minor_by_currency: BTreeMap<String, i64>,
    pub last_batch_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CardView {
    pub source: &'static str,
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Invariant {
    pub name: &'static str,
    /// `null` = not asserted (an unverifiable state never reads as clean).
    pub ok: Option<bool>,
    pub detail: String,
}

pub const CUSTODIAL_SOURCE: &str = "managed_seed+horizon";
pub const PAYALA_SOURCE: &str = "self_reported_unverified";
pub const CARD_SOURCE: &str = "bridge_issued_only";
pub const CARD_NOTE: &str = "on-card balances never reach the bridge; only bridge-issued credits \
     and bridge-verified redemptions are counted";

// ── Arithmetic ─────────────────────────────────────────────────────────

/// `available + held`, checked.
pub fn ledger_total(available: i64, held: i64) -> Option<i64> {
    available.checked_add(held)
}

/// `onchain - ledger_total`, checked.
pub fn drift(onchain_minor: i64, ledger_total_minor: i64) -> Option<i64> {
    onchain_minor.checked_sub(ledger_total_minor)
}

/// `|drift| <= tolerance` (inclusive). `i64::MIN` has no absolute value and
/// reads as out of tolerance.
pub fn drift_ok(drift_minor: i64, tolerance_minor: i64) -> bool {
    drift_minor
        .checked_abs()
        .is_some_and(|d| d <= tolerance_minor)
}

/// Everything the gatherer read about one bucket.
#[derive(Debug, Clone)]
pub struct BucketInput {
    pub currency: String,
    pub minor_scale: i16,
    pub available: i64,
    pub held: i64,
    pub drift_tolerance: i64,
    pub journal_available: i64,
    pub journal_held: i64,
    pub asset: Option<String>,
    pub chain_leg: bool,
    /// Horizon balance string for the bucket's asset; `None` when the chain
    /// was unreadable, the reserve is unconfigured, or the trustline is
    /// missing.
    pub onchain_raw: Option<String>,
    pub trustline: Option<bool>,
    pub offline_held: i64,
}

/// Derive one bucket's position. `chain_readable` says whether the reserve
/// account was read this pass at all — a chain-legged bucket with no
/// balance on a READABLE chain is a missing trustline (onchain 0), while on
/// an unreadable chain every drift field is null.
pub fn bucket_position(b: &BucketInput, chain_readable: bool) -> (BucketPosition, Vec<String>) {
    let mut warnings = Vec::new();
    let ledger = ledger_total(b.available, b.held);
    if ledger.is_none() {
        warnings.push(format!("{}: ledger total overflows i64", b.currency));
    }
    let journal_replay_ok = b.journal_available == b.available && b.journal_held == b.held;
    if !journal_replay_ok {
        warnings.push(format!(
            "{}: journal replays to available={} held={} but the bucket reads {}/{}",
            b.currency, b.journal_available, b.journal_held, b.available, b.held
        ));
    }
    let (onchain_minor, drift_minor, ok) = if !b.chain_leg || !chain_readable {
        (None, None, None)
    } else {
        let onchain = match &b.onchain_raw {
            Some(raw) => match parse_decimal_to_minor(raw, b.minor_scale as u8) {
                Some(m) => Some(m),
                None => {
                    warnings.push(format!(
                        "{}: unparseable on-chain balance {:?}",
                        b.currency, raw
                    ));
                    None
                }
            },
            // Readable chain, no line for this asset: nothing is held there.
            None => Some(0),
        };
        match (onchain, ledger) {
            (Some(o), Some(l)) => match drift(o, l) {
                Some(d) => (Some(o), Some(d), Some(drift_ok(d, b.drift_tolerance))),
                None => {
                    warnings.push(format!("{}: drift overflows i64", b.currency));
                    (Some(o), None, None)
                }
            },
            (o, _) => (o, None, None),
        }
    };
    (
        BucketPosition {
            currency: b.currency.clone(),
            minor_scale: b.minor_scale,
            asset: b.asset.clone(),
            chain_leg: b.chain_leg,
            available_minor: b.available,
            held_minor: b.held,
            ledger_total_minor: ledger,
            journal_available_minor: b.journal_available,
            journal_held_minor: b.journal_held,
            journal_replay_ok,
            onchain_minor,
            onchain_raw: b.onchain_raw.clone(),
            trustline: b.trustline,
            drift_minor,
            drift_tolerance_minor: b.drift_tolerance,
            drift_ok: ok,
            offline_held_minor: b.offline_held,
        },
        warnings,
    )
}

/// The invariant verdicts over a gathered report. `chain_verifiable` is
/// `horizon_fresh && reserve chain read this pass`; while it is false every
/// chain-derived invariant is `null`, never `true`.
pub fn invariants(
    buckets: &[BucketPosition],
    obligations: &Obligations,
    totals: &CustodialTotals,
    chain_verifiable: bool,
    horizon_fresh: bool,
) -> Vec<Invariant> {
    let mut out = Vec::with_capacity(7);

    let bad: Vec<&str> = buckets
        .iter()
        .filter(|b| !b.journal_replay_ok)
        .map(|b| b.currency.as_str())
        .collect();
    out.push(Invariant {
        name: "reserve_journal_replays",
        ok: Some(bad.is_empty()),
        detail: if bad.is_empty() {
            String::new()
        } else {
            format!("journal does not replay: {}", bad.join(", "))
        },
    });

    let chain_legged: Vec<&BucketPosition> = buckets.iter().filter(|b| b.chain_leg).collect();
    if !chain_verifiable {
        let detail = if horizon_fresh {
            "reserve account unreadable on Horizon".to_string()
        } else {
            "Horizon head is lagging or unreachable".to_string()
        };
        out.push(Invariant {
            name: "reserve_chain_covers_ledger",
            ok: None,
            detail: detail.clone(),
        });
        out.push(Invariant {
            name: "reserve_drift_within_tolerance",
            ok: None,
            detail,
        });
    } else {
        let uncovered: Vec<String> = chain_legged
            .iter()
            .filter(|b| match (b.onchain_minor, b.ledger_total_minor) {
                (Some(o), Some(l)) => o < l,
                _ => true,
            })
            .map(|b| b.currency.clone())
            .collect();
        out.push(Invariant {
            name: "reserve_chain_covers_ledger",
            ok: Some(uncovered.is_empty()),
            detail: if uncovered.is_empty() {
                String::new()
            } else {
                format!("chain below ledger: {}", uncovered.join(", "))
            },
        });
        let drifted: Vec<String> = chain_legged
            .iter()
            .filter(|b| b.drift_ok != Some(true))
            .map(|b| {
                format!(
                    "{} drift={} tolerance={}",
                    b.currency,
                    b.drift_minor
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "?".into()),
                    b.drift_tolerance_minor
                )
            })
            .collect();
        out.push(Invariant {
            name: "reserve_drift_within_tolerance",
            ok: Some(drifted.is_empty()),
            detail: drifted.join("; "),
        });
    }

    let short: Vec<String> = buckets
        .iter()
        .filter_map(|b| {
            let queued = obligations
                .refunds_minor
                .queued
                .get(&b.currency)
                .copied()
                .unwrap_or(0);
            (b.available_minor < queued).then(|| {
                format!(
                    "{} available={} queued_refunds={}",
                    b.currency, b.available_minor, queued
                )
            })
        })
        .collect();
    out.push(Invariant {
        name: "reserve_available_covers_queued_refunds",
        ok: Some(short.is_empty()),
        detail: short.join("; "),
    });

    let unheld: Vec<String> = buckets
        .iter()
        .filter(|b| b.held_minor < b.offline_held_minor)
        .map(|b| {
            format!(
                "{} held={} offline={}",
                b.currency, b.held_minor, b.offline_held_minor
            )
        })
        .collect();
    out.push(Invariant {
        name: "offline_liabilities_are_held",
        ok: Some(unheld.is_empty()),
        detail: unheld.join("; "),
    });

    let stale_ok = totals.intents_ambiguous == 0 && totals.intents_stale == 0;
    out.push(Invariant {
        name: "custodial_no_stale_intents",
        ok: Some(stale_ok),
        detail: if stale_ok {
            String::new()
        } else {
            format!(
                "ambiguous={} stale={}",
                totals.intents_ambiguous, totals.intents_stale
            )
        },
    });

    out.push(Invariant {
        name: "custodial_addresses_reachable",
        ok: if horizon_fresh {
            Some(totals.addresses_unreachable == 0)
        } else {
            None
        },
        detail: if totals.addresses_unreachable == 0 {
            String::new()
        } else {
            format!("{} address(es) unreachable", totals.addresses_unreachable)
        },
    });
    out
}

/// Every invariant asserted AND true. A `null` verdict counts as not ok:
/// a lagging day is recorded as unattested, never as clean.
pub fn invariants_ok(invariants: &[Invariant]) -> bool {
    invariants.iter().all(|i| i.ok == Some(true))
}

/// Any chain-legged bucket outside its tolerance (verifiable buckets only).
pub fn drift_detected(buckets: &[BucketPosition]) -> bool {
    buckets.iter().any(|b| b.drift_ok == Some(false))
}

/// Whether today's daily snapshot is due: past the configured UTC hour and
/// not yet recorded for today's UTC date.
pub fn next_snapshot_due(last_daily: Option<NaiveDate>, now: DateTime<Utc>, utc_hour: u32) -> bool {
    now.hour() >= utc_hour && last_daily != Some(now.date_naive())
}

/// A schema-stamped empty report skeleton for the gatherer to fill.
pub fn schema_version() -> i32 {
    RECONCILIATION_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(currency: &str, chain_leg: bool, raw: Option<&str>) -> BucketInput {
        BucketInput {
            currency: currency.to_string(),
            minor_scale: if currency == "USD" { 2 } else { 7 },
            available: 1_000,
            held: 250,
            drift_tolerance: 0,
            journal_available: 1_000,
            journal_held: 250,
            asset: None,
            chain_leg,
            onchain_raw: raw.map(str::to_string),
            trustline: None,
            offline_held: 0,
        }
    }

    #[test]
    fn drift_is_onchain_minus_ledger() {
        let (p, w) = bucket_position(&bucket("XLM", true, Some("0.0001260")), true);
        assert!(w.is_empty());
        assert_eq!(p.ledger_total_minor, Some(1_250));
        assert_eq!(p.onchain_minor, Some(1_260));
        assert_eq!(p.drift_minor, Some(10));
        assert_eq!(p.drift_ok, Some(false)); // tolerance 0
        let (p, _) = bucket_position(&bucket("XLM", true, Some("0.0001240")), true);
        assert_eq!(p.drift_minor, Some(-10));
        assert_eq!(drift(5, 7), Some(-2));
        assert_eq!(drift(i64::MIN, 1), None);
    }

    #[test]
    fn usd_bucket_has_no_drift_leg() {
        let (p, w) = bucket_position(&bucket("USD", false, None), true);
        assert!(w.is_empty());
        assert!(!p.chain_leg);
        assert_eq!(p.onchain_minor, None);
        assert_eq!(p.drift_minor, None);
        assert_eq!(p.drift_ok, None);
        assert_eq!(p.ledger_total_minor, Some(1_250));
    }

    #[test]
    fn tolerance_boundary_inclusive() {
        assert!(drift_ok(0, 0));
        assert!(drift_ok(5, 5));
        assert!(drift_ok(-5, 5));
        assert!(!drift_ok(6, 5));
        assert!(!drift_ok(-6, 5));
        assert!(!drift_ok(i64::MIN, i64::MAX));
        let mut b = bucket("XLM", true, Some("0.0001260"));
        b.drift_tolerance = 10;
        assert_eq!(bucket_position(&b, true).0.drift_ok, Some(true));
        b.drift_tolerance = 9;
        assert_eq!(bucket_position(&b, true).0.drift_ok, Some(false));
    }

    #[test]
    fn unreadable_chain_yields_null_not_ok() {
        let (p, _) = bucket_position(&bucket("XLM", true, Some("0.0001250")), false);
        assert_eq!(p.onchain_minor, None);
        assert_eq!(p.drift_minor, None);
        assert_eq!(p.drift_ok, None);
        let inv = invariants(
            &[p.clone()],
            &Obligations::default(),
            &CustodialTotals::default(),
            false,
            true,
        );
        let by_name = |n: &str| inv.iter().find(|i| i.name == n).unwrap().clone();
        assert_eq!(by_name("reserve_chain_covers_ledger").ok, None);
        assert_eq!(by_name("reserve_drift_within_tolerance").ok, None);
        assert!(
            !invariants_ok(&inv),
            "an unverifiable state never reads as clean"
        );
        // A lagging head also un-asserts the address reachability verdict.
        let inv = invariants(
            &[p],
            &Obligations::default(),
            &CustodialTotals::default(),
            false,
            false,
        );
        assert_eq!(
            inv.iter()
                .find(|i| i.name == "custodial_addresses_reachable")
                .unwrap()
                .ok,
            None
        );
    }

    #[test]
    fn missing_trustline_on_a_readable_chain_is_zero_not_null() {
        // The reserve account was read but holds no line for this asset:
        // nothing is on-chain, and the ledger claiming otherwise is drift.
        let (p, _) = bucket_position(&bucket("USDC", true, None), true);
        assert_eq!(p.onchain_minor, Some(0));
        assert_eq!(p.drift_minor, Some(-1_250));
        assert_eq!(p.drift_ok, Some(false));
    }

    #[test]
    fn journal_replay_mismatch_flags_bucket() {
        let mut b = bucket("XLM", true, Some("0.0001250"));
        b.journal_held = 200;
        let (p, w) = bucket_position(&b, true);
        assert!(!p.journal_replay_ok);
        assert_eq!(w.len(), 1);
        let inv = invariants(
            &[p],
            &Obligations::default(),
            &CustodialTotals::default(),
            true,
            true,
        );
        let j = inv
            .iter()
            .find(|i| i.name == "reserve_journal_replays")
            .unwrap();
        assert_eq!(j.ok, Some(false));
        assert!(j.detail.contains("XLM"));
        assert!(!invariants_ok(&inv));
    }

    #[test]
    fn positions_invariants_flag_uncovered_obligations() {
        let (p, _) = bucket_position(&bucket("XLM", true, Some("0.0001250")), true);
        let mut ob = Obligations::default();
        ob.refunds_minor.queued.insert("XLM".into(), 1_001);
        let inv = invariants(&[p.clone()], &ob, &CustodialTotals::default(), true, true);
        let r = inv
            .iter()
            .find(|i| i.name == "reserve_available_covers_queued_refunds")
            .unwrap();
        assert_eq!(r.ok, Some(false));
        // Chain below ledger reads as uncovered.
        let (low, _) = bucket_position(&bucket("XLM", true, Some("0.0001000")), true);
        let inv = invariants(
            &[low],
            &Obligations::default(),
            &CustodialTotals::default(),
            true,
            true,
        );
        assert_eq!(
            inv.iter()
                .find(|i| i.name == "reserve_chain_covers_ledger")
                .unwrap()
                .ok,
            Some(false)
        );
        // Offline liabilities above held.
        let mut off = bucket("XLM", true, Some("0.0001250"));
        off.offline_held = 251;
        let (off, _) = bucket_position(&off, true);
        let inv = invariants(
            &[off],
            &Obligations::default(),
            &CustodialTotals::default(),
            true,
            true,
        );
        assert_eq!(
            inv.iter()
                .find(|i| i.name == "offline_liabilities_are_held")
                .unwrap()
                .ok,
            Some(false)
        );
        // Stale / ambiguous intents.
        let totals = CustodialTotals {
            intents_ambiguous: 1,
            ..Default::default()
        };
        let inv = invariants(&[p.clone()], &Obligations::default(), &totals, true, true);
        assert_eq!(
            inv.iter()
                .find(|i| i.name == "custodial_no_stale_intents")
                .unwrap()
                .ok,
            Some(false)
        );
        // Everything clean: seven invariants, all asserted true.
        let inv = invariants(
            &[p],
            &Obligations::default(),
            &CustodialTotals::default(),
            true,
            true,
        );
        assert_eq!(inv.len(), 7);
        assert!(invariants_ok(&inv));
        assert!(!drift_detected(&[]));
    }

    #[test]
    fn next_snapshot_due_boundary() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        let today = NaiveDate::from_ymd_opt(2026, 9, 5).unwrap();
        let yesterday = NaiveDate::from_ymd_opt(2026, 9, 4).unwrap();
        // First run ever: due once the hour has passed.
        assert!(next_snapshot_due(None, at("2026-09-05T00:00:00Z"), 0));
        assert!(!next_snapshot_due(None, at("2026-09-05T02:59:59Z"), 3));
        assert!(next_snapshot_due(None, at("2026-09-05T03:00:00Z"), 3));
        // Yesterday recorded, today not yet: due after the hour.
        assert!(next_snapshot_due(
            Some(yesterday),
            at("2026-09-05T00:00:01Z"),
            0
        ));
        // Today recorded: never due again today, whatever the hour.
        assert!(!next_snapshot_due(
            Some(today),
            at("2026-09-05T23:59:59Z"),
            0
        ));
        // The UTC date is what counts, not a local one.
        assert!(!next_snapshot_due(
            Some(today),
            at("2026-09-05T23:00:00Z"),
            0
        ));
        assert!(next_snapshot_due(
            Some(today),
            at("2026-09-06T00:00:00Z"),
            0
        ));
    }

    #[test]
    fn schema_version_is_pinned() {
        assert_eq!(schema_version(), 1);
    }
}
