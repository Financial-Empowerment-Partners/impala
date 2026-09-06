//! Custodial policy: the pause switch and the spend caps, evaluated inside
//! the claim transaction (`custody::intent::claim_user_payment`).
//!
//! The switch and the caps live in ONE Postgres row (`custodial_policy`,
//! 037 part B) read `FOR SHARE` under the per-account transaction lock, so
//! a pause committed before a claim is always seen by that claim and a
//! claim never reads caps that a concurrent edit is halfway through. The
//! decision itself is a pure function so every branch is unit-tested.
//!
//! `0` for a cap means UNCONFIGURED and refuses (032 precedent) — there is
//! deliberately no way to express "unlimited".

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;

use crate::constants::CUSTODIAL_DAILY_WINDOW_SECS;
use crate::error::AppError;

/// The policy row, locked FOR SHARE for the life of the claim transaction
/// (a concurrent `PUT`/pause waits; a committed one is always observed).
pub(crate) const POLICY_READ_SQL: &str = "SELECT paused, per_tx_max_stroops, \
        per_account_daily_max_stroops, require_idempotency_key \
     FROM custodial_policy WHERE id FOR SHARE";

/// Per-account override (NULL = global cap applies; 0 = frozen), key-locked
/// so the account row cannot vanish under the claim.
pub(crate) const ACCOUNT_LIMIT_SQL: &str = "SELECT custodial_daily_max_stroops \
     FROM impala_account WHERE payala_account_id = $1 FOR KEY SHARE";

/// Rolling-window spend for one account. Every non-rejected `sign` intent
/// counts — prepared, submitted, ambiguous AND settled — because an
/// unresolved outcome is money until proven otherwise (the reserve's refund
/// cap counts intents the same way).
pub(crate) const DAILY_SPEND_SQL: &str = "SELECT COALESCE(SUM(amount_minor), 0)::bigint, \
        MIN(created_at) \
     FROM custodial_payment_intent \
     WHERE payala_account_id = $1 AND origin = 'sign' AND status <> 'rejected' \
       AND created_at >= CURRENT_TIMESTAMP - make_interval(secs => $2)";

/// The policy row as read by `POLICY_READ_SQL`.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub(crate) struct PolicyRow {
    pub paused: bool,
    pub per_tx_max_stroops: i64,
    pub per_account_daily_max_stroops: i64,
    pub require_idempotency_key: bool,
}

impl PolicyRow {
    /// Both caps set: custodial signing is enabled (subject to `paused`).
    pub(crate) fn is_configured(&self) -> bool {
        self.per_tx_max_stroops > 0 && self.per_account_daily_max_stroops > 0
    }
}

/// Why a custodial payment is refused. Each maps to exactly one code from
/// `CUSTODIAL_REFUSAL_CODES`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Refusal {
    Paused,
    Unconfigured,
    AccountFrozen,
    PerTx {
        max: i64,
    },
    Daily {
        remaining: i64,
        resets_at: Option<DateTime<Utc>>,
    },
}

impl Refusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Refusal::Paused => "custodial_paused",
            Refusal::Unconfigured => "custodial_unconfigured",
            Refusal::AccountFrozen => "custodial_account_frozen",
            Refusal::PerTx { .. } => "custodial_tx_limit",
            Refusal::Daily { .. } => "custodial_daily_limit",
        }
    }

    /// The machine-readable refusal. `503` for the switch/unconfigured
    /// states ("never sent", safe to retry later), `409` for account-level
    /// refusals, `400` for a request over the per-transaction cap.
    pub(crate) fn into_error(self) -> AppError {
        let code = self.code();
        match self {
            Refusal::Paused => AppError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                code,
                "Custodial payments are paused by an operator",
            ),
            Refusal::Unconfigured => AppError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                code,
                "Custodial payment caps are not configured on this bridge",
            ),
            Refusal::AccountFrozen => AppError::coded(
                StatusCode::CONFLICT,
                code,
                "Custodial payments from this account are frozen",
            ),
            Refusal::PerTx { max } => AppError::coded(
                StatusCode::BAD_REQUEST,
                code,
                format!(
                    "Amount exceeds the per-transaction cap of {} stroops",
                    max
                ),
            )
            .with_details(json!({ "per_tx_max_stroops": max })),
            Refusal::Daily {
                remaining,
                resets_at,
            } => AppError::coded(
                StatusCode::CONFLICT,
                code,
                format!(
                    "Amount exceeds this account's remaining daily allowance of {} stroops",
                    remaining
                ),
            )
            .with_details(json!({
                "remaining_stroops": remaining,
                "resets_at": resets_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            })),
        }
    }
}

/// The policy decision, in this order: paused → unconfigured → account
/// frozen → per-transaction cap → daily cap. Pure.
///
/// `account_override`: `Some(0)` freezes the account; `Some(n)` replaces the
/// global daily cap (even when the global one is 0 — an explicit per-account
/// grant is a configuration); `None` means the global cap applies.
/// `spent_24h` is every non-rejected intent in the window and `window_start`
/// the oldest of them (so `resets_at` is when the oldest drops out).
pub(crate) fn evaluate_policy(
    policy: &PolicyRow,
    account_override: Option<i64>,
    spent_24h: i64,
    window_start: Option<DateTime<Utc>>,
    amount_minor: i64,
) -> Result<(), Refusal> {
    if policy.paused {
        return Err(Refusal::Paused);
    }
    let global_daily = policy.per_account_daily_max_stroops;
    if policy.per_tx_max_stroops == 0 || (global_daily == 0 && account_override.is_none()) {
        return Err(Refusal::Unconfigured);
    }
    if account_override == Some(0) {
        return Err(Refusal::AccountFrozen);
    }
    if amount_minor > policy.per_tx_max_stroops {
        return Err(Refusal::PerTx {
            max: policy.per_tx_max_stroops,
        });
    }
    let effective_daily = account_override.unwrap_or(global_daily);
    let daily_refusal = || Refusal::Daily {
        remaining: effective_daily.saturating_sub(spent_24h).max(0),
        resets_at: window_start.map(|t| t + Duration::seconds(CUSTODIAL_DAILY_WINDOW_SECS)),
    };
    match spent_24h.checked_add(amount_minor) {
        Some(total) if total <= effective_daily => Ok(()),
        _ => Err(daily_refusal()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CUSTODIAL_REFUSAL_CODES;

    fn policy(paused: bool, per_tx: i64, daily: i64) -> PolicyRow {
        PolicyRow {
            paused,
            per_tx_max_stroops: per_tx,
            per_account_daily_max_stroops: daily,
            require_idempotency_key: false,
        }
    }

    #[test]
    fn caps_refuse_when_unconfigured() {
        // A freshly migrated deployment carries 0/0 and must refuse rather
        // than read 0 as "no limit".
        assert_eq!(
            evaluate_policy(&policy(false, 0, 0), None, 0, None, 1),
            Err(Refusal::Unconfigured)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 0, 100), None, 0, None, 1),
            Err(Refusal::Unconfigured)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 100, 0), None, 0, None, 1),
            Err(Refusal::Unconfigured)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 100, 100), None, 0, None, 1),
            Ok(())
        );
        assert!(!policy(false, 100, 0).is_configured());
        assert!(policy(false, 100, 100).is_configured());
    }

    #[test]
    fn override_zero_freezes_the_account() {
        assert_eq!(
            evaluate_policy(&policy(false, 100, 100), Some(0), 0, None, 1),
            Err(Refusal::AccountFrozen)
        );
    }

    #[test]
    fn override_replaces_global_even_when_global_is_zero() {
        // An explicit per-account grant is a configuration in its own right.
        assert_eq!(
            evaluate_policy(&policy(false, 100, 0), Some(50), 0, None, 50),
            Ok(())
        );
        assert!(matches!(
            evaluate_policy(&policy(false, 100, 0), Some(50), 0, None, 51),
            Err(Refusal::Daily { remaining: 50, .. })
        ));
        // ...and it replaces (never widens by) the global cap.
        assert!(matches!(
            evaluate_policy(&policy(false, 100, 1_000), Some(10), 0, None, 11),
            Err(Refusal::Daily { remaining: 10, .. })
        ));
    }

    #[test]
    fn daily_counts_every_non_rejected_status() {
        // SQL pin: prepared/submitted/ambiguous/settled all count as spent;
        // only rejected rows drop out, and only `sign` intents count.
        assert!(DAILY_SPEND_SQL.contains("status <> 'rejected'"));
        assert!(DAILY_SPEND_SQL.contains("origin = 'sign'"));
        assert!(DAILY_SPEND_SQL.contains("make_interval(secs => $2)"));
        // And the arithmetic side: spent + amount over the cap refuses.
        let start = Utc::now();
        let r = evaluate_policy(&policy(false, 100, 100), None, 60, Some(start), 41);
        match r {
            Err(Refusal::Daily {
                remaining,
                resets_at,
            }) => {
                assert_eq!(remaining, 40);
                assert_eq!(
                    resets_at,
                    Some(start + Duration::seconds(CUSTODIAL_DAILY_WINDOW_SECS))
                );
            }
            other => panic!("expected Daily, got {:?}", other),
        }
        assert_eq!(
            evaluate_policy(&policy(false, 100, 100), None, 60, Some(start), 40),
            Ok(())
        );
    }

    #[test]
    fn daily_overflow_is_checked_arithmetic() {
        let r = evaluate_policy(
            &policy(false, i64::MAX, i64::MAX),
            None,
            i64::MAX - 1,
            None,
            2,
        );
        assert!(
            matches!(r, Err(Refusal::Daily { .. })),
            "overflow must refuse, never wrap"
        );
        // remaining never goes negative even when spend already exceeds the cap
        // (a lowered cap after spending).
        match evaluate_policy(&policy(false, 100, 10), None, 50, None, 1) {
            Err(Refusal::Daily { remaining, .. }) => assert_eq!(remaining, 0),
            other => panic!("expected Daily, got {:?}", other),
        }
    }

    #[test]
    fn decision_order_is_pause_unconfigured_frozen_pertx_daily() {
        // Every later condition also holds in each case; the earlier one wins.
        assert_eq!(
            evaluate_policy(&policy(true, 0, 0), Some(0), 1_000, None, 1_000),
            Err(Refusal::Paused)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 0, 0), Some(0), 1_000, None, 1_000),
            Err(Refusal::Unconfigured)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 10, 10), Some(0), 1_000, None, 1_000),
            Err(Refusal::AccountFrozen)
        );
        assert_eq!(
            evaluate_policy(&policy(false, 10, 10), None, 1_000, None, 1_000),
            Err(Refusal::PerTx { max: 10 })
        );
        assert!(matches!(
            evaluate_policy(&policy(false, 10, 10), None, 1_000, None, 10),
            Err(Refusal::Daily { .. })
        ));
    }

    #[test]
    fn policy_read_is_for_share_single_row() {
        assert!(POLICY_READ_SQL.ends_with("WHERE id FOR SHARE"));
        assert!(!POLICY_READ_SQL.contains("LIMIT"));
        assert!(ACCOUNT_LIMIT_SQL.contains("FOR KEY SHARE"));
    }

    #[test]
    fn every_refusal_code_is_in_the_pinned_list() {
        let all = [
            Refusal::Paused,
            Refusal::Unconfigured,
            Refusal::AccountFrozen,
            Refusal::PerTx { max: 1 },
            Refusal::Daily {
                remaining: 0,
                resets_at: None,
            },
        ];
        for r in all {
            assert!(
                CUSTODIAL_REFUSAL_CODES.contains(&r.code()),
                "{} missing from CUSTODIAL_REFUSAL_CODES",
                r.code()
            );
            let err = r.clone().into_error();
            match &err {
                AppError::Coded { code, status, .. } => {
                    assert_eq!(*code, r.code());
                    let expected = match r {
                        Refusal::Paused | Refusal::Unconfigured => StatusCode::SERVICE_UNAVAILABLE,
                        Refusal::AccountFrozen | Refusal::Daily { .. } => StatusCode::CONFLICT,
                        Refusal::PerTx { .. } => StatusCode::BAD_REQUEST,
                    };
                    assert_eq!(*status, expected, "{}", code);
                }
                other => panic!("refusal must map to Coded, got {:?}", other),
            }
        }
    }

    #[test]
    fn daily_refusal_details_carry_remaining_and_reset() {
        let start = DateTime::parse_from_rfc3339("2026-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let err = Refusal::Daily {
            remaining: 7,
            resets_at: Some(start),
        }
        .into_error();
        match err {
            AppError::Coded { details, .. } => {
                let d = details.expect("details");
                assert_eq!(d["remaining_stroops"], 7);
                assert_eq!(d["resets_at"], "2026-01-15T12:00:00Z");
            }
            other => panic!("{:?}", other),
        }
    }
}
