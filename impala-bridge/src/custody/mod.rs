//! Custodial conservation controls (migration 037).
//!
//! - [`intent`] — the write-ahead row behind `POST /managed-account/sign`:
//!   claim (replay + policy) → arm (hash before submit) → submit → settle.
//! - [`policy`] — the pause switch and spend caps, evaluated inside the
//!   claim transaction from ONE Postgres row (never a cache).
//! - [`fingerprint`] — what "the same request" means for an idempotency key.
//! - [`sweep`] — crash recovery: abandon unarmed rows, resolve armed ones
//!   by hash.
//!
//! The admin surface lives in `handlers::admin_custody`; the owner surface
//! in `handlers::managed_seed`.

pub mod fingerprint;
pub mod intent;
pub mod policy;
pub mod sweep;

#[cfg(test)]
mod tripwires {
    //! Order-of-operations pins over the source text. These exist because
    //! "policy after the seed was opened" and "submit before the hash was
    //! persisted" both compile clean and pass every behavioural test.

    const INTENT_SRC: &str = include_str!("intent.rs");
    const HANDLER_SRC: &str = include_str!("../handlers/managed_seed.rs");

    /// The non-test body of intent.rs from the claim function onward — the
    /// slice in which every marker is a USE, not a definition.
    fn intent_body() -> &'static str {
        let start = INTENT_SRC
            .find("pub(crate) async fn claim_user_payment")
            .expect("claim fn present");
        let end = INTENT_SRC.find("#[cfg(test)]").expect("tests present");
        &INTENT_SRC[start..end]
    }

    fn pos(hay: &str, needle: &str) -> usize {
        hay.find(needle)
            .unwrap_or_else(|| panic!("marker {:?} not found", needle))
    }

    #[test]
    fn custodial_sign_orders_policy_before_seed_and_hash_before_submit() {
        let body = intent_body();
        let policy = pos(body, "POLICY_READ_SQL");
        let insert = pos(body, "INTENT_INSERT_SQL");
        let seed = pos(body, "load_protected_seed(");
        let prepare = pos(body, "prepare_payment(");
        let arm = pos(body, "INTENT_ARM_SQL");
        let submit = pos(body, "submit_prepared(");
        assert!(
            policy < insert,
            "policy must be evaluated before the intent row exists"
        );
        assert!(
            insert < seed,
            "the intent row must exist before the seed is opened"
        );
        assert!(seed < prepare, "the seed is opened before signing");
        assert!(prepare < arm, "the hash comes from the prepared envelope");
        assert!(
            arm < submit,
            "hash before submit: no persisted hash, no submit"
        );
        // The claim happens in the handler before the submit task is spawned.
        let handler = &HANDLER_SRC[pos(HANDLER_SRC, "pub async fn sign_and_submit(")..];
        assert!(pos(handler, "claim_user_payment(") < pos(handler, "submit_intent("));
    }

    #[test]
    fn claimed_without_hash_is_provably_unsubmitted() {
        let body = intent_body();
        let insert = pos(body, "INTENT_INSERT_SQL");
        let arm = pos(body, "INTENT_ARM_SQL");
        let between = &body[insert..arm];
        assert!(
            !between.contains("submit_prepared("),
            "nothing may be submitted between the claim and the arm"
        );
        assert!(
            !between.contains("sign_and_submit"),
            "the fused signer is banned on the custodial path"
        );
        // And the arm's failure branch returns before any submit.
        let after_arm = &body[arm..pos(body, "submit_prepared(")];
        assert!(after_arm.contains("rows_affected() == 1"));
        assert!(after_arm.contains("NOT submitting"));
    }

    #[test]
    fn pause_path_never_touches_redis() {
        // The pause switch and the caps are Postgres rows read inside the
        // claim transaction; a cache outage must never fail the brake open
        // or closed.
        assert!(
            !INTENT_SRC.to_ascii_lowercase().contains("redis"),
            "custody/intent.rs must not reference the cache"
        );
        assert!(!include_str!("policy.rs")
            .to_ascii_lowercase()
            .contains("redis"));
        assert!(!include_str!("sweep.rs")
            .to_ascii_lowercase()
            .contains("redis"));
    }

    #[test]
    fn pause_precedes_seed_load() {
        let body = intent_body();
        assert!(pos(body, "policy.paused") < pos(body, "load_protected_seed("));
        assert!(pos(body, "Refusal::Paused") < pos(body, "load_protected_seed("));
    }

    #[test]
    fn no_driver_calls_the_fused_signer() {
        // There is no fused sign+submit for payments any more: every money
        // path is prepare_payment -> persist hash -> submit_prepared, so an
        // ambiguous submit is always resolvable by an exact hash lookup.
        // The trait must not grow one back, and no driver may spell one.
        let fused = ["sign_and_submit", "_payment("].concat();
        assert!(
            !include_str!("../stellar/signer.rs").contains(&fused),
            "the signer trait must not offer a fused payment path"
        );
        for (name, src) in [
            ("managed_seed.rs", HANDLER_SRC),
            ("custody/intent.rs", INTENT_SRC),
            ("custody/sweep.rs", include_str!("sweep.rs")),
            ("custody/policy.rs", include_str!("policy.rs")),
            ("custody/fingerprint.rs", include_str!("fingerprint.rs")),
            (
                "handlers/admin_custody.rs",
                include_str!("../handlers/admin_custody.rs"),
            ),
            (
                "handlers/admin_reserve.rs",
                include_str!("../handlers/admin_reserve.rs"),
            ),
            (
                "exchange/reserve_watch.rs",
                include_str!("../exchange/reserve_watch.rs"),
            ),
            (
                "exchange/replenish.rs",
                include_str!("../exchange/replenish.rs"),
            ),
        ] {
            assert!(
                !src.contains(&fused),
                "{} calls the fused signer; use prepare_payment + submit_prepared",
                name
            );
        }
    }

    #[test]
    fn signing_paths_never_read_payala_tables() {
        // Quarantine: nothing that signs may read the unverified Payala
        // mirror (payala_reserve, transaction.payala_amount, payala_sync_*).
        for (name, src) in [
            ("managed_seed.rs", HANDLER_SRC),
            ("custody/intent.rs", INTENT_SRC),
            ("custody/sweep.rs", include_str!("sweep.rs")),
            ("custody/policy.rs", include_str!("policy.rs")),
            (
                "exchange/reserve_watch.rs",
                include_str!("../exchange/reserve_watch.rs"),
            ),
            (
                "exchange/replenish.rs",
                include_str!("../exchange/replenish.rs"),
            ),
            (
                "handlers/admin_reserve.rs",
                include_str!("../handlers/admin_reserve.rs"),
            ),
        ] {
            for forbidden in ["payala_reserve", "payala_amount", "payala_sync_"] {
                assert!(
                    !src.contains(forbidden),
                    "{} references {} — the signing path must not read Payala tables",
                    name,
                    forbidden
                );
            }
        }
    }

    #[test]
    fn the_old_settle_then_record_insert_is_gone() {
        // The pre-037 handler inserted the transaction row AFTER the
        // fused sign+submit; the only ledger INSERT on the custodial path
        // now lives behind record_settlement.
        assert!(!HANDLER_SRC.contains("INSERT INTO transaction"));
        assert_eq!(INTENT_SRC.matches("INSERT INTO transaction").count(), 1);
    }
}
