# Conservation specification — where value lives, how it moves, and what proves it

This document is the money map of the bridge. It names every place a balance
is owned, every transition that moves value between them, the primitive that
makes each transition happen exactly once, what happens when the process dies
in the middle, and the test that pins each of those facts to the source. It is
a reference for reviewers and operators, not a design proposal: everything
under "today" describes the tree as it is, and everything marked *pending* is
named as such.

It is pinned by `impala-bridge/src/models.rs::conservation_spec_names_every_vocabulary`:
every state literal of the vocabularies in Appendix A, every event type in
Appendix B, and every test named in §3 and §6 must appear here verbatim, and
every named test must exist in the bridge source. A doc edit therefore runs the
bridge test job (`.github/workflows/ci.yml` lists this file in its path filter).

Related: `ARCHITECTURE.md` (system design), `docs/runbooks/conversion-reserve.md`
(reserve operations), `impala-bridge/SECURITY.md` (threat model),
`impala-bridge/migrations/037_custodial_conservation.sql` (the schema this
document describes).

---

## 1. Scope and honesty statement

The bridge is custodial. It signs with keys it holds, on behalf of accounts it
does not own, and it keeps ledgers that claim to describe money it does not
control. The following statements are the ground truth of this document and of
the positions endpoint; nothing below may quietly contradict them.

- **S1 — The chain is authoritative for Stellar.** A Stellar balance is what
  Horizon reports for the address. The bridge never holds a Stellar balance in
  a table; it holds *claims* about one.
- **S2 — `conversion_reserve` is a mirror with an obligation.** Each
  chain-legged bucket (`XLM`, `USDC`, `USDT0` when configured) must satisfy
  `available + held == on-chain balance` for the reserve address, within the
  bucket's `drift_tolerance_minor`. The bucket is the bridge's own promise; the
  positions endpoint (§8) checks the promise against S1. `USD` has no chain leg
  and is asserted only.
- **S3 — The Soroban wrapper is unobserved.** `SOROBAN_CONTRACT_ID` is
  informational. The bridge does not read wrapper balances, does not credit or
  debit on wrapper events, and no conservation statement here covers value
  inside the wrapper.
- **S4 — Payala mirrors are unverified assertions with no value.**
  `payala_reserve`, `payala_sync_batch` / `payala_sync_item`,
  `transaction.payala_amount` and `POST /transaction` record what a client
  *said*. Nothing that signs reads them (§4.5), nothing that reconciles counts
  them as backing, and the positions endpoint labels them
  `self_reported_unverified`.
- **S5 — On-card balances are unbacked today.** The card applet's `myBalance`
  is credited by `VERIFY_TRANSFER` under any key whose counter is higher than
  the last one seen; until the card area ships issuer-key verification and the
  bridge issues certificates (PR4, pending), a card balance is mintable and the
  bridge counts none of it.
- **S6 — No transition crosses a domain boundary today.** Value never moves
  from the chain into a card, or from a card back to the chain, through any
  bridge primitive. Cross-domain conservation is therefore *vacuously
  unenforced*, not enforced. The pending offline design (§5) creates an offline
  unit only after a journaled hold on the reserve and releases it on-chain only
  from a write-ahead intent that names a verified debit proof.

What this document does **not** claim: that every balance in the system sums
to a constant (it cannot, see S3–S6), or that any control here protects
against a compromise of the database *and* the seed protector together.

---

## 2. Domains, owners, units

Seven owners hold balances. Each row is a distinct source of truth; a
transition between two rows is a domain crossing and needs an anchor (§3).

| # | Domain | Owner of the number | Unit | Bridge's relationship |
|---|---|---|---|---|
| 1 | Stellar ledger accounts — every `managed_seed.stellar_account_id` (users) and the reserve address | Horizon / the network | integer stroops (XLM, 7 dp) or asset minor units (`minor_scale` per bucket) | signs from seeds it protects; reads balances; never stores them |
| 2 | `conversion_reserve` buckets (`available`, `held`, `minor_scale`, `low_water`, `refund_max_minor`, `refund_daily_max_minor`, `drift_tolerance_minor`) | the bridge | integer minor | the obligated mirror of the reserve address (S2) |
| 3 | `conversion_reserve_entry` journal (`delta`, `held_delta`, `balance_after`, `held_after`, `kind`) | the bridge | integer minor | append-only; replays the buckets (§4.1) |
| 4 | Payala mirror — `payala_reserve`, `payala_sync_batch`, `payala_sync_item` | the Payala backend (client-asserted) | integer minor as declared by the client | stored, aggregated, never trusted (S4) |
| 5 | `transaction` rows (`stellar_hash`, `payala_amount`, `stellar_amount_minor`, `stellar_destination`, `stellar_asset_code`, `stellar_asset_issuer`, `origin`) | the bridge | mixed: the settlement columns are integer minor; `payala_amount` is a client assertion | audit mirror of settled custodial payments and of client claims; never a balance |
| 6 | Soroban wrapper contract | the contract | contract units | unobserved (S3) |
| 7 | Card applet `myBalance` | the card | `uint32` at card scale | unobserved and unbacked (S5) |

**Units.** Money is integer minor units everywhere: 7 decimal places for
Stellar assets (`RESERVE_SCALE_STELLAR`), 2 for USD (`RESERVE_SCALE_USD`),
summed in `i64` with checked arithmetic. `parse_decimal_to_minor` and
`minor_to_decimal_string` (`impala-bridge/src/exchange/reserve.rs`) are the
only boundary between decimal strings on the wire and integers in the
database; floats never touch money. Card amounts (pending, PR4) are `uint32`
at the card's own scale and are converted by `card_to_bucket_minor` with an
exactness check — a conversion that would lose digits is refused, never
rounded.

---

## 3. As-is state machines

One table per domain. Columns: *transition* (what moves), *owner* (which
component performs it), *unique id* (the row that represents the transition),
*idempotency anchor* (the constraint or CAS that makes it happen at most once),
*crash recovery* (what happens if the process dies after the row exists and
before the transition completes), *event* (outbox type, if any), *pinning
test* (the test that fails if the fact stops being true; `no test` is written
where none exists).

Every write below is a guarded single-statement `UPDATE` naming its from-state,
or an `INSERT` under a `UNIQUE` anchor, inside one transaction with its journal
row and its outbox event. Ambiguous on-chain submits are never resubmitted by
software; they are resolved by an exact hash lookup or by a human.

### 3.1 Custodial user payment (`POST /managed-account/sign`)

Before migration 037 this path had no anchor: the handler signed and submitted
in one fused call and inserted its `transaction` row afterwards ("settle then
record"), so a retry or a crash between the submit and the insert could pay
twice or record nothing. Today every payment is a `custodial_payment_intent`
row written *before* the seed is opened, armed with the signed envelope's hash
*before* Horizon sees it, and closed by a compare-and-swap.

Statuses: `prepared` → `submitted` → `settled` | `rejected` | `ambiguous`
(`ambiguous` → `settled` | `rejected` by hash). Resolutions: `submit_ok`,
`submit_rejected`, `prepare_rejected`, `arm_failed`, `sweep_settled`,
`sweep_failed`, `sweep_expired`, `sweep_abandoned`, `admin_complete`,
`admin_fail`.

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| claim: policy read → intent row `prepared` | handler (`custody::intent::claim_user_payment`), one transaction under `pg_advisory_xact_lock` per account | `intent_id` | `uq_custodial_intent_key (payala_account_id, idempotency_key)` — replay returns the recorded outcome and never re-signs; `uq_custodial_intent_one_inflight` — one non-terminal `sign` intent per account | a `prepared` row with no hash provably never submitted; the sweep rejects it `sweep_abandoned` after `CUSTODIAL_INTENT_ABANDON_SECS` | — | `replay_decision_table`, `same_key_different_fingerprint_is_conflict`, `one_inflight_index_is_partial_on_sign_origin`, `intent_insert_binds_thirteen_and_matches_ddl`, `decision_order_is_pause_unconfigured_frozen_pertx_daily` |
| arm: `prepared` → `submitted` with `stellar_hash` | submit task (`submit_intent`), after `prepare_payment`, before `submit_prepared` | `stellar_hash` | `INTENT_ARM_SQL` CAS on `status = 'prepared' AND stellar_hash IS NULL`; `uq_custodial_intent_hash` | rows affected ≠ 1 ⇒ no submit (`arm_failed`); a late arm after the sweep abandoned the row loses its CAS | — | `arm_sql_requires_prepared_and_null_hash`, `claimed_without_hash_is_provably_unsubmitted`, `custodial_sign_orders_policy_before_seed_and_hash_before_submit` |
| submit → `settled` (+ `transaction` row, origin `custodial_sign`) | submit task → `record_settlement` | `btxid` | `INTENT_SETTLE_SQL` CAS on `status IN ('submitted','ambiguous') AND stellar_hash = $4`; 0 rows ⇒ rollback, the duplicate `transaction` row is discarded | settled on-chain but the settle transaction failed ⇒ the intent stays `submitted` and the sweep records it by hash (the client sees 202, never a 200 with `btxid: null`) | `custodial.payment_settled` | `settle_sql_requires_hash_and_open_status`, `settlement_transaction_insert_binds_ten`, `settled_unrecorded_is_202_never_200_with_null_btxid`, `the_old_settle_then_record_insert_is_gone` |
| submit → `rejected` (Horizon 400 with result codes, or pre-submit `BadRequest`) | submit task | — | `INTENT_REJECT_SUBMITTED_SQL` / `INTENT_REJECT_PREPARED_SQL`, each naming its from-state | none needed: a definitive rejection is final | — | `only_horizon_400_with_result_codes_is_definitive`, `presubmit_retryable_is_transient_rejection_not_ambiguous` |
| submit → `ambiguous` (timeout, 5xx, transport) | submit task | — | `INTENT_AMBIGUOUS_SQL` CAS on `status = 'submitted'` | never resubmitted; resolved by hash below | `custodial.payment_ambiguous` | `ambiguous_sql_only_leaves_submitted`, `ambiguous_maps_to_202_and_is_never_resubmitted` |
| sweep: `submitted`/`ambiguous` older than `CUSTODIAL_STALE_INTENT_SECS` → `settled` (`sweep_settled`) / `rejected` (`sweep_failed`, `sweep_expired`) / left | `custody::sweep::run` under `CUSTODIAL_SWEEP_LOCK_KEY`, every `CUSTODIAL_SWEEP_INTERVAL_SECS` | `stellar_hash` | the same settle/reject CAS; `NotFound` counts as expired only when the Horizon head is fresh (`HORIZON_MAX_LAG_SECS`) and the row is older than the envelope's validity window | idempotent: every write is a CAS, the lock only prevents duplicate work | `custodial.payment_settled` | `sweep_verdict_table`, `stale_head_is_inconclusive`, `unreadable_chain_yields_leave_not_reject`, `stale_sql_selects_only_armed_open_rows`, `abandon_sql_never_touches_armed_rows`, `settles_requires_successful_matching_payment`, `failed_tx_is_rejected_not_settled` |
| admin resolve: `complete` (chain-verified hash) / `fail` (proven absent after the stale window) | `admin_custody::resolve_intent` (`Privileged<ManageCustody>`) | `intent_id` | the same CAS; `fail` requires `resolve_intent_by_hash == Ok(None)` on a fresh Horizon | idempotent | `custody.intent_resolved` (+ the settle/reject events) | `resolve_reads_the_chain_before_every_write`, `custody_admin_mutations_are_guarded_single_statements` |
| account deletion while an intent is non-terminal | `admin::delete_account` | — | refused 409 while `prepared`/`submitted`/`ambiguous` rows exist | — | — | `delete_guard_covers_every_non_terminal_intent_status` |

Policy is evaluated inside the claim transaction from one Postgres row
(`custodial_policy`, `FOR SHARE`), before the seed is opened, and Redis is never
consulted on that path (`pause_path_never_touches_redis`,
`pause_precedes_seed_load`). Refusals are machine-readable codes
(`CUSTODIAL_REFUSAL_CODES`; `every_refusal_code_is_in_the_pinned_list`).

### 3.2 Reserve order (quote → deposit → payout)

Order statuses: `created`, `awaiting_deposit`, `processing`, `on_hold`,
`completed`, `failed`, `refunded`, `expired`. Journal kinds on this path:
`quote_hold`, `quote_release`, `quote_consume`, `hold`, `hold_release`,
`deposit`, `unmatched_deposit`, `payout_attempt`, `fulfillment`,
`disbursement`.

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| quote: price lock holds capacity (`quote_hold`; `quote_release` on expiry, `quote_consume` on order) | `exchange::reserve_quote` | quote id | `RESERVE_HOLD_SQL` — the hold succeeds only if the bucket covers it AND total holds stay ≤ half the pool | an expired lock is released by the watcher tick; a lock is never consumed twice | — | `hold_sql_guards_balance_and_fraction`, `bucket_apply_sql_guards_both_columns` |
| order create: `hold` → `awaiting_deposit` | `handlers::exchange` | `order_id` | `ORDER_HOLD_SQL`; `RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT` | the hold and the order row commit together | `exchange.order_created`, `reserve.payout_pending` | `hold_sql_guards_balance_and_fraction` |
| deposit matched: `deposit` → `processing` | deposit watcher (`reserve_watch::process_payment`) under `RESERVE_WATCHER_LOCK_KEY` | Horizon `paging_token` | one credit per `paging_token`; the cursor (`conversion_reserve_state.horizon_cursor`) is monotonic | a replayed Horizon page hits the same anchor; a late deposit after expiry is recorded as `unmatched_deposit`, never credited to the order | `reserve.deposit_matched`, `reserve.unmatched_deposit`, `reserve.unmatched_deposit_summary` | `expiry_and_replay_sql_are_guarded`, `late_deposit_after_expiry_is_recorded_not_credited_to_order`, `unmatched_insert_records_the_payer`, `claim_sql_collapses_every_invalid_case_to_zero_rows` |
| payout: `payout_attempt` (hash recorded before submit) → `fulfillment` (`completed`) | payout driver (`reserve_watch`) inside the tick | `payout_attempt` row, `UNIQUE(order_id, kind)`; `stellar_tx_hash` | `record_intent_hash(IntentKey::Order)` must affect exactly one row or nothing is submitted | definitive rejection ⇒ bounded retry (≤ `RESERVE_MAX_PAYOUT_ATTEMPTS`); ambiguous ⇒ `on_hold`, never resubmitted; a crash between submit and record is found by `STALE_INTENT_SQL` and resolved by hash | `reserve.fulfilled` | `due_payouts_sql_selects_only_claimable_auto_swaps`, `stale_intent_sql_only_covers_unrecorded_outcomes`, `only_horizon_400_with_result_codes_is_definitive`, `presubmit_retryable_is_transient_rejection_not_ambiguous` |
| admin resolve of `on_hold` (≥ 600 s, chain-verified) → `completed` / `failed` (refund queued) | `admin_reserve::resolve_order` (`Privileged<ManageReserve>`) | `order_id` | guarded CAS on `on_hold`; `verify_settlement_hash` before any credit | idempotent | `exchange.order_updated` | `claim_sql_collapses_every_invalid_case_to_zero_rows` |
| expiry: `awaiting_deposit` → `expired` + `hold_release` | watcher tick, gated on a fresh Horizon head (an unreadable chain never expires anything) | `order_id` | `EXPIRABLE_SQL` names its from-state | idempotent | `reserve.order_expired` | `expiry_sql_only_touches_awaiting_deposit`, `head_freshness_boundary` |
| disbursement (fiat leg) `disbursement` | `admin_reserve::disburse_order` | `order_id` | guarded CAS | — | `reserve.disbursement_pending` | `claim_sql_collapses_every_invalid_case_to_zero_rows` |

### 3.3 Refund obligation (`conversion_reserve_refund`)

Statuses: `needs_review`, `queued`, `inflight`, `sent`, `failed`, `frozen`,
`cancelled`. Journal kinds: `refund_intent`, `refund_sent`, `refund_reversal`.

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| obligation created from an unmatched inflow: `queued` or `needs_review` (caps, dust, unsafe destination) | deposit watcher (`queue_refund`) | `refund_id` | one obligation per payment (`UNIQUE(source_paging_token)`); dust below `RESERVE_REFUND_MIN_MINOR` is recorded without an obligation | commits with the unmatched row | `reserve.refund_queued` | `caps_park_for_review_and_dust_is_recorded_without_an_obligation`, `refunds_refuse_unsafe_destinations`, `unmatched_insert_records_the_payer` |
| `queued` → `inflight`: CAS + `refund_intent` write-ahead debit + 24 h cap (`refund_daily_max_minor`), hash recorded before submit | refund driver (`drive_refunds`) inside the tick | `refund_intent` row; `stellar_tx_hash` | `CLAIM_REFUND_SQL` names its from-state; `record_intent_hash(IntentKey::Refund)` exactly one row | a crash between submit and record is found by `STALE_REFUND_SQL` and resolved by hash | — | `refund_sql_guards_every_transition`, `usd_float_is_never_refunded_on_chain` |
| `inflight` → `sent` (`refund_sent`) | refund driver | `stellar_tx_hash` | CAS on `inflight` | idempotent | `reserve.refund_sent` | `refund_sql_guards_every_transition` |
| `inflight` → `queued` / `failed` with `refund_reversal` (definitive rejection, ≤ `RESERVE_REFUND_MAX_ATTEMPTS`) | refund driver | — | CAS on `inflight` | idempotent | `reserve.refund_failed` | `refund_sql_guards_every_transition` |
| `inflight` → `frozen` (ambiguous submit) | refund driver | — | CAS; never resubmitted | admin resolve verifies the chain by hash | `reserve.refund_failed` | `refund_sql_guards_every_transition` |
| admin: `needs_review`/`frozen` → `queued` / `cancelled` | `admin_reserve::resolve_refund` | `refund_id` | CAS naming its from-state | idempotent | — | `refund_sql_guards_every_transition`, `refund_memo_can_never_be_mistaken_for_an_order_ref` |

### 3.4 Replenishment cycle (`conversion_reserve_replenishment`)

States: `planned`, `creating`, `created`, `sending`, `sent`, `settled`,
`in_transit`, `completed`, `refunded`, `failed`, `frozen`. Journal kinds:
`replenish_hold`, `replenish_attempt`, `replenish_sent`, `replenish_credit`,
`replenish_refund`, `replenish_release`, `offramp_hold`, `offramp_attempt`,
`offramp_sent`, `offramp_refund`, `fiat_in_transit`, `fiat_confirmed`,
`fiat_written_off`, plus `topup`, `withdrawal`, `adjustment`,
`held_adjustment` for admin bookings.

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| plan: `replenish_hold` (`RESERVE_TREASURY_HOLD_SQL`) + `planned` | `maybe_start_cycle` in the tick, or `POST /admin/exchange-reserve/replenishment/run` | `cycle_id` | `uq_crr_inflight` — one live cycle per kind; caps at `0` refuse rather than meaning unlimited; an unreadable chain skips | hold and cycle row commit together | `reserve.entry_recorded` | `unconfigured_caps_refuse_rather_than_meaning_unlimited`, `an_unreadable_chain_skips_rather_than_spends`, `float_guard_reads_the_lower_of_ledger_and_chain`, `spend_ceiling_is_the_tightest_of_every_bound`, `each_guard_fires_on_its_own` |
| `planned` → `creating` → `created` (provider leg) | `create_provider_leg` | `provider_ref` | `CYCLE_CAS_SQL` names its from-state; only OwlPay creates are safe to retry when ambiguous | `creating` older than `RESERVE_REPLENISH_STALE_SECS` is frozen | — | `cycle_sql_guards_every_transition`, `only_owlpay_creates_are_safe_to_retry_when_ambiguous` |
| `created` → `sending`: `replenish_attempt` write-ahead row, then `prepare_payment` → hash on BOTH the attempt row and `send_tx_hash` (NULL-CAS each, one transaction) → `submit_prepared` | `submit_spend` | `send_tx_hash` (`uq_crr_send_tx_hash`, 037 part D) | `CYCLE_ENTRY_HASH_SQL` + `CYCLE_ROW_HASH_SQL` must each affect exactly one row or nothing is submitted; a hash that could not be recorded aborts the cycle (`hash_unrecorded`, hold released) and never re-queues | `sending` with a hash older than `RESERVE_REPLENISH_STALE_SECS` is resolved by hash: settled ⇒ `sent`; proven absent on a fresh Horizon ⇒ `failed` (`send_expired`, hold released); inconclusive ⇒ `frozen`. Hashless `sending` (pre-037 arm) still freezes | — | `submit_spend_records_hash_before_submit`, `cycle_hash_sql_is_a_null_cas_on_both_rows`, `hash_unrecorded_aborts_rather_than_requeues`, `stale_sending_cycle_resolves_by_hash_before_freezing`, `uq_crr_send_tx_hash_is_partial` |
| `sending` → `sent` (`replenish_sent`, held −x) | `record_spend_sent` | `send_tx_hash` | CAS on `sending` that only confirms the armed hash, never replaces it | idempotent | — | `cycle_hash_sql_is_a_null_cas_on_both_rows` |
| `sending` → `failed` (`replenish_release`) on definitive rejection | `abort_cycle` | — | `ABORT_CYCLE_SQL` covers exactly `planned`, `creating`, `sending` — never a state where the spend has left | — | — | `abort_covers_every_pre_send_state` |
| `sent` → `completed` (`replenish_credit`) / `refunded` (`replenish_refund`) / `in_transit` (`fiat_in_transit`) → `completed` (`fiat_confirmed`) / `failed` (`fiat_written_off`) | deposit watcher (`credit_cycle_arrival`) and admin confirm/write-off | Horizon `paging_token`; `cycle_id` | dispatch on the ASSET of the arrival, never the memo alone; CAS `state NOT IN (terminal)` | a frozen cycle still holds its spend until a human resolves it | `reserve.entry_recorded` | `cycle_sql_guards_every_transition` |

### 3.5 Payala sync (`POST /sync/payala`)

No chain effect and no value: this domain records claims (S4).

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| batch → `payala_sync_item` rows: applied / duplicate / conflicting | `handlers::sync::sync_payala`, one transaction | `batch_id` | primary key `(payala_account_id, payala_tx_id)` gates every item; a replayed id with a different amount counts as `conflicting` | the batch commits or nothing does; `MAX_SYNC_BATCH_ITEMS` bounds it | `payala.sync_batch_applied` (counts only) | `test_validate_batch_ok`, `test_validate_batch_duplicate_tx_id_rejected`, `test_validate_batch_abs_sum_overflow_rejected`, `test_aggregate_overflow_is_error`, `test_valid_sync_modes_match_ddl`, `sync_batch_payload_carries_counts_only` |

### 3.6 Outbox and audit

| Transition | Owner | Unique id | Idempotency anchor | Crash recovery | Event | Pinning test |
|---|---|---|---|---|---|---|
| state change + `event_outbox` row | every mutating handler and driver (`emit_event` inside the same transaction) | `event_id` | transactional outbox: the event commits with the change or not at all | none needed | (all) | `key_store_mutations_audit_in_the_same_transaction`, `custody_admin_mutations_are_guarded_single_statements` |
| fan-out → `admin_webhook_delivery` | `admin_webhook_delivery::fan_out` | `(webhook_id, event_id)` | `UNIQUE(webhook_id, event_id)` | idempotent | — | `claim_leases_under_skip_locked_and_keeps_rows_pending` |
| leased delivery → delivered / failed | delivery worker | delivery id | `FOR UPDATE SKIP LOCKED` leases; outcome marks are guarded against late duplicates | a lease expires and is re-claimed | — | `outcome_marks_are_guarded_against_late_duplicates`, `prune_touches_only_terminal_deliveries_and_pending_free_dispatched_events` |
| key import / revoke audit (`bridge_credential`) | `keys::store::insert_version` / `revoke_active` — the store owns the emission | `version` | the audit row is emitted inside the store's own transaction before the commit; a losing version race never reaches the emit | none needed | `bridge.key_imported`, `bridge.key_revoked` | `key_store_mutations_audit_in_the_same_transaction`, `credential_insert_columns_match_its_placeholders` |

Two emissions are deliberately post-commit and informational:
`reserve.unmatched_deposit_summary` (`flush_unmatched_summaries` — a roll-up of
rows that already committed) and the retention scrub `scrub_expired` (not an
audited state change).

### 3.7 Soroban wrapper

wrap / schedule / execute / cancel happen on the contract and are unobserved by
the bridge (S3). `no test` in the bridge; the contract's own tests live under
`impala-soroban/`.

### 3.8 Card

`SIGN_TRANSFER` debits `myBalance` and signs a 60-byte signable with a sender
counter the card does not persist; `VERIFY_TRANSFER` credits from any key whose
counter exceeds the last one seen. Pinned only by the SDK's
`AppletInteropTest.kt` on jcardsim; nothing in the bridge observes either
(S5). Bridge-issued certificates and bridge-verified redemptions are the
pending PR4 work (§5).

---

## 4. Invariants the bridge enforces today

- **4.1 Journal replay.** For every bucket, `available == Σ delta` and
  `held == Σ held_delta` over `conversion_reserve_entry`. Every mutation
  writes its journal row in the same transaction as the bucket update, and
  the positions endpoint recomputes both sums
  (`journal_replay_mismatch_flags_bucket`).
- **4.2 Chain covers ledger.** For every chain-legged bucket,
  `onchain_minor − (available + held)` is the bucket's drift and must lie
  within `drift_tolerance_minor` (`drift_is_onchain_minus_ledger`,
  `tolerance_boundary_inclusive`). Before 037 this was visible only as strings
  in `GET /admin/exchange-reserve`; now it is an invariant with a name, a
  snapshot and an event. `USD` has no chain leg (`usd_bucket_has_no_drift_leg`).
- **4.3 The XLM caveat.** Network fees are paid by the reserve account and
  are not journaled, so the XLM bucket reads *high* by the cumulative fee sum.
  `drift_tolerance_minor` bounds the gap; a `fee` journal kind that books each
  settled transaction's fee is the recommended follow-up (§9). Until then an
  XLM tolerance of `0` alerts on every settlement.
- **4.4 One-shot money.** One payout per order (`UNIQUE(order_id, kind)`);
  one credit per `paging_token`; one refund obligation per payment; the
  Horizon cursor is monotonic; an ambiguous submit is never resubmitted by
  software (`only_horizon_400_with_result_codes_is_definitive`,
  `ambiguous_maps_to_202_and_is_never_resubmitted`); the reserve seed is
  generate-only and quarantined from `/managed-account/*`
  (`the_reserve_quarantine_is_armed_without_a_live_reserve`,
  `no_reserve_configured_quarantines_nothing`); there is no plaintext seed at
  rest (`test_none_protector_fails_closed`).
- **4.5 Quarantine.** Nothing that signs reads `payala_reserve`,
  `transaction.payala_amount` or `payala_sync_*`. Pinned by
  `signing_paths_never_read_payala_tables` over `managed_seed.rs`,
  `reserve_watch.rs`, `replenish.rs`, `admin_reserve.rs`, `custody/intent.rs`,
  `custody/sweep.rs`, `custody/policy.rs` (and `offline/redemption.rs` once
  PR4 lands).
- **4.6 Hash before submit, everywhere.** One signed envelope per intent; no
  submit without a persisted hash; there is no fused sign-and-submit for
  payments left in the signer trait (`no_driver_calls_the_fused_signer`,
  `custodial_sign_orders_policy_before_seed_and_hash_before_submit`,
  `submit_spend_records_hash_before_submit`). Per-account daily custodial
  spend is bounded, counting every non-rejected intent as spent
  (`daily_counts_every_non_rejected_status`, `daily_overflow_is_checked_arithmetic`).
- **4.7 Offline liabilities are held (pending, PR4).**
  `held_offline(currency) == Σ_cards (issued − written_off) − Σ (paid | cancelled redemptions)`;
  per card `outstanding = issued − redeemed − written_off ≥ 0`; aggregate
  `Σ outstanding ≤ bucket.held`. Reported by positions as
  `offline_liabilities_are_held`; `no test` until PR4.

---

## 5. Target state machine mapped to components

The cross-domain machine the pending offline design closes. *Status* is the
honest state of this tree.

| Transition | Component(s) | Status before → after | Primitive | What closes it |
|---|---|---|---|---|
| ONCHAIN_AVAILABLE → RESERVED_FOR_OFFLINE_ISSUANCE | owner custodial sign to the reserve address (memo = issuance ref, via §3.1) → deposit watcher → `issuance_deposit` + `issuance_hold` journal rows | absent → exists (PR4, pending) | `paging_token` anchor + `RESERVE_BUCKET_APPLY_SQL` hold | the funding match commits the hold before any credit can be signed |
| RESERVED → OFFLINE_SPENDABLE | bridge issuer key signs the card credit with a bridge-allocated counter; `issued` committed before the bytes leave; card-side `VERIFY_TRANSFER` with a pinned program key (card area) | absent → partial (bridge half PR4, card half the card lane's personalization/certificate work) | write-ahead `offline_issuance` row, per-card advisory lock | the certificate chain (program id → issuer key → card key) |
| OFFLINE_SPENDABLE → OFFLINE_TRANSFERRED_UNRECONCILED | card `SIGN_TRANSFER` / `VERIFY_TRANSFER`; no coordinator | partial (unchanged) | counter rule on the card | out of scope for the bridge |
| OFFLINE_TRANSFERRED → RECONCILED_OFFLINE_BALANCE | `POST /sync/payala` (unverified, S4) | partial, quarantined (unchanged; out of scope until a Payala contract exists) | primary-key gate | a verifiable Payala contract |
| RECONCILED → PENDING_ONCHAIN_RELEASE | `POST /offline/redemptions` verifying the card's transfer tuple + certificate, per-card bound, `redemption_attempt` + custodial intent (`origin = redemption`) | absent → exists for a card's own bridge-issued value (PR4, pending) | `UNIQUE(card_id, sender_counter)` + `UNIQUE(transfer_id)`; position CAS on `outstanding` | the write-ahead intent names the verified debit proof |
| PENDING_ONCHAIN_RELEASE → ONCHAIN_AVAILABLE | reserve watcher `drive_redemptions` → prepare / hash / submit / classify → `redemption_paid` + `transaction` row (origin `offline_redemption`); sweep / admin resolve | partial (reserve-only primitive exists: §3.1 intents with `origin = redemption` are already admitted by the schema) → exists (PR4, pending) | §3.1 intent machine, `custodial_payment_intent.origin = 'redemption'` | the same hash-before-submit ladder |

---

## 6. Failure-injection matrix

Every scenario a reviewer asked about, mapped to the tests that pin it. *Before
037* is the tree before the custodial conservation change; *Now* is this tree
(PR1–PR3 landed); *Pending* names what PR4 or the client lanes still owe. A cell
that says `no test` means exactly that.

| Scenario | Before 037 | Now | Pending |
|---|---|---|---|
| Duplicate bridge requests (custodial sign) | `no test` (no anchor existed) | `replay_decision_table`, `same_key_different_fingerprint_is_conflict`, `arm_sql_requires_prepared_and_null_hash`, `one_inflight_index_is_partial_on_sign_origin`, `idempotency_key_charset_and_length`, `fingerprint_is_amount_canonical`; DB lane (opt-in, §6.1): `uq_custodial_intent_key_rejects_second_insert`, `one_inflight_index_admits_one_live_sign_intent` | impalactl replay-on-retry (`--idempotency-key`): `no test` (the CLI still sends no key) |
| Duplicate requests (reserve admin) | `claim_sql_collapses_every_invalid_case_to_zero_rows`, `refund_sql_guards_every_transition` | + `custody_admin_mutations_are_guarded_single_statements`, `resume_phrase_names_the_network` | — |
| Repeated Stellar events (replayed Horizon page) | `expiry_and_replay_sql_are_guarded`, `late_deposit_after_expiry_is_recorded_not_credited_to_order`, `unmatched_insert_records_the_payer`, `stale_intent_sql_only_covers_unrecorded_outcomes` | + `sweep_verdict_table` (a replayed page cannot settle an intent twice: CAS on status + hash), `settle_sql_requires_hash_and_open_status`; DB lane: `uq_custodial_intent_hash_rejects_second_arm` | issuance arrival anchored by `paging_token`: `no test` (PR4) |
| Crash between debit and settlement | `stale_intent_sql_only_covers_unrecorded_outcomes`, `refund_sql_guards_every_transition`, `cycle_sql_guards_every_transition`, `abort_covers_every_pre_send_state`, `only_horizon_400_with_result_codes_is_definitive` | + `abandon_sql_never_touches_armed_rows`, `stale_sql_selects_only_armed_open_rows`, `claimed_without_hash_is_provably_unsubmitted`, `submit_spend_records_hash_before_submit`, `stale_sending_cycle_resolves_by_hash_before_freezing`, `settled_unrecorded_is_202_never_200_with_null_btxid`; DB lane: `arm_cas_loses_to_abandon_sweep` | funded issuance never signs before its hold commits: `no test` (PR4) |
| Queue redelivery (SQS) | `active_job_guard_releases_on_panic`, `active_job_guard_releases_exactly_once_on_normal_drop` (jobs move no money) | unchanged — money never rides SQS; every money transition is a Postgres row driven by the watcher, the sweep or a handler | — |
| Database rollback (partial transaction) | `no test` (no DB in `cargo test`) | DB lane (opt-in, §6.1): `settle_tx_is_atomic_when_intent_cas_fails`, `journal_insert_conflict_rolls_back_bucket_apply`, `abandon_sweep_rejects_only_hashless_rows`, `reconciliation_snapshot_daily_anchor_admits_one_row_per_date`, `uq_crr_send_tx_hash_rejects_second_cycle`; source pins `key_store_mutations_audit_in_the_same_transaction`, `the_old_settle_then_record_insert_is_gone` | — |
| Redis outage | `valid_bearer_fails_closed_when_redis_unreachable`, `session_cookie_fails_closed_when_redis_unreachable`, `test_none_protector_fails_closed` | + `pause_path_never_touches_redis` (the brake is a Postgres row, so a cache outage cannot fail it open or closed) | — |
| Network partition (Horizon) | `an_unreadable_chain_skips_rather_than_spends`, `head_freshness_boundary`, `scan_page_crosses_floor_proves_absence`, `scan_page_missing_created_at_never_stops_short`, `presubmit_retryable_is_transient_rejection_not_ambiguous` | + `ambiguous_maps_to_202_and_is_never_resubmitted`, `stale_head_is_inconclusive`, `unreadable_chain_yields_null_not_ok`, `unreadable_chain_yields_leave_not_reject`, `missing_trustline_on_a_readable_chain_is_zero_not_null` | — |
| Delayed card synchronization | `no test` | `no test` — the card's `dateTime` is a per-sender send sequence, not a clock; the bridge enforces no age on it and relies on the counter rule + `transfer_id` uniqueness (PR4) | counter/transfer-id replay tests: `no test` (PR4) |
| Conflicting card / backend balances | `no test` | `no test` — on-card balances are unobserved (S5) and Payala mirrors are quarantined (S4); netting is out of scope | per-card and aggregate outstanding bounds: `no test` (PR4) |
| Partial withdrawal | `no test` | `no test` — no redemption primitive exists yet | position CAS exactness: `no test` (PR4) |
| Bridge signer compromise | `no test` | `resume_refuses_while_ambiguous_intents_exist`, `pause_precedes_seed_load`, `override_zero_freezes_the_account`, `override_replaces_global_even_when_global_is_zero`, `custody_reads_never_hand_out_a_mutation`, `auditor_holds_no_mutation_capability`, `lateral_roles_do_not_cross_surfaces`; containment is pause → per-account `0` → rotate seeds via `POST /admin/stellar-seeds/generate` (`docs/runbooks/incident-response.md`); HSM custody is out of scope — `prepare_payment` / `submit_prepared` is the replacement seam | issuer key generate-only tripwire: `no test` (PR4) |
| Reserve shortfall | `hold_sql_guards_balance_and_fraction`, `bucket_apply_sql_guards_both_columns`, `unconfigured_caps_refuse_rather_than_meaning_unlimited`, `each_guard_fires_on_its_own`, `float_guard_reads_the_lower_of_ledger_and_chain`, `spend_ceiling_is_the_tightest_of_every_bound`, `low_water_breach_flag` | + `drift_is_onchain_minus_ledger`, `tolerance_boundary_inclusive`, `positions_invariants_flag_uncovered_obligations`, `obligation_queries_name_their_states`, `custodial_walk_excludes_the_reserve_account` | issuance hold via `RESERVE_BUCKET_APPLY_SQL`, not the fraction guard: `no test` (PR4) |
| Schema / constant drift | `test_reserve_entry_kinds_match_ddl`, `test_valid_sync_modes_match_ddl` | + `test_custodial_intent_vocabularies_match_ddl`, `test_transaction_origins_match_ddl`, `test_custodial_vocabularies_fit_their_columns`, `snapshot_daily_anchor_is_a_date_column`, `settlement_columns_are_nullable_so_shared_inserts_keep_their_binds`, `uq_crr_send_tx_hash_is_partial`, `intent_insert_binds_thirteen_and_matches_ddl`, `settlement_transaction_insert_binds_ten`, `snapshot_insert_binds_eleven`, `bucket_update_binds_five`, `credential_insert_columns_match_its_placeholders`, `capability_matrix_matches_shared_fixture`, `every_privileged_handler_takes_its_exact_capability`, `extractor_swap_is_complete_per_module`, `advisory_lock_keys_are_distinct`, `event_type_vocabulary_is_append_only`, `schema_version_is_pinned`, `conservation_spec_names_every_vocabulary` | 038 vocabularies: `no test` (PR4) |
| Secrets or ledger pointers in events | `no test` (per-event tests only) | `custodial_payloads_never_carry_addresses_or_hashes`, `sync_batch_payload_carries_counts_only`, `custodial_refusal_codes_are_unique_and_snake_case`, `coded_error_serializes_code_and_details` | offline payloads: `no test` (PR4) |

### 6.1 The opt-in DB lane

`cargo test` runs with no Postgres, so every SQL fact above is pinned by
string. The tests named "DB lane" live in `impala-bridge/tests/db/` as
`#[ignore]` integration tests that connect to `DATABASE_URL` only when
`RUN_DB_TESTS=1`, apply `sqlx::migrate!("./migrations")` into a fresh schema per
test, and prove the constraints and rollbacks with real statements. CI runs
them in the `bridge-db-tests` job against a `postgres:16` service
(`RUN_DB_TESTS=1 cargo test --locked --test db -- --ignored`); locally:
`RUN_DB_TESTS=1 DATABASE_URL=postgres://... cargo test --test db -- --ignored`.

---

## 7. Controls inventory

Every cap, switch, rate limit, lock and role that bounds money movement, with
where it lives and who may move it. Roles: `admin` is the superset and the
only governance role; `treasurer` holds reserve and custody money-ops;
`key-custodian` holds keys and seeds; `auditor` is read-only. Capabilities are
one table (`auth.rs::role_has_capability`), mirrored in the UI and pinned by a
shared fixture.

| Control | Where | Endpoint / actor | Semantics |
|---|---|---|---|
| Custodial pause | `custodial_policy.paused` (single row, `FOR SHARE` in the claim transaction) | `POST /admin/custody/pause` (`ManageCustody`: admin, treasurer); `POST /admin/custody/resume` (**`AdminUser`** only, confirm phrase `resume custody <network>`, 409 while any intent is `ambiguous` unless `force`) | stops new custodial user payments before the seed is opened. **Does NOT gate reserve payouts, refunds or replenishment** — those have their own switches below and must be flipped separately in an incident |
| Custodial caps | `custodial_policy.per_tx_max_stroops`, `per_account_daily_max_stroops`, `require_idempotency_key` | `PUT /admin/custody/policy` (`ManageCustody`) | `0` = unconfigured ⇒ refuse (`custodial_unconfigured`), never unlimited. XLM-stroop caps on user payments only; redemptions (PR4) are bounded by the offline policy caps plus the per-card bound |
| Per-account override | `impala_account.custodial_daily_max_stroops` | `PUT /admin/custody/accounts/{account_id}/limit` (`ManageCustody`; the reserve account is refused) | `NULL` = global cap applies; `0` = the account is frozen (`custodial_account_frozen`) |
| Intent resolution | `custodial_payment_intent` | `POST /admin/custody/intents/{intent_id}/resolve` (`ManageCustody`); reads under `ReadCustody` (admin, treasurer, auditor) | `complete` only with a chain-verified hash; `fail` only after `CUSTODIAL_STALE_INTENT_SECS` with a proven absence on a fresh Horizon |
| Custodial sweep | `CUSTODIAL_SWEEP_INTERVAL_SECS` (60), `CUSTODIAL_INTENT_ABANDON_SECS` (120), `CUSTODIAL_STALE_INTENT_SECS` (600 ≥ 2 × the 300 s envelope validity), `CUSTODIAL_SWEEP_BATCH` (25) | background task under `CUSTODIAL_SWEEP_LOCK_KEY` | every write is a CAS; the lock only prevents duplicate work |
| Rate limits (Redis, fail-closed) | `SIGN_RATE_LIMIT_MAX_REQUESTS` (5) / `SIGN_RATE_LIMIT_WINDOW_SECS` (60) for scopes `sign` and `custody_admin` | `/managed-account/sign`, every custody mutation | throttle only — never a correctness boundary |
| Reserve quote kill switch | `conversion_reserve_policy.enabled` (per provider), `threshold_usd_cents` | `PUT /admin/exchange-reserve/policies/{provider}` (`ManageReserve`) | `enabled:false` stops new exposure even against an issued price lock |
| Hold fraction guard | `RESERVE_HOLD_SQL` (`(held + x) * 2 <= available + held`), `RESERVE_MAX_OPEN_ORDERS_PER_ACCOUNT` (3) | inside every hold | one actor cannot lock the pool with free-to-abandon orders |
| Deposit / quote windows | `RESERVE_DEPOSIT_TTL_MIN_SECS` (300) … `RESERVE_DEPOSIT_TTL_MAX_SECS` (7200); `RESERVE_QUOTE_TTL_MIN_SECS` (60) … `RESERVE_QUOTE_TTL_MAX_SECS` (900) | `PUT /admin/exchange-reserve/settings` | expiry is gated on a fresh Horizon head (`HORIZON_MAX_LAG_SECS` = 90) |
| Payout retries | `RESERVE_MAX_PAYOUT_ATTEMPTS` (5) | payout driver | definitive rejections only; ambiguous ⇒ `on_hold` |
| Refund master switch and caps | `conversion_reserve_state.refunds_enabled` (default off); per bucket `conversion_reserve.refund_max_minor`, `refund_daily_max_minor` (`0` disables); `RESERVE_REFUND_MIN_MINOR` (dust), `RESERVE_REFUND_MAX_ATTEMPTS` (3), `RESERVE_REFUND_COOLDOWN_SECS` (300), `RESERVE_REFUND_MAX_PER_TICK` (5) | `PUT /admin/exchange-reserve/settings`, `PUT /admin/exchange-reserve/buckets/{currency}`; `POST /admin/exchange-reserve/refunds/{refund_id}/resolve` (`ManageReserve`) | USD float is never refunded on-chain |
| Replenishment switch and caps | `conversion_reserve_replenish_policy.enabled`, `max_spend_minor`, `daily_spend_cap_minor`, `cooldown_secs`, `min_float_minor`, `min_price_minor`, `max_slippage_bps`; `RESERVE_REPLENISH_MAX_PER_TICK` (2); `RESERVE_REPLENISH_STALE_SECS` (600) | `PUT /admin/exchange-reserve/replenishment/policies/{kind}`, `POST .../replenishment/run`, `.../{cycle_id}/confirm-fiat`, `.../{cycle_id}/write-off` (`ManageReserve`) | `0` caps refuse; `uq_crr_inflight` one cycle per kind; `uq_crr_send_tx_hash` one envelope per cycle |
| Bucket floors and drift | `conversion_reserve.low_water`, `drift_tolerance_minor` | `PUT /admin/exchange-reserve/buckets/{currency}` (`ManageReserve`) | `low_water` alerts (`reserve.low_water`); `drift_tolerance_minor` bounds §4.2 and gates `reserve.drift` |
| Admin journal bookings | `topup`, `withdrawal`, `adjustment`, `held_adjustment` | `POST /admin/exchange-reserve/entries` (`ManageReserve`) | guarded by `RESERVE_BUCKET_APPLY_SQL` (both columns stay ≥ 0); order-linked kinds are never admin-writable |
| Trustlines | reserve account only, generate-only seed | `POST /admin/exchange-reserve/trustlines` | the only path that signs a change-trust from the reserve |
| Advisory locks | `RESERVE_WATCHER_LOCK_KEY`, `EXCHANGE_RECONCILE_LOCK_KEY`, `CUSTODIAL_SWEEP_LOCK_KEY`, `RECONCILIATION_LOCK_KEY` | watcher tick, reconcile poller, sweep, daily snapshot | pairwise distinct (`advisory_lock_keys_are_distinct`); never a correctness boundary — every write under them is still a CAS |
| Reconciliation job | `RECONCILIATION_SNAPSHOT_UTC_HOUR`, `RECONCILIATION_MAX_ACCOUNTS`, `RECONCILIATION_DEADLINE_SECS` | background task; `POST /admin/reconciliation/snapshots` (`ManageCustody`) for a manual run | one `daily` row per UTC date (`uq_reconciliation_snapshot_daily`) |
| Key custody | `KEY_IMPORT_ENABLED`; seed protector (KMS / Vault / OpenBao, no plaintext-at-rest path); reserve seed generate-only; `bridge_credential` versions with scrub after `CREDENTIAL_SUPERSEDE_GRACE_SECS` | `/admin/keys*` (`ManageKeys`: admin, key-custodian), `POST /admin/stellar-seeds/generate` | no response, log or event ever carries secret bytes (fingerprints only) |
| Governance-only actions | — | `POST /admin/custody/resume` (today); `cancel_redemption`, `write_off_card` (PR4) | `AdminUser`: money-ops may pull the brake and never release it alone |
| Account deletion | `admin::delete_account` | `DELETE /admin/accounts/{id}` | 409 while any custodial intent is non-terminal or any reserve order is open |

---

## 8. Reconciliation procedure

1. **Positions.** `GET /admin/reconciliation/positions` (`ReadCustody`)
   computes, from one Horizon head: every bucket's `available`, `held`,
   journal replay, on-chain balance, drift and `drift_ok`; every obligation
   (refunds by status, order and quote holds, open payout intents, cycles in
   flight, fiat in transit, offline zeros); a page of custodial addresses with
   their open intents; the policy summary; the Payala self-report; and the
   seven invariants (`reserve_journal_replays`, `reserve_chain_covers_ledger`,
   `reserve_drift_within_tolerance`, `reserve_available_covers_queued_refunds`,
   `offline_liabilities_are_held`, `custodial_no_stale_intents`,
   `custodial_addresses_reachable`). An unreachable or lagging Horizon makes
   every chain-dependent invariant `null`, never `true`
   (`unreadable_chain_yields_null_not_ok`).
2. **Daily snapshot.** After `RECONCILIATION_SNAPSHOT_UTC_HOUR`, the job takes
   `RECONCILIATION_LOCK_KEY`, walks every custodial page within
   `RECONCILIATION_MAX_ACCOUNTS` / `RECONCILIATION_DEADLINE_SECS` (exceeding
   either sets `complete=false`), and inserts one `daily` row
   (`reconciliation_snapshot`, `ON CONFLICT DO NOTHING`) with the full payload.
   It emits `reconciliation.snapshot_recorded` always and `reserve.drift` for
   every chain-legged bucket outside tolerance **only when the head was fresh**.
   `GET /admin/reconciliation/snapshots` lists rows with
   `attested = horizon_fresh && complete && invariants_ok`; a lagging day is
   recorded and lists as `attested:false`.
3. **`reserve.drift` triage.** For the named bucket compare `onchain_minor`,
   `ledger_total_minor` and `drift_minor` in the snapshot payload.
   - XLM drift that is negative and small: accumulated network fees (§4.3).
     Book an `adjustment` (`available` −fees) through
     `POST /admin/exchange-reserve/entries`, or raise `drift_tolerance_minor`.
   - Positive drift: an inflow the watcher did not credit. Check
     `GET /admin/exchange-reserve/unmatched` and the cursor; never book a
     `topup` for money you cannot attribute.
   - Drift that appears with an `on_hold`, `frozen` or `ambiguous` item:
     resolve the item first (step 4); the drift usually closes itself.
   - `held_adjustment` is for a hold that no open obligation explains
     (`positions_invariants_flag_uncovered_obligations`); every booking cites
     the snapshot id in its note.
4. **Exception queues** (all read-only for `auditor`, actionable for
   `treasurer`/`admin`):
   - `GET /admin/custody/intents?status=ambiguous` — resolve with
     `complete` (hash verified) or `fail` (proven absent after 600 s).
   - `GET /admin/exchange-reserve` (`pending.on_hold` count; the order ids
     arrive on `reserve.payout_pending` / `exchange.order_updated` events) —
     `POST /admin/exchange-reserve/orders/{order_id}/resolve` after verifying
     the payout hash on-chain.
   - `GET /admin/exchange-reserve/refunds?status=frozen` (and
     `needs_review`) — `resolve` to `queued` or `cancelled`.
   - `GET /admin/exchange-reserve/replenishment` cycles in `frozen` —
     `confirm-fiat` / `write-off`; a `frozen` cycle still holds its spend.
   - (PR4) `GET /admin/offline/redemptions?state=failed`.
5. **Resume.** Only after `ambiguous` is empty: `POST /admin/custody/resume`
   with the confirm phrase (`force` is for the case where a human has
   personally verified every ambiguous row on-chain).

---

## 9. Open gaps with owners

| Gap | Owner | Status |
|---|---|---|
| Card personalization and bridge-issued certificates (program id, issuer key, `VERIFY_TRANSFER` under a pinned key) | impala-card lane + bridge PR4 | pending; until then S5 holds |
| Payala contract — a verifiable statement of off-chain balances | external (Payala) | no contract exists; S4 holds and the quarantine stays |
| Soroban wrapper participation in conservation | decision (owner) | standalone / informational (S3) |
| HSM-backed signing for the custodial and issuer keys | bridge | out of scope; `prepare_payment` / `submit_prepared` is the seam a hardware signer replaces |
| `fee` journal kind so the XLM bucket stops drifting by network fees | bridge | recommended follow-up (§4.3) |
| Stablecoin-denominated cards (`asset` on the sign path) | bridge | out of scope for the XLM pilot |
| DB-executing test suite growth beyond the opt-in lane (§6.1) | bridge | the default suite stays DB-free by design; add DB-lane cases for every new `UNIQUE` anchor or CAS |
| impalactl replay path (`--idempotency-key`, 202 polling, exit 3 only for a genuinely unknown outcome) | impalactl | pending; the CLI still sends no key and `TestTransferSendAmbiguousOutcomesExitThree` pins today's behaviour |

---

## Appendix A — Vocabularies (verbatim, pinned)

- `VALID_RESERVE_ENTRY_KINDS`: `hold`, `hold_release`, `deposit`,
  `unmatched_deposit`, `payout_attempt`, `fulfillment`, `disbursement`,
  `topup`, `withdrawal`, `adjustment`, `held_adjustment`, `quote_hold`,
  `quote_release`, `quote_consume`, `replenish_hold`, `replenish_attempt`,
  `replenish_sent`, `replenish_credit`, `replenish_refund`,
  `replenish_release`, `offramp_hold`, `offramp_attempt`, `offramp_sent`,
  `offramp_refund`, `fiat_in_transit`, `fiat_confirmed`, `fiat_written_off`,
  `refund_intent`, `refund_sent`, `refund_reversal`.
- `VALID_CUSTODIAL_INTENT_STATUSES`: `prepared`, `submitted`, `settled`,
  `rejected`, `ambiguous`.
- `VALID_CUSTODIAL_INTENT_RESOLUTIONS`: `submit_ok`, `submit_rejected`,
  `prepare_rejected`, `arm_failed`, `sweep_settled`, `sweep_failed`,
  `sweep_expired`, `sweep_abandoned`, `admin_complete`, `admin_fail`.
- `VALID_REPLENISH_STATES`: `planned`, `creating`, `created`, `sending`,
  `sent`, `settled`, `in_transit`, `completed`, `refunded`, `failed`,
  `frozen`.
- `VALID_RESERVE_REFUND_STATUSES`: `needs_review`, `queued`, `inflight`,
  `sent`, `failed`, `frozen`, `cancelled`.
- `VALID_EXCHANGE_STATUSES`: `created`, `awaiting_deposit`, `processing`,
  `on_hold`, `completed`, `failed`, `refunded`, `expired`.
- `VALID_TX_ORIGINS`: `manual`, `payala_sync`, `conversion_reserve`,
  `custodial_sign`, `offline_redemption`.
- (PR4, pending) `VALID_OFFLINE_ISSUANCE_STATES` and
  `VALID_OFFLINE_REDEMPTION_STATES` are added here when migration 038 lands.

## Appendix B — Event types (append-only outbox vocabulary)

Payloads carry ids, statuses and integer minor amounts only — never a
destination, memo, Stellar hash, signable, signature, secret or PII.

`account.created`, `account.updated`, `transaction.created`,
`card.registered`, `card.deleted`, `mfa.enrolled`, `notify.mobile_verified`,
`device_token.registered`, `device_token.deleted`, `exchange.order_created`,
`exchange.order_updated`, `reserve.deposit_matched`,
`reserve.trustline_added`, `reserve.fulfilled`, `reserve.payout_pending`,
`reserve.disbursement_pending`, `reserve.order_expired`,
`reserve.unmatched_deposit`, `reserve.unmatched_deposit_summary`,
`reserve.low_water`, `reserve.policy_updated`, `reserve.refund_queued`,
`reserve.refund_sent`, `reserve.refund_failed`, `reserve.entry_recorded`,
`account.role_changed`, `bridge.key_imported`, `bridge.key_revoked`,
`bridge.seed_provisioned`, `custodial.payment_settled`,
`custodial.payment_ambiguous`, `custody.paused`, `custody.resumed`,
`custody.policy_updated`, `custody.account_limit_updated`,
`custody.intent_resolved`, `reserve.drift`,
`reconciliation.snapshot_recorded`, `payala.sync_batch_applied`.
