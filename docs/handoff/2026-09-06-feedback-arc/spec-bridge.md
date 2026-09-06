# impala-bridge conservation controls — implementation spec

All paths are absolute under `/Users/user/sonoranpub/impala/`; `impala-bridge/` is abbreviated `B/`. Line numbers cite the current working tree (HEAD `71abed3` plus the lead's uncommitted `record_intent_hash` diff in `B/src/exchange/reserve_watch.rs:385-446`). Every fact below was verified against the source; where this spec differs from the winning design it is because a judge flaw or graft required it.

Delivery is four PRs on two migrations. Migration **037** carries everything PR1–PR3 need (custodial intent + policy + transaction columns + reconciliation + replenishment hash index) and **038** carries the offline issuance/redemption schema (PR4). Migrations are operator-invoked (`RUN_MODE=migrate`) and must run before the binary that depends on them.

| PR | Scope | Migration |
|---|---|---|
| PR1 | §1 custodial intent/idempotency/sweep, §2 policy + RBAC, §5 error codes, tests, impalactl/UI/openapi/docs for those | 037 |
| PR2 | §3 positions endpoint + daily snapshot | 037 (already applied) |
| PR3 | §4 replenishment hash, §6 admin_keys outbox, §7 conservation spec + CI filter + DB lane | 037 |
| PR4 | §8 offline issuance/redemption | 038 |

---

## 0. Cross-cutting decisions (binding)

1. **Money switches live in Postgres single-row tables** (`id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id)`, precedent `conversion_reserve_state` 031:117-121), read `FOR SHARE` inside the money transaction. Redis is never consulted on the pause/cap path (Redis stays the rate-limit throttle, `B/src/redis_helpers.rs:31`, fail-closed as today).
2. **`0` cap = unconfigured → refuse** (032:197 precedent). A freshly migrated deployment refuses custodial signing until an operator sets caps (deploy order §9).
3. **Hash before submit, everywhere.** Every signer path uses `prepare_payment` → persist hash (exactly 1 row affected, else no submit) → `submit_prepared` (`B/src/stellar/signer.rs:82-88`). `sign_and_submit_payment(` may appear only in `B/src/stellar/signer.rs` and `B/src/handlers/admin_reserve.rs` (`add_trustline` uses `sign_and_submit_change_trust`; the payment variant is banned there too — the tripwire asserts absence in `managed_seed.rs`, `reserve_watch.rs`, `replenish.rs`, `custody/`, `offline/`).
4. **No secret bytes in any response/log/event.** Events never carry destination, memo, Stellar hash, signable or signature bytes (pinned by serialize-and-grep tests, §1.8).
5. **Machine-readable refusals.** New `AppError::Coded` (§5) carries `(status, code, message, details)`; clients branch on `error.code`, never message text.
6. **Capabilities**: two new ones, `ManageCustody` (admin, treasurer) and `ReadCustody` (admin, treasurer, auditor), added via the three-place edit (§2.3). `resume`, `write_off_card` and `cancel_redemption` take `AdminUser` (governance): money-ops may pull the brake and never releases it alone.
7. **Advisory lock keys** (`B/src/constants.rs`, next to `RESERVE_WATCHER_LOCK_KEY` :825 and `EXCHANGE_RECONCILE_LOCK_KEY` :829):
   ```rust
   pub const CUSTODIAL_SWEEP_LOCK_KEY: i64 = 0x494d_5043_5553_5459; // "IMPCUSTY"
   pub const RECONCILIATION_LOCK_KEY: i64 = 0x494d_5052_4543_4f4e; // "IMPRECON"
   ```
   Test `advisory_lock_keys_are_distinct` (constants tests) asserts the four keys are pairwise distinct.
8. **Request cancellation.** `TimeoutLayer` (`B/src/main.rs:789-792`, 30 s) drops the handler future. The submit+record phase of a custodial payment runs in a task spawned on a `tokio_util::task::TaskTracker` (tokio-util `rt` feature is already enabled, `B/Cargo.toml:37`) registered as `Extension<Arc<TaskTracker>>`; the handler awaits the `JoinHandle` (dropping a `JoinHandle` detaches, never aborts). `main.rs` drains it after `drain_background` (`:1061`): `tracker.close(); tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_DEADLINE_SECS), tracker.wait())` (55 s > 30 s Horizon client timeout, `constants.rs:53-54`). Correctness never depends on this: the sweep (§1.6) is the guarantee; the tracker only shortens the window.
9. **Reserve signing stays inside the reserve watcher tick** under `RESERVE_WATCHER_LOCK_KEY` (`reserve_watch.rs:492-514`). Redemption payouts are write-ahead rows the watcher drives (§8.6); no request handler ever loads the reserve seed.

---

## 1. Custodial payment idempotency + write-ahead intent (`POST /managed-account/sign`)

### 1.1 Migration `B/migrations/037_custodial_conservation.sql` — part A

```sql
-- 037: custodial conservation controls (custodial payment intents, custodial
-- policy, transaction settlement columns, reconciliation snapshots, replenishment
-- hash anchor). Applying this file changes NO behaviour by itself. The binary
-- that writes these tables REFUSES custodial signing until an admin/treasurer
-- sets custodial_policy caps (0 = unconfigured, never "unlimited"; 032:197).
-- Deploy order: migrate -> roll -> PUT /admin/custody/policy.

CREATE TABLE IF NOT EXISTS custodial_payment_intent (
    intent_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Deliberately NO foreign key: intents are the money audit trail and must
    -- outlive the account row. admin.rs::delete_account refuses while any
    -- intent for the account is non-terminal (see the guard there).
    payala_account_id   VARCHAR(64)  NOT NULL,
    -- managed_seed.stellar_account_id at claim time (asserted by
    -- load_protected_seed, so row and signature always agree).
    source_account      VARCHAR(56)  NOT NULL,
    -- 'sign' = POST /managed-account/sign (owner, user seed)
    -- 'redemption' = offline redemption payout (038; reserve seed; watcher-driven)
    origin              VARCHAR(16)  NOT NULL DEFAULT 'sign',
    idempotency_key     VARCHAR(64)  NOT NULL,
    key_source          VARCHAR(8)   NOT NULL,
    request_fingerprint CHAR(64)     NOT NULL,
    destination         VARCHAR(69)  NOT NULL,
    asset_code          VARCHAR(12)  NOT NULL DEFAULT 'XLM',
    asset_issuer        VARCHAR(56),
    amount_minor        BIGINT       NOT NULL CHECK (amount_minor > 0),
    memo                VARCHAR(28),
    fee_stroops         BIGINT       CHECK (fee_stroops IS NULL OR fee_stroops > 0),
    -- Hash of the SIGNED envelope, written BEFORE submit (PreparedTx).
    stellar_hash        CHAR(64),
    status              VARCHAR(12)  NOT NULL DEFAULT 'prepared',
    resolution          VARCHAR(24),
    last_error          VARCHAR(200),
    btxid               UUID REFERENCES transaction(btxid) ON DELETE SET NULL,
    -- Offline redemption link; FK + partial unique added by 038.
    redemption_id       UUID,
    created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    armed_at            TIMESTAMP WITH TIME ZONE,
    resolved_at         TIMESTAMP WITH TIME ZONE,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_custodial_intent_key UNIQUE (payala_account_id, idempotency_key),
    CONSTRAINT chk_cpi_origin CHECK (origin IN ('sign', 'redemption')),
    CONSTRAINT chk_cpi_key_source CHECK (key_source IN ('client', 'server')),
    CONSTRAINT chk_cpi_status CHECK (status IN
        ('prepared', 'submitted', 'settled', 'rejected', 'ambiguous')),
    CONSTRAINT chk_cpi_resolution CHECK (resolution IS NULL OR resolution IN
        ('submit_ok', 'submit_rejected', 'prepare_rejected', 'arm_failed',
         'sweep_settled', 'sweep_failed', 'sweep_expired', 'sweep_abandoned',
         'admin_complete', 'admin_fail')),
    CONSTRAINT chk_cpi_asset CHECK (
           (asset_code = 'XLM' AND asset_issuer IS NULL)
        OR (asset_code <> 'XLM' AND asset_issuer IS NOT NULL)),
    -- No hash, no submit: a hash exists iff a submission MAY exist.
    CONSTRAINT chk_cpi_hash_state CHECK (
           (status = 'prepared' AND stellar_hash IS NULL)
        OR (status IN ('submitted', 'settled', 'ambiguous') AND stellar_hash IS NOT NULL)
        OR  status = 'rejected'),
    CONSTRAINT chk_cpi_settled_has_row CHECK (status <> 'settled' OR btxid IS NOT NULL)
);
-- A signed transaction's hash is final; two intents can never share one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_custodial_intent_hash
    ON custodial_payment_intent(stellar_hash) WHERE stellar_hash IS NOT NULL;
-- THE double-pay guard: one unresolved user payment per account, as a
-- constraint. Redemption payouts are serialized by the watcher lock instead.
CREATE UNIQUE INDEX IF NOT EXISTS uq_custodial_intent_one_inflight
    ON custodial_payment_intent(payala_account_id)
    WHERE origin = 'sign' AND status IN ('prepared', 'submitted', 'ambiguous');
CREATE INDEX IF NOT EXISTS idx_custodial_intent_open
    ON custodial_payment_intent(armed_at) WHERE status IN ('submitted', 'ambiguous');
CREATE INDEX IF NOT EXISTS idx_custodial_intent_unarmed
    ON custodial_payment_intent(created_at) WHERE status = 'prepared';
CREATE INDEX IF NOT EXISTS idx_custodial_intent_account_spend
    ON custodial_payment_intent(payala_account_id, created_at)
    WHERE origin = 'sign' AND status <> 'rejected';
CREATE TRIGGER update_custodial_payment_intent_updated_at
    BEFORE UPDATE ON custodial_payment_intent
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Settlement rows finally carry what was paid. NULLable, so every existing
-- shared INSERT (transaction.rs:112-121, sync.rs mirror rows, reserve_watch.rs
-- :1622-1635 / :2297-2310) keeps its bind list untouched.
ALTER TABLE transaction
    ADD COLUMN IF NOT EXISTS stellar_amount_minor BIGINT
        CHECK (stellar_amount_minor IS NULL OR stellar_amount_minor > 0),
    ADD COLUMN IF NOT EXISTS stellar_destination VARCHAR(69),
    ADD COLUMN IF NOT EXISTS stellar_asset_code VARCHAR(12),
    ADD COLUMN IF NOT EXISTS stellar_asset_issuer VARCHAR(56);
-- 031:179-183 pattern. 'offline_redemption' is pre-declared so 038 needs no
-- second CHECK cycle; nothing writes it before 038.
ALTER TABLE transaction DROP CONSTRAINT chk_transaction_origin;
ALTER TABLE transaction ADD CONSTRAINT chk_transaction_origin
    CHECK (origin IN ('manual', 'payala_sync', 'conversion_reserve',
                      'custodial_sign', 'offline_redemption'))
    NOT VALID;
ALTER TABLE transaction VALIDATE CONSTRAINT chk_transaction_origin;
```
(`007_transaction_log_trigger.sql` enumerates no columns — verified — so the widening needs no trigger change.)

### 1.2 Constants (`B/src/constants.rs`) and drift tests (`B/src/models.rs`)

```rust
pub const TX_ORIGIN_CONVERSION_RESERVE: &str = "conversion_reserve";
pub const TX_ORIGIN_CUSTODIAL_SIGN: &str = "custodial_sign";
pub const TX_ORIGIN_OFFLINE_REDEMPTION: &str = "offline_redemption";
pub const VALID_TX_ORIGINS: &[&str] = &["manual", "payala_sync", "conversion_reserve", "custodial_sign", "offline_redemption"];
pub const CUSTODIAL_INTENT_ORIGIN_SIGN: &str = "sign";
pub const CUSTODIAL_INTENT_ORIGIN_REDEMPTION: &str = "redemption";
pub const VALID_CUSTODIAL_INTENT_ORIGINS: &[&str] = &["sign", "redemption"];
pub const VALID_CUSTODIAL_INTENT_STATUSES: &[&str] = &["prepared", "submitted", "settled", "rejected", "ambiguous"];
pub const VALID_CUSTODIAL_KEY_SOURCES: &[&str] = &["client", "server"];
pub const VALID_CUSTODIAL_INTENT_RESOLUTIONS: &[&str] = &["submit_ok", "submit_rejected", "prepare_rejected", "arm_failed", "sweep_settled", "sweep_failed", "sweep_expired", "sweep_abandoned", "admin_complete", "admin_fail"];
pub const CUSTODIAL_IDEMPOTENCY_KEY_MIN_LEN: usize = 1;
pub const CUSTODIAL_IDEMPOTENCY_KEY_MAX_LEN: usize = 64;      // charset [A-Za-z0-9._:-]
pub const MEMO_TEXT_MAX_BYTES: usize = 28;
pub const CUSTODIAL_INTENT_FP_DOMAIN: &str = "impala-custodial-intent-v1";
/// Age (from armed_at) after which an unresolved submitted/ambiguous intent is resolved by hash.
pub const CUSTODIAL_STALE_INTENT_SECS: i64 = 600;
const _: () = assert!(CUSTODIAL_STALE_INTENT_SECS >= 2 * 300);   // signer TX_TIMEOUT_SECS
/// Age (from created_at) after which a 'prepared' row with no hash is rejected as abandoned.
/// Liveness only: the arm CAS makes a late arm fail regardless of timing.
pub const CUSTODIAL_INTENT_ABANDON_SECS: i64 = 120;
const _: () = assert!(CUSTODIAL_INTENT_ABANDON_SECS as u64 > REQUEST_TIMEOUT_SECS + DEFAULT_HTTP_CLIENT_TIMEOUT_SECS);
pub const CUSTODIAL_SWEEP_INTERVAL_SECS: u64 = 60;
pub const CUSTODIAL_SWEEP_BATCH: i64 = 25;
pub const CUSTODIAL_DAILY_WINDOW_SECS: i64 = 86_400;
pub const CUSTODY_ADMIN_RATE_LIMIT_SCOPE: &str = "custody_admin";  // 5/60s via SIGN_RATE_LIMIT_*
/// Refusal codes on the custodial paths (openapi + impalactl pin this list).
pub const CUSTODIAL_REFUSAL_CODES: &[&str] = &["custodial_paused", "custodial_unconfigured", "custodial_tx_limit", "custodial_daily_limit", "custodial_account_frozen", "idempotency_conflict", "idempotency_key_required", "payment_in_flight", "payment_rejected"];
```
`models.rs` tests (mirror `test_reserve_entry_kinds_match_ddl` :2405): `test_custodial_intent_vocabularies_match_ddl` (`include_str!("../migrations/037_custodial_conservation.sql")`; each list's literals appear quoted inside its `CHECK (... IN (` line and the quoted-literal count of that line equals the list length), `test_transaction_origins_match_ddl` (same over `chk_transaction_origin` in 037), `test_custodial_vocabularies_fit_their_columns` (status ≤ 12, origin ≤ 16, key_source ≤ 8, resolution ≤ 24).

### 1.3 Request fingerprint (`B/src/custody/fingerprint.rs`, pure)

```rust
pub(crate) fn intent_fingerprint(destination: &str, asset_code: &str, asset_issuer: Option<&str>,
    amount_minor: i64, memo: Option<&str>, fee_stroops: Option<u32>) -> String
```
SHA-256 (`sha2`, already a dependency) over `CUSTODIAL_INTENT_FP_DOMAIN || 0x00`, then for each field in this order `[destination, asset_code, asset_issuer|"", amount_minor.to_string(), memo|"", fee.map(to_string)|""]`: `u32 BE length || bytes`, then three presence bytes `[issuer.is_some(), memo.is_some(), fee.is_some()]`. Returns 64 lowercase hex. Computed over `amount_minor` (parsed), so `"1.5"` and `"1.50"` fingerprint identically. Tests: `fingerprint_golden_vector` (fixed inputs → fixed 64-hex literal), `fingerprint_distinguishes_absent_from_empty`, `fingerprint_is_amount_canonical`, `fingerprint_changes_with_each_field`.

### 1.4 Request / response contract (append-only)

`B/src/models.rs:256-272`:
```rust
#[derive(Deserialize)]
pub struct SignSubmitRequest {
    pub payala_account_id: String, pub destination: String, pub amount: String,
    pub memo: Option<String>, pub fee: Option<u32>,
    /// NEW, optional. 1-64 chars of [A-Za-z0-9._:-]. Same key + same request => the recorded
    /// outcome (never re-signed); same key + different request => 409 idempotency_conflict.
    /// Absent => the bridge mints a UUIDv4 (key_source 'server'); the client cannot replay it
    /// but can recover the intent via GET /managed-account/intents.
    #[serde(default)] pub idempotency_key: Option<String>,
}
#[derive(Serialize)]
pub struct SignSubmitResponse {
    pub success: bool, pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub stellar_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub btxid: Option<Uuid>,
    // NEW, all optional for old readers (impalactl/internal/bridge/types.go:160-164):
    #[serde(skip_serializing_if = "Option::is_none")] pub intent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")] pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub status: Option<String>,      // VALID_CUSTODIAL_INTENT_STATUSES
    #[serde(skip_serializing_if = "Option::is_none")] pub resolution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub replayed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub amount_minor: Option<i64>,
}
```
Handler signature becomes `-> Result<(StatusCode, Json<SignSubmitResponse>), AppError>`.

| Situation | HTTP | Body |
|---|---|---|
| Settled — first time, or replay of `settled` | 200 | `success:true, status:"settled", stellar_hash, btxid, intent_id, idempotency_key, resolution, replayed` |
| Ambiguous submit — first time, or replay of `ambiguous` | 202 | `success:false, status:"ambiguous", intent_id, stellar_hash, message:"Outcome unknown: the signed transaction may still land within 300s. Do NOT resubmit; resend with the same idempotency_key or poll GET /managed-account/intents/{id}."` |
| Settled on-chain but the settle transaction failed (DB) | 202 | `status:"submitted", stellar_hash, intent_id` — the sweep records it by hash (graft: never a 200 with `btxid:null`) |
| Replay while `prepared` or `submitted` | 409 `payment_in_flight` | `details: {intent_id, status, stellar_hash?}` |
| Definitive rejection (pre-submit `BadRequest`, or Horizon 400 with result codes) — first time or replay of `rejected` | 400 `payment_rejected` | `message: last_error`, `details: {intent_id, status:"rejected", resolution, replayed}` |
| Same key, different fingerprint | 409 `idempotency_conflict` | `details: {intent_id}` |
| Another non-terminal `sign` intent for the account (23505 on `uq_custodial_intent_one_inflight`) | 409 `payment_in_flight` | `details: {intent_id: <the live one>}` |
| Paused / policy row missing or caps 0 | 503 `custodial_paused` / `custodial_unconfigured` | via `AppError::Coded` (status 503; `IsAmbiguousOutcome` treats 503 as "never sent", correct here) |
| Per-account override 0 | 409 `custodial_account_frozen` | |
| `amount > per_tx_max` | 400 `custodial_tx_limit` | `details: {per_tx_max_stroops}` |
| `spent_24h + amount > daily cap` | 409 `custodial_daily_limit` | `details: {remaining_stroops, resets_at}` |
| `require_idempotency_key=true` and none supplied | 400 `idempotency_key_required` | |
| Pre-submit transient (`Retryable`, e.g. sequence fetch) | 503 `service_unavailable` (existing) | intent `rejected/prepare_rejected`; safe to retry with the same key — the replay returns 400 `payment_rejected`, so the client must use a NEW key (documented; impalactl does this automatically) |
| Request deadline fires mid-submit | 408 (TimeoutLayer, empty body) | the tracked task finishes and records; client polls by `intent_id` or replays its key |

**New owner-scoped reads** (in `B/src/handlers/managed_seed.rs`, non-privileged, `AuthenticatedUser`):
* `GET /managed-account/intents/{intent_id}` → `CustodialIntentView` (`models.rs`): `{intent_id, payala_account_id, origin, status, resolution, key_source, idempotency_key, destination, asset_code, asset_issuer, amount_minor, amount (decimal string via minor_to_decimal_string), memo, fee_stroops, stellar_hash, btxid, last_error, created_at, armed_at, resolved_at}`. `require_owner` against the row's `payala_account_id`; a non-owner or missing row is the same 404 (ids not enumerable). `require_not_reserve_account` applies.
* `GET /managed-account/intents?payala_account_id=&idempotency_key=&status=&page=&per_page=` → `PaginatedResponse<CustodialIntentView>` via `PaginationParams::clamped()` (`models.rs:69`); `payala_account_id` required and owner-checked; `idempotency_key` filter lets a client that lost the response of a server-minted-key request find its intent.

### 1.5 Handler flow (`managed_seed::sign_and_submit`, replaces lines 507-615)

New module `B/src/custody/{mod.rs, intent.rs, policy.rs, fingerprint.rs, sweep.rs}` (add `mod custody;` to `main.rs`). The handler:

```
1. require_owner; require_not_reserve_account; check_rate_limit("sign", 5/60s)         (unchanged, fail-closed)
2. validate_stellar_account_id(destination)
   amount_minor = parse_decimal_to_minor(&amount, RESERVE_SCALE_STELLAR) filtered > 0, else 400
   memo: byte length <= MEMO_TEXT_MAX_BYTES else 400
   fee: Some(0) => 400
   key = client key (validated charset/len) | server-minted Uuid::new_v4().to_string()
   fingerprint = intent_fingerprint(destination, "XLM", None, amount_minor, memo, fee)
   canonical_amount = minor_to_decimal_string(amount_minor, 7)     -- what gets signed; row == tx
3. CLAIM (custody::intent::claim_user_payment, ONE transaction):
     SELECT pg_advisory_xact_lock(hashtext('custodial_sign:' || $1))          (sync.rs:331 shape)
     INTENT_LOOKUP_SQL (FOR UPDATE) by (account, key)
       -> row exists: fingerprint differs => ROLLBACK, 409 idempotency_conflict
                      else => ROLLBACK (nothing written) and return the replay per the table above.
          REPLAYS NEVER RE-CHECK POLICY AND NEVER COUNT SPEND (judge flaw on D1).
     POLICY_READ_SQL (FOR SHARE; fetch_one: missing row => 503 custodial_unconfigured)
     require_idempotency_key && key_source == server => 400 idempotency_key_required
     paused => 503 custodial_paused                                            -- BEFORE any seed access
     ACCOUNT_LIMIT_SQL (FOR KEY SHARE) + DAILY_SPEND_SQL; evaluate_policy (§2.2) => refusal or continue
     SOURCE_ACCOUNT_SQL: SELECT stellar_account_id FROM managed_seed WHERE payala_account_id=$1 (FOR KEY SHARE)
        -> none => 404 "No managed seed for this account" (same as load_protected_seed:349)
     INTENT_INSERT_SQL ... RETURNING intent_id
        -> 23505 on uq_custodial_intent_one_inflight => ROLLBACK, 409 payment_in_flight (details: the live intent_id)
     COMMIT
4. SUBMIT PHASE — tracker.spawn(custody::intent::submit_intent(deps, intent_id, account, params)); handler awaits the JoinHandle
     (JoinError => 500 "submit task failed"; the row stays prepared/submitted and the sweep resolves it)
     if cancel.is_cancelled() => leave prepared (sweep abandons; nothing moved) and return 503 service_unavailable
     seed = load_protected_seed(pool, protector, signer, account)              (unchanged; asserts address)
     prepared = signer.prepare_payment(seed, PaymentParams{destination, amount: canonical_amount, asset: Native, memo, fee})
        Err(BadRequest(m)) => INTENT_REJECT_PREPARED_SQL(resolution 'prepare_rejected', last_error m) => 400 payment_rejected
        Err(other)         => same row update, resolution 'prepare_rejected' => 503 service_unavailable
     INTENT_ARM_SQL (hash, status='submitted', armed_at)  -- rows_affected != 1 or any error (incl. 23505 on uq_custodial_intent_hash) =>
        DO NOT SUBMIT; INTENT_REJECT_PREPARED_SQL('arm_failed') best-effort; return 503 service_unavailable
     drop(seed)   -- zeroized before the network call
     submitted = signer.submit_prepared(&prepared)
     match classify_submit(&submitted)                                        (reserve_watch.rs:160, reused as-is)
        Settled            => record_settlement(pool, intent, hash, tx_id, "submit_ok")  (§1.7)
                              Ok(Settled{btxid}) => 200 ; Err(db) => 202 status "submitted" (sweep settles)
        Rejected{msg,..}   => INTENT_REJECT_SUBMITTED_SQL('submit_rejected', msg[..200]) => 400 payment_rejected
        Ambiguous          => one tx: INTENT_AMBIGUOUS_SQL + emit_event(CustodialPaymentAmbiguous); COMMIT => 202
5. After the settle transaction commits ONLY: metrics.transactions_created += 1; notifications::dispatch_event(TransferOutgoing{..}) (today it fires even when bookkeeping failed — no longer).
```

SQL constants in `custody/intent.rs` (string-pinned):
```
INTENT_LOOKUP_SQL   = SELECT intent_id, request_fingerprint, status, resolution, stellar_hash, btxid, last_error, amount_minor
                        FROM custodial_payment_intent WHERE payala_account_id = $1 AND idempotency_key = $2 FOR UPDATE
INTENT_INSERT_SQL   = INSERT INTO custodial_payment_intent
                        (payala_account_id, source_account, origin, idempotency_key, key_source, request_fingerprint,
                         destination, asset_code, asset_issuer, amount_minor, memo, fee_stroops, redemption_id)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING intent_id     -- 13 binds
INTENT_ARM_SQL      = UPDATE custodial_payment_intent SET stellar_hash = $2, status = 'submitted', armed_at = CURRENT_TIMESTAMP
                        WHERE intent_id = $1 AND status = 'prepared' AND stellar_hash IS NULL
INTENT_REJECT_PREPARED_SQL  = UPDATE ... SET status = 'rejected', resolution = $2, last_error = $3, resolved_at = CURRENT_TIMESTAMP
                        WHERE intent_id = $1 AND status = 'prepared'
INTENT_REJECT_SUBMITTED_SQL = ... WHERE intent_id = $1 AND status = 'submitted' AND stellar_hash = $4
INTENT_REJECT_BY_HASH_SQL   = ... WHERE intent_id = $1 AND status IN ('submitted', 'ambiguous') AND stellar_hash = $4   (sweep/admin only)
INTENT_AMBIGUOUS_SQL = UPDATE ... SET status = 'ambiguous', last_error = $2 WHERE intent_id = $1 AND status = 'submitted' AND stellar_hash = $3
INTENT_SETTLE_SQL   = UPDATE ... SET status = 'settled', btxid = $2, resolution = $3, resolved_at = CURRENT_TIMESTAMP
                        WHERE intent_id = $1 AND status IN ('submitted', 'ambiguous') AND stellar_hash = $4
SETTLEMENT_TX_INSERT_SQL = INSERT INTO transaction (stellar_tx_id, stellar_hash, source_account, memo, account_id, origin,
                        stellar_amount_minor, stellar_destination, stellar_asset_code, stellar_asset_issuer)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING btxid                        -- 10 binds
```
`stellar_tx_id` binds `submitted.stellar_tx_id.unwrap_or(hash)` (as `reserve_watch.rs:1628`). `account_id` = the beneficiary account (`payala_account_id` for `sign`; the card owner for `redemption`, §8.6); `origin` = `TX_ORIGIN_CUSTODIAL_SIGN` / `TX_ORIGIN_OFFLINE_REDEMPTION`.

### 1.6 Crash recovery — `custody::sweep::run(deps, cancel)`

Spawned in `main.rs` next to `admin_webhook_delivery` (needs `pool, http, horizon_url, metrics, cancel`; it must NOT live in the reserve tick — intents exist when the reserve is unconfigured). Every `CUSTODIAL_SWEEP_INTERVAL_SECS`, one pass under `AdvisoryLock::new(CUSTODIAL_SWEEP_LOCK_KEY)` (`reserve_watch::AdvisoryLock` is already `pub(crate)`, :462-489). Every write is a CAS, so correctness never depends on the lock.

1. `ABANDON_SQL = UPDATE custodial_payment_intent SET status='rejected', resolution='sweep_abandoned', last_error='abandoned before submit', resolved_at=CURRENT_TIMESTAMP WHERE status='prepared' AND stellar_hash IS NULL AND created_at < CURRENT_TIMESTAMP - make_interval(secs => $1)` (`$1 = CUSTODIAL_INTENT_ABANDON_SECS`). Sound because no hash ⇒ no submit ever happened, and a late arm fails its CAS.
2. `STALE_SQL = SELECT intent_id, payala_account_id, origin, redemption_id, source_account, destination, asset_code, asset_issuer, amount_minor, memo, stellar_hash, status FROM custodial_payment_intent WHERE status IN ('submitted','ambiguous') AND armed_at < CURRENT_TIMESTAMP - make_interval(secs => $1) ORDER BY armed_at LIMIT $2` (`$1 = CUSTODIAL_STALE_INTENT_SECS`, `$2 = CUSTODIAL_SWEEP_BATCH`).
3. `head = fetch_head_closed_at(http, horizon_url)` once per pass; `fresh = head_is_fresh(head, now, HORIZON_MAX_LAG_SECS)` (`horizon.rs:232`).
4. Per row: `fetch_transaction_payments(http, horizon_url, hash)` (`horizon.rs:243`) → pure verdict:
   ```rust
   pub(crate) enum HashLookup { Error, NotFound, Found { settles: bool, any_failed: bool } }
   pub(crate) enum SweepVerdict { Settle, RejectFailedOnChain, RejectExpired, Leave }
   pub(crate) fn sweep_verdict(lookup: HashLookup, head_fresh: Option<bool>) -> SweepVerdict
   ```
   `Found{settles:true}` → `Settle` → `record_settlement(.., "sweep_settled")`; `Found{any_failed:true, settles:false}` → `RejectFailedOnChain` → `INTENT_REJECT_BY_HASH_SQL('sweep_failed')`; `Found{neither}` → `Leave` + `error!` (admin resolves); `NotFound` with `head_fresh == Some(true)` → `RejectExpired` (`'sweep_expired'`; the query already guarantees age ≥ 600 s > 300 s validity — same proof as `resolve_intent_by_hash`, `admin_reserve.rs:2219-2227`); `NotFound` with stale/unknown head, or `Error` → `Leave`. `settles(p, source_account, destination, amount_minor, Some(&asset))` moves from `admin_reserve.rs:2296` (with `asset_matches` :2282) to `B/src/stellar/horizon.rs` as `pub(crate)`; `admin_reserve.rs` re-imports.
5. For `origin='redemption'` rows the settle/reject branches also run `offline::redemption::on_intent_settled/on_intent_rejected` inside the same transaction (§8.6; no-ops in PR1 because the origin cannot exist before 038).
6. Metrics (after commit): `custodial_intents_swept{outcome}` counter, `custodial_intents_open{status}` gauge.

No admin override is needed for resolution by hash; `admin_custody::resolve_intent` (§2.4) exists for the `Found{neither}` case and for definitive rejection after a proven absence.

### 1.7 `record_settlement` (shared by handler, sweep, admin resolve; `custody/intent.rs`)

One transaction: `SETTLEMENT_TX_INSERT_SQL` → `INTENT_SETTLE_SQL` (rows_affected == 0 ⇒ another resolver already settled it: ROLLBACK — the duplicate transaction row is discarded — and return `AlreadySettled`) → for `origin='redemption'`: `offline::redemption::on_intent_settled(&mut tx, ..)` → `emit_event(CustodialPaymentSettled{..})` → COMMIT. Returns `Settled{btxid} | AlreadySettled`.

### 1.8 Events (`B/src/events.rs`, append-only; actor/beneficiary in `account_id`)

```rust
CustodialPaymentSettled   { account_id, intent_id: String, btxid: String, origin: String, amount_minor: i64, asset_code: String, resolution: String } => "custodial.payment_settled"
CustodialPaymentAmbiguous { account_id, intent_id: String, origin: String, amount_minor: i64, asset_code: String }                                  => "custodial.payment_ambiguous"
```
Tests: `custodial_payloads_never_carry_addresses_or_hashes` — serialize `data()`, assert no `destination`/`memo`/`stellar_hash` keys, and (generic helper `assert_no_ledger_pointers(&Value)`) no string value that is 56 chars starting with `G` or 64 lowercase-hex chars; `event_type_vocabulary_is_append_only` — a frozen array of every existing `event_type()` string (the 30 at `events.rs:231-261`) must still be produced by the matching variants.

### 1.9 `admin.rs::delete_account` guard (`B/src/handlers/admin.rs:347-491`)

Before the reserve-order guard: `DELETE_GUARD_INTENTS_SQL = SELECT COUNT(*) FROM custodial_payment_intent WHERE payala_account_id = $1 AND status IN ('prepared','submitted','ambiguous')` > 0 → 409 `Conflict("Account has N unresolved custodial payment(s); wait for the sweep or resolve them first")`. PR4 adds the offline guards (§8.9). String-pinned by `delete_guard_covers_every_non_terminal_intent_status` (contains exactly the three non-terminal statuses).

---

## 2. Custodial policy (pause + caps)

### 2.1 Migration 037 — part B

```sql
CREATE TABLE IF NOT EXISTS custodial_policy (
    id                              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    paused                          BOOLEAN NOT NULL DEFAULT false,
    paused_by                       VARCHAR(64),
    paused_at                       TIMESTAMP WITH TIME ZONE,
    pause_reason                    VARCHAR(200),
    -- 0 = UNCONFIGURED -> refuse (032:197). Never "unlimited".
    per_tx_max_stroops              BIGINT NOT NULL DEFAULT 0 CHECK (per_tx_max_stroops >= 0),
    per_account_daily_max_stroops   BIGINT NOT NULL DEFAULT 0 CHECK (per_account_daily_max_stroops >= 0),
    require_idempotency_key         BOOLEAN NOT NULL DEFAULT false,
    updated_by                      VARCHAR(64),
    created_at                      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO custodial_policy (id) VALUES (true) ON CONFLICT (id) DO NOTHING;
CREATE TRIGGER update_custodial_policy_updated_at BEFORE UPDATE ON custodial_policy
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
-- Per-account override: NULL = global cap applies; 0 = this account is frozen.
ALTER TABLE impala_account ADD COLUMN IF NOT EXISTS custodial_daily_max_stroops BIGINT
    CHECK (custodial_daily_max_stroops IS NULL OR custodial_daily_max_stroops >= 0);
```

### 2.2 Enforcement (inside the §1.5 claim transaction, under the per-account xact lock)

```
POLICY_READ_SQL   = SELECT paused, per_tx_max_stroops, per_account_daily_max_stroops, require_idempotency_key FROM custodial_policy WHERE id FOR SHARE
ACCOUNT_LIMIT_SQL = SELECT custodial_daily_max_stroops FROM impala_account WHERE payala_account_id = $1 FOR KEY SHARE
DAILY_SPEND_SQL   = SELECT COALESCE(SUM(amount_minor), 0)::bigint, MIN(created_at) FROM custodial_payment_intent
                    WHERE payala_account_id = $1 AND origin = 'sign' AND status <> 'rejected'
                      AND created_at >= CURRENT_TIMESTAMP - make_interval(secs => $2)
```
Pure `custody::policy::evaluate_policy(policy: &PolicyRow, account_override: Option<i64>, spent_24h: i64, window_start: Option<DateTime>, amount_minor: i64) -> Result<(), Refusal>` with `enum Refusal { Paused, Unconfigured, AccountFrozen, PerTx{max}, Daily{remaining, resets_at} }` → `AppError::Coded`. Order: `paused` → `per_tx_max == 0 || (global_daily == 0 && override.is_none())` → Unconfigured → `override == Some(0)` → AccountFrozen → `amount > per_tx_max` → PerTx → `effective_daily = override.unwrap_or(global)`; `spent.checked_add(amount)` overflow or `> effective_daily` → Daily{remaining = effective_daily - spent, resets_at = window_start + 24h}. `prepared`, `submitted`, `ambiguous` and `settled` all count as spent (an unresolved outcome is money until proven otherwise; `DAILY_REFUND_SPEND_SQL` precedent :1888). Tests: `caps_refuse_when_unconfigured`, `override_zero_freezes_the_account`, `override_replaces_global_even_when_global_is_zero`, `daily_counts_every_non_rejected_status` (SQL pin: contains `status <> 'rejected'` and `origin = 'sign'`), `daily_overflow_is_checked_arithmetic`, `decision_order_is_pause_unconfigured_frozen_pertx_daily`, `policy_read_is_for_share_single_row`.

`paused` also gates (PR4) issuance creation, redemption creation and the redemption driver's claim of new rows. It does NOT gate the reserve drivers (`refunds_enabled`, replenish `enabled`, quote kill switch are separate) — stated in the runbook and the controls inventory (§7).

### 2.3 Capabilities — the three-place edit (must land in one commit)

1. `B/src/auth.rs:121-221`: variants `Capability::ManageCustody` ("Mutate custodial policy: pause, caps, per-account limits, intent resolution, offline issuance policy. Money-moving.") and `Capability::ReadCustody` ("Read custodial policy, intents, positions, snapshots, offline queues."); `ALL: [Capability; 9]`; matrix rows `ManageCustody => matches!(role, ROLE_ADMIN | ROLE_TREASURER)`, `ReadCustody => matches!(role, ROLE_ADMIN | ROLE_TREASURER | ROLE_AUDITOR)`; marker structs `pub struct ManageCustody; pub struct ReadCustody;` + `RequiredCapability` impls. Tests: `expected_capability_roles` (:652) gains both rows; `auditor_holds_no_mutation_capability` (:717) adds `ManageCustody` to its mutation list; `lateral_roles_do_not_cross_surfaces` (:730): key-custodian holds neither, treasurer holds both, auditor holds ReadCustody only.
2. `impala-ui/html/js/roles.js:36-72`: permissions `view_custody` (treasurer, auditor, admin) and `manage_custody` (treasurer, admin); treasurer description gains "custodial pause/limits"; `impala-ui/html/js/router.js:46-54` adds `{ href: 'custody.html', label: 'Custody' }` for `view_custody || manage_custody`; `impala-ui/tests/role-capabilities-contract.test.js` `SURFACES` gains `'custody'`; `roles-extended.test.js`/`router-nav.test.js` gain the new permission/link assertions.
3. `impala-ui/tests/fixtures/role-capabilities.json`: `"ManageCustody": ["admin", "treasurer"], "ReadCustody": ["admin", "treasurer", "auditor"]` — `capability_matrix_matches_shared_fixture` (`auth.rs:776`) and the UI contract test both fail until all three land.

### 2.4 Endpoints — new module `B/src/handlers/admin_custody.rs` (9 `pub async fn`, exactly one `: AdminUser`)

All mutations rate-limited (`check_rate_limit(CUSTODY_ADMIN_RATE_LIMIT_SCOPE, actor, SIGN_RATE_LIMIT_MAX_REQUESTS, SIGN_RATE_LIMIT_WINDOW_SECS)`) and audited **inside** the mutating transaction (actor in `account_id`, `ReservePolicyUpdated` convention).

| Handler | Route | Extractor | Behaviour |
|---|---|---|---|
| `get_policy` | `GET /admin/custody/policy` | `Privileged<ReadCustody>` | `CustodialPolicyView { paused, paused_by, paused_at, pause_reason, per_tx_max_stroops, per_account_daily_max_stroops, require_idempotency_key, configured: bool, updated_by, updated_at, open_intents: {prepared, submitted, ambiguous}, resume_phrase }` |
| `update_policy` | `PUT /admin/custody/policy` `{per_tx_max_stroops?, per_account_daily_max_stroops?, require_idempotency_key?}` | `Privileged<ManageCustody>` | `LIMITS_SQL = UPDATE custodial_policy SET per_tx_max_stroops = COALESCE($1, per_tx_max_stroops), per_account_daily_max_stroops = COALESCE($2, per_account_daily_max_stroops), require_idempotency_key = COALESCE($3, require_idempotency_key), updated_by = $4 WHERE id`; negative → 400; emits `custody.policy_updated` |
| `pause` | `POST /admin/custody/pause` `{reason: 1..200 chars}` | `Privileged<ManageCustody>` | `PAUSE_SQL = UPDATE custodial_policy SET paused = true, paused_by = $1, paused_at = CURRENT_TIMESTAMP, pause_reason = $2, updated_by = $1 WHERE id AND paused = false`; 0 rows → 200 `{changed:false}` idempotent, no event; else emits `custody.paused` |
| `resume` | `POST /admin/custody/resume` `{confirm_phrase, force?: bool}` | **`AdminUser`** | `confirm_phrase` must equal `keys::confirm_phrase`-style `format!("resume custody {}", network)` (served as `resume_phrase`); refuses 409 `Conflict` while `SELECT COUNT(*) ... WHERE status = 'ambiguous'` > 0 unless `force:true` (reopening with unknown chain state is the double-pay moment); `RESUME_SQL = UPDATE ... SET paused = false, paused_by = NULL, paused_at = NULL, pause_reason = NULL, updated_by = $1 WHERE id AND paused = true` (0 rows → 200 `{changed:false}`); emits `custody.resumed {forced}` |
| `set_account_limit` | `PUT /admin/custody/accounts/{account_id}/limit` `{custodial_daily_max_stroops: int|null}` | `Privileged<ManageCustody>` | refuses the configured reserve account (`ReserveAccountGuard::matches`); `UPDATE impala_account SET custodial_daily_max_stroops = $2 WHERE payala_account_id = $1` (0 rows → 404); emits `custody.account_limit_updated {target_account_id, custodial_daily_max_stroops}` |
| `list_accounts` | `GET /admin/custody/accounts?page&per_page&onchain=bool` | `Privileged<ReadCustody>` | `SELECT payala_account_id, stellar_account_id, origin, format_version, backend, created_at FROM managed_seed ORDER BY id LIMIT $1 OFFSET $2` (clamped ≤ 100); reserve account excluded (reported under reserve); `onchain=true` → `fetch_account_details` per row with `futures::stream::iter(..).buffer_unordered(8)`; unreachable rows → `onchain: null, unreachable: true` (never fails the endpoint) |
| `list_intents` | `GET /admin/custody/intents?status&account&origin&page&per_page` | `Privileged<ReadCustody>` | paged `CustodialIntentView`; `status` validated against `VALID_CUSTODIAL_INTENT_STATUSES` |
| `get_intent` | `GET /admin/custody/intents/{intent_id}` | `Privileged<ReadCustody>` | one view |
| `resolve_intent` | `POST /admin/custody/intents/{intent_id}/resolve` `{action: "complete"|"fail", stellar_hash?}` | `Privileged<ManageCustody>` | only `status IN ('submitted','ambiguous')`. `complete`: `verify_settlement_hash(http, horizon, hash_or_intent_hash, source, destination, amount_minor, Some(&asset))` (`admin_reserve.rs:2183`, make `pub(crate)`) then `record_settlement(.., "admin_complete")`. `fail`: requires `armed_at` age ≥ `CUSTODIAL_STALE_INTENT_SECS` and `resolve_intent_by_hash(..) == Ok(None)` (proven absent/failed on a fresh Horizon; `Inconclusive` fails closed) → `INTENT_REJECT_BY_HASH_SQL('admin_fail')`; redemption-origin rows additionally run `on_intent_rejected`. Emits `custody.intent_resolved {intent_id, action, resolution}` |

Events: `CustodyPaused{account_id, reason}` ⇒ `custody.paused`; `CustodyResumed{account_id, forced}` ⇒ `custody.resumed`; `CustodyPolicyUpdated{account_id, per_tx_max_stroops, per_account_daily_max_stroops, require_idempotency_key}` ⇒ `custody.policy_updated`; `CustodyAccountLimitUpdated{account_id, target_account_id, custodial_daily_max_stroops: Option<i64>}` ⇒ `custody.account_limit_updated`; `CustodyIntentResolved{account_id, intent_id, action, resolution}` ⇒ `custody.intent_resolved`.

Routes in `main.rs` next to `/admin/exchange-reserve/*`. `AppError::Conflict`'s `#[allow(dead_code)]` (`error.rs:15`) is removed (it is already used by handlers).

---

## 3. `GET /admin/reconciliation/positions` + daily snapshot (PR2)

### 3.1 Migration 037 — part C

```sql
-- Per-bucket alert threshold for |onchain - (available + held)|. 0 = alert on
-- any drift. XLM needs a non-zero value: network fees are paid by the reserve
-- account and are not journaled (conservation-spec §4.3), so its ledger reads
-- HIGH by the cumulative fee sum.
ALTER TABLE conversion_reserve
    ADD COLUMN IF NOT EXISTS drift_tolerance_minor BIGINT NOT NULL DEFAULT 0
        CHECK (drift_tolerance_minor >= 0);

CREATE TABLE IF NOT EXISTS reconciliation_snapshot (
    snapshot_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- UTC date the job computed in Rust (never an index expression over a
    -- timestamptz cast: that is STABLE, not IMMUTABLE, and Postgres rejects it).
    snapshot_date           DATE        NOT NULL,
    kind                    VARCHAR(8)  NOT NULL,
    schema_version          INTEGER     NOT NULL,
    as_of                   TIMESTAMP WITH TIME ZONE NOT NULL,
    horizon_head_closed_at  TIMESTAMP WITH TIME ZONE,
    horizon_fresh           BOOLEAN     NOT NULL,
    complete                BOOLEAN     NOT NULL,   -- every custodial address read within budget
    drift_detected          BOOLEAN     NOT NULL,
    invariants_ok           BOOLEAN     NOT NULL,
    payload                 JSONB       NOT NULL,   -- the PositionsResponse as served
    created_by              VARCHAR(64),            -- NULL for the job
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_reconciliation_snapshot_kind CHECK (kind IN ('daily', 'manual'))
);
-- Idempotency anchor for the job: one daily snapshot per UTC date across instances.
CREATE UNIQUE INDEX IF NOT EXISTS uq_reconciliation_snapshot_daily
    ON reconciliation_snapshot(snapshot_date) WHERE kind = 'daily';
CREATE INDEX IF NOT EXISTS idx_reconciliation_snapshot_created ON reconciliation_snapshot(created_at);
```
`update_bucket` (`admin_reserve.rs:273-303`) gains optional `drift_tolerance_minor` (`ReserveBucketUpdateRequest`, `COALESCE($5, drift_tolerance_minor)`; recount: 5 binds).

### 3.2 Response schema (`PositionsResponse`, `schema_version: 1`, append-only; all money `i64` minor)

```jsonc
{ "schema_version": 1, "as_of": "...", "complete": true,
  "horizon": { "url": "...", "head_closed_at": "...|null", "lag_secs": 4, "fresh": true },
  "reserve": { "configured": true, "stellar_address": "G...|null",
    "buckets": [ { "currency": "XLM", "minor_scale": 7, "asset": "CODE:ISSUER|null", "chain_leg": true,
        "available_minor": 0, "held_minor": 0, "ledger_total_minor": 0,
        "journal_available_minor": 0, "journal_held_minor": 0, "journal_replay_ok": true,
        "onchain_minor": 0, "onchain_raw": "0.0000000", "trustline": true,
        "drift_minor": 0, "drift_tolerance_minor": 0, "drift_ok": true,
        "offline_held_minor": 0 } ],           // USD: chain_leg false, onchain_*/drift_* null
    "obligations": { "refunds_minor": { "queued": {"XLM": 0}, "needs_review": {}, "frozen": {}, "inflight": {} },
        "order_holds_minor": {}, "quote_holds_minor": {}, "payout_intents_open": 0,
        "cycles_in_flight": 0, "cycle_holds_minor": {}, "fiat_in_transit_cents": 0,
        "offline_outstanding_minor": {"XLM": 0}, "offline_issuances_open": 0, "offline_redemptions_pending": 0 } },
  "custodial": { "source": "managed_seed+horizon", "accounts_total": 0, "page": 1, "per_page": 25, "checked": 25,
    "positions": [ { "payala_account_id": "...", "stellar_account_id": "G...", "origin": "generated", "format_version": 1,
        "onchain": { "exists": true, "xlm_stroops": 0, "balances": [ {"asset_code": "USDC", "asset_issuer": "G...", "minor": 0} ] } | null,
        "unreachable": false, "open_intents": 0, "open_intents_minor": 0 } ],
    "totals": { "addresses_checked": 0, "addresses_unreachable": 0, "xlm_stroops": 0, "intents_prepared": 0, "intents_submitted": 0, "intents_ambiguous": 0, "intents_settled_24h_minor": 0, "truncated": false },
    "policy": { "paused": false, "configured": true } },
  "payala": { "source": "self_reported_unverified", "accounts_with_reserve": 0, "net_minor_by_currency": {}, "last_batch_at": "...|null" },
  "card": { "source": "bridge_issued_only", "note": "on-card balances never reach the bridge; only bridge-issued credits and bridge-verified redemptions are counted" },
  "invariants": [ { "name": "reserve_journal_replays", "ok": true, "detail": "" },
                  { "name": "reserve_chain_covers_ledger", "ok": true|false|null, "detail": "" },
                  { "name": "reserve_drift_within_tolerance", "ok": true, "detail": "" },
                  { "name": "reserve_available_covers_queued_refunds", "ok": true, "detail": "" },
                  { "name": "offline_liabilities_are_held", "ok": true, "detail": "" },
                  { "name": "custodial_no_stale_intents", "ok": true, "detail": "" },
                  { "name": "custodial_addresses_reachable", "ok": true, "detail": "" } ],
  "warnings": [] }
```
Definitions (pure `B/src/reconciliation/compute.rs`, DB/HTTP-free, tested): `ledger_total = available + held`; `onchain_minor = parse_decimal_to_minor(balance, minor_scale)`; `drift_minor = onchain - ledger_total` (`checked_sub`, overflow → invariant `null` + warning); `drift_ok = |drift| <= tolerance`; `journal_*` = `SELECT currency, COALESCE(SUM(delta),0), COALESCE(SUM(held_delta),0) FROM conversion_reserve_entry GROUP BY currency` compared to the bucket columns; `offline_held_minor` = Σ `held_delta` of the six offline kinds per currency (0 before 038); `invariants[].ok = null` (not asserted) whenever Horizon is unreachable or `fresh=false` — an unverifiable state never reads as clean. Data sources: `conversion_reserve` (+`drift_tolerance_minor`), `get_status`'s chain snapshot loop (`admin_reserve.rs:163-199`) factored into `pub(crate) async fn reserve_chain_snapshot(http, horizon_url, reserve) -> Result<OnchainAccount, AppError>`; refunds `SELECT currency, status, COALESCE(SUM(refund_minor),0) FROM conversion_reserve_refund WHERE status IN ('queued','needs_review','frozen','inflight') GROUP BY 1,2`; `payout_intents_open = SELECT COUNT(*) FROM conversion_reserve_entry e WHERE e.kind='payout_attempt' AND NOT EXISTS (SELECT 1 FROM conversion_reserve_entry f WHERE f.order_id=e.order_id AND f.kind='fulfillment')`; cycles `WHERE state NOT IN ('completed','failed','refunded')`; `SUM(fiat_minor) WHERE state='in_transit'`; order/quote holds from `ORDER_HOLD_SQL` semantics; custodial page from `managed_seed ORDER BY id` (per_page clamp 1..=100, default 25; reserve row excluded), Horizon fan-out `buffer_unordered(8)`; payala `SELECT COUNT(DISTINCT payala_account_id), currency, SUM(balance) FROM payala_reserve GROUP BY currency` + `MAX(created_at) FROM payala_sync_batch`.

### 3.3 Handlers — `B/src/handlers/admin_reconciliation.rs` (4 `pub async fn`, no `AdminUser`)

`get_positions` (`GET /admin/reconciliation/positions?page&per_page`, `Privileged<ReadCustody>`), `create_snapshot` (`POST /admin/reconciliation/snapshots`, `Privileged<ManageCustody>`, kind `manual`, `created_by` = actor, iterates ALL custodial pages under the same budget as the job), `list_snapshots` (`GET /admin/reconciliation/snapshots?page&per_page`, `Privileged<ReadCustody>`, rows without `payload`: `{snapshot_id, snapshot_date, kind, as_of, horizon_fresh, complete, drift_detected, invariants_ok, attested: horizon_fresh && complete && invariants_ok, created_by}` — a lagging day lists as `attested:false`), `get_snapshot` (`GET /admin/reconciliation/snapshots/{id}`, `Privileged<ReadCustody>`, stored payload verbatim).

### 3.4 Daily job — decision: **required for T3; the endpoint alone does not suffice** (durable, attributable daily evidence)

`B/src/reconciliation/job.rs::run(deps, cancel)` spawned in `main.rs` background vec (always; reserve part reports `configured:false` when absent). Config (`config.rs`, `.env.example`): `RECONCILIATION_SNAPSHOT_UTC_HOUR` (default 0, 0..=23), `RECONCILIATION_MAX_ACCOUNTS` (default 10_000), `RECONCILIATION_DEADLINE_SECS` (default 600). Every 60 s: if `now.hour() >= utc_hour` and no `daily` row for today's UTC date (cheap `SELECT 1`), take `AdvisoryLock::new(RECONCILIATION_LOCK_KEY)` (skip pass if held), compute the full report (all custodial pages; exceeding either budget sets `complete=false`), then one transaction:
```sql
SNAPSHOT_INSERT_SQL = INSERT INTO reconciliation_snapshot
    (snapshot_date, kind, schema_version, as_of, horizon_head_closed_at, horizon_fresh, complete,
     drift_detected, invariants_ok, payload, created_by)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING RETURNING snapshot_id   -- 11 binds
```
0 rows ⇒ another instance won; stop. Else for every chain-legged bucket with `drift_ok=false` **and** `horizon_fresh=true`: `emit_event(ReserveDrift{account_id: reserve payala id, currency, ledger_total_minor, onchain_minor, drift_minor, tolerance_minor, snapshot_id})` ⇒ `reserve.drift`; always `emit_event(ReconciliationSnapshotRecorded{account_id: reserve id or "bridge", snapshot_id, kind, complete, drift_detected, invariants_ok, horizon_fresh})` ⇒ `reconciliation.snapshot_recorded`; COMMIT. A Horizon-lagging day is still recorded (`horizon_fresh=false`, `invariants_ok=false`, warning `horizon_lagging`) with drift alerts suppressed. Metrics after commit: `reconciliation_drift_minor{currency}` gauge, `reconciliation_snapshots{complete, invariants_ok}` counter. Pure `next_snapshot_due(last_daily: Option<NaiveDate>, now: DateTime<Utc>, utc_hour: u32) -> bool` tested at the day boundary and first run.

Surfaces: `impala-ui/html/js/reserve-math.js` gains `driftBadge(bucket)` (pure; Vitest `reserve-math.test.js`), `reserve.js` renders drift per bucket; `impalactl reconciliation positions [--page] [--json]`, `reconciliation snapshot run|list|show` (§10).

---

## 4. Replenishment driver hash persistence (PR3; the lead's payout/refund work is not redesigned)

### 4.1 Migration 037 — part D
```sql
-- 032:135-139 promised send_tx_hash is "captured BEFORE the submit"; the code
-- wrote it after settlement. The NULL-CAS below plus this partial unique make a
-- re-arm unable to overwrite a hash that may already have been submitted.
CREATE UNIQUE INDEX IF NOT EXISTS uq_crr_send_tx_hash
    ON conversion_reserve_replenishment(send_tx_hash) WHERE send_tx_hash IS NOT NULL;
```

### 4.2 Code (`B/src/exchange/reserve_watch.rs:385-446`, `replenish.rs:941-1033`)

Extend the lead's enum and function (make both `pub(crate)`):
```rust
pub(crate) enum IntentKey { Order(Uuid), Refund(Uuid), Cycle { cycle_id: Uuid, attempt_kind: &'static str } }
```
`IntentKey::Cycle` runs ONE transaction with two statements, each of which must affect exactly 1 row (else rollback + `Retryable("intent hash not recorded; not submitting")`):
```
CYCLE_ENTRY_HASH_SQL = UPDATE conversion_reserve_entry SET stellar_tx_hash = $2
                       WHERE cycle_id = $1 AND kind = $3 AND stellar_tx_hash IS NULL
CYCLE_ROW_HASH_SQL   = UPDATE conversion_reserve_replenishment SET send_tx_hash = $2
                       WHERE cycle_id = $1 AND state = 'sending' AND send_tx_hash IS NULL
```
(`uq_conversion_reserve_entry_cycle_kind` guarantees ≤ 1 journal row; `attempt_kind` is the value computed at `replenish.rs:957-961`.) In `submit_spend` replace lines 1011-1014 with the prepare → `record_intent_hash(&deps.pool, IntentKey::Cycle{..}, &prepared.stellar_hash)` → `submit_prepared` ladder used at `reserve_watch.rs:1468-1484`. The pre-submit `Retryable` classifies as a non-permanent `Rejected` and flows to the existing `abort_cycle(deps, c, "send_rejected")` branch — **never `requeue_cycle`** (its CAS is `WHERE state='creating'`, :1111-1116, and the cycle is already `sending`); `ABORT_CYCLE_SQL` covers `sending` (:369-371) and nothing was sent, so releasing the hold is safe. Use reason `"hash_unrecorded"` for that case (branch on the `Retryable` message? no — on `prepared.is_some() && hash_recorded == false` tracked in a local `let hash_armed: bool`). `record_spend_sent` (:1036) keeps writing `send_tx_hash = $2` (same value, idempotent).

`freeze_stale_cycles` (`replenish.rs:491`) gains hash resolution before freezing a `sending` cycle: `SELECT send_tx_hash, send_address, spend_currency, spend_minor FROM conversion_reserve_replenishment WHERE cycle_id=$1`; when `send_tx_hash IS NOT NULL` → `resolve_intent_by_hash(http, horizon, hash, reserve.stellar_address, send_address, spend_minor, Some(&asset))`: `Ok(Some(_))` → `record_spend_sent`; `Ok(None)` → `abort_cycle(.., "send_expired")`; `Err` (inconclusive/lagging) → freeze as today. `GET /admin/exchange-reserve/replenishment` (`admin_replenish::get_status`) exposes `send_tx_hash` per cycle (append-only).

Tests: `submit_spend_records_hash_before_submit` (in `replenish.rs` tests, `include_str!("replenish.rs")`: inside `fn submit_spend`, `prepare_payment(` < `record_intent_hash(` < `submit_prepared(`, and `sign_and_submit_payment(` absent from the file), `cycle_hash_sql_is_a_null_cas_on_both_rows` (both constants contain `IS NULL`; the row one contains `state = 'sending'`), `hash_unrecorded_aborts_rather_than_requeues` (pure branch test on the outcome mapper), `abort_covers_every_pre_send_state` (:1626) unchanged.

---

## 5. Machine-readable refusal codes — `B/src/error.rs`

```rust
/// A refusal whose code clients branch on. Unlike the other variants the code is
/// chosen by the handler, not derived from the variant.
Coded { status: StatusCode, code: &'static str, message: String, details: Option<serde_json::Value> },
```
`ErrorDetail` gains `#[serde(skip_serializing_if = "Option::is_none")] details: Option<Value>` (append-only). `into_response` handles `Coded` before the match (like `RateLimited`); `Display` prints `"{code}: {message}"`. Constructor helper `AppError::coded(status, code, message) -> Self` and `.with_details(Value)`. Tests: `coded_error_serializes_code_and_details`, `coded_error_without_details_omits_the_key`. The pure `Refusal → AppError` mapping in `custody/policy.rs` uses only codes from `CUSTODIAL_REFUSAL_CODES` (test `every_refusal_code_is_in_the_pinned_list`).

---

## 6. Transactional-outbox exceptions in `admin_keys.rs` (PR3)

`store::insert_version` (`B/src/keys/store.rs:451-605`) and `revoke_active` (:612-636) own their transactions; `store_and_audit` (`admin_keys.rs:552-577`) and `revoke_key` (:868-882) emit `BridgeKeyImported`/`BridgeKeyRevoked` in a second transaction. Fix — the store functions own the audit emission:

```rust
pub async fn insert_version(pool, protector, kind, parts, expected_active_fp, imported_by, note,
                            audit: &dyn Fn(i32) -> AccountEvent) -> Result<i32, AppError>
// inside the winning attempt, after the supersede-link UPDATE (:583-593) and BEFORE tx.commit() (:595):
crate::events::emit_event(&mut tx, &audit(next)).await?;

pub async fn revoke_active(pool, kind, expected_fp, audit: &dyn Fn(i32) -> AccountEvent) -> Result<i32, AppError>
// wrap the UPDATE ... RETURNING version in pool.begin(); None => rollback + the existing Conflict;
// Some(version) => emit_event(&mut tx, &audit(version)); tx.commit()
```
`store_and_audit` passes `&|version| AccountEvent::BridgeKeyImported { account_id: actor.to_string(), kind: kind.to_string(), version, set_fingerprint: set_fingerprint.clone(), replaced, action: action.to_string() }` (`set_fingerprint = parts.set_fingerprint(kind)` is computed before the call) and deletes lines 564-577; `revoke_key` likewise deletes 870-882. A losing attempt (`continue`) never reaches the emit. `scrub_expired` stays post-commit (retention, not an audited state change). `flush_unmatched_summaries` (`reserve_watch.rs:686`) stays post-commit by design (informational roll-up of already-committed rows) — documented in the spec.

Also (graft): `PayalaSyncBatchApplied { account_id, batch_id: String, sync_mode: String, item_count: i64, applied_count: i64, duplicate_count: i64, conflicting_count: i64 }` ⇒ `payala.sync_batch_applied`, emitted in `sync.rs` immediately before the commit at :542 (counts only: no amounts, memos, digests; test `sync_batch_payload_carries_counts_only`).

Tripwire `key_store_mutations_audit_in_the_same_transaction` (in `keys/store.rs` tests): `include_str!("../handlers/admin_keys.rs")` contains no `"audit begin"`; in `include_str!("store.rs")` `emit_event(&mut tx` occurs at least twice, and within the `fn insert_version` slice it occurs before `tx.commit()`. `credential_insert_columns_match_its_placeholders` (:796) untouched.

---

## 7. `docs/conservation-spec.md` (PR3)

Location `docs/conservation-spec.md` (repo root). Linked from `ARCHITECTURE.md` (new "Conservation" paragraph under `## System Overview` :68 and a row in `## Data Model` :664), `docs/runbooks/README.md` (new "I need to…" row "Reconcile positions or understand a money state machine → `../conservation-spec.md`"), `impala-bridge/SECURITY.md` (new `### Custody controls` after `### Payala Sync`). Pinned by `models.rs::conservation_spec_names_every_vocabulary` — `include_str!("../../docs/conservation-spec.md")` inside `#[cfg(test)]` (never compiled by `cargo build --release` in the Dockerfile, which copies only `src/` and `migrations/`; `cargo clippy --locked -- -D warnings` does not build test targets either) asserts every literal of `VALID_RESERVE_ENTRY_KINDS`, `VALID_CUSTODIAL_INTENT_STATUSES`, `VALID_CUSTODIAL_INTENT_RESOLUTIONS`, `VALID_REPLENISH_STATES`, `VALID_RESERVE_REFUND_STATUSES`, `VALID_EXCHANGE_STATUSES`, (038) `VALID_OFFLINE_ISSUANCE_STATES`, `VALID_OFFLINE_REDEMPTION_STATES`, every `AccountEvent::event_type()` string, and every test name in §7.6 appears verbatim. `.github/workflows/ci.yml:47-56` adds `'docs/conservation-spec.md'` to both path lists (load-bearing: a doc edit must run the pin).

Document structure (writer fills prose; every table row below is mandatory):

**§1 Scope and honesty statement** — S1–S6 verbatim from the flow map: chain is authoritative for Stellar; `conversion_reserve` is a mirror obligated to `available+held == on-chain` per chain-legged bucket (checked by §3); the Soroban wrapper is unobserved (`SOROBAN_CONTRACT_ID` informational); `payala_reserve`, mirror rows and `POST /transaction` are unverified assertions with no value; on-card `myBalance` is unbacked and mintable by any key until the card area ships issuer-key verification; **no transition crosses a domain boundary today, so cross-domain conservation is vacuously unenforced, not enforced**; after this design an offline unit is created only after a journaled hold and released on-chain only from a write-ahead intent naming a verified debit proof.

**§2 Domains, owners, units** — table of the seven balance owners from `managed_seed.rs:36` BALANCE OWNERSHIP TABLE; units: integer minor, 7 dp Stellar, 2 dp USD, `parse_decimal_to_minor`/`minor_to_decimal_string` the only boundary; card amount uint32 at card scale, converted by `card_to_bucket_minor` (§8.3).

**§3 As-is state machines** — one table per domain, columns *transition | owner | unique id | idempotency anchor | crash recovery | event | pinning test*, content from the flow map's AS-IS machine and these facts: custodial sign (today: no anchor, settle-then-record `managed_seed.rs:546-588`; after §1: prepared→submitted→settled|rejected|ambiguous, anchors `uq_custodial_intent_key`/`uq_custodial_intent_one_inflight`/`uq_custodial_intent_hash`, recovery = sweep by hash); reserve order (quote_hold|hold → awaiting_deposit → deposit(paging_token) → processing → payout_attempt(hash before submit) → completed | payout_retry ≤5 | on_hold → admin resolve ≥600 s chain-verified; expiry gated on Horizon head) with tests `hold_sql_guards_balance_and_fraction`, `due_payouts_sql_selects_only_claimable_auto_swaps`, `stale_intent_sql_only_covers_unrecorded_outcomes`, `expiry_sql_only_touches_awaiting_deposit`, `only_horizon_400_with_result_codes_is_definitive`, `presubmit_retryable_is_transient_rejection_not_ambiguous`, `late_deposit_after_expiry_is_recorded_not_credited_to_order`, `claim_sql_collapses_every_invalid_case_to_zero_rows`, `expiry_and_replay_sql_are_guarded`; refund obligation (needs_review|queued → inflight(CAS + write-ahead debit + 24 h cap, hash before submit) → sent | queued/failed(reversal) | frozen | cancelled) with `refund_sql_guards_every_transition`, `caps_park_for_review_and_dust_is_recorded_without_an_obligation`, `refunds_refuse_unsafe_destinations`, `refund_memo_can_never_be_mistaken_for_an_order_ref`, `usd_float_is_never_refunded_on_chain`; replenishment cycle (planned(uq_crr_inflight) → creating → created → sending(replenish_attempt + send_tx_hash before submit, §4) → sent → settled|in_transit → completed|refunded|failed|frozen) with `cycle_sql_guards_every_transition`, `abort_covers_every_pre_send_state`, `unconfigured_caps_refuse_rather_than_meaning_unlimited`, `an_unreadable_chain_skips_rather_than_spends`, `float_guard_reads_the_lower_of_ledger_and_chain`, `only_owlpay_creates_are_safe_to_retry_when_ambiguous`, `submit_spend_records_hash_before_submit`; payala sync (PK gate → applied|duplicate|conflicting; no chain effect) with `test_validate_batch_*`, `test_aggregate_overflow_is_error`, `test_valid_sync_modes_match_ddl`; outbox (emit in-tx → fan_out UNIQUE(webhook_id,event_id) → leased delivery) with `claim_leases_under_skip_locked_and_keeps_rows_pending`, `outcome_marks_are_guarded_against_late_duplicates`, `prune_touches_only_terminal_deliveries_and_pending_free_dispatched_events`; Soroban (wrap/schedule/execute/cancel — unobserved); card (SIGN_TRANSFER debit with no persisted sender counter; VERIFY_TRANSFER credit from any key, counter > last — `AppletInteropTest.kt` only).

**§4 Invariants the bridge enforces today** — (4.1) `available+held` replays from the journal; (4.2) chain ≥ ledger per chain-legged bucket (checked by §3 positions; before this design only visible as strings); (4.3) **XLM caveat**: network fees are not journaled, so the XLM bucket reads high by the cumulative fee sum — `drift_tolerance_minor` bounds it; a `fee` journal kind is a recommended follow-up; (4.4) one payout per order; one credit per paging_token; one obligation per payment; cursor monotonic; ambiguous submits never resubmitted; reserve seed generate-only and quarantined; no plaintext seed at rest; (4.5) **quarantine**: nothing that signs reads `payala_reserve`, `transaction.payala_amount` or `payala_sync_*` — tripwire `signing_paths_never_read_payala_tables` (`include_str!` of `managed_seed.rs`, `reserve_watch.rs`, `replenish.rs`, `admin_reserve.rs`, `custody/intent.rs`, `custody/sweep.rs`, `offline/redemption.rs` contains none of those identifiers); (4.6) after §1: one signed custodial envelope per intent, no submit without a persisted hash, per-account daily spend bounded; (4.7) after §8: `held_offline(currency) == Σ_cards(issued − written_off) − Σ(paid|cancelled redemptions)` (§8.5).

**§5 Target state machine mapped to components** (columns: transition | component(s) | status before → after | primitive | what closes it):

| Transition | Component | Status |
|---|---|---|
| ONCHAIN_AVAILABLE → RESERVED_FOR_OFFLINE_ISSUANCE | owner custodial sign to the reserve (memo = issuance ref) → deposit watcher → `issuance_deposit` + `issuance_hold` (§8.4) | absent → **exists** |
| RESERVED → OFFLINE_SPENDABLE | bridge issuer key signs the 60-byte signable with a bridge-allocated counter; `issued` committed before bytes leave (§8.4); card-side VERIFY_TRANSFER with pinned program key (card area) | absent → **partial** (bridge half exists; card half is the card area's personalization/cert work) |
| OFFLINE_SPENDABLE → OFFLINE_TRANSFERRED_UNRECONCILED | card SIGN_TRANSFER/VERIFY_TRANSFER; no coordinator | partial (unchanged) |
| OFFLINE_TRANSFERRED → RECONCILED_OFFLINE_BALANCE | `POST /sync/payala` (unverified) | partial, quarantined (unchanged; out of scope until the Payala contract exists) |
| RECONCILED → PENDING_ONCHAIN_RELEASE | `POST /offline/redemptions` verifying the card's SIGN_TRANSFER tuple + certificate, per-card bound, `redemption_attempt` + custodial intent (origin `redemption`) (§8.6) | absent → **exists for a card's own bridge-issued value** |
| PENDING_ONCHAIN_RELEASE → ONCHAIN_AVAILABLE | reserve watcher `drive_redemptions` → prepare/hash/submit/classify → `redemption_paid` + transaction row; sweep/admin resolve | partial (reserve-only primitive) → **exists** |

**§6 Failure-injection matrix** — every reviewer scenario → pinning test(s) or `no test` with owner:

| Scenario | Today | After this design |
|---|---|---|
| Duplicate bridge requests (custodial) | no test | `replay_decision_table`, `same_key_different_fingerprint_is_conflict`, `arm_sql_requires_prepared_and_null_hash`, `one_inflight_index_is_partial_on_sign_origin`; impalactl `TestTransferSendReusesKeyOnRetry`; DB lane `uq_custodial_intent_key_rejects_second_insert` |
| Duplicate requests (reserve admin) | `claim_sql_collapses_every_invalid_case_to_zero_rows`, `refund_sql_guards_every_transition` | + `custody_admin_mutations_are_guarded_single_statements` |
| Repeated Stellar events | `expiry_and_replay_sql_are_guarded`, `late_deposit_after_expiry_is_recorded_not_credited_to_order`, `unmatched_insert_records_the_payer`, `stale_intent_sql_only_covers_unrecorded_outcomes` | + `sweep_verdict_table` (a replayed Horizon page cannot settle an intent twice: CAS on status+hash), `issuance_arrival_is_anchored_by_paging_token` |
| Crash between debit and settlement | `stale_intent_sql_only_covers_unrecorded_outcomes`, `refund_sql_guards_every_transition`, `cycle_sql_guards_every_transition`, `abort_covers_every_pre_send_state`, `only_horizon_400_with_result_codes_is_definitive` | + `abandon_sql_never_touches_armed_rows`, `stale_sql_selects_only_armed_open_rows`, `claimed_without_hash_is_provably_unsubmitted` (order tripwire), `submit_spend_records_hash_before_submit`, `funded_issuance_never_signs_before_its_hold_commits` |
| Queue redelivery (SQS) | `active_job_guard_releases_on_panic`, `active_job_guard_releases_exactly_once_on_normal_drop` (jobs move no money) | unchanged; the spec states money never rides SQS |
| Database rollback | no test (no DB in `cargo test`) | DB lane (§7.7): `settle_tx_is_atomic_when_intent_cas_fails`, `journal_insert_conflict_rolls_back_bucket_apply`, `abandon_sweep_rejects_only_hashless_rows` |
| Redis outage | `valid_bearer_fails_closed_when_redis_unreachable`, `session_cookie_fails_closed_when_redis_unreachable`, `test_none_protector_fails_closed` | + `pause_path_never_touches_redis` (tripwire) |
| Network partition (Horizon) | `an_unreadable_chain_skips_rather_than_spends`, `head_freshness_boundary`, `scan_page_crosses_floor_proves_absence`, `scan_page_missing_created_at_never_stops_short`, `presubmit_retryable_is_transient_rejection_not_ambiguous` | + `ambiguous_maps_to_202_and_is_never_resubmitted`, `stale_head_is_inconclusive`, `unreadable_chain_yields_null_not_ok` |
| Delayed card synchronization | no test | `redemption_rejects_stale_datetime` (bridge-enforced expiry); remainder out of scope (Payala contract) |
| Conflicting card/backend balances | no test | `redemption_refused_when_exceeding_card_outstanding` (per-card bound) and `redemption_refused_when_exceeding_aggregate_outstanding`; netting out of scope |
| Partial withdrawal | no test | `partial_redemptions_reduce_outstanding_exactly` (position CAS pin), `redemption_amount_is_exactly_the_signed_debit` |
| Bridge signer compromise | no test | `resume_refuses_while_ambiguous_intents_exist`, `pause_precedes_seed_load` (tripwire), `issuer_key_is_generate_only` (no import route; tripwire on `admin_card_issuer.rs`), `override_zero_freezes_the_account`; runbook: pause → per-account 0 → rotate seeds via `/admin/stellar-seeds/generate`; HSM custody out of scope (`prepare_payment/submit_prepared` is the replacement seam) |
| Reserve shortfall | `hold_sql_guards_balance_and_fraction`, `bucket_apply_sql_guards_both_columns`, `unconfigured_caps_refuse_rather_than_meaning_unlimited`, `each_guard_fires_on_its_own`, `float_guard_reads_the_lower_of_ledger_and_chain`, `spend_ceiling_is_the_tightest_of_every_bound`, `low_water_breach_flag` | + `drift_is_onchain_minus_ledger`, `tolerance_boundary_inclusive`, `positions_invariants_flag_uncovered_obligations`, `issuance_hold_uses_bucket_apply_not_the_fraction_guard` |

**§7 Controls inventory** (every cap, switch, rate limit, lock, role, with table/column and endpoint — including the explicit statement that `custodial_policy.paused` does NOT gate reserve payouts/refunds/replenishment, and that custodial caps are XLM-stroop caps on user payments while redemptions are bounded by the offline policy caps + per-card bound). **§8 Reconciliation procedure** (positions, daily snapshot, `reserve.drift` triage, `adjustment`/`held_adjustment` booking, exception queues: `custody/intents?status=ambiguous`, `offline/redemptions?state=failed`, reserve `on_hold`/`frozen`). **§9 Open gaps with owners** (card personalization/cert — impala-card; Payala contract — external; Soroban participation — decision; HSM — bridge; fee journaling — bridge; stablecoin-denominated cards — bridge; DB-executing suite growth — bridge).

### 7.7 Opt-in DB lane (graft)

`B/tests/db/mod.rs` + `B/tests/db/*.rs`: `#[ignore]` integration tests that connect to `DATABASE_URL` only when `RUN_DB_TESTS=1`, apply `sqlx::migrate!("./migrations")` into a fresh schema per test (`CREATE SCHEMA` + `search_path`), and prove: `uq_custodial_intent_key_rejects_second_insert`, `uq_custodial_intent_hash_rejects_second_arm`, `one_inflight_index_admits_one_live_sign_intent`, `arm_cas_loses_to_abandon_sweep`, `settle_tx_is_atomic_when_intent_cas_fails`, `journal_insert_conflict_rolls_back_bucket_apply`, `reconciliation_snapshot_daily_anchor_admits_one_row_per_date`, (PR4) `uq_custodial_intent_redemption_live_admits_one_live_release`, `card_position_cas_bounds_redemption_to_outstanding`, `journal_replays_buckets_after_issue_and_redeem`. New CI job `bridge-db-tests` in `ci.yml` with a `postgres:16` service, running `cargo test --locked --test db -- --ignored` with `RUN_DB_TESTS=1`. Default `cargo test` stays DB-free.

---

## 8. Offline issuance and redemption (PR4, migration 038) — DECISION

**Build the bridge half now, user-funded, XLM-denominated pilot, safe without the Payala backend.** In scope: (a) generate-only issuer key custody; (b) bridge-signed card certificates; (c) an issuance that is funded on-chain first (the owner pays XLM from their custodial account to the reserve address with the issuance ref as memo, through the §1 idempotent sign path) and whose signed card credit is released only after `issued` is committed; (d) redemption of a card's own bridge-issued value against a verified SIGN_TRANSFER tuple naming the deployment's redemption identity, deduped on `(card_id, counter)` and on the signable hash, bounded per card AND per currency, paid to the owner's custodial address through a `custodial_payment_intent(origin='redemption')` driven by the reserve watcher. Properties that hold alone: no card credit without a prior committed hold; a released signable is a liability until a chain-settled payout or a loud, admin-only write-off; no redemption without a verified debit proof and a unique anchor; `held` covers every outstanding offline liability (§8.5 invariant).

### 8.1 Migration `B/migrations/038_offline_issuance.sql`

```sql
-- 038: offline issuance/redemption. Inert until an issuer key is generated,
-- offline_policy is enabled and configured, and a card is certified.
CREATE TABLE IF NOT EXISTS card_issuer_key (
    version            INTEGER PRIMARY KEY CHECK (version > 0),
    state              VARCHAR(16) NOT NULL,
    backend            VARCHAR(16) NOT NULL,
    ciphertext         BYTEA, wrapped_data_key BYTEA, nonce BYTEA,   -- sealed PKCS#8 P-256 key (SeedProtector envelope)
    key_id             VARCHAR(256), key_version VARCHAR(32),
    public_key_hex     CHAR(130) NOT NULL,                            -- uncompressed SEC1, non-secret
    fingerprint        VARCHAR(64) NOT NULL,                           -- keys::fingerprint("card_issuer","public_key",point)
    generated_by       VARCHAR(64) NOT NULL,
    generated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    superseded_at      TIMESTAMP WITH TIME ZONE, scrubbed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_cik_state CHECK (state IN ('active', 'superseded', 'revoked')),
    CONSTRAINT chk_cik_active_has_material CHECK (state <> 'active' OR ciphertext IS NOT NULL),
    CONSTRAINT chk_cik_scrub_is_total CHECK (scrubbed_at IS NULL
        OR (ciphertext IS NULL AND wrapped_data_key IS NULL AND nonce IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_card_issuer_key_single_active
    ON card_issuer_key((true)) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS offline_policy (
    id                          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    enabled                     BOOLEAN NOT NULL DEFAULT false,
    -- Per-deployment identity a card names as `recipient` when it signs a
    -- redemption. Minted once by the first issuer-key generation; stable across
    -- key rotations; NULL = unconfigured -> refuse. Never a code constant.
    redemption_uuid             UUID,
    -- Caps in BUCKET minor units (7dp), evaluated per currency. 0 = unconfigured -> refuse.
    issue_per_tx_max_minor      BIGINT NOT NULL DEFAULT 0 CHECK (issue_per_tx_max_minor >= 0),
    issue_daily_max_minor       BIGINT NOT NULL DEFAULT 0 CHECK (issue_daily_max_minor >= 0),
    outstanding_max_minor       BIGINT NOT NULL DEFAULT 0 CHECK (outstanding_max_minor >= 0),
    redeem_per_tx_max_minor     BIGINT NOT NULL DEFAULT 0 CHECK (redeem_per_tx_max_minor >= 0),
    redeem_daily_max_minor      BIGINT NOT NULL DEFAULT 0 CHECK (redeem_daily_max_minor >= 0),
    -- Bound on any client-supplied counter jump (issue observed counter, redemption counter).
    counter_max_jump            INTEGER NOT NULL DEFAULT 1024 CHECK (counter_max_jump BETWEEN 1 AND 16777216),
    updated_by                  VARCHAR(64),
    created_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO offline_policy (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- Certification columns. card_id is unique only among active rows (021), so
-- offline tables reference it by value with is_delete = FALSE lookups.
ALTER TABLE card
    ADD COLUMN IF NOT EXISTS currency            VARCHAR(12) REFERENCES conversion_reserve(currency),
    ADD COLUMN IF NOT EXISTS card_minor_scale    SMALLINT CHECK (card_minor_scale BETWEEN 0 AND 7),
    ADD COLUMN IF NOT EXISTS issuer_cert_hex     VARCHAR(144),   -- DER ECDSA <= 72 bytes
    ADD COLUMN IF NOT EXISTS cert_issuer_version INTEGER REFERENCES card_issuer_key(version),
    ADD COLUMN IF NOT EXISTS certified_at        TIMESTAMP WITH TIME ZONE;

-- Per-card liability ledger + the bridge-side counters the card lacks.
CREATE TABLE IF NOT EXISTS card_offline_position (
    card_id               VARCHAR(128) PRIMARY KEY,
    currency              VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    issued_minor          BIGINT NOT NULL DEFAULT 0 CHECK (issued_minor >= 0),
    redeemed_minor        BIGINT NOT NULL DEFAULT 0 CHECK (redeemed_minor >= 0),
    written_off_minor     BIGINT NOT NULL DEFAULT 0 CHECK (written_off_minor >= 0),
    last_issued_counter   INTEGER NOT NULL DEFAULT 0 CHECK (last_issued_counter >= 0),
    last_redeemed_counter INTEGER NOT NULL DEFAULT 0 CHECK (last_redeemed_counter >= 0),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_cop_outstanding CHECK (issued_minor - redeemed_minor - written_off_minor >= 0)
);

CREATE TABLE IF NOT EXISTS offline_issuance (
    issuance_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuance_ref         VARCHAR(28) NOT NULL UNIQUE,      -- 'IS' || 24 Crockford chars: the funding memo
    payala_account_id    VARCHAR(64) NOT NULL,              -- owner; no FK (audit trail), delete_account guards
    card_id              VARCHAR(128) NOT NULL,
    card_account_uuid    UUID NOT NULL,
    currency             VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    card_minor_scale     SMALLINT NOT NULL CHECK (card_minor_scale BETWEEN 0 AND 7),
    card_amount          BIGINT NOT NULL CHECK (card_amount BETWEEN 1 AND 4294967295),   -- uint32 at card scale
    amount_minor         BIGINT NOT NULL CHECK (amount_minor > 0),                        -- bucket minor
    funding_source       VARCHAR(56) NOT NULL,              -- the owner's custodial G-address
    funding_paging_token VARCHAR(64),
    funding_tx_hash      VARCHAR(64),
    funded_minor         BIGINT,                            -- ACTUAL amount received
    counter              INTEGER CHECK (counter IS NULL OR counter BETWEEN 1 AND 2147483647),
    issuer_version       INTEGER REFERENCES card_issuer_key(version),
    format_version       SMALLINT NOT NULL DEFAULT 1,
    signable             BYTEA CHECK (signable IS NULL OR octet_length(signable) = 60),
    signature_der        BYTEA CHECK (signature_der IS NULL OR octet_length(signature_der) BETWEEN 8 AND 72),
    state                VARCHAR(16) NOT NULL DEFAULT 'awaiting_funds',
    reason               VARCHAR(32),
    ack_status_word      CHAR(4),
    resolved_by          VARCHAR(64),
    expires_at           TIMESTAMP WITH TIME ZONE NOT NULL,   -- funding window (reserve deposit_ttl_secs)
    issued_at            TIMESTAMP WITH TIME ZONE, acked_at TIMESTAMP WITH TIME ZONE, resolved_at TIMESTAMP WITH TIME ZONE,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_oi_state CHECK (state IN
        ('awaiting_funds', 'funded', 'issued', 'acked', 'expired', 'reversed')),
    CONSTRAINT chk_oi_issued_has_material CHECK (state NOT IN ('issued', 'acked')
        OR (counter IS NOT NULL AND signable IS NOT NULL AND signature_der IS NOT NULL AND issuer_version IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_offline_issuance_card_counter
    ON offline_issuance(card_id, counter) WHERE counter IS NOT NULL;
-- One issuance being funded per card at a time (issued credits may accumulate).
CREATE UNIQUE INDEX IF NOT EXISTS uq_offline_issuance_one_open_per_card
    ON offline_issuance(card_id) WHERE state IN ('awaiting_funds', 'funded');
CREATE INDEX IF NOT EXISTS idx_offline_issuance_open ON offline_issuance(expires_at) WHERE state = 'awaiting_funds';
CREATE INDEX IF NOT EXISTS idx_offline_issuance_card ON offline_issuance(card_id, state);

CREATE TABLE IF NOT EXISTS offline_redemption (
    redemption_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    redemption_ref       VARCHAR(28) NOT NULL UNIQUE,      -- 'OR' || 8 Crockford chars: the payout memo
    payala_account_id    VARCHAR(64) NOT NULL,              -- card owner = payee; no FK
    card_id              VARCHAR(128) NOT NULL,
    card_account_uuid    UUID NOT NULL,
    currency             VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    card_amount          BIGINT NOT NULL CHECK (card_amount BETWEEN 1 AND 4294967295),
    amount_minor         BIGINT NOT NULL CHECK (amount_minor > 0),
    sender_counter       INTEGER NOT NULL CHECK (sender_counter > 0),
    format_version       SMALLINT NOT NULL DEFAULT 1,
    signable             BYTEA NOT NULL CHECK (octet_length(signable) = 60),
    signable_hash        CHAR(64) NOT NULL UNIQUE,          -- sha256 hex: second dedupe anchor
    signature_der        BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 72),
    card_pubkey_hex      CHAR(130) NOT NULL,
    cert_issuer_version  INTEGER NOT NULL REFERENCES card_issuer_key(version),
    signed_at            TIMESTAMP WITH TIME ZONE NOT NULL, -- signable.dateTime
    destination          VARCHAR(56) NOT NULL,              -- owner's managed_seed.stellar_account_id
    intent_id            UUID REFERENCES custodial_payment_intent(intent_id) ON DELETE SET NULL,
    attempts             INTEGER NOT NULL DEFAULT 0,
    state                VARCHAR(16) NOT NULL DEFAULT 'accepted',
    reason               VARCHAR(200),
    resolved_by          VARCHAR(64),
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at          TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_offline_redemption_card_counter UNIQUE (card_id, sender_counter),
    CONSTRAINT chk_or_state CHECK (state IN ('accepted', 'paying', 'frozen', 'paid', 'failed', 'cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_offline_redemption_due ON offline_redemption(created_at) WHERE state = 'accepted';

-- Exception-procedure audit rows (card-level write-off; the amount is released
-- through the position CAS, so this row is the record, not the anchor).
CREATE TABLE IF NOT EXISTS offline_writeoff (
    writeoff_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    card_id              VARCHAR(128) NOT NULL,
    currency             VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    amount_minor         BIGINT NOT NULL CHECK (amount_minor > 0),
    outstanding_before   BIGINT NOT NULL,
    reason               VARCHAR(200) NOT NULL,
    admin_account_id     VARCHAR(64) NOT NULL,
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One live on-chain release per redemption, ever (DB-enforced "never paid twice").
ALTER TABLE custodial_payment_intent
    ADD CONSTRAINT fk_custodial_intent_redemption FOREIGN KEY (redemption_id)
        REFERENCES offline_redemption(redemption_id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_custodial_intent_redemption_live
    ON custodial_payment_intent(redemption_id) WHERE redemption_id IS NOT NULL AND status <> 'rejected';

-- Journal linkage (031/032 twins) + kinds.
ALTER TABLE conversion_reserve_entry
    ADD COLUMN IF NOT EXISTS issuance_id   UUID REFERENCES offline_issuance(issuance_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS redemption_id UUID REFERENCES offline_redemption(redemption_id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_issuance_kind
    ON conversion_reserve_entry(issuance_id, kind) WHERE issuance_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_redemption_kind
    ON conversion_reserve_entry(redemption_id, kind) WHERE redemption_id IS NOT NULL;
-- Kinds (delta / held_delta):
--   issuance_deposit    funding arrived (ACTUAL amount, paging_token anchor): available +a
--   issuance_hold       liability created:                                    available -x, held +x
--   issuance_release    funded-but-never-issued reversal:                     available +x, held -x
--   redemption_attempt  write-ahead before the payout submit:                 0 / 0
--   redemption_paid     payout settled (stellar_tx_hash):                     0 / -x
--   offline_writeoff    liability extinguished WITHOUT chain proof (admin):   available +x, held -x
ALTER TABLE conversion_reserve_entry DROP CONSTRAINT chk_conversion_reserve_entry_kind;
ALTER TABLE conversion_reserve_entry ADD CONSTRAINT chk_conversion_reserve_entry_kind
    CHECK (kind IN ( /* the 30 literals of 032:343-352 in that order */ ...,
                    'issuance_deposit', 'issuance_hold', 'issuance_release',
                    'redemption_attempt', 'redemption_paid', 'offline_writeoff'))
    NOT VALID;
ALTER TABLE conversion_reserve_entry VALIDATE CONSTRAINT chk_conversion_reserve_entry_kind;

CREATE TRIGGER update_offline_policy_updated_at BEFORE UPDATE ON offline_policy FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_card_offline_position_updated_at BEFORE UPDATE ON card_offline_position FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_offline_issuance_updated_at BEFORE UPDATE ON offline_issuance FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_offline_redemption_updated_at BEFORE UPDATE ON offline_redemption FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

Rust mirrors: `VALID_RESERVE_ENTRY_KINDS` appends the six kinds (36 total, all ≤ 24 chars; `test_reserve_entry_kinds_match_ddl` list extended in DDL order, `test_reserve_entry_kinds_fit_the_column` unchanged); new `RESERVE_OFFLINE_ENTRY_KINDS` (the six) excluded from utilization/forecast aggregates like `RESERVE_INTERNAL_ENTRY_KINDS` (test `offline_kinds_are_excluded_from_utilization`; they are customer stored-value flow, not swap demand); `JournalEntry` gains `issuance_id: Option<Uuid>, redemption_id: Option<Uuid>` **appended last**, `RESERVE_ENTRY_INSERT_SQL` grows 17 → 19 columns with `$18, $19` last (`entry_insert_covers_all_journal_columns` :1717 extended to the 19 names and asserts the placeholder list ends `$18, $19`); `VALID_OFFLINE_ISSUANCE_STATES`, `VALID_OFFLINE_REDEMPTION_STATES`, `VALID_CARD_ISSUER_STATES` + `models.rs` drift twins; `ISSUER_KEY_HEADER_MAGIC = "impala-issuer-v1"` (drift test: the three magics are pairwise distinct and `-v1`-suffixed); `ISSUANCE_MEMO_PREFIX = "IS"`, `REDEMPTION_MEMO_PREFIX = "OR"` with const asserts `"IS".len()+24 <= 28`, `"OR".len()+8 <= 28` and test `issuance_ref_and_memo_prefixes_are_disjoint` (`I` and `O` are not in the Crockford alphabet `reserve.rs:735`, so neither memo can equal a 26-char order ref; both differ from `RESERVE_REFUND_MEMO_PREFIX`; `find_onchain_payout` can never read one as an order payout); `CARD_CERT_DOMAIN_PREFIX: &[u8; 12] = b"IMPALA-CERT:"`; `CARD_CURRENCY_TAGS: &[(&str, [u8; 4])] = &[("XLM", *b"XLM\0"), ("USDC", *b"USDC"), ("USDT0", *b"UST0")]` (explicit table, no truncation ambiguity; pinned); `REDEMPTION_MAX_AGE_SECS = 7 * 86_400`, `REDEMPTION_MAX_FUTURE_SKEW_SECS = 300`, `OFFLINE_SIGNABLE_LEN = 60`, `RESERVE_MAX_REDEMPTION_ATTEMPTS = 5`, `OFFLINE_RATE_LIMIT_SCOPE_ISSUE = "issuance"`, `OFFLINE_RATE_LIMIT_SCOPE_REDEEM = "redeem"` (5/60 s).

### 8.2 Issuer key custody — `B/src/offline/issuer.rs`, handlers `B/src/handlers/admin_card_issuer.rs` (3 `pub async fn`) + public `B/src/handlers/card_issuer.rs` (1)

| Handler | Route | Extractor | Behaviour |
|---|---|---|---|
| `generate_issuer_key` | `POST /admin/card-issuer/generate` `{confirm_supersede?: fingerprint, confirm_phrase?}` | `Privileged<ManageKeys>` | requires `KEY_IMPORT_ENABLED` (`admin_keys::require_enabled` precedent) and a real protector backend; `aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())` (aws-lc-rs is a normal dependency, `Cargo.toml:50`); plaintext = `format!("{}\n{}\n", ISSUER_KEY_HEADER_MAGIC, version)` ‖ PKCS#8 DER in `Zeroizing<Vec<u8>>`; `protector.encrypt_seed(&plaintext)`; version = `MAX+1` predicted then arbitrated by the PK like `store::insert_version:467-480`; one tx: if an active row exists, `confirm_supersede` must equal its fingerprint (`tokens_match`) and `confirm_phrase == "replace card-issuer {network}"`, else 409; `UPDATE card_issuer_key SET state='superseded', superseded_at=now WHERE state='active'`; `ISSUER_INSERT_SQL = INSERT INTO card_issuer_key (version, state, backend, ciphertext, wrapped_data_key, nonce, key_id, key_version, public_key_hex, fingerprint, generated_by) VALUES ($1, 'active', $2, $3, $4, $5, $6, $7, $8, $9, $10)` (**10 binds**, one literal — pinned exactly like `credential_insert_columns_match_its_placeholders`); `UPDATE offline_policy SET redemption_uuid = COALESCE(redemption_uuid, gen_random_uuid()) WHERE id RETURNING redemption_uuid`; `emit_event(CardIssuerKeyGenerated{version, fingerprint, replaced})`; commit. Response `{version, public_key_hex, fingerprint, redemption_uuid, note: "rotation requires re-installing the program key on cards and re-certifying them"}`. **There is no import endpoint** (generate-only; tripwire `issuer_key_is_generate_only` asserts `admin_card_issuer.rs` contains no `import` route/handler and `main.rs` mounts none under `/admin/card-issuer/`). Rate scope `KEY_IMPORT_RATE_LIMIT_SCOPE`. |
| `list_issuer_keys` | `GET /admin/card-issuer` | `Privileged<ReadKeys>` | every version: `{version, state, public_key_hex, fingerprint, generated_by, generated_at, superseded_at}` + `redemption_uuid` |
| `certify_card` | `POST /admin/cards/{card_id}/certificate` `{currency, card_minor_scale, recertify?: bool}` | `Privileged<ManageKeys>` | active card row (`is_delete=false`); `account_id` parses as UUID (409 otherwise — the certificate binds the UUID the card signs with, `card_auth.rs:282-291`); `currency` must be XLM or a configured stablecoin (`reserve.asset_for_bucket(..).is_some()`); message = `CARD_CERT_DOMAIN_PREFIX(12) || account_uuid(16) || currency_tag(4) || card_pubkey(65)` (97 bytes); sign with the active issuer key; `CERTIFY_SQL = UPDATE card SET issuer_cert_hex=$2, cert_issuer_version=$3, currency=$4, card_minor_scale=$5, certified_at=CURRENT_TIMESTAMP WHERE card_id=$1 AND is_delete = FALSE AND (issuer_cert_hex IS NULL OR $6)` (write-once unless `recertify`); `emit_event(CardCertified{card_id, issuer_version, replaced})`; response `{card_id, issuer_version, issuer_cert_hex, cert_message_hex, issuer_public_key_hex, currency, card_minor_scale}` so the terminal can install it (card area contract). |
| `get_card_issuer` (public, unauthenticated, `card_issuer.rs`) | `GET /card-issuer` | none | `{version, public_key_hex, fingerprint, redemption_uuid} | {configured:false}` — the program key and redemption identity terminals pin offline (public data only; kept out of `/network` so its tests stay untouched) |

`offline::issuer::load_issuer_key(pool, protector, version: Option<i32>) -> Result<(IssuerKey, i32, Vec<u8> /*pubkey*/), AppError>`: loads the requested (or active) row, backend match (`load_protected_seed:351-363` twin), decrypt, verify header `magic|version` (fixed error strings, never echoes bytes), `EcdsaKeyPair::from_pkcs8`, assert derived public point == `public_key_hex` (the transplant defence, `managed_seed.rs:389-400` twin), returns a zeroizing wrapper; `IssuerKey::sign(&self, msg) -> Vec<u8>` (DER). `Debug` redacted. `verify_under_version(pool, version, msg, sig)` uses `public_key_hex` only (no decrypt) for `active`/`superseded` rows, never `revoked`.

Cross-stack golden vectors (graft): `B/src/offline/signable.rs` tests embed literal hex for (a) a fixed `Signable` → 120-hex encoding, (b) the 97-byte certificate message for fixed uuid/currency/pubkey, (c) a 209-byte VERIFY_TRANSFER tail; the same literals are embedded in `impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/AppletInteropTest.kt`; `scripts/check-shared-vectors.sh` greps both files for each literal and runs in both `ci.yml` (bridge job) and `impala-card.yml`. The card area's implementation MUST verify these exact bytes; a divergence fails CI by construction.

### 8.3 Pure helpers (`B/src/offline/{signable.rs, convert.rs}`)

```rust
pub(crate) struct Signable { date_time_ms: i64, sender: Uuid, recipient: Uuid, currency: [u8; 4], amount: u32, phone_id: i64, counter: i32 }
pub(crate) fn encode(&self) -> [u8; 60]   // BE: dateTime@0(8) | sender@8(16) | recipient@24(16) | currency@40(4) | amount@44(4) | phoneId@48(8) | counter@56(4) — TransactionParser.java:18-24
pub(crate) fn decode(bytes: &[u8]) -> Result<Signable, SignableError>   // exactly 60 bytes; counter > 0
pub(crate) fn signable_hash_hex(bytes: &[u8; 60]) -> String            // sha256
pub(crate) fn currency_tag(bucket: &str) -> Option<[u8; 4]>            // CARD_CURRENCY_TAGS lookup
pub(crate) fn card_cert_message(account: &Uuid, tag: [u8;4], card_pubkey: &[u8]) -> Vec<u8>   // 97 bytes
pub(crate) fn card_to_bucket_minor(card_amount: u32, card_scale: u8, bucket_scale: u8) -> Option<i64>  // card_amount * 10^(bucket_scale - card_scale), checked; None when card_scale > bucket_scale
pub(crate) fn pad72(der: &[u8]) -> [u8; 72]                               // right-padded zeros (SDK pad72)
pub(crate) fn verify_p256(pubkey65: &[u8], msg: &[u8], der: &[u8]) -> bool // ECDSA_P256_SHA256_ASN1; 65-byte 0x04 point; DER 8..=72 (card_auth.rs:61-84 shape)
```
Tests: `signable_layout_golden`, `decode_rejects_wrong_length_and_nonpositive_counter`, `amount_is_uint32_big_endian`, `currency_tags_are_pinned`, `card_cert_message_golden`, `conversion_is_exact_and_checked` (`card_scale > bucket_scale` → None; overflow → None), `tail_layout_is_72_65_72`.

### 8.4 Issuance flow — owner endpoints in `B/src/handlers/offline.rs`, ledger in `B/src/offline/issuance.rs`

All owner endpoints: `AuthenticatedUser` + `require_owner` first, `require_not_reserve_account`, rate limit scope `issuance` (5/60 s), reserve `Option<Extension<Arc<ConversionReserve>>>` None → 400 "Conversion reserve is not configured" (exchange-handler precedent).

**Create** — `POST /offline/issuances` `{payala_account_id, card_id, card_amount: u32, observed_receive_counter?: i32}`:
1. `OFFLINE_POLICY_READ_SQL` (`FOR SHARE`, fetch_one): `enabled`, `redemption_uuid IS NOT NULL`, `issue_per_tx_max_minor > 0`, `issue_daily_max_minor > 0`, `outstanding_max_minor > 0`, an `active` issuer key — any miss → 503 `Coded("offline_unconfigured", names the field)`; `custodial_policy.paused` → 503 `custodial_paused`.
2. Card: active row owned by `payala_account_id`, `issuer_cert_hex IS NOT NULL`, its `cert_issuer_version` row is `active` (a superseded issuer refuses new issuance — recertify first), `currency`/`card_minor_scale` set; `card_account_uuid = Uuid::parse_str(card.account_id)`; `amount_minor = card_to_bucket_minor(card_amount, card_minor_scale, bucket.minor_scale)` else 400; `funding_source = managed_seed.stellar_account_id` for the owner (404 if none).
3. One tx under `pg_advisory_xact_lock(hashtext('offline_card:' || card_id))`: caps (pure `check_issue_caps(policy, amount_minor, issued_today, outstanding_currency)` with `ISSUED_TODAY_SQL = SELECT COALESCE(SUM(amount_minor),0) FROM offline_issuance WHERE currency=$1 AND state NOT IN ('expired','reversed') AND created_at >= CURRENT_TIMESTAMP - interval '24 hours'` and `OUTSTANDING_CURRENCY_SQL = SELECT COALESCE(SUM(issued_minor - redeemed_minor - written_off_minor),0) FROM card_offline_position WHERE currency=$1`) → 409 `offline_issue_limit`/`offline_exposure_limit`; `issuance_ref = "IS" + base32_order_ref(&issuance_id)[2..]`; `ISSUANCE_INSERT_SQL = INSERT INTO offline_issuance (issuance_id, issuance_ref, payala_account_id, card_id, card_account_uuid, currency, card_minor_scale, card_amount, amount_minor, funding_source, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)` (**11 binds**; `expires_at = now + reserve.deposit_ttl_secs` bound as a timestamp); 23505 on `uq_offline_issuance_one_open_per_card` → 409 `offline_issuance_in_flight`; `emit_event(OfflineIssuanceCreated{issuance_id, card_id, currency, amount_minor})`; commit.
4. Response `{issuance_id, issuance_ref, state:"awaiting_funds", funding: {destination: reserve.stellar_address, asset: "XLM", amount: minor_to_decimal_string(amount_minor, 7), memo: issuance_ref, idempotency_key: issuance_ref}, expires_at}`. The client funds it with `POST /managed-account/sign` using exactly those parameters (the sign path validates nothing issuance-specific; the watcher matches). XLM pilot only: stablecoin-denominated cards need `asset` support on the sign path (out of scope).

**Funding match** — `reserve_watch::process_payment` gains a branch after the cycle-ref branch (`:927-975`): inbound memo `UPPER(TRIM(memo))` starting with `IS` and matching `offline_issuance.issuance_ref` → `offline::issuance::credit_issuance_arrival(deps, &row, p, budget)`: asset must map to `row.currency` (`payment_currency`) and `p.to == reserve` — else fall through to the ordinary classifier (`wrong_asset`); `p.from != Some(funding_source)` → `record_unmatched(.., "no_match", ..)` (a third party may never fund a liability the owner then redeems; `no_match` is not auto-refunded); actual `amount < amount_minor` → `record_unmatched(.., "underpaid", ..)` (existing auto-refund path; issuance stays `awaiting_funds` until expiry). Otherwise one tx: `UPDATE offline_issuance SET state='funded', funding_paging_token=$2, funding_tx_hash=$3, funded_minor=$4 WHERE issuance_id=$1 AND state='awaiting_funds'` (0 rows → `record_unmatched(.., "late", ..)` → auto-refund, exactly like late order deposits); `RESERVE_BUCKET_APPLY_SQL(currency, +actual, 0)` + `journal_insert(issuance_deposit, delta +actual, paging_token, stellar_tx_hash, sender_address, sender_muxed, issuance_id, note "overpaid ..." when actual > amount)` (23505 → rollback no-op, the paging-token anchor); then `RESERVE_BUCKET_APPLY_SQL(currency, -amount_minor, +amount_minor)` + `journal_insert(issuance_hold, delta -x, held_delta +x, issuance_id)` — deliberately **not** the 50 %-fraction-guarded `RESERVE_HOLD_SQL`: the funds for this hold arrived in this very transaction (pinned by `issuance_hold_uses_bucket_apply_not_the_fraction_guard`); `emit_event(OfflineIssuanceFunded{issuance_id, card_id, currency, amount_minor, overpaid})`; commit. The `seen` pre-check at `:915-925` makes replay a no-op.

**Issue** — `GET /offline/issuances/{id}/credit` (owner): `funded` → one tx under the card lock: `INSERT INTO card_offline_position (card_id, currency) VALUES ($1,$2) ON CONFLICT DO NOTHING`; `SELECT last_issued_counter FROM card_offline_position WHERE card_id=$1 FOR UPDATE`; `observed = observed_receive_counter.unwrap_or(0)`; refuse 409 `counter_jump_refused` if `observed > last + counter_max_jump` (a lying terminal cannot jam the card's stream); `counter = max(last, observed) + 1` (refuse if > i32::MAX); build the signable: `date_time_ms = now`, `sender = policy.redemption_uuid` (card check `sender != me` ✓), `recipient = card_account_uuid`, `currency = currency_tag`, `amount = card_amount`, `phone_id = 0`, `counter`; `signature_der = issuer.sign(raw 60 bytes)` (v1 untagged wire, `ImpalaApplet.java:851`; `format_version=1`); `POSITION_ISSUE_SQL = UPDATE card_offline_position SET issued_minor = issued_minor + $2, last_issued_counter = $3 WHERE card_id = $1 AND last_issued_counter < $3` (1 row required); `ISSUE_SQL = UPDATE offline_issuance SET state='issued', counter=$2, issuer_version=$3, signable=$4, signature_der=$5, issued_at=CURRENT_TIMESTAMP WHERE issuance_id=$1 AND state='funded'` (1 row); `emit_event(OfflineIssuanceIssued{issuance_id, card_id, counter})`; **commit, then** return. `issued`/`acked` → same bytes again (idempotent replay). Other states → 409. Response `{issuance_id, state, counter, format_version, signable_hex, signature_der_hex, issuer_public_key_hex, issuer_self_cert_hex, tail_hex}` where `issuer_self_cert = issuer.sign(card_cert_message(redemption_uuid, currency_tag, issuer_pubkey))` (so a card that verifies `pubKeySig` under the program key accepts the bridge as a sender) and `tail_hex = pad72(sig) || issuer_pubkey(65) || pad72(self_cert)` (209 bytes, VERIFY_TRANSFER P1=1).

**Ack** — `POST /offline/issuances/{id}/ack` `{applied: bool, status_word?: "9000"|"6233"|...}` (owner): `issued → acked` when `applied` (`UPDATE ... SET state='acked', acked_at=now, ack_status_word=$2 WHERE issuance_id=$1 AND state='issued'`); otherwise stays `issued` with `reason='card_rejected'`, `ack_status_word` recorded. Client-asserted, informational: the liability is counted from `issued`; no path here reduces `held`. **No re-issue** for a rejected counter (a second signed credit for one hold could double-apply); resolution is the card-level write-off (§8.7) or a later successful presentation.

**Expire** — `offline::issuance::expire_issuances(deps)` in the watcher tick (after quote expiry): `UPDATE offline_issuance SET state='expired', resolved_at=now WHERE state='awaiting_funds' AND expires_at < $1::timestamptz RETURNING issuance_id` (`$1` = Horizon head, gated on `deposits_drained.is_ok()` like order expiry) — no hold existed; late arrivals refund via the existing `late` path. `funded`, `issued`, `acked` never expire.

`GET /offline/issuances/{id}` (owner) → row view without signature bytes unless `issued|acked`; `GET /offline/cards/{card_id}` (owner) → `{card_id, currency, card_minor_scale, certified: bool, last_issued_counter, last_redeemed_counter, issued_minor, redeemed_minor, written_off_minor, outstanding_minor}`.

### 8.5 The conservation identity (checked by positions, DB lane, and every accept)

Per currency: `held_offline := Σ held_delta over kinds {issuance_hold, issuance_release, redemption_paid, offline_writeoff}` and the invariant `offline_liabilities_are_held`: `held_offline == Σ_cards (issued_minor − written_off_minor) − Σ amount_minor(redemptions in paid|cancelled)`. Per card: `outstanding = issued − redeemed − written_off ≥ 0` (CHECK). Aggregate: `Σ_cards outstanding ≤ bucket.held`.

### 8.6 Redemption — `POST /offline/redemptions` (owner) + watcher driver `B/src/offline/redemption.rs`

Body `{payala_account_id, card_id, signable_hex (120), signature_der_hex (≤144), card_pubkey_hex (130), pubkey_sig_hex?: (≤144), format_version?: 1}`; rate scope `redeem`. Pure verifier `verify_redemption_tuple(card: &CertifiedCard, issuer_pubkey: &[u8], redemption_uuid: Uuid, now, tuple) -> Result<ParsedRedemption, RedemptionRefusal>` (unit-tested with `aws_lc_rs` keypairs like `card_auth.rs:366-385`):
1. `card_pubkey_hex == card.ec_pubkey` (registered key; the key in the message is never trusted alone).
2. `card.issuer_cert_hex` present and verifies under the public key of `card.cert_issuer_version` (active or superseded, never revoked) over `card_cert_message(card_account_uuid, currency_tag(card.currency), card_pubkey)` — recomputed every time (defence against DB tampering); when `pubkey_sig_hex` is present it must equal the stored cert (`tokens_match`).
3. `verify_p256(card_pubkey, raw 60 bytes, signature_der)`; `format_version` must be 1 (v2 tagged messages are an additive follow-up once the card area ships them).
4. Parse: `sender == card_account_uuid`; `recipient == redemption_uuid` (`subtle` constant-time); `currency == currency_tag(card.currency)`; `amount ≥ 1`; `counter > 0`; `date_time_ms` within `[now − REDEMPTION_MAX_AGE_SECS, now + REDEMPTION_MAX_FUTURE_SKEW_SECS]` (bridge-enforced expiry; the card has no clock).
5. `amount_minor = card_to_bucket_minor(amount, card.card_minor_scale, bucket_scale)`.

Then one tx under `pg_advisory_xact_lock(hashtext('offline_card:' || card_id))`: `custodial_policy.paused` → 503; `offline_policy` enabled + redeem caps > 0 (503 `offline_unconfigured`); `destination = managed_seed.stellar_account_id` for the owner (409 `no_custodial_account` — a redemption pays the owner's custodial account only, never a client-supplied address); `destination != reserve.stellar_address && !reserve.is_asset_issuer(destination)`; dedupe: `SELECT redemption_id, state, signable_hash FROM offline_redemption WHERE card_id=$1 AND sender_counter=$2` → same hash → 202 replay of the stored row; different hash → 409 `counter_consumed`; caps: `amount ≤ redeem_per_tx_max`, `REDEEMED_TODAY_SQL` (`SUM(amount_minor) WHERE currency=$1 AND state <> 'cancelled' AND created_at >= now - 24h`) + amount ≤ `redeem_daily_max` → 409 `offline_redeem_limit`; counter rule (pure `check_redeem_counter(last, counter, max_jump)`): `last < counter ≤ last + max_jump` → 409 `counter_replay`/`counter_jump_refused`; **per-card bound as a guarded single statement**: `POSITION_REDEEM_SQL = UPDATE card_offline_position SET redeemed_minor = redeemed_minor + $2, last_redeemed_counter = $3 WHERE card_id = $1 AND currency = $4 AND issued_minor - redeemed_minor - written_off_minor >= $2 AND last_redeemed_counter < $3` (0 rows → 409 `redemption_exceeds_issued_value` — a card can never pull out more than the bridge put in; card-to-card receipts are not redeemable until netting exists); **aggregate second guard**: `amount ≤ OUTSTANDING_CURRENCY_SQL` (post-update) and `amount ≤ (SELECT held FROM conversion_reserve WHERE currency=$1)` (ledger-drift tripwire) → 409 `redemption_exceeds_aggregate` + `error!`; `REDEMPTION_INSERT_SQL = INSERT INTO offline_redemption (redemption_id, redemption_ref, payala_account_id, card_id, card_account_uuid, currency, card_amount, amount_minor, sender_counter, format_version, signable, signable_hash, signature_der, card_pubkey_hex, cert_issuer_version, signed_at, destination) VALUES ($1..$17)` (**17 binds**; `redemption_ref = "OR" + last 8 chars of base32_order_ref(&redemption_id)`); 23505 on `uq_offline_redemption_card_counter`/`signable_hash` → 409 `duplicate_debit_proof`; `emit_event(OfflineRedemptionAccepted{redemption_id, card_id, currency, amount_minor})`; commit. Response 202 `{redemption_id, redemption_ref, state:"accepted", card_amount, amount_minor, currency}`. `GET /offline/redemptions/{id}` (owner only — `destination` is the owner's address) → `{state, intent_id, stellar_hash, btxid, attempts, reason}`.

**Driver** — `reserve_watch::tick_inner` gains `offline::redemption::drive_redemptions(deps)` after `drive_refunds` (chain-OK-gated; skips claiming while `custodial_policy.paused`; cancel-token checked between rows; ≤ 10 per tick): per `accepted` row (`ORDER BY created_at`): tx1: `UPDATE offline_redemption SET state='paying', attempts=attempts+1 WHERE redemption_id=$1 AND state='accepted'` (0 → skip) + `journal_insert(redemption_attempt, 0/0, redemption_id, bucket snapshots FOR UPDATE)` (23505 → skip) + `custody::intent::insert_intent(tx, IntentRequest{payala_account_id: reserve.reserve_account_id, source_account: reserve.stellar_address, origin: 'redemption', idempotency_key: format!("redeem:{}", redemption_id), key_source: 'server', fingerprint, destination, asset: Native, amount_minor, memo: redemption_ref, fee: None, redemption_id})` (23505 on `uq_custodial_intent_redemption_live` → rollback, skip: a live release already exists) + `UPDATE offline_redemption SET intent_id=$2 WHERE redemption_id=$1`; commit. Then `custody::intent::submit_intent(deps, intent_id, reserve.reserve_account_id, params)` (the §1.5 prepare → arm → submit → classify ladder with the reserve seed via `load_protected_seed`, under the watcher lock so the reserve's sequence number never races payouts/refunds):
* Settled → `record_settlement` runs `on_intent_settled(tx, intent)`: `RESERVE_BUCKET_APPLY_SQL(currency, 0, −amount)` (held −x; 0 rows ⇒ drift: still commit the intent/transaction facts, set redemption `failed` with reason `ledger_underflow`, `error!("OFFLINE REDEMPTION SETTLED BUT LEDGER NOT APPLIED")`), `journal_insert(redemption_paid, held_delta −x, stellar_tx_hash, redemption_id)`, `UPDATE offline_redemption SET state='paid', resolved_at=now WHERE redemption_id=$1 AND state IN ('paying','frozen')`, transaction row `origin='offline_redemption'`, `account_id` = owner; `emit_event(OfflineRedemptionPaid{redemption_id, intent_id, btxid, currency, amount_minor})`.
* Rejected permanent (`op_no_destination` etc.) → intent `rejected`; `UPDATE offline_redemption SET state='failed', reason=$2 WHERE redemption_id=$1 AND state='paying'`; event `offline.redemption_failed{reason}`. Liability stays in `held`.
* Rejected non-permanent → intent `rejected`; back to `accepted` while `attempts < RESERVE_MAX_REDEMPTION_ATTEMPTS`, else `failed('max_attempts')`.
* Ambiguous → intent `ambiguous`; redemption `frozen`; the §1.6 sweep resolves by hash: `sweep_settled` runs the settle branch; `sweep_expired`/`sweep_failed` run `on_intent_rejected` → `frozen → accepted` (a new intent is allowed because the old one is `rejected`).

### 8.7 Admin — `B/src/handlers/admin_offline.rs` (8 `pub async fn`, exactly two `: AdminUser`)

| Handler | Route | Extractor | Behaviour |
|---|---|---|---|
| `get_offline_policy` | `GET /admin/offline/policy` | `Privileged<ReadCustody>` | policy row + `redemption_uuid` + open counts |
| `update_offline_policy` | `PUT /admin/offline/policy` `{enabled?, issue_per_tx_max_minor?, issue_daily_max_minor?, outstanding_max_minor?, redeem_per_tx_max_minor?, redeem_daily_max_minor?, counter_max_jump?}` | `Privileged<ManageCustody>` | COALESCE update; `enabled:true` refused while `redemption_uuid IS NULL` or no active issuer key; emits `offline.policy_updated` |
| `list_issuances` | `GET /admin/offline/issuances?state&card&page&per_page` | `Privileged<ReadCustody>` | paged, no signature bytes |
| `reverse_issuance` | `POST /admin/offline/issuances/{id}/reverse` `{reason}` | `Privileged<ManageCustody>` | only from `funded` (signable never released): `UPDATE ... SET state='reversed', reason=$2, resolved_by=$3, resolved_at=now WHERE issuance_id=$1 AND state='funded'`; `RESERVE_BUCKET_APPLY_SQL(currency, +x, −x)` + `journal_insert(issuance_release, issuance_id)`; queue the deposit refund via `queue_refund(QueueRefundInput{source_paging_token: funding_paging_token, source_tx_hash, order_id: None, currency, amount_minor: funded_minor, reason: "manual", op_type: "payment", declared_refund_address: Some(funding_source), ..})` (reuses `UNIQUE(source_paging_token)`); emits `offline.issuance_reversed` |
| `list_redemptions` | `GET /admin/offline/redemptions?state&card&page&per_page` | `Privileged<ReadCustody>` | paged |
| `retry_redemption` | `POST /admin/offline/redemptions/{id}/retry` | `Privileged<ManageCustody>` | `failed → accepted` CAS, re-resolving `destination` from the owner's current `managed_seed` row, `attempts = 0`; emits `offline.redemption_retried` |
| `cancel_redemption` | `POST /admin/offline/redemptions/{id}/cancel` `{reason, confirm_phrase}` | **`AdminUser`** | phrase `"cancel redemption {network}"`; `failed → cancelled` CAS; the card was debited and will not be paid, so the liability is extinguished loudly: `RESERVE_BUCKET_APPLY_SQL(currency, +x, −x)` + `journal_insert(offline_writeoff, redemption_id, admin_account_id, note reason)` (anchored by `(redemption_id, kind)`); `warn!`; emits `offline.redemption_cancelled{redemption_id, amount_minor, reason}` |
| `write_off_card` | `POST /admin/offline/cards/{card_id}/write-off` `{amount_minor, expected_outstanding_minor, reason, confirm_phrase}` | **`AdminUser`** | phrase `"write off card {network}"`; the documented exception procedure (lost/destroyed card, counter-rejected credit with out-of-band evidence): `POSITION_WRITEOFF_SQL = UPDATE card_offline_position SET written_off_minor = written_off_minor + $2 WHERE card_id = $1 AND issued_minor - redeemed_minor - written_off_minor = $3 AND $2 <= $3` (compare-and-swap on the outstanding the admin saw; 0 rows → 409); `RESERVE_BUCKET_APPLY_SQL(currency, +x, −x)` + `journal_insert(offline_writeoff, admin_account_id, note reason)`; `INSERT INTO offline_writeoff (card_id, currency, amount_minor, outstanding_before, reason, admin_account_id) VALUES ($1..$6)` (6 binds); `warn!`; emits `offline.card_written_off{card_id, currency, amount_minor, reason}` — the only path besides `cancel_redemption` that releases `held` without chain proof, and the daily snapshot lists both |

### 8.8 Events (038, append-only; no addresses/memos/hashes/signables/signatures; `card_id` is public NFC data already in `card.registered`)

`custody.issuer_key_generated {version, fingerprint, replaced}`, `custody.card_certified {card_id, issuer_version, replaced}`, `offline.policy_updated {fields}`, `offline.issuance_created|funded|issued|acked|expired|reversed {issuance_id, card_id, currency, amount_minor, counter?, overpaid?}`, `offline.redemption_accepted|paid|failed|retried|cancelled {redemption_id, card_id, currency, amount_minor, intent_id?, btxid?, reason?}`, `offline.card_written_off {card_id, currency, amount_minor, reason}`. Test `offline_payloads_never_carry_signables_or_addresses` (same grep helper as §1.8, plus rejects any 120-hex string).

### 8.9 Guards and wiring

* `admin.rs::delete_account`: also 409 while `offline_issuance` rows for the account are `awaiting_funds|funded` or any `card_offline_position` for the account's active cards has `outstanding > 0`, or any `offline_redemption` is `accepted|paying|frozen|failed`.
* `card.rs::delete_card`: 409 while the card's position has `outstanding > 0` or an open issuance/redemption exists.
* Rotation: superseding the issuer key keeps old versions verifiable (`superseded`) so existing certificates and credits stay redeemable; new issuance requires the card's `cert_issuer_version` to be active (recertify). Documented in `docs/runbooks/custody.md`.
* `ReserveAccountGuard` keeps its name (the managed_seed tripwires `the_reserve_quarantine_is_armed_without_a_live_reserve` :725 and `no_reserve_configured_quarantines_nothing` :734 stay untouched).

---

## 9. Ordered implementation steps

**PR1 (037, custodial core)**
1. `error.rs`: `Coded` variant + `details` field + tests. 2. `constants.rs`: §1.2 + §2 + lock keys; `models.rs` drift tests (fail until 037 exists). 3. `migrations/037_custodial_conservation.sql` (parts A–D in one file; part C/D tables are inert until PR2/PR3). 4. `models.rs`: request/response fields, `CustodialIntentView`, `CustodialPolicyView`, query structs. 5. `custody/` module (fingerprint, policy, intent, sweep) with all SQL constants and pure fns + tests. 6. `stellar/horizon.rs`: move `settles`/`asset_matches`; make `resolve_intent_by_hash`/`verify_settlement_hash` `pub(crate)` (admin_reserve re-imports). 7. `managed_seed.rs`: rewrite `sign_and_submit`, add `get_intent`/`list_intents`; delete the old `INSERT INTO transaction` block. 8. `events.rs`: new variants + tests. 9. `auth.rs`: capabilities (three-place edit with UI + fixture). 10. `handlers/admin_custody.rs`. 11. `admin.rs` delete guard. 12. `main.rs`: `TaskTracker` extension + drain, `custody::sweep::run` background task, routes. 13. `auth.rs` tripwires (§11). 14. `telemetry.rs` metrics. 15. openapi, impalactl, UI, docs (§10). 16. `cargo fmt && cargo clippy -- -D warnings && cargo test`.

**PR2 (reconciliation)**: `reconciliation/{compute.rs, job.rs}`, `handlers/admin_reconciliation.rs`, `update_bucket` field, config vars, events, metrics, routes, tripwire rows, UI drift badge, impalactl, docs.

**PR3**: §4 replenish (+ `admin_replenish::get_status` field), §6 keys outbox + payala event, `docs/conservation-spec.md` + pin test + `ci.yml` path filter + DB lane job, tripwires `signing_paths_never_read_payala_tables`, global `sign_and_submit_payment(` ban.

**PR4 (038)**: migration, `offline/` module, handlers (`offline.rs`, `admin_offline.rs`, `admin_card_issuer.rs`, `card_issuer.rs`), watcher hooks (`process_payment` branch, `drive_redemptions`, `expire_issuances`), sweep origin dispatch, `record_settlement` origin dispatch, journal widening (17 → 19), guards, events, tripwires, shared vectors + script, openapi, impalactl, docs.

**Deploy order**: 037 migrate → roll binary (custodial sign answers 503 `custodial_unconfigured` — expected, brief) → `impalactl custody policy set --per-tx-max-stroops N --daily-max-stroops M` → verify `GET /admin/custody/policy` shows `configured:true` → (later) `require_idempotency_key=true` once clients send keys. Rollback: the old binary runs against 037 (nullable columns, unused tables); roll back only after `GET /admin/custody/intents?status=ambiguous` is empty. 038: migrate → roll → `POST /admin/card-issuer/generate` (needs `KEY_IMPORT_ENABLED=true` + KMS/Vault) → `PUT /admin/offline/policy` → certify cards → `enabled:true`.

---

## 10. Contracts, clients, docs

**openapi.yaml** (append-only): `SignSubmitRequest.idempotency_key` (optional, pattern `^[A-Za-z0-9._:-]{1,64}$`); `SignSubmitResponse` new optional fields; `/managed-account/sign` responses `202`, `409`, `503` with an `ErrorDetail.details` object and the documented `error.code` values (`CUSTODIAL_REFUSAL_CODES`, `offline_*`, `counter_*`, `redemption_*`, `duplicate_debit_proof`); new paths `/managed-account/intents`, `/managed-account/intents/{intent_id}`, `/admin/custody/policy` (GET/PUT), `/admin/custody/pause`, `/admin/custody/resume`, `/admin/custody/accounts` (GET), `/admin/custody/accounts/{account_id}/limit` (PUT), `/admin/custody/intents` (GET), `/admin/custody/intents/{intent_id}` (GET), `/admin/custody/intents/{intent_id}/resolve` (POST), `/admin/reconciliation/positions`, `/admin/reconciliation/snapshots` (GET/POST), `/admin/reconciliation/snapshots/{snapshot_id}`, `/admin/card-issuer` (GET), `/admin/card-issuer/generate`, `/admin/cards/{card_id}/certificate`, `/card-issuer` (GET), `/offline/issuances` (POST), `/offline/issuances/{id}` (GET), `/offline/issuances/{id}/credit` (GET), `/offline/issuances/{id}/ack` (POST), `/offline/cards/{card_id}` (GET), `/offline/redemptions` (POST), `/offline/redemptions/{id}` (GET), `/admin/offline/policy` (GET/PUT), `/admin/offline/issuances` (GET), `/admin/offline/issuances/{id}/reverse`, `/admin/offline/redemptions` (GET), `/admin/offline/redemptions/{id}/retry`, `/admin/offline/redemptions/{id}/cancel`, `/admin/offline/cards/{card_id}/write-off`; `ReserveBucketUpdateRequest.drift_tolerance_minor`; replenishment status `send_tx_hash`. Each new description states what is client-asserted (`ack`) vs bridge-verified.

**impalactl** (`impalactl/internal/cli/*`, `internal/bridge/types.go`): `SignSubmitRequest.IdempotencyKey string \`json:"idempotency_key,omitempty"\``; `SignSubmitResponse` gains `IntentID, Status, Resolution, IdempotencyKey string; Replayed bool` (omitempty); `transfer send` gains `--idempotency-key` (default: mint UUIDv4, printed to stderr **before** the request: `Idempotency key: <k> (re-run with --idempotency-key <k> to replay safely)`), on 202 or `IsAmbiguousOutcome` replays the same key up to 3× with backoff, then polls `GET /managed-account/intents?payala_account_id=&idempotency_key=` up to `--wait` (default 330 s); exit 0 `settled`, 1 `rejected` (prints `error.code`), 3 otherwise with the notice naming `intent_id` and the key; `failAmbiguousTransfer` text rewritten (step 1 becomes "re-run with the same key: the bridge returns the recorded outcome and never pays twice"). New commands: `transfer intent show <id>`, `custody policy get|set`, `custody pause|resume`, `custody account-limit <id> <n|none>`, `custody intents list|show|resolve`, `reconciliation positions`, `reconciliation snapshot run|list|show`, `card-issuer generate|show|certify`, `offline issue|credit|ack|redeem|show|policy`. `--json` passes the raw body (existing `render`). Tests via the scripted mux (`commands_test.go:863` pattern): `TestTransferSendReusesKeyOnRetry`, `TestTransferSendPollsOn202`, `TestTransferSendRejectedIsExitOne`, `TestTransferSendAmbiguousOutcomesExitThree` updated for the replay path.

**impala-ui**: `roles.js`/`router.js`/fixture/tests (§2.3); new `custody.html` + DOM-free `custody-view.js` (`policyRows(view)`, `intentBadge(status)`, `refusalText(code)`; Vitest `custody-view.test.js`) + thin `custody.js` (`EscapeHtml.escape` on every dynamic string, no attribute interpolation, `requirePermission('view_custody')`); `reserve-math.js` `driftBadge`; keys page lists the card issuer key (fingerprint/version).

**Docs**: `docs/conservation-spec.md` (§7); new `docs/runbooks/custody.md` (deploy order, caps, pause/resume phrase, per-account limits, intent triage, positions/snapshots, `reserve.drift` triage, offline issuance/redemption operations, issuer key rotation, exception procedures write-off/cancel); `docs/runbooks/README.md` rows; `incident-response.md`: containment step 0 = `impalactl custody pause`, with the explicit note that the custodial pause does NOT gate reserve drivers (`refunds_enabled=false`, replenish `enabled=false`, quote kill switch must be flipped separately); `conversion-reserve.md`: "Positions and drift" + `drift_tolerance_minor` + offline pointer; `deploy.md`: 037/038 deploy-order note; `ARCHITECTURE.md`: conservation paragraph, Data Model rows, endpoint list; `impala-bridge/SECURITY.md`: `### Custody controls`, `### Offline issuance and redemption` (Payala Sync section unchanged); `impala-bridge/README.md`, `.env.example` (`RECONCILIATION_*`), `CHANGELOG.md` Unreleased entries per PR, `CLAUDE.md` (capability count 9; new tripwire modules; `cargo test` count updated; note the DB lane), `impalactl-operations.md`, `accounts-and-roles.md`.

---

## 11. Test plan (all default tests run with `cargo test`, no DB/Redis/hardware)

**Pure logic**: `fingerprint_*` (§1.3); `idempotency_key_charset_and_length`; `replay_decision_table` (every (status, fingerprint eq?) → verdict incl. 200/202/400/409); `ambiguous_maps_to_202_and_is_never_resubmitted`; `caps_*`/`decision_order_*` (§2.2); `sweep_verdict_table` incl. `stale_head_is_inconclusive`, `failed_tx_is_rejected_not_settled`, `settles_requires_successful_matching_payment`; `drift_is_onchain_minus_ledger`, `usd_bucket_has_no_drift_leg`, `tolerance_boundary_inclusive`, `unreadable_chain_yields_null_not_ok`, `journal_replay_mismatch_flags_bucket`, `positions_invariants_flag_uncovered_obligations`, `next_snapshot_due_boundary`; `hash_unrecorded_aborts_rather_than_requeues`; (038) `signable_layout_golden`, `card_cert_message_golden`, `conversion_is_exact_and_checked`, `currency_tags_are_pinned`, `verify_redemption_tuple_*` (valid passes; wrong key / uncertified / revoked issuer / wrong recipient / wrong currency / stale or future dateTime / counter 0 / amount 0 / format_version 2 each refuse with a distinct reason), `check_redeem_counter_bounds_jump_and_rejects_replay`, `issue_counter_allocation_bounds_observed_jump`, `issuance_ref_and_memo_prefixes_are_disjoint`.

**SQL/string pins**: `intent_insert_binds_thirteen_and_matches_ddl`; `settlement_transaction_insert_binds_ten`; `arm_sql_requires_prepared_and_null_hash`; `settle_sql_requires_hash_and_open_status`; `ambiguous_sql_only_leaves_submitted`; `abandon_sql_never_touches_armed_rows`; `stale_sql_selects_only_armed_open_rows`; `daily_counts_every_non_rejected_status`; `one_inflight_index_is_partial_on_sign_origin` (037 text); `custody_admin_mutations_are_guarded_single_statements` (PAUSE/RESUME/LIMITS name their from-state or `WHERE id`); `delete_guard_covers_every_non_terminal_intent_status`; `snapshot_insert_binds_eleven`; `snapshot_daily_anchor_is_a_date_column` (037 text contains `snapshot_date DATE` and `WHERE kind = 'daily'`, not `as_of::date`); `cycle_hash_sql_is_a_null_cas_on_both_rows`; `uq_crr_send_tx_hash_is_partial` (037 text); (038) `issuer_insert_binds_ten_with_one_literal`, `issuance_insert_binds_eleven`, `redemption_insert_binds_seventeen`, `writeoff_insert_binds_six`, `entry_insert_covers_all_journal_columns` (19, `$19` last), `position_redeem_sql_bounds_outstanding_and_counter`, `position_writeoff_sql_is_a_cas_on_outstanding`, `issuance_hold_uses_bucket_apply_not_the_fraction_guard`, `offline_state_updates_are_guarded` (every `UPDATE offline_issuance|offline_redemption` literal names its from-state), `redemption_live_index_excludes_only_rejected` (038 text).

**Tripwires (`include_str!`)**: `custodial_sign_orders_policy_before_seed_and_hash_before_submit` (in `managed_seed.rs`+`custody/intent.rs` text: `POLICY_READ_SQL` < `INTENT_INSERT_SQL` < `load_protected_seed(` < `prepare_payment(` < `INTENT_ARM_SQL` < `submit_prepared(`); `claimed_without_hash_is_provably_unsubmitted` (no `submit_prepared(` between `INTENT_INSERT_SQL` and `INTENT_ARM_SQL`); `pause_path_never_touches_redis` (no `redis` identifier in `custody/intent.rs`); `no_driver_calls_the_fused_signer` (`sign_and_submit_payment(` absent from `managed_seed.rs`, `reserve_watch.rs`, `replenish.rs`, `custody/*.rs`, `offline/*.rs`); `key_store_mutations_audit_in_the_same_transaction`; `signing_paths_never_read_payala_tables`; `issuer_key_is_generate_only`; `submit_spend_records_hash_before_submit`; `advisory_lock_keys_are_distinct`; `migration_037_and_038_vocabularies_match_constants`; `conservation_spec_names_every_vocabulary`; `every_privileged_handler_takes_its_exact_capability` gains rows for admin_custody (9: get_policy/list_accounts/list_intents/get_intent → `Privileged<ReadCustody>`; update_policy/pause/set_account_limit/resolve_intent → `Privileged<ManageCustody>`; resume → `AdminUser`), admin_reconciliation (4), admin_card_issuer (3: generate/certify → `Privileged<ManageKeys>`, list → `Privileged<ReadKeys>`), admin_offline (8: reads → ReadCustody; update_offline_policy/reverse_issuance/retry_redemption → ManageCustody; cancel_redemption/write_off_card → `AdminUser`) with `pub async fn ` count guards 9/4/3/8 and the existing 14/5/6/5 unchanged; `extractor_swap_is_complete_per_module` adds admin_reconciliation.rs and admin_card_issuer.rs to the no-`AdminUser` list, and asserts admin_custody.rs has exactly 1 and admin_offline.rs exactly 2 `: AdminUser`; `offline_owner_endpoints_gate_before_reading_policy` (`require_owner(` precedes any SQL in each `offline.rs` handler).

**Events**: `custodial_payloads_never_carry_addresses_or_hashes`, `offline_payloads_never_carry_signables_or_addresses`, `sync_batch_payload_carries_counts_only`, `event_type_vocabulary_is_append_only`.

**Models drift**: `test_transaction_origins_match_ddl`, `test_custodial_intent_vocabularies_match_ddl`, `test_custodial_vocabularies_fit_their_columns`, `test_offline_vocabularies_match_ddl`, `test_reserve_entry_kinds_match_ddl` (36), `offline_kinds_are_excluded_from_utilization`, `capability_matrix_matches_shared_fixture` (9 rows).

**Clients**: impalactl scripted-mux tests (§10); Vitest `roles.test.js`, `role-capabilities-contract.test.js`, `router-nav.test.js`, `custody-view.test.js`, `reserve-math.test.js`; card interop `AppletInteropTest.kt` shared-vector assertions + `scripts/check-shared-vectors.sh` in both workflows.

**DB lane** (opt-in, §7.7). **T2 evidence package** (`scripts/t2-evidence.sh`, PR4): positions before → `card-issuer generate` → certify → `offline issue` → fund via `transfer send --idempotency-key <ref>` → watcher funds → `offline credit` → jcardsim `verifyTransfer` with the tail → `signTransfer` to the redemption identity → `offline redeem` → watcher pays → positions after (drift 0; `offline_outstanding_minor` decreased by the exact amount) → replay every POST with the same body showing 200-replay/202-replay/409 → replay the Horizon hash into the sweep showing no second row. Every step prints DB row ids, event ids (`GET /admin/events`), the Stellar hash (`GET /transaction/{btxid}`) and the snapshot id.

## 12. Acceptance checks

1. `cd impala-bridge && cargo fmt -- --check && cargo clippy --locked -- -D warnings && cargo test --locked` green (test count in `CLAUDE.md` updated). 2. `cd impala-ui && npm test && npm run lint` green with the fixture carrying 9 capabilities. 3. `cd impalactl && go test ./... && go build ./...` green. 4. `RUN_DB_TESTS=1 DATABASE_URL=... cargo test --test db -- --ignored` green against `docker compose` Postgres 16; 037 then 038 apply cleanly to an existing 036 database and again idempotently. 5. Manual: with caps 0 → `POST /managed-account/sign` = 503 `custodial_unconfigured`; after caps → a payment settles and a second POST with the same key returns the same `intent_id`/`btxid` with `replayed:true` and no second Horizon submission (scripted-mux count = 1); same key with a different amount → 409 `idempotency_conflict`; `POST /admin/custody/pause` → sign = 503 `custodial_paused`; `resume` without the phrase → 400, with an ambiguous intent present → 409 unless `force`. 6. `GET /admin/reconciliation/positions` returns `drift_minor == 0` for a freshly funded reserve; setting the XLM tolerance and burning a fee produces `drift_ok:true`; a manual snapshot appears in the list with `attested:true`; a daily row is unique per date across two concurrent instances. 7. Replenishment: a `sending` cycle row carries `send_tx_hash` before Horizon is contacted (scripted signer asserts order). 8. Key import/revoke: the outbox row and the `bridge_credential` row share one transaction (DB lane test). 9. PR4 evidence script completes end-to-end on jcardsim + Stellar testnet with all replay steps refused.