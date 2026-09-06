-- 037: custodial conservation controls (custodial payment intents, custodial
-- policy, transaction settlement columns, reconciliation snapshots,
-- replenishment hash anchor). Applying this file changes NO behaviour by
-- itself. The binary that writes these
-- tables REFUSES custodial signing until an admin/treasurer sets
-- custodial_policy caps (0 = unconfigured, never "unlimited"; 032:197).
-- Deploy order: migrate -> roll -> PUT /admin/custody/policy.
--
-- Part A: custodial payment intents (write-ahead rows for
--         POST /managed-account/sign) + transaction settlement columns.
-- Part B: custodial policy (pause + caps) + per-account override.
-- Part C: reconciliation snapshots + per-bucket drift tolerance.
-- Part D: replenishment send hash anchor (hash before submit, §4 of
--         docs/conservation-spec.md).

-- ── Part A: custodial payment intents ──────────────────────────────────

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
-- shared INSERT (transaction.rs, sync.rs mirror rows, reserve_watch.rs
-- fulfillment / refund rows) keeps its bind list untouched.
ALTER TABLE transaction
    ADD COLUMN IF NOT EXISTS stellar_amount_minor BIGINT
        CHECK (stellar_amount_minor IS NULL OR stellar_amount_minor > 0),
    ADD COLUMN IF NOT EXISTS stellar_destination VARCHAR(69),
    ADD COLUMN IF NOT EXISTS stellar_asset_code VARCHAR(12),
    ADD COLUMN IF NOT EXISTS stellar_asset_issuer VARCHAR(56);
-- 031 pattern (DROP + ADD ... NOT VALID + VALIDATE). 'offline_redemption' is
-- pre-declared so 038 needs no second CHECK cycle; nothing writes it before
-- 038.
ALTER TABLE transaction DROP CONSTRAINT chk_transaction_origin;
ALTER TABLE transaction ADD CONSTRAINT chk_transaction_origin
    CHECK (origin IN ('manual', 'payala_sync', 'conversion_reserve',
                      'custodial_sign', 'offline_redemption'))
    NOT VALID;
ALTER TABLE transaction VALIDATE CONSTRAINT chk_transaction_origin;

-- ── Part B: custodial policy (pause + caps) ─────────────────────────────

-- Single-row money switch (031 conversion_reserve_state precedent), read
-- FOR SHARE inside the claim transaction. Redis is never consulted on the
-- pause/cap path.
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

-- ── Part C: reconciliation snapshots ────────────────────────────────────

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

-- ── Part D: replenishment send hash anchor ──────────────────────────────

-- 032 promised send_tx_hash is "captured BEFORE the submit"; the code wrote
-- it after settlement. The NULL-CAS in reserve_watch::record_intent_hash
-- (IntentKey::Cycle) plus this partial unique make a re-arm unable to
-- overwrite a hash that may already have been submitted, and two cycles
-- unable to share one signed envelope.
CREATE UNIQUE INDEX IF NOT EXISTS uq_crr_send_tx_hash
    ON conversion_reserve_replenishment(send_tx_hash) WHERE send_tx_hash IS NOT NULL;
