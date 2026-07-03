-- Payala account synchronization modes (reserve / mirror).
--
-- 'reserve' (default): each POST /sync/payala batch of offline Payala
-- transactions is aggregated into a single per-currency net update of the
-- account's reserve balance (payala_reserve).
-- 'mirror': every fresh item in a batch is reflected 1:1 as a `transaction`
-- row (origin = 'payala_sync').
--
-- Bookkeeping only: amounts are unverified client assertions (JWT-gated,
-- owner-only), quarantined from anything that moves value on-chain.

-- Per-account sync mode (template: 019_add_account_role.sql).
ALTER TABLE impala_account
    ADD COLUMN IF NOT EXISTS sync_mode VARCHAR(16) NOT NULL DEFAULT 'reserve';

ALTER TABLE impala_account
    ADD CONSTRAINT chk_impala_account_sync_mode
    CHECK (sync_mode IN ('reserve', 'mirror'));

CREATE INDEX IF NOT EXISTS idx_impala_account_sync_mode ON impala_account(sync_mode);

-- Per-account, per-currency Payala-side reserve balance. Signed minor units
-- (BIGINT, following the stellar_fee convention); negatives are legal because
-- offline batches can arrive out of order.
CREATE TABLE IF NOT EXISTS payala_reserve (
    payala_account_id VARCHAR(64) NOT NULL
        REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    currency   VARCHAR(16) NOT NULL,
    balance    BIGINT      NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (payala_account_id, currency)
);

-- Batch audit: one row per POST /sync/payala call that reaches application,
-- written even when every item is a duplicate (applied_count = 0). net_deltas
-- holds counts and per-currency deltas only — no client memo/digest bytes.
CREATE TABLE IF NOT EXISTS payala_sync_batch (
    batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payala_account_id VARCHAR(64) NOT NULL
        REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    sync_mode         VARCHAR(16) NOT NULL,
    item_count        INTEGER     NOT NULL,
    applied_count     INTEGER     NOT NULL,
    duplicate_count   INTEGER     NOT NULL,
    conflicting_count INTEGER     NOT NULL DEFAULT 0,
    net_deltas        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_payala_sync_batch_mode CHECK (sync_mode IN ('reserve', 'mirror'))
);

CREATE INDEX IF NOT EXISTS idx_payala_sync_batch_account
    ON payala_sync_batch(payala_account_id);

-- Idempotency ledger shared by both modes. PK is (account, tx) — NOT a global
-- payala_tx_id — because one offline transfer between two bridge accounts
-- legitimately appears in BOTH parties' batches (opposite signs), and a global
-- key would let one account block another's ids.
CREATE TABLE IF NOT EXISTS payala_sync_item (
    payala_account_id VARCHAR(64) NOT NULL
        REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    payala_tx_id VARCHAR(128) NOT NULL,
    batch_id UUID NOT NULL
        REFERENCES payala_sync_batch(batch_id) ON DELETE CASCADE,
    amount   BIGINT      NOT NULL,
    currency VARCHAR(16) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (payala_account_id, payala_tx_id)
);

CREATE INDEX IF NOT EXISTS idx_payala_sync_item_batch ON payala_sync_item(batch_id);

-- Mirror-mode columns on transaction. origin distinguishes server-created
-- mirror rows from client-posted rows and is never settable via the API
-- (migration 007's audit trigger only RAISE LOGs, so these ALTERs are safe).
ALTER TABLE transaction ADD COLUMN IF NOT EXISTS payala_amount BIGINT;
ALTER TABLE transaction ADD COLUMN IF NOT EXISTS origin VARCHAR(16) NOT NULL DEFAULT 'manual';

ALTER TABLE transaction
    ADD CONSTRAINT chk_transaction_origin CHECK (origin IN ('manual', 'payala_sync'));

-- Backstop against duplicate mirror rows; the payala_sync_item PK is the
-- primary dedupe, so this index never fires under normal operation.
CREATE UNIQUE INDEX IF NOT EXISTS uq_transaction_payala_sync
    ON transaction(source_account, payala_tx_id) WHERE origin = 'payala_sync';
