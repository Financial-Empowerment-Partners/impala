-- Conversion reserve: a bridge-OWNED pool that fulfills small exchange orders
-- (under a per-provider threshold of $20-$200) instead of routing them to the
-- external provider. Distinct from payala_reserve (027), which holds
-- per-account, unverified client assertions quarantined from value movement —
-- this pool is real value on a bridge-controlled Stellar account, and every
-- row here must stay reconcilable against that chain state.
--
-- Money convention: balances/deltas are signed BIGINT minor units of the
-- row's currency (027 precedent) — USDC and XLM at 7 decimal places
-- (Stellar's native precision), USD at 2 (cents). The exchange_order amount
-- strings (029) remain non-arithmetic; src/exchange/reserve.rs owns the one
-- tested string<->minor-unit conversion boundary.
--
-- Diverted orders reuse exchange_order with provider = 'reserve' (CHECK
-- widened below): same lifecycle vocabulary, same listing APIs, same events.
-- The reconcile poller explicitly excludes provider = 'reserve'; the reserve
-- watcher (src/exchange/reserve_watch.rs) drives these rows instead, using
-- the same next_poll_at column and pending partial index.

-- One row per currency bucket. `available` is what new orders may hold
-- against; `held` is committed to in-flight orders. Guarded single-statement
-- UPDATEs (WHERE available >= x ...) keep both non-negative under
-- concurrency — the CHECKs are the backstop, not the mechanism.
CREATE TABLE IF NOT EXISTS conversion_reserve (
    currency VARCHAR(12) PRIMARY KEY,
    -- Decimal places of this bucket's minor unit (USDC/XLM 7, USD 2).
    minor_scale SMALLINT NOT NULL CHECK (minor_scale BETWEEN 0 AND 18),
    available BIGINT NOT NULL DEFAULT 0 CHECK (available >= 0),
    held BIGINT NOT NULL DEFAULT 0 CHECK (held >= 0),
    -- Admin-set alert floor for `available`; 0 disables the alert.
    low_water BIGINT NOT NULL DEFAULT 0 CHECK (low_water >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Per-provider routing policy, admin-editable at runtime. threshold_usd_cents
-- is the requirement's "$20 to $200" band, DB-enforced. Only providers with a
-- buildable fulfillment path are seeded (changelly_crypto: automatic on-chain
-- USDC payout; owlpay: USDC pay-in + admin fiat disbursement queue).
-- changelly_fiat has no divertable order shape (bank details live on the
-- provider's hosted page) — the CHECK admits it so a future migration need
-- not touch this table, but the API refuses to enable it.
CREATE TABLE IF NOT EXISTS conversion_reserve_policy (
    provider VARCHAR(24) PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT false,
    threshold_usd_cents BIGINT NOT NULL DEFAULT 2000
        CHECK (threshold_usd_cents BETWEEN 2000 AND 20000),
    -- Acting admin's payala_account_id (audit; matches info! log lines).
    updated_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_conversion_reserve_policy_provider
        CHECK (provider IN ('owlpay', 'changelly_crypto', 'changelly_fiat'))
);

-- Append-only double-entry-ish journal. `delta` is the signed effect on
-- available, `held_delta` on held; balance_after/held_after snapshot the
-- bucket AFTER the entry, written under the same row lock as the bucket
-- UPDATE so the journal replays exactly. Kinds:
--   hold            order creation:  available -x, held +x
--   hold_release    expiry/resolve-fail: available +x, held -x
--   deposit         matched pay-in (ACTUAL on-chain amount): available +x
--   unmatched_deposit  stray inflow (late/underpaid/no-match): available +x
--   payout_attempt  write-ahead intent BEFORE an on-chain submit: 0 / 0
--   fulfillment     payout recorded: held -x
--   disbursement    admin fiat completion: available (hold-actual), held -hold
--   topup / withdrawal / adjustment    admin ops on available
--   held_adjustment admin repair of held drift (held_delta only)
CREATE TABLE IF NOT EXISTS conversion_reserve_entry (
    entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    currency VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    kind VARCHAR(24) NOT NULL,
    delta BIGINT NOT NULL,
    held_delta BIGINT NOT NULL DEFAULT 0,
    balance_after BIGINT NOT NULL,
    held_after BIGINT NOT NULL,
    -- SET NULL so the journal outlives order rows (021 precedent). The
    -- partial UNIQUE below is the idempotency anchor for every order-linked
    -- transition (a replayed deposit/fulfillment INSERT aborts).
    order_id UUID REFERENCES exchange_order(order_id) ON DELETE SET NULL,
    -- Which provider the order would have used (utilization attribution).
    diverted_provider VARCHAR(24),
    stellar_tx_hash VARCHAR(64),
    -- Horizon operation cursor of the payment this entry credits (deposit /
    -- unmatched_deposit only). The payment-level idempotency anchor: a
    -- replayed Horizon page must be a no-op even when the payment's
    -- classification CHANGES between passes (matched first, then "late" on
    -- replay because the order already left awaiting_deposit) — the
    -- order-keyed and unmatched-keyed anchors each cover only one side.
    paging_token VARCHAR(64),
    admin_account_id VARCHAR(64),
    note VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_conversion_reserve_entry_kind
        CHECK (kind IN ('hold', 'hold_release', 'deposit', 'unmatched_deposit',
                        'payout_attempt', 'fulfillment', 'disbursement',
                        'topup', 'withdrawal', 'adjustment', 'held_adjustment'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_order_kind
    ON conversion_reserve_entry(order_id, kind) WHERE order_id IS NOT NULL;

-- One credit per on-chain payment, ever (see paging_token comment above).
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_paging_token
    ON conversion_reserve_entry(paging_token) WHERE paging_token IS NOT NULL;

-- Forecast scans aggregate by currency and day.
CREATE INDEX IF NOT EXISTS idx_conversion_reserve_entry_currency_time
    ON conversion_reserve_entry(currency, created_at);

CREATE INDEX IF NOT EXISTS idx_conversion_reserve_entry_order
    ON conversion_reserve_entry(order_id) WHERE order_id IS NOT NULL;

-- Single-row watcher state: the Horizon paging cursor advances only AFTER a
-- page's matches have committed (misses forbidden; replays are idempotent
-- no-ops via the UNIQUE entry anchor), and only monotonically forward.
CREATE TABLE IF NOT EXISTS conversion_reserve_state (
    id BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    horizon_cursor VARCHAR(64),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Stray inflows to the reserve account (late deposits after expiry,
-- underpayments, wrong asset, unknown memo). Durable admin work queue — a
-- custodial system may not track customer money in log lines. paging_token
-- is Horizon's operation cursor: the natural replay-safe PK.
CREATE TABLE IF NOT EXISTS conversion_reserve_unmatched (
    paging_token VARCHAR(64) PRIMARY KEY,
    tx_hash VARCHAR(64) NOT NULL,
    op_type VARCHAR(32) NOT NULL,
    asset_code VARCHAR(24),
    asset_issuer VARCHAR(64),
    -- Raw Horizon amount string plus parsed minor units when the asset maps
    -- to a known bucket (NULL otherwise — visible as chain-vs-ledger drift).
    amount VARCHAR(40) NOT NULL,
    amount_minor BIGINT,
    memo VARCHAR(64),
    -- Order the memo pointed at, when it exists but could not accept the
    -- deposit (late/underpaid); NULL for unknown memos.
    matched_order_id UUID REFERENCES exchange_order(order_id) ON DELETE SET NULL,
    reason VARCHAR(24) NOT NULL,
    seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_conversion_reserve_unmatched_reason
        CHECK (reason IN ('late', 'underpaid', 'wrong_asset', 'no_match'))
);

-- Reuse update_updated_at_column() from 002.
CREATE TRIGGER update_conversion_reserve_updated_at
    BEFORE UPDATE ON conversion_reserve
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversion_reserve_policy_updated_at
    BEFORE UPDATE ON conversion_reserve_policy
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversion_reserve_state_updated_at
    BEFORE UPDATE ON conversion_reserve_state
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Widen the exchange_order provider vocabulary with the internal 'reserve'
-- provider. CHECKs cannot be altered in place: drop + re-add (re-validates
-- the table; exchange_order is small enough that this is fine in-migration).
-- The request-side vocabulary (VALID_EXCHANGE_PROVIDERS) deliberately does
-- NOT gain 'reserve' — clients cannot request it; only the row/filter
-- vocabulary (EXCHANGE_ORDER_ROW_PROVIDERS) mirrors this CHECK.
-- NOT VALID + VALIDATE keeps the ACCESS EXCLUSIVE window to a metadata
-- change; the validation scan then runs under SHARE UPDATE EXCLUSIVE, so
-- writes to these hot tables are not blocked for the duration of a full scan.
ALTER TABLE exchange_order DROP CONSTRAINT chk_exchange_order_provider;
ALTER TABLE exchange_order ADD CONSTRAINT chk_exchange_order_provider
    CHECK (provider IN ('owlpay', 'changelly_crypto', 'changelly_fiat', 'reserve'))
    NOT VALID;
ALTER TABLE exchange_order VALIDATE CONSTRAINT chk_exchange_order_provider;

-- Reserve payout settlements land in the transaction table with a dedicated
-- origin. 'conversion_reserve' is 18 chars — widen the column (027 created it
-- VARCHAR(16); varchar widening is metadata-only) before extending the CHECK.
ALTER TABLE transaction ALTER COLUMN origin TYPE VARCHAR(32);
ALTER TABLE transaction DROP CONSTRAINT chk_transaction_origin;
ALTER TABLE transaction ADD CONSTRAINT chk_transaction_origin
    CHECK (origin IN ('manual', 'payala_sync', 'conversion_reserve'))
    NOT VALID;
ALTER TABLE transaction VALIDATE CONSTRAINT chk_transaction_origin;

-- Seed the buckets, the watcher state row, and the two supported policies
-- (disabled, $20 threshold) so the admin UI has rows to edit.
INSERT INTO conversion_reserve (currency, minor_scale)
    VALUES ('USDC', 7), ('USD', 2), ('XLM', 7)
    ON CONFLICT (currency) DO NOTHING;

INSERT INTO conversion_reserve_state (id, horizon_cursor)
    VALUES (true, NULL)
    ON CONFLICT (id) DO NOTHING;

INSERT INTO conversion_reserve_policy (provider, enabled, threshold_usd_cents)
    VALUES ('changelly_crypto', false, 2000), ('owlpay', false, 2000)
    ON CONFLICT (provider) DO NOTHING;
