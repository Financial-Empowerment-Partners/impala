-- Conversion reserve, second wave: automated replenishment, reserved price
-- quotes, and automated refunds. One migration for all three because they
-- share a single object — `chk_conversion_reserve_entry_kind` — and three
-- sequential rewrites of one CHECK is worse than one deliberate rewrite.
--
-- Applying this file changes NO behavior. Every feature is gated on a flag
-- that defaults false and a cap that defaults 0 (0 means *unconfigured,
-- refuse to run* — never "unlimited"), so an admin must opt in twice before
-- a single stroop can move. The new columns are all nullable and the new
-- kinds are unwritten until the code that writes them ships.
--
-- Money conventions are unchanged from 031: signed BIGINT minor units,
-- guarded single-statement UPDATEs as the mechanism with CHECKs as the
-- backstop, and CHECK replacement via DROP + ADD ... NOT VALID + VALIDATE so
-- the ACCESS EXCLUSIVE window stays a metadata change.

-- ── Journal: linkage columns for all three features ───────────────────
--
-- One INSERT shape serves this append-only table. Rather than a companion
-- INSERT per feature (four near-identical statements, where picking the
-- wrong one silently drops a linkage column), the single shared statement
-- widens and every writer binds NULL for the columns it does not use.
ALTER TABLE conversion_reserve_entry
    -- Pre-order capacity lock (reserved price quotes).
    ADD COLUMN IF NOT EXISTS quote_id UUID,
    -- Treasury cycle (replenishment); FK added after the table exists.
    ADD COLUMN IF NOT EXISTS cycle_id UUID,
    -- Refund obligation this entry belongs to.
    ADD COLUMN IF NOT EXISTS refund_id UUID,
    -- Counterparty of an inbound payment, captured on `deposit` entries so a
    -- stranded deposit has somewhere to be returned to. Stellar G-addresses
    -- are 56 chars; M-strkeys (muxed) are 69.
    ADD COLUMN IF NOT EXISTS sender_address VARCHAR(56),
    ADD COLUMN IF NOT EXISTS sender_muxed VARCHAR(69);

-- ── Reserved price quotes ─────────────────────────────────────────────
--
-- A quote locks a price AND reserves the capacity behind it, so an order
-- placed against a live quote is guaranteed fulfillable. The capacity is
-- taken once here and handed to the order without ever returning to
-- `available`, so no racing order can take it in between.
CREATE TABLE IF NOT EXISTS conversion_reserve_quote (
    quote_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payala_account_id VARCHAR(64) NOT NULL
        REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    -- The provider this order would otherwise have used (attribution).
    diverted_provider VARCHAR(24) NOT NULL,
    shape VARCHAR(16) NOT NULL,
    direction VARCHAR(24) NOT NULL,
    from_currency VARCHAR(24) NOT NULL,
    to_currency VARCHAR(24) NOT NULL,
    -- The locked terms. amount_to is DERIVED from hold_minor, never the
    -- reverse: fulfillment releases `held` by parsing the order's amount_to
    -- string, so any divergence between the two drifts the held column.
    amount_from VARCHAR(40) NOT NULL,
    amount_to VARCHAR(40) NOT NULL,
    pricing VARCHAR(24) NOT NULL,
    hold_currency VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    hold_minor BIGINT NOT NULL CHECK (hold_minor > 0),
    -- Bound at quote time: the trustline check ran against THIS address, so
    -- consuming with a different one must be refused.
    payout_address TEXT,
    payout_extra_id TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    -- SET NULL so a quote's audit record outlives order rows (021/031).
    order_id UUID REFERENCES exchange_order(order_id) ON DELETE SET NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_conversion_reserve_quote_status
        CHECK (status IN ('open', 'consumed', 'expired')),
    CONSTRAINT chk_conversion_reserve_quote_shape
        CHECK (shape IN ('auto_swap', 'disburse')),
    -- Keyed on consumed_at, NOT order_id: order_id is nulled by the FK's
    -- ON DELETE SET NULL, and a CHECK re-evaluated on that UPDATE would
    -- block the order delete outright.
    CONSTRAINT chk_conversion_reserve_quote_consumed
        CHECK ((status = 'consumed') = (consumed_at IS NOT NULL))
);

-- Expiry sweep (partial, on the live state — idx_exchange_order_pending shape).
CREATE INDEX IF NOT EXISTS idx_conversion_reserve_quote_open
    ON conversion_reserve_quote(expires_at) WHERE status = 'open';

-- Per-account open-exposure cap, and the account-deletion guard.
CREATE INDEX IF NOT EXISTS idx_conversion_reserve_quote_account
    ON conversion_reserve_quote(payala_account_id) WHERE status = 'open';

-- One order is produced by at most one quote (belt-and-braces behind the
-- guarded status transition, which is the real mechanism).
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_quote_order
    ON conversion_reserve_quote(order_id) WHERE order_id IS NOT NULL;

ALTER TABLE conversion_reserve_entry
    ADD CONSTRAINT fk_conversion_reserve_entry_quote
    FOREIGN KEY (quote_id) REFERENCES conversion_reserve_quote(quote_id)
    ON DELETE SET NULL;

-- The pre-order lifecycle's idempotency anchor (uq_..._order_kind twin).
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_quote_kind
    ON conversion_reserve_entry(quote_id, kind) WHERE quote_id IS NOT NULL;

-- ── Automated replenishment ───────────────────────────────────────────
--
-- The reserve takes XLM in and pays USDC out, so without this the USDC
-- bucket drains monotonically while XLM accumulates. A cycle sells the
-- accumulated asset back through a provider. Two independently triggered
-- kinds, deliberately NOT chained: off-ramping the USDC just bought would be
-- self-defeating, and a failed second leg would strand a settled first leg.
CREATE TABLE IF NOT EXISTS conversion_reserve_replenishment (
    cycle_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind VARCHAR(16) NOT NULL,
    state VARCHAR(24) NOT NULL DEFAULT 'planned',
    -- Crockford-base32 of cycle_id: the payout memo handed to the provider
    -- AND the memo arrivals are matched on. UNIQUE so one memo can never
    -- address two cycles.
    cycle_ref VARCHAR(32) NOT NULL UNIQUE,
    trigger_source VARCHAR(16) NOT NULL,
    admin_account_id VARCHAR(64),
    -- Sizing snapshot, frozen at plan time: the audit answer to "why this
    -- size?" long after the forecast has moved on.
    need_minor BIGINT NOT NULL,
    spend_currency VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    spend_minor BIGINT NOT NULL CHECK (spend_minor > 0),
    recv_currency VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    quoted_recv_minor BIGINT NOT NULL CHECK (quoted_recv_minor > 0),
    -- What actually landed (float rate); never assumed equal to the quote.
    actual_recv_minor BIGINT,
    quote_pricing VARCHAR(24),
    provider VARCHAR(24) NOT NULL,
    provider_ref VARCHAR(128),
    provider_status VARCHAR(48),
    leg_order_id UUID REFERENCES exchange_order(order_id) ON DELETE SET NULL,
    -- Exactly what was signed, captured BEFORE the submit so a crash can be
    -- reconstructed and an admin can verify it against the chain.
    send_address TEXT,
    send_memo VARCHAR(64),
    send_tx_hash VARCHAR(64),
    -- Fiat leg only: USD cents booked IN TRANSIT until an admin confirms the
    -- bank credit. The bridge can see USDC leave and the provider's status,
    -- but never a bank credit — so this never reaches `available` on its own.
    fiat_minor BIGINT,
    fiat_confirmed_by VARCHAR(64),
    fiat_confirmed_at TIMESTAMP WITH TIME ZONE,
    external_ref VARCHAR(128),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_action_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    note VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_crr_kind CHECK (kind IN ('xlm_to_usdc', 'usdc_to_usd')),
    CONSTRAINT chk_crr_provider CHECK (provider IN ('changelly_crypto', 'owlpay')),
    CONSTRAINT chk_crr_trigger CHECK (trigger_source IN ('auto', 'admin')),
    CONSTRAINT chk_crr_state CHECK (state IN (
        'planned', 'creating', 'created', 'sending', 'sent', 'settled',
        'in_transit', 'completed', 'refunded', 'failed', 'frozen'))
);

-- "Exactly one cycle in flight per kind" as a CONSTRAINT, not a scan: a
-- second INSERT for a kind with a live cycle fails 23505 and the caller
-- aborts. 'frozen' and 'in_transit' deliberately COUNT as in flight —
-- unknown on-chain state and unverified fiat must both block new spending.
-- The terminal set here must stay identical to RESERVE_TERMINAL_CYCLE_STATES
-- in constants.rs; a drift test enforces that.
CREATE UNIQUE INDEX IF NOT EXISTS uq_crr_inflight
    ON conversion_reserve_replenishment(kind)
    WHERE state NOT IN ('completed', 'failed', 'refunded');

CREATE INDEX IF NOT EXISTS idx_crr_due
    ON conversion_reserve_replenishment(next_action_at)
    WHERE state NOT IN ('completed', 'failed', 'refunded');

CREATE INDEX IF NOT EXISTS idx_crr_created
    ON conversion_reserve_replenishment(created_at);

ALTER TABLE conversion_reserve_entry
    ADD CONSTRAINT fk_conversion_reserve_entry_cycle
    FOREIGN KEY (cycle_id) REFERENCES conversion_reserve_replenishment(cycle_id)
    ON DELETE SET NULL;

-- One entry of each kind per cycle, ever (uq_..._order_kind twin).
CREATE UNIQUE INDEX IF NOT EXISTS uq_conversion_reserve_entry_cycle_kind
    ON conversion_reserve_entry(cycle_id, kind) WHERE cycle_id IS NOT NULL;

-- Replenishment policy: the caps, admin-editable at runtime because money
-- policy must change without a redeploy (conversion_reserve_policy, 031).
CREATE TABLE IF NOT EXISTS conversion_reserve_replenish_policy (
    kind VARCHAR(16) PRIMARY KEY,
    -- MASTER SWITCH, default OFF.
    enabled BOOLEAN NOT NULL DEFAULT false,
    target_days INTEGER NOT NULL DEFAULT 30 CHECK (target_days BETWEEN 1 AND 365),
    window_days INTEGER NOT NULL DEFAULT 30 CHECK (window_days BETWEEN 1 AND 365),
    -- Dust floor: never start a cycle for a smaller shortfall (recv minor).
    min_need_minor BIGINT NOT NULL DEFAULT 0 CHECK (min_need_minor >= 0),
    -- 0 means UNCONFIGURED -> refuse to run. Not "unlimited".
    max_spend_minor BIGINT NOT NULL DEFAULT 0 CHECK (max_spend_minor >= 0),
    daily_spend_cap_minor BIGINT NOT NULL DEFAULT 0
        CHECK (daily_spend_cap_minor >= 0),
    cooldown_secs INTEGER NOT NULL DEFAULT 3600
        CHECK (cooldown_secs BETWEEN 60 AND 604800),
    -- Never spent: XLM for fees + the Stellar base reserve, or the USDC kept
    -- back to serve customer payouts.
    min_float_minor BIGINT NOT NULL DEFAULT 0 CHECK (min_float_minor >= 0),
    -- Price floor: recv minor units per ONE WHOLE spend unit. 0 disables.
    min_price_minor BIGINT NOT NULL DEFAULT 0 CHECK (min_price_minor >= 0),
    -- Max drift between the reference quote and the at-size re-quote. This
    -- is the valve that stops a mispriced or manipulated quote dumping the
    -- whole float.
    max_slippage_bps INTEGER NOT NULL DEFAULT 300
        CHECK (max_slippage_bps BETWEEN 0 AND 5000),
    updated_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_crrp_kind CHECK (kind IN ('xlm_to_usdc', 'usdc_to_usd'))
);

INSERT INTO conversion_reserve_replenish_policy (kind)
    VALUES ('xlm_to_usdc'), ('usdc_to_usd')
    ON CONFLICT (kind) DO NOTHING;

-- ── Automated refunds ─────────────────────────────────────────────────
--
-- Money the reserve cannot use — deposits arriving after expiry, underpaid
-- deposits, and deposits stranded when an admin fails an order — is returned
-- instead of living in a queue until someone reads the runbook.
--
-- source_paging_token is the obligation anchor: conversion_reserve_unmatched
-- .paging_token for a stray inflow, or the `deposit` entry's paging_token for
-- an order deposit. A payment lands in exactly one of those two places, so
-- the two queueing sites can never mint two obligations for one payment.
CREATE TABLE IF NOT EXISTS conversion_reserve_refund (
    refund_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_paging_token VARCHAR(64) NOT NULL UNIQUE,
    source_tx_hash VARCHAR(64) NOT NULL,
    order_id UUID REFERENCES exchange_order(order_id) ON DELETE SET NULL,
    currency VARCHAR(12) NOT NULL REFERENCES conversion_reserve(currency),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    refund_minor BIGINT NOT NULL CHECK (refund_minor > 0),
    destination VARCHAR(56) NOT NULL,
    -- Deliberately NOT the order ref: find_onchain_payout treats any
    -- outgoing payment carrying the order ref as "the payout landed", so a
    -- refund wearing that memo would corrupt both admin resolve actions.
    memo VARCHAR(28),
    reason VARCHAR(24) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'needs_review',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_at TIMESTAMP WITH TIME ZONE,
    stellar_tx_hash VARCHAR(64),
    btxid UUID REFERENCES transaction(btxid) ON DELETE SET NULL,
    last_error VARCHAR(200),
    skip_reason VARCHAR(32),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- A refund never exceeds what arrived.
    CONSTRAINT chk_crr_refund_not_over CHECK (refund_minor <= amount_minor),
    CONSTRAINT chk_crr_refund_reason
        CHECK (reason IN ('late', 'underpaid', 'order_failed', 'manual')),
    CONSTRAINT chk_crr_refund_status
        CHECK (status IN ('needs_review', 'queued', 'inflight', 'sent',
                          'failed', 'frozen', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_crr_refund_due
    ON conversion_reserve_refund(next_attempt_at) WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS idx_crr_refund_inflight
    ON conversion_reserve_refund(claimed_at) WHERE status = 'inflight';

CREATE INDEX IF NOT EXISTS idx_crr_refund_order
    ON conversion_reserve_refund(order_id) WHERE order_id IS NOT NULL;

ALTER TABLE conversion_reserve_entry
    ADD CONSTRAINT fk_conversion_reserve_entry_refund
    FOREIGN KEY (refund_id) REFERENCES conversion_reserve_refund(refund_id)
    ON DELETE SET NULL;

-- Deliberately NOT unique on (refund_id, kind): a retried refund
-- legitimately writes refund_intent / refund_reversal / refund_intent. The
-- claim CAS on conversion_reserve_refund.status is the anchor instead.
CREATE INDEX IF NOT EXISTS idx_conversion_reserve_entry_refund
    ON conversion_reserve_entry(refund_id) WHERE refund_id IS NOT NULL;

-- Sender capture + disposition trail on the stray-inflow queue.
ALTER TABLE conversion_reserve_unmatched
    ADD COLUMN IF NOT EXISTS sender_address VARCHAR(56),
    ADD COLUMN IF NOT EXISTS sender_muxed VARCHAR(69),
    ADD COLUMN IF NOT EXISTS refund_skip_reason VARCHAR(32),
    ADD COLUMN IF NOT EXISTS refund_id UUID
        REFERENCES conversion_reserve_refund(refund_id) ON DELETE SET NULL;

-- Refund caps, per bucket. 0 disables refunds for that currency entirely
-- (the low_water "0 disables" precedent). There is deliberately no way to
-- express "unlimited daily" on a money path.
ALTER TABLE conversion_reserve
    ADD COLUMN IF NOT EXISTS refund_max_minor BIGINT NOT NULL DEFAULT 0
        CHECK (refund_max_minor >= 0),
    ADD COLUMN IF NOT EXISTS refund_daily_max_minor BIGINT NOT NULL DEFAULT 0
        CHECK (refund_daily_max_minor >= 0);

-- Refund master switch, default OFF.
ALTER TABLE conversion_reserve_state
    ADD COLUMN IF NOT EXISTS refunds_enabled BOOLEAN NOT NULL DEFAULT false;

-- ── Journal kind vocabulary ───────────────────────────────────────────
--
-- Semantics (delta / held_delta), grouped by feature. Note `kind` is
-- VARCHAR(24): every name below is at most 24 characters, and a unit test
-- asserts it — an over-long kind fails at RUNTIME (22001) on a money path,
-- not at compile time.
--
-- Quotes:
--   quote_hold        price lock issued:        available -H, held +H
--   quote_release     lock expired unused:      available +H, held -H
--   quote_consume     lock handed to an order:  0 / 0 (pure linkage)
--
-- Replenishment (ALL excluded from utilization — see
-- RESERVE_INTERNAL_ENTRY_KINDS. Booking them as customer flow would inflate
-- the EWMA that sizes the next cycle, and the off-ramp leg would then buy
-- USDC to replace the USDC it deliberately spent: a runaway loop):
--   replenish_hold    XLM committed to a cycle: available -s, held +s
--   replenish_attempt write-ahead intent:       0 / 0
--   replenish_sent    XLM provably left:        0 / -s
--   replenish_credit  bought asset arrived:     available +a
--   replenish_refund  provider returned it:     available +r
--   replenish_release aborted before sending:   available +s, held -s
--   offramp_*         the USDC->USD twins of the four above
--   fiat_in_transit   provider says wired:      0 / +z   (NOT available)
--   fiat_confirmed    admin confirmed receipt:  available +z, held -z
--   fiat_written_off  never arrived:            0 / -z
--
-- Refunds (held_delta is always 0: the hold and the deposit are always in
-- different buckets, so a refund can never interact with a hold):
--   refund_intent     write-ahead debit:        available -x
--   refund_sent       settled on-chain:         0 / 0
--   refund_reversal   provably did not land:    available +x
ALTER TABLE conversion_reserve_entry DROP CONSTRAINT chk_conversion_reserve_entry_kind;
ALTER TABLE conversion_reserve_entry ADD CONSTRAINT chk_conversion_reserve_entry_kind
    CHECK (kind IN ('hold', 'hold_release', 'deposit', 'unmatched_deposit',
                    'payout_attempt', 'fulfillment', 'disbursement',
                    'topup', 'withdrawal', 'adjustment', 'held_adjustment',
                    'quote_hold', 'quote_release', 'quote_consume',
                    'replenish_hold', 'replenish_attempt', 'replenish_sent',
                    'replenish_credit', 'replenish_refund', 'replenish_release',
                    'offramp_hold', 'offramp_attempt', 'offramp_sent',
                    'offramp_refund',
                    'fiat_in_transit', 'fiat_confirmed', 'fiat_written_off',
                    'refund_intent', 'refund_sent', 'refund_reversal'))
    NOT VALID;
ALTER TABLE conversion_reserve_entry VALIDATE CONSTRAINT chk_conversion_reserve_entry_kind;

-- Reuse update_updated_at_column() from 002.
CREATE TRIGGER update_conversion_reserve_quote_updated_at
    BEFORE UPDATE ON conversion_reserve_quote
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversion_reserve_replenishment_updated_at
    BEFORE UPDATE ON conversion_reserve_replenishment
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversion_reserve_replenish_policy_updated_at
    BEFORE UPDATE ON conversion_reserve_replenish_policy
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_conversion_reserve_refund_updated_at
    BEFORE UPDATE ON conversion_reserve_refund
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
