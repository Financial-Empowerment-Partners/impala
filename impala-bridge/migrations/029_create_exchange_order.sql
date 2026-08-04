-- Exchange orders: fiat<->USDC on/off-ramp (OwlPay Harbor, Changelly Fiat API)
-- and crypto->USDC swaps (Changelly Exchange API v2).
--
-- One row per provider-side order, inserted only after the provider accepted
-- the order (provider_order_id is NOT NULL). `status` is the internal
-- lifecycle vocabulary (constants.rs VALID_EXCHANGE_STATUSES); each provider's
-- raw status is mapped onto it and preserved verbatim in provider_status.
--
-- Amounts are provider-quoted decimal STRINGS: fiat and crypto assets carry
-- heterogeneous precisions and the values are never used for arithmetic, so
-- they deliberately do NOT follow the BIGINT minor-unit convention used for
-- Payala ledger amounts (027). Raw provider payloads live in provider_payload.
CREATE TABLE IF NOT EXISTS exchange_order (
    order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payala_account_id VARCHAR(64) NOT NULL
        REFERENCES impala_account(payala_account_id) ON DELETE CASCADE,
    provider VARCHAR(24) NOT NULL,
    direction VARCHAR(24) NOT NULL,
    from_currency VARCHAR(24) NOT NULL,
    to_currency VARCHAR(24) NOT NULL,
    -- Provider-quoted decimal string (heterogeneous precisions; NOT arithmetic data).
    amount_from VARCHAR(40) NOT NULL,
    amount_to VARCHAR(40),
    status VARCHAR(24) NOT NULL DEFAULT 'created',
    -- Raw (unmapped) provider status string, kept for support/debugging.
    provider_status VARCHAR(48),
    provider_order_id VARCHAR(128) NOT NULL,
    -- Where the customer sends the pay-in (crypto swaps), plus memo/tag.
    payin_address TEXT,
    payin_extra_id TEXT,
    payout_address TEXT,
    payout_extra_id TEXT,
    -- Hosted checkout URL (Changelly Fiat buy flow).
    redirect_url TEXT,
    -- OwlPay wire/bank transfer instructions for the customer (JSON passthrough).
    transfer_instructions JSONB,
    -- Latest raw provider order/transfer object for audit + support.
    provider_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Settlement link; SET NULL so order history outlives transaction rows
    -- (the 021 precedent).
    btxid UUID REFERENCES transaction(btxid) ON DELETE SET NULL,
    last_error TEXT,
    -- Reconcile-poller bookkeeping: refresh attempts so far and the next due
    -- time (exponential backoff, admin_webhook_delivery precedent).
    poll_count INTEGER NOT NULL DEFAULT 0,
    next_poll_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_exchange_order_provider
        CHECK (provider IN ('owlpay', 'changelly_crypto', 'changelly_fiat')),
    CONSTRAINT chk_exchange_order_direction
        CHECK (direction IN ('fiat_to_crypto', 'crypto_to_fiat', 'crypto_to_crypto')),
    CONSTRAINT chk_exchange_order_status
        CHECK (status IN ('created', 'awaiting_deposit', 'processing', 'on_hold',
                          'completed', 'failed', 'refunded', 'expired'))
);

-- Webhook/poller idempotency: one row per provider-side order.
CREATE UNIQUE INDEX IF NOT EXISTS uq_exchange_order_provider_ref
    ON exchange_order(provider, provider_order_id);

CREATE INDEX IF NOT EXISTS idx_exchange_order_account
    ON exchange_order(payala_account_id);

-- Reconcile-poller scan: due, non-terminal orders only.
CREATE INDEX IF NOT EXISTS idx_exchange_order_pending ON exchange_order(next_poll_at)
    WHERE status IN ('created', 'awaiting_deposit', 'processing', 'on_hold');

-- Reuse update_updated_at_column() defined in 002_create_impala_auth.sql.
CREATE TRIGGER update_exchange_order_updated_at
    BEFORE UPDATE ON exchange_order
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
