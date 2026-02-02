-- Create transaction table
CREATE TABLE IF NOT EXISTS transaction (
    btxid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stellar_tx_id VARCHAR(128),
    payala_tx_id VARCHAR(128),
    stellar_hash VARCHAR(128),
    source_account VARCHAR(128),
    stellar_fee BIGINT,
    stellar_max_fee BIGINT,
    memo TEXT,
    signatures TEXT,
    preconditions TEXT,
    payala_currency VARCHAR(16),
    payala_digest VARCHAR(256),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_tx_id CHECK (stellar_tx_id IS NOT NULL OR payala_tx_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_transaction_stellar_tx_id ON transaction(stellar_tx_id);
CREATE INDEX IF NOT EXISTS idx_transaction_payala_tx_id ON transaction(payala_tx_id);
