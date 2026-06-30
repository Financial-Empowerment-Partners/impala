-- Admin review / flag / annotation state for transactions.
-- Kept SEPARATE from `transaction` so the dual-chain record stays immutable:
-- the AFTER INSERT OR UPDATE trigger in migration 007 logs on every base-row
-- write, and review state is mutable operational metadata, not part of the
-- chain record. One review row per transaction (1:1), upserted in place by
-- PUT /transaction/:btxid/review. A LEFT JOIN surfaces un-reviewed
-- transactions with default state and needs no backfill of existing rows.
CREATE TABLE IF NOT EXISTS transaction_review (
    btxid        UUID PRIMARY KEY
                     REFERENCES transaction(btxid) ON DELETE CASCADE,
    flagged      BOOLEAN     NOT NULL DEFAULT FALSE,
    status       VARCHAR(16) NOT NULL DEFAULT 'unreviewed',
    note         TEXT,
    reviewed_by  VARCHAR(64),  -- JWT sub == impala_account.payala_account_id
    reviewed_at  TIMESTAMP WITH TIME ZONE,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_review_status
        CHECK (status IN ('unreviewed', 'cleared', 'flagged', 'escalated'))
);

-- Admin list-view filters.
CREATE INDEX IF NOT EXISTS idx_transaction_review_status ON transaction_review(status);
CREATE INDEX IF NOT EXISTS idx_transaction_review_flagged ON transaction_review(flagged)
    WHERE flagged = TRUE;
