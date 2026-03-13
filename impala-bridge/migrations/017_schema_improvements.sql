-- Add soft-delete timestamp to card table for audit trail
ALTER TABLE card ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Backfill deleted_at for already soft-deleted cards
UPDATE card SET deleted_at = CURRENT_TIMESTAMP WHERE is_delete = TRUE AND deleted_at IS NULL;

-- Add foreign key constraint: card.account_id -> impala_account.payala_account_id
-- Note: Using NOT VALID to avoid locking the table during creation, then VALIDATE separately
ALTER TABLE card ADD CONSTRAINT fk_card_account
    FOREIGN KEY (account_id) REFERENCES impala_account(payala_account_id)
    ON DELETE CASCADE NOT VALID;

ALTER TABLE card VALIDATE CONSTRAINT fk_card_account;
