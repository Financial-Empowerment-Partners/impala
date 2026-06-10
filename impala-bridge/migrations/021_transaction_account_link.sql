-- Link transactions to their owning account.
--
-- Plain (non-CONCURRENT) statements only: sqlx runs each migration inside a
-- transaction, and Postgres rejects CREATE INDEX CONCURRENTLY there.
--
-- account_id stays NULLable: rows created before this migration carry no
-- owner information and are unrecoverable.
ALTER TABLE transaction ADD COLUMN IF NOT EXISTS account_id VARCHAR(64);

-- NOT VALID + VALIDATE per the 017 precedent (avoids a long exclusive lock
-- when applied outside a wrapping transaction).
ALTER TABLE transaction ADD CONSTRAINT fk_transaction_account
    FOREIGN KEY (account_id) REFERENCES impala_account(payala_account_id)
    ON DELETE SET NULL NOT VALID;

ALTER TABLE transaction VALIDATE CONSTRAINT fk_transaction_account;

CREATE INDEX IF NOT EXISTS idx_transaction_account_id ON transaction(account_id);

-- card.card_id uniqueness for the card-auth lookup: soft-delete all but the
-- most recent active row per card_id, then enforce uniqueness on active rows
-- going forward.
UPDATE card c
SET is_delete = TRUE,
    deleted_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE c.is_delete = FALSE
  AND c.id <> (SELECT MAX(c2.id) FROM card c2
               WHERE c2.card_id = c.card_id AND c2.is_delete = FALSE);

CREATE UNIQUE INDEX IF NOT EXISTS uq_card_active_card_id
    ON card(card_id) WHERE is_delete = FALSE;
