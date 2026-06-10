-- Performance indices for common query patterns
--
-- Amended 2026-06-09: as originally written this migration could not apply on
-- any path — CREATE INDEX CONCURRENTLY is rejected inside the transaction
-- sqlx wraps each migration in, and idx_notify_account_active referenced a
-- notify.active column that has never existed (initdb's psql, run with
-- ON_ERROR_STOP=1, aborted there too). No environment can therefore have a
-- recorded checksum for this migration, so amending it in place is safe.
-- notify(account_id) is already indexed by 009's idx_notify_account_id.

CREATE INDEX IF NOT EXISTS idx_card_account_active
    ON card(account_id) WHERE is_delete = FALSE;

CREATE INDEX IF NOT EXISTS idx_mfa_account_type
    ON impala_mfa(account_id, mfa_type);

CREATE INDEX IF NOT EXISTS idx_transaction_created_at
    ON transaction(created_at);

CREATE INDEX IF NOT EXISTS idx_notif_sub_account_event
    ON notification_subscription(account_id, event_type) WHERE enabled = TRUE;
