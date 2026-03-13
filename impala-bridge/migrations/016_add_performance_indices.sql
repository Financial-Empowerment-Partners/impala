-- Performance indices for common query patterns
-- Using CONCURRENTLY to avoid table locks in production

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_card_account_active
    ON card(account_id) WHERE is_delete = FALSE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_account_type
    ON impala_mfa(account_id, mfa_type);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notify_account_active
    ON notify(account_id) WHERE active = TRUE;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_transaction_created_at
    ON transaction(created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notif_sub_account_event
    ON notification_subscription(account_id, event_type) WHERE enabled = TRUE;
