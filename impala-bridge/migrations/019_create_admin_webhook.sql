-- Admin-registered webhook endpoints for the account/transaction event feed.
CREATE TABLE IF NOT EXISTS admin_webhook (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    -- HMAC-SHA256 signing secret. Returned to the admin ONCE at registration.
    -- Stored cleartext so the worker can sign; use Vault/KMS in production.
    secret TEXT NOT NULL,
    -- NULL or empty array = subscribe to all event types.
    event_types TEXT[],
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_delivery_at TIMESTAMP WITH TIME ZONE,
    -- Admin account_id (JWT sub) that registered the webhook.
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_webhook_enabled
    ON admin_webhook (enabled) WHERE enabled = TRUE;

-- Reuse update_updated_at_column() defined in 002_create_impala_auth.sql.
CREATE TRIGGER update_admin_webhook_updated_at
    BEFORE UPDATE ON admin_webhook
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
