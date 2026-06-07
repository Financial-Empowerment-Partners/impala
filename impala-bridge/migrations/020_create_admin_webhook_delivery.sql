-- Per-(event, webhook) delivery queue + audit trail for the admin webhook feed.
-- The delivery worker inserts one 'pending' row per matching webhook when an
-- event is fanned out, then retries with backoff until delivered or failed.
CREATE TABLE IF NOT EXISTS admin_webhook_delivery (
    id BIGSERIAL PRIMARY KEY,
    webhook_id BIGINT NOT NULL REFERENCES admin_webhook(id) ON DELETE CASCADE,
    event_id BIGINT NOT NULL REFERENCES event_outbox(id) ON DELETE CASCADE,
    attempt INTEGER NOT NULL DEFAULT 0,
    -- 'pending' | 'delivered' | 'failed'
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_code INTEGER,
    response_body TEXT,
    delivered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (webhook_id, event_id)
);

-- Worker scan: due pending deliveries.
CREATE INDEX IF NOT EXISTS idx_admin_webhook_delivery_due
    ON admin_webhook_delivery (next_attempt_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_admin_webhook_delivery_webhook
    ON admin_webhook_delivery (webhook_id);
