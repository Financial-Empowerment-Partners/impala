-- Durable event log (transactional outbox) backing the admin webhook feed.
-- Rows are appended in the same transaction as the originating state change,
-- then fanned out to admin webhooks by the delivery worker and served by
-- GET /admin/events.
CREATE TABLE IF NOT EXISTS event_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    dispatched BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Worker fan-out scan: undispatched rows in insertion order.
CREATE INDEX IF NOT EXISTS idx_event_outbox_undispatched
    ON event_outbox (id) WHERE dispatched = FALSE;

-- Pull/replay (GET /admin/events) ordering.
CREATE INDEX IF NOT EXISTS idx_event_outbox_created_at ON event_outbox (created_at);
