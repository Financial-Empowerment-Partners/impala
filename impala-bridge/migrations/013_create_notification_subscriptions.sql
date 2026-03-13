CREATE TYPE event_type AS ENUM (
    'login_success',
    'login_failure',
    'password_change',
    'transfer_incoming',
    'transfer_outgoing',
    'profile_updated'
);

CREATE TABLE IF NOT EXISTS notification_subscription (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    event_type event_type NOT NULL,
    medium notify_medium NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, event_type, medium)
);

CREATE INDEX IF NOT EXISTS idx_notif_sub_account_event
    ON notification_subscription(account_id, event_type);

CREATE TRIGGER update_notification_subscription_updated_at BEFORE UPDATE
    ON notification_subscription FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
