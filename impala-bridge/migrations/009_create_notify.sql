-- Create enum type for notification medium
CREATE TYPE notify_medium AS ENUM ('webhook', 'sms', 'mobile_push', 'to_app');

-- Create notify table for storing notification records
CREATE TABLE IF NOT EXISTS notify (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    medium notify_medium NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on account_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_notify_account_id ON notify(account_id);

-- Reuse the update_updated_at_column() function from impala_auth migration
CREATE TRIGGER update_notify_updated_at BEFORE UPDATE
    ON notify FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
