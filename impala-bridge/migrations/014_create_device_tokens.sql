CREATE TABLE IF NOT EXISTS device_token (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    platform VARCHAR(16) NOT NULL DEFAULT 'android',
    token TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(account_id, token)
);

CREATE INDEX IF NOT EXISTS idx_device_token_account ON device_token(account_id);

CREATE TRIGGER update_device_token_updated_at BEFORE UPDATE
    ON device_token FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
