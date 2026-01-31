-- Create impala_mfa table for storing MFA enrollment data
CREATE TABLE IF NOT EXISTS impala_mfa (
    id SERIAL,
    account_id VARCHAR(255) NOT NULL,
    mfa_type VARCHAR(50) NOT NULL,         -- e.g. 'totp', 'sms'
    secret VARCHAR(512),                    -- TOTP shared secret or similar credential
    phone_number VARCHAR(50),               -- phone number for SMS-based MFA
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, mfa_type),
    CONSTRAINT fk_mfa_account
        FOREIGN KEY (account_id)
        REFERENCES impala_account(payala_account_id)
        ON DELETE CASCADE
);

-- Create index for faster lookups on account_id
CREATE INDEX IF NOT EXISTS idx_impala_mfa_account_id ON impala_mfa(account_id);

-- Reuse the update_updated_at_column() function from impala_auth migration
CREATE TRIGGER update_impala_mfa_updated_at BEFORE UPDATE
    ON impala_mfa FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
