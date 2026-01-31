-- Create impala_auth table for storing password hashes
CREATE TABLE impala_auth (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_account
        FOREIGN KEY (account_id)
        REFERENCES impala_account(payala_account_id)
        ON DELETE CASCADE
);

-- Create index for faster lookups on account_id
CREATE INDEX idx_impala_auth_account_id ON impala_auth(account_id);

-- Create trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_impala_auth_updated_at BEFORE UPDATE
    ON impala_auth FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
