-- Create impala_account table
CREATE TABLE IF NOT EXISTS impala_account (
    id SERIAL PRIMARY KEY,
    stellar_account_id VARCHAR(128) NOT NULL,
    payala_account_id VARCHAR(64) NOT NULL,
    first_name VARCHAR(32) NOT NULL,
    middle_name VARCHAR(32),
    last_name VARCHAR(32) NOT NULL,
    nickname VARCHAR(64),
    affiliation VARCHAR(128),
    gender VARCHAR(16),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(stellar_account_id),
    UNIQUE(payala_account_id)
);

-- Create index on stellar_account_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_impala_account_stellar_id ON impala_account(stellar_account_id);

-- Create index on payala_account_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_impala_account_payala_id ON impala_account(payala_account_id);
