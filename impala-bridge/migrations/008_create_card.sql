-- Create card table
CREATE TABLE IF NOT EXISTS card (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(64) NOT NULL,
    card_id VARCHAR(128) NOT NULL,
    ec_pubkey VARCHAR(256) NOT NULL,
    rsa_pubkey VARCHAR(1024) NOT NULL,
    is_delete BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ec_pubkey),
    UNIQUE(rsa_pubkey)
);

-- Create index on ec_pubkey for faster lookups
CREATE INDEX IF NOT EXISTS idx_card_ec_pubkey ON card(ec_pubkey);

-- Create index on rsa_pubkey for faster lookups
CREATE INDEX IF NOT EXISTS idx_card_rsa_pubkey ON card(rsa_pubkey);
