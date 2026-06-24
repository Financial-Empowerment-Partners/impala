-- Custodial Stellar secret seeds, protected at rest by a pluggable backend
-- (AWS KMS envelope encryption or HashiCorp Vault Transit). One row per account.
--
-- SECURITY: this table never stores a plaintext seed. `ciphertext`,
-- `wrapped_data_key`, and `nonce` are all backend-produced ciphertext/metadata;
-- decryption requires the external KMS CMK or Vault transit key.
CREATE TABLE IF NOT EXISTS managed_seed (
    id                 SERIAL PRIMARY KEY,
    payala_account_id  VARCHAR(64)  NOT NULL,
    stellar_account_id VARCHAR(128) NOT NULL,   -- public G-address derived from the seed
    backend            VARCHAR(16)  NOT NULL,   -- 'kms' | 'vault'
    ciphertext         BYTEA        NOT NULL,    -- AES-GCM ct (KMS) or vault:vN:... token (Vault)
    wrapped_data_key   BYTEA,                    -- KMS-wrapped data key (KMS backend only)
    nonce              BYTEA,                    -- AES-GCM nonce (KMS backend only)
    key_id             VARCHAR(256) NOT NULL,    -- KMS key ARN/id or Vault transit key name
    key_version        VARCHAR(32),              -- Vault transit key version, when applicable
    origin             VARCHAR(16)  NOT NULL,    -- 'generated' | 'imported'
    created_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (payala_account_id),
    UNIQUE (stellar_account_id)
);

COMMENT ON TABLE managed_seed IS
    'Custodial Stellar seeds, encrypted at rest. No plaintext seed is ever stored here.';

CREATE INDEX IF NOT EXISTS idx_managed_seed_payala_id ON managed_seed (payala_account_id);
CREATE INDEX IF NOT EXISTS idx_managed_seed_stellar_id ON managed_seed (stellar_account_id);
