ALTER TABLE impala_auth ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(32) NOT NULL DEFAULT 'local';
CREATE INDEX IF NOT EXISTS idx_impala_auth_provider ON impala_auth(auth_provider);
