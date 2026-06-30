-- Records where an account's profile data originates, enabling the admin
-- console to force a directory re-sync via the account's profile source.
--   local — manually entered (default); no external source to pull from
--   ldap  — sourced from the LDAP directory; supports live force-sync
--   okta  — provisioned via Okta SSO; refreshed on the user's next Okta login
ALTER TABLE impala_account
    ADD COLUMN IF NOT EXISTS profile_source VARCHAR(16) NOT NULL DEFAULT 'local';

ALTER TABLE impala_account
    ADD CONSTRAINT chk_impala_account_profile_source
    CHECK (profile_source IN ('local', 'ldap', 'okta'));

-- Last successful directory sync timestamp (NULL until first force-sync).
ALTER TABLE impala_account
    ADD COLUMN IF NOT EXISTS profile_synced_at TIMESTAMPTZ;
