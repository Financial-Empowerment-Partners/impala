-- Widen the profile_source CHECK to admit the new OIDC SSO providers.
--
-- Multi-provider SSO (see src/oidc.rs) auto-provisions accounts with
-- profile_source = the provider name (okta | auth0 | duo). The original
-- constraint (migration 020) only allowed local/ldap/okta, so inserts from
-- Auth0/Duo would fail the CHECK. auth_provider (impala_auth) has no CHECK, so
-- it needs no change.
ALTER TABLE impala_account DROP CONSTRAINT IF EXISTS chk_impala_account_profile_source;

ALTER TABLE impala_account
    ADD CONSTRAINT chk_impala_account_profile_source
    CHECK (profile_source IN ('local', 'ldap', 'okta', 'auth0', 'duo'));
