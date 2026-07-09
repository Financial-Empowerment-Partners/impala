-- Admit `openbao` as a profile_source.
--
-- The multi-provider SSO registry (src/oidc.rs) auto-provisions accounts with
-- profile_source = the provider name, and the local docker-compose stack now
-- bootstraps OpenBao as an `openbao` OIDC test IdP (see
-- docs/runbooks/test-sso-openbao-local.md). Same widening pattern as
-- migration 026: any newly configured provider name must be added here or its
-- first login fails the CHECK at provisioning time.
ALTER TABLE impala_account DROP CONSTRAINT IF EXISTS chk_impala_account_profile_source;

ALTER TABLE impala_account
    ADD CONSTRAINT chk_impala_account_profile_source
    CHECK (profile_source IN ('local', 'ldap', 'okta', 'auth0', 'duo', 'openbao'));
