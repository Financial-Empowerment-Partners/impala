-- Three LATERAL privileged roles splitting the admin surface by blast radius:
--   treasurer      reserve & replenishment money operations
--   key-custodian  bridge provider credentials & custodial Stellar seeds
--   auditor        read-only oversight of the privileged surfaces
-- None includes another; `admin` remains the unchanged superset and the only
-- governance role (role grants, deletions, sync, webhooks). Enforcement lives
-- in the bridge's capability table (auth.rs role_has_capability), stamped
-- into JWTs at issuance exactly like the original roles.
--
-- Deploy order: run this migration BEFORE rolling the new binary. The new
-- binary's validate_role accepts the new names, so granting one against the
-- old CHECK would otherwise 500; the old binary treats the new roles as
-- unknown and they fail closed everywhere (AdminUser rejects them, ordinary
-- endpoints never read the role).
--
-- One statement, one ACCESS EXCLUSIVE acquisition, same constraint name as
-- migration 023. Re-validation of existing rows is safe: the new set is a
-- strict superset of the old.
ALTER TABLE impala_account
    DROP CONSTRAINT chk_impala_account_role,
    ADD CONSTRAINT chk_impala_account_role
    CHECK (role IN ('view-only', 'device', 'token', 'treasurer', 'key-custodian', 'auditor', 'admin'));
