-- Server-side account role. The bridge becomes the source of truth for RBAC;
-- the role is embedded in the JWT and read by the admin UI (deprecating the
-- UI's localStorage roles). Hyphenated 'view-only' mirrors the UI role keys.
ALTER TABLE impala_account
    ADD COLUMN IF NOT EXISTS role VARCHAR(16) NOT NULL DEFAULT 'view-only';

ALTER TABLE impala_account
    ADD CONSTRAINT chk_impala_account_role
    CHECK (role IN ('view-only', 'device', 'token', 'admin'));

CREATE INDEX IF NOT EXISTS idx_impala_account_role ON impala_account(role);

-- Bootstrap-first-admin, server-side, covering ALL insert paths
-- (create_account, okta auto-provision, managed-account generate/import):
-- the very first account ever created becomes admin, mirroring the UI's old
-- first-login-admin behaviour. The advisory lock serializes the empty-table
-- check so two concurrent first-inserts cannot both be promoted.
CREATE OR REPLACE FUNCTION impala_account_bootstrap_admin()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('impala_account_bootstrap_admin'));
    IF NOT EXISTS (SELECT 1 FROM impala_account) THEN
        NEW.role := 'admin';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_impala_account_bootstrap_admin ON impala_account;
CREATE TRIGGER trg_impala_account_bootstrap_admin
    BEFORE INSERT ON impala_account
    FOR EACH ROW
    EXECUTE FUNCTION impala_account_bootstrap_admin();

-- Backfill for EXISTING deployments: if no admin exists yet, promote the
-- earliest account so the admin endpoints are reachable after deploy.
UPDATE impala_account
   SET role = 'admin'
 WHERE id = (SELECT id FROM impala_account ORDER BY id ASC LIMIT 1)
   AND NOT EXISTS (SELECT 1 FROM impala_account WHERE role = 'admin');
