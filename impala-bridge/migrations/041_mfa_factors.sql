-- 041: multi-factor sign-in (docs/mfa-card-pin-biometrics.md).
--
-- Additive. Run before rolling the binary that stamps `amr`/`auth_time`/`mfr`
-- into sessions, serves /mfa/step-up, /mfa/challenge, /mfa/device-keys and the
-- admin MFA surfaces, and enforces the per-account MFA mandate. Inert for
-- accounts that enroll no factor and are not required to be multi-factor:
-- `mfa_required` defaults false and no device key exists until one is enrolled.

-- Per-account MFA mandate. A session for an account with this set must be
-- multi-factor (in addition to any role listed in MFA_REQUIRED_ROLES, which is
-- operator configuration, enforced in the bridge, not stored here).
ALTER TABLE impala_account
    ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN NOT NULL DEFAULT FALSE;

-- Phone-held device keys (the "something you have", optionally biometric-bound
-- on the device). A P-256 public key generated in the phone's keystore and
-- never exported; the bridge only ever verifies assertions against it
-- (docs/mfa-card-pin-biometrics.md §4). Soft-deleted like `card`.
CREATE TABLE IF NOT EXISTS mfa_device_key (
    id                 SERIAL PRIMARY KEY,
    account_id         VARCHAR(255) NOT NULL,
    key_id             UUID NOT NULL DEFAULT gen_random_uuid(),
    public_key_hex     CHAR(130) NOT NULL,            -- uncompressed SEC1 04||X||Y (P-256)
    label              VARCHAR(128),
    platform           VARCHAR(32),
    -- What the client DECLARED at enrollment; the bridge cannot verify it
    -- without platform key attestation (§4.3), so `bio` is credited only when
    -- MFA_DEVICE_BIOMETRIC=claimed and this is 'biometric'.
    user_verification  VARCHAR(16) NOT NULL DEFAULT 'none'
        CHECK (user_verification IN ('biometric', 'none')),
    is_delete          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_device_key_account
        FOREIGN KEY (account_id)
        REFERENCES impala_account(payala_account_id)
        ON DELETE CASCADE
);

-- key_id is the external handle; unique among a given account's active keys,
-- and the public key is unique among active keys (a key is enrolled once).
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_device_key_active_id
    ON mfa_device_key(account_id, key_id) WHERE is_delete = FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS uq_mfa_device_key_active_pub
    ON mfa_device_key(public_key_hex) WHERE is_delete = FALSE;
CREATE INDEX IF NOT EXISTS idx_mfa_device_key_account
    ON mfa_device_key(account_id) WHERE is_delete = FALSE;

CREATE TRIGGER update_mfa_device_key_updated_at BEFORE UPDATE
    ON mfa_device_key FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
