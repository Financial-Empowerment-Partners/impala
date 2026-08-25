-- Admin key import: provider credential sets stored encrypted at rest, plus
-- cryptographic binding for the custodial seeds that were already here.
--
-- Applying this file changes NO behavior. The credential resolver only
-- consults `bridge_credential` when `KEY_IMPORT_ENABLED=true`, which defaults
-- false, and the table starts empty — so every deployment keeps reading its
-- provider secrets from the environment exactly as before.
--
-- SECURITY: no plaintext secret is ever stored here. `ciphertext`,
-- `wrapped_data_key` and `nonce` are produced by the configured
-- `SeedProtector` (AWS KMS envelope encryption or Vault/OpenBao Transit);
-- decryption requires the external CMK or transit key. `fingerprints` and
-- `set_fingerprint` are one-way digests over *canonical parsed* key material,
-- safe to display, and are the compare-and-swap token an admin must echo back
-- before a replacement is accepted.

-- ── Provider credential sets ──────────────────────────────────────────
--
-- One row per VERSION of a complete credential SET, not per individual
-- secret. A provider client is only constructible from a whole set
-- (Changelly needs api key + RSA key together), so a per-secret table would
-- let an admin leave a provider half-imported and unbuildable. The set is
-- serialized to JSON and sealed as one blob, which also makes activation
-- atomic: a version either resolves completely or not at all.
CREATE TABLE IF NOT EXISTS bridge_credential (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Which provider client this set builds. Mirrors CREDENTIAL_KINDS in
    -- src/keys/mod.rs; a drift test pins the two together.
    kind              VARCHAR(32) NOT NULL,
    -- Monotonic per kind, allocated inside the insert transaction. Also part
    -- of the bound header sealed into the ciphertext, so a blob cannot be
    -- replayed into a different row.
    version           INTEGER     NOT NULL,
    state             VARCHAR(16) NOT NULL,
    -- 'kms' | 'vault' — which backend can decrypt this row.
    backend           VARCHAR(16) NOT NULL,
    -- NULL once the row has been scrubbed (see the retention note below).
    ciphertext        BYTEA,
    wrapped_data_key  BYTEA,
    nonce             BYTEA,
    key_id            VARCHAR(256),
    key_version       VARCHAR(32),
    -- {part_name: fingerprint} over canonical parsed material. Non-secret.
    fingerprints      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Digest over the whole set; the confirmation token for a replacement.
    set_fingerprint   VARCHAR(64) NOT NULL,
    imported_by       VARCHAR(255) NOT NULL,
    imported_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    superseded_at     TIMESTAMP WITH TIME ZONE,
    superseded_by     UUID REFERENCES bridge_credential(id) ON DELETE SET NULL,
    scrubbed_at       TIMESTAMP WITH TIME ZONE,
    -- Free-text operator note. Stored in plaintext and re-served in listings,
    -- so the handler rejects secret-shaped values before it lands here.
    note              VARCHAR(256),
    CONSTRAINT chk_bridge_credential_state
        CHECK (state IN ('active', 'superseded', 'revoked')),
    CONSTRAINT chk_bridge_credential_version CHECK (version > 0),
    -- An active row must still carry decryptable material: a scrubbed active
    -- row would resolve to "provider configured but unusable" at boot.
    CONSTRAINT chk_bridge_credential_active_has_material
        CHECK (state <> 'active' OR ciphertext IS NOT NULL),
    -- Scrubbing is one-way and must clear every secret column together.
    CONSTRAINT chk_bridge_credential_scrub_is_total
        CHECK (scrubbed_at IS NULL
               OR (ciphertext IS NULL AND wrapped_data_key IS NULL AND nonce IS NULL))
);

COMMENT ON TABLE bridge_credential IS
    'Encrypted provider credential sets (Changelly / OwlPay). No plaintext secret is ever stored here; resolution is opt-in via KEY_IMPORT_ENABLED and takes effect at the next restart.';

-- Version identity per kind. Load-bearing: the version is sealed into the
-- bound header, so two rows sharing (kind, version) would make the header
-- ambiguous and a blob portable between them.
CREATE UNIQUE INDEX IF NOT EXISTS uq_bridge_credential_kind_version
    ON bridge_credential (kind, version);

-- At most one active row per kind. This is the compare-and-swap anchor for
-- replacement: superseding the old row and inserting the new one race against
-- this index rather than against a read-then-write window.
CREATE UNIQUE INDEX IF NOT EXISTS uq_bridge_credential_active
    ON bridge_credential (kind) WHERE state = 'active';

-- Retention sweep: superseded rows older than the overlap grace.
CREATE INDEX IF NOT EXISTS idx_bridge_credential_superseded
    ON bridge_credential (kind, superseded_at)
    WHERE state = 'superseded' AND scrubbed_at IS NULL;

-- ── Custodial seed binding ────────────────────────────────────────────
--
-- `managed_seed` ciphertexts were portable between rows: neither protector
-- backend binds an encryption context, and `load_protected_seed` selected by
-- `payala_account_id` without ever checking that the decrypted seed derives
-- the address the row claims. An adversary with database write access (but
-- no KMS/Vault access) could therefore copy the conversion reserve's
-- ciphertext into an ordinary account's row and sign payments FROM the
-- reserve through /managed-account/sign — the quarantine in that handler
-- keys off the account id, which the transplanted row no longer matches.
--
-- Two independent fixes land together: the loader now asserts the derived
-- address equals `stellar_account_id` (covers every row, including legacy
-- ones), and new writes seal an account-bound header inside the ciphertext so
-- a blob only decrypts under the row it was written for.
--
-- 0 = legacy, unbound (address assertion only). 1 = bound header present.
-- Legacy rows are upgraded opportunistically on their next successful
-- decrypt, so no backfill is required and no seed is re-wrapped in a
-- migration that cannot see the KMS key.
ALTER TABLE managed_seed
    ADD COLUMN IF NOT EXISTS format_version SMALLINT NOT NULL DEFAULT 0;

COMMENT ON COLUMN managed_seed.format_version IS
    '0 = legacy ciphertext with no bound header (guarded by the derived-address assertion); 1 = account-bound header sealed inside the ciphertext.';
