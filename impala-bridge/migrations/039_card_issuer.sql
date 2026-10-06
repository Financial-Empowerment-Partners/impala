-- 039: card issuer key custody + bridge-issued card certificates (handoff
-- lane C1; spec-bridge.md §8.1-8.2 as amended by contract-addendum.md §A.1,
-- A.7, A.8). The offline issuance/redemption ledger (lane C2: positions,
-- issuances, redemptions, write-offs, journal kinds) is a later migration.
--
-- Inert until an operator generates an issuer key
-- (POST /admin/card-issuer/generate). Run before rolling the binary that
-- serves /admin/card-issuer, /admin/cards/{card_id}/certificate and
-- /card-issuer (RUN_MODE=migrate).

-- The program issuer key: a generate-only P-256 key sealed by the seed
-- protector (KMS / Vault / OpenBao envelope), exactly like a custodial seed.
-- Old versions stay as public keys (superseded) so certificates they signed
-- keep verifying; revoked versions never verify.
CREATE TABLE IF NOT EXISTS card_issuer_key (
    version            INTEGER PRIMARY KEY CHECK (version > 0),
    state              VARCHAR(16) NOT NULL,
    backend            VARCHAR(16) NOT NULL,
    ciphertext         BYTEA,
    wrapped_data_key   BYTEA,
    nonce              BYTEA,
    key_id             VARCHAR(256),
    key_version        VARCHAR(32),
    public_key_hex     CHAR(130) NOT NULL,             -- uncompressed SEC1 04||X||Y, public
    fingerprint        VARCHAR(64) NOT NULL,           -- keys::fingerprint("card_issuer","public_key",point)
    generated_by       VARCHAR(64) NOT NULL,
    generated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    superseded_at      TIMESTAMP WITH TIME ZONE,
    scrubbed_at        TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_cik_state CHECK (state IN ('active', 'superseded', 'revoked')),
    CONSTRAINT chk_cik_active_has_material CHECK (state <> 'active' OR ciphertext IS NOT NULL),
    CONSTRAINT chk_cik_scrub_is_total CHECK (scrubbed_at IS NULL
        OR (ciphertext IS NULL AND wrapped_data_key IS NULL AND nonce IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_card_issuer_key_single_active
    ON card_issuer_key((true)) WHERE state = 'active';

-- Program identity. program_id (16 random bytes, bridge-generated) is minted
-- in the same transaction as the FIRST issuer key and never changes on key
-- rotation; redemption_uuid is the identity a card names as `recipient` when
-- it signs a redemption. Both NULL = unconfigured. `enabled` and the caps are
-- the offline issuance/redemption switches (lane C2): dormant, 0 = refuse.
CREATE TABLE IF NOT EXISTS offline_policy (
    id                          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    enabled                     BOOLEAN NOT NULL DEFAULT false,
    program_id                  BYTEA CHECK (program_id IS NULL OR octet_length(program_id) = 16),
    redemption_uuid             UUID,
    issue_per_tx_max_minor      BIGINT NOT NULL DEFAULT 0 CHECK (issue_per_tx_max_minor >= 0),
    issue_daily_max_minor       BIGINT NOT NULL DEFAULT 0 CHECK (issue_daily_max_minor >= 0),
    outstanding_max_minor       BIGINT NOT NULL DEFAULT 0 CHECK (outstanding_max_minor >= 0),
    redeem_per_tx_max_minor     BIGINT NOT NULL DEFAULT 0 CHECK (redeem_per_tx_max_minor >= 0),
    redeem_daily_max_minor      BIGINT NOT NULL DEFAULT 0 CHECK (redeem_daily_max_minor >= 0),
    -- Shared with the card (CARD_RECEIVE_COUNTER_MAX_JUMP, addendum §A.5).
    counter_max_jump            INTEGER NOT NULL DEFAULT 1024 CHECK (counter_max_jump BETWEEN 1 AND 1024),
    updated_by                  VARCHAR(64),
    created_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_op_program_and_redemption_together CHECK ((program_id IS NULL) = (redemption_uuid IS NULL))
);
INSERT INTO offline_policy (id) VALUES (true) ON CONFLICT (id) DO NOTHING;

-- Certification columns. card_id is unique only among active rows (021), so
-- the certificate rides on the active row.
ALTER TABLE card
    ADD COLUMN IF NOT EXISTS currency            VARCHAR(12) REFERENCES conversion_reserve(currency),
    ADD COLUMN IF NOT EXISTS card_minor_scale    SMALLINT CHECK (card_minor_scale BETWEEN 0 AND 7),
    ADD COLUMN IF NOT EXISTS issuer_cert_hex     VARCHAR(144),   -- DER ECDSA <= 72 bytes
    ADD COLUMN IF NOT EXISTS cert_issuer_version INTEGER REFERENCES card_issuer_key(version),
    ADD COLUMN IF NOT EXISTS certified_at        TIMESTAMP WITH TIME ZONE;

CREATE TRIGGER update_offline_policy_updated_at BEFORE UPDATE ON offline_policy
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
