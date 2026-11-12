-- 040: SEP-10 web authentication with card-held Stellar keys
-- (docs/sep10-card-keys.md §6; the signing-key table is
-- docs/sep10-authentication.md §6.1, card key kind only: no
-- login-key link table and no attestation table in this phase).
--
-- Additive. Run before rolling the binary that serves /admin/sep10/* and,
-- with SEP10_ENABLED=true, /.well-known/stellar.toml and /auth/sep10
-- (RUN_MODE=migrate). Inert until an operator generates and activates a
-- signing key.

-- The SEP-10 server signing key: a generate-only Ed25519 seed plus the
-- challenge MAC key, sealed together by the seed protector (KMS / Vault /
-- OpenBao), exactly like the card issuer key (039). Generated `pending`,
-- fenced by `activate_at`, then `active`; the previous key becomes
-- `superseded` (kept for the in-flight challenge grace) and any version can
-- be `revoked` (material scrubbed).
CREATE TABLE IF NOT EXISTS sep10_signing_key (
    version            INTEGER PRIMARY KEY CHECK (version > 0),
    state              VARCHAR(16) NOT NULL,
    backend            VARCHAR(16) NOT NULL,
    ciphertext         BYTEA,
    wrapped_data_key   BYTEA,
    nonce              BYTEA,
    key_id             VARCHAR(256),
    key_version        VARCHAR(32),
    public_address     CHAR(56) NOT NULL UNIQUE,       -- G... strkey, public (stellar.toml SIGNING_KEY)
    fingerprint        VARCHAR(64) NOT NULL,           -- keys::fingerprint("sep10_signing","public_key",raw32)
    generated_by       VARCHAR(64) NOT NULL,
    generated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activate_at        TIMESTAMP WITH TIME ZONE,
    superseded_at      TIMESTAMP WITH TIME ZONE,
    revoked_at         TIMESTAMP WITH TIME ZONE,
    scrubbed_at        TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_ssk_state CHECK (state IN ('pending', 'active', 'superseded', 'revoked')),
    CONSTRAINT chk_ssk_material CHECK (state NOT IN ('pending', 'active') OR ciphertext IS NOT NULL),
    CONSTRAINT chk_ssk_scrub CHECK (scrubbed_at IS NULL
        OR (ciphertext IS NULL AND wrapped_data_key IS NULL AND nonce IS NULL)),
    CONSTRAINT chk_ssk_revoked CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sep10_signing_key_active
    ON sep10_signing_key((true)) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_sep10_signing_key_pending
    ON sep10_signing_key((true)) WHERE state = 'pending';

-- The card's Stellar (Ed25519) key and the two cross-signatures made at
-- personalization (docs/sep10-card-keys.md §3.2). All three NULL for a card
-- registered without them (legacy applet, or an older client).
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_address CHAR(56)
    CHECK (stellar_address IS NULL OR stellar_address ~ '^G[A-Z2-7]{55}$');
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_binding_sig VARCHAR(144);
ALTER TABLE card ADD COLUMN IF NOT EXISTS stellar_proof_sig CHAR(128);
CREATE UNIQUE INDEX IF NOT EXISTS uq_card_active_stellar_address
    ON card(stellar_address) WHERE is_delete = FALSE AND stellar_address IS NOT NULL;
