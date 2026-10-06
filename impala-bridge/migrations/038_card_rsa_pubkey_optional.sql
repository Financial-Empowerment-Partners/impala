-- Applet 0.2 has no RSA key (GET_RSA_PUB_KEY 0x07 answers 0x6D00), so a real
-- card can never satisfy `rsa_pubkey NOT NULL UNIQUE`: no value exists to send,
-- and a shared placeholder would collide on the UNIQUE constraint. Card auth
-- never reads this column (card_auth.rs verifies against ec_pubkey).
--
-- Make the column nullable and keep uniqueness only among present keys.
-- Postgres UNIQUE already treats NULLs as distinct; the partial index states
-- that intent explicitly and replaces the redundant non-unique lookup index.
--
-- Run before rolling a binary that inserts NULL (RUN_MODE=migrate). The old
-- binary always inserts a non-null value, so it stays compatible afterwards.

ALTER TABLE card ALTER COLUMN rsa_pubkey DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_card_rsa_pubkey
    ON card(rsa_pubkey) WHERE rsa_pubkey IS NOT NULL;

ALTER TABLE card DROP CONSTRAINT IF EXISTS card_rsa_pubkey_key;
DROP INDEX IF EXISTS idx_card_rsa_pubkey;
