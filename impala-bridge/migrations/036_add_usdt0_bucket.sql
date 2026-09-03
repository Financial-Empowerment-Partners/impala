-- 036: USDT0 reserve bucket.
--
-- Tether's USDT0 (the LayerZero OFT form of USDT) is issued natively on
-- Stellar as a classic asset since 2026-09-02. The conversion reserve can now
-- hold, recognize, refund, and pay it out as a second issuer-pinned
-- stablecoin alongside USDC.
--
-- This migration only seeds the bucket row (031 precedent: every bucket is
-- seeded up front, enabled or not, so the admin UI has a row to edit and the
-- journal's FK has a target). It changes NO behavior by itself: the bucket is
-- inert until `RESERVE_USDT0_ISSUER` is configured — nothing classifies to
-- it and nothing pays out of it before then. The on-chain identity
-- `(code, issuer)` is deliberately NOT stored here: it is operator-supplied
-- configuration validated at startup, because the issuer differs per network
-- and is the entire trust anchor (a "USDT0" from any other issuer is a
-- foreign token, not money).
--
-- Seven decimal places, like every Stellar-native bucket (031 §minor_scale).
-- Replenishment cycle kinds (032 `chk_crr_kind`) stay USDC-only: a USDT0
-- bucket that drains is topped up by ops (unmemoed inflow -> unmatched queue
-- -> credit), the same manual path USDC had before 032.
INSERT INTO conversion_reserve (currency, minor_scale)
    VALUES ('USDT0', 7)
    ON CONFLICT (currency) DO NOTHING;
