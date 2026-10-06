# Runbook — Card program issuer key and card certificates

**Audience:** engineer bringing up card issuance (personalizing JavaCards that
can log in and, once the offline issuance/redemption lane lands, carry value).
Generating the key and certifying cards require the **admin or key-custodian**
role (`manage_keys`); auditors can read the key inventory (`read_keys`).

**Status.** Migration `039_card_issuer.sql` and the endpoints below are the
issuer-custody half of the offline lane (handoff lane C1). Offline issuance
and redemption (lane C2: `/offline/*`, `/admin/offline/*`) are **not built**;
`offline_policy.enabled` stays `false` and its caps stay `0`.

---

## What the issuer key is

One P-256 key per deployment. It signs:

- **card certificates** — ECDSA over the 114-byte CERT message
  `"IMPALA-CERT:" ‖ 0x01 ‖ programId ‖ accountId ‖ currency ‖ cardPubKey`
  (`impala-card/docs/transfer-protocol.md` §2). A card refuses to finish
  personalization (and so refuses `SIGN_AUTH`, i.e. card login) until it holds
  a certificate that verifies under its issuer key;
- (lane C2) every credit the bridge sends to a card.

Whoever holds it can certify any key as a card and mint value onto any card in
the program. So it is **generate-only**, exactly like the conversion-reserve
seed: created inside the bridge, sealed by the seed protector (KMS / Vault /
OpenBao), never imported, never exported. No response, log line or event ever
carries private bytes — fingerprints and public keys only.

The first generation also mints the **program identity**, which never changes:

| Field | Use |
|---|---|
| `program_id_hex` (16 random bytes) | PERSONALIZE part A on every card; inside every CERT/XFER message |
| `redemption_uuid` | the recipient a card names when it signs a redemption (lane C2) |

## Prerequisites

- Migration 039 applied (`RUN_MODE=migrate`) **before** rolling a binary that
  serves these routes. 038 (`rsa_pubkey` optional, so applet 0.2 cards can
  register) must be applied too.
- `KEY_IMPORT_ENABLED=true` and `SEED_PROTECTION_BACKEND` = `kms`, `vault` or
  `openbao` (the same gate as `/admin/keys`; see `import-keys.md`).

## Generate the key (once per deployment)

```bash
curl -sS -X POST "$BRIDGE/admin/card-issuer/generate" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' -d '{}'
```

Response: `{version, public_key_hex, fingerprint, redemption_uuid, program_id_hex, replaced:false, note}`.
Event: `custody.issuer_key_generated {version, fingerprint, replaced}`.

Check the public view terminals read:

```bash
curl -sS "$BRIDGE/card-issuer"
# {"configured":true,"version":1,"public_key_hex":"04…","fingerprint":"…","redemption_uuid":"…","program_id_hex":"…"}
```

## Certify a card

The card must be registered by its holder first (`POST /card` with the
130-hex uncompressed `ec_pubkey`, no `rsa_pubkey`) and its account id must be
a UUID (the CERT message binds the UUID the card signs with).

```bash
curl -sS -X POST "$BRIDGE/admin/cards/$CARD_ID/certificate" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d '{"currency":"XLM","card_minor_scale":7}'
```

Response: `{card_id, issuer_version, issuer_cert_hex, cert_message_hex, cert_id,
issuer_public_key_hex, program_id_hex, currency, card_minor_scale, replaced}` —
exactly what PERSONALIZE needs (A: `program_id_hex`; B: `issuer_public_key_hex`;
C: `issuer_cert_hex`). Certificates are **write-once**: a second call answers
409 unless `"recertify": true` (only for a card that tore before personalization
committed, or after a key rotation). Event: `custody.card_certified`.

`currency` must be `XLM` or a configured reserve stablecoin (`USDC`, `USDT0`);
the pilot is XLM with `card_minor_scale` 7.

**In practice use the issuance tool**, which runs the whole ceremony
(INITIALIZE, per-card SCP03 keys, register, certify, PERSONALIZE, PINs,
read-back) and is idempotent per step:

```bash
cd impala-card
export IMPALA_ISSUE_KMK=… IMPALA_HOLDER_TOKEN=… IMPALA_OPERATOR_TOKEN=…
./gradlew :tools:issue:run --args="--transport pcsc --account $HOLDER_UUID --bridge $BRIDGE"
```

See `impala-card/README.md` → "Issuance tool".

## Rotate the key

Rotation invalidates the program key installed on every card: cards keep
verifying credits signed by the issuer **they** hold, so after rotation every
card must be re-personalized (re-issued) and re-certified before new
issuance. Old versions stay `superseded` (public key kept) so certificates
they signed still verify.

```bash
FP=$(curl -sS "$BRIDGE/card-issuer" | jq -r .fingerprint)
curl -sS -X POST "$BRIDGE/admin/card-issuer/generate" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"confirm_supersede\":\"$FP\",\"confirm_phrase\":\"replace card-issuer $NETWORK\"}"
```

The phrase names the network (`testnet` / `pubnet`) to catch the commonest
operator error: the right action in the wrong environment.

## Inventory

`GET /admin/card-issuer` (`read_keys`): every version with state, public key,
fingerprint, who generated it and when, plus the program identity.
