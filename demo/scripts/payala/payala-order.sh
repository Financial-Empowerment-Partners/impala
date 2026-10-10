#!/usr/bin/env bash
# Build and POST a Payala "Order" (a remote transfer the server signs itself; the balances move on the
# server). No card private key is needed: the API checks that sender_public_key equals the sender card's
# stored signing key and that hash == sha256(preimage). demo/payala-stub/server.mjs implements exactly
# this contract, so a wrong preimage layout here is refused there (400 hash_mismatch).
#
# Usage: scripts/payala/payala-order.sh <sender_uuid> <recipient_uuid> <amount_cents> <device_id_hex24>
# Prints the created transfer (JSON) on stdout; exit 1 on rejection.
# Preimage (256 bytes, big-endian — the Order encoding of the Payala API; in this repo the authority is
# demo/payala-stub/server.mjs orderPreimage(), pinned by the layout test in demo/payala-stub/server.test.mjs):
#   int64 created_at_ms | sender uuid(16) | recipient uuid(16) | "USD\0" | int32 amount |
#   device_id(12) | int32 0 | sender_public_key X||Y (64) | 64 zero bytes | 64 zero bytes
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq openssl od
require_payala
[ $# -eq 4 ] || die "usage: $0 <sender_uuid> <recipient_uuid> <amount_cents> <device_id_hex24>"
SENDER="$1"; RECIPIENT="$2"; CENTS="$3"; DEVICE_HEX="$(printf '%s' "$4" | tr 'A-F' 'a-f')"
[ "${#DEVICE_HEX}" -eq 24 ] || die "device_id must be 24 hex chars (12 bytes), got ${#DEVICE_HEX}"
printf '%s' "$DEVICE_HEX" | grep -Eq '^[0-9a-f]{24}$' || die "device_id must be hex (got '$DEVICE_HEX')"
printf '%s' "$CENTS" | grep -Eq '^[0-9]+$' || die "amount must be an integer number of cents"
[ "$CENTS" -ge 1 ] || die "amount must be at least 1 cent"
[ "$CENTS" -le 2147483647 ] || die "amount out of int32 range"
role="$(payala_role_for_id "$SENDER")" || die "unknown sender $SENDER (not one of the demo users)"
PUB="$(payala_pub_hex "$role")"
[ "${#PUB}" -eq 128 ] || die "bad public key for $role"

SECS="$(now_s)"; MS=$((SECS * 1000)); CREATED="$(utc_from_epoch "$SECS")"
ZERO64="$(printf '%0128d' 0)"   # 64 zero bytes as hex
PRE="$(printf '%016x' "$MS")$(uuid_hex "$SENDER")$(uuid_hex "$RECIPIENT")55534400$(printf '%08x' "$CENTS")${DEVICE_HEX}00000000${PUB}${ZERO64}${ZERO64}"
[ "${#PRE}" -eq 512 ] || die "internal: preimage is ${#PRE} hex chars, expected 512"
HASH_B64="$(printf '%s' "$PRE" | hex_to_bin | openssl dgst -sha256 -binary | openssl base64 -A)"
DEV_B64="$(printf '%s' "$DEVICE_HEX" | hex_to_b64)"
PUB_B64="$(printf '%s' "$PUB" | hex_to_b64)"

body="$(jq -cn --arg d "$DEV_B64" --arg s "$SENDER" --arg r "$RECIPIENT" --argjson a "$CENTS" --arg c "$CREATED" --arg h "$HASH_B64" --arg p "$PUB_B64" \
  '{device_id:$d, sender_id:$s, sender_name:"", recipient_id:$r, recipient_name:"", currency:"USD", amount:$a, counter:0, created_at:$c, hash:$h, sender_public_key:$p}')"
# no Authorization header: the stub has no auth (it journals any header sent; scenario 08 asserts none ever was)
out="$(curl -sS -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "$body" "$PAYALA_URL/transfers/order")"
code="${out##*$'\n'}"; resp="${out%$'\n'*}"
if [ "$code" = "403" ]; then
  die "order refused (403 sender_public_key_mismatch): the stub's card key for $role is not state/keys/$role.pub.hex — the demo keys were regenerated after the stub's ledger was seeded (the seed never overwrites an existing card). scripts/reset.sh --yes, then scripts/up.sh && scripts/seed.sh"
fi
[ "$code" = "200" ] || die "order rejected (HTTP $code): $resp"
[ "$resp" != "null" ] || die "order returned null: sender $SENDER has no card_id"
printf '%s' "$resp" | jq -e '.counter < 0' >/dev/null || die "unexpected order response: $resp"
printf '%s\n' "$resp"
log "  payala order ok: $CENTS cents $role -> $(payala_role_for_id "$RECIPIENT" || echo "$RECIPIENT"); payala_tx_id=$(printf '%s' "$resp" | jq -r .hash | b64_to_hex)"
