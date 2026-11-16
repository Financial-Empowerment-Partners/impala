#!/usr/bin/env bash
# Scenario 15 — the card's own rules: what a SEP-10 smartcard signs, and what it refuses.
# The card's Stellar key signs one kind of thing only: the hash of a transaction the CARD ITSELF read and
# found to be a SEP-10 challenge for its key (docs/sep10-card-keys.md §3.3). This lane shows that from the
# outside, with the simulated card in the field and nothing but curl and the Python standard library
# (scripts/sep10-card.py: the APDUs written out by hand, plain XDR, the RFC 8032 verification algorithm;
# no card SDK, no app, no Stellar library):
#   1. the card in the simulator names its Stellar key and the engine that made it (GET_STELLAR_KEY);
#   2. the bridge's challenge for that key is handed to the card (SIGN_SEP10 BEGIN / FINISH): the card
#      answers a signature that verifies under its public key, and the bridge mints the holder's session;
#   3. a challenge is good for one sign-in: the same signed envelope is refused the second time;
#   4. everything else is refused by the card with a status word and no signature: a payment out of the
#      card's own address, a payment dressed up as a challenge, the real challenge with sequence number 1,
#      the real challenge with a byte added, a real challenge made for another account;
#   5. after the refusals the card still signs a challenge.
# It runs on whatever card the simulator serves: DEMO_CARD_PLATFORM=jc305 (the default CAP's software
# Ed25519 engine on a JavaCard 3.0.5 card) or jc32 (the native CAP on a JavaCard 3.2 card's own EdDSA).
# Usage: scripts/scenario-15-sep10-card-rules.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq python3
require_env DEMO_HOLDER_ID PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD HOLDER_G AGENT_G
t0="$(now_s)"
hr "scenario 15: what the SEP-10 card signs, and what it refuses (simulated card on 127.0.0.1:$SIM_PORT)"
wait_bridge 10
if ! sep10_enabled; then
  warn "DEMO_SEP10=$DEMO_SEP10: the bridge runs without SEP-10, so there is no challenge to hand to the card; nothing to do"
  record_json scenario-15-sep10-card-rules "$(jq -cn --arg at "$(utc_now)" '{scenario:"scenario-15-sep10-card-rules", status:"skipped", reason:"DEMO_SEP10 is off", finished_at:$at}')"
  exit 0
fi
CARDPY="$DEMO_DIR/scripts/sep10-card.py"
BASE="http://$SEP10_HOME_DOMAIN"
PUBNET_PASSPHRASE="Public Global Stellar Network ; September 2015"
card() { python3 "$CARDPY" "$@"; }
# sep10_http <METHOD> <url> [json-body] -> the body; the status afterwards in $(http_code). These are
# pre-auth requests (30 per 60 s per source): a 429 is paced with one wait, not failed.
sep10_http() {
  local method="$1" url="$2" body="${3:-}" out try
  for try in 1 2; do
    if [ -n "$body" ]; then
      out="$(printf '%s' "$body" | sep10_curl -sS -X "$method" -H 'Content-Type: application/json' --data-binary @- -w '\n%{http_code}' "$url")" || { printf '000' > "$HTTP_CODE_FILE"; return 1; }
    else
      out="$(sep10_curl -sS -X "$method" -w '\n%{http_code}' "$url")" || { printf '000' > "$HTTP_CODE_FILE"; return 1; }
    fi
    printf '%s' "${out##*$'\n'}" > "$HTTP_CODE_FILE"
    if [ "$(http_code)" = 429 ] && [ "$try" = 1 ]; then
      warn "pre-auth budget exhausted (429: 30 requests per 60 s from this host); waiting 61 s, then one retry"
      sleep 61; continue
    fi
    break
  done
  printf '%s\n' "${out%$'\n'*}"
}

info "1/5 the card in the simulator, asked over its socket"
# A running simulator is one card on one kind of hardware; the card must be the one scenario 05 issued.
SIM_HW="$("$DEMO_DIR/scripts/simulator.sh" hardware 2>/dev/null | cut -f1 || true)"
if ! "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1 || [ ! -f "$RECORDS_DIR/scenario-05-card-issue.json" ] || [ "$SIM_HW" != "$DEMO_CARD_PLATFORM" ]; then
  log "  no issued card of $DEMO_CARD_PLATFORM hardware in a running simulator: running scenario 05 first"
  "$DEMO_DIR/scripts/scenario-05-card-issue.sh" >/dev/null
fi
HW="$("$DEMO_DIR/scripts/simulator.sh" hardware)"
SIM_PLATFORM="$(printf '%s' "$HW" | cut -f1)"; SIM_LEVEL="$(printf '%s' "$HW" | cut -f2)"; SIM_CAP="$(printf '%s' "$HW" | cut -f3)"
key="$(card key --port "$SIM_PORT")" || die "the simulated card did not answer GET_STELLAR_KEY (scripts/simulator.sh status)"
CARD_G="$(printf '%s' "$key" | jq -r '.address // empty')"; CARD_PUB="$(printf '%s' "$key" | jq -r '.public_key // empty')"; CARD_ENGINE="$(printf '%s' "$key" | jq -r '.engine // empty')"
check_jq "GET_STELLAR_KEY: the card holds a Stellar key made by its $SIM_CAP engine ($SIM_PLATFORM hardware, JavaCard $SIM_LEVEL), with the cross-signatures of a personalized card" \
  ".engine==\"$SIM_CAP\" and .personalized==true and (.address | test(\"^G[A-Z2-7]{55}\$\"))" "$key"
[ -n "$CARD_G" ] || die "this card has no Stellar key (a legacy card): the SEP-10 lanes need jc305, jc31 or jc32 hardware"
check "it is the address the issuance record names ($CARD_G)" [ "$CARD_G" = "$(record_get scenario-05-card-issue .stellar_address)" ]
check_eval "the bridge holds exactly one active card with that Stellar address, and it is the holder's" \
  "[ \"\$(psql_impala -tAc \"select count(*) from card where stellar_address='$CARD_G' and is_delete=false and account_id='$DEMO_HOLDER_ID'\" | tr -d '[:space:]')\" = 1 ]"

info "2/5 the bridge's challenge, signed by the card and accepted by the bridge"
sep10_wait_active "$(admin_jwt)" 240 >/dev/null || die "SEP-10 is not in service on this bridge (scripts/seed.sh arms it; scripts/status.sh shows the key)"
sign_ins() { compose logs --no-color impala-bridge 2>/dev/null | grep -c "sep10: card key $CARD_G signed in; tokens issued for account_id=$DEMO_HOLDER_ID" || true; }
before="$(sign_ins)"
ch="$(sep10_http GET "$BASE/auth/sep10?account=$CARD_G")"
check "GET /auth/sep10?account=<the card's address> answers 200" [ "$(http_code)" = 200 ]
TX="$(printf '%s' "$ch" | jq -r '.transaction // empty')"
shape="$(python3 "$DEMO_DIR/scripts/sep10-challenge.py" "$TX" 2>/dev/null || echo '{}')"
SERVER_G="$(printf '%s' "$shape" | jq -r '.source // empty')"
check_jq "the challenge is a transaction with sequence number 0 whose first operation is \"$SEP10_HOME_DOMAIN auth\", sourced by the card's key" \
  ".sequence==0 and .operations[0].source==\"$CARD_G\" and .operations[0].name==\"$SEP10_HOME_DOMAIN auth\"" "$shape"
check "the challenge carries the bridge's own signature: it verifies under its source account $SERVER_G for the testnet passphrase (the check a client makes before any card is asked to sign)" \
  card server-signed "$TX" --passphrase "$TESTNET_PASSPHRASE"
signed="$(card sign --envelope "$TX" --passphrase "$TESTNET_PASSPHRASE" --port "$SIM_PORT")" || signed='{}'
check_jq "SIGN_SEP10: the card read the $(printf '%s' "$signed" | jq -r '.tx_bytes // "?"')-byte transaction itself ($(printf '%s' "$signed" | jq -r '.apdus // "?"') APDUs) and answered SW 9000 with a 64-byte signature" \
  '.sw=="9000" and (.signature | length)==128' "$signed"
SIG="$(printf '%s' "$signed" | jq -r '.signature // empty')"; TX_HASH="$(printf '%s' "$signed" | jq -r '.tx_hash // empty')"
check "the signature is the card key's over the transaction hash $TX_HASH (Ed25519 as in RFC 8032, checked here without the card, its SDK or the bridge)" \
  card verify --envelope "$TX" --passphrase "$TESTNET_PASSPHRASE" --public-key "$CARD_PUB" --signature "$SIG"
other_network() { ! card verify --envelope "$TX" --passphrase "$PUBNET_PASSPHRASE" --public-key "$CARD_PUB" --signature "$SIG"; }
check "it is a testnet signature: the same bytes do not verify for the public network's passphrase (the card hashed the network id it was given)" other_network
SIGNED_ENV="$(card attach "$TX" --public-key "$CARD_PUB" --signature "$SIG")"
resp="$(sep10_http POST "$BASE/auth/sep10" "$(jq -cn --arg t "$SIGNED_ENV" '{transaction:$t}')")"
check "POST /auth/sep10 with the card's signature appended answers 200" [ "$(http_code)" = 200 ]
check_jq "the answer carries SEP-10's token and the bridge's token pair" '.success==true and (.token | type)=="string" and (.temporal_token | type)=="string" and (.refresh_token | type)=="string"' "$resp"
TOKEN="$(printf '%s' "$resp" | jq -r '.temporal_token // empty')"
check "the session is the card holder's (the token's sub is $DEMO_HOLDER_ID)" [ "$(jwt_claim "$TOKEN" sub)" = "$DEMO_HOLDER_ID" ]
check_jq "GET /mfa/status with that token: the card is the session's one verified factor (amr has sc, and is not multi-factor)" \
  '(.amr | index("sc")) != null and (.amr | index("mfa")) == null and .mfa != true' "$(bridge_api GET /mfa/status "$TOKEN")"
sleep 1
check "bridge log: one more 'sep10: card key $CARD_G signed in' line for the holder than before this tap" [ "$(sign_ins)" -eq $(( before + 1 )) ]

info "3/5 one challenge, one sign-in"
resp2="$(sep10_http POST "$BASE/auth/sep10" "$(jq -cn --arg t "$SIGNED_ENV" '{transaction:$t}')")"
replay="$(http_code)"; leaked=0; printf '%s' "$resp2" | grep -qi 'token' && leaked=1
check "the same signed challenge, posted a second time, is refused with the generic 401 and no token" [ "$replay" = 401 -a "$leaked" = 0 ]

info "4/5 what the card refuses: every answer is a status word, and nothing is signed"
REFUSALS='[]'
# refuse <case> <expected status word> <label> <transaction hex>
refuse() {
  local id="$1" want="$2" label="$3" tx="$4" out
  out="$(card sign --tx "$tx" --passphrase "$TESTNET_PASSPHRASE" --port "$SIM_PORT")" || out='{}'
  check_jq "$label: SW $(printf '%s' "$out" | jq -r '.sw // "?"') at $(printf '%s' "$out" | jq -r '.step // "?"'), no signature ($(printf '%s' "$out" | jq -r '.meaning // "?"'))" \
    ".sw==\"$want\" and (has(\"signature\") | not)" "$out"
  REFUSALS="$(printf '%s' "$REFUSALS" | jq -c --arg id "$id" --arg want "$want" --argjson o "$out" '. + [{case:$id, expected:$want, sw:($o.sw // null), step:($o.step // null), meaning:($o.meaning // null)}]')"
}
refuse payment-from-card 6243 "a payment of 100 XLM out of the card's own address, with a real sequence number" \
  "$(card variant payment --source "$CARD_G" --op-source "$CARD_G" --destination "$AGENT_G" --stroops 1000000000)"
refuse payment-as-challenge 6242 "the same payment dressed as a challenge (sequence 0, time bounds, sourced by the bridge's signing key)" \
  "$(card variant payment --source "$SERVER_G" --op-source "$CARD_G" --destination "$AGENT_G" --stroops 1000000000 --challenge-shaped)"
TX2="$(sep10_http GET "$BASE/auth/sep10?account=$CARD_G" | jq -r '.transaction // empty')"
refuse sequence-one 6241 "the bridge's own challenge with its sequence number changed from 0 to 1" "$(card variant sequence "$TX2")"
refuse trailing-byte 6240 "the bridge's own challenge with one byte added after its end" "$(card variant trailing "$TX2")"
OTHER="$(sep10_http GET "$BASE/auth/sep10?account=$HOLDER_G" | jq -r '.transaction // empty')"
refuse another-account 6243 "a real challenge the bridge made for another account (the holder's custodial address)" "$(card tx "$OTHER")"
check_jq "a FINISH with nothing staged answers SW 6985: a refused transaction leaves nothing behind to finish" '.sw=="6985"' "$(card finish --port "$SIM_PORT" || echo '{}')"

info "5/5 after the refusals the card still signs a challenge"
signed2="$(card sign --envelope "$TX2" --passphrase "$TESTNET_PASSPHRASE" --port "$SIM_PORT")" || signed2='{}'
check_jq "the untouched challenge is signed (SW 9000): the refusals changed nothing on the card" '.sw=="9000" and (.signature | length)==128' "$signed2"
check "and that signature verifies under the card's key too" \
  card verify --envelope "$TX2" --passphrase "$TESTNET_PASSPHRASE" --public-key "$CARD_PUB" --signature "$(printf '%s' "$signed2" | jq -r '.signature // "00"')"

# The record keeps public values only: the address, the transaction hash, status words. No token, no signature.
finish_scenario scenario-15-sep10-card-rules "$(jq -cn --arg g "$CARD_G" --arg e "$CARD_ENGINE" --arg p "$SIM_PLATFORM" --arg l "$SIM_LEVEL" --arg cap "$SIM_CAP" \
  --arg h "$TX_HASH" --arg d "$SEP10_HOME_DOMAIN" --arg srv "$SERVER_G" --argjson replay "${replay:-0}" --argjson r "$REFUSALS" \
  --argjson apdus "$(printf '%s' "$signed" | jq '.apdus // 0')" --argjson bytes "$(printf '%s' "$signed" | jq '.tx_bytes // 0')" \
  '{stellar_address:$g, card_engine:$e, card_platform:$p, card_javacard:$l, card_cap:$cap, home_domain:$d, server_signing_key:$srv,
    signed:{sw:"9000", tx_hash:$h, tx_bytes:$bytes, apdus:$apdus}, replay_status:$replay, refusals:$r}')" "$t0"
