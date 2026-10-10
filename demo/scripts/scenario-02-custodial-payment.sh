#!/usr/bin/env bash
# Scenario 02 — a custodial payment on Stellar testnet: the agent's session asks the bridge to sign
# N XLM to the beneficiary from the seed the bridge holds (POST /managed-account/sign, idempotent),
# Horizon confirms it, the bridge's intent and transaction rows agree, and the same idempotency key
# replays the recorded outcome instead of paying twice.
# Usage: scripts/scenario-02-custodial-payment.sh [amount_xlm]   (default DEMO_PAYMENT_XLM)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq
require_env AGENT_G BENEF_G PAYALA_AGENT_ID PAYALA_ADMIN_ID IMPALA_AGENT_PASSWORD IMPALA_ADMIN_PASSWORD
XLM="${1:-${DEMO_PAYMENT_XLM:-25}}"
printf '%s' "$XLM" | grep -Eq '^[0-9]+$' || die "amount must be a whole number of XLM (got $XLM)"
STROOPS=$(( XLM * 10000000 ))
t0="$(now_s)"
hr "scenario 02: custodial payment ($XLM XLM agent -> beneficiary)"

info "before"
B_A="$(horizon_native_balance "$AGENT_G")"; B_B="$(horizon_native_balance "$BENEF_G")"
log "  agent       $AGENT_G  $B_A XLM"
log "  beneficiary $BENEF_G  $B_B XLM"

info "1/4 agent signs $XLM XLM -> beneficiary via the bridge (POST /managed-account/sign)"
AGENT_JWT="$(bridge_login "$PAYALA_AGENT_ID" "$IMPALA_AGENT_PASSWORD")"
KEY="demo-$(date -u +%Y%m%dT%H%M%SZ)"
body="$(jq -cn --arg id "$PAYALA_AGENT_ID" --arg d "$BENEF_G" --arg a "$XLM" --arg k "$KEY" '{payala_account_id:$id,destination:$d,amount:$a,memo:"impala-demo",idempotency_key:$k}')"
resp="$(bridge_api POST /managed-account/sign "$AGENT_JWT" "$body")"
case "$(http_code)" in
  200) ;;
  202) warn "bridge answered 202 ($(printf '%s' "$resp" | jq -r .status)); polling the intent by idempotency key — never resending"
       ambiguous() { # the outcome is unknown: record it, say so, exit 3 — a re-run with the SAME key replays, a different key would pay twice
         fail_line "payment outcome AMBIGUOUS (intent $(printf '%s' "$resp" | jq -r '.intent_id // "?"'), idempotency key $KEY): do not resend; check the intent and Horizon"
         record_json scenario-02-custodial-payment "$(jq -cn --arg k "$KEY" --argjson r "$resp" --arg at "$(utc_now)" '{scenario:"scenario-02-custodial-payment",status:"ambiguous",idempotency_key:$k,intent:$r,passed:0,failed:1,finished_at:$at}')"
         exit 3
       }
       i=0; until printf '%s' "$resp" | jq -e '.status=="settled"' >/dev/null; do
         printf '%s' "$resp" | jq -e '.status=="rejected" or .status=="failed"' >/dev/null && die "payment rejected: $resp"
         printf '%s' "$resp" | jq -e '.status=="ambiguous"' >/dev/null && ambiguous
         i=$((i + 1)); [ "$i" -le 30 ] || ambiguous; sleep 3
         resp="$(bridge_api GET "/managed-account/intents?payala_account_id=$PAYALA_AGENT_ID&idempotency_key=$KEY" "$AGENT_JWT" | jq -c '.data[0] // {}')"
       done ;;
  *) die "sign failed ($(http_code)): $resp" ;;
esac
HASH="$(printf '%s' "$resp" | jq -r .stellar_hash)"; BTXID="$(printf '%s' "$resp" | jq -r .btxid)"; INTENT="$(printf '%s' "$resp" | jq -r .intent_id)"
[ "${#HASH}" -eq 64 ] || die "no stellar_hash in: $resp"
ok "settled: stellar_hash=$HASH btxid=$BTXID intent=$INTENT"

info "2/4 confirming on Horizon testnet"
tx="$(horizon_wait_tx "$HASH" 20)" || die "tx $HASH not found on Horizon"
LEDGER="$(printf '%s' "$tx" | jq -r .ledger)"; FEE="$(printf '%s' "$tx" | jq -r .fee_charged)"
op="$(curl -fsS "$HORIZON_URL/transactions/$HASH/operations" | jq -c '._embedded.records[0]')"
emit_txid custodial_payment "$HASH" "$XLM XLM ${AGENT_G:0:8}… -> ${BENEF_G:0:8}… ledger $LEDGER"
check_jq "horizon: transaction successful in ledger $LEDGER" '.successful==true' "$tx"
check_jq "horizon: memo 'impala-demo' on chain" '.memo_type=="text" and .memo=="impala-demo"' "$tx"
check_jq "horizon: payment $XLM XLM from the agent's custodial address to the beneficiary's" ".type==\"payment\" and .asset_type==\"native\" and .amount==\"$(stroops_to_xlm "$STROOPS")\" and .from==\"$AGENT_G\" and .to==\"$BENEF_G\"" "$op"

info "3/4 the bridge's own records"
ADMIN_JWT="$(admin_jwt)"
intent="$(bridge_api GET "/admin/custody/intents/$INTENT" "$ADMIN_JWT")"
check_jq "bridge: intent settled, $STROOPS stroops to the beneficiary, idempotency_key '$KEY'" ".status==\"settled\" and .amount_minor==$STROOPS and .idempotency_key==\"$KEY\" and .destination==\"$BENEF_G\" and .stellar_hash==\"$HASH\" and .btxid==\"$BTXID\"" "$intent"
byhash="$(bridge_api GET "/transactions?q=$HASH&per_page=10" "$ADMIN_JWT")"
check_jq "bridge: one custodial_sign transaction row carries the hash, memo and source" "[.data[]|select(.origin==\"custodial_sign\" and .stellar_hash==\"$HASH\" and .source_account==\"$AGENT_G\")]|length==1" "$byhash"
own="$(bridge_api GET "/transactions?q=$HASH&per_page=10" "$AGENT_JWT")"
check_jq "bridge: the agent sees its own row (owner-scoped listing)" "[.data[]|select(.stellar_hash==\"$HASH\")]|length==1" "$own"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$ADMIN_JWT")"
check_jq "bridge: a custodial.payment_settled event names the intent" "[.events[]|select(.event_type==\"custodial.payment_settled\" and .payload.intent_id==\"$INTENT\")]|length==1" "$events"

info "4/4 balances and replay"
A_A="$(horizon_native_balance "$AGENT_G")"; A_B="$(horizon_native_balance "$BENEF_G")"
check "stellar: beneficiary +$XLM XLM exactly ($B_B -> $A_B)" [ $(( $(xlm_to_stroops "$A_B") - $(xlm_to_stroops "$B_B") )) -eq "$STROOPS" ]
check "stellar: agent -$XLM XLM and the $FEE-stroop fee ($B_A -> $A_A)" [ $(( $(xlm_to_stroops "$B_A") - $(xlm_to_stroops "$A_A") )) -eq $(( STROOPS + FEE )) ]
replay="$(bridge_api POST /managed-account/sign "$AGENT_JWT" "$body")"
check_jq "replay with the same idempotency key is replayed, same hash, nothing paid twice" ".replayed==true and .stellar_hash==\"$HASH\"" "$replay"
check "stellar: beneficiary balance unchanged by the replay" [ "$(horizon_native_balance "$BENEF_G")" = "$A_B" ]
log "  agent       $B_A -> $A_A XLM"
log "  beneficiary $B_B -> $A_B XLM"
log "  UI: $UI_URL -> Transactions -> search '$HASH'"

finish_scenario scenario-02-custodial-payment "$(jq -cn --arg h "$HASH" --arg b "$BTXID" --arg i "$INTENT" --argjson xlm "$XLM" --argjson st "$STROOPS" --arg k "$KEY" --argjson l "$LEDGER" --argjson fee "$FEE" \
  --arg hu "$(horizon_tx_url "$HASH")" --arg eu "$(explorer_tx_url "$HASH")" --arg from "$AGENT_G" --arg to "$BENEF_G" \
  '{stellar_hash:$h,btxid:$b,intent_id:$i,xlm:$xlm,stroops:$st,idempotency_key:$k,ledger:$l,fee_charged_stroops:$fee,from:$from,to:$to,horizon_url:$hu,explorer_url:$eu}')" "$t0"
