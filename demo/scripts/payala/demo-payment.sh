#!/usr/bin/env bash
# The forward direction: the agent pays the beneficiary on Stellar testnet through the bridge (custodial
# sign), Horizon confirms it, the relay reflects it into the Payala stub as an Order (device_id = the first
# 12 bytes of the Stellar hash) and mirrors the Payala transfer back into the bridge (two payala_sync rows).
# Usage: scripts/payala/demo-payment.sh [amount_xlm]   (default DEMO_PAYMENT_XLM from .env)
# Every id of the run (hash, btxid, intent, Payala tx id, ledger, lookup URLs) is written to
# state/records/payala-last-payment.json.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq openssl od
require_payala
require_env AGENT_G BENEF_G PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID PAYALA_ADMIN_ID IMPALA_AGENT_PASSWORD IMPALA_ADMIN_PASSWORD DEMO_CENTS_PER_XLM
XLM="${1:-${DEMO_PAYMENT_XLM:-25}}"
printf '%s' "$XLM" | grep -Eq '^[0-9]+$' || die "amount must be a whole number of XLM for this demo (got $XLM)"
CENTS=$(( XLM * DEMO_CENTS_PER_XLM ))
hr "payala relay, forward: $XLM XLM agent -> beneficiary on Stellar, reflected as $CENTS cents in Payala"

info "before"
B_AX="$(horizon_native_balance "$AGENT_G")"; B_BX="$(horizon_native_balance "$BENEF_G")"
B_AC="$(payala_balance "$PAYALA_AGENT_ID")"; B_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
log "  Stellar  agent $B_AX XLM   beneficiary $B_BX XLM"
log "  Payala   agent $B_AC cents  beneficiary $B_BC cents"

info "1/4 agent signs $XLM XLM -> beneficiary via the bridge (POST /managed-account/sign)"
AGENT_JWT="$(relay_token "$PAYALA_AGENT_ID" "$IMPALA_AGENT_PASSWORD")"
KEY="payala-demo-$(date -u +%Y%m%dT%H%M%SZ)"
body="$(jq -cn --arg id "$PAYALA_AGENT_ID" --arg d "$BENEF_G" --arg a "$XLM" --arg k "$KEY" '{payala_account_id:$id,destination:$d,amount:$a,memo:"payala-demo",idempotency_key:$k}')"
resp="$(bridge_api POST /managed-account/sign "$AGENT_JWT" "$body")"
case "$(http_code)" in
  200) ;;
  202) warn "bridge answered 202 ($(printf '%s' "$resp" | jq -r .status)); polling the intent by idempotency key — never resending"
       ambiguous() { # the outcome is unknown: record it, say so, exit 3 — a re-run with the SAME key replays, a different key would pay twice
         fail_line "payment outcome AMBIGUOUS (intent $(printf '%s' "$resp" | jq -r '.intent_id // "?"'), idempotency key $KEY): do not resend; check the intent and Horizon"
         record_json payala-last-payment "$(jq -cn --arg k "$KEY" --argjson r "$resp" --arg at "$(utc_now)" '{direction:"impala_to_payala",status:"ambiguous",idempotency_key:$k,intent:$r,recorded_at:$at}')"
         exit 3
       }
       i=0; until printf '%s' "$resp" | jq -e '.status=="settled"' >/dev/null; do
         printf '%s' "$resp" | jq -e '.status=="rejected"' >/dev/null && die "payment rejected: $resp"
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
printf '%s' "$tx" | jq -e '.successful==true' >/dev/null || die "Horizon reports the transaction as failed"
LEDGER="$(printf '%s' "$tx" | jq -r .ledger)"
ok "ledger $LEDGER: $(curl -fsS "$HORIZON_URL/transactions/$HASH/operations" | jq -r '._embedded.records[0] | "\(.type) \(.amount) XLM \(.from[0:8])… -> \(.to[0:8])…"')"
emit_txid impala_to_payala "$HASH" "$XLM XLM ${AGENT_G:0:8}… -> ${BENEF_G:0:8}… ledger $LEDGER"

info "3/4 reflecting into the Payala stub (relay: event feed -> intent -> POST /transfers/order) and mirroring back"
REC="$RELAY_DIR/reflected/$HASH.json"
i=0
until [ -f "$REC" ]; do
  i=$((i + 1)); [ "$i" -le 6 ] || die "the relay did not reflect $HASH (see warnings above)"
  [ "$i" -eq 1 ] || { log "  settled event not visible yet; polling again in 5s ($i/6)"; sleep 5; }
  "$DEMO_DIR/scripts/payala/reflect.sh" --once --sync-back
done
PTX="$(jq -r .payala_tx_id "$REC")"
[ "${#PTX}" -eq 64 ] || die "the relay recorded $HASH without a Payala tx id: $(jq -c . "$REC")"

info "4/4 after"
A_AX="$(horizon_native_balance "$AGENT_G")"; A_BX="$(horizon_native_balance "$BENEF_G")"
A_AC="$(payala_balance "$PAYALA_AGENT_ID")"; A_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
log "  Stellar  agent $B_AX -> $A_AX XLM   beneficiary $B_BX -> $A_BX XLM"
log "  Payala   agent $B_AC -> $A_AC cents  beneficiary $B_BC -> $A_BC cents   (1 XLM = $DEMO_CENTS_PER_XLM cents)"
log "  Payala transfer (GET /transfers?device_id=<stellar hash prefix>):"
payala_transfers "device_id=${HASH:0:24}" | jq -r '.Data[] | "    payala_tx_id \(.hash_hex)  \(.kind)  \(.sender_name) -> \(.recipient_name)  \(.amount) \(.currency)  counter \(.counter)  device_id \(.device_id_hex)"' >&2
ADMIN_JWT="$(relay_admin_jwt)"
log "  Impala transactions linked to this payment (GET /transactions?q=<stellar hash>; the payala_sync rows carry it in their memo):"
bridge_api GET "/transactions?q=$HASH&per_page=10" "$ADMIN_JWT" \
  | jq -r '.data[] | [.origin, (.source_account[0:8] + "…"), ((.stellar_hash // "-")[0:12]), ((.payala_tx_id // "-")[0:12]), ((.payala_amount // "-")|tostring), (.payala_currency // "-")] | @tsv' \
  | awk -F'\t' 'BEGIN{printf "    %-15s %-10s %-13s %-13s %8s %s\n","origin","source","stellar_hash","payala_tx_id","p_amt","cur"} {printf "    %-15s %-10s %-13s %-13s %8s %s\n",$1,$2,$3,$4,$5,$6}' >&2
record_json payala-last-payment "$(jq -cn --arg h "$HASH" --arg b "$BTXID" --arg i "$INTENT" --arg p "$PTX" --argjson xlm "$XLM" --argjson cents "$CENTS" --arg k "$KEY" --argjson l "$LEDGER" \
      --arg hu "$(horizon_tx_url "$HASH")" --arg eu "$(explorer_tx_url "$HASH")" \
  '{direction:"impala_to_payala",stellar_hash:$h,btxid:$b,intent_id:$i,payala_tx_id:$p,xlm:$xlm,cents:$cents,idempotency_key:$k,ledger:$l,horizon_url:$hu,explorer_url:$eu}')"
log "  testnet transaction id (look it up elsewhere):"
log "    $HASH"
log "    $(horizon_tx_url "$HASH")"
log "    $(explorer_tx_url "$HASH")"
log "  record: state/records/payala-last-payment.json"
log ""
ok "done. Look at it in the UI: $UI_URL -> Transactions -> search '$HASH' or '$PTX'"
