#!/usr/bin/env bash
# Test: a transfer happens on the Payala stub and is reflected in the impala-bridge (the reverse direction).
#   1/3  POST /transfers/order in Payala (agent -> beneficiary, N cents): the Payala ledger moves.
#   2/3  scripts/payala/reflect-payala.sh --once --sync-back: the bridge signs the matching Stellar testnet payment
#        from the agent's custodial seed (memo payala:<id>), Horizon confirms it, and the Payala transfer is mirrored
#        back into the bridge as two payala_sync rows.
#   3/3  21 assertions over the Payala stub, Horizon and the bridge, including that re-running the relay pays nothing
#        twice and that the forward relay (scripts/payala/reflect.sh) does not order the payment back into Payala.
# Usage: scripts/payala/test-payala-to-impala.sh [cents]   (default DEMO_PAYALA_TRANSFER_CENTS=1234, i.e. 12.34 XLM)
# Exit 0 when every assertion passed. The testnet transaction id is printed for lookup elsewhere and appended to
# state/testnet-txids.tsv; every id of the run is written to state/records/payala-last-transfer.json and the
# tally to state/records/payala-test.json.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq openssl od
require_payala
require_env AGENT_G BENEF_G PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD DEMO_CENTS_PER_XLM
CENTS="${1:-${DEMO_PAYALA_TRANSFER_CENTS:-1234}}"
printf '%s' "$CENTS" | grep -Eq '^[1-9][0-9]*$' || die "amount must be a positive whole number of cents (got $CENTS)"
STROOPS="$(cents_to_stroops "$CENTS")" || die "$CENTS cents is not a whole number of stroops at $DEMO_CENTS_PER_XLM cents/XLM"
XLM="$(stroops_to_xlm "$STROOPS")"
t0="$(now_s)"
payala_unchanged() { [ "$(payala_balance "$PAYALA_AGENT_ID")" = "$M_AC" ] && [ "$(payala_balance "$PAYALA_BENEFICIARY_ID")" = "$M_BC" ]; }
hr "payala relay, reverse: $CENTS cents agent -> beneficiary in Payala, reflected as $XLM XLM on Stellar"

info "before"
B_AX="$(horizon_native_balance "$AGENT_G")"; B_BX="$(horizon_native_balance "$BENEF_G")"
B_AC="$(payala_balance "$PAYALA_AGENT_ID")"; B_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
log "  Stellar  agent $B_AX XLM   beneficiary $B_BX XLM"
log "  Payala   agent $B_AC cents  beneficiary $B_BC cents"
[ "$B_AC" -ge "$CENTS" ] || die "the Payala agent has only $B_AC cents; scripts/payala/seed-payala.sh tops it up"

info "1/3 transfer in Payala: agent -> beneficiary, $CENTS cents (POST /transfers/order; random device_id — this transfer does not come from Stellar)"
DEV="$(openssl rand -hex 12)"
resp="$("$DEMO_DIR/scripts/payala/payala-order.sh" "$PAYALA_AGENT_ID" "$PAYALA_BENEFICIARY_ID" "$CENTS" "$DEV")"
PTX="$(printf '%s' "$resp" | jq -r .hash | b64_to_hex)"
[ "${#PTX}" -eq 64 ] || die "no transfer hash in: $resp"
log "  payala_tx_id=$PTX  device_id=$DEV"
M_AC="$(payala_balance "$PAYALA_AGENT_ID")"; M_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
check "payala: agent debited $CENTS cents ($B_AC -> $M_AC)" [ $(( B_AC - M_AC )) -eq "$CENTS" ]
check "payala: beneficiary credited $CENTS cents ($B_BC -> $M_BC)" [ $(( M_BC - B_BC )) -eq "$CENTS" ]
check_jq "payala: the stub holds the transfer as one server-signed Order of $CENTS cents (counter < 0)" "[.Data[]|select(.kind==\"Order\" and .amount==$CENTS and .counter<0)]|length==1" "$(payala_transfers "hash=$PTX")"

info "2/3 reflecting into the impala bridge (relay: Payala transfer table -> POST /managed-account/sign as the agent -> Horizon) and mirroring back"
"$DEMO_DIR/scripts/payala/reflect-payala.sh" --once --sync-back
REC="$RELAY_DIR/payala/$PTX.json"
[ -f "$REC" ] || die "the relay did not process $PTX (see warnings above)"
jq -e '.skipped != true' "$REC" >/dev/null || die "the relay skipped the transfer: $(jq -r .reason "$REC")"
HASH="$(jq -r .stellar_hash "$REC")"; INTENT="$(jq -r .intent_id "$REC")"; BTXID="$(jq -r .btxid "$REC")"; LEDGER="$(jq -r .ledger "$REC")"
MEMO="payala:${PTX:0:20}"; IKEY="payala:${PTX:0:56}"
[ "${#HASH}" -eq 64 ] || die "no stellar_hash in $REC"

info "3/3 assertions"
tx="$(horizon_tx "$HASH")" || die "Horizon does not answer for $HASH"
op="$(curl -fsS "$(horizon_tx_url "$HASH")/operations" | jq -c '._embedded.records[0]')"
FEE="$(printf '%s' "$tx" | jq -r .fee_charged)"
check_jq "horizon: transaction successful in ledger $LEDGER" ".successful==true and .ledger==$LEDGER" "$tx"
check_jq "horizon: memo text '$MEMO' links the payment to the Payala transfer" ".memo_type==\"text\" and .memo==\"$MEMO\"" "$tx"
check_jq "horizon: payment $XLM XLM ${AGENT_G:0:8}… -> ${BENEF_G:0:8}…" ".type==\"payment\" and .asset_type==\"native\" and .amount==\"$XLM\" and .from==\"$AGENT_G\" and .to==\"$BENEF_G\"" "$op"
A_AX="$(horizon_native_balance "$AGENT_G")"; A_BX="$(horizon_native_balance "$BENEF_G")"
check "stellar: beneficiary +$XLM XLM ($B_BX -> $A_BX)" [ $(( $(xlm_to_stroops "$A_BX") - $(xlm_to_stroops "$B_BX") )) -eq "$STROOPS" ]
check "stellar: agent -$XLM XLM and the $FEE-stroop fee ($B_AX -> $A_AX)" [ $(( $(xlm_to_stroops "$B_AX") - $(xlm_to_stroops "$A_AX") )) -eq $(( STROOPS + FEE )) ]
T="$(relay_admin_jwt)"
byhash="$(bridge_api GET "/transactions?q=$HASH&per_page=10" "$T")"
byptx="$(bridge_api GET "/transactions?q=$PTX&per_page=10" "$T")"
check_jq "bridge: one custodial_sign row for the Stellar hash, memo '$MEMO', source = agent" "[.data[]|select(.origin==\"custodial_sign\" and .stellar_hash==\"$HASH\" and .memo==\"$MEMO\" and .source_account==\"$AGENT_G\")]|length==1" "$byhash"
check_jq "bridge: two payala_sync mirror rows carry memo 'stellar:<hash>'" "[.data[]|select(.origin==\"payala_sync\" and .memo==\"stellar:$HASH\")]|length==2" "$byhash"
check_jq "bridge: payala_sync -$CENTS USD for the agent (payala_tx_id = the Payala hash)" "[.data[]|select(.origin==\"payala_sync\" and .payala_tx_id==\"$PTX\" and .payala_amount==-$CENTS and .payala_currency==\"USD\" and .source_account==\"$AGENT_G\")]|length==1" "$byptx"
check_jq "bridge: payala_sync +$CENTS USD for the beneficiary" "[.data[]|select(.origin==\"payala_sync\" and .payala_tx_id==\"$PTX\" and .payala_amount==$CENTS and .payala_currency==\"USD\" and .source_account==\"$BENEF_G\")]|length==1" "$byptx"
intent="$(bridge_api GET "/admin/custody/intents/$INTENT" "$T")"
check_jq "bridge: intent settled, $STROOPS stroops to the beneficiary, idempotency_key '$IKEY'" ".status==\"settled\" and .amount_minor==$STROOPS and .idempotency_key==\"$IKEY\" and .destination==\"$BENEF_G\" and .stellar_hash==\"$HASH\" and .btxid==\"$BTXID\"" "$intent"
log "  re-running the relay (must pay nothing twice)"
"$DEMO_DIR/scripts/payala/reflect-payala.sh" --once --sync-back
check "relay re-run: record unchanged (same Stellar hash)" [ "$(jq -r .stellar_hash "$REC")" = "$HASH" ]
check_jq "relay re-run: still exactly one custodial_sign row with memo '$MEMO'" "[.data[]|select(.origin==\"custodial_sign\")]|length==1" "$(bridge_api GET "/transactions?q=$MEMO&per_page=10" "$T")"
check "relay re-run: Payala balances unchanged" payala_unchanged
log "  running the forward relay scripts/payala/reflect.sh --once (must not order this payment back into Payala)"
NT="$(payala_transfer_count)"
"$DEMO_DIR/scripts/payala/reflect.sh" --once
check "forward relay: no Payala transfer with device_id = this Stellar hash prefix" [ "$(payala_transfer_count "device_id=${HASH:0:24}")" = 0 ]
check "forward relay: Payala transfer count unchanged ($NT)" [ "$(payala_transfer_count)" = "$NT" ]
check_jq "forward relay: marker records the Payala origin of $HASH" '.direction=="payala_to_impala"' "$(cat "$RELAY_DIR/reflected/$HASH.json" 2>/dev/null || echo '{}')"
check "forward relay: Payala balances unchanged" payala_unchanged
check "testnet tx id recorded in $(txid_log_file)" txid_recorded "$HASH"

info "after"
log "  Payala   agent $B_AC -> $M_AC cents  beneficiary $B_BC -> $M_BC cents   (1 XLM = $DEMO_CENTS_PER_XLM cents)"
log "  Stellar  agent $B_AX -> $A_AX XLM   beneficiary $B_BX -> $A_BX XLM"
log "  Payala transfer:  $PTX | Order | $CENTS cents | device_id $DEV"
log "  Impala transactions linked to this transfer (GET /transactions?q=<stellar hash>):"
printf '%s' "$byhash" \
  | jq -r '.data[] | [.origin, (.source_account[0:8] + "…"), ((.stellar_hash // "-")[0:12]), ((.payala_tx_id // "-")[0:12]), ((.payala_amount // "-")|tostring), (.payala_currency // "-"), (.memo // "-")] | @tsv' \
  | awk -F'\t' 'BEGIN{printf "    %-15s %-10s %-13s %-13s %8s %-4s %s\n","origin","source","stellar_hash","payala_tx_id","p_amt","cur","memo"} {printf "    %-15s %-10s %-13s %-13s %8s %-4s %s\n",$1,$2,$3,$4,$5,$6,$7}' >&2
log "  testnet transaction id (look it up elsewhere):"
log "    $HASH"
log "    $(horizon_tx_url "$HASH")"
log "    $(explorer_tx_url "$HASH")"
log "  UI: $UI_URL -> Transactions -> search '$HASH' or '$PTX'"
IDS="$(jq -cn --arg p "$PTX" --arg h "$HASH" --arg b "$BTXID" --arg i "$INTENT" --argjson c "$CENTS" --arg x "$XLM" --argjson st "$STROOPS" --arg m "$MEMO" --arg k "$IKEY" --arg d "$DEV" --argjson l "$LEDGER" --argjson f "$FEE" \
      --arg hu "$(horizon_tx_url "$HASH")" --arg eu "$(explorer_tx_url "$HASH")" \
  '{direction:"payala_to_impala",payala_tx_id:$p,stellar_hash:$h,btxid:$b,intent_id:$i,cents:$c,xlm:$x,stroops:$st,memo:$m,idempotency_key:$k,device_id_hex:$d,ledger:$l,fee_charged_stroops:$f,horizon_url:$hu,explorer_url:$eu}')"
record_json payala-last-transfer "$(printf '%s' "$IDS" | jq -c --arg at "$(utc_now)" --argjson pa "$PASSES" --argjson fa "$FAILS" '. + {tested_at:$at,passed:$pa,failed:$fa}')"
finish_scenario payala-test "$IDS" "$t0"
