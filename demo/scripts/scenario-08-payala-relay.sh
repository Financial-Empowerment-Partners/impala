#!/usr/bin/env bash
# Scenario 08 — the Payala <-> Impala relays in both directions on Stellar testnet, against the in-repo Payala
# stub (demo/payala-stub; the proprietary Payala API is not part of the demo):
#   scripts/payala/seed-payala.sh            the six demo users exist on the stub; the mint funds the agent (a real Order)
#   scripts/payala/demo-payment.sh           forward: a custodial payment through the bridge is reflected into the stub
#                                            as an Order (device_id = the Stellar hash prefix) and mirrored back
#   scripts/payala/test-payala-to-impala.sh  reverse: a stub Order becomes a custodial testnet payment (memo
#                                            payala:<id>), with its 21 assertions (nothing paid twice, no loop back)
# then this script's own assertions: both relay records, both hashes successful on Horizon, the stub ledger moved
# by exactly the expected cents, the bridge's payala_sync mirror rows for both transfers, and the stub's request
# journal (GET /__stub/requests) and counters (GET /__stub/state): exactly one order request carried the forward
# hash prefix and was answered 200, none carried the reverse one, and no request since the stub started carried an
# Authorization header. An ambiguous forward payment (exit 3 from demo-payment.sh) is recorded as such and stops the run.
# Usage: scripts/scenario-08-payala-relay.sh     (amounts: DEMO_PAYMENT_XLM and DEMO_PAYALA_TRANSFER_CENTS in .env)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/payala/lib-payala.sh"
load_env
require_cmd curl jq openssl od
require_env AGENT_G BENEF_G PAYALA_MINT_ID PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD IMPALA_AGENT_PASSWORD DEMO_CENTS_PER_XLM
XLM="${DEMO_PAYMENT_XLM:-25}"; CENTS="${DEMO_PAYALA_TRANSFER_CENTS:-1234}"
printf '%s' "$XLM" | grep -Eq '^[0-9]+$' || die "DEMO_PAYMENT_XLM must be a whole number of XLM (got $XLM)"
printf '%s' "$CENTS" | grep -Eq '^[1-9][0-9]*$' || die "DEMO_PAYALA_TRANSFER_CENTS must be a positive whole number of cents (got $CENTS)"
FWD_CENTS=$(( XLM * DEMO_CENTS_PER_XLM ))
EXPECTED=$(( FWD_CENTS + CENTS ))
PAY="$DEMO_DIR/scripts/payala"
t0="$(now_s)"
hr "scenario 08: Payala <-> Impala relays against the Payala stub (forward $XLM XLM = $FWD_CENTS cents, reverse $CENTS cents)"
wait_bridge 30
require_payala

# run_step <label> <command...>: the sub-script's output stays visible; its exit code counts as one assertion.
# Exit 3 (a fund-moving step whose outcome is unknown) is never collapsed into a failure: the scenario records
# itself as ambiguous and stops before any further payment (run-all.sh then refuses to make more).
run_step() {
  local label="$1" rc; shift
  if "$@"; then ok "$label"; PASSES=$((PASSES + 1)); return 0; fi
  rc=$?
  if [ "$rc" -eq 3 ]; then
    fail_line "$label: AMBIGUOUS payment outcome (exit 3); stopping — resolve it (state/records, the intent, Horizon) before re-running"
    record_json scenario-08-payala-relay "$(jq -cn --arg s "$label" --argjson p "$PASSES" --argjson f "$((FAILS + 1))" --argjson t "$(( $(now_s) - t0 ))" --arg at "$(utc_now)" \
      '{scenario:"scenario-08-payala-relay",status:"ambiguous",step:$s,passed:$p,failed:$f,seconds:$t,finished_at:$at}')"
    exit 3
  fi
  fail_line "$label (exit $rc)"; FAILS=$((FAILS + 1))
}
tx_ok() { [ "${#1}" -eq 64 ] && horizon_tx "$1" | jq -e '.successful==true' >/dev/null; }
# the records are "last run" files: remember what was there so a stale record cannot pass for this run's
PREV_FWD_H="$(record_get payala-last-payment .stellar_hash)"; PREV_REV_PTX="$(record_get payala-last-transfer .payala_tx_id)"

info "0/5 the Payala stub"
health="$(payala_get /)"
check_jq "payala stub answers at $PAYALA_URL: service payala-stub, status ok, the six seeded users" '.service=="payala-stub" and .status=="ok" and .users>=6' "$health"
log "  $(printf '%s' "$health" | jq -c '{users,transfers,persistent,seeded_at}')"

info "1/5 Payala users and the agent's funding"
run_step "step: seed-payala.sh completed" "$PAY/seed-payala.sh"

info "2/5 forward relay catch-up: custodial payments of earlier scenarios are reflected now, before the stub balances are snapshotted"
"$PAY/reflect.sh" --once --sync-back || warn "the forward relay reported a failure; it retries on its next run"
B_AC="$(payala_balance "$PAYALA_AGENT_ID")"; B_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
SEQ0="$(payala_journal_seq)"
log "  Payala   agent $B_AC cents  beneficiary $B_BC cents   (stub request journal at seq $SEQ0)"

info "3/5 forward: Impala -> Payala ($XLM XLM through the bridge, reflected as $FWD_CENTS cents)"
run_step "step: demo-payment.sh completed" "$PAY/demo-payment.sh" "$XLM"

info "4/5 reverse: Payala -> Impala ($CENTS cents, with its own 21 assertions)"
run_step "step: test-payala-to-impala.sh passed" "$PAY/test-payala-to-impala.sh" "$CENTS"

info "5/5 scenario assertions"
FWD_H="$(record_get payala-last-payment .stellar_hash)"; FWD_PTX="$(record_get payala-last-payment .payala_tx_id)"
if [ -z "$FWD_H" ] || [ "$FWD_H" = "$PREV_FWD_H" ]; then FWD_H=""; FWD_PTX=""; fi
REV_H="$(record_get payala-last-transfer .stellar_hash)"; REV_PTX="$(record_get payala-last-transfer .payala_tx_id)"; REV_XLM="$(record_get payala-last-transfer .xlm)"
if [ -z "$REV_PTX" ] || [ "$REV_PTX" = "$PREV_REV_PTX" ]; then REV_H=""; REV_PTX=""; REV_XLM=""; fi
check "forward: this run wrote state/records/payala-last-payment.json (stellar hash ${FWD_H:0:12}…, payala_tx_id ${FWD_PTX:0:12}…)" [ "${#FWD_H}" -eq 64 ]
check "reverse: this run wrote state/records/payala-last-transfer.json (stellar hash ${REV_H:0:12}…, payala_tx_id ${REV_PTX:0:12}…)" [ "${#REV_PTX}" -eq 64 ]
check_jq "forward relay record: state/relay/reflected/<hash>.json is impala_to_payala, $FWD_CENTS cents, that Payala tx id" \
  ".direction==\"impala_to_payala\" and .cents==$FWD_CENTS and .payala_tx_id==\"$FWD_PTX\" and .device_id_hex==\"${FWD_H:0:24}\"" \
  "$(cat "$RELAY_DIR/reflected/$FWD_H.json" 2>/dev/null || echo '{}')"
check_jq "reverse relay record: state/relay/payala/<payala_tx_id>.json is payala_to_impala, $CENTS cents, not skipped, that Stellar hash" \
  ".direction==\"payala_to_impala\" and .skipped!=true and .cents==$CENTS and .stellar_hash==\"$REV_H\" and .memo==\"payala:${REV_PTX:0:20}\"" \
  "$(cat "$RELAY_DIR/payala/$REV_PTX.json" 2>/dev/null || echo '{}')"
check_jq "loop guard marker: state/relay/reflected/<reverse hash>.json records the Payala origin" \
  ".direction==\"payala_to_impala\" and .payala_tx_id==\"$REV_PTX\"" "$(cat "$RELAY_DIR/reflected/$REV_H.json" 2>/dev/null || echo '{}')"
check "horizon: forward payment successful ($FWD_H)" tx_ok "$FWD_H"
check "horizon: reverse payment successful ($REV_H)" tx_ok "$REV_H"
A_AC="$(payala_balance "$PAYALA_AGENT_ID")"; A_BC="$(payala_balance "$PAYALA_BENEFICIARY_ID")"
check "payala: agent -$EXPECTED cents over both directions ($B_AC -> $A_AC)" [ $(( B_AC - A_AC )) -eq "$EXPECTED" ]
check "payala: beneficiary +$EXPECTED cents over both directions ($B_BC -> $A_BC)" [ $(( A_BC - B_BC )) -eq "$EXPECTED" ]
check_jq "payala: the stub holds the forward transfer as one server-signed Order with device_id = the Stellar hash prefix" \
  "[.Data[]|select(.kind==\"Order\" and .counter<0 and .amount==$FWD_CENTS and .device_id_hex==\"${FWD_H:0:24}\")]|length==1" "$(payala_transfers "hash=${FWD_PTX:-0}" 2>/dev/null || echo '{"Data":[]}')"
T="$(relay_admin_jwt)" || T=""
fwd_rows='{"data":[]}'; rev_rows='{"data":[]}'
if [ -n "$FWD_PTX" ] && [ -n "$T" ]; then fwd_rows="$(bridge_api GET "/transactions?q=$FWD_PTX&per_page=10" "$T")" || fwd_rows='{"data":[]}'; fi
if [ -n "$REV_PTX" ] && [ -n "$T" ]; then rev_rows="$(bridge_api GET "/transactions?q=$REV_PTX&per_page=10" "$T")" || rev_rows='{"data":[]}'; fi
check_jq "bridge: two payala_sync rows mirror the forward Payala transfer (-$FWD_CENTS agent, +$FWD_CENTS beneficiary, memo stellar:<hash>)" \
  "[.data[]|select(.origin==\"payala_sync\" and .payala_tx_id==\"$FWD_PTX\" and .memo==\"stellar:$FWD_H\")] | length==2 and (map(.payala_amount)|sort)==[-$FWD_CENTS,$FWD_CENTS]" "$fwd_rows"
check_jq "bridge: two payala_sync rows mirror the reverse Payala transfer (-$CENTS agent, +$CENTS beneficiary, memo stellar:<hash>)" \
  "[.data[]|select(.origin==\"payala_sync\" and .payala_tx_id==\"$REV_PTX\" and .memo==\"stellar:$REV_H\")] | length==2 and (map(.payala_amount)|sort)==[-$CENTS,$CENTS]" "$rev_rows"
check_eval "both testnet tx ids recorded in $(txid_log_file)" "txid_recorded '$FWD_H' && txid_recorded '$REV_H'"
# the stub's request journal: what the relays actually sent since the catch-up
orders="$(payala_journal "since_seq=$SEQ0&path=/transfers/order&method=POST")"
check_jq "stub journal: exactly one order request carried the forward device_id ${FWD_H:0:24} and was answered 200" \
  "([.Data[]|select(.order.device_id_hex==\"${FWD_H:0:24}\")]|length==1) and ([.Data[]|select(.order.device_id_hex==\"${FWD_H:0:24}\")|.status]==[200])" "$orders"
check_jq "stub journal: no order request ever carried the reverse hash prefix ${REV_H:0:24} (the forward relay did not order the payment back)" \
  "[.Data[]|select(.order.device_id_hex==\"${REV_H:0:24}\")]|length==0" "$orders"
check_jq "stub counters: no request since the stub started carried an Authorization header (monotonic counter; none of the bridge's credentials leaves)" \
  '.counters.authorization_requests==0' "$(payala_get /__stub/state)"
check_jq "stub journal: none of this run's requests carried an Authorization header" \
  '[.Data[]|.has_authorization]|any|not' "$(payala_journal "since_seq=$SEQ0")"
N_ORDERS="$(printf '%s' "$orders" | jq '.Data|length')"

TEST_PASSED=null; TEST_FAILED=null
if [ -n "$REV_PTX" ]; then TEST_PASSED="$(record_get payala-test .passed)"; TEST_FAILED="$(record_get payala-test .failed)"; fi
[ -n "$TEST_PASSED" ] || TEST_PASSED=null; [ -n "$TEST_FAILED" ] || TEST_FAILED=null
log "  forward  ${FWD_H:-?}  ($XLM XLM -> $FWD_CENTS cents, payala_tx_id ${FWD_PTX:-?})"
log "  reverse  ${REV_H:-?}  ($CENTS cents -> ${REV_XLM:-?} XLM, payala_tx_id ${REV_PTX:-?})"
log "  Payala   agent $B_AC -> $A_AC cents  beneficiary $B_BC -> $A_BC cents   (1 XLM = $DEMO_CENTS_PER_XLM cents)"
log "  stub     $N_ORDERS order request(s) since seq $SEQ0; journal: $PAYALA_URL/__stub/requests?since_seq=$SEQ0"
log "  UI: $UI_URL -> Transactions -> search a Stellar hash or a Payala tx id above"

finish_scenario scenario-08-payala-relay "$(jq -cn \
  --arg fh "$FWD_H" --arg fp "$FWD_PTX" --argjson fx "$XLM" --argjson fc "$FWD_CENTS" --arg fk "$(record_get payala-last-payment .idempotency_key)" \
  --arg fhu "$( [ -n "$FWD_H" ] && horizon_tx_url "$FWD_H" || true )" --arg feu "$( [ -n "$FWD_H" ] && explorer_tx_url "$FWD_H" || true )" \
  --arg rh "$REV_H" --arg rp "$REV_PTX" --arg rx "$REV_XLM" --argjson rc "$CENTS" --arg rm "$(record_get payala-last-transfer .memo)" --arg rk "$(record_get payala-last-transfer .idempotency_key)" \
  --arg rhu "$( [ -n "$REV_H" ] && horizon_tx_url "$REV_H" || true )" --arg reu "$( [ -n "$REV_H" ] && explorer_tx_url "$REV_H" || true )" \
  --argjson rate "$DEMO_CENTS_PER_XLM" --argjson exp "$EXPECTED" --argjson bac "$B_AC" --argjson aac "$A_AC" --argjson bbc "$B_BC" --argjson abc "$A_BC" \
  --argjson tp "$TEST_PASSED" --argjson tf "$TEST_FAILED" --arg su "$PAYALA_URL" --argjson sq "$SEQ0" --argjson so "${N_ORDERS:-0}" \
  '{stellar_hash:$fh, stellar_hashes:[$fh,$rh], payala_tx_ids:[$fp,$rp], cents_per_xlm:$rate, expected_cents_moved:$exp,
    forward:{direction:"impala_to_payala",stellar_hash:$fh,payala_tx_id:$fp,xlm:$fx,cents:$fc,idempotency_key:$fk,horizon_url:$fhu,explorer_url:$feu},
    reverse:{direction:"payala_to_impala",stellar_hash:$rh,payala_tx_id:$rp,xlm:$rx,cents:$rc,memo:$rm,idempotency_key:$rk,horizon_url:$rhu,explorer_url:$reu,test_passed:$tp,test_failed:$tf},
    payala_balances:{agent:{before:$bac,after:$aac},beneficiary:{before:$bbc,after:$abc}},
    payala_stub:{url:$su, journal_seq_at_start:$sq, order_requests:$so}}')" "$t0"
