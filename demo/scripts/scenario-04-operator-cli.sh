#!/usr/bin/env bash
# Scenario 04 — the operator CLI (impalactl) against the bridge contract: endpoint-scoped login,
# account status, a custodial transfer (beneficiary -> agent) with the exit-3 ambiguity protocol
# honoured, and the activity/event feeds that show it. Nothing here talks to the database directly.
# Usage: scripts/scenario-04-operator-cli.sh [amount_xlm]   (default DEMO_OPERATOR_SEND_XLM)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env AGENT_G BENEF_G PAYALA_BENEFICIARY_ID PAYALA_ADMIN_ID IMPALA_BENEFICIARY_PASSWORD IMPALA_ADMIN_PASSWORD
CTL="$(impalactl_bin)" || die "bin/impalactl missing: run scripts/build.sh tools"
XLM="${1:-${DEMO_OPERATOR_SEND_XLM:-3}}"
printf '%s' "$XLM" | grep -Eq '^[0-9]+$' || die "amount must be a whole number of XLM (got $XLM)"
STROOPS=$(( XLM * 10000000 ))
t0="$(now_s)"
hr "scenario 04: operator CLI (impalactl) — beneficiary pays the agent $XLM XLM"
export IMPALA_ENDPOINT="$BRIDGE_URL"
CFG_B="$STATE_DIR/impalactl/beneficiary"; CFG_A="$STATE_DIR/impalactl/admin"; mkdir -p "$CFG_B" "$CFG_A"; chmod 700 "$STATE_DIR/impalactl" "$CFG_B" "$CFG_A"
ctl_b() { IMPALA_CONFIG_DIR="$CFG_B" "$CTL" "$@"; }
ctl_a() { IMPALA_CONFIG_DIR="$CFG_A" "$CTL" "$@"; }

info "1/5 login (password from IMPALA_PASSWORD, never argv; credentials stored 0600, scoped to this endpoint)"
IMPALA_PASSWORD="$IMPALA_BENEFICIARY_PASSWORD" ctl_b login --username "$PAYALA_BENEFICIARY_ID" >&2
IMPALA_PASSWORD="$IMPALA_ADMIN_PASSWORD" ctl_a login --username "$PAYALA_ADMIN_ID" >&2
who="$(ctl_b whoami 2>/dev/null | head -n 3 | tr '\n' ' ' || true)"
check_eval "impalactl whoami names the beneficiary" "ctl_b whoami 2>&1 | grep -q '$PAYALA_BENEFICIARY_ID'"
check_eval "impalactl health: healthy on testnet" "ctl_b health --json 2>/dev/null | jq -e '.health.status==\"healthy\" and .health.stellar_network==\"testnet\"' >/dev/null"
# the same bridge behind the UI's proxy is a DIFFERENT endpoint URL: the stored credentials must not be sent there
check_eval "credentials are endpoint-scoped: the same bridge under another URL is refused" "IMPALA_ENDPOINT='$UI_URL/api/testnet' ctl_b account show '$BENEF_G' 2>&1 | grep -q 'stored credentials are for'"

info "2/5 account status"
check_eval "impalactl account show (bridge record) maps the beneficiary's address to its Payala id" "ctl_b account show '$BENEF_G' --json 2>/dev/null | jq -e '.payala_account_id==\"$PAYALA_BENEFICIARY_ID\"' >/dev/null"
B_A="$(horizon_native_balance "$AGENT_G")"; B_B="$(horizon_native_balance "$BENEF_G")"
check_eval "impalactl account onchain (Horizon) shows the live balance $B_B" "ctl_b account onchain '$BENEF_G' --json 2>/dev/null | grep -q '${B_B%.*}'"
check_eval "impalactl account list (admin) lists the four seeded accounts" "ctl_a account list --json --per-page 50 2>/dev/null | jq -e '[.data[].payala_account_id] | index(\"$PAYALA_ADMIN_ID\") and index(\"$PAYALA_BENEFICIARY_ID\") and index(\"$PAYALA_AGENT_ID\") and index(\"${DEMO_HOLDER_ID:-}\")' >/dev/null"

info "3/5 transfer send: beneficiary -> agent $XLM XLM (real testnet payment; exit 3 = ambiguous, never retried)"
set +e
out="$(ctl_b transfer send --to "$AGENT_G" --amount "$XLM" --memo "impalactl demo" --json 2>"$STATE_DIR/impalactl-send.err")"
rc=$?
set -e
if [ "$rc" -ne 0 ] && grep -qi 'outcome.*unknown' "$STATE_DIR/impalactl-send.err"; then rc=3; fi
case "$rc" in
  0) ;;
  3) fail_line "impalactl reports an AMBIGUOUS outcome (exit 3): the payment may have been submitted. Not retrying."; cat "$STATE_DIR/impalactl-send.err" >&2
     record_json scenario-04-operator-cli "$(jq -cn --arg at "$(utc_now)" '{scenario:"scenario-04-operator-cli",status:"ambiguous",passed:0,failed:1,finished_at:$at}')"; exit 3 ;;
  *) cat "$STATE_DIR/impalactl-send.err" >&2; die "impalactl transfer send failed (exit $rc)" ;;
esac
HASH="$(printf '%s' "$out" | jq -r '.stellar_hash // empty')"; BTXID="$(printf '%s' "$out" | jq -r '.btxid // empty')"
[ "${#HASH}" -eq 64 ] || die "no stellar_hash in impalactl output: $out"
grep -q 'testnet' "$STATE_DIR/impalactl-send.err" && ok "impalactl announced the bridge URL and network before sending" || warn "impalactl did not print the network notice"
tx="$(horizon_wait_tx "$HASH" 20)" || die "tx $HASH not found on Horizon"
LEDGER="$(printf '%s' "$tx" | jq -r .ledger)"; FEE="$(printf '%s' "$tx" | jq -r .fee_charged)"
emit_txid operator_payment "$HASH" "$XLM XLM ${BENEF_G:0:8}… -> ${AGENT_G:0:8}… via impalactl ledger $LEDGER"
check_jq "horizon: successful, memo 'impalactl demo'" '.successful==true and .memo=="impalactl demo"' "$tx"

info "4/5 activity and events"
sleep 1
check_eval "impalactl activity list --search finds the custodial_sign row" "ctl_b activity list --search '$HASH' --json 2>/dev/null | jq -e '[.data[]|select(.stellar_hash==\"$HASH\" and .origin==\"custodial_sign\")]|length==1' >/dev/null"
if [ -n "$BTXID" ]; then check_eval "impalactl activity show <btxid> shows the transaction" "ctl_b activity show '$BTXID' --json 2>/dev/null | jq -e '.stellar_hash==\"$HASH\"' >/dev/null"; fi
check_eval "impalactl activity events (admin) carries custodial.payment_settled" "ctl_a activity events --since 0 --limit 500 --json 2>/dev/null | jq -e '[.events[]|select(.event_type==\"custodial.payment_settled\")]|length>=1' >/dev/null"
check_eval "the beneficiary cannot read the admin event feed (role-gated)" "! ctl_b activity events --since 0 >/dev/null 2>&1"

info "5/5 balances"
A_A="$(horizon_native_balance "$AGENT_G")"; A_B="$(horizon_native_balance "$BENEF_G")"
check "stellar: agent +$XLM XLM exactly ($B_A -> $A_A)" [ $(( $(xlm_to_stroops "$A_A") - $(xlm_to_stroops "$B_A") )) -eq "$STROOPS" ]
check "stellar: beneficiary -$XLM XLM and the $FEE-stroop fee ($B_B -> $A_B)" [ $(( $(xlm_to_stroops "$B_B") - $(xlm_to_stroops "$A_B") )) -eq $(( STROOPS + FEE )) ]

finish_scenario scenario-04-operator-cli "$(jq -cn --arg h "$HASH" --arg b "$BTXID" --argjson xlm "$XLM" --argjson st "$STROOPS" --argjson l "$LEDGER" --argjson fee "$FEE" --arg from "$BENEF_G" --arg to "$AGENT_G" \
  --arg hu "$(horizon_tx_url "$HASH")" --arg eu "$(explorer_tx_url "$HASH")" --arg who "${who:-}" \
  '{stellar_hash:$h, btxid:$b, xlm:$xlm, stroops:$st, ledger:$l, fee_charged_stroops:$fee, from:$from, to:$to, horizon_url:$hu, explorer_url:$eu, whoami:$who}')" "$t0"
