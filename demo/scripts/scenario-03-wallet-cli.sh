#!/usr/bin/env bash
# Scenario 03 — a self-custody wallet (lumencli) on Stellar testnet pays into the bridge: a fresh
# keypair is funded by Friendbot, sends N XLM with a memo to the card holder's custodial address, and
# the bridge's on-chain view of the holder reflects it. The wallet seed exists only in this process.
# Usage: scripts/scenario-03-wallet-cli.sh [amount_xlm]   (default DEMO_WALLET_SEND_XLM)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env HOLDER_G DEMO_HOLDER_ID IMPALA_HOLDER_PASSWORD
LUMEN="$(lumencli_bin)" || die "bin/lumencli missing: run scripts/build.sh tools"
XLM="${1:-${DEMO_WALLET_SEND_XLM:-5}}"
printf '%s' "$XLM" | grep -Eq '^[0-9]+$' || die "amount must be a whole number of XLM (got $XLM)"
STROOPS=$(( XLM * 10000000 ))
t0="$(now_s)"
hr "scenario 03: self-custody wallet (lumencli) -> holder's custodial account ($XLM XLM)"
export LUMEN_NETWORK=testnet

info "1/5 new keypair (offline; the seed stays in this process and is never written)"
new="$("$LUMEN" account new 2>/dev/null)"
WALLET_G="$(printf '%s' "$new" | sed -n 's/^Public key (address): *//p' | tr -d '[:space:]')"
WALLET_S="$(printf '%s' "$new" | sed -n 's/^Secret seed: *//p' | tr -d '[:space:]')"
[ "${#WALLET_G}" -eq 56 ] && [ "${#WALLET_S}" -eq 56 ] || die "could not parse the keypair from lumencli"
ok "wallet $WALLET_G"

info "2/5 Friendbot funds the wallet (10,000 XLM on testnet)"
"$LUMEN" account fund --address "$WALLET_G" >&2
i=0; until horizon_account_exists "$WALLET_G"; do i=$((i + 1)); [ "$i" -le 20 ] || die "wallet not visible on Horizon after funding"; sleep 3; done
FUND_HASH="$(curl -fsS "$HORIZON_URL/accounts/$WALLET_G/transactions?order=asc&limit=1" | jq -r '._embedded.records[0].hash')"
[ "${#FUND_HASH}" -eq 64 ] && emit_txid friendbot "$FUND_HASH" "funding $WALLET_G"
check_eval "lumencli balance shows the funded wallet" "'$LUMEN' balance '$WALLET_G' 2>/dev/null | grep -Eq '10000|XLM'"
B_H="$(horizon_native_balance "$HOLDER_G")"

info "3/5 send $XLM XLM to the holder's custodial address with a memo (seed from LUMEN_SECRET, never argv)"
set +e
out="$(LUMEN_SECRET="$WALLET_S" "$LUMEN" send --to "$HOLDER_G" --amount "$XLM" --memo "demo wallet to holder" --yes 2>"$STATE_DIR/lumencli-send.err")"
rc=$?
set -e
unset WALLET_S
case "$rc" in
  0) ;;
  3) fail_line "lumencli reports an AMBIGUOUS outcome (exit 3): the payment may have been submitted. Not retrying."; cat "$STATE_DIR/lumencli-send.err" >&2
     record_json scenario-03-wallet-cli "$(jq -cn --arg w "$WALLET_G" --arg at "$(utc_now)" '{scenario:"scenario-03-wallet-cli",status:"ambiguous",wallet_g:$w,passed:0,failed:1,finished_at:$at}')"; exit 3 ;;
  *) cat "$STATE_DIR/lumencli-send.err" >&2; die "lumencli send failed (exit $rc)" ;;
esac
HASH="$(printf '%s' "$out" | sed -n 's/^Transaction: *//p' | tr -d '[:space:]')"
[ "${#HASH}" -eq 64 ] || die "no transaction hash in lumencli output: $out"
printf '%s\n' "$out" | sed 's/^/  /' >&2

info "4/5 confirming on Horizon and through lumencli"
tx="$(horizon_wait_tx "$HASH" 20)" || die "tx $HASH not found on Horizon"
LEDGER="$(printf '%s' "$tx" | jq -r .ledger)"
emit_txid wallet_payment "$HASH" "$XLM XLM ${WALLET_G:0:8}… -> ${HOLDER_G:0:8}… (holder) ledger $LEDGER"
check_jq "horizon: successful with the text memo" '.successful==true and .memo_type=="text" and .memo=="demo wallet to holder"' "$tx"
op="$(curl -fsS "$HORIZON_URL/transactions/$HASH/operations" | jq -c '._embedded.records[0]')"
check_jq "horizon: payment $XLM XLM wallet -> holder" ".type==\"payment\" and .amount==\"$(stroops_to_xlm "$STROOPS")\" and .from==\"$WALLET_G\" and .to==\"$HOLDER_G\"" "$op"
check_eval "lumencli tx shows the memo" "'$LUMEN' tx '$HASH' 2>/dev/null | grep -q 'demo wallet to holder'"
check_eval "lumencli history (JSON) of the wallet lists the payment" "'$LUMEN' history '$WALLET_G' --json 2>/dev/null | grep -q '$HASH'"
check_eval "lumencli history (JSON) of the holder lists it as received" "'$LUMEN' history '$HOLDER_G' --json 2>/dev/null | grep -q '$HASH'"

info "5/5 the bridge sees the deposit on the holder's custodial account"
A_H="$(horizon_native_balance "$HOLDER_G")"
check "stellar: holder +$XLM XLM exactly ($B_H -> $A_H)" [ $(( $(xlm_to_stroops "$A_H") - $(xlm_to_stroops "$B_H") )) -eq "$STROOPS" ]
HOLDER_JWT="$(bridge_login "$DEMO_HOLDER_ID" "$IMPALA_HOLDER_PASSWORD")"
onchain="$(bridge_api GET "/account/onchain?stellar_account_id=$HOLDER_G" "$HOLDER_JWT")"
check "bridge GET /account/onchain answers 200 for the holder's address" [ "$(http_code)" = "200" ]
check_jq "bridge: the account exists on chain" '.exists==true' "$onchain"
check_eval "bridge: the live native balance $A_H is what the bridge reports" "printf '%s' '$onchain' | grep -q '\"$A_H\"'"
log "  wallet      $WALLET_G  $(horizon_native_balance "$WALLET_G") XLM   $(explorer_account_url "$WALLET_G")"
log "  holder      $HOLDER_G  $B_H -> $A_H XLM"

finish_scenario scenario-03-wallet-cli "$(jq -cn --arg w "$WALLET_G" --arg f "$FUND_HASH" --arg h "$HASH" --argjson xlm "$XLM" --argjson st "$STROOPS" --argjson l "$LEDGER" --arg to "$HOLDER_G" \
  --arg hu "$(horizon_tx_url "$HASH")" --arg eu "$(explorer_tx_url "$HASH")" \
  '{wallet_g:$w, friendbot_hash:$f, stellar_hash:$h, xlm:$xlm, stroops:$st, ledger:$l, to:$to, horizon_url:$hu, explorer_url:$eu}')" "$t0"
