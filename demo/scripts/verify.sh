#!/usr/bin/env bash
# Re-verify every recorded scenario against the LIVE system (Horizon, the bridge, the database, the
# host lanes) — the scorecard is not trusted, the facts are re-checked. Exit 1 when any check fails.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq
rec() { [ -f "$RECORDS_DIR/$1.json" ]; }
get() { record_get "$1" "$2"; }
show_txid() { log "  verifying testnet tx $1 ($2)"; log "    $(horizon_tx_url "$1")"; log "    $(explorer_tx_url "$1")"; }
tx_ok() { horizon_tx "$1" | jq -e '.successful==true' >/dev/null; }

hr "stack"
check_eval "bridge healthy on testnet" "curl -fsS $BRIDGE_URL/health | jq -e '.status==\"healthy\" and .stellar_network==\"testnet\"' >/dev/null"
check_eval "ui proxies /api/testnet to the bridge" "[ \"\$(curl -fsS $UI_URL/api/testnet/network | jq -r .stellar_network)\" = testnet ]"
check_eval "every repo migration recorded by sqlx" "[ \"\$(psql_impala -tAc 'select count(*) from _sqlx_migrations where success' | tr -d '[:space:]')\" = \"\$(ls '$REPO_DIR'/impala-bridge/migrations/*.sql | wc -l | tr -d ' ')\" ]"

if [ -n "${AGENT_G:-}" ]; then
  hr "seed"
  T="$(admin_jwt)"
  ACC="$(bridge_api GET '/accounts?per_page=50' "$T")"
  check_eval "admin has role admin" "printf '%s' '$ACC' | jq -e --arg id '$PAYALA_ADMIN_ID' '.data[]|select(.payala_account_id==\$id)|.role==\"admin\"' >/dev/null"
  for pair in "agent:$PAYALA_AGENT_ID:$AGENT_G" "beneficiary:$PAYALA_BENEFICIARY_ID:${BENEF_G:-}" "holder:${DEMO_HOLDER_ID:-}:${HOLDER_G:-}"; do
    name="${pair%%:*}"; rest="${pair#*:}"; id="${rest%%:*}"; g="${rest#*:}"
    [ -n "$g" ] || continue
    check_eval "$name is a custodial bridge account mapped to $id" "printf '%s' '$ACC' | jq -e --arg id '$id' --arg g '$g' '.data[]|select(.payala_account_id==\$id)|.stellar_account_id==\$g' >/dev/null"
    check "$name funded on testnet" horizon_account_exists "$g"
  done
  check_eval "custody caps configured" "bridge_api GET /admin/custody/policy '$T' | jq -e '.configured==true' >/dev/null"
  check_eval "card program issuer key configured" "curl -fsS $BRIDGE_URL/card-issuer | jq -e '.configured==true' >/dev/null"
  if sep10_enabled; then
    check_eval "SEP-10 enabled for $SEP10_HOME_DOMAIN with one signing key active or scheduled" "sep10_status '$T' | jq -e '.enabled==true and .home_domain==\"$SEP10_HOME_DOMAIN\" and ([.keys[] | select(.state==\"active\" or (.state==\"pending\" and .activate_at != null))] | length)==1' >/dev/null"
  fi
else
  warn "no state/impala.env (scripts/seed.sh): skipping account checks"
fi

if rec scenario-02-custodial-payment; then
  hr "scenario 02: custodial payment"
  H="$(get scenario-02-custodial-payment .stellar_hash)"; I="$(get scenario-02-custodial-payment .intent_id)"; ST="$(get scenario-02-custodial-payment .stroops)"
  show_txid "$H" "custodial payment, $(get scenario-02-custodial-payment .xlm) XLM"
  check "horizon: successful" tx_ok "$H"
  check_eval "bridge: intent settled with that hash and amount" "bridge_api GET '/admin/custody/intents/$I' '$T' | jq -e '.status==\"settled\" and .stellar_hash==\"$H\" and .amount_minor==$ST' >/dev/null"
  check_eval "bridge: custodial_sign row present" "bridge_api GET '/transactions?q=$H' '$T' | jq -e '[.data[]|select(.origin==\"custodial_sign\")]|length==1' >/dev/null"
  check "txid recorded in $(txid_log_file)" txid_recorded "$H"
fi
if rec scenario-03-wallet-cli; then
  hr "scenario 03: wallet cli"
  H="$(get scenario-03-wallet-cli .stellar_hash)"; W="$(get scenario-03-wallet-cli .wallet_g)"
  show_txid "$H" "wallet -> holder, $(get scenario-03-wallet-cli .xlm) XLM"
  check "horizon: successful" tx_ok "$H"
  check_eval "horizon: payment from the wallet to the holder" "curl -fsS '$HORIZON_URL/transactions/$H/operations' | jq -e --arg w '$W' --arg h '${HOLDER_G:-}' '._embedded.records[0] | .from==\$w and .to==\$h' >/dev/null"
  check "friendbot funding tx recorded" txid_recorded "$(get scenario-03-wallet-cli .friendbot_hash)"
fi
if rec scenario-04-operator-cli; then
  hr "scenario 04: operator cli"
  H="$(get scenario-04-operator-cli .stellar_hash)"
  show_txid "$H" "impalactl transfer send, $(get scenario-04-operator-cli .xlm) XLM"
  check "horizon: successful" tx_ok "$H"
  check_eval "bridge: custodial_sign row present" "bridge_api GET '/transactions?q=$H' '$T' | jq -e '[.data[]|select(.origin==\"custodial_sign\")]|length==1' >/dev/null"
fi
if rec scenario-05-card-issue; then
  hr "scenario 05: card issuance (jcardsim)"
  CID="$(get scenario-05-card-issue .card_id)"
  check_eval "card program id on the bridge equals the issued card's" "[ \"\$(curl -fsS $BRIDGE_URL/card-issuer | jq -r .program_id_hex)\" = \"$(get scenario-05-card-issue .program_id_hex)\" ]"
  check_eval "card $CID is registered for the holder" "[ \"\$(psql_impala -tAc \"select count(*) from card where card_id='$CID' and account_id='${DEMO_HOLDER_ID:-}'\" | tr -d '[:space:]')\" = 1 ]"
  CG="$(get scenario-05-card-issue .stellar_address)"
  [ -z "$CG" ] || check_eval "the card's Stellar key $CG is the one registered on its row (SEP-10 identity)" "[ \"\$(psql_impala -tAc \"select count(*) from card where card_id='$CID' and is_delete=false and stellar_address='$CG'\" | tr -d '[:space:]')\" = 1 ]"
  if "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1; then AV="$(applet_version || true)"; check_eval "simulator still serving the issued card (GET_VERSION ${AV:-unreadable})" "[ -n '$AV' ] && '$DEMO_DIR/scripts/simulator.sh' probe | grep -qF 'applet $AV '"; else warn "simulator not running: the issued card lives in that process (scenario 05 re-issues on the next run)"; fi
fi
for s in scenario-06-card-login-jvm scenario-07-android-emulator scenario-08-payala-relay scenario-09-soroban scenario-12-sep10-bridge scenario-13-sep10-third-party scenario-15-sep10-card-rules scenario-14-mfa scenario-16-cli-auth scenario-17-cli-card-setup; do
  if rec "$s"; then
    hr "$s"
    if [ "$(get "$s" .status)" = skipped ]; then log "  $s was skipped: $(get "$s" .reason)"; continue; fi
    check "$s recorded as passed ($(get "$s" .passed) assertions)" [ "$(get "$s" .status)" = passed ]
    rep="$(get "$s" .report)"
    [ -n "$rep" ] && check "$s report artifact present: $rep" [ -e "$rep" ]
  fi
done
if rec scenario-12-sep10-bridge && [ "$(get scenario-12-sep10-bridge .status)" = passed ]; then
  K="$(get scenario-12-sep10-bridge .signing_key.public_address)"
  check_eval "SEP-10: stellar.toml still names the signing key scenario 12 saw ($K), and the admin API still reports it active" \
    "[ \"\$(sep10_curl -fsS 'http://$SEP10_HOME_DOMAIN/.well-known/stellar.toml' | toml_value SIGNING_KEY)\" = '$K' ] && sep10_status '$T' | jq -e '[.keys[] | select(.state==\"active\" and .public_address==\"$K\")] | length==1' >/dev/null"
  n="$(get scenario-12-sep10-bridge '[.sign_ins[] | select(.mechanism=="sep10")] | length')"
  check "SEP-10: scenario 12 recorded $n sign-ins through the bridge's SEP-10 endpoint (both Ed25519 engines)" [ "${n:-0}" -ge 2 ]
fi
if rec scenario-13-sep10-third-party && [ "$(get scenario-13-sep10-third-party .status)" = passed ]; then
  check "SEP-10: scenario 13 recorded sign-ins at third-party servers: $(get scenario-13-sep10-third-party '[.servers[] | select(.reachable==true) | .domain] | join(", ")')" \
    [ "$(get scenario-13-sep10-third-party '[.servers[] | select(.reachable==true) | .sign_ins | length] | add // 0')" -ge 2 ]
fi
if rec scenario-15-sep10-card-rules && [ "$(get scenario-15-sep10-card-rules .status)" = passed ]; then
  check "SEP-10 card rules: scenario 15 recorded the card's signature accepted by the bridge once (the replay answered $(get scenario-15-sep10-card-rules .replay_status)) and $(get scenario-15-sep10-card-rules '.refusals | length') transactions the card refused, each with the status word expected" \
    [ "$(get scenario-15-sep10-card-rules .replay_status)" = 401 -a "$(get scenario-15-sep10-card-rules '[.refusals[] | select(.sw == .expected)] | length')" -ge 5 -a "$(get scenario-15-sep10-card-rules '[.refusals[] | select(.sw != .expected)] | length')" = 0 ]
  CG15="$(get scenario-15-sep10-card-rules .stellar_address)"
  check_eval "SEP-10 card rules: the key that signed ($CG15) is still an active card's registered Stellar key" "[ \"\$(psql_impala -tAc \"select count(*) from card where is_delete=false and stellar_address='$CG15'\" | tr -d '[:space:]')\" = 1 ]"
fi
if rec scenario-16-cli-auth && [ "$(get scenario-16-cli-auth .status)" = passed ]; then
  check "CLI: scenario 16 signed the holder in with the card through impalactl (SEP-10), and with card and PIN as a multi-factor session ($(get scenario-16-cli-auth '.impalactl.card_and_pin.amr | join(" ")'))" \
    [ "$(get scenario-16-cli-auth .impalactl.card_sign_in)" = sep10 -a "$(get scenario-16-cli-auth .impalactl.card_and_pin.mfa)" = true ]
  K16="$(get scenario-16-cli-auth .impalactl.device_key_id)"
  [ -z "$K16" ] || check_eval "CLI: the device key scenario 16 enrolled is revoked on the bridge (no live mfa_device_key row for it)" \
    "[ \"\$(psql_impala -tAc \"select count(*) from mfa_device_key where key_id::text='$K16' and is_delete=false\" | tr -d '[:space:]')\" = 0 ]"
fi
if rec scenario-17-cli-card-setup && [ "$(get scenario-17-cli-card-setup .status)" = passed ]; then
  C17="$(get scenario-17-cli-card-setup .card_id)"; G17="$(get scenario-17-cli-card-setup .stellar_address)"
  check_eval "card setup: the card impalactl set up ($C17, a $(get scenario-17-cli-card-setup .card_cap) CAP on $(get scenario-17-cli-card-setup .card_platform) hardware) is still the holder's active, certified card with its Stellar key $G17" \
    "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$C17') and account_id='${DEMO_HOLDER_ID:-}' and is_delete=false and cert_issuer_version>=1 and stellar_address='$G17'\" | tr -d '[:space:]')\" = 1 ]"
  check "card setup: scenario 17 recorded the reference tool agreeing with impalactl about that card, and a PIN blocked by $(get scenario-17-cli-card-setup .pin.blocked_after_wrong_tries) wrong tries reset with the master PIN" \
    [ "$(get scenario-17-cli-card-setup .setup.reference_tool_agrees)" = true -a "$(get scenario-17-cli-card-setup .pin.reset_with_master_pin)" = true ]
fi
if rec scenario-14-mfa && [ "$(get scenario-14-mfa .status)" = passed ]; then
  check "MFA: scenario 14 stepped a session up to multi-factor and enforced the per-account mandate" \
    [ "$(get scenario-14-mfa '.stepped_up.mfa')" = true -a "$(get scenario-14-mfa '.mandate_enforced')" = true ]
fi

if rec scenario-08-payala-relay; then
  if payala_get / >/dev/null 2>&1; then
    for p in $(get scenario-08-payala-relay '.payala_tx_ids[]'); do
      check_eval "payala stub still holds transfer $p as one server-signed Order" "payala_get '/transfers?hash=$p' | jq -e '[.Data[]|select(.kind==\"Order\" and .counter<0)]|length==1' >/dev/null"
    done
  else
    warn "payala stub not answering: its ledger is not re-checked"
  fi
fi

hr "testnet transactions of this run"
n=0; bad=0
for h in $(cat "$RECORDS_DIR"/scenario-*.json 2>/dev/null | jq -r '.stellar_hash? // empty, .friendbot_hash? // empty' | sort -u); do
  n=$((n + 1)); tx_ok "$h" || { fail_line "$h not successful on Horizon"; bad=$((bad + 1)); }
done
check "all $n transaction hashes recorded by this run's scenarios are on Horizon and successful" [ "$bad" -eq 0 ]
log "  (the historical log state/testnet-txids.tsv survives resets: scripts/txids.sh --check re-confirms all of it)"

log ""
[ "$FAILS" -eq 0 ] && ok "verify: all $PASSES checks passed" || die "verify: $FAILS of $(( PASSES + FAILS )) checks failed"
