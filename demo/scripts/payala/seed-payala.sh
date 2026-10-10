#!/usr/bin/env bash
# Make sure the six Payala demo users exist on the stub (mint, admin, agent, beneficiary, sync, holder — seeded
# from build/payala-stub/seed.json when the stub starts; existing users are never reset) and fund the agent from
# the mint with a real Order (POST /transfers/order). Idempotent: re-running tops the agent back up to
# DEMO_AGENT_FUNDING_CENTS.
set -euo pipefail
. "$(dirname "$0")/../lib.sh"
. "$(dirname "$0")/lib-payala.sh"
load_env
require_cmd curl jq od
require_env PAYALA_MINT_ID PAYALA_AGENT_ID DEMO_AGENT_FUNDING_CENTS
wait_http "$PAYALA_URL/" 30 2

info "the stub's seeded users (build/payala-stub/seed.json, applied when the stub starts)"
n="$(payala_users_json | jq '[.Data[] | select(.card_id != null)] | length')"
[ "$n" -ge 6 ] || die "expected 6 seeded users with cards, found $n (scripts/prepare.sh renders the seed; scripts/up.sh starts the stub)"
ok "$n Payala users with cards"

bal="$(payala_balance "$PAYALA_AGENT_ID")"
if [ "$bal" -lt "$DEMO_AGENT_FUNDING_CENTS" ]; then
  top=$((DEMO_AGENT_FUNDING_CENTS - bal))
  info "funding the agent from the mint: $top cents via POST /transfers/order"
  "$DEMO_DIR/scripts/payala/payala-order.sh" "$PAYALA_MINT_ID" "$PAYALA_AGENT_ID" "$top" "$(printf '%s' 'demo-funding' | bin_to_hex)" >/dev/null
else
  ok "agent already funded ($bal cents)"
fi

info "Payala balances"
payala_users_json | jq -r '.Data[] | "  \(.user_id)  \(.role|.+"      "|.[0:6])  \(.given_name) \(.family_name): \(.balance) cents"' >&2
log "next: scripts/payala/demo-payment.sh (forward direction), or scripts/scenario-08-payala-relay.sh for both directions with assertions"
