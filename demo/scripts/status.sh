#!/usr/bin/env bash
# Everything at a glance: containers, bridge health, accounts, custody intents, transactions, the host
# lanes (simulator, emulator), the scenario scorecard and the last testnet transaction ids.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq

info "containers ($ENGINE, project $PROJECT)"
compose ps 2>/dev/null | sed 's/^/  /' >&2 || true

info "impala-bridge ($BRIDGE_URL)"
curl -fsS "$BRIDGE_URL/health" 2>/dev/null | jq -c '{status,database,redis,stellar_network}' | sed 's/^/  /' >&2 || warn "bridge not answering"
if [ -n "${IMPALA_ADMIN_PASSWORD:-}" ] && [ -n "${AGENT_G:-}" ] && curl -fsS -o /dev/null "$BRIDGE_URL/readyz" 2>/dev/null; then
  T="$(admin_jwt)"
  info "accounts (payala_account_id = login; custodial addresses are bridge-held seeds)"
  bridge_api GET "/accounts?per_page=50" "$T" | jq -r '.data[] | [.payala_account_id, .role, .stellar_account_id, (.first_name + " " + .last_name)] | @tsv' \
    | awk -F'\t' '{printf "  %-38s %-10s %-56s %s\n",$1,$2,$3,$4}' >&2
  info "Stellar testnet balances (Horizon)"
  for pair in "agent:$AGENT_G" "beneficiary:${BENEF_G:-}" "holder:${HOLDER_G:-}"; do
    g="${pair#*:}"; [ -n "$g" ] || continue
    log "  $(printf '%-12s' "${pair%%:*}") $g  $(horizon_native_balance "$g") XLM"
  done
  info "custody intents (newest first)"
  bridge_api GET "/admin/custody/intents?per_page=5" "$T" | jq -r '.data[]? | [.created_at[0:19], .status, (.amount_minor|tostring), (.stellar_hash // "-")[0:16], (.idempotency_key // "-")[0:24]] | @tsv' \
    | awk -F'\t' 'BEGIN{printf "  %-19s %-10s %12s %-16s %s\n","created","status","stroops","stellar_hash","idempotency_key"} {printf "  %-19s %-10s %12s %-16s %s\n",$1,$2,$3,$4,$5}' >&2
  info "transactions (newest first)"
  bridge_api GET "/transactions?per_page=10" "$T" | jq -r '.data[] | [.created_at[0:19], .origin, (.stellar_hash // "-")[0:16], (.memo // "-"), .source_account[0:8]] | @tsv' \
    | awk -F'\t' 'BEGIN{printf "  %-19s %-15s %-16s %-24s %s\n","created","origin","stellar_hash","memo","source"} {printf "  %-19s %-15s %-16s %-24s %s\n",$1,$2,$3,$4,$5}' >&2
  info "card program"
  curl -fsS "$BRIDGE_URL/card-issuer" | jq -c '{configured, fingerprint, program_id_hex, redemption_uuid}' | sed 's/^/  /' >&2
else
  warn "no seeded accounts yet (scripts/seed.sh)"
fi

info "Payala stub ($PAYALA_URL; payala-stub/README.md)"
if payala_get / >/dev/null 2>&1; then
  payala_get /users | jq -r '.Data[] | [.user_id, .role, (.given_name + " " + .family_name), (.balance|tostring)] | @tsv' \
    | awk -F'\t' '{printf "  %-38s %-8s %-18s %s cents\n",$1,$2,$3,$4}' >&2
  log "  transfers on the stub ledger: $(payala_get / | jq -r .transfers)"
else
  warn "payala stub not answering"
fi

info "host lanes"
"$DEMO_DIR/scripts/simulator.sh" status 2>&1 | sed 's/^/  /' >&2 || true
"$DEMO_DIR/scripts/emulator.sh" status 2>&1 | sed 's/^/  /' >&2 || true

if ls "$RECORDS_DIR"/scenario-*.json >/dev/null 2>&1; then
  info "scenario scorecard (state/records)"
  for f in "$RECORDS_DIR"/scenario-*.json; do
    jq -r '"  \(.scenario)\t\(.status)\t\(.passed)/\(.passed+.failed) assertions\t\(.seconds)s\t\(.finished_at)"' "$f"
  done | column -t -s "$(printf '\t')" >&2
fi
F="$(txid_log_file)"
if [ -s "$F" ]; then
  info "testnet transaction ids (last 5 of $F; scripts/txids.sh lists and checks all)"
  tail -5 "$F" | awk -F'\t' '{printf "  %-20s %-20s %s\n  %-41s %s\n", $1, $2, $3, "", $4}' >&2
fi
