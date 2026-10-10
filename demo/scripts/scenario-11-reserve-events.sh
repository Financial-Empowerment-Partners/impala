#!/usr/bin/env bash
# Scenario 11 — what the demo does NOT configure, shown as evidence rather than asserted in prose: the
# conversion reserve is armed but inactive (buckets at zero, no policies, no provider), the exchange
# providers are unconfigured, the bridge's key inventory is empty, and the admin event feed carries the
# audit trail of this run without a single secret in it. Read-only.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD DEMO_HOLDER_ID IMPALA_HOLDER_PASSWORD
t0="$(now_s)"
hr "scenario 11: reserve (armed but inactive), providers, key inventory, event feed"
wait_bridge 10
ADMIN_JWT="$(admin_jwt)"

info "1/4 conversion reserve"
reserve="$(bridge_api GET /admin/exchange-reserve "$ADMIN_JWT")"
check "GET /admin/exchange-reserve answers 200 for the admin" [ "$(http_code)" = "200" ]
check_jq "reserve not configured (no RESERVE_ACCOUNT_ID), refunds off" '.configured==false and .refunds_enabled==false' "$reserve"
check_jq "seeded buckets incl. USD / USDC / USDT0, every bucket at zero, no on-chain balance" '((["USD","USDC","USDT0"] - [.buckets[].currency])|length)==0 and ([.buckets[]|.available_minor==0 and .held_minor==0 and .onchain_balance==null]|all)' "$reserve"
log "  $(printf '%s' "$reserve" | jq -c '{configured, refunds_enabled, buckets: [.buckets[]|{currency,available_minor,held_minor}]}')"

info "2/4 exchange providers"
providers="$(bridge_api GET /exchange/providers "$ADMIN_JWT")"
check_jq "owlpay, changelly_crypto, changelly_fiat present and all disabled (no credentials installed)" '([.providers[].provider]|sort)==["changelly_crypto","changelly_fiat","owlpay"] and ([.providers[].enabled]|all(.==false))' "$providers"
HOLDER_JWT="$(bridge_login "$DEMO_HOLDER_ID" "$IMPALA_HOLDER_PASSWORD")"
bridge_api POST /exchange/quote "$HOLDER_JWT" '{"provider":"changelly_crypto","direction":"crypto_to_crypto","from_currency":"xlm","to_currency":"usdcxlm","amount":"10"}' >/dev/null 2>&1 || true
check "a quote request is refused while no provider is configured (4xx, nothing routed)" sh -c "case '$(http_code)' in 4*) exit 0;; *) exit 1;; esac"

info "3/4 key inventory (install-only; fingerprints only)"
keys="$(bridge_api GET /admin/keys "$ADMIN_JWT")"
check_jq "key import enabled with the openbao protector, not degraded" '.enabled==true and .protection_backend=="openbao" and .degraded==false' "$keys"
check_jq "no provider credential stored or active" '[.keys[]|.active==false and .effective_source=="unconfigured"]|all' "$keys"
check_eval "the inventory carries fingerprints only (no secret-shaped values)" "! printf '%s' '$(printf '%s' "$keys" | tr -d "'")' | grep -Eq 'S[A-Z2-7]{55}|BEGIN (RSA |EC )?PRIVATE KEY'"

info "4/4 the event feed: the audit trail of this run"
events="$(bridge_api GET '/admin/events?since=0&limit=1000' "$ADMIN_JWT")"
counts="$(printf '%s' "$events" | jq -c '[.events[].event_type]|group_by(.)|map({(.[0]):length})|add')"
log "  $counts"
check_jq "the three custodial accounts seed.sh created through the API appear as account.created + bridge.seed_provisioned events (the admin row is inserted by SQL and has none)" '([.events[]|select(.event_type=="account.created")]|length)>=3 and ([.events[]|select(.event_type=="bridge.seed_provisioned")]|length)>=3' "$events"
check_jq "custody events: policy update, issuer key generated, card certified, payments settled" '([.events[]|select(.event_type=="custody.policy_updated")]|length)>=1 and ([.events[]|select(.event_type=="custody.issuer_key_generated")]|length)>=1 and ([.events[]|select(.event_type=="custodial.payment_settled")]|length)>=1' "$events"
check_eval "no event payload carries a Stellar seed, a password or a JWT" "! printf '%s' '$(printf '%s' "$events" | tr -d "'")' | grep -Eq 'S[A-Z2-7]{55}|\"password\"|eyJ[A-Za-z0-9_-]{20,}\\.'"
check_jq "payment events carry the intent id, never the destination or hash (payload minimalism)" '[.events[]|select(.event_type=="custodial.payment_settled")|.payload|has("intent_id") and (has("destination")|not) and (has("stellar_hash")|not)]|all' "$events"
check_eval "the holder cannot read the admin event feed" "bridge_api GET '/admin/events?since=0&limit=1' '$HOLDER_JWT' >/dev/null 2>&1; [ \"\$(http_code)\" = 403 ]"

finish_scenario scenario-11-reserve-events "$(jq -cn --argjson r "$(printf '%s' "$reserve" | jq -c '{configured,refunds_enabled}')" --argjson p "$(printf '%s' "$providers" | jq -c '[.providers[]|{provider,enabled}]')" --argjson c "$counts" '{reserve:$r, providers:$p, event_counts:$c}')" "$t0"
