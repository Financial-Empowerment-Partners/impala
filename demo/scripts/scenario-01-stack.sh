#!/usr/bin/env bash
# Scenario 01 — the stack: the bridge is healthy on Stellar testnet, every migration was applied by the
# operator step, the admin UI proxies to it, OpenBao seals seeds and serves SSO, the card program is ready.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq
t0="$(now_s)"
hr "scenario 01: stack"

health="$(curl -fsS "$BRIDGE_URL/health")"
check_jq "bridge /health healthy on testnet (database + redis ok)" '.status=="healthy" and .database=="ok" and .redis=="ok" and .stellar_network=="testnet"' "$health"
check "bridge /readyz answers 200" curl -fsS -o /dev/null "$BRIDGE_URL/readyz"
net="$(curl -fsS "$BRIDGE_URL/network")"
check_jq "bridge /network passphrase is the testnet passphrase" ".network_passphrase==\"$TESTNET_PASSPHRASE\"" "$net"
version="$(curl -fsS "$BRIDGE_URL/version")"
check_jq "bridge /version reports a build" 'has("version") or has("git_sha") or has("build")' "$version"
applied=$(psql_impala -tAc "select count(*) from _sqlx_migrations where success" | tr -d '[:space:]')
files=$(ls "$REPO_DIR"/impala-bridge/migrations/*.sql | wc -l | tr -d ' ')
check "every repo migration is recorded by sqlx ($applied of $files)" [ "$applied" = "$files" ]
latest=$(psql_impala -tAc "select max(version) from _sqlx_migrations where success" | tr -d '[:space:]')
check "latest migration version is $(ls "$REPO_DIR"/impala-bridge/migrations/*.sql | tail -n1 | xargs basename | cut -d_ -f1 | sed 's/^0*//')" [ "$latest" = "$(ls "$REPO_DIR"/impala-bridge/migrations/*.sql | tail -n1 | xargs basename | cut -d_ -f1 | sed 's/^0*//')" ]
check_eval "admin UI serves its index" "curl -fsS '$UI_URL/' | grep -qi impala"
check_eval "admin UI proxies /api/testnet to the bridge" "[ \"\$(curl -fsS '$UI_URL/api/testnet/network' | jq -r .stellar_network)\" = testnet ]"
check_eval "admin UI config lists testnet only (no mainnet network entry)" "curl -fsS '$UI_URL/config.js' | grep -Eq '^[[:space:]]*testnet[[:space:]]*:' && ! curl -fsS '$UI_URL/config.js' | grep -Eq '^[[:space:]]*mainnet[[:space:]]*:'"
check "OpenBao transit key impala-seeds exists" compose exec -T openbao sh -c 'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$BAO_DEV_ROOT_TOKEN_ID" bao read transit/keys/impala-seeds'
providers="$(curl -fsS "$BRIDGE_URL/auth/providers" 2>/dev/null || echo '{}')"
check_eval "bridge advertises the OpenBao SSO provider" "printf '%s' '$providers' | grep -q openbao"
check "OpenBao OIDC discovery answers on the host port" curl -fsS -o /dev/null "$OPENBAO_URL/v1/identity/oidc/provider/openbao/.well-known/openid-configuration"
check_eval "bridge SSO config for openbao is enabled (client id minted at bootstrap reached the bridge)" "curl -fsS '$BRIDGE_URL/auth/sso/openbao/config' | jq -e '.enabled==true and .provider==\"openbao\"' >/dev/null"
check "OpenBao still holds the Transit key that sealed the seeds (canary decrypts)" transit_canary_ok
issuer="$(curl -fsS "$BRIDGE_URL/card-issuer")"
check_jq "card program issuer key configured (program id + redemption identity published)" '.configured==true and (.program_id_hex|length)==32' "$issuer"
check_eval "otel collector receives the bridge's telemetry (logs show OTLP traffic)" "compose logs --tail=200 otel-collector 2>/dev/null | grep -qi 'ResourceSpans\|ResourceMetrics\|Metrics\|Traces'"
check_eval "no container is restarting" "! compose ps 2>/dev/null | grep -qi restarting"

finish_scenario scenario-01-stack "$(jq -cn --argjson h "$health" --argjson v "$version" --argjson n "$net" --argjson i "$issuer" --arg e "$ENGINE" --argjson m "${applied:-0}" \
  '{engine:$e, health:$h, version:$v, network:$n, card_issuer:$i, migrations_applied:$m}')" "$t0"
