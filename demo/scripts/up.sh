#!/usr/bin/env bash
# Bring the stack up in phases (works with docker compose and podman compose without relying on
# depends_on conditions), run the operator migration step, then check for the failures that stay silent.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq
[ -f "$BUILD_DIR/impala-bridge.Containerfile" ] || die "run scripts/prepare.sh first"
image_exists "$IMAGE_BRIDGE" || die "image $IMAGE_BRIDGE missing: run scripts/build.sh"
[ -f "$BUILD_DIR/payala-stub/seed.json" ] || die "build/payala-stub/seed.json missing: run scripts/prepare.sh"
t0="$(now_s)"

if ! stack_running; then
  for p in $UI_PORT $BRIDGE_PORT $OPENBAO_PORT $PAYALA_PORT; do
    if port_open "$p"; then
      die "host port $p is already in use: another stack (the repo's impala-bridge compose, the external impala-demo kit, or the other engine)? stop it, or change the port in .env"
    fi
  done
fi

info "phase 1/5: postgres, redis, openbao, otel-collector, payala-stub"
compose up -d --no-build --remove-orphans postgres redis openbao otel-collector payala-stub   # --remove-orphans: containers of services an older kit version defined

info "phase 2/5: openbao transit key + OIDC test IdP (one-shot openbao-init)"
compose up -d --no-build openbao-init
i=0
until compose logs openbao-init 2>/dev/null | grep -q 'OIDC test IdP ready'; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then compose logs openbao-init >&2 || true; die "openbao-init did not finish"; fi
  sleep 2
done
ok "transit key impala-seeds + OIDC IdP ready"
if compose logs openbao-init 2>/dev/null | grep -q 'transit key re-created'; then
  die "OpenBao restarted and re-created the Transit key: every custodial seed and the card issuer key the bridge sealed are undecryptable. Run scripts/reset.sh --yes, then scripts/up.sh"
fi

info "phase 3/5: migrations (RUN_MODE=migrate, operator step; sqlx records versions)"
if compose run --rm --no-deps impala-migrate >"$STATE_DIR/migrate.log" 2>&1; then
  ok "migrations: $(grep -c '' "$STATE_DIR/migrate.log") log lines; see state/migrate.log"
else
  cat "$STATE_DIR/migrate.log" >&2
  grep -q 'previously applied but has been modified' "$STATE_DIR/migrate.log" && die "sqlx VersionMismatch: a migration already applied to this volume differs from the repo file (sqlx records version + checksum). Run scripts/reset.sh --yes for a fresh volume, then scripts/up.sh"
  die "impala-migrate failed"
fi

info "phase 4/5: impala-bridge"
compose up -d --no-build impala-bridge
info "waiting for the bridge (it checks Horizon testnet at boot; needs outbound HTTPS)"
wait_http "$BRIDGE_URL/readyz" 150 2
wait_http "$PAYALA_URL/" 60 2
ok "bridge ready: $(curl -fsS "$BRIDGE_URL/health" | jq -c '{status,database,redis,stellar_network}')"

info "phase 5/5: impala-ui (nginx resolves the bridge name at startup, so it starts last and is recreated on every up)"
compose up -d --no-build --no-deps --force-recreate impala-ui   # --no-deps: podman-compose would otherwise recreate the dependencies (incl. OpenBao)
wait_http "$UI_URL/" 30 2
wait_http "$UI_URL/api/testnet/network" 30 2
ok "ui proxy -> bridge: $(curl -fsS "$UI_URL/api/testnet/network" | jq -r '.stellar_network')"

info "silent-failure checks"
applied=$(psql_impala -tAc "select count(*) from _sqlx_migrations where success" | tr -d '[:space:]')
files=$(ls "$REPO_DIR"/impala-bridge/migrations/*.sql | wc -l | tr -d ' ')
[ "${applied:-0}" = "$files" ] || die "sqlx applied $applied migrations but the repo has $files files (state/migrate.log)"
ok "schema: $applied/$files migrations recorded in _sqlx_migrations"
pp=$(curl -fsS "$BRIDGE_URL/network" | jq -r '.network_passphrase')
[ "$pp" = "$TESTNET_PASSPHRASE" ] || die "bridge is not on testnet: $pp"
sso=$(curl -fsS "$BRIDGE_URL/auth/providers" 2>/dev/null | jq -c '.' 2>/dev/null || echo '{}')
printf '%s' "$sso" | grep -q openbao && ok "sso: openbao provider advertised by /auth/providers" || warn "sso: /auth/providers does not list openbao ($sso)"
# The stub applies the seed only on its first start and never overwrites an existing user or card key, and a
# re-rendered seed does not recreate the container: compare the live ledger with build/payala-stub/seed.json.
stub_state="$(payala_get /__stub/state)"
seed_diff="$(jq -rn --argjson seed "$(cat "$BUILD_DIR/payala-stub/seed.json")" --argjson live "$stub_state" '
  [ $seed.users[] | . as $u | ($live.cards[] | select(.user_id == $u.id)) as $c
    | if ($c|not) then "\($u.id): not on the stub" elif $c.signing_public_key_hex != $u.card.signing_public_key_hex then "\($u.id): card key differs from state/keys" else empty end ] | .[]')"
if [ -n "$seed_diff" ]; then
  printf '%s\n' "$seed_diff" | sed 's/^/  /' >&2
  die "the Payala stub's ledger (volume payala-stub-data) does not match build/payala-stub/seed.json: the ids or the demo keys changed after the stub was first seeded. scripts/reset.sh --yes, then scripts/up.sh"
fi
n="$(printf '%s' "$stub_state" | jq '.cards|length')"
ok "payala stub: ledger matches the seed ($n users with cards, $(printf '%s' "$stub_state" | jq -r '.transfers') transfer(s); volume payala-stub-data)"
timing "up.sh" "$(( $(now_s) - t0 ))" passed

log ""
ok "stack is up ($ENGINE, $(( $(now_s) - t0 ))s)"
log "  admin UI        $UI_URL   (Account ID = the uuid of a seeded account; or Continue with OpenBao: testuser / testpassword)"
log "  impala-bridge   $BRIDGE_URL   (/health /network /version)"
log "  OpenBao         $OPENBAO_URL   (dev mode, root token in .env)"
log "  Payala stub     $PAYALA_URL   (/users /transfers /__stub/requests — payala-stub/README.md)"
log "next: scripts/seed.sh"
