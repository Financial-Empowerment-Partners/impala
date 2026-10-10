#!/usr/bin/env bash
# Bootstrap the bridge for the demo: admin (first row + password), custody caps, the three custodial
# users (agent, beneficiary, card holder), Friendbot funding on testnet, mirror sync mode, and the
# card program issuer key. Idempotent: re-running reuses what exists. Writes state/impala.env.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
require_cmd curl jq
require_env PAYALA_ADMIN_ID PAYALA_AGENT_ID PAYALA_BENEFICIARY_ID DEMO_HOLDER_ID IMPALA_ADMIN_PASSWORD IMPALA_AGENT_PASSWORD IMPALA_BENEFICIARY_PASSWORD IMPALA_HOLDER_PASSWORD
LUMEN="$(lumencli_bin)" || die "bin/lumencli missing: run scripts/build.sh tools"
t0="$(now_s)"
wait_bridge 30

# ---------------------------------------------------------------- admin: first row (trigger + explicit role) + password
if [ -z "${ADMIN_G:-}" ]; then
  ADMIN_G="$(psql_impala -tAc "select stellar_account_id from impala_account where payala_account_id='$PAYALA_ADMIN_ID'" | tr -d '[:space:]')"
fi
if [ -z "${ADMIN_G:-}" ]; then
  info "generating the admin's (non-custodial, unfunded) Stellar address with lumencli"
  ADMIN_G="$(LUMEN_NETWORK=testnet "$LUMEN" account new 2>/dev/null | grep -Eo 'G[A-Z2-7]{55}' | head -n1 || true)"
  [ -n "$ADMIN_G" ] || die "could not parse a G address from lumencli"
fi
psql_impala -c "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name, affiliation, role)
  VALUES ('$ADMIN_G', '$PAYALA_ADMIN_ID', 'Demo', 'Admin', 'Payala', 'admin') ON CONFLICT (payala_account_id) DO NOTHING;" >/dev/null
ok "admin row: payala_account_id=$PAYALA_ADMIN_ID stellar=$ADMIN_G"
act="$(bridge_authenticate "$PAYALA_ADMIN_ID" "$IMPALA_ADMIN_PASSWORD")"
ok "admin password $act"
ADMIN_JWT="$(admin_jwt)"
role="$(jwt_claim "$ADMIN_JWT" role)"
[ "$role" = "admin" ] || die "admin token carries role '$role', expected admin"
ok "admin token role=admin (DB role + ADMIN_ACCOUNT_IDS allowlist)"

# ---------------------------------------------------------------- custody caps (default 0 = refuse everything)
bridge_api PUT /admin/custody/policy "$ADMIN_JWT" '{"per_tx_max_stroops":1000000000,"per_account_daily_max_stroops":10000000000}' >/dev/null
[ "$(http_code)" = "200" ] || die "custody policy update failed ($(http_code))"
bridge_api GET /admin/custody/policy "$ADMIN_JWT" | jq -e '.configured==true and .paused==false' >/dev/null || die "custody policy not configured"
ok "custody caps: 100 XLM per tx, 1000 XLM per account per day"

# ---------------------------------------------------------------- custodial users
custodial_accounts="$(bridge_api GET '/admin/custody/accounts?per_page=100' "$ADMIN_JWT")"
provision() { # <payala_id> <label> <first> <last> <password>  -> prints G
  local id="$1" label="$2" first="$3" last="$4" pw="$5" g resp
  g="$(printf '%s' "$custodial_accounts" | jq -r --arg id "$id" '.data[] | select(.payala_account_id==$id) | .stellar_account_id')"
  if [ -z "$g" ]; then
    resp="$(bridge_api POST /admin/stellar-seeds/generate "$ADMIN_JWT" "$(jq -cn --arg id "$id" --arg l "$label" '{payala_account_id:$id,label:$l}')")"
    [ "$(http_code)" = "200" ] || die "stellar-seeds/generate failed for $id ($(http_code)): $resp"
    g="$(printf '%s' "$resp" | jq -er .stellar_account_id)" || die "no stellar_account_id in: $resp"
    ok "custodial seed generated for $label: $g (sealed by OpenBao Transit; the bridge never returns it)"
  else
    ok "custodial account for $label exists: $g"
  fi
  bridge_api PUT /account "$ADMIN_JWT" "$(jq -cn --arg id "$id" --arg f "$first" --arg l "$last" '{payala_account_id:$id,first_name:$f,last_name:$l,affiliation:"Payala"}')" >/dev/null
  [ "$(http_code)" = "200" ] || warn "PUT /account for $id returned $(http_code)"
  bridge_authenticate "$id" "$pw" >/dev/null
  bridge_api PUT "/admin/accounts/$id/sync-mode" "$ADMIN_JWT" '{"sync_mode":"mirror"}' >/dev/null
  [ "$(http_code)" = "200" ] || warn "sync-mode for $id returned $(http_code)"
  printf '%s' "$g"
}
AGENT_G="$(provision "$PAYALA_AGENT_ID" "Agent" "Ada" "Agent" "$IMPALA_AGENT_PASSWORD")"
BENEF_G="$(provision "$PAYALA_BENEFICIARY_ID" "Beneficiary" "Ben" "Beneficiary" "$IMPALA_BENEFICIARY_PASSWORD")"
HOLDER_G="$(provision "$DEMO_HOLDER_ID" "Holder" "Cara" "Holder" "$IMPALA_HOLDER_PASSWORD")"

# ---------------------------------------------------------------- testnet funding (the bridge never calls Friendbot)
friendbot_fund "$AGENT_G"
friendbot_fund "$BENEF_G"
friendbot_fund "$HOLDER_G"

# ---------------------------------------------------------------- card program issuer key (generate-only; sealed by the protector)
issuer="$(curl -fsS "$BRIDGE_URL/card-issuer")"
if printf '%s' "$issuer" | jq -e '.configured==true' >/dev/null 2>&1; then
  ok "card issuer key present: fingerprint $(printf '%s' "$issuer" | jq -r '.fingerprint // "?"') program_id $(printf '%s' "$issuer" | jq -r '.program_id_hex // "?"')"
else
  info "generating the card program issuer key (POST /admin/card-issuer/generate; first generation mints the program id)"
  gen="$(bridge_api POST /admin/card-issuer/generate "$ADMIN_JWT" '{}')"
  [ "$(http_code)" = "200" ] || die "card-issuer generate failed ($(http_code)): $gen"
  ok "issuer key v$(printf '%s' "$gen" | jq -r .version): fingerprint $(printf '%s' "$gen" | jq -r .fingerprint) program_id $(printf '%s' "$gen" | jq -r .program_id_hex) redemption_uuid $(printf '%s' "$gen" | jq -r .redemption_uuid)"
  issuer="$(curl -fsS "$BRIDGE_URL/card-issuer")"
fi

umask 077
cat > "$STATE_DIR/impala.env" <<EOT
ADMIN_G=$ADMIN_G
AGENT_G=$AGENT_G
BENEF_G=$BENEF_G
HOLDER_G=$HOLDER_G
EOT
record_json seed "$(jq -cn --arg a "$ADMIN_G" --arg ag "$AGENT_G" --arg b "$BENEF_G" --arg h "$HOLDER_G" --argjson issuer "$issuer" --arg at "$(utc_now)" --argjson t "$(( $(now_s) - t0 ))" \
  '{admin_g:$a, agent_g:$ag, beneficiary_g:$b, holder_g:$h, card_issuer:$issuer, seeded_at:$at, seconds:$t}')"
timing "seed.sh" "$(( $(now_s) - t0 ))" passed
log ""
ok "accounts (login = the uuid, passwords in .env):"
log "  admin        $PAYALA_ADMIN_ID  role=admin      $ADMIN_G (not funded, never signs)"
log "  agent        $PAYALA_AGENT_ID  custodial       $AGENT_G  $(horizon_native_balance "$AGENT_G") XLM"
log "  beneficiary  $PAYALA_BENEFICIARY_ID  custodial       $BENEF_G  $(horizon_native_balance "$BENEF_G") XLM"
log "  holder       $DEMO_HOLDER_ID  custodial       $HOLDER_G  $(horizon_native_balance "$HOLDER_G") XLM"
log "  explorer     $(explorer_account_url "$AGENT_G")"
log "  UI: $UI_URL  (Account ID = a uuid above)"
log "next: scripts/scenario-01-stack.sh (or scripts/run-all.sh)"
