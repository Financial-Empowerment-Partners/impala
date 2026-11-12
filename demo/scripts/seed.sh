#!/usr/bin/env bash
# Bootstrap the bridge for the demo: admin (first row + password), custody caps, the three custodial
# users (agent, beneficiary, card holder), Friendbot funding on testnet, mirror sync mode, the card
# program issuer key, and the SEP-10 signing key (generated first and activated last, so its
# activation delay runs while the scenarios before the card lanes do). Idempotent: re-running reuses
# what exists. Writes state/impala.env.
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

# ---------------------------------------------------------------- SEP-10 signing key, step 1 of 2: generate (generate-only; sealed by the protector)
# Generated here and activated at the end of this script: the bridge refuses to activate a key until its
# own key ring has opened it (one 30 s poll), and the accounts below are seeded in the meantime.
SEP10_VERSION=""; sep10="null"; KEYOPS_T0="$(now_s)"
if sep10_enabled; then
  sep10="$(sep10_status "$ADMIN_JWT")"
  [ "$(http_code)" = "200" ] || die "GET /admin/sep10/signing-keys failed ($(http_code)): is the bridge image older than the SEP-10 routes? scripts/build.sh bridge"
  printf '%s' "$sep10" | jq -e --arg d "$SEP10_HOME_DOMAIN" '.enabled==true and .home_domain==$d' >/dev/null \
    || die "the bridge does not serve SEP-10 for $SEP10_HOME_DOMAIN (enabled=$(printf '%s' "$sep10" | jq -r .enabled), home_domain=$(printf '%s' "$sep10" | jq -r .home_domain)): scripts/up.sh recreates it with compose.yaml's settings"
  if printf '%s' "$sep10" | jq -e '[.keys[] | select(.state=="active" or .state=="pending")] | length >= 1' >/dev/null; then
    ok "SEP-10 signing key present: $(printf '%s' "$sep10" | jq -r '[.keys[] | select(.state=="active" or .state=="pending")][0] | "v\(.version) \(.state) fingerprint \(.fingerprint)"')"
  else
    info "generating the SEP-10 signing key (POST /admin/sep10/signing-keys/generate; pending until activated)"
    gen10="$(bridge_api POST /admin/sep10/signing-keys/generate "$ADMIN_JWT" '{}')"
    [ "$(http_code)" = "201" ] || die "sep10 signing-key generate failed ($(http_code)): $gen10"
    ok "SEP-10 signing key v$(printf '%s' "$gen10" | jq -r .version) generated: $(printf '%s' "$gen10" | jq -r .public_address) fingerprint $(printf '%s' "$gen10" | jq -r .fingerprint) (sealed by OpenBao Transit; never returned)"
  fi
  SEP10_VERSION="$(sep10_status "$ADMIN_JWT" | jq -r '[.keys[] | select(.state=="pending" and .activate_at==null)][0].version // empty')"
fi

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

# ---------------------------------------------------------------- SEP-10 signing key, step 2 of 2: activate (takes over after the 120 s activation delay)
if sep10_enabled && [ -n "$SEP10_VERSION" ]; then
  i=0
  until sep10_status "$ADMIN_JWT" | jq -e --argjson v "$SEP10_VERSION" '[.keys[] | select(.version==$v and .opened==true)] | length==1' >/dev/null; do
    i=$((i + 1))
    [ "$i" -le 20 ] || die "the bridge's key ring did not open SEP-10 signing key v$SEP10_VERSION within 60 s (scripts/logs.sh: lines starting 'sep10 ring:'; OpenBao reachable?)"
    [ "$i" = 1 ] && log "  waiting for the bridge's key ring to open v$SEP10_VERSION (it reads new keys every 30 s; activation is refused before that)"
    sleep 3
  done
  net10="$(printf '%s' "$sep10" | jq -r .network)"
  act_body="$(jq -cn --arg p "activate sep10-signing $net10" '{confirm_supersede:"none", confirm_phrase:$p}')"
  act10="$(bridge_api POST "/admin/sep10/signing-keys/$SEP10_VERSION/activate" "$ADMIN_JWT" "$act_body")"
  if [ "$(http_code)" = "429" ]; then
    # Key-custody calls share one budget: 5 per 60 s per operator. On a fresh database this script has just
    # made five (the SEP-10 key, three custodial seeds, the issuer key); the sixth waits for the window.
    pause=$(( 61 - ( $(now_s) - KEYOPS_T0 ) )); [ "$pause" -ge 1 ] && [ "$pause" -le 61 ] || pause=61
    warn "key-custody budget used up (5 calls per 60 s per operator: the seeds and keys above); waiting ${pause}s, then one retry"
    sleep "$pause"
    act10="$(bridge_api POST "/admin/sep10/signing-keys/$SEP10_VERSION/activate" "$ADMIN_JWT" "$act_body")"
  fi
  [ "$(http_code)" = "200" ] || die "sep10 signing-key activate failed ($(http_code)): $act10"
  ok "SEP-10 signing key v$SEP10_VERSION activated: takes over at $(printf '%s' "$act10" | jq -r .activate_at) on every bridge instance (the scenarios that need it wait for that)"
fi
if sep10_enabled; then sep10="$(sep10_status "$ADMIN_JWT")"; fi

umask 077
cat > "$STATE_DIR/impala.env" <<EOT
ADMIN_G=$ADMIN_G
AGENT_G=$AGENT_G
BENEF_G=$BENEF_G
HOLDER_G=$HOLDER_G
EOT
record_json seed "$(jq -cn --arg a "$ADMIN_G" --arg ag "$AGENT_G" --arg b "$BENEF_G" --arg h "$HOLDER_G" --argjson issuer "$issuer" --argjson sep10 "$sep10" --arg at "$(utc_now)" --argjson t "$(( $(now_s) - t0 ))" \
  '{admin_g:$a, agent_g:$ag, beneficiary_g:$b, holder_g:$h, card_issuer:$issuer,
    sep10:(if $sep10 == null then null else ($sep10 | {enabled, home_domain, web_auth_endpoint, keys:[.keys[] | {version, state, public_address, fingerprint, activate_at}]}) end),
    seeded_at:$at, seconds:$t}')"
timing "seed.sh" "$(( $(now_s) - t0 ))" passed
log ""
ok "accounts (login = the uuid, passwords in .env):"
log "  admin        $PAYALA_ADMIN_ID  role=admin      $ADMIN_G (not funded, never signs)"
log "  agent        $PAYALA_AGENT_ID  custodial       $AGENT_G  $(horizon_native_balance "$AGENT_G") XLM"
log "  beneficiary  $PAYALA_BENEFICIARY_ID  custodial       $BENEF_G  $(horizon_native_balance "$BENEF_G") XLM"
log "  holder       $DEMO_HOLDER_ID  custodial       $HOLDER_G  $(horizon_native_balance "$HOLDER_G") XLM"
log "  explorer     $(explorer_account_url "$AGENT_G")"
if sep10_enabled; then
  log "  SEP-10       home domain $SEP10_HOME_DOMAIN; signing key $(printf '%s' "$sep10" | jq -r '[.keys[] | select(.state=="active" or .state=="pending")][0] | "v\(.version) \(.state)\(if .activate_at then " (takes over at " + .activate_at + ")" else "" end)"')"
fi
log "  UI: $UI_URL  (Account ID = a uuid above)"
log "next: scripts/scenario-01-stack.sh (or scripts/run-all.sh)"
