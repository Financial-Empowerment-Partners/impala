#!/usr/bin/env bash
# Scenario 16 — the command-line tools speak the same authentication as the phone.
# impalactl is the operator's client of the bridge API; lumencli is a self-custody wallet that talks to the
# Stellar network only. Both sign in with SEP-10 here, each in its own role:
#   1. impalactl reads the simulated card (`card info`) and the bridge's SEP-10 service (`sep10 info`,
#      `sep10 status`, `sep10 cards`);
#   2. impalactl signs the card holder in with the card over the simulator's socket (`login --card`): a SEP-10
#      sign-in, refused while the home domain is not named (a signed challenge only ever goes to the home domain);
#   3. card and PIN in one tap (`login --card --pin`): the card verifies the PIN and signs a PIN proof, and the
#      session is multi-factor from the card alone; a wrong PIN is an error, never a PIN-less sign-in; and the
#      legacy card challenge still signs the same card in (`--no-sep10`);
#   4. a device key on this machine steps a password session up (`mfa device enroll`, `mfa step-up --device`);
#   5. lumencli reads the bridge's challenge with the Stellar SDK (`sep10 inspect`), then a fresh wallet key signs
#      in at a third-party SEP-10 server (`sep10 login`) and uses the token it receives.
# Secrets travel by environment, never argv (the password, the card PIN, the wallet seed); the scenario stores
# no token. The card is whatever the simulator serves (DEMO_CARD_PLATFORM).
# Usage: scripts/scenario-16-cli-auth.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env DEMO_HOLDER_ID HOLDER_G PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD PAYALA_BENEFICIARY_ID IMPALA_BENEFICIARY_PASSWORD IMPALA_USER_PIN
CTL="$(impalactl_bin)" || die "bin/impalactl missing: run scripts/build.sh tools"
LUMEN="$(lumencli_bin)" || die "bin/lumencli missing: run scripts/build.sh tools"
t0="$(now_s)"
hr "scenario 16: SEP-10 and multi-factor from the command line (impalactl, lumencli)"
wait_bridge 10
if ! sep10_enabled; then
  warn "DEMO_SEP10=$DEMO_SEP10: the bridge runs without SEP-10; nothing to do"
  record_json scenario-16-cli-auth "$(jq -cn --arg at "$(utc_now)" '{scenario:"scenario-16-cli-auth", status:"skipped", reason:"DEMO_SEP10 is off", finished_at:$at}')"
  exit 0
fi
export IMPALA_ENDPOINT="$BRIDGE_URL" LUMEN_NETWORK=testnet
CARD_TCP="tcp:127.0.0.1:$SIM_PORT"
CFG="$STATE_DIR/impalactl"; CFG_H="$CFG/holder-card"; CFG_A="$CFG/admin-auth"; CFG_B="$CFG/beneficiary-auth"
rm -rf "$CFG_H" "$CFG_A" "$CFG_B"; mkdir -p "$CFG_H" "$CFG_A" "$CFG_B"; chmod 700 "$CFG" "$CFG_H" "$CFG_A" "$CFG_B"
ctl_h() { IMPALA_CONFIG_DIR="$CFG_H" "$CTL" "$@"; }
ctl_a() { IMPALA_CONFIG_DIR="$CFG_A" "$CTL" "$@"; }
ctl_b() { IMPALA_CONFIG_DIR="$CFG_B" "$CTL" "$@"; }
ERR="$(mktemp "${TMPDIR:-/tmp}/impala-suite-cli.XXXXXX")"; HDR="$(mktemp "${TMPDIR:-/tmp}/impala-suite-cli.XXXXXX")"
# Whatever happens below, a device key this run enrolled for the beneficiary is removed again.
KEY_ID=""; KEY_LIVE=0
restore() {
  [ "$KEY_LIVE" = 1 ] && { ctl_a mfa admin revoke-device "$PAYALA_BENEFICIARY_ID" "$KEY_ID" --yes >/dev/null 2>&1 || true; }
  rm -f "$ERR" "$HDR"; cleanup_tmp
}
trap restore EXIT
amr_of() { IMPALA_CONFIG_DIR="$1" "$CTL" mfa status --json 2>/dev/null || echo '{}'; }
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo '?'; }   # GNU, then BSD

info "1/5 impalactl reads the card and the bridge's SEP-10 service"
SIM_HW="$("$DEMO_DIR/scripts/simulator.sh" hardware 2>/dev/null | cut -f1 || true)"
if ! "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1 || [ ! -f "$RECORDS_DIR/scenario-05-card-issue.json" ] || [ "$SIM_HW" != "$DEMO_CARD_PLATFORM" ]; then
  log "  no issued card of $DEMO_CARD_PLATFORM hardware in a running simulator: running scenario 05 first"
  "$DEMO_DIR/scripts/scenario-05-card-issue.sh" >/dev/null
fi
SIM_CAP="$("$DEMO_DIR/scripts/simulator.sh" hardware | cut -f3)"
CARD_ID="$(record_get scenario-05-card-issue .card_id)"; CARD_G="$(record_get scenario-05-card-issue .stellar_address)"
APPLET_VERSION="$(applet_version)" || die "cannot read the applet version from impala-card (applet BuildConfig.java)"
ci="$(ctl_h card info --card "$CARD_TCP" --json 2>/dev/null || echo '{}')"
check_jq "impalactl card info: applet $APPLET_VERSION, the issued card and its account, personalized, with the bridge's certificate" \
  ".applet==\"$APPLET_VERSION\" and (.card_id | ascii_downcase)==\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\" and .account_id==\"$DEMO_HOLDER_ID\" and .state==\"personalized\" and .issuer_certificate==true" "$ci"
check_jq "impalactl card info: the card's Stellar key ($CARD_G, $SIM_CAP engine, bound to the card key) and a provisioned user PIN that sign-in does not require" \
  ".stellar_key.address==\"$CARD_G\" and .stellar_key.engine==\"$SIM_CAP\" and .stellar_key.bound==true and .user_verification.pin_provisioned==true and .user_verification.sign_in_pin_required==false" "$ci"
sep10_wait_active "$(admin_jwt)" 240 >/dev/null || die "SEP-10 is not in service on this bridge (scripts/seed.sh arms it)"
IMPALA_PASSWORD="$IMPALA_ADMIN_PASSWORD" ctl_a login --username "$PAYALA_ADMIN_ID" >/dev/null 2>&1 || die "impalactl login failed for the admin"
st="$(ctl_a sep10 status --json 2>/dev/null || echo '{}')"
check_jq "impalactl sep10 status (admin): enabled for $SEP10_HOME_DOMAIN, key ring live, exactly one key active and open on this instance" \
  ".enabled==true and .home_domain==\"$SEP10_HOME_DOMAIN\" and .key_ring_live==true and ([.keys[] | select(.state==\"active\" and .opened==true)] | length)==1" "$st"
ACTIVE_G="$(printf '%s' "$st" | jq -r '[.keys[] | select(.state=="active")][0].public_address // empty')"
si="$("$CTL" sep10 info 2>&1 || true)"
si_has() { printf '%s\n' "$si" | grep -q -- "$1"; }
check_eval "impalactl sep10 info (public, no session): stellar.toml names that key ($ACTIVE_G) and the web-auth endpoint, and says which home domain to name" \
  "si_has 'SIGNING_KEY: *$ACTIVE_G' && si_has 'WEB_AUTH_ENDPOINT: *http://$SEP10_HOME_DOMAIN/auth/sep10' && si_has '--sep10-home-domain $SEP10_HOME_DOMAIN'"
check_jq "impalactl sep10 cards <holder>: the card is listed as active with its Stellar address" \
  "[.cards[]? | select(.active==true and .stellar_address==\"$CARD_G\")] | length == 1" "$(ctl_a sep10 cards "$DEMO_HOLDER_ID" --json 2>/dev/null || echo '{}')"

info "2/5 impalactl signs the holder in with the card (SEP-10 over the simulator's socket)"
sign_ins() { compose logs --no-color impala-bridge 2>/dev/null | grep -c "sep10: card key $CARD_G signed in; tokens issued for account_id=$DEMO_HOLDER_ID" || true; }
before="$(sign_ins)"
set +e
ctl_h login --card "$CARD_TCP" >/dev/null 2>"$ERR"; rc_plain=$?
set -e
check "without the home domain's name the sign-in is refused (exit $rc_plain, HOST_MISMATCH): the bridge is reached at 127.0.0.1 here, and a signed challenge only ever goes to the home domain it was made for" \
  sh -c "[ $rc_plain -ne 0 ] && grep -q 'HOST_MISMATCH' '$ERR' && [ ! -s '$CFG_H/credentials.json' ]"
set +e
ctl_h login --card "$CARD_TCP" --sep10-home-domain "$SEP10_HOME_DOMAIN" >/dev/null 2>"$ERR"; rc=$?
set -e
grep -E '^(Card|Mechanism|Factors):' "$ERR" | sed 's/^/  /' >&2 || true
check "impalactl login --card --sep10-home-domain $SEP10_HOME_DOMAIN exits 0 and names the mechanism: SEP-10, with the card's Stellar key" \
  sh -c "[ $rc -eq 0 ] && grep -q 'Mechanism: SEP-10 (Stellar key $CARD_G)' '$ERR'"
check_jq "the session's one verified factor is the card (impalactl mfa status: amr = [sc])" '.amr == ["sc"] and .mfa == false' "$(amr_of "$CFG_H")"
check_eval "the stored credentials work: impalactl account show reads the holder's own record" \
  "ctl_h account show '$HOLDER_G' --json 2>/dev/null | jq -e '.payala_account_id==\"$DEMO_HOLDER_ID\"' >/dev/null"
sleep 1
check "bridge log: one more 'sep10: card key $CARD_G signed in' line for the holder than before" [ "$(sign_ins)" -eq $(( before + 1 )) ]
check "nothing secret was printed: no token, challenge nonce or signature in impalactl's output" \
  sh -c "! grep -Eq 'eyJ[A-Za-z0-9_-]{20,}|[0-9a-f]{128}' '$ERR'"

info "3/5 card and PIN in one tap; a wrong PIN; the legacy challenge"
set +e
IMPALA_CARD_PIN="$IMPALA_USER_PIN" ctl_h login --card "$CARD_TCP" --sep10-home-domain "$SEP10_HOME_DOMAIN" --pin >/dev/null 2>"$ERR"; rc=$?
set -e
grep -E '^(Mechanism|Factors):' "$ERR" | sed 's/^/  /' >&2 || true
check "impalactl login --card --pin exits 0 (the PIN came from the environment, was verified on the card, and the card signed a PIN proof)" [ "$rc" -eq 0 ]
PIN_ST="$(amr_of "$CFG_H")"
check_jq "the session is multi-factor from the card alone: amr has sc and pin, and the derived mfa (the bridge credits the PIN proof of an issuer-certified card)" \
  '(.amr | index("sc")) != null and (.amr | index("pin")) != null and (.amr | index("mfa")) != null and .mfa == true' "$PIN_ST"
# A wrong PIN: four digits that are not the card's. It costs one try, which the next correct PIN gives back.
WRONG=1234; [ "$IMPALA_USER_PIN" = "$WRONG" ] && WRONG=4321
rm -f "$CFG_H/credentials.json"
set +e
IMPALA_CARD_PIN="$WRONG" ctl_h login --card "$CARD_TCP" --sep10-home-domain "$SEP10_HOME_DOMAIN" --pin >/dev/null 2>"$ERR"; rc_wrong=$?
set -e
check "a wrong PIN is an error (exit $rc_wrong), never a PIN-less sign-in: nothing is stored and no request reaches the bridge" \
  sh -c "[ $rc_wrong -ne 0 ] && [ ! -s '$CFG_H/credentials.json' ] && ! grep -q 'Mechanism:' '$ERR'"
check_jq "the card counted it: one user-PIN try is gone (4 left)" '.user_verification.tries_left == 4' "$(ctl_h card info --card "$CARD_TCP" --json 2>/dev/null || echo '{}')"
set +e
IMPALA_CARD_PIN="$IMPALA_USER_PIN" ctl_h login --card "$CARD_TCP" --no-sep10 --pin >/dev/null 2>"$ERR"; rc=$?
set -e
grep -E '^(Mechanism|Factors):' "$ERR" | sed 's/^/  /' >&2 || true
check "the legacy card challenge still signs the same card in (--no-sep10: SIGN_AUTH and POST /auth/card), PIN proof included" \
  sh -c "[ $rc -eq 0 ] && grep -q 'Mechanism: legacy card challenge' '$ERR'"
check_jq "that session is multi-factor too (amr: sc, pin, mfa)" '(.amr | index("sc")) != null and (.amr | index("pin")) != null and .mfa == true' "$(amr_of "$CFG_H")"
check_jq "and the correct PIN gave the card its tries back (5 left)" '.user_verification.tries_left == 5' "$(ctl_h card info --card "$CARD_TCP" --json 2>/dev/null || echo '{}')"

info "4/5 a device key on this machine steps a password session up"
IMPALA_PASSWORD="$IMPALA_BENEFICIARY_PASSWORD" ctl_b login --username "$PAYALA_BENEFICIARY_ID" >/dev/null 2>&1 || die "impalactl login failed for the beneficiary"
check_jq "a password session starts single-factor (amr = [pwd])" '.amr == ["pwd"] and .mfa == false' "$(amr_of "$CFG_B")"
enr="$(ctl_b mfa device enroll --label "demo cli" --json 2>/dev/null || echo '{}')"
KEY_ID="$(printf '%s' "$enr" | jq -r '.key_id // empty')"; [ -n "$KEY_ID" ] && KEY_LIVE=1
check "impalactl mfa device enroll registers a P-256 key for this machine (key id $KEY_ID)" [ -n "$KEY_ID" ]
KEY_FILE="$(find "$CFG_B/device-keys" -type f 2>/dev/null | head -n1 || true)"
KEY_MODE="$( { [ -n "$KEY_FILE" ] && file_mode "$KEY_FILE"; } || echo '?')"
check "the private key stays on this machine, in a file only its owner can read (mode $KEY_MODE)" [ "$KEY_MODE" = 600 ]
ctl_b mfa step-up --device >/dev/null 2>"$ERR" || true
check_jq "impalactl mfa step-up --device: the session is multi-factor (amr: pwd, dev, mfa) and the new tokens replaced the stored ones" \
  '(.amr | index("pwd")) != null and (.amr | index("dev")) != null and (.amr | index("mfa")) != null and .mfa == true' "$(amr_of "$CFG_B")"
check_jq "the admin's factor summary shows the device key as a possession factor, never biometric (impalactl mfa admin show: platform impalactl, user verification none)" \
  "[.device_keys[]? | select(.key_id==\"$KEY_ID\" and .platform==\"impalactl\" and .user_verification==\"none\")] | length == 1" "$(ctl_a mfa admin show "$PAYALA_BENEFICIARY_ID" --json 2>/dev/null || echo '{}')"
ctl_b mfa device revoke "$KEY_ID" --yes >/dev/null 2>&1 && KEY_LIVE=0
check_jq "impalactl mfa device revoke removes it, on the bridge and on this machine" \
  "type==\"array\" and ([.[] | select(.key_id==\"$KEY_ID\")] | length == 0)" "$(ctl_b mfa device list --json 2>/dev/null || echo '{}')"
check "and the key file is gone from this machine" sh -c "[ -z \"\$(find '$CFG_B/device-keys' -type f 2>/dev/null)\" ]"

info "5/5 lumencli: the bridge's challenge read with the Stellar SDK, and a wallet key signing in at a third-party server"
ins="$(sep10_curl -fsS "http://$SEP10_HOME_DOMAIN/auth/sep10?account=$CARD_G" | "$LUMEN" sep10 inspect --server-key "$ACTIVE_G" --home-domain "$SEP10_HOME_DOMAIN" --account "$CARD_G" --json 2>/dev/null || echo '{}')"
check_jq "lumencli sep10 inspect passes every client check on the bridge's challenge (sequence 0, \"$SEP10_HOME_DOMAIN auth\" sourced by the card, the bridge's signature): a third reader, the Stellar SDK's" \
  ".verified==true and .sequence==\"0\" and .operations[0].name==\"$SEP10_HOME_DOMAIN auth\" and .operations[0].source_account==\"$CARD_G\"" "$ins"
DOMAIN="$(printf '%s' "${DEMO_SEP10_THIRD_PARTY:-}" | tr ',' ' ' | awk '{print $1}')"
WALLET_G=""; TP_STATUS="skipped"; TP_SUB=""
if [ -z "$DOMAIN" ]; then
  log "  no third-party SEP-10 server configured (DEMO_SEP10_THIRD_PARTY): the wallet sign-in is skipped"
elif ! tpi="$("$LUMEN" sep10 info "$DOMAIN" --json 2>/dev/null)"; then
  warn "$DOMAIN: not reachable from this host (or it offers no testnet SEP-10): the wallet sign-in is skipped"
else
  check_jq "lumencli sep10 info $DOMAIN: a signing key and an https web-auth endpoint on testnet" \
    "(.signing_key | test(\"^G[A-Z2-7]{55}\$\")) and (.web_auth_endpoint | startswith(\"https://\")) and (.network_passphrase // \"$TESTNET_PASSPHRASE\")==\"$TESTNET_PASSPHRASE\"" "$tpi"
  new="$("$LUMEN" account new 2>/dev/null)"
  WALLET_G="$(printf '%s\n' "$new" | awk '/Public key/ {print $NF}')"; WALLET_S="$(printf '%s\n' "$new" | awk '/Secret seed/ {print $NF}')"; unset new
  [ "${#WALLET_G}" -eq 56 ] && [ "${#WALLET_S}" -eq 56 ] || die "could not parse the keypair from lumencli"
  log "  a fresh wallet key (never funded; SEP-10 moves no funds): $WALLET_G"
  set +e
  tok="$(LUMEN_SECRET="$WALLET_S" "$LUMEN" sep10 login "$DOMAIN" --json 2>"$ERR")"; rc=$?
  set -e
  unset WALLET_S
  check "lumencli sep10 login $DOMAIN exits 0: the wallet's key signed that server's challenge after every client check passed" [ "$rc" -eq 0 ]
  TP_SUB="$(printf '%s' "$tok" | jq -r '.claims.sub // empty')"
  check_jq "the server's token is a JWT whose subject is the wallet's account" \
    "(.token | test(\"^[A-Za-z0-9_-]+\\\\.[A-Za-z0-9_-]+\\\\.[A-Za-z0-9_-]+\$\")) and .account==\"$WALLET_G\" and ((.claims.sub // \"\") | startswith(\"$WALLET_G\"))" "$tok"
  check "the seed and the token stayed out of lumencli's notices" sh -c "! grep -Eq 'S[A-Z2-7]{55}|eyJ[A-Za-z0-9_-]{20,}' '$ERR'"
  # The token at work: a SEP-24 route of that server answers with it and refuses without it.
  S24="$(curl -fsS "https://$DOMAIN/.well-known/stellar.toml" 2>/dev/null | toml_value TRANSFER_SERVER_SEP0024 || true)"
  ASSET="$( { [ -n "$S24" ] && curl -fsS "${S24%/}/info" 2>/dev/null | jq -r '(.deposit // {}) | keys[0] // empty'; } || true)"
  if [ -n "$S24" ] && [ -n "$ASSET" ]; then
    ( umask 077; printf 'Authorization: Bearer %s\n' "$(printf '%s' "$tok" | jq -r .token)" > "$HDR" )
    without="$(curl -sS -o /dev/null -w '%{http_code}' "${S24%/}/transactions?asset_code=$ASSET" || echo 000)"
    with="$(curl -sS -o /dev/null -w '%{http_code}' -H "@$HDR" "${S24%/}/transactions?asset_code=$ASSET" || echo 000)"
    : > "$HDR"
    check "the token at work: $DOMAIN's SEP-24 route refuses the request without it ($without) and answers with it ($with)" \
      sh -c "{ [ '$without' = 401 ] || [ '$without' = 403 ]; } && [ '$with' = 200 ]"
  else
    log "  $DOMAIN publishes no SEP-24 server to try the token on: not checked"
  fi
  unset tok
  TP_STATUS="signed-in"
fi

# The record keeps public values only: addresses, mechanisms, factor names. No token, PIN, seed or key.
finish_scenario scenario-16-cli-auth "$(jq -cn --arg g "$CARD_G" --arg c "$CARD_ID" --arg cap "$SIM_CAP" --arg hw "$DEMO_CARD_PLATFORM" --arg d "$SEP10_HOME_DOMAIN" \
  --argjson pin "$(printf '%s' "$PIN_ST" | jq -c '{amr, mfa}')" --arg k "$KEY_ID" --arg td "$DOMAIN" --arg ts "$TP_STATUS" --arg w "$WALLET_G" --arg sub "$TP_SUB" \
  '{card:{card_id:$c, stellar_address:$g, card_cap:$cap, card_platform:$hw}, home_domain:$d,
    impalactl:{card_sign_in:"sep10", card_and_pin:$pin, legacy_challenge:true, wrong_pin_refused:true, device_key_step_up:true, device_key_id:$k},
    lumencli:{bridge_challenge_verified:true, third_party:{domain:$td, status:$ts, wallet:$w, token_subject:$sub}}}')" "$t0"
