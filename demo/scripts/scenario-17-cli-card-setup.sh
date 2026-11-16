#!/usr/bin/env bash
# Scenario 17 — a card set up from the command line.
# Scenario 05 issues the holder's card with the reference issuance tool (impala-card tools/issue, Kotlin).
# impalactl is its Go port, and this scenario sets a SECOND card up with it, from blank to signed in:
#   1. a second simulated card, blank, in a simulator process of its own (scripts/simulator.sh, instance
#      "setup" on SIM2_PORT). Its hardware is the other class than the holder's card unless
#      DEMO_SETUP_CARD_PLATFORM names one: a JavaCard 3.2 card with the native CAP next to a JavaCard 3.0.5 one;
#   2. the ceremony needs two people, and impalactl checks that before it touches the card: without the
#      holder's token nothing is sent to the card, and the holder alone is refused the certificate (403);
#   3. `impalactl card setup` as the operator: INITIALIZE, per-card SCP03 keys derived from the KMK, POST /card
#      under the holder's token, a certificate from the bridge's program key, PERSONALIZE A/B/C, both PINs, and
#      the card's Stellar key registered. It continues where the refused run stopped;
#   4. the bridge's view, a second run (a no-op), and the reference tool reading the same card: it prints the
#      same record and says already-issued;
#   5. the new card signs the holder in (SEP-10 with its own Stellar key);
#   6. the holder's own setup (`impalactl card pin policy`, `card pin change`): the card can require its PIN
#      before it signs in at all, and then a tap without the PIN is refused before any request;
#   7. five wrong PINs block the card's PIN, and the master PIN set at issuance resets it (`card pin reset`).
# Secrets travel by environment, never argv (the KMK, the PINs, both tokens); the record keeps public values.
# The second simulator is stopped at the end: the card lived in that process (DEMO_KEEP_SETUP_CARD=1 keeps it).
# Usage: scripts/scenario-17-cli-card-setup.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq python3
require_env DEMO_HOLDER_ID IMPALA_HOLDER_PASSWORD PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD IMPALA_ISSUE_KMK IMPALA_USER_PIN IMPALA_MASTER_PIN
CTL="$(impalactl_bin)" || die "bin/impalactl missing: run scripts/build.sh tools"
CARD="$REPO_DIR/impala-card"
t0="$(now_s)"
case "${DEMO_SETUP_CARD_PLATFORM:-}" in
  '') if [ "$DEMO_CARD_PLATFORM" = jc305 ]; then SETUP_PLATFORM=jc32; else SETUP_PLATFORM=jc305; fi ;;
  *) SETUP_PLATFORM="$DEMO_SETUP_CARD_PLATFORM" ;;
esac
hr "scenario 17: a card set up from the command line (impalactl card setup; a blank $SETUP_PLATFORM card on 127.0.0.1:$SIM2_PORT)"
wait_bridge 10
[ "$SIM2_PORT" != "$SIM_PORT" ] || die "SIM2_PORT must differ from SIM_PORT ($SIM_PORT): the second card is a second simulator process"
export IMPALA_ENDPOINT="$BRIDGE_URL"
CARD_TCP="tcp:127.0.0.1:$SIM2_PORT"
# the second card: its own simulator process, port and state directory (state/simulator-setup)
sim2() { SIM_PORT="$SIM2_PORT" DEMO_SIM_INSTANCE=setup DEMO_CARD_PLATFORM="$SETUP_PLATFORM" DEMO_CARD_ED25519="" "$DEMO_DIR/scripts/simulator.sh" "$@"; }
CFG="$STATE_DIR/impalactl"; CFG_A="$CFG/admin-setup"; CFG_S="$CFG/holder-setup"; CFG_X="$CFG/holder-alone"
rm -rf "$CFG_A" "$CFG_S" "$CFG_X"; mkdir -p "$CFG_A" "$CFG_S" "$CFG_X"; chmod 700 "$CFG" "$CFG_A" "$CFG_S" "$CFG_X"
ctl_a() { IMPALA_CONFIG_DIR="$CFG_A" "$CTL" "$@"; }   # the operator (admin: keys-manage)
ctl_s() { IMPALA_CONFIG_DIR="$CFG_S" "$CTL" "$@"; }   # the holder, signing in with the new card
ERR="$(mktemp "${TMPDIR:-/tmp}/impala-suite-setup.XXXXXX")"; OUT="$(mktemp "${TMPDIR:-/tmp}/impala-suite-setup.XXXXXX")"
restore() {
  if [ "${DEMO_KEEP_SETUP_CARD:-}" != 1 ]; then sim2 down >/dev/null 2>&1 || true; fi
  rm -f "$ERR" "$OUT"; cleanup_tmp
}
trap restore EXIT
amr_of() { IMPALA_CONFIG_DIR="$1" "$CTL" mfa status --json 2>/dev/null || echo '{}'; }
card_info() { "$CTL" card info --card "$CARD_TCP" --json 2>/dev/null || echo '{}'; }
notices() { grep -v '^\s*$' "$ERR" | sed 's/^/  /' | tail -n "${1:-14}" >&2 || true; }
lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
# card_login <extra flags...>: the holder taps the new card; stderr goes to $ERR, the exit code is returned
card_login() { IMPALA_CONFIG_DIR="$CFG_S" "$CTL" login --card "$CARD_TCP" --sep10-home-domain "$SEP10_HOME_DOMAIN" "$@" >/dev/null 2>"$ERR"; }
if sep10_enabled; then MECH="SEP-10"; else MECH="legacy card challenge"; fi
# PINs of this scenario: the card's own (from .env, as scenario 05), a second one to change to, and a wrong one
NEW_PIN=2468; [ "$IMPALA_USER_PIN" != "$NEW_PIN" ] || NEW_PIN=8642
WRONG_PIN=1357; for c in 1357 7531 9753; do if [ "$c" != "$IMPALA_USER_PIN" ] && [ "$c" != "$NEW_PIN" ]; then WRONG_PIN="$c"; break; fi; done

info "1/7 a second simulated card, blank, next to the holder's"
jdk17_home >/dev/null || die "JDK 17 not found (JAVA17_HOME): the simulator is launched through Gradle"
sim2 restart
HW="$(sim2 hardware)"
S_PLATFORM="$(printf '%s' "$HW" | cut -f1)"; S_LEVEL="$(printf '%s' "$HW" | cut -f2)"; S_CAP="$(printf '%s' "$HW" | cut -f3)"
check "a second simulator serves a $S_CAP CAP on $S_PLATFORM hardware (JavaCard $S_LEVEL) on port $SIM2_PORT; the holder's card on port $SIM_PORT is not touched" \
  [ "$S_PLATFORM" = "$SETUP_PLATFORM" -a -n "$S_CAP" ]
APPLET_VERSION="$(applet_version)" || die "cannot read the applet version from impala-card (applet BuildConfig.java)"
ci="$(card_info)"
check_jq "impalactl card info: applet $APPLET_VERSION, blank: no keys, no account, no certificate, still on the GlobalPlatform default SCP03 keys with the provisioning gate set; it can sign nothing" \
  ".applet==\"$APPLET_VERSION\" and .state==\"blank\" and (.flags | index(\"scp03-default-keys\")) != null and (.flags | index(\"provisioning-enforced\")) != null and (.flags | index(\"initialized\")) == null and .issuer_certificate==false and .stellar_key==null and (.signs_in_with | startswith(\"nothing\"))" "$ci"

info "2/7 the card program, and the two people of the ceremony"
is="$("$CTL" card issuer show --json 2>/dev/null || echo '{}')"
PROGRAM_ID="$(printf '%s' "$is" | jq -r '.program_id_hex // empty')"
check_jq "impalactl card issuer show (public, no session): the bridge's card program is configured, with its issuer key's fingerprint and program id" \
  '.configured==true and (.program_id_hex | test("^[0-9a-f]{32}$")) and (.fingerprint | length) > 0 and (.version >= 1)' "$is"
OPERATOR_TOKEN="$(admin_jwt)"
HOLDER_TOKEN="$(bridge_login "$DEMO_HOLDER_ID" "$IMPALA_HOLDER_PASSWORD")"
IMPALA_PASSWORD="$IMPALA_ADMIN_PASSWORD" ctl_a login --username "$PAYALA_ADMIN_ID" >/dev/null 2>&1 || die "impalactl login failed for the admin"
EV0="$(bridge_api GET '/admin/events?since=0&limit=1000' "$OPERATOR_TOKEN" | jq '[.events[].id] | max // 0')"
# setup <config dir> <holder token | ''> <session token | ''> [card]: the ceremony -> its record (JSON) on stdout.
# Every secret is an environment assignment of this one command (never an argument of any process): the KMK, the
# two PINs, the holder's token, and for the holder-alone run a session token in place of the stored session.
setup() {
  IMPALA_CONFIG_DIR="$1" IMPALA_HOLDER_TOKEN="$2" IMPALA_TOKEN="$3" IMPALA_ISSUE_KMK="$IMPALA_ISSUE_KMK" IMPALA_CARD_PIN="$IMPALA_USER_PIN" IMPALA_CARD_MASTER_PIN="$IMPALA_MASTER_PIN" \
    "$CTL" card setup --card "${4:-$CARD_TCP}" --account "$DEMO_HOLDER_ID" --yes --json
}
# The operator's session without the holder's token: a card is registered by its own holder (POST /card), so
# there is nothing impalactl could do, and it says so before the card is changed.
set +e
setup "$CFG_A" "" "" >/dev/null 2>"$ERR"; rc_nohold=$?
set -e
check "without the holder's token the ceremony is refused as a usage error (exit $rc_nohold), and the message names IMPALA_HOLDER_TOKEN" \
  sh -c "[ $rc_nohold -eq 2 ] && grep -q 'IMPALA_HOLDER_TOKEN' '$ERR'"
check_jq "and nothing was sent to the card: it is still blank" '.state=="blank" and (.flags | index("initialized")) == null' "$(card_info)"
# The holder alone: the same command under the holder's own session. The card is initialized and registered,
# and then the certificate is refused: certifying a card needs keys-manage (admin or key-custodian).
set +e
setup "$CFG_X" "" "$HOLDER_TOKEN" >/dev/null 2>"$ERR"; rc_alone=$?
set -e
notices 6
check "the holder alone cannot finish it: the bridge refuses the certificate (exit $rc_alone, HTTP 403: certifying a card needs keys-manage)" \
  sh -c "[ $rc_alone -eq 1 ] && grep -q '403' '$ERR'"
ci="$(card_info)"
check_jq "that run stopped half-way and the card shows it: initialized, with a P-256 key and per-card SCP03 keys, registered by its holder, not personalized" \
  '.state=="initialized" and (.flags | index("scp03-default-keys")) == null and (.flags | index("personalized")) == null and (.ec_pubkey | length) == 130 and .issuer_certificate==false' "$ci"
CARD_ID="$(printf '%s' "$ci" | jq -r '.card_id // empty')"

info "3/7 the ceremony as the operator: impalactl card setup (the KMK, the PINs and the holder's token travel by environment)"
set +e
rec="$(setup "$CFG_A" "$HOLDER_TOKEN" "" 2>"$ERR")"; rc=$?
if [ "$rc" -ne 0 ] && grep -q '429' "$ERR"; then
  # Key-custody calls, certificates among them, share one budget: 5 per 60 s per operator. The ceremony is
  # idempotent per step, so the second run continues the first.
  warn "the bridge's key-custody budget (5 per 60 s per operator) is used up; waiting 61 s, then running the ceremony again (it continues where it was refused)"
  sleep 61
  rec="$(setup "$CFG_A" "$HOLDER_TOKEN" "" 2>"$ERR")"; rc=$?
fi
set -e
notices 14
printf '%s\n' "$rec" > "$OUT"
jq -c . "$OUT" 2>/dev/null | sed 's/^/  /' >&2 || true
check "impalactl card setup exits 0" [ "$rc" -eq 0 ]
check_jq "its record: card $CARD_ID issued to the holder under this bridge's card program, in XLM, with a certificate id" \
  ".status==\"issued\" and (.card_id | ascii_downcase)==\"$(lower "$CARD_ID")\" and .account_id==\"$DEMO_HOLDER_ID\" and (.program_id | ascii_downcase)==\"$(lower "$PROGRAM_ID")\" and .currency==\"XLM\" and (.cert_id | test(\"^[0-9a-f]{64}\$\")) and .applet==\"$APPLET_VERSION\" and (.issuer_version >= 1)" "$rec"
CERT_ID="$(printf '%s' "$rec" | jq -r '.cert_id // empty')"; STELLAR="$(printf '%s' "$rec" | jq -r '.stellar_key.address // empty')"
check_jq "the record carries the card's Stellar address, made by its $S_CAP engine on $S_PLATFORM hardware, and says the bridge registered it" \
  "(.stellar_key.address | test(\"^G[A-Z2-7]{55}\$\")) and .stellar_key.engine==\"$S_CAP\" and .stellar_key.registered==true" "$rec"
check "it continued where the refused run stopped: the per-card SCP03 keys opened at once (no second INITIALIZE, no second key rotation), then PERSONALIZE and both PINs" \
  sh -c "grep -q 'SCP03 open on per-card keys' '$ERR' && ! grep -q 'card key generated' '$ERR' && ! grep -q 'keys rotated' '$ERR' && grep -qw 'personalized' '$ERR' && grep -q 'PINs provisioned' '$ERR'"
check "nothing secret was printed: not the KMK, a PIN or a token, on stdout or stderr" \
  sh -c "! cat '$OUT' '$ERR' | grep -Eq 'eyJ[A-Za-z0-9_-]{20,}' && ! cat '$OUT' '$ERR' | grep -Fqi -- '$IMPALA_ISSUE_KMK' && ! cat '$OUT' '$ERR' | grep -qw -e '$IMPALA_USER_PIN' -e '$IMPALA_MASTER_PIN'"

info "4/7 the bridge's view, a second run, and the reference tool reading the same card"
check_eval "card $CARD_ID is registered for the holder and certified by the bridge's issuer key (card table: issuer version, certificate, certified_at)" \
  "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and account_id='$DEMO_HOLDER_ID' and is_delete=false and cert_issuer_version>=1 and length(issuer_cert_hex)>0 and certified_at is not null\" | tr -d '[:space:]')\" = 1 ]"
check_eval "the card row holds the Stellar address and both cross-signatures the bridge verified" \
  "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and is_delete=false and stellar_address='$STELLAR' and length(stellar_binding_sig)>=16 and length(stellar_proof_sig)=128\" | tr -d '[:space:]')\" = 1 ]"
ev_for() { printf '%s' "$events" | jq "[.events[] | select(.event_type==\"$1\" and ((.payload.card_id // \"\") | ascii_downcase)==\"$(lower "$CARD_ID")\")] | length"; }
events="$(bridge_api GET "/admin/events?since=$EV0&limit=500" "$OPERATOR_TOKEN")"
check "events: card.registered once (by the holder), custody.card_certified once (by the operator), card.stellar_key_registered once" \
  [ "$(ev_for card.registered)" = 1 -a "$(ev_for custody.card_certified)" = 1 -a "$(ev_for card.stellar_key_registered)" = 1 ]
ev_actor() { printf '%s' "$events" | jq -r "[.events[] | select(.event_type==\"$1\" and ((.payload.card_id // \"\") | ascii_downcase)==\"$(lower "$CARD_ID")\")][0].account_id // empty"; }
check "each event names who did it: the holder registered the card and its Stellar key, the operator certified it" \
  [ "$(ev_actor card.registered)" = "$DEMO_HOLDER_ID" -a "$(ev_actor custody.card_certified)" = "$PAYALA_ADMIN_ID" -a "$(ev_actor card.stellar_key_registered)" = "$DEMO_HOLDER_ID" ]
set +e
rec2="$(setup "$CFG_A" "$HOLDER_TOKEN" "" 2>"$ERR")"; rc2=$?
set -e
check_jq "a second run changes nothing and prints the same record (exit $rc2, status already-issued)" \
  ".status==\"already-issued\" and (.card_id | ascii_downcase)==\"$(lower "$CARD_ID")\" and .cert_id==\"$CERT_ID\" and .stellar_key.address==\"$STELLAR\" and .stellar_key.registered==true" "$rec2"
events="$(bridge_api GET "/admin/events?since=$EV0&limit=500" "$OPERATOR_TOKEN")"
check "events: still one certificate and one card.stellar_key_registered after two runs" [ "$(ev_for custody.card_certified)" = 1 -a "$(ev_for card.stellar_key_registered)" = 1 ]
# The reference issuance tool (impala-card tools/issue, on the Kotlin SDK) reads the card impalactl set up. It
# rebuilds the certificate id from what the card reports, so an identical record is two implementations
# agreeing about the card, not one tool agreeing with itself.
set +e
ref="$( cd "$CARD" && JAVA_HOME="$(jdk17_home)" IMPALA_ISSUE_KMK="$IMPALA_ISSUE_KMK" IMPALA_HOLDER_TOKEN="$HOLDER_TOKEN" IMPALA_OPERATOR_TOKEN="$OPERATOR_TOKEN" \
    IMPALA_USER_PIN="$IMPALA_USER_PIN" IMPALA_MASTER_PIN="$IMPALA_MASTER_PIN" \
    ./gradlew -q :tools:issue:run --console=plain --args="--transport tcp:127.0.0.1:$SIM2_PORT --account $DEMO_HOLDER_ID --bridge $BRIDGE_URL --currency XLM" 2>"$STATE_DIR/issue-reference.err" )"; rc_ref=$?
set -e
printf '%s\n' "$ref" | grep -E '^(card_id|cert_id|stellar_address|status)=' | sed 's/^/  reference tool: /' >&2 || true
rkv() { printf '%s\n' "$ref" | sed -n "s/^$1=//p" | head -n1 | tr -d '[:space:]'; }
check "the reference tool agrees (exit $rc_ref): the same card id, certificate id, program id and Stellar address, status already-issued" \
  [ "$rc_ref" -eq 0 -a "$(lower "$(rkv card_id)")" = "$(lower "$CARD_ID")" -a "$(rkv cert_id)" = "$CERT_ID" -a "$(lower "$(rkv program_id)")" = "$(lower "$PROGRAM_ID")" -a "$(rkv stellar_address)" = "$STELLAR" -a "$(rkv status)" = already-issued ]
# And the other way round: impalactl reads the card the reference tool issued in scenario 05, when that card is
# still the one the first simulator serves (checked by its id first: a blank card there is not this scenario's
# to issue).
MAIN_CARD="$(record_get scenario-05-card-issue .card_id)"; MAIN_CERT="$(record_get scenario-05-card-issue .cert_id)"
MAIN_SEEN="$("$CTL" card info --card "tcp:127.0.0.1:$SIM_PORT" --json 2>/dev/null | jq -r 'select(.state=="personalized") | .card_id // empty' || true)"
REVERSE=skipped
if [ -n "$MAIN_CARD" ] && [ "$(lower "$MAIN_SEEN")" = "$(lower "$MAIN_CARD")" ]; then
  set +e
  main_rec="$(setup "$CFG_A" "$HOLDER_TOKEN" "" "tcp:127.0.0.1:$SIM_PORT" 2>"$ERR")"; rc_main=$?
  set -e
  check_jq "and the other way round: impalactl reads the card the reference tool issued in scenario 05 and finds the same card id and certificate id (exit $rc_main, status already-issued, nothing changed on it)" \
    ".status==\"already-issued\" and (.card_id | ascii_downcase)==\"$(lower "$MAIN_CARD")\" and .cert_id==\"$MAIN_CERT\" and .account_id==\"$DEMO_HOLDER_ID\"" "$main_rec"
  REVERSE=agrees
else
  log "  the first simulator is not serving the card scenario 05 recorded: the reverse reading is skipped"
fi
check_jq "impalactl card info: personalized, certified, the Stellar key bound to the card key, a provisioned user PIN that sign-in does not require" \
  ".state==\"personalized\" and .issuer_certificate==true and .account_id==\"$DEMO_HOLDER_ID\" and .stellar_key.address==\"$STELLAR\" and .stellar_key.bound==true and .user_verification.pin_provisioned==true and .user_verification.sign_in_pin_required==false and .user_verification.tries_left==5" "$(card_info)"

info "5/7 the new card signs the holder in"
set +e
card_login; rc=$?
set -e
grep -E '^(Card|Mechanism|Factors):' "$ERR" | sed 's/^/  /' >&2 || true
if sep10_enabled; then
  check "impalactl login --card exits 0 with SEP-10 and this card's own Stellar key ($STELLAR)" sh -c "[ $rc -eq 0 ] && grep -q 'Mechanism: SEP-10 (Stellar key $STELLAR)' '$ERR'"
else
  check "impalactl login --card exits 0 with the legacy card challenge (this bridge runs without SEP-10)" sh -c "[ $rc -eq 0 ] && grep -q 'Mechanism: legacy card challenge' '$ERR'"
fi
check_jq "the session's one verified factor is the card (amr = [sc])" '.amr == ["sc"] and .mfa == false' "$(amr_of "$CFG_S")"
MAIN_G="$(record_get scenario-05-card-issue .stellar_address)"; MIN_CARDS=1
if [ -n "$MAIN_G" ] && [ "$MAIN_G" != "$STELLAR" ]; then MIN_CARDS=2; fi
cards="$(ctl_a sep10 cards "$DEMO_HOLDER_ID" --json 2>/dev/null || echo '{}')"
check_jq "impalactl sep10 cards: the holder has this card, active with its Stellar address, next to the one scenario 05 issued (at least $MIN_CARDS active)" \
  "([.cards[]? | select(.active==true and .stellar_address==\"$STELLAR\")] | length) == 1 and ([.cards[]? | select(.active==true)] | length) >= $MIN_CARDS" "$cards"

info "6/7 the holder's own setup: require the PIN to sign in, then change it"
set +e
pol="$(IMPALA_CARD_PIN="$IMPALA_USER_PIN" "$CTL" card pin policy on --card "$CARD_TCP" --json 2>"$ERR")"; rc=$?
set -e
check_jq "impalactl card pin policy on (exit $rc; the card verified the PIN first): the card now requires its PIN before it signs in" \
  '.user_verification.sign_in_pin_required==true and .user_verification.sign_in_pin_fixed==false' "$pol"
rm -f "$CFG_S/credentials.json"
set +e
card_login; rc_nopin=$?
set -e
check "a tap without the PIN is refused before any request (exit $rc_nopin): impalactl reads the card's policy first, and nothing is stored" \
  sh -c "[ $rc_nopin -ne 0 ] && grep -qi 'requires its user PIN' '$ERR' && ! grep -q 'Mechanism:' '$ERR' && [ ! -s '$CFG_S/credentials.json' ]"
set +e
IMPALA_CARD_PIN="$IMPALA_USER_PIN" card_login --pin; rc=$?
set -e
grep -E '^(Mechanism|Factors):' "$ERR" | sed 's/^/  /' >&2 || true
PIN_ST="$(amr_of "$CFG_S")"
check "with the PIN the same tap signs in (exit $rc, $MECH)" sh -c "[ $rc -eq 0 ] && grep -q 'Mechanism: $MECH' '$ERR'"
check_jq "and the session is multi-factor from the card alone (amr: sc, pin, mfa)" \
  '(.amr | index("sc")) != null and (.amr | index("pin")) != null and (.amr | index("mfa")) != null and .mfa == true' "$PIN_ST"
set +e
chg="$(IMPALA_CARD_PIN="$IMPALA_USER_PIN" IMPALA_CARD_NEW_PIN="$NEW_PIN" "$CTL" card pin change --card "$CARD_TCP" --json 2>"$ERR")"; rc=$?
set -e
check_jq "impalactl card pin change (exit $rc): the card took a new PIN from its verified holder, and the new PIN verifies" \
  '.user_verification.pin_provisioned==true and .user_verification.tries_left==5' "$chg"
rm -f "$CFG_S/credentials.json"
set +e
IMPALA_CARD_PIN="$IMPALA_USER_PIN" card_login --pin; rc_old=$?
set -e
check "the old PIN no longer works: the card refuses it (exit $rc_old) and nothing is stored" sh -c "[ $rc_old -ne 0 ] && [ ! -s '$CFG_S/credentials.json' ] && ! grep -q 'Mechanism:' '$ERR'"
check_jq "the card counted that try (4 left)" '.user_verification.tries_left == 4' "$(card_info)"

info "7/7 a blocked PIN, and the master PIN that resets it"
for _ in 1 2 3 4; do IMPALA_CARD_PIN="$WRONG_PIN" card_login --pin >/dev/null 2>&1 || true; done
check_jq "after five wrong PINs in a row the card's PIN is blocked (0 tries left)" '.user_verification.tries_left == 0' "$(card_info)"
set +e
IMPALA_CARD_PIN="$NEW_PIN" card_login --pin; rc_blocked=$?
set -e
check "a blocked card refuses even the right PIN (exit $rc_blocked, PIN_BLOCKED), so it cannot sign in while its policy requires the PIN" \
  sh -c "[ $rc_blocked -ne 0 ] && grep -q 'PIN_BLOCKED' '$ERR' && [ ! -s '$CFG_S/credentials.json' ]"
set +e
rst="$(IMPALA_CARD_MASTER_PIN="$IMPALA_MASTER_PIN" IMPALA_CARD_NEW_PIN="$IMPALA_USER_PIN" "$CTL" card pin reset --card "$CARD_TCP" --json 2>"$ERR")"; rc=$?
set -e
check_jq "impalactl card pin reset (exit $rc): the master PIN set at issuance gives the card a new user PIN and its five tries back" \
  '.user_verification.pin_provisioned==true and .user_verification.tries_left==5' "$rst"
set +e
IMPALA_CARD_PIN="$IMPALA_USER_PIN" card_login --pin; rc=$?
set -e
check_jq "the card signs in again with the reset PIN (exit $rc), multi-factor as before" '(.amr | index("pin")) != null and .mfa == true' "$(amr_of "$CFG_S")"
set +e
pol="$(IMPALA_CARD_PIN="$IMPALA_USER_PIN" "$CTL" card pin policy off --card "$CARD_TCP" --json 2>"$ERR")"; rc=$?
set -e
check_jq "impalactl card pin policy off (exit $rc): the requirement is the holder's to lift, with the PIN" '.user_verification.sign_in_pin_required==false' "$pol"
rm -f "$CFG_S/credentials.json"
set +e
card_login; rc=$?
set -e
check_jq "and a tap without the PIN signs in again (exit $rc, amr = [sc])" '.amr == ["sc"] and .mfa == false' "$(amr_of "$CFG_S")"
printf '%s\n%s\n%s\n' "$pol" "$chg" "$rst" > "$OUT"
check "no PIN was printed by any of the PIN commands" sh -c "! grep -qw -e '$IMPALA_USER_PIN' -e '$NEW_PIN' -e '$IMPALA_MASTER_PIN' '$OUT'"

# The record keeps public values only: ids, addresses, hardware, factor names. No KMK, PIN or token.
finish_scenario scenario-17-cli-card-setup "$(jq -cn --arg c "$CARD_ID" --arg cert "$CERT_ID" --arg p "$PROGRAM_ID" --arg g "$STELLAR" --arg h "$DEMO_HOLDER_ID" --arg a "$APPLET_VERSION" \
  --arg hw "$S_PLATFORM" --arg lvl "$S_LEVEL" --arg cap "$S_CAP" --arg mech "$MECH" --arg rev "$REVERSE" --argjson pin "$(printf '%s' "$PIN_ST" | jq -c '{amr, mfa}')" \
  '{card_id:$c, cert_id:$cert, program_id_hex:$p, stellar_address:$g, holder:$h, applet_version:$a, card_platform:$hw, card_javacard:$lvl, card_cap:$cap,
    setup:{tool:"impalactl card setup", status:"issued", refused_without_holder_token:true, holder_alone_refused:403, resumed:true, rerun:"already-issued", reference_tool_agrees:true, reads_reference_tools_card:$rev},
    sign_in:{mechanism:$mech, amr:["sc"]},
    pin:{policy_on:true, tap_without_pin_refused:true, card_and_pin:$pin, changed:true, old_pin_refused:true, blocked_after_wrong_tries:5, reset_with_master_pin:true, policy_off:true}}')" "$t0"
