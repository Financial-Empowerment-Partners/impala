#!/usr/bin/env bash
# Scenario 05 — card issuance on the JavaCard simulator: the real ImpalaApplet runs on jcardsim behind
# a TCP socket; the issuance tool (impala-card tools/issue) runs the whole ceremony against this bridge
# for the card holder — INITIALIZE, per-card SCP03 keys from the KMK, POST /card, a bridge-issued card
# certificate (the program's issuer key, sealed by OpenBao), PERSONALIZE A/B/C, PINs — and prints the
# signed-off record. Re-running the tool is a no-op: the ceremony is idempotent per step.
# Optional: a scardutil fleet check of the CAP's plaintext dispatch on the vpcd simulator (SCARDUTIL_DIR).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env DEMO_HOLDER_ID IMPALA_HOLDER_PASSWORD PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD IMPALA_ISSUE_KMK IMPALA_USER_PIN IMPALA_MASTER_PIN
CARD="$REPO_DIR/impala-card"
t0="$(now_s)"
hr "scenario 05: card issuance on jcardsim (holder $DEMO_HOLDER_ID)"
wait_bridge 10

info "1/4 simulator"
"$DEMO_DIR/scripts/simulator.sh" up
check_eval "simulator answers SELECT + GET_VERSION with applet 0.2" "'$DEMO_DIR/scripts/simulator.sh' probe | grep -q 'applet 0.2'"
issuer="$(curl -fsS "$BRIDGE_URL/card-issuer")"
check_jq "bridge card program configured (issuer key sealed by the protector)" '.configured==true' "$issuer"

info "2/4 issuance ceremony (tools/issue --transport tcp; tokens and the KMK travel by environment, never argv)"
HOLDER_TOKEN="$(bridge_login "$DEMO_HOLDER_ID" "$IMPALA_HOLDER_PASSWORD")"
OPERATOR_TOKEN="$(admin_jwt)"
issue() { # -> record on stdout; exit code of the tool
  ( cd "$CARD" && JAVA_HOME="$(jdk17_home)" IMPALA_ISSUE_KMK="$IMPALA_ISSUE_KMK" IMPALA_HOLDER_TOKEN="$HOLDER_TOKEN" IMPALA_OPERATOR_TOKEN="$OPERATOR_TOKEN" \
      IMPALA_USER_PIN="$IMPALA_USER_PIN" IMPALA_MASTER_PIN="$IMPALA_MASTER_PIN" \
      ./gradlew -q :tools:issue:run --console=plain --args="--transport tcp:127.0.0.1:$SIM_PORT --account $DEMO_HOLDER_ID --bridge $BRIDGE_URL --currency XLM" )
}
set +e
record="$(issue 2>"$STATE_DIR/issue.err")"; rc=$?
set -e
sed 's/^/  /' "$STATE_DIR/issue.err" | grep -v '^\s*$' | tail -n 12 >&2 || true
printf '%s\n' "$record" | sed 's/^/  /' >&2
check "issuance tool exited 0 (card personalized and certified)" [ "$rc" -eq 0 ]
kv() { printf '%s\n' "$record" | sed -n "s/^$1=//p" | head -n1 | tr -d '[:space:]'; }
CARD_ID="$(kv card_id)"; CERT_ID="$(kv cert_id)"; PROGRAM_ID="$(kv program_id)"; APPLET="$(kv applet_version)"; CAP_SHA="$(kv cap_sha256)"
[ -n "$CARD_ID" ] || CARD_ID="$(printf '%s' "$record" | grep -Eo '[0-9a-f]{32}' | head -n1 || true)"
check "record names the card id" [ -n "$CARD_ID" ]
check "record says issuer=bridge (not the local test issuer) and status issued / already-issued" sh -c "[ '$(kv issuer)' = bridge ] && case '$(kv status)' in issued|already-issued) exit 0;; *) exit 1;; esac"
check "record carries a certificate id" [ "${#CERT_ID}" -ge 32 ]
check "record's account_uuid is the holder ($DEMO_HOLDER_ID)" [ "$(kv account_uuid)" = "$DEMO_HOLDER_ID" ]
check "record names the program id of this bridge's card program" [ "$(printf '%s' "$PROGRAM_ID" | tr 'A-F' 'a-f')" = "$(printf '%s' "$issuer" | jq -r .program_id_hex | tr 'A-F' 'a-f')" ]

info "3/4 the bridge's view, and idempotency"
check_eval "card $CARD_ID registered for the holder (card table)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and account_id='$DEMO_HOLDER_ID' and is_delete=false\" | tr -d '[:space:]')\" = 1 ]"
check_eval "card registered with an EC key and no RSA key (applet 0.2)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and ec_pubkey<>'' and rsa_pubkey is null\" | tr -d '[:space:]')\" = 1 ]"
check_eval "card certified by the bridge's issuer key (cert row: issuer version, certificate hex, certified_at)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and cert_issuer_version>=1 and length(issuer_cert_hex)>0 and certified_at is not null\" | tr -d '[:space:]')\" = 1 ]"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$OPERATOR_TOKEN")"
check_jq "events: the program issuer key was generated exactly once (never rotated by the demo)" '([.events[]|select(.event_type=="custody.issuer_key_generated")]|length)==1' "$events"
check_jq "events: card.registered and custody.card_certified name this card" "([.events[]|select(.event_type==\"card.registered\" and (.payload|tostring|ascii_downcase|contains(\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\")))]|length)>=1 and ([.events[]|select(.event_type==\"custody.card_certified\" and (.payload|tostring|ascii_downcase|contains(\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\")))]|length)>=1" "$events"
set +e
record2="$(issue 2>/dev/null)"; rc2=$?
set -e
check "re-running the ceremony is a no-op that prints the same record (exit 0)" [ "$rc2" -eq 0 ]
check "same card id on the second run" [ "$(printf '%s\n' "$record2" | sed -n 's/^card_id=//p' | head -n1 | tr -d '[:space:]')" = "$CARD_ID" ]
check_eval "simulator still serves the (now issued) card" "'$DEMO_DIR/scripts/simulator.sh' probe | grep -q 'applet 0.2'"

info "4/4 optional: scardutil fleet check of the CAP's plaintext dispatch (vpcd simulator)"
FLEET="skipped"; FLEET_PASSED=0; FLEET_FAILED=0
if [ -n "${SCARDUTIL_DIR:-}" ] && [ -d "$SCARDUTIL_DIR/src/scardutil" ] && command -v python3 >/dev/null 2>&1; then
  if ( cd "$CARD" && JAVA_HOME="$(jdk17_home)" ./gradlew -q :simulator:vpcdClasspath >/dev/null 2>&1 ) && \
     ( cd "$CARD" && PYTHONPATH="$SCARDUTIL_DIR/src" python3 -m scardutil make-sequence scardutil/impala-dispatch.md -o "$STATE_DIR/impala-dispatch.json" --cap-dir applet/build >/dev/null 2>&1 ); then
    set +e
    ( cd "$CARD" && PYTHONPATH="$SCARDUTIL_DIR/src" python3 -m scardutil test-sequence "$STATE_DIR/impala-dispatch.json" --sim-cfg scardutil/impala-sim.cfg --jcardsim "bash scripts/vpcd-sim.sh" --no-cap-info ) > "$STATE_DIR/scardutil-fleet.log" 2>&1
    frc=$?
    set -e
    tail -n 3 "$STATE_DIR/scardutil-fleet.log" | sed 's/^/  /' >&2
    FLEET_PASSED=$(grep -Eo '[0-9]+ passed' "$STATE_DIR/scardutil-fleet.log" | awk '{print $1}' | tail -n1); FLEET_FAILED=$(grep -Eo '[0-9]+ failed' "$STATE_DIR/scardutil-fleet.log" | awk '{print $1}' | tail -n1)
    check "scardutil dispatch sequence: ${FLEET_PASSED:-0} passed, ${FLEET_FAILED:-0} failed" sh -c "[ '$frc' -eq 0 ] && [ '${FLEET_FAILED:-1}' = 0 ]"
    FLEET="passed"; [ "$frc" -eq 0 ] || FLEET="failed"
  else
    warn "scardutil present but make-sequence / vpcdClasspath failed; fleet check skipped (see impala-card/scardutil/README.md)"
  fi
else
  log "  scardutil not configured (SCARDUTIL_DIR): skipped; see impala-card/scardutil/README.md for the fleet matrix on physical cards"
fi

finish_scenario scenario-05-card-issue "$(jq -cn --arg c "$CARD_ID" --arg cert "$CERT_ID" --arg p "$PROGRAM_ID" --arg a "$APPLET" --arg cap "$CAP_SHA" --arg h "$DEMO_HOLDER_ID" --arg fl "$FLEET" --argjson fp "${FLEET_PASSED:-0}" --argjson ff "${FLEET_FAILED:-0}" --arg rec "$record" \
  '{card_id:$c, cert_id:$cert, program_id_hex:$p, applet_version:$a, cap_sha256:$cap, holder:$h, fleet_check:$fl, fleet_passed:$fp, fleet_failed:$ff, record:$rec}')" "$t0"
