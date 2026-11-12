#!/usr/bin/env bash
# Scenario 05 — card issuance on the JavaCard simulator: the real ImpalaApplet runs on jcardsim behind
# a TCP socket; the issuance tool (impala-card tools/issue) runs the whole ceremony against this bridge
# for the card holder — INITIALIZE, per-card SCP03 keys from the KMK, POST /card, a bridge-issued card
# certificate (the program's issuer key, sealed by OpenBao), PERSONALIZE A/B/C, PINs — and prints the
# signed-off record. Re-running the tool is a no-op: the ceremony is idempotent per step.
# The simulated card is a CAP on hardware (scripts/simulator.sh): DEMO_CARD_PLATFORM=jc305 (the default) is a
# JavaCard 3.0.5 card running the default CAP's software Ed25519 engine, jc32 a JavaCard 3.2 card running the
# native CAP on the platform's own EdDSA. The scenario asserts which engine made the card's Stellar key.
# Optional: a scardutil fleet check of the plaintext dispatch on both simulated hardware classes (SCARDUTIL_DIR).
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
# A running simulator is one card on one kind of hardware. If it is not the hardware asked for, replace it:
# issuing the card is this scenario's job anyway.
if "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1; then
  running="$("$DEMO_DIR/scripts/simulator.sh" hardware 2>/dev/null || true)"
  if [ "$(printf '%s' "$running" | cut -f1)" != "$DEMO_CARD_PLATFORM" ] || { [ -n "$DEMO_CARD_ED25519" ] && [ "$(printf '%s' "$running" | cut -f3)" != "$DEMO_CARD_ED25519" ]; }; then
    warn "the running simulator is another card ($(printf '%s' "$running" | tr '\t' ' ')): restarting it as $DEMO_CARD_PLATFORM${DEMO_CARD_ED25519:+ with the $DEMO_CARD_ED25519 CAP}; this scenario issues the new card"
    "$DEMO_DIR/scripts/simulator.sh" restart
  fi
fi
"$DEMO_DIR/scripts/simulator.sh" up
HW="$("$DEMO_DIR/scripts/simulator.sh" hardware)"
SIM_PLATFORM="$(printf '%s' "$HW" | cut -f1)"; SIM_LEVEL="$(printf '%s' "$HW" | cut -f2)"; SIM_CAP="$(printf '%s' "$HW" | cut -f3)"
check "the simulated card is the $SIM_CAP CAP on $SIM_PLATFORM hardware (JavaCard $SIM_LEVEL), as DEMO_CARD_PLATFORM=$DEMO_CARD_PLATFORM${DEMO_CARD_ED25519:+ and DEMO_CARD_ED25519=$DEMO_CARD_ED25519} ask" \
  [ "$SIM_PLATFORM" = "$DEMO_CARD_PLATFORM" -a -n "$SIM_CAP" -a \( -z "$DEMO_CARD_ED25519" -o "$SIM_CAP" = "$DEMO_CARD_ED25519" \) ]
APPLET_VERSION="$(applet_version)" || die "cannot read the applet version from impala-card (applet BuildConfig.java)"
check_eval "simulator answers SELECT + GET_VERSION with applet $APPLET_VERSION" "'$DEMO_DIR/scripts/simulator.sh' probe | grep -qF 'applet $APPLET_VERSION '"
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
if [ "$rc" -ne 0 ] && grep -q 'HTTP 429' "$STATE_DIR/issue.err"; then
  # Key-custody calls, certificates among them, share one budget: 5 per 60 s per operator. Another card lane
  # may just have used it. The ceremony is idempotent per step, so the second run continues the first.
  warn "the bridge's key-custody budget (5 certificates per 60 s per operator) is used up; waiting 61 s, then running the ceremony again (it continues where it was refused)"
  sleep 61
  record="$(issue 2>"$STATE_DIR/issue.err")"; rc=$?
fi
set -e
sed 's/^/  /' "$STATE_DIR/issue.err" | grep -v '^\s*$' | tail -n 12 >&2 || true
printf '%s\n' "$record" | sed 's/^/  /' >&2
check "issuance tool exited 0 (card personalized and certified)" [ "$rc" -eq 0 ]
kv() { printf '%s\n' "$record" | sed -n "s/^$1=//p" | head -n1 | tr -d '[:space:]'; }
CARD_ID="$(kv card_id)"; CERT_ID="$(kv cert_id)"; PROGRAM_ID="$(kv program_id)"; APPLET="$(kv applet_version)"; CAP_SHA="$(kv cap_sha256)"; STELLAR="$(kv stellar_address)"
[ -n "$CARD_ID" ] || CARD_ID="$(printf '%s' "$record" | grep -Eo '[0-9a-f]{32}' | head -n1 || true)"
check "record names the card id" [ -n "$CARD_ID" ]
check "record says issuer=bridge (not the local test issuer) and status issued / already-issued" sh -c "[ '$(kv issuer)' = bridge ] && case '$(kv status)' in issued|already-issued) exit 0;; *) exit 1;; esac"
check "record carries a certificate id" [ "${#CERT_ID}" -ge 32 ]
check "record's account_uuid is the holder ($DEMO_HOLDER_ID)" [ "$(kv account_uuid)" = "$DEMO_HOLDER_ID" ]
check "record names the program id of this bridge's card program" [ "$(printf '%s' "$PROGRAM_ID" | tr 'A-F' 'a-f')" = "$(printf '%s' "$issuer" | jq -r .program_id_hex | tr 'A-F' 'a-f')" ]
check_eval "record carries the card's Stellar address (the Ed25519 key the card made at INITIALIZE; applet 0.3). A card model that cannot make one is a legacy card: the SEP-10 lanes need jc305, jc31 or jc32 hardware" "printf '%s' '$STELLAR' | grep -Eq '^G[A-Z2-7]{55}\$'"
check_eval "the tool registered that key with the bridge as its last step (PUT /card/stellar-key)" "grep -q 'Stellar key registered with the bridge' '$STATE_DIR/issue.err'"
# The card itself, asked over the socket: which engine made its key, and that it is the key of the record.
# The engine follows the CAP: the software engine of the default CAP, or the platform's EdDSA of the native CAP.
KEY_LINE="$("$DEMO_DIR/scripts/simulator.sh" stellar 2>/dev/null || echo unreadable)"
CARD_ENGINE="${KEY_LINE%% *}"; CARD_KEY_HEX="${KEY_LINE#* }"
check "the card reports a Stellar key made by its $SIM_CAP engine (GET_STELLAR_KEY engine byte: $CARD_ENGINE) on $SIM_PLATFORM hardware" [ "$CARD_ENGINE" = "$SIM_CAP" ]
CARD_G="$(python3 - "$CARD_KEY_HEX" <<'EOF' 2>/dev/null || true
import base64, struct, sys
key = bytes.fromhex(sys.argv[1])
if len(key) != 32: sys.exit(1)
payload = bytes([6 << 3]) + key
crc = 0
for b in payload:
    crc ^= b << 8
    for _ in range(8):
        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
print(base64.b32encode(payload + struct.pack("<H", crc)).decode())
EOF
)"
check "that key is the address of the record ($STELLAR)" [ -n "$CARD_G" -a "$CARD_G" = "$STELLAR" ]

info "3/4 the bridge's view, and idempotency"
check_eval "card $CARD_ID registered for the holder (card table)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and account_id='$DEMO_HOLDER_ID' and is_delete=false\" | tr -d '[:space:]')\" = 1 ]"
check_eval "card registered with an EC key and no RSA key (applet 0.2 and later)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and ec_pubkey<>'' and rsa_pubkey is null\" | tr -d '[:space:]')\" = 1 ]"
check_eval "card certified by the bridge's issuer key (cert row: issuer version, certificate hex, certified_at)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and cert_issuer_version>=1 and length(issuer_cert_hex)>0 and certified_at is not null\" | tr -d '[:space:]')\" = 1 ]"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$OPERATOR_TOKEN")"
check_jq "events: the program issuer key was generated exactly once (never rotated by the demo)" '([.events[]|select(.event_type=="custody.issuer_key_generated")]|length)==1' "$events"
check_eval "card row holds the Stellar address and both cross-signatures the bridge verified (binding by the card's P-256 key, proof by the Stellar key)" "[ \"\$(psql_impala -tAc \"select count(*) from card where lower(card_id)=lower('$CARD_ID') and is_delete=false and stellar_address='$STELLAR' and length(stellar_binding_sig)>=16 and length(stellar_proof_sig)=128\" | tr -d '[:space:]')\" = 1 ]"
check_jq "admin API: GET /admin/accounts/{holder}/cards lists the card as active with its Stellar address" "[.cards[]? | select((.card_id | ascii_downcase)==\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\" and .active==true and .stellar_address==\"$STELLAR\")] | length == 1" "$(bridge_api GET "/admin/accounts/$DEMO_HOLDER_ID/cards" "$OPERATOR_TOKEN")"
check_jq "events: card.registered and custody.card_certified name this card" "([.events[]|select(.event_type==\"card.registered\" and (.payload|tostring|ascii_downcase|contains(\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\")))]|length)>=1 and ([.events[]|select(.event_type==\"custody.card_certified\" and (.payload|tostring|ascii_downcase|contains(\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\")))]|length)>=1" "$events"
set +e
record2="$(issue 2>/dev/null)"; rc2=$?
set -e
check "re-running the ceremony is a no-op that prints the same record (exit 0)" [ "$rc2" -eq 0 ]
check "same card id on the second run" [ "$(printf '%s\n' "$record2" | sed -n 's/^card_id=//p' | head -n1 | tr -d '[:space:]')" = "$CARD_ID" ]
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$OPERATOR_TOKEN")"
check_jq "events: exactly one card.stellar_key_registered for this card, after two runs (the re-run's PUT changed nothing)" "[.events[] | select(.event_type==\"card.stellar_key_registered\" and ((.payload.card_id // \"\") | ascii_downcase)==\"$(printf '%s' "$CARD_ID" | tr 'A-F' 'a-f')\")] | length == 1" "$events"
check_eval "simulator still serves the (now issued) card" "'$DEMO_DIR/scripts/simulator.sh' probe | grep -qF 'applet $APPLET_VERSION '"

info "4/4 optional: scardutil fleet check of the plaintext dispatch on both simulated hardware classes (vpcd simulator)"
# The same sequence file that runs on a fleet of physical cards, here on two simulator targets of their own
# (not the card just issued): a JavaCard 3.0.5 card with the default CAP and a JavaCard 3.2 card with the
# native CAP. Both must pass, and GET_STELLAR_KEY must name a different engine on each (01 soft, 02 native).
FLEET="skipped"; FLEET_PASSED=0; FLEET_FAILED=0; FLEET_ENGINES=""
if [ -n "${SCARDUTIL_DIR:-}" ] && [ -d "$SCARDUTIL_DIR/src/scardutil" ] && command -v python3 >/dev/null 2>&1; then
  if ( cd "$CARD" && JAVA_HOME="$(jdk17_home)" ./gradlew -q :simulator:vpcdClasspath >/dev/null 2>&1 ) && \
     ( cd "$CARD" && PYTHONPATH="$SCARDUTIL_DIR/src" python3 -m scardutil make-sequence scardutil/impala-dispatch.md -o "$STATE_DIR/impala-dispatch.json" --cap-dir applet/build >/dev/null 2>&1 ); then
    FLEET="passed"; : > "$STATE_DIR/scardutil-fleet.log"
    for target in jc305 jc32; do
      set +e
      ( cd "$CARD" && JAVA_HOME="$(jdk17_home)" PYTHONPATH="$SCARDUTIL_DIR/src" python3 -m scardutil test-sequence "$STATE_DIR/impala-dispatch.json" --sim-cfg "scardutil/impala-sim-$target.cfg" --jcardsim "bash scripts/vpcd-sim.sh" --no-cap-info ) > "$STATE_DIR/scardutil-fleet-$target.log" 2>&1
      frc=$?
      set -e
      { printf '== sim-%s\n' "$target"; cat "$STATE_DIR/scardutil-fleet-$target.log"; } >> "$STATE_DIR/scardutil-fleet.log"
      tail -n 1 "$STATE_DIR/scardutil-fleet-$target.log" | sed "s/^/  sim-$target: /" >&2
      p=$(grep -Eo '[0-9]+ passed' "$STATE_DIR/scardutil-fleet-$target.log" | awk '{print $1}' | tail -n1); f=$(grep -Eo '[0-9]+ failed' "$STATE_DIR/scardutil-fleet-$target.log" | awk '{print $1}' | tail -n1)
      # the engine byte: the first byte of the data GET_STELLAR_KEY answers after INITIALIZE
      eng=$(grep -A1 'apdu 0037000000 -> 9000' "$STATE_DIR/scardutil-fleet-$target.log" | sed -n 's/^ *data: \([0-9A-Fa-f][0-9A-Fa-f]\).*/\1/p' | tail -n1)
      check "scardutil dispatch sequence on sim-$target: ${p:-0} passed, ${f:-0} failed" sh -c "[ '$frc' -eq 0 ] && [ '${f:-1}' = 0 ]"
      FLEET_PASSED=$(( FLEET_PASSED + ${p:-0} )); FLEET_FAILED=$(( FLEET_FAILED + ${f:-0} )); FLEET_ENGINES="$FLEET_ENGINES $target=${eng:-none}"
      [ "$frc" -eq 0 ] || FLEET="failed"
    done
    check "the fleet check tells the two hardware classes apart by the engine behind the Stellar key (${FLEET_ENGINES# })" [ "${FLEET_ENGINES# }" = "jc305=01 jc32=02" ]
  else
    warn "scardutil present but make-sequence / vpcdClasspath failed; fleet check skipped (see impala-card/scardutil/README.md)"
  fi
else
  log "  scardutil not configured (SCARDUTIL_DIR): skipped; see impala-card/scardutil/README.md for the fleet matrix on physical cards"
fi

export SIM_PLATFORM SIM_LEVEL SIM_CAP CARD_ENGINE FLEET_ENGINES   # read by jq ($ENV) for the record
finish_scenario scenario-05-card-issue "$(jq -cn --arg c "$CARD_ID" --arg cert "$CERT_ID" --arg p "$PROGRAM_ID" --arg a "$APPLET" --arg cap "$CAP_SHA" --arg g "$STELLAR" --arg h "$DEMO_HOLDER_ID" --arg fl "$FLEET" --argjson fp "${FLEET_PASSED:-0}" --argjson ff "${FLEET_FAILED:-0}" --arg rec "$record" \
  '{card_id:$c, cert_id:$cert, program_id_hex:$p, applet_version:$a, cap_sha256:$cap, stellar_address:$g, holder:$h, fleet_check:$fl, fleet_passed:$fp, fleet_failed:$ff, record:$rec}
   + {card_platform:$ENV.SIM_PLATFORM, card_javacard:$ENV.SIM_LEVEL, card_cap:$ENV.SIM_CAP, card_engine:$ENV.CARD_ENGINE, fleet_engines:($ENV.FLEET_ENGINES | ltrimstr(" "))}')" "$t0"
