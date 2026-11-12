#!/usr/bin/env bash
# Scenario 13 — SEP-10 sign-in with third-party services: the card's Stellar key is an ordinary Stellar
# identity, so the card signs in at SEP-10 servers nobody here wrote. For every home domain in
# DEMO_SEP10_THIRD_PARTY (TESTNET servers; the default is the SDF reference anchor, testanchor.stellar.org):
#   1. discovery from the host with curl: stellar.toml names a web-auth endpoint and a signing key on
#      testnet, and its challenge, read by scripts/sep10-challenge.py, has the shape the card accepts;
#   2. the card lane on the JVM (`:app:e2eTnetDebug -Pe2e.tests=CardSep10ThirdPartyE2ETest`): the holder's
#      issued card (scenario 05, over the simulator's TCP socket) and one jcardsim card per hardware class
#      (a JavaCard 3.0.5 card on the software engine, a JavaCard 3.2 card on the platform's EdDSA) parse
#      the server's challenge with the applet's own rules, sign it, and receive the server's token;
#   3. the token at work: a SEP-24 route of that server refuses a request without it and answers with it.
# No token is written anywhere: the report carries addresses, claims and status codes only.
# A server that cannot be reached is reported and skipped; a server that does not offer SEP-10 on testnet
# (its stellar.toml must name the testnet passphrase) fails the scenario, and neither a challenge is
# requested from it nor anything signed for it. Needs outbound HTTPS to the servers named; not the bridge.
# Usage: scripts/scenario-13-sep10-third-party.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq python3
APP="$REPO_DIR/impala-android-demo"
[ -f "$APP/app/google-services.json" ] || die "$APP/app/google-services.json missing (cp google-services.json.example google-services.json)"
t0="$(now_s)"
DOMAINS="$(printf '%s' "${DEMO_SEP10_THIRD_PARTY:-}" | tr ',' ' ')"
hr "scenario 13: SEP-10 sign-in with third-party services (${DOMAINS:-none configured})"
if [ -z "$(printf '%s' "$DOMAINS" | tr -d ' ')" ]; then
  warn "DEMO_SEP10_THIRD_PARTY is empty: no third-party server to sign in to; nothing to do"
  record_json scenario-13-sep10-third-party "$(jq -cn --arg at "$(utc_now)" '{scenario:"scenario-13-sep10-third-party", status:"skipped", reason:"DEMO_SEP10_THIRD_PARTY is empty", finished_at:$at}')"
  exit 0
fi
ART="$ARTIFACTS_DIR/e2e-sep10-third-party"; mkdir -p "$ART"; rm -f "$ART"/*.xml "$ART"/*.json

info "1/3 discovery from the host (curl; challenges read by scripts/sep10-challenge.py)"
# A throwaway account id to ask for a challenge with: any checksum-valid G address gets one.
PROBE_G="${HOLDER_G:-GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7}"
reachable=""; discovery='[]'
for d in $DOMAINS; do
  if ! toml="$(curl -fsS -m 20 "https://$d/.well-known/stellar.toml" 2>/dev/null)"; then
    warn "$d: stellar.toml is not reachable from this host; skipped"
    discovery="$(printf '%s' "$discovery" | jq -c --arg d "$d" '. + [{domain:$d, reachable:false}]')"
    continue
  fi
  ep="$(printf '%s\n' "$toml" | toml_value WEB_AUTH_ENDPOINT)"; key="$(printf '%s\n' "$toml" | toml_value SIGNING_KEY)"; pp="$(printf '%s\n' "$toml" | toml_value NETWORK_PASSPHRASE)"
  check "$d: stellar.toml offers SEP-10 (WEB_AUTH_ENDPOINT $ep, SIGNING_KEY $key)" [ -n "$ep" -a -n "$key" ]
  check "$d: it is a TESTNET server (the demo never signs in on another network)" [ "$pp" = "$TESTNET_PASSPHRASE" ]
  if [ -z "$ep" ] || [ -z "$key" ] || [ "$pp" != "$TESTNET_PASSPHRASE" ]; then
    # A configured server that does not offer SEP-10 on testnet is a failure of the scenario, and it ends
    # here for that server: no challenge is requested from it and no card is asked to sign for it.
    warn "$d: not a testnet SEP-10 server (NETWORK_PASSPHRASE '${pp:-not stated}'): nothing more is requested from it and nothing is signed for it"
    discovery="$(printf '%s' "$discovery" | jq -c --arg d "$d" --arg pp "$pp" '. + [{domain:$d, reachable:true, usable:false, network_passphrase:(if $pp == "" then null else $pp end)}]')"
    continue
  fi
  reachable="$reachable $d"
  shape='{}'
  if [ -n "$ep" ] && tx="$(curl -fsS -m 20 "$ep?account=$PROBE_G" 2>/dev/null | jq -r '.transaction // empty')" && [ -n "$tx" ]; then
    shape="$(python3 "$DEMO_DIR/scripts/sep10-challenge.py" "$tx" 2>/dev/null || echo '{}')"
  fi
  check_jq "$d: its challenge is what the card signs — sourced by that signing key, sequence 0, time-bounded, manage-data only, first operation \"… auth\" for the client" \
    ".source==\"$key\" and .sequence==0 and .lifetime_secs > 0 and (.operations|length) >= 1 and (.operations|length) <= 5 and .operations[0].source==\"$PROBE_G\" and (.operations[0].name | endswith(\" auth\")) and .operations[0].value_bytes==64" "$shape"
  discovery="$(printf '%s' "$discovery" | jq -c --arg d "$d" --arg ep "$ep" --arg key "$key" --argjson shape "$shape" \
    '. + [{domain:$d, reachable:true, web_auth_endpoint:$ep, signing_key:$key, challenge:($shape | {fee, lifetime_secs, operations:[.operations[]? | {name, value_bytes}], signatures:(.signatures // [] | length)})}]')"
done
if [ -z "$reachable" ] && [ "$FAILS" -gt 0 ]; then
  # Reachable, but not usable (see above): that is a failed scenario, never a skipped one.
  finish_scenario scenario-13-sep10-third-party "$(jq -cn --argjson disc "$discovery" '{servers:$disc, issued_card:null, tests:0, failures:0, skipped:0}')" "$t0"
fi
if [ -z "$reachable" ]; then
  warn "none of the configured servers is reachable from this host: skipped (outbound HTTPS to: $DOMAINS)"
  record_json scenario-13-sep10-third-party "$(jq -cn --argjson disc "$discovery" --arg at "$(utc_now)" '{scenario:"scenario-13-sep10-third-party", status:"skipped", reason:"no third-party server reachable", servers:$disc, finished_at:$at}')"
  exit 0
fi

info "2/3 the card lane on the JVM: :app:e2eTnetDebug -Pe2e.tests=CardSep10ThirdPartyE2ETest (first run compiles; several minutes)"
CARD_TCP=""; CARD_G=""; CARD_HW=""; CARD_ENG=""
if "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1 && [ -f "$RECORDS_DIR/scenario-05-card-issue.json" ]; then
  CARD_TCP="127.0.0.1:$SIM_PORT"; CARD_G="$(record_get scenario-05-card-issue .stellar_address)"
  CARD_HW="$(record_get scenario-05-card-issue .card_platform)"; CARD_ENG="$(record_get scenario-05-card-issue .card_engine)"
  log "  the holder's issued card (scenario 05) takes part: $CARD_G at $CARD_TCP (${CARD_HW:-?} hardware, ${CARD_ENG:-?} engine)"
else
  log "  no issued card in a running simulator (scenario 05): the lane uses its own jcardsim cards only"
fi
RES_DIR="$APP/app/build/test-results/testTnetDebugUnitTest"
rm -f "$RES_DIR"/TEST-com.payala.impala.demo.e2e.*.xml
set +e
( cd "$APP" && JAVA_HOME="$(jdk17_home)" \
  IMPALA_E2E_SEP10_THIRD_PARTY="$(printf '%s' "$reachable" | sed 's/^ //' | tr ' ' ',')" IMPALA_E2E_CARD_TCP="$CARD_TCP" IMPALA_E2E_REPORT_DIR="$ART" \
  ./gradlew -q :app:e2eTnetDebug -Pe2e.tests=CardSep10ThirdPartyE2ETest --console=plain ) > "$STATE_DIR/e2e-sep10-third-party.log" 2>&1
rc=$?
set -e
grep -E '^e2e: |FAILED|BUILD' "$STATE_DIR/e2e-sep10-third-party.log" | tail -n 14 | sed 's/^/  /' >&2 || true
cp "$RES_DIR"/TEST-com.payala.impala.demo.e2e.CardSep10ThirdPartyE2ETest.xml "$ART/" 2>/dev/null || true
summary="$(python3 - "$ART" <<'EOF'
import glob, sys, xml.etree.ElementTree as ET, json
tests=fail=err=skip=0; cases=[]
for f in glob.glob(sys.argv[1] + "/TEST-*.xml"):
    r = ET.parse(f).getroot()
    suites = [r] if r.tag == "testsuite" else r.findall("testsuite")
    for s in suites:
        tests += int(s.get("tests", 0)); fail += int(s.get("failures", 0)); err += int(s.get("errors", 0)); skip += int(s.get("skipped", 0))
        for c in s.findall("testcase"):
            st = "skipped" if c.find("skipped") is not None else ("failed" if (c.find("failure") is not None or c.find("error") is not None) else "passed")
            cases.append({"class": c.get("classname"), "name": c.get("name"), "status": st})
print(json.dumps({"tests": tests, "failures": fail, "errors": err, "skipped": skip, "cases": cases}))
EOF
)"
rep='{"servers":[]}'; [ -f "$ART/sep10-third-party.json" ] && rep="$(cat "$ART/sep10-third-party.json")"
check "gradle :app:e2eTnetDebug -Pe2e.tests=CardSep10ThirdPartyE2ETest exited 0" [ "$rc" -eq 0 ]
check_jq "CardSep10ThirdPartyE2ETest ran and passed (not skipped, not failed)" '.tests==1 and .failures==0 and .errors==0 and .skipped==0' "$summary"
for d in $reachable; do
  srv="$(printf '%s' "$rep" | jq -c --arg d "$d" '[.servers[]? | select(.domain==$d)][0] // {}')"
  check_jq "$d: both hardware classes received its token: a simulated JavaCard 3.0.5 card (software engine) and a simulated JavaCard 3.2 card (the platform's EdDSA)" \
    '([.sign_ins[]? | select(.platform != null) | {engine, platform}] | sort_by(.engine)) == [{"engine":"native","platform":"jc32"},{"engine":"soft","platform":"jc305"}]' "$srv"
  check_jq "$d: every token is a JWT for the card's own Stellar account (sub), not expired" \
    '(.sign_ins | length) >= 2 and ([.sign_ins[] | . as $s | (($s.claims.sub // "") | startswith($s.stellar_address)) and ($s.claims.exp > (now|floor)) and $s.token_length > 40] | all)' "$srv"
  if [ -n "$CARD_G" ]; then
    check_jq "$d: the holder's issued card ($CARD_G, ${CARD_HW:-?} hardware) signed in there with the key it uses at the bridge" "[.sign_ins[]? | select(.stellar_address==\"$CARD_G\")] | length == 1" "$srv"
  fi
  check_jq "$d: the token opens a protected SEP-24 route (refused without it: $(printf '%s' "$srv" | jq -r '.protected.anonymous_status // "?"'); answered with it: $(printf '%s' "$srv" | jq -r '.protected.authenticated_status // "?"'))" \
    '.protected.checked==false or ((.protected.anonymous_status==401 or .protected.anonymous_status==403) and .protected.authenticated_status==200)' "$srv"
done

info "3/3 what was shown"
printf '%s' "$rep" | jq -r --arg hw "${CARD_HW:-}" '.servers[]? | select(.reachable==true) | .domain as $d | .sign_ins[]? | "  \($d)\t\(.card)\t\(.platform // (if $hw == "" then "?" else $hw end))\t\(.engine // "?")\t\(.stellar_address)\tiss=\(.claims.iss // "?")"' | column -t -s "$(printf '\t')" >&2 || true
log "  artifacts: state/artifacts/e2e-sep10-third-party/ (junit xml, sep10-third-party.json; no token is stored)"
check_eval "the report holds no token (claims and status codes only)" "! grep -Eq 'eyJ[A-Za-z0-9_-]{10,}\\.' '$ART/sep10-third-party.json'"

finish_scenario scenario-13-sep10-third-party "$(jq -cn --argjson disc "$discovery" --argjson s "$summary" --argjson rep "$rep" --arg art "$ART" --arg card "$CARD_G" --arg hw "$CARD_HW" --argjson rc "$rc" \
  '{servers:[$disc[] | . as $d | . + ([$rep.servers[]? | select(.domain==$d.domain)][0] // {} | {sign_ins:(.sign_ins // []), protected:(.protected // null)})],
    issued_card:(if $card == "" then null else $card end), issued_card_platform:(if $hw == "" then null else $hw end), tests:$s.tests, failures:$s.failures, skipped:$s.skipped, report:$art, gradle_exit:$rc}')" "$t0"
