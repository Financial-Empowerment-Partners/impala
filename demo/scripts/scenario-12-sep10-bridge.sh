#!/usr/bin/env bash
# Scenario 12 — SEP-10 sign-in with the bridge, end to end: a card's Stellar key signs the bridge's
# SEP-10 challenge and the bridge mints the card's session.
#   1. the signing key seed.sh activated is in service (the scenario waits out its activation delay);
#   2. discovery, read from the host with curl: stellar.toml names the active key and the endpoint, and a
#      challenge read field by field with scripts/sep10-challenge.py (no Stellar library, nothing shared
#      with the bridge) has the SEP-10 shape; malformed and unsigned requests are refused;
#   3. the app's real flow classes on the JVM (`:app:e2eTnetDebug -Pe2e.tests=CardSep10E2ETest`): cards
#      issued by the ceremony sign in through LoginViewModel with SEP-10 on both hardware classes, a
#      simulated JavaCard 3.0.5 card (the default CAP's software engine) and a simulated JavaCard 3.2 card
#      (the native CAP on the platform's EdDSA); a signed challenge works once; a card without a Stellar
#      key keeps the legacy login; an account with a privileged role (the admin) is never served by SEP-10;
#   4. the bridge's own evidence: its log names each sign-in, the event feed records each registered key,
#      the admin API lists the cards with their Stellar addresses.
# The bridge's SEP-10 home domain is 10.0.2.2:$BRIDGE_PORT (the emulator's name for this host); the host
# reaches the same listener at 127.0.0.1 and keeps the name (lib.sh sep10_curl; Sep10E2e.AliasedTransport).
# Usage: scripts/scenario-12-sep10-bridge.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq python3
require_env PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD HOLDER_G
APP="$REPO_DIR/impala-android-demo"
[ -f "$APP/app/google-services.json" ] || die "$APP/app/google-services.json missing (cp google-services.json.example google-services.json)"
t0="$(now_s)"
hr "scenario 12: SEP-10 sign-in with the bridge (home domain $SEP10_HOME_DOMAIN)"
wait_bridge 10
if ! sep10_enabled; then
  warn "DEMO_SEP10=$DEMO_SEP10: the bridge runs without SEP-10 and every card login is the legacy challenge; nothing to do"
  record_json scenario-12-sep10-bridge "$(jq -cn --arg at "$(utc_now)" '{scenario:"scenario-12-sep10-bridge", status:"skipped", reason:"DEMO_SEP10 is off", finished_at:$at}')"
  exit 0
fi
ART="$ARTIFACTS_DIR/e2e-sep10"; mkdir -p "$ART"; rm -f "$ART"/*.xml "$ART"/*.json
BASE="http://$SEP10_HOME_DOMAIN"
HDR="$(mktemp "${TMPDIR:-/tmp}/impala-suite-sep10.XXXXXX")"
trap 'rm -f "$HDR"; cleanup_tmp' EXIT
# sep10_req <METHOD> <url> [json-body] -> the body; the status afterwards in $(http_code), the response
# headers in $HDR (files, because callers use command substitution). Sent with an Origin, as a browser would.
sep10_req() {
  local method="$1" url="$2" body="${3:-}" out
  if [ -n "$body" ]; then
    out="$(printf '%s' "$body" | sep10_curl -sS -X "$method" -D "$HDR" -H 'Content-Type: application/json' -H 'Origin: https://wallet.example' --data-binary @- -w '\n%{http_code}' "$url")" || { printf '000' > "$HTTP_CODE_FILE"; return 1; }
  else
    out="$(sep10_curl -sS -X "$method" -D "$HDR" -H 'Origin: https://wallet.example' -w '\n%{http_code}' "$url")" || { printf '000' > "$HTTP_CODE_FILE"; return 1; }
  fi
  printf '%s' "${out##*$'\n'}" > "$HTTP_CODE_FILE"
  printf '%s\n' "${out%$'\n'*}"
}
acao_any() { grep -qi '^access-control-allow-origin: \*' "$HDR"; }

info "1/4 the signing key (generated and activated by seed.sh) is in service"
ADMIN_JWT="$(admin_jwt)"
st="$(sep10_wait_active "$ADMIN_JWT" 240)" || die "SEP-10 is not in service on this bridge (scripts/seed.sh arms it; scripts/status.sh shows the key)"
check_jq "admin API: SEP-10 is enabled for $SEP10_HOME_DOMAIN and this instance's key ring is live" ".enabled==true and .home_domain==\"$SEP10_HOME_DOMAIN\" and .key_ring_live==true" "$st"
ACTIVE="$(printf '%s' "$st" | jq -c '[.keys[] | select(.state=="active")][0]')"
ACTIVE_G="$(printf '%s' "$ACTIVE" | jq -r .public_address)"
check_jq "exactly one signing key is active and open on this bridge instance (v$(printf '%s' "$ACTIVE" | jq -r .version), fingerprint $(printf '%s' "$ACTIVE" | jq -r .fingerprint))" '[.keys[] | select(.state=="active" and .opened==true)] | length == 1' "$st"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$ADMIN_JWT")"
check_jq "event feed: the key's custody trail (custody.sep10_key_generated and _activated: fingerprints, never an address)" \
  '([.events[] | select(.event_type=="custody.sep10_key_generated")] | length) >= 1 and ([.events[] | select(.event_type=="custody.sep10_key_activated")] | length) >= 1 and ([.events[] | select(.event_type | startswith("custody.sep10_")) | .payload | tostring | test("G[A-Z2-7]{55}")] | any | not)' "$events"

info "2/4 discovery and the challenge, from the host (curl; the challenge is read by scripts/sep10-challenge.py)"
toml="$(sep10_req GET "$BASE/.well-known/stellar.toml")"
check "GET /.well-known/stellar.toml answers 200" [ "$(http_code)" = 200 ]
check "stellar.toml is readable from any origin (Access-Control-Allow-Origin: *)" acao_any
TOML_KEY="$(printf '%s\n' "$toml" | toml_value SIGNING_KEY)"; TOML_EP="$(printf '%s\n' "$toml" | toml_value WEB_AUTH_ENDPOINT)"; TOML_PP="$(printf '%s\n' "$toml" | toml_value NETWORK_PASSPHRASE)"
check "stellar.toml SIGNING_KEY is the active key the admin API reports ($ACTIVE_G)" [ "$TOML_KEY" = "$ACTIVE_G" ]
check "stellar.toml WEB_AUTH_ENDPOINT is $BASE/auth/sep10" [ "$TOML_EP" = "$BASE/auth/sep10" ]
check "stellar.toml NETWORK_PASSPHRASE is the testnet passphrase" [ "$TOML_PP" = "$TESTNET_PASSPHRASE" ]

# Any checksum-valid account gets a challenge (the bridge stores nothing per request): the issued card's
# Stellar address when scenario 05 ran, else the holder's address.
ACC="$(record_get scenario-05-card-issue .stellar_address)"; [ -n "$ACC" ] || ACC="$HOLDER_G"
ch="$(sep10_req GET "$BASE/auth/sep10?account=$ACC&home_domain=$SEP10_HOME_DOMAIN")"
check "GET /auth/sep10?account=$ACC answers 200" [ "$(http_code)" = 200 ]
check_eval "the challenge is not cacheable (Cache-Control: no-store) and readable from any origin" "grep -qi '^cache-control: no-store' '$HDR' && acao_any"
check_jq "the answer carries the transaction and the testnet passphrase" "(.transaction|type)==\"string\" and .network_passphrase==\"$TESTNET_PASSPHRASE\"" "$ch"
TX="$(printf '%s' "$ch" | jq -r '.transaction // empty')"
shape="$(python3 "$DEMO_DIR/scripts/sep10-challenge.py" "$TX" 2>/dev/null || echo '{}')"
TTL="$(printf '%s' "$st" | jq -r .challenge_ttl_secs)"
check_jq "challenge: a v1 transaction sourced by the signing key, sequence number 0 (no network accepts it), no memo" ".source==\"$ACTIVE_G\" and .sequence==0" "$shape"
check_jq "challenge: time bounds of exactly ${TTL}s, valid now" ".lifetime_secs==$TTL and .min_time <= (now|floor) + 5 and .max_time >= (now|floor)" "$shape"
check_jq "challenge: two manage-data operations — \"$SEP10_HOME_DOMAIN auth\" sourced by the client with a 64-character nonce, web_auth_domain sourced by the server" \
  "(.operations|length)==2 and .operations[0].source==\"$ACC\" and .operations[0].name==\"$SEP10_HOME_DOMAIN auth\" and .operations[0].value_bytes==64 and .operations[1].source==\"$ACTIVE_G\" and .operations[1].name==\"web_auth_domain\" and .operations[1].value==\"$SEP10_HOME_DOMAIN\"" "$shape"
check_jq "challenge: exactly one signature, the server's" '(.signatures|length)==1 and .signatures[0].bytes==64' "$shape"

sep10_req GET "$BASE/auth/sep10?account=not-an-account" >/dev/null
check "a malformed account is refused with 400" [ "$(http_code)" = 400 ]
check "the refusal is readable from any origin too (errors carry Access-Control-Allow-Origin: *)" acao_any
sep10_req GET "$BASE/auth/sep10?account=$ACC&memo=7" >/dev/null
check "a memo is refused with 400 (muxed accounts and memos are not offered)" [ "$(http_code)" = 400 ]
sep10_req POST "$BASE/auth/sep10" '{"transaction":"AAAA"}' >/dev/null
check "POST of something that is not a challenge is refused with 400" [ "$(http_code)" = 400 ]
# A challenge for an address that is no card's key, returned without a client signature: the generic 401.
hch="$(sep10_req GET "$BASE/auth/sep10?account=$HOLDER_G" | jq -r '.transaction // empty')"
resp="$(sep10_req POST "$BASE/auth/sep10" "$(jq -cn --arg t "$hch" '{transaction:$t}')")"
unsigned_code="$(http_code)"; leaked=0; printf '%s' "$resp" | grep -qi 'token' && leaked=1
check "POST of an unsigned challenge is refused with the generic 401, and no token is in the answer" [ "$unsigned_code" = 401 -a "$leaked" = 0 ]

info "3/4 the app's flow classes on the JVM: :app:e2eTnetDebug -Pe2e.tests=CardSep10E2ETest (first run compiles; several minutes)"
E2E_DIR="$STATE_DIR/e2e"; mkdir -p "$E2E_DIR"; chmod 700 "$E2E_DIR"
( umask 077; printf '%s' "$IMPALA_ADMIN_PASSWORD" > "$E2E_DIR/operator-password"; openssl rand -base64 18 > "$E2E_DIR/holder-password" )
RES_DIR="$APP/app/build/test-results/testTnetDebugUnitTest"
rm -f "$RES_DIR"/TEST-com.payala.impala.demo.e2e.*.xml
set +e
( cd "$APP" && JAVA_HOME="$(jdk17_home)" \
  IMPALA_E2E_BRIDGE_URL="$BRIDGE_URL" IMPALA_E2E_OPERATOR_ACCOUNT="$PAYALA_ADMIN_ID" \
  IMPALA_E2E_OPERATOR_PASSWORD_FILE="$E2E_DIR/operator-password" IMPALA_E2E_HOLDER_PASSWORD_FILE="$E2E_DIR/holder-password" \
  IMPALA_E2E_SEP10_HOME_DOMAIN="$SEP10_HOME_DOMAIN" IMPALA_E2E_REPORT_DIR="$ART" \
  ./gradlew -q :app:e2eTnetDebug -Pe2e.tests=CardSep10E2ETest --console=plain ) > "$STATE_DIR/e2e-sep10.log" 2>&1
rc=$?
set -e
rm -f "$E2E_DIR/operator-password" "$E2E_DIR/holder-password"
grep -E '^e2e: SEP-10|FAILED|BUILD' "$STATE_DIR/e2e-sep10.log" | tail -n 12 | sed 's/^/  /' >&2 || true
cp "$RES_DIR"/TEST-com.payala.impala.demo.e2e.CardSep10E2ETest.xml "$ART/" 2>/dev/null || true
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
printf '%s' "$summary" | jq -r '.cases[] | "  \(.status)\t\(.name)"' | column -t -s "$(printf '\t')" >&2
rep='{}'; [ -f "$ART/sep10-bridge.json" ] && rep="$(cat "$ART/sep10-bridge.json")"
check "gradle :app:e2eTnetDebug -Pe2e.tests=CardSep10E2ETest exited 0" [ "$rc" -eq 0 ]
check_jq "CardSep10E2ETest: all four cases ran and passed (none skipped, none failed)" '.tests==4 and .failures==0 and .errors==0 and .skipped==0' "$summary"
check_jq "both hardware classes signed in through SEP-10: a simulated JavaCard 3.0.5 card (the default CAP's software engine) and a simulated JavaCard 3.2 card (the native CAP, the platform's own EdDSA)" \
  '([.sign_ins[]? | select(.mechanism=="sep10") | {engine, platform, javacard}] | sort_by(.engine)) == [{"engine":"native","platform":"jc32","javacard":"3.2"},{"engine":"soft","platform":"jc305","javacard":"3.0.5"}]' "$rep"
check_jq "a card without a Stellar key signed in with the legacy challenge on the same bridge" '[.sign_ins[]? | select(.engine=="none" and .mechanism=="legacy")] | length == 1' "$rep"
check_jq "the admin's card was refused by SEP-10 (privileged role) and signed in the legacy way" "[.sign_ins[]? | select(.account==\"$PAYALA_ADMIN_ID\" and .mechanism==\"legacy\" and ((.sep10 // \"\") | startswith(\"refused\")))] | length == 1" "$rep"
check "no TEST ISSUER banner: the lane's cards were certified by the bridge's program key" sh -c "! grep -q 'TEST ISSUER' '$STATE_DIR/e2e-sep10.log'"

info "4/4 the bridge's own evidence"
blog="$(compose logs --no-color --tail=4000 impala-bridge 2>/dev/null || true)"
n_sep10="$(printf '%s' "$rep" | jq '[.sign_ins[]? | select(.mechanism=="sep10")] | length')"
missing=0
for g in $(printf '%s' "$rep" | jq -r '.sign_ins[]? | select(.mechanism=="sep10") | .stellar_address'); do
  printf '%s' "$blog" | grep -q "sep10: card key $g signed in" || missing=$((missing + 1))
done
check "bridge log: a 'sep10: card key G… signed in' line for each of the lane's $n_sep10 SEP-10 sign-ins" [ "$missing" -eq 0 -a "$n_sep10" -ge 2 ]
check_eval "bridge log: the admin's SEP-10 attempt was refused for its privileged role" "printf '%s' \"\$blog\" | grep -q 'account_id=$PAYALA_ADMIN_ID holds a privileged role; SEP-10 sign-in refused'"
events="$(bridge_api GET '/admin/events?since=0&limit=500' "$ADMIN_JWT")"
keyed="$(printf '%s' "$rep" | jq -c '[.sign_ins[]? | select(.stellar_address != null) | .card_id]')"
check_jq "event feed: exactly one card.stellar_key_registered for each card of the lane that has a Stellar key (payload: the card id)" \
  "($keyed) as \$ids | (\$ids | length) >= 3 and ([\$ids[] as \$id | [.events[] | select(.event_type==\"card.stellar_key_registered\" and ((.payload.card_id // \"\") | ascii_downcase)==(\$id | ascii_downcase))] | length] | all(. == 1))" "$events"
st2="$(sep10_status "$ADMIN_JWT")"
check_jq "admin API: registered_card_keys counts them ($(printf '%s' "$st2" | jq -r .registered_card_keys) active cards with a Stellar key on this bridge)" ".registered_card_keys >= ($keyed | length)" "$st2"
lane_acct="$(printf '%s' "$rep" | jq -r '[.sign_ins[]? | select(.mechanism=="sep10")][0].account // empty')"
cards="$(bridge_api GET "/admin/accounts/$lane_acct/cards" "$ADMIN_JWT")"
want="$(printf '%s' "$rep" | jq -c "[.sign_ins[]? | select(.account==\"$lane_acct\" and .stellar_address != null) | .stellar_address] | sort")"
check_jq "admin API: GET /admin/accounts/{holder}/cards lists the lane holder's cards with their Stellar addresses" \
  "([.cards[]? | select(.active==true and .stellar_address != null) | .stellar_address]) as \$have | ($want | length) >= 2 and (($want - \$have) == [])" "$cards"

finish_scenario scenario-12-sep10-bridge "$(jq -cn --arg d "$SEP10_HOME_DOMAIN" --argjson key "$ACTIVE" --arg ep "$TOML_EP" --argjson shape "$shape" --argjson s "$summary" --argjson rep "$rep" --arg art "$ART" --argjson rc "$rc" \
  '{home_domain:$d, signing_key:($key | {version, fingerprint, public_address}), web_auth_endpoint:$ep,
    challenge:($shape | {source, fee, sequence, lifetime_secs, operations:[.operations[]? | {source, name, value_bytes}], signatures}),
    tests:$s.tests, failures:$s.failures, skipped:$s.skipped, cases:$s.cases, sign_ins:($rep.sign_ins // []), report:$art, gradle_exit:$rc}')" "$t0"
