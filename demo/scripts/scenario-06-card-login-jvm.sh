#!/usr/bin/env bash
# Scenario 06 — card login, SDK lane: the demo app's real flow classes (LoginViewModel, CardsViewModel)
# drive a jcardsim card issued by the issuance ceremony against THIS bridge, on the JVM (no emulator):
# `./gradlew :app:e2eTnetDebug` (impala-android-demo/app/src/e2e). CardAuthE2ETest proves card login
# end to end; CardTransferE2ETest skips honestly until the bridge serves the offline lane (/offline/*).
# Usage: scripts/scenario-06-card-login-jvm.sh   (DEMO_E2E_SLOW=1 adds the 61 s challenge-expiry test)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env PAYALA_ADMIN_ID IMPALA_ADMIN_PASSWORD
APP="$REPO_DIR/impala-android-demo"
[ -f "$APP/app/google-services.json" ] || die "$APP/app/google-services.json missing (cp google-services.json.example google-services.json)"
t0="$(now_s)"
hr "scenario 06: card login on the JVM (e2eTnetDebug against $BRIDGE_URL)"
wait_bridge 10

# the operator (ADMIN_ACCOUNT_IDS → manage_keys) lets the lane generate issuer certificates; passwords travel by file, never argv
E2E_DIR="$STATE_DIR/e2e"; mkdir -p "$E2E_DIR"; chmod 700 "$E2E_DIR"
( umask 077; printf '%s' "$IMPALA_ADMIN_PASSWORD" > "$E2E_DIR/operator-password"; openssl rand -base64 18 > "$E2E_DIR/holder-password" )
info "running :app:e2eTnetDebug (first run compiles the app and the card SDK; several minutes)"
set +e
( cd "$APP" && JAVA_HOME="$(jdk17_home)" \
  IMPALA_E2E_BRIDGE_URL="$BRIDGE_URL" IMPALA_E2E_OPERATOR_ACCOUNT="$PAYALA_ADMIN_ID" \
  IMPALA_E2E_OPERATOR_PASSWORD_FILE="$E2E_DIR/operator-password" IMPALA_E2E_HOLDER_PASSWORD_FILE="$E2E_DIR/holder-password" \
  IMPALA_E2E_SLOW="${DEMO_E2E_SLOW:-}" \
  ./gradlew -q :app:e2eTnetDebug --console=plain ) > "$STATE_DIR/e2e-jvm.log" 2>&1
rc=$?
set -e
rm -f "$E2E_DIR/operator-password" "$E2E_DIR/holder-password"
tail -n 15 "$STATE_DIR/e2e-jvm.log" | sed 's/^/  /' >&2

# results: e2eTnetDebug runs testTnetDebugUnitTest filtered to com.payala.impala.demo.e2e.*; Gradle writes JUnit XML per class
RES_DIR="$APP/app/build/test-results/testTnetDebugUnitTest"
ls "$RES_DIR"/TEST-com.payala.impala.demo.e2e.*.xml >/dev/null 2>&1 || die "no e2e test results under app/build/test-results/testTnetDebugUnitTest (gradle exit $rc; see state/e2e-jvm.log)"
mkdir -p "$ARTIFACTS_DIR/e2e-jvm"; rm -f "$ARTIFACTS_DIR"/e2e-jvm/*.xml; cp "$RES_DIR"/TEST-com.payala.impala.demo.e2e.*.xml "$ARTIFACTS_DIR/e2e-jvm/"
summary="$(python3 - "$ARTIFACTS_DIR/e2e-jvm" <<'EOF'
import glob, sys, xml.etree.ElementTree as ET, json
tests=fail=err=skip=0; cases=[]
for f in glob.glob(sys.argv[1] + "/TEST-com.payala.impala.demo.e2e.*.xml"):
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
printf '%s' "$summary" | jq -r '.cases[] | "  \(.status)\t\(.class | split(".") | last).\(.name)"' | column -t -s "$(printf '\t')" >&2
check "gradle :app:e2eTnetDebug exited 0" [ "$rc" -eq 0 ]
check_jq "CardAuthE2ETest ran at least 4 card-login cases with no failures" '([.cases[] | select((.class | endswith("CardAuthE2ETest")) and .status=="passed")] | length) >= 4 and .failures==0 and .errors==0' "$summary"
check_jq "CardTransferE2ETest is skipped (the bridge has no /offline lane yet), not failed" '([.cases[] | select((.class | endswith("CardTransferE2ETest")) and .status=="failed")] | length) == 0' "$summary"
check "junit xml copied to state/artifacts/e2e-jvm" sh -c "ls '$ARTIFACTS_DIR'/e2e-jvm/*.xml >/dev/null 2>&1"
check "no TEST ISSUER banner: the lane's cards were certified by the bridge's program key" sh -c "! grep -q 'TEST ISSUER' '$STATE_DIR/e2e-jvm.log'"

finish_scenario scenario-06-card-login-jvm "$(printf '%s' "$summary" | jq -c --arg rep "$ARTIFACTS_DIR/e2e-jvm" --argjson rc "$rc" '. + {report:$rep, gradle_exit:$rc}')" "$t0"
