#!/usr/bin/env bash
# Scenario 07 — the Android emulator: the demo app's tnet flavor on an API-34 emulator reaches this
# bridge at 10.0.2.2:$BRIDGE_PORT and the simulated card through `adb reverse` + the debug TCP card
# transport (the emulator has no NFC). The instrumented tests drive the REAL login screen:
# CardLoginUiTest taps "Sign in with Card" and lands on MainActivity as the holder; CardRedeemUiTest is run
# too so its honest skip (the offline lane is not deployed) shows in the report. (SmokeTest is not run: it
# asserts the base package name and the tnet flavor installs as com.payala.impala.demo.testnet.)
# Artifacts: screenshots, a screen recording and the JUnit XML under state/artifacts/android/.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd curl jq
require_env DEMO_HOLDER_ID
APP="$REPO_DIR/impala-android-demo"
[ -f "$APP/app/google-services.json" ] || die "$APP/app/google-services.json missing (cp google-services.json.example google-services.json)"
SERIAL="${DEMO_EMULATOR_SERIAL:-emulator-5554}"
ADB="$(adb_bin)" || die "adb not found"
adb() { "$ADB" -s "$SERIAL" "$@"; }
ART="$ARTIFACTS_DIR/android"; mkdir -p "$ART"
PKG="com.payala.impala.demo.testnet"
t0="$(now_s)"
hr "scenario 07: Android emulator (card login UI test against $BRIDGE_URL)"
wait_bridge 10

info "1/5 the simulated card must be issued (scenario 05) and the emulator booted"
if ! "$DEMO_DIR/scripts/simulator.sh" status >/dev/null 2>&1 || [ ! -f "$RECORDS_DIR/scenario-05-card-issue.json" ]; then
  log "  no issued card in a running simulator: running scenario 05 first"
  "$DEMO_DIR/scripts/scenario-05-card-issue.sh" >/dev/null
fi
CARD_ID="$(record_get scenario-05-card-issue .card_id)"
check "an issued card is available on the simulator ($CARD_ID)" sh -c "[ -n '$CARD_ID' ] && '$DEMO_DIR/scripts/simulator.sh' status >/dev/null 2>&1"
"$DEMO_DIR/scripts/emulator.sh" up
check "emulator booted (API $(adb shell getprop ro.build.version.sdk | tr -d '\r'))" sh -c "[ \"\$('$ADB' -s $SERIAL shell getprop sys.boot_completed | tr -d '\r')\" = 1 ]"

info "2/5 wiring: adb reverse tcp:$SIM_PORT (card) and the debug transport property; the bridge is 10.0.2.2:$BRIDGE_PORT from the emulator"
adb reverse "tcp:$SIM_PORT" "tcp:$SIM_PORT" >/dev/null
adb shell setprop debug.impala.tcp_card "127.0.0.1:$SIM_PORT"
cleanup() { adb reverse --remove "tcp:$SIM_PORT" >/dev/null 2>&1 || true; adb shell setprop debug.impala.tcp_card '""' >/dev/null 2>&1 || true; }
trap 'cleanup; cleanup_tmp' EXIT
check_eval "adb reverse forwards tcp:$SIM_PORT from the emulator to the host simulator" "'$ADB' -s $SERIAL reverse --list | grep -q 'tcp:$SIM_PORT'"
check_eval "debug.impala.tcp_card points the app's debug card transport at 127.0.0.1:$SIM_PORT" "'$ADB' -s $SERIAL shell getprop debug.impala.tcp_card | grep -q '127.0.0.1:$SIM_PORT'"

info "3/5 build + install the tnet app and its instrumentation, then run CardLoginUiTest (screen recorded)"
# screenrecord must be stopped with SIGINT ON THE DEVICE to finalize the mp4 (killing the host adb does not)
adb shell screenrecord --time-limit 170 /sdcard/impala-demo.mp4 >/dev/null 2>&1 &
REC_PID=$!
# stills: the login screen is captured deterministically before the test (install + launch + screencap); the main
# screen after the card login is captured by a watcher the moment MainActivity becomes the resumed activity
# (a warm run finishes in seconds; the activity RECORD lingers after finish, the resumed one does not)
rm -f "$ART/login-screen.png" "$ART/main-after-card-login.png"
( cd "$APP" && JAVA_HOME="$(jdk17_home)" ANDROID_SERIAL="$SERIAL" ./gradlew -q :app:installTnetDebug --console=plain ) >> "$STATE_DIR/android-connected.log" 2>&1 || warn "installTnetDebug failed (the connected test installs the app itself)"
adb shell am start -W -n "$PKG/com.payala.impala.demo.ui.login.LoginActivity" >/dev/null 2>&1 || true
sleep 2; adb exec-out screencap -p > "$ART/login-screen.png" 2>/dev/null || true
adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
resumed() { "$ADB" -s "$SERIAL" shell dumpsys activity activities 2>/dev/null | grep -m1 'topResumedActivity=' | grep -oE 'com\.payala\.impala\.demo\.ui\.[a-z]+\.[A-Za-z]+Activity' || true; }
( while :; do
    case "$(resumed)" in *MainActivity) sleep 0.3; "$ADB" -s "$SERIAL" exec-out screencap -p > "$ART/main-after-card-login.png" 2>/dev/null; break ;; esac
    sleep 0.15
  done ) &
WATCH_PID=$!
set +e
( cd "$APP" && JAVA_HOME="$(jdk17_home)" ANDROID_SERIAL="$SERIAL" ./gradlew -q :app:connectedTnetDebugAndroidTest --console=plain \
    -Pandroid.testInstrumentationRunnerArguments.class=com.payala.impala.demo.CardLoginUiTest,com.payala.impala.demo.CardRedeemUiTest \
    -Pandroid.testInstrumentationRunnerArguments.cardAccount="$DEMO_HOLDER_ID" ) > "$STATE_DIR/android-connected.log" 2>&1
rc=$?
set -e
tail -n 12 "$STATE_DIR/android-connected.log" | sed 's/^/  /' >&2
adb shell 'pkill -INT screenrecord || kill -2 $(pidof screenrecord) 2>/dev/null' >/dev/null 2>&1 || true
sleep 3; kill "$REC_PID" "$WATCH_PID" 2>/dev/null || true; wait "$REC_PID" "$WATCH_PID" 2>/dev/null || true
adb pull /sdcard/impala-demo.mp4 "$ART/card-login-ui-test.mp4" >/dev/null 2>&1 && ok "screen recording: state/artifacts/android/card-login-ui-test.mp4 ($(wc -c < "$ART/card-login-ui-test.mp4" | tr -d ' ') bytes)" || warn "no screen recording pulled"
adb shell rm -f /sdcard/impala-demo.mp4 >/dev/null 2>&1 || true

info "4/5 results and screenshots"
XML_DIR="$(ls -d "$APP"/app/build/outputs/androidTest-results/connected/*/ 2>/dev/null | head -n1 || true)"
[ -n "$XML_DIR" ] || XML_DIR="$(ls -d "$APP"/app/build/outputs/androidTest-results/connected 2>/dev/null || true)"
cp "$XML_DIR"/*.xml "$ART/" 2>/dev/null || cp "$(find "$APP/app/build/outputs/androidTest-results" -name '*.xml' | head -n1)" "$ART/" 2>/dev/null || true
summary="$(python3 - "$ART" <<'EOF'
import glob, sys, xml.etree.ElementTree as ET, json
tests=fail=err=skip=0; cases=[]
for f in glob.glob(sys.argv[1] + "/*.xml"):
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
check "gradle connectedTnetDebugAndroidTest exited 0" [ "$rc" -eq 0 ]
check "the connected run produced a JUnit report for the tnet app on this AVD" sh -c "ls '$ART'/*.xml >/dev/null 2>&1"
check_jq "CardLoginUiTest: Sign in with Card landed on MainActivity as the holder" '[.cases[] | select((.class | endswith("CardLoginUiTest")) and .status=="passed")] | length >= 1' "$summary"
check_jq "CardRedeemUiTest reports skipped (offline lane not deployed), not failed" '[.cases[] | select((.class | endswith("CardRedeemUiTest")) and .status=="failed")] | length == 0' "$summary"
# connectedAndroidTest uninstalls the app afterwards; the stills were taken by the activity watcher during the run.
if command -v ffprobe >/dev/null 2>&1 && [ -s "$ART/card-login-ui-test.mp4" ]; then
  dur="$( (ffprobe -v error -show_entries format=duration -of csv=p=0 "$ART/card-login-ui-test.mp4" 2>/dev/null || true) | cut -d. -f1)"
  log "  recording: ${dur:-?}s"
  [ -s "$ART/main-after-card-login.png" ] || ffmpeg -v error -y -sseof -1 -i "$ART/card-login-ui-test.mp4" -frames:v 1 "$ART/main-after-card-login.png" >/dev/null 2>&1 || true
fi
check "stills captured (login screen, main after card login)" sh -c "[ -s '$ART/login-screen.png' ] && [ -s '$ART/main-after-card-login.png' ]"

info "5/5 done"
log "  artifacts: state/artifacts/android/ (junit xml, mp4, png)"
finish_scenario scenario-07-android-emulator "$(printf '%s' "$summary" | jq -c --arg rep "$ART" --argjson rc "$rc" --arg c "$CARD_ID" --arg pkg "$PKG" '. + {report:$rep, gradle_exit:$rc, card_id:$c, package:$pkg}')" "$t0"
