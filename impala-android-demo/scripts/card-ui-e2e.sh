#!/usr/bin/env bash
# T2 card UI lane (plan C-11): drive the real login screen on an emulator with
# a jcardsim card served from the host, issued against a live bridge.
#
# Prerequisites: an emulator running (`adb devices`), a DISPOSABLE bridge on
# the host's :8080 (the tnet flavor reaches it as 10.0.2.2:8080) set up as in
# app/src/e2e/README.md, and:
#   IMPALA_E2E_OPERATOR_ACCOUNT, IMPALA_E2E_OPERATOR_PASSWORD_FILE  (ADMIN_ACCOUNT_IDS account)
#   IMPALA_ISSUE_KMK                                                  (32 hex, any value for a test card)
# Usage: scripts/card-ui-e2e.sh   (from impala-android-demo/)
set -euo pipefail

BRIDGE=${BRIDGE:-http://127.0.0.1:8080}
PORT=${SIM_PORT:-9443}
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
card_root="$here/../impala-card"
tmp="$(mktemp -d)"
trap 'kill "${server_pid:-}" 2>/dev/null || true; adb shell setprop debug.impala.tcp_card "" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT

json() { python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
token() { # account password -> temporal token
  local r; r=$(curl -sf -X POST "$BRIDGE/token" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | json "['refresh_token']")
  curl -sf -X POST "$BRIDGE/token" -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$r\"}" | json "['temporal_token']"
}
random_g() { python3 - <<'PY'
import os, base64
p = bytes([6 << 3]) + os.urandom(32)
crc = 0
for b in p:
    crc ^= b << 8
    for _ in range(8):
        crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
    crc &= 0xFFFF
print(base64.b32encode(p + bytes([crc & 0xFF, crc >> 8])).decode().rstrip('='))
PY
}

echo "== operator + holder"
OP_TOKEN=$(token "$IMPALA_E2E_OPERATOR_ACCOUNT" "$(cat "$IMPALA_E2E_OPERATOR_PASSWORD_FILE")")
HOLDER=$(python3 -c 'import uuid; print(uuid.uuid4())')
HOLDER_PW=$(head -c 18 /dev/urandom | base64)
curl -sf -X POST "$BRIDGE/account" -H "Authorization: Bearer $OP_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"stellar_account_id\":\"$(random_g)\",\"payala_account_id\":\"$HOLDER\",\"first_name\":\"UI\",\"last_name\":\"Holder\"}" >/dev/null
curl -sf -X POST "$BRIDGE/authenticate" -H 'Content-Type: application/json' -d "{\"account_id\":\"$HOLDER\",\"password\":\"$HOLDER_PW\"}" >/dev/null
HOLDER_TOKEN=$(token "$HOLDER" "$HOLDER_PW")

echo "== simulated card on 127.0.0.1:$PORT"
(cd "$card_root" && ./gradlew -q :simulator:serve --args="--port $PORT") > "$tmp/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 120); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 1; done

echo "== issue it through the bridge"
(cd "$card_root" && IMPALA_HOLDER_TOKEN="$HOLDER_TOKEN" IMPALA_OPERATOR_TOKEN="$OP_TOKEN" \
  IMPALA_USER_PIN=2468 IMPALA_MASTER_PIN=14117298 \
  ./gradlew -q :tools:issue:run --args="--transport tcp:127.0.0.1:$PORT --account $HOLDER --bridge $BRIDGE")

echo "== emulator wiring"
adb reverse "tcp:$PORT" "tcp:$PORT"
adb shell setprop debug.impala.tcp_card "127.0.0.1:$PORT"

echo "== CardLoginUiTest"
cd "$here"
./gradlew connectedTnetDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.payala.impala.demo.CardLoginUiTest \
  -Pandroid.testInstrumentationRunnerArguments.cardAccount="$HOLDER"
