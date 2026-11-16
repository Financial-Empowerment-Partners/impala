#!/usr/bin/env bash
# Re-record the issuance sessions of this directory: the reference issuance tool (impala-card tools/issue, on
# the Kotlin card SDK) setting up the real ImpalaApplet on jcardsim, captured by a logging proxy on the
# simulator's TCP framing. impalactl's tests replay them byte for byte (internal/card and internal/cli), so they
# are what keeps `impalactl card setup` and the reference tool the same ceremony.
#
# Re-record when the ceremony changes (a step, its order, a payload) or the applet's version does (the first
# answer of every session is GET_VERSION). Every value is test material: a throwaway KMK, PINs, account and
# issuer (--test-issuer needs no bridge). Card keys and challenges are random, so every recording is new bytes.
#
# Needs JDK 17 (JAVA17_HOME or /usr/libexec/java_home -v 17) and python3. Two free local ports per card.
# Usage: record.sh [out_dir]      (default: this directory)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE}"
CARD="$(cd "$HERE/../../../../impala-card" && pwd)"
KMK=000102030405060708090a0b0c0d0e0f; USER_PIN=4821; MASTER_PIN=31415926
ACCOUNT=6f1d9c52-0b7e-4c3a-9e15-2a4b8c7d6e90
if [ -n "${JAVA17_HOME:-}" ]; then export JAVA_HOME="$JAVA17_HOME"; else JAVA_HOME="$(/usr/libexec/java_home -v 17)"; export JAVA_HOME; fi
TMP="$(mktemp -d "${TMPDIR:-/tmp}/impala-record.XXXXXX")"
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; pkill -f "SimulatorApduServerKt --port 94[67][0-9] " 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# session <file stem> <sim port> <proxy port> <extra tool args...>: one run of the tool through the proxy
session() {
  local stem="$1" sim="$2" px="$3"; shift 3
  python3 "$HERE/record_proxy.py" "$px" "$sim" "$TMP/$stem.rec" & local pp=$!
  PIDS="$PIDS $pp"; sleep 1
  ( cd "$CARD" && IMPALA_ISSUE_KMK="$KMK" IMPALA_USER_PIN="$USER_PIN" IMPALA_MASTER_PIN="$MASTER_PIN" \
      ./gradlew -q :tools:issue:run --console=plain --args="--transport tcp:127.0.0.1:$px --account $ACCOUNT --test-issuer $*" ) > "$TMP/$stem.out" 2> "$TMP/$stem.err" \
    || { cat "$TMP/$stem.err" >&2; echo "the issuance tool failed for $stem" >&2; exit 1; }
  kill "$pp" 2>/dev/null || true; wait "$pp" 2>/dev/null || true
}

# card <name> <platform> <description> <currency> <initial counter> <sim port> <proxy port>
card() {
  local name="$1" platform="$2" desc="$3" currency="$4" counter="$5" sim="$6" px="$7" stem what
  port_open "$sim" && { echo "port $sim is in use" >&2; exit 1; }
  ( cd "$CARD" && ./gradlew -q :simulator:serve --args="--port $sim --platform $platform" > "$TMP/sim-$sim.log" 2>&1 & )
  local i=0; until port_open "$sim"; do i=$((i + 1)); [ "$i" -lt 180 ] || { cat "$TMP/sim-$sim.log" >&2; exit 1; }; sleep 1; done
  session "$name" "$sim" "$px" --currency "$currency" --initial-counter "$counter"
  session "$name-rerun" "$sim" "$px" --currency "$currency" --initial-counter "$counter"
  pkill -f "SimulatorApduServerKt --port $sim " 2>/dev/null || true
  for stem in "$name" "$name-rerun"; do
    if [ "$stem" = "$name" ]; then what="a blank, factory-installed card (ENFORCE, GP default SCP03 keys, not program-bound): the whole ceremony"
    else what="the same card again, already personalized: the no-op re-run (read-only)"; fi
    {
      cat <<HEAD
# A recorded card session, kept as a known-answer vector for impalactl's card setup.
# Recorded $(date -u +%Y-%m-%d) by record.sh through a logging TCP proxy between the reference issuance tool
# (impala-card tools/issue, on the Kotlin card SDK) and the real ImpalaApplet on jcardsim:
# hardware $desc.
# Session: $what.
# Lines: '> hex' is a command APDU exactly as sent, '< hex' the card's answer (data then SW1 SW2).
# The tool does not SELECT (the simulator's applet is already selected); a client that does adds one exchange.
#
# Everything here is test material: a throwaway KMK, PINs, account and issuer (--test-issuer).
# kmk=$KMK
# user_pin=$USER_PIN
# master_pin=$MASTER_PIN
# account=$ACCOUNT
# currency=$currency
# initial_counter=$counter
# transport_keys=GP default (40 41 .. 4F for ENC, MAC and DEK)
# The issuer's public key, the program id and the certificate are the ones the final
# GET_PERSONALIZATION (00 34) reports: bytes 2..18, 22..87 and 87..159 (zero-padded DER).
#
# What the tool printed (its record):
HEAD
      for k in card_id account_uuid program_id currency cert_id applet_version stellar_address status; do
        printf '# record.%s=%s\n' "$k" "$(sed -n "s/^$k=//p" "$TMP/$stem.out" | head -n1)"
      done
      echo "#"
      grep -E '^[<>] ' "$TMP/$stem.rec"
    } > "$OUT/issuance-$stem.txt"
    echo "wrote $OUT/issuance-$stem.txt ($(grep -c '^> ' "$OUT/issuance-$stem.txt") exchanges)" >&2
  done
}

mkdir -p "$OUT"
card jc305-soft jc305 "jc305 (a JavaCard 3.0.5 card), the default CAP with the software Ed25519 engine" XLM 0 9461 9471
card jc32-native jc32 "jc32 (a JavaCard 3.2 card), the native CAP on the platform's own EdDSA" USDC 7 9462 9472
echo "done: run 'go test ./...' in impalactl (the replays read these files)" >&2
