#!/usr/bin/env bash
# =============================================================================
# testnet-smoke.sh — opt-in end-to-end smoke test against the REAL Stellar
# testnet (Friendbot + Horizon at https://horizon-testnet.stellar.org).
#
# This script talks to live network services and is NEVER run in CI — it is a
# manual, opt-in check for a developer machine, proving the wallet works end
# to end: fund, create, send, history (text/JSON/CSV/summary), tx lookup, and
# (best-effort) --follow streaming.
#
# Requires: go, jq, curl.
#
# Usage:
#   scripts/testnet-smoke.sh [--record]
#
#   --record   Additionally save the raw Horizon payments page for account B
#              to internal/cli/testdata/live_payments_page.json
#              (pretty-printed) for use as a recorded fixture.
#
# Assertions check INVARIANTS (direction, amount, memo, counterparty), never
# exact bytes of the whole output, so cosmetic changes do not break the script.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

HORIZON="https://horizon-testnet.stellar.org"
NET=(--network testnet)

RECORD=0
for arg in "$@"; do
  case "$arg" in
    --record) RECORD=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

command -v jq   >/dev/null || { echo "error: jq is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 2; }

PASS=0
FAIL=0
note() { printf '\n== %s\n' "$*"; }
ok()   { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }

# assert_contains <desc> <haystack> <needle>
assert_contains() {
  if grep -qF -- "$3" <<<"$2"; then
    ok "$1 contains '$3'"
  else
    bad "$1 does not contain '$3'"
  fi
}

# assert_eq <desc> <got> <want>
assert_eq() {
  if [ "$2" = "$3" ]; then
    ok "$1 == '$3'"
  else
    bad "$1: got '$2', want '$3'"
  fi
}

FOLLOW_PID=""
cleanup() {
  if [ -n "$FOLLOW_PID" ]; then kill "$FOLLOW_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

note "building ./lumencli"
go build -o lumencli .

note "generating two keypairs (offline)"
OUT_A="$(./lumencli account new)"
ADDR_A="$(grep -Eo 'G[A-Z2-7]{55}' <<<"$OUT_A" | head -n1 || true)"
SEED_A="$(grep -Eo 'S[A-Z2-7]{55}' <<<"$OUT_A" | head -n1 || true)"
OUT_B="$(./lumencli account new)"
ADDR_B="$(grep -Eo 'G[A-Z2-7]{55}' <<<"$OUT_B" | head -n1 || true)"
SEED_B="$(grep -Eo 'S[A-Z2-7]{55}' <<<"$OUT_B" | head -n1 || true)"
if [ -z "$ADDR_A" ] || [ -z "$SEED_A" ] || [ -z "$ADDR_B" ] || [ -z "$SEED_B" ]; then
  echo "error: could not parse keypairs from 'account new' output" >&2
  exit 1
fi
echo "A: $ADDR_A"
echo "B: $ADDR_B"

note "funding A via Friendbot"
# Friendbot's edge has been seen serving a certificate chain Go's x509 parser
# rejects ("trailing data") while curl accepts it; fall back to curl so a
# Friendbot-side TLS quirk doesn't scrub the whole smoke run.
if ! ./lumencli "${NET[@]}" account fund --address "$ADDR_A"; then
  echo "WARNING: 'account fund' failed; falling back to curl against Friendbot" >&2
  curl -fsS -o /dev/null "https://friendbot.stellar.org/?addr=$ADDR_A"
fi

note "A creates B with 100 XLM"
LUMEN_SECRET="$SEED_A" ./lumencli "${NET[@]}" account create --dest "$ADDR_B" --amount 100

note "A sends B 25 XLM with an id memo"
LUMEN_SECRET="$SEED_A" ./lumencli "${NET[@]}" send \
  --to "$ADDR_B" --amount 25 --memo-type id --memo 424242

note "waiting for the payment to appear in B's history"
HIST=""
for _ in $(seq 1 30); do
  HIST="$(./lumencli "${NET[@]}" history "$ADDR_B" 2>/dev/null || true)"
  if grep -q '25\.0000000 XLM' <<<"$HIST"; then break; fi
  sleep 2
done
if ! grep -q '25\.0000000 XLM' <<<"$HIST"; then
  echo "error: payment never appeared in B's history after ~60s" >&2
  echo "RESULT: FAIL"
  exit 1
fi

note "invariants: history text"
assert_contains "history text" "$HIST" "received  25.0000000 XLM"
assert_contains "history text" "$HIST" "id 424242"

note "invariants: history --json (first line = newest entry = the payment)"
JSON_ALL="$(./lumencli "${NET[@]}" history "$ADDR_B" --json)"
JSON_FIRST="$(head -n1 <<<"$JSON_ALL")"
if jq -e . >/dev/null 2>&1 <<<"$JSON_FIRST"; then
  ok "first --json line parses as JSON"
else
  bad "first --json line does not parse as JSON: $JSON_FIRST"
fi
assert_eq "json .direction"    "$(jq -r '.direction'    <<<"$JSON_FIRST")" "received"
assert_eq "json .amount"       "$(jq -r '.amount'       <<<"$JSON_FIRST")" "25.0000000"
assert_eq "json .counterparty" "$(jq -r '.counterparty' <<<"$JSON_FIRST")" "$ADDR_A"
assert_eq "json .memo.value"   "$(jq -r '.memo.value'   <<<"$JSON_FIRST")" "424242"

note "invariants: history --csv"
CSV_ALL="$(./lumencli "${NET[@]}" history "$ADDR_B" --csv)"
CSV_HEAD="$(head -n1 <<<"$CSV_ALL")"
if [ -n "$CSV_HEAD" ] && grep -q ',' <<<"$CSV_HEAD"; then
  ok "--csv output has a header row ($CSV_HEAD)"
else
  bad "--csv output missing a header row"
fi

note "invariants: history --summary --json (create 100 + payment 25)"
SUMMARY="$(./lumencli "${NET[@]}" history "$ADDR_B" --summary --json)"
assert_eq "summary .assets[0].received" \
  "$(jq -r '.assets[0].received' <<<"$SUMMARY")" "125.0000000"

note "invariants: tx <hash of the payment>"
TX_HASH="$(jq -r '.tx // .tx_hash // .hash // empty' <<<"$JSON_FIRST")"
if [ -z "$TX_HASH" ]; then
  # Fall back to the first 64-hex string in the text history; the listing is
  # newest-first, so that is the payment's transaction hash.
  TX_HASH="$(grep -Eo '[0-9a-f]{64}' <<<"$HIST" | head -n1 || true)"
fi
if [ -n "$TX_HASH" ]; then
  TX_OUT="$(./lumencli "${NET[@]}" tx "$TX_HASH")"
  assert_contains "tx output" "$TX_OUT" "succeeded"
  assert_contains "tx output" "$TX_OUT" "424242"
else
  bad "could not determine the payment's tx hash"
fi

# --follow is BEST-EFFORT: streams can be flaky, so a miss prints a WARNING
# and the script continues — it never fails on this leg.
note "best-effort: history --follow streams a new payment"
FOLLOW_OUT="$(mktemp)"
./lumencli "${NET[@]}" history "$ADDR_B" --follow >"$FOLLOW_OUT" 2>&1 &
FOLLOW_PID=$!
sleep 3
LUMEN_SECRET="$SEED_A" ./lumencli "${NET[@]}" send --to "$ADDR_B" --amount 1 || true
FOUND=0
for _ in $(seq 1 25); do
  if grep -q ' 1\.0000000 XLM' "$FOLLOW_OUT"; then FOUND=1; break; fi
  sleep 1
done
kill "$FOLLOW_PID" 2>/dev/null || true
wait "$FOLLOW_PID" 2>/dev/null || true
FOLLOW_PID=""
if [ "$FOUND" = 1 ]; then
  ok "--follow streamed the 1 XLM payment"
else
  echo "WARNING: --follow did not show the 1 XLM payment within ~25s;" \
       "continuing (stream flakiness never fails this script)"
fi
rm -f "$FOLLOW_OUT"

if [ "$RECORD" = 1 ]; then
  note "recording raw Horizon payments page for B"
  mkdir -p internal/cli/testdata
  # Write to a temp file and move into place only on success: a direct
  # redirect truncates the committed fixture the moment the pipeline starts,
  # so a failed curl would leave a 0-byte file and break go test.
  RECORD_TMP="$(mktemp)"
  if curl -fsSL \
    "$HORIZON/accounts/$ADDR_B/payments?join=transactions&limit=200&order=desc" \
    | jq . >"$RECORD_TMP"; then
    mv "$RECORD_TMP" internal/cli/testdata/live_payments_page.json
    echo "wrote internal/cli/testdata/live_payments_page.json"
  else
    rm -f "$RECORD_TMP"
    bad "--record failed; the committed fixture was left untouched"
  fi
fi

note "summary"
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
