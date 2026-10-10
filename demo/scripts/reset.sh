#!/usr/bin/env bash
# Destroy the stack including volumes and the recorded demo state (keeps .env, the demo keys and the
# testnet tx id log: those transactions stay valid on testnet). Required after any OpenBao restart
# (in-memory dev mode) and the way to pick up a fresh schema.
# Usage: scripts/reset.sh [--yes]   (--yes skips the confirmation; required when stdin is not a terminal)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
if [ "${1:-}" != "--yes" ]; then
  printf 'This deletes the impala database, the Payala stub ledger, every sealed seed and the recorded demo state. Continue? [y/N] ' >&2
  read -r ans || die "aborted (no confirmation on stdin; use --yes)"
  case "$ans" in y|Y|yes) ;; *) die "aborted" ;; esac
fi
"$DEMO_DIR/scripts/simulator.sh" down 2>/dev/null || true
"$DEMO_DIR/scripts/emulator.sh" down 2>/dev/null || true
compose down -v --remove-orphans
rm -f "$STATE_DIR/impala.env" "$STATE_DIR/migrate.log" "$STATE_DIR/report.md" "$STATE_DIR/report.json"
rm -rf "$RECORDS_DIR" "$ARTIFACTS_DIR" "$STATE_DIR/relay" "$STATE_DIR/simulator" "$STATE_DIR/impalactl"
mkdir -p "$RECORDS_DIR" "$ARTIFACTS_DIR"
ok "reset done (kept: .env, state/keys, state/testnet-txids.tsv, state/timings.tsv). Next: scripts/up.sh && scripts/seed.sh"
