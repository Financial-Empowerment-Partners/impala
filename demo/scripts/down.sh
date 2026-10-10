#!/usr/bin/env bash
# Stop the stack, keep the data volumes. NOTE: OpenBao (dev mode) forgets its Transit key when it
# restarts, so after `down` + `up` the custodial seeds and the card issuer key are unusable ->
# use scripts/reset.sh for a clean slate. Also stops the host-side simulator and emulator.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env; engine_ready
"$DEMO_DIR/scripts/simulator.sh" down 2>/dev/null || true
"$DEMO_DIR/scripts/emulator.sh" down 2>/dev/null || true
compose down --remove-orphans
warn "volumes kept. OpenBao dev mode is in-memory: the bridge's sealed seeds will NOT work after the next up; run scripts/reset.sh before scripts/up.sh."
