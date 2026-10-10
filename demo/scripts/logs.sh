#!/usr/bin/env bash
# Tail logs. Usage: scripts/logs.sh [service...]   (default: impala-bridge; `simulator` and `emulator` tail the host lanes)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
if [ $# -eq 0 ]; then set -- impala-bridge; fi
case "$1" in
  simulator) exec tail -f "$STATE_DIR/simulator/server.log" ;;
  emulator) exec tail -f "$STATE_DIR/emulator.log" ;;
esac
engine_ready
compose logs -f "$@"
