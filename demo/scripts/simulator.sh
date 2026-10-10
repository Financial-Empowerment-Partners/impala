#!/usr/bin/env bash
# The JavaCard simulator lane: the real ImpalaApplet on jcardsim, served over a length-prefixed TCP
# socket on 127.0.0.1:$SIM_PORT by impala-card's SimulatorApduServer (host JVM, Gradle launched on JDK 17).
# The card lives in that process: `down` destroys it (scenario 05 issues a fresh one on the next `up`).
# Usage: scripts/simulator.sh up|down|status|probe
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
SIM_DIR="$STATE_DIR/simulator"; PID_FILE="$SIM_DIR/pid"; LOG="$SIM_DIR/server.log"
mkdir -p "$SIM_DIR"

sim_pid() { pgrep -f "com.impala.simulator.SimulatorApduServerKt --port $SIM_PORT" 2>/dev/null | head -n1 || true; }

# probe: SELECT the applet and read GET_VERSION over the TCP framing (python3 for the binary I/O)
probe() {
  command -v python3 >/dev/null 2>&1 || { port_open "$SIM_PORT" && echo "listening (python3 missing: no APDU probe)"; return 0; }
  python3 - "$SIM_PORT" <<'EOF'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
def apdu(h):
    b = bytes.fromhex(h); s.sendall(struct.pack(">H", len(b)) + b)
    n = struct.unpack(">H", s.recv(2))[0]; r = b""
    while len(r) < n: r += s.recv(n - len(r))
    return r.hex()
sel = apdu("00A404000A0102030405060708010200")
ver = apdu("0064000000")
s.close()
if not sel.endswith("9000") or not ver.endswith("9000"):
    print("select=%s get_version=%s" % (sel, ver)); sys.exit(1)
print("applet %d.%d (GET_VERSION %s)" % (int(ver[0:4], 16), int(ver[4:8], 16), ver))
EOF
}

case "${1:-status}" in
  up)
    if port_open "$SIM_PORT"; then
      if [ -n "$(sim_pid)" ]; then ok "simulator already serving on 127.0.0.1:$SIM_PORT (pid $(sim_pid)): $(probe)"; exit 0; fi
      die "port $SIM_PORT is busy but no simulator process is ours (another server? change SIM_PORT in .env)"
    fi
    jdk17_home >/dev/null || die "JDK 17 not found (JAVA17_HOME): the simulator is launched through Gradle"
    info "starting the jcardsim ImpalaApplet server on 127.0.0.1:$SIM_PORT (impala-card :simulator:serve, JDK 17)"
    : > "$LOG"
    ( gradle_card -q :simulator:serve --args="--port $SIM_PORT" >> "$LOG" 2>&1 & )
    if ! wait_port "$SIM_PORT" 240 1; then tail -n 20 "$LOG" >&2; die "simulator did not start within 240s (see $LOG)"; fi
    sleep 1
    sim_pid > "$PID_FILE"
    ok "simulator serving on 127.0.0.1:$SIM_PORT (pid $(cat "$PID_FILE")): $(probe)"
    log "  issue a card: scripts/scenario-05-card-issue.sh   emulator reaches it through adb reverse tcp:$SIM_PORT"
    ;;
  down)
    p="$(sim_pid)"
    if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; sleep 1; pkill -f 'com.impala.simulator.SimulatorApduServerKt' 2>/dev/null || true; ok "simulator stopped (pid $p); the simulated card is gone"
    else log "  simulator not running"; fi
    rm -f "$PID_FILE"
    ;;
  status)
    if port_open "$SIM_PORT"; then ok "simulator listening on 127.0.0.1:$SIM_PORT (pid $(sim_pid)): $(probe 2>&1)"; else log "  simulator not running (scripts/simulator.sh up)"; exit 1; fi
    ;;
  probe) probe ;;
  *) die "usage: $0 up|down|status|probe" ;;
esac
