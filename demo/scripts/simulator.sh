#!/usr/bin/env bash
# The JavaCard simulator lane: the real ImpalaApplet on jcardsim, served over a length-prefixed TCP
# socket on 127.0.0.1:$SIM_PORT by impala-card's SimulatorApduServer (host JVM, Gradle launched on JDK 17).
# The card lives in that process: `down` destroys it (scenario 05 issues a fresh one on the next `up`).
#
# The card is a CAP on hardware, and both are chosen here: DEMO_CARD_PLATFORM names the simulated hardware
# (jc305 = a JavaCard 3.0.5 card, the default; jc32 = a JavaCard 3.2 card; `models` lists the rest) and
# DEMO_CARD_ED25519 the CAP variant (empty: the one an operator would load on that hardware). A CAP the
# hardware does not load (native on a JavaCard 3.0.5 card) is refused at `up`, as a card's loader refuses it.
# Usage: scripts/simulator.sh up|down|restart|status|probe|stellar|hardware|models
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
SIM_DIR="$STATE_DIR/simulator"; PID_FILE="$SIM_DIR/pid"; LOG="$SIM_DIR/server.log"; HW_FILE="$SIM_DIR/hardware"
mkdir -p "$SIM_DIR"
case "$DEMO_CARD_PLATFORM" in ''|*[!a-z0-9-]*) die "DEMO_CARD_PLATFORM must be a card model name such as jc305 or jc32, not '$DEMO_CARD_PLATFORM'" ;; esac
case "$DEMO_CARD_ED25519" in ''|soft|native|none) ;; *) die "DEMO_CARD_ED25519 must be soft, native, none or empty, not '$DEMO_CARD_ED25519'" ;; esac

# What the running simulator serves, as the server itself reported it at start (platform<TAB>level<TAB>cap).
hw_platform() { cut -f1 "$HW_FILE" 2>/dev/null || true; }
hw_level() { cut -f2 "$HW_FILE" 2>/dev/null || true; }
hw_cap() { cut -f3 "$HW_FILE" 2>/dev/null || true; }
hw_line() { if [ -s "$HW_FILE" ]; then printf '%s (JavaCard %s), CAP %s' "$(hw_platform)" "$(hw_level)" "$(hw_cap)"; else printf 'hardware not recorded'; fi; }

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

# stellar: the card's Stellar key as GET_STELLAR_KEY reports it: "<engine> <public key hex>", or "none" for a
# card without one (a blank card, a legacy card). The engine is the first byte: 01 soft, 02 native.
stellar() {
  python3 - "$SIM_PORT" <<'EOF'
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
def apdu(h):
    b = bytes.fromhex(h); s.sendall(struct.pack(">H", len(b)) + b)
    n = struct.unpack(">H", s.recv(2))[0]; r = b""
    while len(r) < n: r += s.recv(n - len(r))
    return r.hex()
apdu("00A404000A0102030405060708010200")
r = apdu("0037000000")
s.close()
if r.endswith("623c"):
    print("none")
elif r.endswith("9000") and len(r) >= 70:
    print("%s %s" % ({"01": "soft", "02": "native"}.get(r[0:2], "engine-" + r[0:2]), r[2:66]))
else:
    print("unexpected " + r); sys.exit(1)
EOF
}

up() {
  local want_cap="$DEMO_CARD_ED25519"
  if port_open "$SIM_PORT"; then
    [ -n "$(sim_pid)" ] || die "port $SIM_PORT is busy but no simulator process is ours (another server? change SIM_PORT in .env)"
    # A running simulator IS a card: it cannot become another one. Say so instead of handing a scenario the wrong hardware.
    if [ -s "$HW_FILE" ] && { [ "$(hw_platform)" != "$DEMO_CARD_PLATFORM" ] || { [ -n "$want_cap" ] && [ "$(hw_cap)" != "$want_cap" ]; }; }; then
      die "the running simulator serves $(hw_line), not DEMO_CARD_PLATFORM=$DEMO_CARD_PLATFORM${want_cap:+ with the $want_cap CAP}: scripts/simulator.sh restart (the card it holds is lost; scenario 05 issues a new one)"
    fi
    ok "simulator already serving on 127.0.0.1:$SIM_PORT (pid $(sim_pid)): $(probe); $(hw_line)"; return 0
  fi
  jdk17_home >/dev/null || die "JDK 17 not found (JAVA17_HOME): the simulator is launched through Gradle"
  info "starting the jcardsim ImpalaApplet server on 127.0.0.1:$SIM_PORT, hardware $DEMO_CARD_PLATFORM${want_cap:+, CAP $want_cap} (impala-card :simulator:serve, JDK 17)"
  : > "$LOG"; rm -f "$HW_FILE"
  ( gradle_card -q :simulator:serve --args="--port $SIM_PORT --platform $DEMO_CARD_PLATFORM${want_cap:+ --ed25519 $want_cap}" >> "$LOG" 2>&1 & )
  # Wait for the port, but not for a server that has already said it will never listen: an unknown card model,
  # or a CAP this hardware does not load.
  local i=0
  until port_open "$SIM_PORT"; do
    if grep -Eq 'does not load on a JavaCard|unknown card platform|^usage: serve|BUILD FAILED' "$LOG" 2>/dev/null; then
      # The server's own sentence when it has one (it names the fix); the end of the log otherwise.
      grep -E 'does not load on a JavaCard|unknown card platform' "$LOG" | head -n 2 | sed 's/^/  /' >&2 || true
      grep -Eq 'does not load on a JavaCard|unknown card platform' "$LOG" || tail -n 12 "$LOG" | sed 's/^/  /' >&2
      die "the simulator refused to start (scripts/simulator.sh models lists the card models; log: $LOG)"
    fi
    i=$((i + 1)); [ "$i" -lt 240 ] || { tail -n 20 "$LOG" >&2; die "simulator did not start within 240s (see $LOG)"; }
    sleep 1
  done
  sleep 1
  sim_pid > "$PID_FILE"
  # The server says what it is serving; keep that for status, the scenarios and the report.
  printf '%s\t%s\t%s\n' "$(sed -n 's/^hardware: \([a-z0-9-]*\), JavaCard \([0-9.]*\).*/\1/p' "$LOG" | head -n1)" \
    "$(sed -n 's/^hardware: \([a-z0-9-]*\), JavaCard \([0-9.]*\).*/\2/p' "$LOG" | head -n1)" \
    "$(sed -n 's/^CAP: .* (ed25519 \([a-z]*\)).*/\1/p' "$LOG" | head -n1)" > "$HW_FILE"
  [ -n "$(hw_platform)" ] && [ -n "$(hw_cap)" ] || die "the simulator did not say which hardware it serves (see $LOG): is impala-card built from this checkout?"
  ok "simulator serving on 127.0.0.1:$SIM_PORT (pid $(cat "$PID_FILE")): $(probe); $(hw_line)"
  log "  issue a card: scripts/scenario-05-card-issue.sh   emulator reaches it through adb reverse tcp:$SIM_PORT"
}

down() {
  local p; p="$(sim_pid)"
  if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; sleep 1; pkill -f 'com.impala.simulator.SimulatorApduServerKt' 2>/dev/null || true; ok "simulator stopped (pid $p); the simulated card is gone"
  else log "  simulator not running"; fi
  rm -f "$PID_FILE" "$HW_FILE"
}

case "${1:-status}" in
  up) up ;;
  down) down ;;
  restart) down; up ;;
  status)
    if port_open "$SIM_PORT"; then ok "simulator listening on 127.0.0.1:$SIM_PORT (pid $(sim_pid)): $(probe 2>&1); $(hw_line)"; else log "  simulator not running (scripts/simulator.sh up)"; exit 1; fi
    ;;
  probe) probe ;;
  stellar) port_open "$SIM_PORT" || die "simulator not running"; stellar ;;
  # hardware: "platform<TAB>JavaCard level<TAB>CAP variant" of the running simulator (for scripts)
  hardware) port_open "$SIM_PORT" && [ -s "$HW_FILE" ] || die "simulator not running, or it did not record its hardware"; cat "$HW_FILE" ;;
  models) jdk17_home >/dev/null || die "JDK 17 not found (JAVA17_HOME)"; gradle_card -q :simulator:serve --args="--help" 2>&1 | sed -n '/--platform/,$p' ;;
  *) die "usage: $0 up|down|restart|status|probe|stellar|hardware|models" ;;
esac
