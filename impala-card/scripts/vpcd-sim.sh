#!/usr/bin/env bash
# Serve one simulated Impala card to scardutil over the vsmartcard (vpcd)
# protocol: the real ImpalaApplet on jcardsim, instantiated with optional
# install parameters. scardutil's managed mode runs this with the generated
# jcardsim .cfg (which carries the vpcd host/port) as the last argument:
#
#   scardutil test-sequence seq.json --sim-cfg impala.cfg \
#       --jcardsim "bash /path/to/impala-card/scripts/vpcd-sim.sh"
#
# or as a fleet target: {"name":"jcardsim","sim":true,"cfg":"impala.cfg",
#                        "jcardsim":"bash /path/to/impala-card/scripts/vpcd-sim.sh"}
#
# Optional cfg keys (ours, ignored by jcardsim):
#   impala.install.params=<hex>   applet install TLV (see docs/apdu.md)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cp_file="$here/simulator/build/vpcd-classpath.txt"
if [ ! -f "$cp_file" ]; then
  (cd "$here" && ./gradlew -q :simulator:vpcdClasspath) >&2
fi
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/}java"
exec "$JAVA_BIN" -cp "$(cat "$cp_file")" com.impala.simulator.VpcdSimulatorKt "$@"
