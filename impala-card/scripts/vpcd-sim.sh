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
#   impala.ed25519=soft|native|none   which CAP variant's Ed25519 engine the
#                                     card has (default soft, as the default CAP)
#   impala.platform=<card model>  the simulated hardware: jc305 (JavaCard 3.0.5),
#                                 jc32 (JavaCard 3.2) and their variants; it also
#                                 picks the CAP when impala.ed25519 is not set.
#                                 A CAP the hardware does not load (native on a
#                                 JavaCard 3.0.5 card) ends this script with exit 3,
#                                 as a card's loader refuses it.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cp_file="$here/simulator/build/vpcd-classpath.txt"

# The classpath file is a build output, cached between runs. It is wrong as
# soon as the simulator's module graph changes (a new module or dependency on
# its runtime path), so a build script newer than the file rebuilds it, and so
# does an entry that no longer exists (a cleaned build directory).
stale=0
if [ ! -f "$cp_file" ]; then
  stale=1
else
  for f in "$here/settings.gradle.kts" "$here/gradle/libs.versions.toml" \
           "$here/simulator/build.gradle.kts" "$here/applet/build.gradle.kts" \
           "$here/sdk/build.gradle.kts" "$here/jcardsim-jc31/build.gradle.kts"; do
    if [ -f "$f" ] && [ "$f" -nt "$cp_file" ]; then stale=1; fi
  done
  if [ "$stale" = 0 ]; then
    # The file has no trailing newline, so read reports end-of-file (status 1)
    # after filling the array.
    IFS=: read -r -a entries < "$cp_file" || true
    for e in "${entries[@]}"; do
      # Resource and class directories of a module without that kind of source
      # are legitimately absent; a missing jar is not.
      case "$e" in *.jar) [ -f "$e" ] || stale=1 ;; esac
    done
  fi
fi
if [ "$stale" = 1 ]; then
  (cd "$here" && ./gradlew -q :simulator:vpcdClasspath) >&2
  # An up-to-date task leaves the file untouched: mark it checked.
  touch "$cp_file"
fi
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/}java"
exec "$JAVA_BIN" -cp "$(cat "$cp_file")" com.impala.simulator.VpcdSimulatorKt "$@"
