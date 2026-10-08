# Fleet compatibility testing with scardutil

[scardutil](https://github.com/Financial-Empowerment-Partners/scardutil) drives
GlobalPlatformPro/GPShell and raw PC/SC to install and exercise applets across
many card types at once. This directory holds what the Impala applet needs for
it; the worked scenario is in `docs/sep10-authentication.md` (Part B).

| File | Purpose |
|---|---|
| `impala-dispatch.md` | The plaintext dispatch sequence every card OS must answer identically (converted with `scardutil make-sequence`) |
| `impala-sim.cfg` | jcardsim-style cfg for the simulator target |
| `fleet.example.json` | A fleet: the simulator plus two readers (stack-of-cards `wait`) |
| `../scripts/vpcd-sim.sh` | The simulator target: the real `ImpalaApplet` on jcardsim served over vpcd (jcardsim's own `VSmartCard` cannot instantiate it; see `VpcdSimulator.kt`) |

```bash
# Offline: what the CAP declares (Java Card 3.0.5 target, API 1.6 imports, AIDs)
scardutil cap-info applet/build/ImpalaApplet.cap

# Author once, run everywhere
scardutil make-sequence scardutil/impala-dispatch.md -o /tmp/impala-dispatch.json --cap-dir applet/build

# Simulator target (no reader, no card): install/delete steps skip, the checks run
scardutil test-sequence /tmp/impala-dispatch.json --sim-cfg scardutil/impala-sim.cfg \
    --jcardsim "bash scripts/vpcd-sim.sh"

# One physical card: install, check, remove
scardutil test-sequence /tmp/impala-dispatch.json --cap-dir applet/build -r 0

# The fleet matrix (candidates in applet/build x targets in fleet.json), with reports
cd scardutil && scardutil evaluate ../applet/build --targets fleet.example.json \
    --sequence /tmp/impala-dispatch.json --cleanup --report-dir ../build/fleet-reports/

# Per-card evidence: readers + profile (JC version, SCP03, free memory) + triage
scardutil card-info --report-dir ../build/fleet-reports/<card-model>/ -r 0
```

**Boundary.** The applet implements SCP03 itself (CLA `84`, INS `50`/`82`/`70`–`73`),
not the GlobalPlatform ISD channel scardutil's `secure: true` steps use. So
PERSONALIZE, PROVISION_PIN and key rotation stay with the issuance tool
(`./gradlew :tools:issue:run --args="--transport pcsc …"`); scardutil owns
install, plaintext dispatch checks, profiling and the matrix. A `profile` that
lacks `SCP03` or Java Card ≥ 3.0.5 rules a card out before issuance is tried.
