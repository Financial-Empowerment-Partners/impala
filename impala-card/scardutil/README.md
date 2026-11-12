# Fleet compatibility testing with scardutil

[scardutil](https://github.com/Financial-Empowerment-Partners/scardutil) drives
GlobalPlatformPro/GPShell and raw PC/SC to install and exercise applets across
many card types at once. This directory holds what the Impala applet needs for
it; the worked scenario is in `docs/sep10-authentication.md` (Part B).

| File | Purpose |
|---|---|
| `impala-dispatch.md` | The plaintext dispatch sequence every card OS must answer identically (converted with `scardutil make-sequence`) |
| `impala-sim.cfg` | jcardsim-style cfg for the simulator target. Optional keys of ours: `impala.install.params`, `impala.ed25519=soft\|native\|none` (the CAP variant the simulated card was loaded with) and `impala.platform=<card model>` (its hardware) |
| `impala-sim-jc305.cfg`, `impala-sim-jc32.cfg` | The two hardware classes as simulator targets: the default CAP on a JavaCard 3.0.5 card, the native CAP on a JavaCard 3.2 card |
| `fleet.example.json` | A fleet: those two simulated cards plus two readers (stack-of-cards `wait`) |
| `../scripts/vpcd-sim.sh` | The simulator target: the real `ImpalaApplet` on jcardsim served over vpcd (jcardsim's own `VSmartCard` cannot instantiate it; see `VpcdSimulator.kt`) |

```bash
# Offline: what the CAP declares (Java Card 3.0.5 target, API 1.6 imports, AIDs)
scardutil cap-info applet/build/ImpalaApplet.cap

# Author once, run everywhere
scardutil make-sequence scardutil/impala-dispatch.md -o /tmp/impala-dispatch.json --cap-dir applet/build

# Simulator target (no reader, no card): install/delete steps skip, the checks run
scardutil test-sequence /tmp/impala-dispatch.json --sim-cfg scardutil/impala-sim.cfg \
    --jcardsim "bash scripts/vpcd-sim.sh"

# The same on each simulated hardware class: a JavaCard 3.0.5 card, a JavaCard 3.2 card
scardutil test-sequence /tmp/impala-dispatch.json --sim-cfg scardutil/impala-sim-jc305.cfg \
    --jcardsim "bash scripts/vpcd-sim.sh"
scardutil test-sequence /tmp/impala-dispatch.json --sim-cfg scardutil/impala-sim-jc32.cfg \
    --jcardsim "bash scripts/vpcd-sim.sh"

# One physical card: install, check, remove
scardutil test-sequence /tmp/impala-dispatch.json --cap-dir applet/build -r 0

# The fleet matrix (candidates x targets in fleet.json), with reports. The candidates
# directory holds the CAP under test (see "Simulated hardware" for why one at a time
# when the fleet has simulator targets)
cd scardutil && mkdir -p ../build/candidates && cp ../applet/build/ImpalaApplet.cap ../build/candidates/
scardutil evaluate ../build/candidates --targets fleet.example.json \
    --sequence /tmp/impala-dispatch.json --cleanup --report-dir ../build/fleet-reports/

# Per-card evidence: readers + profile (JC version, SCP03, free memory) + triage
scardutil card-info --report-dir ../build/fleet-reports/<card-model>/ -r 0
```

**CAP variants.** `applet/build` holds one CAP per Ed25519 engine
(`ImpalaApplet.cap` = soft, `ImpalaApplet-native.cap`, `ImpalaApplet-none.cap`;
see the card README). The dispatch sequence installs the default one and
checks, after INITIALIZE, that the card made its Stellar key
(`GET_PERSONALIZATION` starts `01 89`, `GET_STELLAR_KEY` answers `9000`). A
card OS that answers `01 09` / `623C` there cannot run that CAP's engine and
is a legacy card (`SIGN_AUTH` only): record it. In an `evaluate` matrix over
the whole directory the same two answers are expected for the `none` CAP, and
the `native` CAP loads only on JavaCard 3.1 cards. What each CAP imports and
which optional algorithms its engine asks the card for (the list a fleet
finding is read against) is in the card README, "Platform dependencies:
JavaCard 3.0.5, 3.1 and 3.2".

**Simulated hardware.** A simulator target is a card that already has its
CAP, on hardware its cfg names (`impala.platform`, a card model of
[`../jcardsim-jc31/README.md`](../jcardsim-jc31/README.md); `impala.ed25519`
for a CAP other than the one an operator would load on it). The dispatch
sequence passes unchanged on both hardware classes, and one answer tells them
apart: the first byte `GET_STELLAR_KEY` returns after INITIALIZE, the engine
behind the card's Stellar key.

| Target | Card | Steps 19 and 20 after INITIALIZE | Run of 2026-11-12 |
|---|---|---|---|
| `impala-sim-jc305.cfg` | default CAP on a JavaCard 3.0.5 card | `0189`, `9000` with data starting `01` (software engine) | 21 passed, 0 failed, 3 skipped |
| `impala-sim-jc32.cfg` | native CAP on a JavaCard 3.2 card | `0189`, `9000` with data starting `02` (platform EdDSA) | 21 passed, 0 failed, 3 skipped |
| `impala.platform=jc32-per-curve` | native CAP on a 3.2 card with Ed25519 under the 3.2 cipher only | the same as `jc32` | 21 passed, 0 failed, 3 skipped |
| `impala.platform=jc305-no-xy` | default CAP on a 3.0.5 card without the engine's ECDH | `0109`, `623C`: a legacy card | step 19 fails ("expected data containing 0189"), which is the fleet finding |
| `impala.platform=jc305` with `impala.ed25519=native` | a CAP the hardware does not load | none: the simulator exits, naming what the CAP imports and what the card has | "the simulator exited before connecting" |

The lesser card models exist so that a finding on a physical card can be
recognised: a card that answers like `jc305-no-xy` cannot run the engine of
`ImpalaApplet.cap`, and the record of that run is what
`docs/physical-evidence/` wants.

Two things a simulator target is not. It does not load the candidate CAP:
scardutil skips install and delete on a raw transport, and the card is
whatever its cfg says. And it is one card for the whole run: in an `evaluate`
over several CAP files the simulated card stays as the first candidate left
it (initialized), so only the first candidate's cell means anything on a
simulator target. Give `evaluate` a directory with the one CAP a simulator
target stands for, or use `test-sequence` per target as above.

**Boundary.** The applet implements SCP03 itself (CLA `84`, INS `50`/`82`/`70`–`73`),
not the GlobalPlatform ISD channel scardutil's `secure: true` steps use. So
PERSONALIZE, PROVISION_PIN and key rotation stay with the issuance tool
(`./gradlew :tools:issue:run --args="--transport pcsc …"`); scardutil owns
install, plaintext dispatch checks, profiling and the matrix. A `profile` that
lacks `SCP03` or Java Card ≥ 3.0.5 rules a card out before issuance is tried.
