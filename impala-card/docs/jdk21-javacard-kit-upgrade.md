# Plan — JDK 21 LTS and Java Card kit upgrade (not yet implemented)

**Status:** planned, not started. impala-card builds on **JDK 17** today and
nothing in this document is implemented. It records what moving to JDK 21 LTS
requires so the work can be picked up later without re-discovery.

## Why JDK 17 today

The CAP is built by the vendored ant-javacard task
(`applet/libs/ant-javacard-v26.05.15.jar`), which runs **inside the Gradle
JVM**, so the JDK that launches Gradle is the JDK that builds the CAP. The
applet targets Java Card **3.0.5** (`targetsdk="3.0.5"` in `applet/build.xml`)
and is converted with the vendored **Java Card 3.1.0** kit
(`sdk.build = libs/sdks/jc310b43_kit`).

ant-javacard ties the JDK to the kit version. Observed on 2026-10-05 with
`./gradlew :applet:buildJavacard`:

| Gradle JDK | Kit | Result |
|---|---|---|
| 17 | jc310b43 | builds (current) |
| 21.0.11 LTS | jc310b43 | refused: `JavaCard kit v25.0+ required for JDK 21. Use JDK 17 or upgrade to v26.0.` |
| 26.0.1 | jc310b43 | refused with the same message for JDK 26; ant-javacard also asks for an LTS JDK (8, 11, 17, 21) |

ant-javacard recommends `jc320v26.0_kit`. The newest kit vendored in
`applet/libs/sdks/` is `jc320v24.0_kit`, which is **too old** for JDK 21.

**So JDK 21 is blocked by the Java Card kit, not by the code.** Target JDK 21
(LTS), not the newest JDK: ant-javacard itself warns on non-LTS releases.

## What pins JDK 17 today

| Where | Pin |
|---|---|
| `applet/build.gradle.kts`, `sdk/build.gradle.kts`, `simulator/build.gradle.kts`, `tools/issue/build.gradle.kts` | `jvmToolchain(17)` |
| `applet/build.xml` | `sdk.build = libs/sdks/jc310b43_kit` (and the `jc305u4_kit` build used for the 3.0.3 target) |
| `.github/workflows/impala-card.yml` | `setup-java` `java-version: '17'` in every job (test, CAP build testnet/live, publish, release) |
| `.github/workflows/impala-android.yml` | `java-version: '17'` in the assemble and instrumented jobs; the unit-test and card-e2e jobs already launch on 21 (they never build the CAP) |
| `README.md` "Toolchain: JDK 17", `DEVELOPMENT.md` JDK row, root `CLAUDE.md` | documentation of the above |

impala-lib and the Android demo already compile and test on a JDK 21 toolchain
(Robolectric needs it) with JVM 17 bytecode; they are not affected.

## Plan

Do it on a branch, in this order. Each step has its own exit check.

### 1. Vendor the Java Card 3.2 kit (v26.0)

- Obtain `jc320v26.0_kit` from the same source as the other kits (see
  `applet/libs/sdks/README.md`), add it under `applet/libs/sdks/`, and record
  its provenance and SHA-256 the way `applet/libs/README.md` does for the tool
  jars.
- Confirm the Oracle Java Card Development Kit licence terms allow vendoring it
  in this repository, as for the existing kits.
- Check whether a newer ant-javacard release is required or recommended for
  kit v26.0 (currently v26.05.15). If it is updated, re-pin its SHA-256 too.

**Exit:** the kit and its provenance are committed; nothing else changes yet.

### 2. Build the CAP with the new kit, still on JDK 17

- Point `sdk.build` at `libs/sdks/jc320v26.0_kit` and keep
  `targetsdk="3.0.5"`, so the CAP still installs on 3.0.5 cards.
- Decide what happens to the secondary `jc305u4_kit` → 3.0.3 target in
  `build.xml` (keep, move to the new kit, or drop it if nothing ships it).
- Run `./gradlew :applet:buildJavacard` (verify=true) for the testnet AIDs and,
  with `-Papplet.aid=… -Papplet.aid.app=…`, for the live AIDs.

**Exit:** both CAPs build and verify on JDK 17. Changing only the kit first
separates "the new converter" from "the new JDK".

### 3. Compare the CAP

- The converter changed, so the **CAP bytes and hash change**. Diff the
  exported CAP components (`ant-javacard` / `gp --info` / `capdump`) against the
  JDK 17 + 3.1.0 build: same package and applet AIDs, same imported packages
  and versions (must stay within Java Card 3.0.5 APIs), same install
  parameters.
- Run CAPRunner (`caprunner` CI job) against the new CAP.

**Exit:** no new imports or API levels beyond 3.0.5; CAPRunner passes.

### 4. Move the launcher and toolchains to JDK 21

- Set `jvmToolchain(21)` in the four impala-card modules, keeping **JVM 17
  bytecode** for the SDK (consumers such as impala-lib target 17) via
  `compilerOptions.jvmTarget`, as impala-lib does.
- Run the whole suite on a JDK 21 launcher:
  `./gradlew :sdk:jvmTest :simulator:jvmTest :tools:issue:test :applet:buildJavacard`.
- Watch jcardsim 3.0.6.0: it is the oracle for every interop test and is only
  validated on 17. Any behavioural difference on 21 (crypto provider,
  reflection used by `SimulatorBibo` to give each card its own key) must be
  understood before going further, not suppressed.
- Check the iOS framework and Android KMP targets of `:sdk` still build (AGP 9
  supports 21).

**Exit:** all card suites green on JDK 21; CAP builds on JDK 21 and is
byte-identical to step 2's CAP (same kit, so the launcher JDK must not change
the output; if it does, find out why).

### 5. Update CI and the composite builds

- `impala-card.yml`: `java-version: '21'` in every job. Path filters are
  unchanged.
- `impala-android.yml`: the assemble and instrumented jobs can move to 21 (the
  unit-test and card-e2e jobs already use it); impala-lib and the demo
  composite-build impala-card, so run their full suites too.
- Keep the CAP artifact names (`ImpalaApplet-testnet-cap-<sha>`) so evidence
  records keep pointing at the right builds.

**Exit:** all workflows green on 21.

### 6. Re-establish card evidence

- A new converter means a new artifact: re-run the physical-card checklist
  (`docs/transfer-protocol.md` §9, plan item A-4) with the new CAP before any
  card is issued with it, and record the new CAP sha256 in the evidence file.
  Until then, cards already issued with the 3.1.0-kit CAP stay as they are; the
  CAP is not re-installed on personalized cards.

### 7. Documentation

- Rewrite `README.md` "Toolchain: JDK 17" (and the reasons listed there),
  the `DEVELOPMENT.md` JDK row, root `CLAUDE.md` build notes, and
  `applet/libs/README.md` provenance.
- Mark this document as done (or delete it) in the same change.

## Risks and rollback

| Risk | Mitigation |
|---|---|
| The 3.2 converter emits something a 3.0.5 card rejects | Step 3 diff + CAPRunner; physical-card install (step 6) before release |
| jcardsim behaves differently on JDK 21 | Step 4 isolates the launcher change after the kit change; fix or pin, never weaken a test |
| CAP hash changes break evidence traceability | Record old and new hashes; evidence files name the CAP hash they were taken with |
| Kit licence or availability | Step 1 is first and blocking; if the kit cannot be vendored, stay on 17 |

**Rollback:** each step is a separate commit; reverting to
`sdk.build = jc310b43_kit` and `jvmToolchain(17)` restores today's build
exactly.
