# Plan — JDK 21 LTS and Java Card kit upgrade (not yet implemented)

**Status:** planned, not started. impala-card builds on **JDK 17** today and
nothing in this document is implemented. It records what moving to JDK 21 LTS
requires so the work can be picked up later without re-discovery.

## Why JDK 17 today

The CAP is built by the vendored ant-javacard task
(`applet/libs/ant-javacard-v26.05.15.jar`), which runs **inside the Gradle
JVM**, so the JDK that launches Gradle is the JDK that builds the CAP. The
applet is built as three CAPs (`-Papplet.ed25519=soft|native|none`): `soft`
and `none` are converted for Java Card **3.0.5** (`buildJavacard305` in
`applet/build.xml`), `native` for Java Card **3.1.0** (`buildJavacard31`), all
with the vendored **Java Card 3.1.0** kit
(`sdk.build = libs/sdks/jc310b43_kit`). What each CAP needs from a card is in
the README, "Platform dependencies: JavaCard 3.0.5, 3.1 and 3.2".

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
| `jcardsim-jc31/build.gradle.kts` | `JavaLanguageVersion.of(17)` for the module and for its bytecode patcher |
| `applet/build.xml` | `sdk.build = libs/sdks/jc310b43_kit` for the three CAPs (and `jc305u4_kit` with `jc303_kit` for `buildJavacardLegacy`, the Java Card 3.0.1 CAP without a Stellar key) |
| `.github/workflows/impala-card.yml` | `setup-java` `java-version: '17'` in every job (test, CAP build testnet/live, publish, release) |
| `.github/workflows/impala-android.yml` | `java-version: '17'` in the assemble and instrumented jobs; the unit-test and card-e2e jobs already launch on 21 (they never build the CAP) |
| `README.md` "Toolchain: JDK 17", `DEVELOPMENT.md` JDK row, root `CLAUDE.md` | documentation of the above |

impala-lib and the Android demo already compile and test on a JDK 21 toolchain
(Robolectric needs it) with JVM 17 bytecode; they are not affected.

## What the vendored 3.2 kit already shows

`applet/libs/sdks/jc320v24.0_kit` is too old for JDK 21, but it is a Java
Card 3.2 converter, and trying it answers part of step 3 below in advance.
On 2026-11-12, from a scratch Ant project outside the build (JDK 17,
ant-javacard v26.05.15, the staged sources of `applet/build/cap-src/`), with
that kit as `jckit`:

| Engine | `targetsdk` | Result | Imports (`framework` / `security` / `crypto`) | CAP format |
|---|---|---|---|---|
| `soft` | 3.0.5 | converts, off-card verification passed | 1.6 / 1.6 / 1.6 | 2.1 |
| `native` | 3.1.0 | converts, off-card verification passed | 1.8 / 1.7 / 1.7 | 2.3 |
| `soft` | 3.2.0 | converts, off-card verification passed | 1.9 / 1.8 / 1.8 | 2.3 |
| `native` | 3.2.0 | converts, off-card verification passed | 1.9 / 1.8 / 1.8 | 2.3 |

What follows from it:

- **For the two levels the build targets, the 3.2 converter produced the same
  CAP components.** Compared with the CAPs of the 3.1.0 kit, every component
  (Header, Directory, Import, Applet, Class, Method, StaticField,
  ConstantPool, RefLocation, Descriptor) of `soft` → 3.0.5 and of `native` →
  3.1.0 is byte for byte the same. The files differ only in two manifest
  lines (`Java-Card-CAP-Creation-Time` and `Java-Card-Converter-Version:
  [v3.1.0]` / `[v3.2.0]`), so the file hash changes and what a card loads does
  not. That was observed with kit v24.0; kit v26.0 has to be compared the same
  way (step 3), not assumed.
- **The 3.2 kit finds its own export files.** The explicit
  `<import exps="…/api_export_files_3.0.5"/>` that `buildJavacard305` needs
  with the 3.1.0 kit (see the comment in `build.xml`) was not needed: the
  probe had none and converted for 3.0.5. Whether passing it anyway is an
  error with the new kit, as it is for the 3.1.0 target today, is to be
  checked in step 2.
- **The source is 3.2-clean, and a 3.2 target is not wanted.** Converting for
  3.2.0 only raises the import versions (the README says why no variant is
  built for it). The one new warning at that level is that
  `RandomData.getInstance(byte)` is deprecated in the 3.2 API. The native
  engine's request for the 3.2 per-curve cipher (added after the first probe;
  the probe was repeated with it) needs no 3.2 target either: it passes the
  cipher's value, and the CAP converted for 3.1.0 is unchanged in its imports.

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

- Point `sdk.build` at `libs/sdks/jc320v26.0_kit` and keep both targets as
  they are: `targetsdk="3.0.5"` for `soft` and `none`, so those CAPs still
  load on 3.0.5 cards, and `targetsdk="3.1.0"` for `native`. Do not move
  either to 3.2.0.
- Revisit the explicit export path of `buildJavacard305` (see the finding
  above): keep it only if the new kit needs it.
- Decide what happens to `buildJavacardLegacy` (`jc305u4_kit` converting for
  the 3.0.1 API of `jc303_kit`): keep, move to the new kit, or drop it if
  nothing ships it.
- Run `./gradlew :applet:buildJavacard`, the same with
  `-Papplet.ed25519=native` and `-Papplet.ed25519=none` (verify=true), for the
  testnet AIDs and, with `-Papplet.aid=… -Papplet.aid.app=…`, for the live
  AIDs.

**Exit:** all three variants build and verify on JDK 17, for both AID sets.
Changing only the kit first separates "the new converter" from "the new JDK".

### 3. Compare the CAP

- The converter changed, so the **CAP file and its hash change** (at least
  the manifest names the converter). Diff the CAP components of each variant
  against the JDK 17 + 3.1.0 build: same package and applet AIDs, same
  imported packages and versions (`soft` and `none` must stay at 1.6 / 1.6 /
  1.6, `native` at 1.8 / 1.7 / 1.7), same CAP format, same install
  parameters. With kit v24.0 the components were identical (see above); if
  v26.0 changes one, find out what and why before going on.
- Run `./gradlew :simulator:capMatrix` on the three new CAPs: it reads their
  import tables and fails if one no longer loads on the JavaCard level it
  loads on today (`soft` and `none` from 3.0.5, `native` from 3.1).
- Run CAPRunner (`caprunner` CI job) against the new CAP.

**Exit:** no variant imports a later API level than it does today
(`capMatrix` passes); every component difference is explained; CAPRunner
passes.

### 4. Move the launcher and toolchains to JDK 21

- Set the toolchain to 21 in the five impala-card modules (`jvmToolchain(21)`
  in four, `JavaLanguageVersion.of(21)` in `:jcardsim-jc31`), keeping **JVM 17
  bytecode** for the SDK (consumers such as impala-lib target 17) via
  `compilerOptions.jvmTarget`, as impala-lib does.
- Run the whole suite on a JDK 21 launcher:
  `./gradlew :applet:jvmTest :sdk:jvmTest :simulator:jvmTest :tools:issue:test`
  and `:applet:buildJavacard` for the three variants.
- Watch jcardsim 3.0.6.0: it is the oracle for every interop test and is only
  validated on 17. Any behavioural difference on 21 (crypto provider,
  reflection used by `SimulatorBibo` to give each card its own key) must be
  understood before going further, not suppressed.
- Watch `:jcardsim-jc31` in particular: it patches jcardsim's bytecode at
  build time (ASM) and signs with the JDK's own Ed25519, so it depends on the
  launcher JDK twice. Its patcher fails rather than guesses when a class does
  not look as expected; `Jc31LayerTest` and `Ed25519NativeTest` are its check.
- Check the iOS framework and Android KMP targets of `:sdk` still build (AGP 9
  supports 21).

**Exit:** all card suites green on JDK 21; each CAP builds on JDK 21 with the
same components as step 2's (same kit, so the launcher JDK must not change
them; the manifest's `Created-By` and creation time will differ; if anything
else does, find out why).

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

- Rewrite `README.md` "Toolchain: JDK 17" (and the reasons listed there) and
  the kit rows of "What the build and the tests need" in its platform
  section, the `DEVELOPMENT.md` JDK row, root `CLAUDE.md` build notes, and
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
