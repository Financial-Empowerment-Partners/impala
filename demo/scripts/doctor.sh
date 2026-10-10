#!/usr/bin/env bash
# Check host prerequisites and report what each missing item disables. Writes state/doctor.json for
# scripts/run-all.sh. Exit 1 only when the mandatory lane (containers + bridge + testnet) cannot run.
# Usage: scripts/doctor.sh
set -euo pipefail
. "$(dirname "$0")/lib.sh"
# before prepare.sh has written .env, the non-secret defaults of .env.example still describe the lanes
[ -f "$DEMO_DIR/.env" ] || load_env_file "$DEMO_DIR/.env.example"
load_env 2>/dev/null || true
hard=0; have_engine=""; have_jdk17=""; have_sdk=""; have_image=""; have_adb=""; have_scardutil=""

hr "host tools"
for c in bash curl jq openssl od git tar; do
  if command -v "$c" >/dev/null 2>&1; then ok "$c"; else fail_line "$c missing (required)"; hard=1; fi
done
command -v go >/dev/null 2>&1 && ok "go $(go version | awk '{print $3}') (lumencli / impalactl are built from source)" || { fail_line "go missing (required to build lumencli and impalactl)"; hard=1; }
command -v python3 >/dev/null 2>&1 && ok "python3 (card lanes: the simulator APDU probe)" || warn "python3 not found: scenarios 05-07 cannot probe the simulated card"
if command -v cargo >/dev/null 2>&1; then
  if command -v rustup >/dev/null 2>&1 && rustup target list --installed --toolchain stable 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    ok "cargo $(cargo --version 2>/dev/null | awk '{print $2}') + rustup stable with wasm32-unknown-unknown (scenario 09 builds the WASM)"
  else
    warn "cargo found, but no rustup stable toolchain with the wasm32-unknown-unknown target: scenario 09 runs the contract tests and skips the WASM build (rustup target add wasm32-unknown-unknown --toolchain stable)"
  fi
else
  warn "cargo not found: scenario 09 (Soroban) is skipped (DEVELOPMENT.md lists the Rust toolchain)"
fi
command -v vhs >/dev/null 2>&1 && ok "vhs (optional: recordings/demo.tape)" || warn "vhs not found (optional: console recording)"
command -v stellar >/dev/null 2>&1 && ok "stellar-cli (optional: Soroban testnet tests)" || warn "stellar-cli not found (optional: scenario 09 runs the in-process contract tests only)"

hr "container engine"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  have_engine=docker; ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) daemon reachable; compose $(docker compose version --short 2>/dev/null)"
fi
if command -v podman >/dev/null 2>&1; then
  if podman info >/dev/null 2>&1; then
    [ -n "$have_engine" ] || have_engine=podman
    ok "podman $(podman version --format '{{.Client.Version}}' 2>/dev/null) reachable (compose provider: ${PODMAN_COMPOSE_PROVIDER:-default search order})"
  else
    warn "podman installed but its machine is not running (podman machine start)"
  fi
fi
if [ -z "$have_engine" ]; then fail_line "no container engine reachable: start Docker (OrbStack/Docker Desktop) or 'podman machine start'"; hard=1
else ok "selected engine: ${CONTAINER_ENGINE:-$have_engine (auto)}"; fi

hr "testnet"
if pp="$(curl -fsS -m 10 "$HORIZON_URL/" 2>/dev/null | jq -r .network_passphrase)" && [ "$pp" = "$TESTNET_PASSPHRASE" ]; then
  ok "Horizon testnet reachable (latest ledger $(curl -fsS -m 10 "$HORIZON_URL/" | jq -r .history_latest_ledger))"
else fail_line "Horizon testnet unreachable ($HORIZON_URL): the bridge refuses to boot without it"; hard=1; fi

hr "JavaCard simulator lane (host JVM)"
if jh="$(jdk17_home)"; then have_jdk17="$jh"; ok "JDK 17 at $jh (launches Gradle for impala-card and the Android app)"
else warn "JDK 17 not found: set JAVA17_HOME; scenarios 05-07 need it"; fi

hr "Android emulator lane"
if r="$(android_sdk_root)"; then
  have_sdk="$r"; ok "Android SDK with emulator: $r ($("$r/emulator/emulator" -version 2>/dev/null | grep -o 'version [0-9.]*' | head -n1))"
  if system_image_present; then have_image=1; ok "system image ${DEMO_SYSTEM_IMAGE:-system-images;android-34;google_apis;arm64-v8a} present"
  else warn "system image ${DEMO_SYSTEM_IMAGE:-system-images;android-34;google_apis;arm64-v8a} missing (scripts/emulator.sh up installs it when DEMO_INSTALL_SDK=1; ~1.3 GB)"; fi
  if a="$(adb_bin)"; then have_adb="$a"; ok "adb: $a"; else warn "adb not found"; fi
  [ -x "$r/cmdline-tools/latest/bin/avdmanager" ] && ok "cmdline-tools/latest present (avdmanager)" || warn "cmdline-tools/latest missing in $r (scripts/emulator.sh installs it when DEMO_INSTALL_SDK=1)"
else
  warn "no Android SDK with an emulator found (DEMO_ANDROID_SDK_ROOT / ANDROID_SDK_ROOT / ~/Library/Android/sdk): scenario 07 is skipped"
fi
[ -f "$REPO_DIR/impala-android-demo/app/google-services.json" ] && ok "impala-android-demo/app/google-services.json present" \
  || warn "impala-android-demo/app/google-services.json missing: every Gradle task of the app fails without it (cp google-services.json.example google-services.json)"

hr "optional lanes"
ok "payala stub: in-repo (payala-stub/server.mjs on docker.io/library/node:22-alpine; no Payala API image or source tree needed)"
if [ -n "${SCARDUTIL_DIR:-}" ] && [ -d "$SCARDUTIL_DIR/src/scardutil" ]; then have_scardutil=1; ok "scardutil checkout: $SCARDUTIL_DIR"; else warn "scardutil not configured (SCARDUTIL_DIR): the fleet check in scenario 05 is skipped"; fi

mkdir -p "$STATE_DIR"
jq -n --arg engine "$have_engine" --arg jdk "$have_jdk17" --arg sdk "$have_sdk" --arg image "$have_image" --arg adb "$have_adb" \
      --arg scardutil "$have_scardutil" --arg at "$(utc_now)" --argjson hard "$hard" \
  '{checked_at:$at, engine:$engine, jdk17:$jdk, android_sdk_root:$sdk, system_image:($image=="1"), adb:$adb, payala:"stub", scardutil:($scardutil=="1"), hard_failures:$hard}' \
  > "$STATE_DIR/doctor.json"
log ""
if [ "$hard" -eq 0 ]; then ok "doctor: the mandatory lane can run (state/doctor.json)"; else die "doctor: fix the items marked FAIL first"; fi
