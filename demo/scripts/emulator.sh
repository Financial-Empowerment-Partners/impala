#!/usr/bin/env bash
# The Android emulator lane: an API-34 (Google APIs, arm64) AVD booted headless by default, reached
# through adb. Idempotent: `up` reuses a running emulator of the same AVD.
# Usage: scripts/emulator.sh up|down|status|screenshot <name>|avd-ensure
#   DEMO_HEADLESS=0        show the emulator window (live demos)
#   DEMO_INSTALL_SDK=1     let this script install cmdline-tools and the system image with sdkmanager (downloads)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
SERIAL="${DEMO_EMULATOR_SERIAL:-emulator-5554}"
PORT="${SERIAL#emulator-}"
AVD="${DEMO_AVD:-impala-demo-34}"
IMG="${DEMO_SYSTEM_IMAGE:-system-images;android-34;google_apis;arm64-v8a}"
LOG="$STATE_DIR/emulator.log"

sdk="$(android_sdk_root)" || die "no Android SDK with an emulator found (DEMO_ANDROID_SDK_ROOT / ANDROID_SDK_ROOT / ANDROID_HOME / ~/Library/Android/sdk)"
export ANDROID_SDK_ROOT="$sdk" ANDROID_HOME="$sdk"
ADB="$(adb_bin)" || die "adb not found"
EMU="$sdk/emulator/emulator"
adb() { "$ADB" -s "$SERIAL" "$@"; }

running_avd() { "$ADB" -s "$SERIAL" emu avd name 2>/dev/null | head -n1 | tr -d '\r' || true; }
booted() { [ "$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; }

ensure_tools() {
  local sdkm avdm
  if [ ! -x "$sdk/cmdline-tools/latest/bin/avdmanager" ]; then
    [ "${DEMO_INSTALL_SDK:-0}" = "1" ] || die "cmdline-tools/latest missing in $sdk: run with DEMO_INSTALL_SDK=1 (downloads from Google) or install it with Android Studio"
    sdkm="$(command -v sdkmanager || true)"; [ -n "$sdkm" ] || die "no sdkmanager on PATH to install cmdline-tools;latest into $sdk"
    info "installing cmdline-tools;latest into $sdk"
    yes | "$sdkm" --sdk_root="$sdk" --install "cmdline-tools;latest" >/dev/null
  fi
  if ! system_image_present; then
    [ "${DEMO_INSTALL_SDK:-0}" = "1" ] || die "system image $IMG missing in $sdk: run with DEMO_INSTALL_SDK=1 (downloads ~1.3 GB from Google) or install it with Android Studio"
    info "installing $IMG into $sdk (this downloads ~1.3 GB)"
    yes | "$sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$sdk" --install "$IMG" >/dev/null
    system_image_present || die "system image install failed"
  fi
}

ensure_avd() {
  ensure_tools
  local avdm="$sdk/cmdline-tools/latest/bin/avdmanager"
  if "$avdm" list avd 2>/dev/null | grep -q "Name: $AVD\$"; then ok "AVD $AVD exists"; return 0; fi
  info "creating AVD $AVD ($IMG, pixel_6)"
  echo no | "$avdm" create avd -n "$AVD" -k "$IMG" --device pixel_6 >/dev/null
  ok "AVD $AVD created"
}

case "${1:-status}" in
  avd-ensure) ensure_avd ;;
  up)
    ensure_avd
    "$ADB" start-server >/dev/null 2>&1 || true
    if booted && [ "$(running_avd)" = "$AVD" ]; then ok "emulator $SERIAL already booted ($AVD)"; exit 0; fi
    if "$ADB" devices | grep -q "^$SERIAL"; then die "$SERIAL is in use by another AVD ($(running_avd)); stop it or set DEMO_EMULATOR_SERIAL"; fi
    flags="-avd $AVD -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect -port $PORT"
    [ "${DEMO_HEADLESS:-1}" = "1" ] && flags="$flags -no-window"
    info "booting emulator $AVD as $SERIAL ($( [ "${DEMO_HEADLESS:-1}" = "1" ] && printf 'headless' || printf 'with window'))"
    t0="$(now_s)"
    # shellcheck disable=SC2086
    nohup "$EMU" $flags > "$LOG" 2>&1 &
    i=0
    until booted; do i=$((i + 1)); if [ "$i" -ge 100 ]; then tail -n 20 "$LOG" >&2; die "emulator did not boot within 300s (see $LOG)"; fi; sleep 3; done
    # animations off and keyguard dismissed: Espresso needs a stable, unlocked screen
    adb shell settings put global window_animation_scale 0 >/dev/null 2>&1 || true
    adb shell settings put global transition_animation_scale 0 >/dev/null 2>&1 || true
    adb shell settings put global animator_duration_scale 0 >/dev/null 2>&1 || true
    adb shell input keyevent 82 >/dev/null 2>&1 || true
    ok "emulator booted in $(( $(now_s) - t0 ))s: Android $(adb shell getprop ro.build.version.release | tr -d '\r') (API $(adb shell getprop ro.build.version.sdk | tr -d '\r'), $(adb shell getprop ro.product.cpu.abi | tr -d '\r'))"
    timing "emulator boot" "$(( $(now_s) - t0 ))" passed
    ;;
  down)
    if "$ADB" devices | grep -q "^$SERIAL"; then adb emu kill >/dev/null 2>&1 || true; sleep 3; ok "emulator $SERIAL stopped"; else log "  emulator not running"; fi
    pkill -f "qemu-system-aarch64.*-avd $AVD" 2>/dev/null || true
    ;;
  status)
    if booted; then ok "emulator $SERIAL booted: AVD $(running_avd), API $(adb shell getprop ro.build.version.sdk | tr -d '\r')"; else log "  emulator not booted (scripts/emulator.sh up)"; exit 1; fi
    ;;
  screenshot)
    name="${2:-screen}"; mkdir -p "$ARTIFACTS_DIR"
    adb exec-out screencap -p > "$ARTIFACTS_DIR/$name.png"
    ok "screenshot: state/artifacts/$name.png ($(wc -c < "$ARTIFACTS_DIR/$name.png" | tr -d ' ') bytes)"
    ;;
  *) die "usage: $0 up|down|status|screenshot <name>|avd-ensure" ;;
esac
