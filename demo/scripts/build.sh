#!/usr/bin/env bash
# Build the images with the native engine CLI (docker build / podman build --format docker) and the host
# tools (lumencli, impalactl) from source into bin/.
# Usage: scripts/build.sh [bridge|tools|warm|all]   (default all; `warm` pre-compiles the Gradle lanes)
# The Payala stub needs no build: it runs from the public node image (compose service payala-stub).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
what="${1:-all}"

build_image() {
  local tag="$1" ctx="$2" file="$3"; shift 3
  local t0; t0="$(now_s)"
  info "building $tag ($ENGINE)"
  case "$ENGINE" in
    docker) docker build -t "$tag" -f "$file" "$@" "$ctx" ;;
    podman) podman build --format docker -t "$tag" -f "$file" "$@" "$ctx" ;;
  esac
  timing "build $tag" "$(( $(now_s) - t0 ))" built
  ok "$tag ($(( $(now_s) - t0 ))s)"
}

if [ "$what" = tools ] || [ "$what" = all ]; then
  require_cmd go
  mkdir -p "$BIN_DIR"
  t0="$(now_s)"
  info "building lumencli and impalactl from source (GOTOOLCHAIN=auto may download the pinned Go)"
  CGO_ENABLED=0 GOTOOLCHAIN=auto go build -C "$REPO_DIR/lumencli" -trimpath -ldflags '-s -w' -o "$BIN_DIR/lumencli" .
  CGO_ENABLED=0 GOTOOLCHAIN=auto go build -C "$REPO_DIR/impalactl" -trimpath -o "$BIN_DIR/impalactl" .
  ok "bin/lumencli $("$BIN_DIR/lumencli" version 2>/dev/null | head -n1), bin/impalactl ($(( $(now_s) - t0 ))s)"
fi

if [ "$what" = bridge ] || [ "$what" = all ]; then
  engine_ready
  [ -f "$BUILD_DIR/impala-bridge.Containerfile" ] || die "run scripts/prepare.sh first"
  log "  (a cold Rust release build takes ~3-5 minutes on an M-series Mac; Podman machines are slower)"
  build_image "$IMAGE_BRIDGE" "$REPO_DIR/impala-bridge" "$BUILD_DIR/impala-bridge.Containerfile"
fi


if [ "$what" = warm ]; then
  t0="$(now_s)"
  info "warming the Gradle lanes on JDK 17 (card simulator + issuance tool, Android app tnetDebug)"
  gradle_card -q :simulator:jvmJar :tools:issue:installDist
  if [ -f "$REPO_DIR/impala-android-demo/app/google-services.json" ]; then
    gradle_app -q :app:assembleTnetDebug :app:assembleTnetDebugAndroidTest
  else
    warn "impala-android-demo/app/google-services.json missing: skipping the app warm-up"
  fi
  timing "gradle warm-up" "$(( $(now_s) - t0 ))" built
  ok "gradle lanes warm ($(( $(now_s) - t0 ))s)"
fi

ok "build done; next: scripts/up.sh"
