#!/usr/bin/env bash
# Shared card ⇄ bridge golden vectors (contract-addendum.md §A.11;
# impala-card/docs/transfer-protocol.md §4). Every literal must appear,
# verbatim, in every file that pins it — so neither the card SDK nor the
# bridge (nor a client that composes transfers) can drift from the shared
# byte formats without failing CI. Run from any directory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CERT=494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
XFER=494d50414c412d584645523a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000100112233445566778899aabbccddeeffffeeddccbbaa9988776655443322110055534443000003e8000000000000000000000001
TRANSFER_ID=6b3c272189bde62d55636e21b345929c1c077d008bb533af44f813adf56b67b9
CERT_ID=82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b

SDK_GOLDEN=impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/TransferProtocolGoldenTest.kt
BRIDGE_GOLDEN=impala-bridge/src/handlers/card_auth.rs
SDK_FLOW=impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/flows/RedemptionFlowTest.kt
DEMO_WIRE=impala-android-demo/app/src/test/java/com/payala/impala/demo/WireFormatsTest.kt

failures=0
require() { # name literal file...
  local name="$1" literal="$2"; shift 2
  for f in "$@"; do
    if [ ! -f "$root/$f" ]; then
      echo "MISSING FILE: $f (expected to pin $name)"; failures=$((failures + 1)); continue
    fi
    if ! grep -qF "$literal" "$root/$f"; then
      echo "DRIFT: $name literal not found in $f"; failures=$((failures + 1))
    else
      echo "ok: $name in $f"
    fi
  done
}

require CERT "$CERT" "$SDK_GOLDEN" "$BRIDGE_GOLDEN"
require XFER "$XFER" "$SDK_GOLDEN" "$BRIDGE_GOLDEN" "$SDK_FLOW"
require transfer_id "$TRANSFER_ID" "$SDK_GOLDEN" "$BRIDGE_GOLDEN" "$SDK_FLOW" "$DEMO_WIRE"
require cert_id "$CERT_ID" "$SDK_GOLDEN" "$BRIDGE_GOLDEN"

if [ "$failures" -ne 0 ]; then
  echo "check-shared-vectors: $failures failure(s)"
  exit 1
fi
echo "check-shared-vectors: all shared card/bridge vectors present"
