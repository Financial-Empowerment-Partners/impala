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

# SEP-10 with card-held keys (docs/sep10-card-keys.md): the login challenge the
# bridge issues to the deterministic simulator card, that challenge signed by
# the applet, and the applet's two registration cross-signatures. The bridge
# builds and verifies them in Rust; the card SDK and the applet sign and
# verify them on the JVM.
SEP10_ISSUED=AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAH3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwA=
SEP10_CARD_SIGNED=AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAL3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwBVU/2ZAAAAQD5j/mz4dfCycHkSai6dC23Xdio+GWlmCMT7i2qFmqUVrF0IsVp8Gq7w6REyFvr8gDG9VzN+TPEC+bBFAT7CIQk=
SEP10_CARD_ADDRESS=GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF
SEP10_BINDING_SIG=304502202b495a9b4142dc317624626ad108d4896c12a97af1a1372e9a7b0f29adcaeb49022100fde245243f8e85f3c60a013d3423d514499cd65fa46d9b26622712ea13b90603
SEP10_PROOF_SIG=6da881be63f5dc8c56e103625c67d5c89fc5c88a53629b7884775d522a763beffba92b3107031f2e0ead000068049e4bc3633b4de6428073eb429100f2e7e705
SEP10_SKEY_TAG=494d50414c412d534b45593a

# MFA domain tags (docs/mfa-card-pin-biometrics.md §8): the card PIN proof tag
# "IMPALA-APIN:" and the phone device-key tag "IMPALA-DKEY:", pinned in hex on
# the card side (impala-lib) and the bridge side so neither can drift.
MFA_PIN_TAG=494d50414c412d4150494e3a
MFA_DKEY_TAG=494d50414c412d444b45593a
LIB_MFA=impala-lib/src/test/java/com/payala/impala/card/CardSignInTest.kt
BRIDGE_CONSTANTS=impala-bridge/src/constants.rs

SDK_SEP10=impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/BridgeVectorTest.kt
BRIDGE_SEP10=impala-bridge/src/sep10/card_vectors.rs
BRIDGE_SKEY=impala-bridge/src/sep10/binding.rs
SDK_SKEY=impala-card/sdk/src/jvmTest/kotlin/com/impala/sdk/StellarKeySdkTest.kt
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
require sep10_issued "$SEP10_ISSUED" "$SDK_SEP10" "$BRIDGE_SEP10"
require sep10_card_signed "$SEP10_CARD_SIGNED" "$SDK_SEP10" "$BRIDGE_SEP10"
require sep10_card_address "$SEP10_CARD_ADDRESS" "$SDK_SEP10" "$BRIDGE_SEP10"
require sep10_binding_sig "$SEP10_BINDING_SIG" "$SDK_SEP10" "$BRIDGE_SEP10"
require sep10_proof_sig "$SEP10_PROOF_SIG" "$SDK_SEP10" "$BRIDGE_SEP10"
require skey_tag "$SEP10_SKEY_TAG" "$SDK_SKEY" "$BRIDGE_SKEY"
require mfa_pin_proof_tag "$MFA_PIN_TAG" "$LIB_MFA" "$BRIDGE_CONSTANTS"
require mfa_device_key_tag "$MFA_DKEY_TAG" "$LIB_MFA" "$BRIDGE_CONSTANTS"

if [ "$failures" -ne 0 ]; then
  echo "check-shared-vectors: $failures failure(s)"
  exit 1
fi
echo "check-shared-vectors: all shared card/bridge vectors present"
