#!/usr/bin/env bash
# Scenario 09 — the Soroban contract (MultisigUsdcWrapper): the in-process contract tests always run
# (no network); the testnet end-to-end tests run only when stellar-cli is installed (they self-issue a
# throwaway test asset). The bridge does not invoke the contract: it only echoes SOROBAN_CONTRACT_ID
# on GET /network, and the demo says so instead of pretending otherwise.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
load_env
require_cmd cargo jq
SOROBAN="$REPO_DIR/impala-soroban"
t0="$(now_s)"
hr "scenario 09: Soroban contract tests"

# cargo invocation: rustup's stable toolchain when it carries the wasm32 target (a Homebrew cargo on PATH has
# none). Two host gotchas, both covered by this form: the toolchain's cargo would spawn whichever `rustc` is
# first on PATH (Homebrew's, without the wasm32 std -> "can't find crate for core"), hence RUSTC pinned to
# rustup's rustc; and rust-lld needs rustup's dyld library path (libLLVM.dylib), hence `rustup run` rather
# than the toolchain's binary path. Without rustup + the target, plain cargo runs the tests and the WASM is skipped.
if command -v rustup >/dev/null 2>&1 && rustup target list --installed --toolchain stable 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  RUSTC_PIN="$(rustup which --toolchain stable rustc)"
  cargo_run() { RUSTC="$RUSTC_PIN" rustup run stable cargo "$@"; }
  HAVE_WASM=1
  log "  cargo: rustup stable ($(rustup run stable rustc --version 2>/dev/null)), RUSTC=$RUSTC_PIN"
else
  cargo_run() { cargo "$@"; }
  HAVE_WASM=0
fi

info "1/3 in-process contract tests (cargo test in impala-soroban/integration-test; includes the proptest state machine)"
set +e
( cd "$SOROBAN/integration-test" && cargo_run test --locked 2>&1 ) > "$STATE_DIR/soroban-unit.log"
rc=$?
set -e
grep -E '^test result:' "$STATE_DIR/soroban-unit.log" | sed 's/^/  /' >&2
passed=$(grep -E '^test result:' "$STATE_DIR/soroban-unit.log" | sed -E 's/.* ([0-9]+) passed.*/\1/' | awk '{s+=$1} END {print s+0}')
failed=$(grep -E '^test result:' "$STATE_DIR/soroban-unit.log" | sed -E 's/.* ([0-9]+) failed.*/\1/' | awk '{s+=$1} END {print s+0}')
check "integration-test: cargo test exited 0 ($passed passed, $failed failed)" [ "$rc" -eq 0 ]
check "integration-test: at least one test ran" [ "${passed:-0}" -gt 0 ]

info "1b/3 the release WASM and the pinned-host artifact gate"
WASM="$SOROBAN/integration-test/target/wasm32-unknown-unknown/release/soroban_impala_integration_test.wasm"; WASM_SHA=""
if [ "$HAVE_WASM" = 1 ]; then
  set +e
  ( cd "$SOROBAN/integration-test" && cargo_run build --release --locked --target wasm32-unknown-unknown 2>&1 ) > "$STATE_DIR/soroban-wasm.log"
  wrc=$?
  set -e
  check "WASM builds for wasm32-unknown-unknown" [ "$wrc" -eq 0 ]
  if [ -f "$WASM" ]; then
    WASM_SHA="$(shasum -a 256 "$WASM" | awk '{print $1}')"
    log "  $(basename "$WASM") sha256 $WASM_SHA ($(wc -c < "$WASM" | tr -d ' ') bytes) — equals the on-chain ContractCode hash of a deployment of this build"
    set +e
    ( cd "$SOROBAN/integration-test" && IMPALA_WASM="$WASM" cargo_run test --locked test_wasm_artifact_loads_in_pinned_host -- --ignored 2>&1 ) > "$STATE_DIR/soroban-artifact-gate.log"
    grc=$?
    set -e
    check "artifact gate: the release WASM loads in the pinned Soroban host" [ "$grc" -eq 0 ]
  fi
else
  warn "no rustup stable toolchain with the wasm32-unknown-unknown target: WASM build skipped (rustup target add wasm32-unknown-unknown --toolchain stable)"
fi

info "2/3 testnet end-to-end tests (need stellar-cli)"
tn_status="skipped"; tn_passed=0
if command -v stellar >/dev/null 2>&1; then
  set +e
  ( cd "$SOROBAN/testnet-tests" && cargo test --locked 2>&1 ) > "$STATE_DIR/soroban-testnet.log"
  trc=$?
  set -e
  grep -E '^test result:' "$STATE_DIR/soroban-testnet.log" | sed 's/^/  /' >&2
  tn_passed=$(grep -E '^test result:' "$STATE_DIR/soroban-testnet.log" | sed -E 's/.* ([0-9]+) passed.*/\1/' | awk '{s+=$1} END {print s+0}')
  check "testnet-tests: cargo test exited 0 ($tn_passed passed)" [ "$trc" -eq 0 ]
  tn_status="passed"; [ "$trc" -eq 0 ] || tn_status="failed"
else
  warn "stellar-cli not installed: testnet-tests skipped (brew install stellar-cli to enable; the fixture self-issues a test USDC asset)"
fi

info "3/3 what the bridge says about Soroban"
net="$(curl -fsS "$BRIDGE_URL/network" 2>/dev/null || echo '{}')"
log "  GET /network: $(printf '%s' "$net" | jq -c '{stellar_network, soroban_contract_id: (.soroban_contract_id // null)}')"
manifests="$(ls "$SOROBAN"/deployments/testnet/*.json 2>/dev/null | wc -l | tr -d ' ')"
log "  deployment manifests on record: $manifests (impala-soroban/deployments/testnet) — no active testnet instance is deployed by this demo"
check "the contract is informational to the bridge (no contract id configured in this demo)" sh -c "printf '%s' '$net' | jq -e '(.soroban_contract_id // \"\") == \"\"' >/dev/null"

finish_scenario scenario-09-soroban "$(jq -cn --argjson p "${passed:-0}" --argjson f "${failed:-0}" --arg tn "$tn_status" --argjson tnp "${tn_passed:-0}" --arg log "$STATE_DIR/soroban-unit.log" --arg wasm "$WASM_SHA" \
  '{unit_passed:$p, unit_failed:$f, wasm_sha256:$wasm, testnet_tests:$tn, testnet_passed:$tnp, report:$log}')" "$t0"
