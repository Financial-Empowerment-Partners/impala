#!/usr/bin/env bash
# Verify a deployment manifest against the live network.
#
# Usage: scripts/verify-deployment.sh <manifest.json> [--source <identity>]
#
# Fails closed on every step. Exit codes:
#   0  every field verified (drift in max_entry_ttl and an unavailable
#      `stellar tx fetch` are warnings, printed as such)
#   1  a mismatch, an RPC/CLI error, or an issuer-policy violation
#   2  usage / tooling error (missing stellar, jq, sha256sum, or a manifest
#      that has nothing to verify, e.g. a placeholder contract_id)
#
# Steps:
#   1. load the manifest (network, contract_id, issuer, SAC, governance)
#   2. issuer policy: public refuses anything but Circle's pubnet issuer,
#      self_issued must be false and both thresholds >= 2; testnet requires
#      Circle's testnet issuer unless self_issued == true
#   3. `stellar contract fetch` the on-chain WASM; sha256 == wasm_sha256
#   4. `stellar contract id asset --asset USDC:<issuer>` == usdc.sac_contract_id
#   5. read fns (simulation only, never submitted): usdc_token, usdc_issuer,
#      min_threshold, min_lock_duration, multisig_config (signers set-equal,
#      threshold equal, epoch printed), max_entry_ttl (compared with
#      policy.network_max_entry_ttl_at_deploy — warn only on drift)
#   6. the SAC's name() == usdc.expected_name
#   7. the deploy transaction exists (`stellar tx fetch`; warn-only when the
#      pinned CLI lacks the subcommand)
#   8. expected/actual table
#
# CLI output formats (quotes around strings, JSON for structs) are confirmed
# on the first manual run; this script strips surrounding quotes and parses
# multisig_config with jq. Reads are invoked with `--send=no` so nothing is
# ever submitted by this script.
set -euo pipefail

usage() {
  echo "usage: $0 <manifest.json> [--source <identity>]" >&2
  exit 2
}

manifest=""
src=""
while (($#)); do
  case "$1" in
    --source)
      [[ $# -ge 2 ]] || usage
      src="$2"
      shift 2
      ;;
    -h|--help) usage ;;
    *)
      [[ -z "$manifest" ]] || usage
      manifest="$1"
      shift
      ;;
  esac
done
[[ -n "$manifest" && -f "$manifest" ]] || usage
for tool in stellar jq sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 2; }
done

readonly CIRCLE_PUBLIC_ISSUER="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
readonly CIRCLE_TESTNET_ISSUER="GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
rows=()
record() { # field expected actual status
  rows+=("$1|$2|$3|$4")
}
mismatch() { # field expected actual
  echo "MISMATCH $1: expected '$2' got '$3'" >&2
  record "$1" "$2" "$3" "MISMATCH"
  fail=1
}
verified() { record "$1" "$2" "$3" "ok"; }
warn() { echo "warning: $1" >&2; }

strip_quotes() { sed -e 's/^"//' -e 's/"$//'; }

# --- 1. manifest -----------------------------------------------------------
jq -e . "$manifest" >/dev/null 2>&1 || { echo "error: $manifest is not valid JSON" >&2; exit 2; }
mf() { jq -r "$1" "$manifest"; }
NET="$(mf .network)"
CID="$(mf .contract_id)"
STATUS="$(mf .status)"
ISSUER="$(mf .usdc.issuer)"
SAC="$(mf .usdc.sac_contract_id)"
EXPECTED_NAME="$(mf .usdc.expected_name)"
SELF_ISSUED="$(mf .usdc.self_issued)"
WASM_SHA="$(mf .wasm_sha256)"
THRESHOLD="$(mf .governance.threshold)"
MIN_THRESHOLD="$(mf .governance.min_threshold)"
MIN_LOCK="$(mf .governance.min_lock_duration_seconds)"
TTL_AT_DEPLOY="$(mf .policy.network_max_entry_ttl_at_deploy)"
DEPLOY_TX="$(mf .deploy.tx_hash)"

case "$NET" in
  testnet|public) ;;
  *) echo "error: unsupported network '$NET'" >&2; exit 2 ;;
esac
if [[ ! "$CID" =~ ^C[A-Z2-7]{55}$ ]]; then
  echo "error: contract_id '$CID' is not a contract strkey (placeholder or retired-without-id entry: nothing to verify)" >&2
  exit 2
fi
if [[ "$STATUS" != "active" ]]; then
  warn "manifest status is '$STATUS' (verifying anyway)"
fi
echo "verifying $CID on $NET (manifest: $manifest)"

# --- 2. issuer policy ------------------------------------------------------
if [[ "$NET" == "public" ]]; then
  [[ "$ISSUER" == "$CIRCLE_PUBLIC_ISSUER" ]] || mismatch "issuer policy (public)" "$CIRCLE_PUBLIC_ISSUER" "$ISSUER"
  [[ "$SELF_ISSUED" == "false" ]] || mismatch "usdc.self_issued (public)" "false" "$SELF_ISSUED"
  [[ "$THRESHOLD" =~ ^[0-9]+$ && "$THRESHOLD" -ge 2 ]] || mismatch "governance.threshold (public >= 2)" ">=2" "$THRESHOLD"
  [[ "$MIN_THRESHOLD" =~ ^[0-9]+$ && "$MIN_THRESHOLD" -ge 2 ]] || mismatch "governance.min_threshold (public >= 2)" ">=2" "$MIN_THRESHOLD"
else
  if [[ "$ISSUER" != "$CIRCLE_TESTNET_ISSUER" && "$SELF_ISSUED" != "true" ]]; then
    mismatch "issuer policy (testnet)" "$CIRCLE_TESTNET_ISSUER or self_issued=true" "$ISSUER"
  fi
fi
if (( fail )); then
  echo "error: issuer policy violated; refusing to continue" >&2
  exit 1
fi
verified "issuer policy" "$ISSUER" "$ISSUER"

# --- 3. on-chain WASM hash -------------------------------------------------
if ! stellar contract fetch --id "$CID" --network "$NET" --out-file "$tmp/onchain.wasm" >"$tmp/fetch.out" 2>&1; then
  echo "error: stellar contract fetch failed:" >&2
  cat "$tmp/fetch.out" >&2
  exit 1
fi
actual_sha="$(sha256sum "$tmp/onchain.wasm" | cut -d' ' -f1)"
if [[ "$actual_sha" == "$WASM_SHA" ]]; then
  verified "wasm_sha256" "$WASM_SHA" "$actual_sha"
else
  mismatch "wasm_sha256" "$WASM_SHA" "$actual_sha"
fi

# --- 4. SAC id from the asset ---------------------------------------------
if ! actual_sac="$(stellar contract id asset --asset "USDC:$ISSUER" --network "$NET" 2>"$tmp/sac.err" | tr -d '\r' | tail -n1)"; then
  echo "error: stellar contract id asset failed:" >&2
  cat "$tmp/sac.err" >&2
  exit 1
fi
if [[ "$actual_sac" == "$SAC" ]]; then
  verified "usdc.sac_contract_id (id asset)" "$SAC" "$actual_sac"
else
  mismatch "usdc.sac_contract_id (id asset)" "$SAC" "$actual_sac"
fi

# --- 5. contract read functions (simulation only) --------------------------
invoke_read() { # contract fn [args...]
  local id="$1" fn="$2"
  shift 2
  local -a cmd=(stellar contract invoke --id "$id" --network "$NET" --send=no)
  if [[ -n "$src" ]]; then
    cmd+=(--source "$src")
  fi
  cmd+=(-- "$fn" "$@")
  if ! "${cmd[@]}" 2>"$tmp/invoke.err" | tr -d '\r'; then
    echo "error: invoke $fn on $id failed:" >&2
    cat "$tmp/invoke.err" >&2
    return 1
  fi
}
read_scalar() { # contract fn
  invoke_read "$1" "$2" | tail -n1 | strip_quotes
}

actual_token="$(read_scalar "$CID" usdc_token)" || exit 1
[[ "$actual_token" == "$SAC" ]] && verified "usdc_token()" "$SAC" "$actual_token" || mismatch "usdc_token()" "$SAC" "$actual_token"

actual_issuer="$(read_scalar "$CID" usdc_issuer)" || exit 1
[[ "$actual_issuer" == "$ISSUER" ]] && verified "usdc_issuer()" "$ISSUER" "$actual_issuer" || mismatch "usdc_issuer()" "$ISSUER" "$actual_issuer"

actual_min_threshold="$(read_scalar "$CID" min_threshold)" || exit 1
[[ "$actual_min_threshold" == "$MIN_THRESHOLD" ]] && verified "min_threshold()" "$MIN_THRESHOLD" "$actual_min_threshold" || mismatch "min_threshold()" "$MIN_THRESHOLD" "$actual_min_threshold"

actual_min_lock="$(read_scalar "$CID" min_lock_duration)" || exit 1
[[ "$actual_min_lock" == "$MIN_LOCK" ]] && verified "min_lock_duration()" "$MIN_LOCK" "$actual_min_lock" || mismatch "min_lock_duration()" "$MIN_LOCK" "$actual_min_lock"

config_json="$(invoke_read "$CID" multisig_config | tail -n1)" || exit 1
if ! printf '%s' "$config_json" | jq -e . >/dev/null 2>&1; then
  echo "error: multisig_config output is not JSON: $config_json" >&2
  exit 1
fi
expected_signers="$(jq -c '.governance.signers | sort' "$manifest")"
actual_signers="$(printf '%s' "$config_json" | jq -c '.signers | sort')"
actual_threshold="$(printf '%s' "$config_json" | jq -r '.threshold')"
actual_epoch="$(printf '%s' "$config_json" | jq -r '.epoch')"
[[ "$actual_signers" == "$expected_signers" ]] && verified "multisig_config().signers" "$expected_signers" "$actual_signers" || mismatch "multisig_config().signers" "$expected_signers" "$actual_signers"
[[ "$actual_threshold" == "$THRESHOLD" ]] && verified "multisig_config().threshold" "$THRESHOLD" "$actual_threshold" || mismatch "multisig_config().threshold" "$THRESHOLD" "$actual_threshold"
record "multisig_config().epoch" "(rotations so far)" "$actual_epoch" "info"

actual_ttl="$(read_scalar "$CID" max_entry_ttl)" || exit 1
if [[ "$actual_ttl" == "$TTL_AT_DEPLOY" ]]; then
  verified "max_entry_ttl()" "$TTL_AT_DEPLOY" "$actual_ttl"
else
  warn "max_entry_ttl() drifted since deploy: manifest $TTL_AT_DEPLOY, network $actual_ttl (persistent extensions clamp to the network max)"
  record "max_entry_ttl()" "$TTL_AT_DEPLOY" "$actual_ttl" "WARN drift"
fi

# --- 6. the SAC's name() ---------------------------------------------------
actual_name="$(read_scalar "$SAC" name)" || exit 1
[[ "$actual_name" == "$EXPECTED_NAME" ]] && verified "SAC name()" "$EXPECTED_NAME" "$actual_name" || mismatch "SAC name()" "$EXPECTED_NAME" "$actual_name"

# --- 7. the deploy transaction ----------------------------------------------
if stellar tx fetch --help >/dev/null 2>&1; then
  if stellar tx fetch --hash "$DEPLOY_TX" --network "$NET" >"$tmp/tx.out" 2>&1; then
    verified "deploy.tx_hash (tx fetch)" "$DEPLOY_TX" "found"
    echo "deploy tx (first lines):"
    head -n 5 "$tmp/tx.out" | sed 's/^/  /'
  else
    echo "error: stellar tx fetch --hash $DEPLOY_TX failed:" >&2
    cat "$tmp/tx.out" >&2
    mismatch "deploy.tx_hash (tx fetch)" "$DEPLOY_TX" "not found / error"
  fi
else
  warn "this stellar-cli has no 'tx fetch' subcommand; verify $DEPLOY_TX via Horizon /transactions/<hash> manually"
  record "deploy.tx_hash (tx fetch)" "$DEPLOY_TX" "unavailable" "WARN"
fi

# --- 8. table -------------------------------------------------------------
echo
printf '%-36s %-8s %s\n' "FIELD" "STATUS" "EXPECTED -> ACTUAL"
for r in "${rows[@]}"; do
  IFS='|' read -r f e a s <<<"$r"
  printf '%-36s %-8s %s -> %s\n' "$f" "$s" "$e" "$a"
done
echo
if (( fail )); then
  echo "RESULT: MISMATCH — do not trust this manifest until resolved" >&2
  exit 1
fi
echo "RESULT: verified"
