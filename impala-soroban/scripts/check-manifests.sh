#!/usr/bin/env bash
# Validate the deployment manifests under impala-soroban/deployments/.
#
# Usage: scripts/check-manifests.sh [--require-active]
#
# Rules (see deployments/README.md for the schema):
#   * every deployments/{testnet,public}/*.json is schema_version 1 with the
#     right network / passphrase and status active|retired
#   * at most one `active` entry per network directory (a directory holding
#     only retired entries is the transitional state between a retirement and
#     the next deploy; --require-active makes that fatal)
#   * active entries are fully validated: strkeys, 64-hex hashes,
#     expected_name == "USDC:" + issuer, threshold >= min_threshold >= 1,
#     positive TTL policy with threshold <= extend-to, and the issuer policy
#       public : Circle's pubnet issuer, self_issued == false,
#                threshold >= 2, min_threshold >= 2
#       testnet: Circle's testnet issuer unless self_issued == true
#   * retired entries need a `retired` block; a contract_id that is the literal
#     placeholder <TF_VAR_testnet_soroban_contract_id> is accepted only for a
#     retired entry whose file is named retired-*.json (the pre-manifest
#     instance whose id lives in a CI secret); every other present, non-null
#     field is validated with the active rules
#   * when $TF_VAR_testnet_soroban_contract_id is non-empty it must equal the
#     active testnet entry's contract_id (CI equality check); with no active
#     entry a warning is printed (fatal with --require-active); an empty
#     variable is skipped with a notice
#
# Exit 0 when everything validates, 1 on any violation (file + rule printed),
# 2 on usage / tooling errors. Needs jq.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
# DEPLOYMENTS_DIR overrides the directory (used by the script self-test).
dep="${DEPLOYMENTS_DIR:-$root/deployments}"

require_active=0
case "${1:-}" in
  "") ;;
  --require-active) require_active=1 ;;
  *) echo "usage: $0 [--require-active]" >&2; exit 2 ;;
esac
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }
[[ -d "$dep" ]] || { echo "error: $dep not found" >&2; exit 2; }

readonly CIRCLE_PUBLIC_ISSUER="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
readonly CIRCLE_TESTNET_ISSUER="GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
readonly PASSPHRASE_PUBLIC="Public Global Stellar Network ; September 2015"
readonly PASSPHRASE_TESTNET="Test SDF Network ; September 2015"
readonly PLACEHOLDER_ID='<TF_VAR_testnet_soroban_contract_id>'
readonly ARTIFACT="soroban_impala_integration_test.wasm"

fail=0
violation() { echo "error: $1: $2" >&2; fail=1; }

# jq program: emits one violation string per line for a single manifest.
read -r -d '' JQ_PROGRAM <<'JQ' || true
def is_g: type == "string" and test("^G[A-Z2-7]{55}$");
def is_c: type == "string" and test("^C[A-Z2-7]{55}$");
def is_hex64: type == "string" and test("^[0-9a-f]{64}$");
def is_hex40: type == "string" and test("^[0-9a-f]{40}$");
def is_posint: type == "number" and . == floor and . > 0;
def is_nonneg: type == "number" and . == floor and . >= 0;
def nonempty: type == "string" and length > 0;
def check(cond; msg): if cond then empty else msg end;
def present(f): (f != null);

# Rules for the body of a manifest. `strict` = active entry: every field is
# required. Otherwise only present, non-null fields are checked.
def body_rules(strict):
  def want(f; cond; msg): if strict or present(f) then check(cond; msg) else empty end;
  want(.wasm_sha256; .wasm_sha256 | is_hex64; "wasm_sha256 must be 64 lowercase hex"),
  want(.wasm_artifact; .wasm_artifact == $artifact; "wasm_artifact must be \($artifact)"),
  want(.source; (.source|type) == "object"; "source block required"),
  (if strict or present(.source) then
     want(.source.git_sha; .source.git_sha | is_hex40; "source.git_sha must be 40 hex"),
     want(.source.git_tag; .source.git_tag | nonempty; "source.git_tag required"),
     want(.source.rust_toolchain; .source.rust_toolchain | nonempty; "source.rust_toolchain required"),
     want(.source.target; .source.target | nonempty; "source.target required"),
     want(.source.soroban_sdk; .source.soroban_sdk | nonempty; "source.soroban_sdk required"),
     want(.source.soroban_env_host; .source.soroban_env_host | nonempty; "source.soroban_env_host required"),
     want(.source.cargo_lock_sha256; .source.cargo_lock_sha256 | is_hex64; "source.cargo_lock_sha256 must be 64 hex"),
     want(.source.ci_run; .source.ci_run | nonempty; "source.ci_run required")
   else empty end),
  want(.usdc; (.usdc|type) == "object"; "usdc block required"),
  (if strict or present(.usdc) then
     want(.usdc.sac_contract_id; .usdc.sac_contract_id | is_c; "usdc.sac_contract_id must be a C strkey"),
     want(.usdc.issuer; .usdc.issuer | is_g; "usdc.issuer must be a G strkey"),
     want(.usdc.expected_name; .usdc.expected_name == ("USDC:" + (.usdc.issuer // "")); "usdc.expected_name must be USDC:<issuer>"),
     want(.usdc.self_issued; (.usdc.self_issued|type) == "boolean"; "usdc.self_issued must be a boolean"),
     (if $net == "public" then
        want(.usdc.issuer; .usdc.issuer == $circle_public; "public: usdc.issuer must be Circle's pubnet issuer \($circle_public)"),
        want(.usdc.self_issued; .usdc.self_issued == false; "public: usdc.self_issued must be false")
      else
        want(.usdc.issuer; (.usdc.issuer == $circle_testnet) or (.usdc.self_issued == true); "testnet: usdc.issuer must be Circle's testnet issuer \($circle_testnet) unless self_issued == true")
      end)
   else empty end),
  want(.governance; (.governance|type) == "object"; "governance block required"),
  (if strict or present(.governance) then
     want(.governance.signers; (.governance.signers|type) == "array" and (.governance.signers|length) > 0 and all(.governance.signers[]; is_g); "governance.signers must be a non-empty array of G strkeys"),
     want(.governance.signers; (.governance.signers // [] | length) == (.governance.signers // [] | unique | length); "governance.signers must not contain duplicates"),
     want(.governance.threshold; .governance.threshold | is_posint; "governance.threshold must be a positive integer"),
     want(.governance.min_threshold; .governance.min_threshold | is_posint; "governance.min_threshold must be a positive integer"),
     want(.governance.threshold; (.governance.threshold // 0) >= (.governance.min_threshold // 0); "governance.threshold must be >= min_threshold"),
     want(.governance.threshold; (.governance.threshold // 0) <= ((.governance.signers // []) | length); "governance.threshold must be <= number of signers"),
     want(.governance.min_lock_duration_seconds; .governance.min_lock_duration_seconds | is_nonneg; "governance.min_lock_duration_seconds must be a non-negative integer"),
     (if $net == "public" then
        want(.governance.threshold; (.governance.threshold // 0) >= 2; "public: governance.threshold must be >= 2"),
        want(.governance.min_threshold; (.governance.min_threshold // 0) >= 2; "public: governance.min_threshold must be >= 2")
      else empty end)
   else empty end),
  want(.policy; (.policy|type) == "object"; "policy block required"),
  (if strict or present(.policy) then
     want(.policy.max_lock_duration_seconds; .policy.max_lock_duration_seconds | is_posint; "policy.max_lock_duration_seconds must be a positive integer"),
     want(.policy.execution_window_seconds; .policy.execution_window_seconds | is_posint; "policy.execution_window_seconds must be a positive integer"),
     want(.policy.ttl_threshold_ledgers; .policy.ttl_threshold_ledgers | is_posint; "policy.ttl_threshold_ledgers must be a positive integer"),
     want(.policy.ttl_extend_to_ledgers; .policy.ttl_extend_to_ledgers | is_posint; "policy.ttl_extend_to_ledgers must be a positive integer"),
     want(.policy.ttl_threshold_ledgers; (.policy.ttl_threshold_ledgers // 0) <= (.policy.ttl_extend_to_ledgers // 0); "policy.ttl_threshold_ledgers must be <= ttl_extend_to_ledgers"),
     want(.policy.instance_ttl_threshold_ledgers; .policy.instance_ttl_threshold_ledgers | is_posint; "policy.instance_ttl_threshold_ledgers must be a positive integer"),
     want(.policy.instance_ttl_extend_to_ledgers; .policy.instance_ttl_extend_to_ledgers | is_posint; "policy.instance_ttl_extend_to_ledgers must be a positive integer"),
     want(.policy.instance_ttl_threshold_ledgers; (.policy.instance_ttl_threshold_ledgers // 0) <= (.policy.instance_ttl_extend_to_ledgers // 0); "policy.instance_ttl_threshold_ledgers must be <= instance_ttl_extend_to_ledgers"),
     want(.policy.network_max_entry_ttl_at_deploy; .policy.network_max_entry_ttl_at_deploy | is_posint; "policy.network_max_entry_ttl_at_deploy must be a positive integer"),
     want(.policy.network_max_entry_ttl_at_deploy; (.policy.network_max_entry_ttl_at_deploy // 0) >= (.policy.ttl_extend_to_ledgers // 0); "policy.network_max_entry_ttl_at_deploy must be >= ttl_extend_to_ledgers (the constructor refuses lower networks)")
   else empty end),
  want(.deploy; (.deploy|type) == "object"; "deploy block required"),
  (if strict or present(.deploy) then
     want(.deploy.upload_tx_hash; .deploy.upload_tx_hash | is_hex64; "deploy.upload_tx_hash must be 64 hex"),
     want(.deploy.tx_hash; .deploy.tx_hash | is_hex64; "deploy.tx_hash must be 64 hex"),
     want(.deploy.ledger; .deploy.ledger | is_posint; "deploy.ledger must be a positive integer"),
     want(.deploy.deployer; .deploy.deployer | is_g; "deploy.deployer must be a G strkey"),
     want(.deploy.stellar_cli_version; .deploy.stellar_cli_version | nonempty; "deploy.stellar_cli_version required"),
     want(.deploy.deployed_at; .deploy.deployed_at | nonempty; "deploy.deployed_at required")
   else empty end),
  want(.evaluator_accounts; (.evaluator_accounts|type) == "array" and all(.evaluator_accounts[]; is_g); "evaluator_accounts must be an array of G strkeys");

[
  check(.schema_version == 1; "schema_version must be 1"),
  check(.network == $net; "network must equal the directory name (\($net))"),
  check(.network_passphrase == $passphrase; "network_passphrase must be \"\($passphrase)\""),
  check((.status == "active") or (.status == "retired"); "status must be active or retired"),
  (if .status == "active" then
     check(.contract_id | is_c; "active: contract_id must be a C strkey"),
     check($file == ((.contract_id // "") + ".json"); "active: file must be named <contract_id>.json"),
     check(.retired == null; "active: retired must be null"),
     body_rules(true)
   elif .status == "retired" then
     check((.retired|type) == "object"; "retired: `retired` block required"),
     check(.retired.reason | nonempty; "retired: retired.reason required"),
     check(.retired.retired_at | nonempty; "retired: retired.retired_at required"),
     check((.retired.superseded_by == null) or (.retired.superseded_by | is_c); "retired: retired.superseded_by must be null or a C strkey"),
     (if .contract_id == $placeholder then
        check($file | startswith("retired-"); "retired: a placeholder contract_id is only allowed in a file named retired-*.json")
      else
        check(.contract_id | is_c; "retired: contract_id must be a C strkey (or the documented placeholder)"),
        check($file == ((.contract_id // "") + ".json"); "retired: file must be named <contract_id>.json")
      end),
     body_rules(false)
   else empty end)
] | .[]
JQ

active_testnet=""
for net in testnet public; do
  dir="$dep/$net"
  [[ -d "$dir" ]] || continue
  case "$net" in
    public) passphrase="$PASSPHRASE_PUBLIC" ;;
    testnet) passphrase="$PASSPHRASE_TESTNET" ;;
  esac
  active_ids=()
  shopt -s nullglob
  for f in "$dir"/*.json; do
    rel="${f#"$root/"}"
    base="$(basename "$f")"
    if ! jq -e . "$f" >/dev/null 2>&1; then
      violation "$rel" "not valid JSON"
      continue
    fi
    while IFS= read -r msg; do
      [[ -n "$msg" ]] && violation "$rel" "$msg"
    done < <(jq -r --arg net "$net" --arg file "$base" --arg passphrase "$passphrase" \
                --arg circle_public "$CIRCLE_PUBLIC_ISSUER" --arg circle_testnet "$CIRCLE_TESTNET_ISSUER" \
                --arg placeholder "$PLACEHOLDER_ID" --arg artifact "$ARTIFACT" \
                "$JQ_PROGRAM" "$f")
    if [[ "$(jq -r '.status' "$f")" == "active" ]]; then
      active_ids+=("$(jq -r '.contract_id' "$f")")
    fi
  done
  shopt -u nullglob
  if (( ${#active_ids[@]} > 1 )); then
    violation "deployments/$net" "exactly one active entry allowed, found ${#active_ids[@]}: ${active_ids[*]}"
  elif (( ${#active_ids[@]} == 0 )); then
    if (( require_active )); then
      violation "deployments/$net" "no active entry (--require-active)"
    else
      echo "notice: deployments/$net has no active entry (transitional: retired instance, next deploy pending)"
    fi
  else
    echo "ok: deployments/$net active instance ${active_ids[0]}"
    [[ "$net" == "testnet" ]] && active_testnet="${active_ids[0]}"
  fi
done

# Terraform equality check (ci.yml feeds terraform from this secret).
tf_id="${TF_VAR_testnet_soroban_contract_id:-}"
if [[ -z "$tf_id" ]]; then
  echo "notice: TF_VAR_testnet_soroban_contract_id is empty; terraform equality check skipped"
elif [[ -n "$active_testnet" ]]; then
  if [[ "$tf_id" == "$active_testnet" ]]; then
    echo "ok: TF_VAR_testnet_soroban_contract_id equals the active testnet manifest"
  else
    violation "terraform" "TF_VAR_testnet_soroban_contract_id ($tf_id) != active testnet manifest ($active_testnet)"
  fi
else
  msg="TF_VAR_testnet_soroban_contract_id is set ($tf_id) but deployments/testnet has no active entry; terraform points at a retired or unrecorded instance — deploy via docs/runbooks/deploy-soroban.md and add the manifest"
  if (( require_active )); then
    violation "terraform" "$msg"
  else
    echo "::warning::$msg"
  fi
fi

if (( fail )); then
  echo "error: manifest validation failed" >&2
  exit 1
fi
echo "ok: manifests valid"
