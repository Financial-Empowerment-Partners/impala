# Soroban deployment manifests

One file per deployed `MultisigUsdcWrapper` instance at
`<network>/<contract_id>.json`. This directory is the **record of which
issuer, signer set and WASM each instance was constructed with** — the one
binding the contract itself cannot decide (it pins *an* issuer via the SAC's
`name()`; only this record says whether that issuer is Circle's).

Rules:

- **Append-only — retire, never delete.** An instance that is taken out of
  service gets `"status": "retired"` with a `retired` block; its file stays.
- **Exactly one `active` entry per network** once a network has a deployed
  instance. A directory holding only retired entries is the transitional
  state between a retirement and the next deploy (`check-manifests.sh` prints
  a notice; `--require-active` makes it fatal).
- **Public (mainnet) entries** must use Circle's pubnet issuer
  `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`,
  `"self_issued": false`, `threshold >= 2` and `min_threshold >= 2`.
  Testnet entries use Circle's testnet issuer
  `GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5` unless
  `"self_issued": true` (throwaway e2e issuers only).
- **No secret ever belongs here** — public identifiers only (contract ids,
  G-addresses, hashes, versions, URLs).
- `terraform/variables.tf` `testnet_soroban_contract_id` (fed from the CI
  secret `TF_VAR_testnet_soroban_contract_id`) must equal the active testnet
  entry: `scripts/check-manifests.sh` compares them when the variable is set
  (the `impala-soroban.yml` contract job passes the secret through).

## Files

| Path | Meaning |
|---|---|
| `TEMPLATE.json` | The skeleton for the next `active` entry. `<placeholder>` values are filled by the operator following `docs/runbooks/deploy-soroban.md`; the file is not validated as a manifest (it lives outside the network directories). |
| `testnet/retired-pre-constructor-instance.json` | The instance that predates this record and the constructor ABI. Its id is only known to the CI secret `TF_VAR_testnet_soroban_contract_id`, so `contract_id` carries that literal placeholder; when the owner reads the secret, rename the file to `<C…>.json` and replace the placeholder (the checker then enforces the strkey format). Unknown historical fields are `null`. |

## Schema (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "contract_id": "C…",
  "wasm_sha256": "<64 hex == on-chain ContractCode hash == `stellar contract upload` output == deploy --wasm-hash>",
  "wasm_artifact": "soroban_impala_integration_test.wasm",
  "source": {
    "git_sha": "<40 hex>", "git_tag": "impala-soroban-v0.2.0", "rust_toolchain": "1.96.0",
    "target": "wasm32-unknown-unknown", "soroban_sdk": "23.5.3", "soroban_env_host": "23.0.1",
    "cargo_lock_sha256": "<64 hex>", "ci_run": "https://github.com/…/actions/runs/…"
  },
  "usdc": { "sac_contract_id": "C…", "issuer": "G…", "expected_name": "USDC:G…", "self_issued": false },
  "governance": { "signers": ["G…"], "threshold": 2, "min_threshold": 2, "min_lock_duration_seconds": 86400 },
  "policy": {
    "max_lock_duration_seconds": 7776000, "execution_window_seconds": 2592000,
    "ttl_threshold_ledgers": 518400, "ttl_extend_to_ledgers": 2764800,
    "instance_ttl_threshold_ledgers": 120960, "instance_ttl_extend_to_ledgers": 518400,
    "network_max_entry_ttl_at_deploy": 3110400
  },
  "deploy": {
    "upload_tx_hash": "<64 hex>", "tx_hash": "<64 hex>", "ledger": 0, "deployer": "G…",
    "stellar_cli_version": "<stellar --version>", "deployed_at": "2026-09-05T00:00:00Z"
  },
  "evaluator_accounts": ["G…"],
  "status": "active",
  "retired": null
}
```

`retired` (when `status == "retired"`):
`{ "reason": "…", "superseded_by": "C…" | null, "retired_at": "<ISO-8601>" }`.

Field notes:

- `wasm_sha256` is `sha256(wasm)`, which is also Soroban's on-chain
  `ContractCode` hash: it is printed by `stellar contract upload`, it is the
  `--wasm-hash` deploy parameter, and CI prints it in the job summary and
  `build-info.json` (`source.*` is copied from that file).
- `policy.*` are the contract constants at the time of deploy
  (`MAX_LOCK_DURATION`, `EXECUTION_WINDOW`, the persistent and instance TTL
  policies) plus the network's `max_entry_ttl` as read from
  `max_entry_ttl()` right after deploy. The constructor refuses a network
  whose `max_entry_ttl` is below `ttl_extend_to_ledgers`.
- `evaluator_accounts` are the holder accounts the keep-alive job bumps with
  `bump_entry_ttl`; they hold no authority.
- `governance.signers` are public keys only. In a fresh entry they are
  `<placeholder>` until the signer ceremony has produced them.

## Tooling

- `scripts/check-manifests.sh [--require-active]` — offline schema and policy
  validation (runs in CI on every push touching `impala-soroban/`).
- `scripts/verify-deployment.sh <manifest.json> [--source <identity>]` — reads
  the chain: on-chain WASM hash, `stellar contract id asset` for
  `USDC:<issuer>`, the contract's `usdc_token()`, `usdc_issuer()`,
  `min_threshold()`, `min_lock_duration()`, `multisig_config()` and
  `max_entry_ttl()`, the SAC's `name()`, and the deploy transaction.
- `docs/runbooks/deploy-soroban.md` — the deploy / verify / retire procedure
  that produces and consumes these files.
