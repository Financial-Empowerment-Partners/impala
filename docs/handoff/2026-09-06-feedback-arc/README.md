# Handoff — reviewer-feedback arc (stopped 2026-09-06 for human testing)

This directory is the state of the "evaluate `payala-impala-feedback.txt` and
improve the most important aspects and security concerns" arc at the point
the owner asked to stop and begin human testing. Everything below is
uncommitted in the working tree; nothing here was tagged or released.

## Status at a glance

| Lane | State | Gate at handoff |
|---|---|---|
| Card protocol v1 (applet 0.2 + SDK + interop tests + `docs/apdu.md`, `docs/transfer-protocol.md`, card README) | **landed** | `./gradlew :sdk:jvmTest` 214 tests, CAP built and verified (JDK 17) |
| Soroban `MultisigUsdcWrapper` hardening (constructor, issuer pin, persistent storage, reservations, current-config execution, proptest invariants, manifests, CI) | **landed** (owner items open, see below) | `cargo test` 125 + artifact gate, clippy/fmt/deny clean, release WASM sha256 `929d95e6…5378` |
| Bridge A — custodial payment intents/idempotency, custodial policy (pause + caps), `ManageCustody`/`ReadCustody`, positions + daily snapshot, coded refusals | **landed** | `cargo test` 875, clippy/fmt clean, UI 240 |
| Bridge B — replenishment hash-before-submit, admin-keys outbox fix, `docs/conservation-spec.md`, opt-in DB test lane, `bridge-db-tests` CI job | **landed** | as above; DB lane 9/9 against postgres:16 locally |
| Bridge C1 — issuer key custody, `POST /admin/cards/{id}/certificate`, `GET /card-issuer`, shared golden vectors, `scripts/check-shared-vectors.sh` | **not started** (a 13-minute partial run was fully reversed) | — |
| Bridge C2 — offline issuance / redemption (migration 038) | **not started** | — |
| Documentation phase (README/ARCHITECTURE rewrite, capability matrix, known limitations, threat model, roadmap, deployments, SCF templates, docs guards) | **not started** | — |
| Adversarial verification of the landed code (phase 4) | **not run** | — |

Earlier in the same session (also uncommitted, also green): the reserve watcher
now persists the prepared transaction hash on `payout_attempt` / `refund_intent`
rows before submitting, and order expiry is keyed on Horizon's ingestion head
behind the freshness gate (`reserve_watch.rs::record_intent_hash`,
`drain_deposits`).

## What human testers need to know

**Bridge**
- Run migration `037_custodial_conservation.sql` (`RUN_MODE=migrate`) before
  starting the new binary; it is operator-invoked like every migration.
- After migrating, `POST /managed-account/sign` **refuses** until an operator
  sets both caps: `PUT /admin/custody/policy` with `per_tx_max_stroops` and
  `per_account_daily_max_stroops` greater than zero (house rule: 0 means
  unconfigured, refuse). `POST /admin/custody/pause` / `resume` (resume is
  admin-only with a confirm phrase). Per-account override:
  `PUT /admin/custody/accounts/{account_id}/limit`.
- The sign endpoint now takes an optional `idempotency_key`; replays return the
  original outcome, a different request under the same key is a 409, an
  ambiguous submit answers 202 with an intent id you can poll at
  `GET /managed-account/intents/{intent_id}`. Refusals carry a machine-readable
  `error.code`.
- Positions: `GET /admin/reconciliation/positions` (auditor/treasurer/admin);
  daily snapshot job configured by `RECONCILIATION_SNAPSHOT_UTC_HOUR`,
  `RECONCILIATION_MAX_ACCOUNTS`, `RECONCILIATION_DEADLINE_SECS`.
- Full endpoint list: `impala-bridge/openapi.yaml` (custody and reconciliation
  tags). Admin UI gained a Custody page and a reserve drift badge.

**Card (applet 0.2)**
- Already-flashed 0.1 cards are not upgradable in place: reflash the CAP and
  run the issuance ceremony in `impala-card/docs/transfer-protocol.md`
  (install with custom SCP03 keys, INITIALIZE, PERSONALIZE A/B/C, PROVISION_PIN).
- Behaviour changes visible to existing clients: `SIGN_AUTH` on an
  unpersonalized card answers `0x6234` (the Android demo login against a blank
  card now fails at the card); `GET_EC_PUB_KEY` before INITIALIZE answers
  `0x6230`; the old INS `0x06`/`0x14` answer `0x6D00`. The new commands and
  every status word are in `impala-card/docs/apdu.md`.
- The bridge does not yet issue certificates or program ids (lane C1), so a
  card can be personalized today only with a test issuer such as
  `IssuerFixture.kt`; `VERIFY_TRANSFER_V2` requires a certified sender.

**Soroban**
- The contract now deploys through `__constructor(signers, threshold,
  min_threshold, usdc_token, usdc_issuer, min_lock_duration)`; `initialize`
  is gone. The previously deployed testnet instance is marked retired in
  `impala-soroban/deployments/testnet/` with a placeholder id; deploy a fresh
  instance per the README's Deploy section and write the first active manifest
  from `deployments/TEMPLATE.json`.

## Decisions taken (binding for the remaining work)

`contract-addendum.md` fixes the card ⇄ bridge wire contract the two specs
disagreed on: the card's 114-byte `IMPALA-CERT:` certificate and 89-byte
`IMPALA-XFER:` envelope are the truth; the bridge must sign and verify those,
`transfer_id = SHA-256(XFER)`, no age/skew checks on `dateTime`, jump bound
1024, bridge-generated `program_id`. It also records the scope calls: build
issuance/redemption dormant (policy disabled, caps 0), Soroban wrapper stays
standalone/informational, USDT0 listed outside accepted SCF scope until
confirmed, the card personalization change resolves KL-C1.

Inputs kept here: `phase1-verified-map.json` (line-cited verification of every
reviewer claim), `spec-card.md`, `spec-soroban.md`, `spec-bridge.md`,
`spec-docs.md` (judge-panel syntheses), `docs-for-card-lane.md`, and the four
lane reports (`lane-report-*.json`: landed / deviations / unfinished / risks —
read the `risks` lists before human testing).

## Remaining work for the next session (in order)

1. **Bridge C1** — `spec-bridge.md` §8.1–8.3 with the addendum (§A) applied,
   plus the card spec §9.6 bridge mirror constants and golden tests in
   `card_auth.rs`, `scripts/check-shared-vectors.sh`, and its two CI steps.
   The card workflow already carries a guarded step that runs the script when
   it exists (`impala-card.yml`, "Check shared card/bridge vectors"); the
   `ci.yml` bridge-job step is still to add.
2. **Bridge C2** — `spec-bridge.md` §8.4–8.9 (issuance, funding match,
   issue/ack/expire, redemption verifier + watcher driver, admin, events),
   then §10 clients (`impalactl` `--idempotency-key`/intent commands, UI).
3. **Docs phase** — `spec-docs.md` in its §15 order: `docs/README.md`
   conventions; `scripts/check-doc-claims.py` + `scripts/docs-check/banned-claims.txt`;
   `.github/workflows/docs.yml` and `Justfile lint-docs`;
   `docs/known-limitations.md`, `docs/capability-matrix.md`,
   `docs/threat-model.md`, `docs/roadmap.md`, `docs/deployments.md` +
   `deployments/README.md`, `docs/scf/*`; then the README/ARCHITECTURE
   rewrite and the §14 edits (SECURITY.md admin section, CHANGELOG migration
   numbers, CONTRIBUTING threat-model pointer, soroban/bridge READMEs, iOS
   status, runbook token fixes). Cross-links to `docs/conservation-spec.md`
   from ARCHITECTURE, runbooks README and SECURITY.md are also pending.
4. **CI components still open**
   - `docs.yml` (docs guards) — not created.
   - `ci.yml`: bridge-job step for `scripts/check-shared-vectors.sh`; terraform
     job equality step calling `impala-soroban/scripts/check-manifests.sh --require-active`
     once an active manifest exists.
   - `bridge-db-tests` job exists in `ci.yml` but has not yet run in GitHub
     Actions (validated locally only).
   - `impala-soroban.yml`: `keepalive-verify` stays `workflow_dispatch`-only
     until the owner adds `STELLAR_TESTNET_KEEPER_SECRET`; the Docker
     reproducibility check stays non-gating until it passes on a tag; the
     first testnet deploy through the runbook, the constructor-arg CLI syntax
     and `--send=no` spelling are to be confirmed on the first manual run.
   - Release tags are owner decisions: `impala-card-v0.2.0`,
     `impala-soroban-v0.2.0`, `scf-baseline` / `scf-t1`.
5. **Phase 4 adversarial review** of everything landed (find → verify → fix),
   with verifiers told to mutation-test the new tripwires and to probe the
   reserve/custody SQL against a live Postgres (the opt-in DB lane exists:
   `RUN_DB_TESTS=1 DATABASE_URL=… cargo test --test db`).

To resume the implementation workflow with the cached lane results:
`~/.claude/projects/-Users-user-sonoranpub-impala/46324de6-bc0d-4c25-9dce-de2b8e48a6c2/workflows/scripts/feedback-phase3-implement-wf_4edf707c-7b3.js`
(run id `wf_4edf707c-7b3`). Lane C1 must run again from the start; its partial
edits were reversed.

## Incident during the stop (read before trusting `reserve.rs`)

While reversing C1's partial edits, a reversal script truncated
`impala-bridge/src/exchange/reserve.rs` to zero bytes (Python opened the file
for writing before its replace call failed). The file was rebuilt from the
line-numbered reads the phase-2 agents made while the file was unchanged
(two independent complete reads, no conflicts across all 2027 lines), plus the
one later edit lane A made to it (the `ConversionReserve::account_id()`
accessor). Verification after the rebuild: `cargo test` 875 passed (including
the string-pin tests, the migration/constant tripwires and the
`include_str!` conservation-spec test over this file), `cargo clippy -- -D warnings`
clean, `cargo fmt --check` clean. The reconstruction inputs are in the session
scratchpad (`reserve-evidence.json`, `reconstruct_reserve.py`); a manual read
of the file's USDT0 sections is still recommended before release.
