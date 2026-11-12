# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Impala is a polyglot monorepo for a **custodial Stellar/Payala money bridge**. Wrong code here loses real funds or leaks spend authority — correctness conventions below are load-bearing, not style. There is no root build system; each sub-project builds and tests independently (prerequisites and versions: `DEVELOPMENT.md`; system design: `ARCHITECTURE.md`; operations: `docs/runbooks/`).

## Commands

### impala-bridge (Rust / Axum — the server of record)
```bash
cd impala-bridge
cargo test                          # unit tests, no DB/Redis needed (they run in-process)
cargo test <name>                   # single test by substring
cargo clippy -- -D warnings        # CI gate: warnings are errors
cargo fmt
cargo run                           # RUN_MODE=server (default) | worker | migrate
docker compose up --build           # Postgres 16 + Redis 7 + bridge :8080
```
Migrations are **operator-invoked** (`RUN_MODE=migrate`), never run at startup. Run new migrations before rolling a binary that depends on them (e.g. a role/CHECK widening). Minimum env: `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET` (≥32 chars) — see `.env.example`; the full env surface is parsed in `src/config.rs`.

### impala-ui (vanilla-JS admin dashboard — no build step)
```bash
cd impala-ui
npm test                            # Vitest, environment: node (no jsdom)
npx vitest run tests/roles.test.js  # single suite
npm run lint                        # eslint over html/js ONLY (tests/ are ESM and not linted)
docker compose up                   # Nginx :3000; bring impala-bridge up first (shared Docker network)
```

### lumencli (Go CLI wallet)
```bash
cd lumencli
make verify                         # fmt-check + vet + test + race + build
go test -run '^TestName$' ./internal/cli
go test ./internal/cli -update      # regenerate golden files (review the diff — schemas are frozen)
make cross                          # six-platform release build into dist/
make verify-linux                   # full suite on linux/arm64 + amd64 in Docker (OrbStack on macOS)
scripts/testnet-smoke.sh [--record] # opt-in live-testnet E2E; --record refreshes the recorded Horizon fixture
```

### impalactl (Go operator CLI)
```bash
cd impalactl && go test ./... && go build ./...
```

### Others
```bash
cd impala-soroban/integration-test && cargo test          # in-process; testnet-tests/ needs stellar-cli
cd impala-card && ./gradlew :applet:jvmTest :sdk:jvmTest :simulator:jvmTest :tools:issue:test   # applet units + SDK + simulator + issuance tool on jcardsim
cd impala-card && ./gradlew :applet:buildJavacard [-Papplet.ed25519=soft|native|none]              # the CAP; one Ed25519 engine per CAP (soft = default, JavaCard 3.0.5)
cd impala-card && ./gradlew :simulator:capMatrix                                                   # which JavaCard levels load each built CAP (build the three variants first); :simulator:serve --args="--platform jc32" serves one simulated card over TCP
cd impala-lib && ./gradlew testDebugUnitTest              # Robolectric
cd impala-android-demo && ./gradlew testTnetDebugUnitTest testLiveDebugUnitTest   # :app:e2eTnetDebug = live-bridge card lane (app/src/e2e/README.md)
cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
cd demo && scripts/doctor.sh && scripts/run-all.sh --smoke   # the full-suite testnet demo (containers + jcardsim + emulator + the Payala stub; the bridge runs with SEP-10 on); scripts/run-all.sh --only <step> (e.g. scenario-12-sep10-bridge, scenario-13-sep10-third-party); shellcheck -S warning -x -P SCRIPTDIR scripts/*.sh scripts/payala/*.sh; node --test payala-stub/server.test.mjs; python3 scripts/sep10-challenge.py "$(cat scripts/testdata/sep10-challenge.b64)" | jq -S . | diff - scripts/testdata/sep10-challenge.json
```

## Architecture — what you must know before editing

**The bridge is the source of truth; everything else is a client.** impala-ui, impalactl, lumencli (Horizon-only, no bridge), the Android demo, and the card SDK all consume server-enforced contracts. UI/CLI-side gating is display convenience — never a security boundary.

**Auth has two credential paths that must not diverge** (`impala-bridge/src/auth.rs`, `validate_request_auth`): bearer temporal JWTs (role stamped at issuance from the DB role + `ADMIN_ACCOUNT_IDS` allowlist; HS256 with pinned iss/aud/type; ≤1h life) and `__Host-` session cookies (CSRF-checked; carry only admin-or-view-only — granular roles ride the bearer path). Revocation is a Redis auth-epoch bump, checked **fail-closed** on every request; role grants and account deletions bump the target's epoch, so grants take effect at the target's next sign-in. A bad `Authorization` header never falls back to the cookie path.

**RBAC is a capability matrix, in exactly one place.** Seven roles (`constants.rs::ALL_ROLES`): the view-only/device/token/admin ladder plus three lateral privileged roles (treasurer = reserve money ops, key-custodian = keys/seeds, auditor = read-only oversight; none includes another, admin is the superset and the only governance role). `auth.rs::role_has_capability` is THE table; routes are gated at the type level via `Privileged<Capability>` extractors (and legacy `AdminUser` for governance). The matrix is mirrored for UI gating in `impala-ui/html/js/roles.js` and both sides assert against the shared fixture `impala-ui/tests/fixtures/role-capabilities.json` — change role/capability semantics only by editing all three together.

**Tripwire tests are guard rails, not incidental tests.** `auth.rs` tests `include_str!` the migration files and handler sources to pin (a) the migration CHECK list against `ALL_ROLES` and (b) **every privileged handler's exact extractor by name**. If your change trips one, update it consciously — they exist because "forgot to swap one handler" and "migration/constant drift" are the two bug classes that compile clean and pass every other test.

**Money conventions (recurring house rules across the bridge and lumencli):**
- Integer minor units everywhere (stroops/cents), summed in `big.Int`/`i64` — floats never touch money.
- Guarded single-statement SQL updates with `UNIQUE` idempotency anchors; write-ahead intent rows before on-chain submits; fail closed on ambiguity (an unverifiable state is refused, not assumed).
- Fees are per-*transaction* while walks are per-*operation*: any fee aggregation must dedupe by tx hash.
- Horizon wire realities: fields like a failed path payment's execution leg arrive as `"0.0000000"` placeholders, never absent — discriminate on transaction outcome, not field presence.
- widening a shared `INSERT`'s column list is a runtime money-path bug the compiler cannot see (sqlx runtime queries; there are no DB-executing tests) — recount every bind site.

**Reserve engine flow** (`impala-bridge/src/exchange/`): quote (price lock holds capacity) → order → deposit watcher (`reserve_watch.rs`) matches inbound payments → payout/refund submits (ambiguous submits freeze `on_hold`, never auto-retry) → admin resolution (`handlers/admin_reserve.rs`) which must verify on-chain state before releasing holds or crediting reversals. Replenishment (`replenish.rs`) spends real reserve funds under per-cycle/daily caps. Provider webhooks (`exchange_webhook.rs`) verify HMAC over the raw body before parsing.

**Reserve assets are issuer-pinned, in one place.** The reserve recognizes money by `(asset_code, issuer)` — never by code alone (codes are not unique on Stellar) and never by the `credit_alphanum4`/`credit_alphanum12` type tag. `ConversionReserve::stablecoins()` (`exchange/reserve.rs`) is THE list — USDC always, USDT0 when `RESERVE_USDT0_ISSUER` is set — and every asset decision (`bucket_for_asset`, `asset_for_bucket`, `is_asset_issuer`, trustline audit, admin balances) goes through it; adding a stablecoin means adding to that list plus a bucket seed migration, not a new `match`. Issuers are operator configuration validated with a strkey checksum (`validate_stellar_account_id_checksum`), never constants. Orders persist the stablecoin leg they were created with (`provider_payload.deposit_currency` / `hold_currency`) so config changes never re-interpret existing orders; provider tickers for USDT0 are operator-supplied (`RESERVE_USDT0_TICKERS`), never guessed. Trustlines on the generate-only reserve account can only be added through `POST /admin/exchange-reserve/trustlines` (the seed exists nowhere else).

**Card sign-in has two mechanisms and one session** (`docs/sep10-card-keys.md` is the byte-level contract across card, SDK, impala-lib, bridge and app). Applet 0.3 cards hold a second, Ed25519 "Stellar key" and sign in with SEP-10 (`/auth/sep10`); every card still supports the legacy `SIGN_AUTH` challenge (`/auth/card`), and both mint the same session.
- SEP-10 never mints a privileged session: an account whose role holds any capability (`auth::role_is_privileged`, which includes `ADMIN_ACCOUNT_IDS` admins) gets the generic 401 and its card signs in the legacy way. The route is public and wildcard-CORS; do not remove the check to "fix" an admin's card login.
- The Stellar key signs exactly two things: once, at `PERSONALIZE`, a fixed proof message; and the hash of a transaction the **card itself** parsed and found to be a SEP-10 challenge for its key (`applet/Sep10.java`: sequence 0, manage-data only). Never add a path that signs a host-supplied hash or message with it; that property is what makes the key unable to move funds. The engines' self-tests use RFC 8032 test keys, never the card's key, and a staged challenge is discarded by anything but the next accepted part (`process()` takes it out of service first).
- One CAP, one Ed25519 engine (`-Papplet.ed25519`): `Ed25519Soft` (JavaCard 3.0.5, ECDH on Wei25519 plus 16-bit applet arithmetic), `Ed25519Native` (the platform's EdDSA: converted for JavaCard 3.1, runs on 3.1 and 3.2 cards) or none. The simulator holds all of them (`SimulatorBibo(ed25519 = …)`); `Ed25519Provider` in `src/jvmMain` is the simulator's, the CAP ones live in `applet/src/cap/`. Applet code is 16-bit JavaCard: no `int`, and it must still convert (`:applet:buildJavacard`) after any change.
- The CAP's API level is a compatibility contract (`impala-card/README.md`, "Platform dependencies"): `soft` and `none` are converted for JavaCard 3.0.5 (imports 1.6/1.6/1.6), `native` for 3.1 (1.8/1.7/1.7), nothing for 3.2. Code shared by the variants may use only what the 3.0.5 API has (and only the 3.0.1 API if `buildJavacardLegacy` is to keep converting); anything newer belongs in `Ed25519Native`. Raising a target or an import version shrinks the set of cards the CAP loads on, and an optional algorithm must be probed at install so its absence costs the Stellar key, never the install.
- Tests reach jcardsim only through `:jcardsim-jc31` (jcardsim plus the JavaCard 3.1 / 3.2 EdDSA API and the hardware model); a direct `com.klinec:jcardsim` dependency next to it shadows the patched API classes.
- A simulated card is a CAP on hardware (`SimulatorBibo(ed25519 = …, platform = CardPlatform.…)`; `impala-card/README.md` "Simulated hardware"): `CardPlatform` presets are card models from JavaCard 3.0.5 (`jc305`) to 3.2 (`jc32`), each with or without the optional algorithms, and a CAP the hardware would not load is refused (`CapNotLoadableException`). What every (card model, CAP) pair yields is a contract pinned by `CardHardwareInteropTest`, which fails when a preset is added without a row. `Card.execute { }` scopes simulated API calls to one card (never Kotlin's `card.run { }`: that is the stdlib scope function and does not make the card current). `CapVariant`'s import versions mirror the build and are checked against the real CAP files by `:simulator:capMatrix` in CI: change a CAP's `targetsdk` and that table together or not at all.
- The native engine asks a card for pure Ed25519 three ways, in order (`SIG_CIPHER_EDDSA` with `ALG_NULL`, with `ALG_SHA_512`, then the JavaCard 3.2 cipher `SIG_CIPHER_EDDSA_ED25519` by value, since the CAP is converted against the 3.1 API), and keeps the first that passes its verify-and-sign self-test. Add a candidate only behind that self-test, and never reorder them: the order is what keeps the choice on existing cards unchanged.
- The client fallback from SEP-10 to the legacy challenge has exactly three cases and lives in one function (`impala-lib` `CardSignIn.fallbackFor`); a failed check (bad challenge, lockout, card refusal) is an error, never a downgrade.
- The admin status object says what the *answering instance* can serve (`key_ring_live`, per-key `opened`), and `opened` is the activation gate's own test (`opened_here` and `check_ring_can_serve` in `handlers/admin_sep10.rs`, pinned together by a test): change them together. The dashboard holds Activate on the same field (`Sep10View.activationHold`).
- Bridge side: the identity is the active `card` row by `stellar_address`, set only after both card cross-signatures verify against messages rebuilt server-side (`sep10/binding.rs`, via `POST /card` or `PUT /card/stellar-key`), with `card.stellar_key_registered` emitted in the same transaction. The lookup by address casts its parameter (`$1::bpchar`): a `text` bind against a `CHAR` column skips the index. The server signing key is generate-only like the issuer key. Card and bridge pin the same vectors (`scripts/check-shared-vectors.sh`, `sep10/card_vectors.rs`, `BridgeVectorTest.kt`): change bytes on both sides or not at all.

**Key custody:** provider credentials and custodial seeds are install-only via `/admin/keys*` (or safer, `impalactl keys import`); nothing returns secret bytes in any response, log, or event — payloads carry fingerprints only. The conversion-reserve seed and the card program issuer key (`/admin/card-issuer/generate`, migration 039) are **generate-only** (an imported reserve seed would put the pool's signing key in a person's hands; an imported issuer key, mint authority over every card). Seed material at rest is envelope-protected (KMS/Vault/OpenBao, `seed_protect/`); there is deliberately no plaintext-at-rest path.

**Machine-readable schemas are append-only contracts**: lumencli `--json`/`--csv`, the bridge event-outbox payloads (`events.rs`, no PII/secrets ever), and `openapi.yaml`. lumencli pins its exact output bytes with golden files (`testdata/`, `-update` flag) plus a recorded real-Horizon page; its fake-Horizon fixtures pass an "honesty gate" (round-trip through the SDK unmarshaller + required-wire-field lists) so tests can't certify JSON that never occurs on the wire.

**impala-ui conventions:** static files served by Nginx — no bundler, no transpile. Modules are IIFEs exposing one named global; script order in each HTML page is the dependency graph. Vitest runs in plain node with **no jsdom** — put testable logic in DOM-free pure modules (the `keys-view.js` / `reserve-math.js` / `Router.linksForRole` pattern) and keep DOM controllers thin. Escape all dynamic HTML through `EscapeHtml.escape` (it escapes `& < >` but **not quotes** — never interpolate into attribute value contexts); role keys used as CSS classes are whitelisted via `Roles.isKnownRole`, and unknown role claims must degrade to neutral display + view-only gating (deploy-skew safety). Per-network JWTs live in namespaced localStorage keys (`api.js`).

**CLI conventions (lumencli/impalactl):** data on stdout, notices/prompts on stderr; exit 0/1/2, plus **3 = ambiguous outcome** (a fund-moving submit whose fate is unknown — the notice carries the transaction hash and says do not re-run; never collapse it into 1); secrets never in argv (env var, no-echo prompt, or stdin); identifiers printed in full, never truncated; mainnet fund-moving commands require explicit confirmation, and the missing-memo guard's override is deliberately separate from `--yes`.

## Gotchas

- The demo stack (`demo/`) runs the bridge with SEP-10 on and the home domain `10.0.2.2:$BRIDGE_PORT` (the emulator's name for the host): host-side clients must keep that name and alias the address (`sep10_curl` in `demo/scripts/lib.sh`, `Sep10E2e.AliasedTransport`), never change the home domain to suit the host. Custody writes (seeds, issuer key, SEP-10 key, card certificates) share one budget of 5 per 60 s per operator: a script that makes a sixth has to wait and retry, as `seed.sh`, scenario 05 and `E2e.issue` do.
- `ADMIN_ACCOUNT_IDS` overrides the stored DB role to admin at every token issuance — the accounts API/UI mark such accounts `allowlisted` ("effective admin"); treat the allowlist as break-glass, incompatible with granular scoping.
- `JWT_SECRET` rotates with zero downtime via `JWT_SECRET_PREVIOUS` overlap (see `docs/runbooks/rotate-secrets.md`).
- `cargo test` (992) runs with no Postgres/Redis (an opt-in DB lane, `RUN_DB_TESTS=1 DATABASE_URL=… cargo test --test db`, executes the pinned SQL against a real Postgres): SQL is pinned by string/tripwire tests only, so schema-vs-query drift is a runtime failure class — double-check migrations against every query touching changed tables.
- lumencli's `verify-linux` pins `--platform` on every `docker run`; a bare image tag silently resolves to whichever arch was pulled last.
- Do not run `git checkout -- <file>` to "restore" during experiments on uncommitted work — it restores HEAD and destroys in-flight changes; mutate copies outside the repo instead.
- CI workflows are path-filtered per sub-project; the workflow file itself belongs in its own path filter.
