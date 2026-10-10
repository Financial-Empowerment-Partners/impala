# Impala demo suite — the whole system on Stellar testnet

A self-contained kit that stands up Impala on a laptop and walks it through real **Stellar testnet**
money flows, with every claim checked by a script and every testnet transaction id printed in full
(Horizon and stellar.expert links) and logged. It uses the three mechanisms the project is built on:

| Mechanism | What runs there | Why |
|---|---|---|
| **Docker or Podman** — one `compose.yaml`, project `impala-suite` | postgres 16, redis 7, OpenBao (dev mode: Transit seal + OIDC test IdP), an OTLP collector, `impala-migrate` (the operator-run `RUN_MODE=migrate` step), `impala-bridge` built from this checkout, `impala-ui` (nginx), and `payala-stub` — an in-repo stand-in for the Payala API (`payala-stub/`: one dependency-free Node module on the public `node:22-alpine` image; the proprietary Payala API is not part of the demo) | the server of record and its dependencies are containers in every real deployment |
| **JavaCard simulator** — host JVM 17 | the real `ImpalaApplet` on jcardsim behind a TCP APDU socket (`impala-card :simulator:serve`), issued by the issuance ceremony (`tools/issue`) against the bridge's card program | jcardsim is the oracle every card test already uses; no reader or card needed |
| **Android emulator** — API 34, Google APIs, arm64, headless by default | the demo app's `tnet` flavor reaching the bridge at `10.0.2.2:8080` and the simulated card through `adb reverse`; `CardLoginUiTest` drives the real login screen | the phone is the holder's device; the emulator has no NFC, so the debug TCP card transport stands in |

Plus the two CLIs built from this checkout: `lumencli` (a self-custody wallet) and `impalactl` (the
operator client). It generalises the external Payala ↔ Impala kit: the relay scenarios from that kit are
included, running against the Payala stub instead of the proprietary Payala API.

```
 host scripts (bash 3.2 / curl / jq / openssl)        ┌─ host JVM 17 ──────────────────────────────┐
   scripts/run-all.sh ──► doctor → prepare → build    │ jcardsim ImpalaApplet  :9443  ◄── tools/issue│
      → up → seed → scenario-01..11 → verify          │ Android emulator (API 34) ──adb reverse──┘   │
      every testnet tx id → state/testnet-txids.tsv   │   tnet app ──► 10.0.2.2:8080                 │
                                                      └──────────────────────────────────────────────┘
 ┌──────────────────── compose project impala-suite (docker or podman) ────────────────────────────┐
 │ impala-ui :3000 ──► impala-bridge :8080 ──► Stellar testnet (Horizon)                             │
 │                     │ postgres · redis · openbao :8200 (Transit + OIDC) · otel-collector           │
 │                     │ impala-migrate (one-shot RUN_MODE=migrate)                                   │
│ payala-stub :4000 — the in-repo stand-in for the Payala API (the relays' counterparty)             │
 └───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Not in scope, said plainly.** Mainnet; the production topology (ECS/terraform); physical cards
and readers (the fleet check in scenario 05 points at them); the offline stored-value ledger —
`/offline/*` is not built, so the card lanes end at **card login** (the Android *Load card* / *Redeem*
flows and `CardTransferE2ETest` skip, and the suite says so); the exchange/reserve engine (needs
provider credentials; the reserve stays unconfigured).

## 1. Quick start

```bash
cd demo
scripts/doctor.sh        # what this host can run (engine, testnet, JDK 17, Android SDK, optional lanes)
scripts/run-all.sh       # the whole suite with a scorecard; add --smoke for stack + payment only
```

`run-all.sh` is `doctor → prepare → build → up → seed → scenario-01 … scenario-11 → verify`, each a
script you can run on its own (section 4). It writes `state/report.md` and `state/report.json`, and
`scripts/txids.sh --check` re-confirms every testnet hash on Horizon afterwards. Two tiers:

| Tier | What runs | Time (M3 Pro, OrbStack) |
|---|---|---|
| `--smoke` | stack, accounts, the custodial payment, roles, reserve/events, verify — no Gradle, no emulator | ≈1 min warm (45 s measured); ≈4 min cold (the bridge image is a Rust release build, 159 s measured) |
| default (full) | smoke + wallet and operator CLIs, card issuance, JVM card login, the emulator, the Payala relays against the stub, Soroban | ≈6½ min warm (386 s measured, three 61 s pre-auth quiet windows included); 20–30 min cold (card SDK + app compile, WASM build) |

Every scenario is re-runnable. The payment scenarios are *re-runnable, not idempotent*: each run is a
new testnet payment (only scenario 02's keyed replay proves idempotency).

Prerequisites (`doctor.sh` checks them and says what each missing one disables):

- a container engine: Docker with Compose v2 (verified with OrbStack on macOS 14 arm64) **or**
  Podman ≥ 5 with `podman-compose` or a `docker-compose` v2 binary as its compose provider;
- `bash` 3.2+, `curl`, `jq`, `openssl`, `git`, `tar`; Go 1.26+ (the CLIs are built from source); `python3` for the card lanes (the simulator probe); a Rust toolchain for scenario 09 (`cargo` runs the contract tests; the WASM build needs rustup's stable toolchain with the `wasm32-unknown-unknown` target, otherwise it is skipped with a notice) — `doctor.sh` reports what each missing one disables;
- outbound HTTPS to `horizon-testnet.stellar.org` and `friendbot.stellar.org` (the bridge refuses to boot without Horizon);
- for the card lanes: **JDK 17** to launch Gradle (`JAVA17_HOME` or `/usr/libexec/java_home -v 17`; the Kotlin toolchain 21 is provisioned automatically) and the Android SDK location the repo's Gradle projects already use (`local.properties`);
- for the emulator lane: an Android SDK with `emulator/`, `platform-tools/adb`, `cmdline-tools/latest` and the
  `system-images;android-34;google_apis;arm64-v8a` image (`DEMO_INSTALL_SDK=1` lets `scripts/emulator.sh up` install the missing pieces with `sdkmanager`), and `impala-android-demo/app/google-services.json` (copy the `.example`);
- optional: a [scardutil](https://github.com/Financial-Empowerment-Partners/scardutil) checkout (`SCARDUTIL_DIR`) for the fleet check, `stellar-cli` for the Soroban testnet tests, `vhs` for the recording. Node is **not** needed on the host: the Payala stub runs in its container (`node --test demo/payala-stub/server.test.mjs` runs its own tests wherever Node ≥ 20 exists).

Ports, all bound to `127.0.0.1`: `3000` UI, `8080` bridge, `8200` OpenBao, `9443` the simulated card,
`4000` the Payala stub. `up.sh` refuses to start while another stack (the repo's
`impala-bridge/docker-compose.yml`, the external kit, or the other engine) holds them.

## 2. The accounts

`seed.sh` creates them; the bridge **login username is the account's uuid** (`payala_account_id`),
passwords are generated into `.env`. The three custodial users hold seeds the bridge generated and
OpenBao sealed; nothing ever returns a seed.

| Role | uuid | bridge role | custody | funding |
|---|---|---|---|---|
| admin | `10000000-0000-4000-8000-000000000002` | `admin` (first row + `ADMIN_ACCOUNT_IDS`) | none (unfunded address) | — |
| agent | `…0003` | view-only | custodial (`POST /admin/stellar-seeds/generate`) | Friendbot, 10 000 XLM |
| beneficiary | `…0004` | view-only | custodial | Friendbot |
| holder (the card holder) | `…0006` | view-only | custodial | Friendbot |

The same uuids are the users `prepare.sh` seeds into the Payala stub, so the relays map 1:1. Passwords and
bearer tokens never appear in a process's argv: the scripts build request bodies from environment
variables, send them on curl's stdin and attach tokens through a `0600` header file; the CLIs read
secrets from the environment or files. The admin also
acts as the card program operator (`manage_keys` through the admin role). The admin UI at
`http://localhost:3000` (exactly that origin) accepts any of these accounts, or *Continue with
OpenBao* with `testuser` / `testpassword` (the OIDC test IdP bootstrapped by `openbao-init`).

## 3. What a run looks like

Every scenario prints `ok` / `FAIL` per assertion, records `state/records/<scenario>.json` (ids,
hashes, URLs, timings, tally), and announces each testnet transaction like this — three human lines on
stderr and one machine-readable `TESTNET_TXID` line on stdout, appended once to `state/testnet-txids.tsv`:

```
  testnet tx 96f2929b61e945a431f00fb2aaa247f07a9c3c70361297a16270426640bdeb28  (custodial_payment; 25 XLM GDNB4GOM… -> GDN75DK6… ledger 5111423)
    horizon  https://horizon-testnet.stellar.org/transactions/96f2929b61e945a431f00fb2aaa247f07a9c3c70361297a16270426640bdeb28
    explorer https://stellar.expert/explorer/testnet/tx/96f2929b61e945a431f00fb2aaa247f07a9c3c70361297a16270426640bdeb28
TESTNET_TXID	custodial_payment	96f2929b61e945a431f00fb2aaa247f07a9c3c70361297a16270426640bdeb28	https://stellar.expert/explorer/testnet/tx/96f2929b…
```

The scorecard at the end of `run-all.sh` (also `state/report.md`; this one is a warm run with `--no-build` on 2026-10-09 — the smoke scenarios run first, then the host lanes; three 61 s pre-auth quiet windows are inside the total):

```
── scorecard (386 s) ──
  doctor                           passed          1s
  prepare                          passed          1s
  build                            skipped         0s  --no-build
  up                               passed         15s
  seed                             passed         17s
  scenario-01-stack                passed          1s  17/17 assertions
  scenario-02-custodial-payment    passed          9s  11/11 assertions; tx e1106bfe69dd…
  scenario-10-roles                passed          1s  28/28 assertions
  scenario-11-reserve-events       passed          1s  13/13 assertions
  scenario-03-wallet-cli           passed         14s  10/10 assertions; tx affe73498743…
  scenario-04-operator-cli         passed          4s  13/13 assertions; tx 06e0dcb59eed…
  scenario-05-card-issue           passed         10s  16/16 assertions
  scenario-06-card-login-jvm       passed         67s  5/5 assertions
  scenario-07-android-emulator     passed         34s  9/9 assertions
  scenario-08-payala-relay         passed         12s  21/21 assertions; tx e7651bf819eb…
  scenario-09-soroban              passed          8s  5/5 assertions
  verify                           passed          4s
```

## 4. The scenarios

Each script is idempotent and safe to re-run (a re-run makes another payment where one is made).
Mandatory steps stop `run-all.sh`; optional lanes are skipped with a reason when their prerequisites
are missing. Amounts are integer stroops in the scripts; nothing is ever resent without its
idempotency key; an **ambiguous** outcome (lumencli or impalactl exit 3, a bridge `202` that never
settles) stops the script and is reported as `ambiguous`, never retried.

### 01 — the stack (`scenario-01-stack.sh`)

Proves the containers are the system: `/health` healthy with database and redis `ok` on testnet,
`/readyz` 200, `/network` carries the testnet passphrase, **every migration file in the repo is
recorded in `_sqlx_migrations`** (the one-shot `impala-migrate` service ran `RUN_MODE=migrate`, the
same step an operator runs before rolling a binary), the UI serves and proxies `/api/testnet` to the
bridge with a testnet-only `config.js`, OpenBao holds the `impala-seeds` Transit key and answers OIDC
discovery, the bridge advertises the `openbao` SSO provider, the card program issuer key is published
by `GET /card-issuer`, the OTLP collector is receiving telemetry, nothing is restarting, the bridge's
SSO config for `openbao` is `enabled`, and **OpenBao still holds the Transit key that sealed the seeds**:
`openbao-init` wrote a canary ciphertext once; a re-created key (dev mode forgets everything on restart)
fails to decrypt it, and `up.sh` stops with the reset instruction instead of letting the first payment
discover orphaned seeds. 17 assertions.

### 02 — a custodial payment (`scenario-02-custodial-payment.sh [xlm]`)

The agent's session asks the bridge to sign 25 XLM to the beneficiary from the seed the bridge holds
(`POST /managed-account/sign` with an idempotency key; a `202` is polled by that key and never
resent). Horizon confirms the transaction, memo and operation; the bridge's intent is `settled` with the
same hash and 250 000 000 stroops; the `custodial_sign` transaction row and the
`custodial.payment_settled` event name it; balances move by exactly 25 XLM (+ the 100-stroop fee on
the sender); and **the same idempotency key replays the recorded outcome** (`replayed: true`, same
hash, balances unchanged). 11 assertions.

### 03 — a self-custody wallet pays in (`scenario-03-wallet-cli.sh [xlm]`)

`lumencli account new` (the seed lives only in this process, read by `send` from `LUMEN_SECRET`,
never argv or disk), `account fund` through Friendbot (the funding hash is logged), `send 5 XLM` to the
holder's custodial address with a text memo, then `tx` and `history --json` from the wallet's and the
holder's side; Horizon shows the payment; the holder's balance rises by exactly 5 XLM; and the bridge's
`GET /account/onchain` for the holder reports that live balance. 10 assertions.

### 04 — the operator CLI (`scenario-04-operator-cli.sh [xlm]`)

`impalactl login` (password from `IMPALA_PASSWORD`; credentials stored `0600`, **scoped to the
endpoint** — the same bridge under the UI's proxy URL is refused with "stored credentials are for …"),
`health`, `whoami`, `account show/onchain/list`, then `transfer send` 3 XLM beneficiary → agent with a
memo (impalactl announces the bridge URL and network first; an unknown outcome would be exit 3 and the
script stops), Horizon confirmation, `activity list --search <hash>`, `activity show <btxid>`, the
admin's `activity events` carrying `custodial.payment_settled`, and the role gate (the beneficiary
cannot read the event feed). 13 assertions. `impalactl transfer send` has no idempotency flag, so a re-run
is a second payment; the keyed replay lives in scenario 02.

### 05 — card issuance on the JavaCard simulator (`scenario-05-card-issue.sh`)

`scripts/simulator.sh up` starts the real `ImpalaApplet` on jcardsim (`:simulator:serve`, JDK 17) and
probes it (`SELECT`, `GET_VERSION` → applet 0.2). The issuance tool then runs the whole ceremony over
TCP for the holder — INITIALIZE (the card generates its P-256 key), per-card SCP03 keys derived from
the KMK, `POST /card`, a **bridge-issued card certificate** signed by the program's issuer key
(sealed by OpenBao), PERSONALIZE A/B/C, master and user PINs — and prints the signed-off record:

```
  card_id=4c87dad3f22e5af1e6ca29dfba8e2455
  account_uuid=10000000-0000-4000-8000-000000000006
  program_id=7754d4f5e029429cba9a8ad7aa8b2e36
  currency=XLM
  cert_id=f0b9a112f5774d0b7c56180e13914d64abbd7a60c3fa724dbd53b082bc345e87
  applet_version=0.2+00000000
  issuer_version=1
  issuer=bridge
  status=issued
```

Assertions: the record says `issuer=bridge` (never the local test issuer) and names the holder's
account, the program id is the bridge's, the card row exists for the holder with an EC key, no RSA key
and a certificate (`cert_issuer_version`, `issuer_cert_hex`, `certified_at`), the event feed holds
`card.registered` and `custody.card_certified` for this card and exactly one
`custody.issuer_key_generated`, **re-running the ceremony is a no-op with the same record**
(`already-issued`), and the simulator still serves the issued card. With `SCARDUTIL_DIR` set, the CAP's plaintext
dispatch sequence (`impala-card/scardutil/impala-dispatch.md`) also runs on the vpcd simulator through
scardutil — the same file that runs on a fleet of physical cards (see `impala-card/scardutil/README.md`).
10 assertions. The card lives in the simulator process: `simulator.sh down` destroys it and the next
run issues a new one (the bridge keeps the old row).

### 06 — card login, SDK lane on the JVM (`scenario-06-card-login-jvm.sh`)

`./gradlew :app:e2eTnetDebug` in `impala-android-demo` against this bridge: the app's real flow
classes (`LoginViewModel`, `CardsViewModel`) drive a jcardsim card issued by the ceremony in library
mode. `CardAuthE2ETest` proves card login end to end — challenge, `SIGN_AUTH`, `POST /auth/card`,
single-use challenges, unregistered cards → generic 401, foreign cards refused client-side, lockout
after five bad signatures (`DEMO_E2E_SLOW=1` adds the 61 s expiry case). `CardTransferE2ETest` is
reported **skipped**: the bridge has no `/offline/*` lane yet. The lane fails if the `TEST ISSUER`
banner appears (certificates must come from the bridge's program key). The operator password travels
by file and is deleted afterwards. JUnit XML is copied to `state/artifacts/e2e-jvm/`.

### 07 — the Android emulator (`scenario-07-android-emulator.sh`)

`scripts/emulator.sh up` creates the AVD `impala-demo-34` if needed (API 34, Google APIs, arm64,
`pixel_6`), boots it headless (≈30 s warm, up to 3 min), turns animations off. The simulated card is
wired with `adb reverse tcp:9443` and `debug.impala.tcp_card=127.0.0.1:9443`; the app reaches the
bridge at `10.0.2.2:8080` (the tnet flavor's cleartext allow-list). `connectedTnetDebugAndroidTest`
runs `CardLoginUiTest` with `cardAccount=<holder>`: it taps **Sign in with Card** on the real login
screen and asserts `MainActivity` is reached with the holder's account and `auth_provider = card`;
`CardRedeemUiTest` runs too so its honest skip (the offline lane is not deployed) shows in the report.
The run is screen-recorded, and a watcher screenshots the login screen and the main screen the moment
each becomes the resumed activity; the two stills, the mp4 and the JUnit XML land in
`state/artifacts/android/`. `DEMO_HEADLESS=0` shows the window for a live demo. (`SmokeTest` is not
run: it asserts the base package name while the tnet flavor installs as `com.payala.impala.demo.testnet`.)

### 08 — the Payala relays against the Payala stub (`scenario-08-payala-relay.sh`)

The Payala side of the demo is **`payala-stub/`**, an in-repo stand-in for the Payala API: one
dependency-free Node module on the public `node:22-alpine` image, seeded by `prepare.sh` with the six demo
users and their P-256 card signing keys (`payala-stub/README.md` is its contract; `node --test` covers it).
The proprietary Payala API is not part of the demo, and no Payala image or source tree is needed. The
external kit's two relay directions run against it, ported under `scripts/payala/`: the agent is funded
by a mint Order; a bridge custodial payment is **reflected into the stub** by the forward relay (event
feed → intent → `POST /transfers/order` with the Stellar hash prefix as `device_id`; the stub verifies
the 256-byte preimage hash and that the sender key is the seeded card key, and moves the balances once)
and mirrored back with `POST /sync/payala`; then a stub Order is **reflected into the bridge** as a real
testnet payment signed from the sender's custodial seed (memo `payala:<first 20 hex of the Payala tx
id>`, idempotency key `payala:<first 56 hex>`), with the 21 assertions of `test-payala-to-impala.sh`,
including that re-running the relay pays nothing twice and that the forward relay never orders the
payment back. The scenario then reads the stub's **request journal** (`GET /__stub/requests`, in
memory, the newest 2000 entries) and its monotonic counters (`GET /__stub/state`) to show the requests
themselves behaved: exactly one order request carried the forward hash prefix and was answered 200,
none ever carried the reverse hash prefix, and no request since the stub started carried an
`Authorization` header. A forward payment whose outcome stays ambiguous (a `202` that never settles)
is recorded with `status: ambiguous` and stops the scenario with exit 3, like scenario 02. The relay scripts
cache the four principals' temporal bearer tokens (`state/relay/tokens/`, `0600`, reused for 40 minutes of
their one-hour life, dropped on a `401`, removed by `reset.sh`): every host lane is one TCP peer for the
bridge's pre-auth budget (30 `/token` calls per minute), and `run-all.sh` also leaves a 61-second quiet
window before this scenario. Cursor policy: the
forward relay first catches up on every custodial payment the earlier scenarios made (they are reflected
into the stub too), and only then are the stub balances snapshotted for the scenario's own delta
assertions. The stub's ledger lives in the `payala-stub-data` volume (kept by `down.sh`, cleared by
`reset.sh`, like the bridge database).

### 09 — the Soroban contract (`scenario-09-soroban.sh`)

`cargo test` in `impala-soroban/integration-test` (125 in-process tests incl. the proptest state
machine); the release WASM built for `wasm32-unknown-unknown` with rustup's stable toolchain (`rustup run
stable` with `RUSTC` pinned to its `rustc`: a Homebrew `cargo`/`rustc` on PATH has no wasm target and
would otherwise shadow it), its sha256 printed (the on-chain `ContractCode` hash of any deployment of
that build) and the pinned-host **artifact gate** test run against it; `impala-soroban/testnet-tests`
when `stellar-cli` is installed (it self-issues a test asset); and the honest statement of what the
bridge does with Soroban: nothing but echo `SOROBAN_CONTRACT_ID` on `GET /network` (unset here) — no
testnet instance is deployed by this demo.

### 10 — roles and the capability matrix (`scenario-10-roles.sh`)

Three new accounts start as `view-only` (and are refused on `/admin/*`); the admin grants
`treasurer`, `key-custodian` and `auditor` with `PUT /admin/accounts/{id}/role`; each grant **revokes
the target's existing tokens** (the pre-grant token is now 401 — the auth-epoch bump), the next login's
JWT carries the role, and the capability matrix — `impala-ui/tests/fixtures/role-capabilities.json`,
the one table the bridge and the UI both assert against — decides: the treasurer reads custody and
the reserve but not keys or events, the key-custodian reads keys and accounts but not custody, the
auditor reads events, keys and custody but cannot change policy, and nobody but the admin grants
roles. The admin itself is reported `allowlisted` (`ADMIN_ACCOUNT_IDS`, the break-glass path).
`account.role_changed` events are emitted. Read-mostly; no money moves. 30 assertions.

### 11 — what is deliberately unconfigured, as evidence (`scenario-11-reserve-events.sh`)

Read-only: the conversion reserve is *armed but inactive* (`GET /admin/exchange-reserve`:
`configured:false`, the three seeded buckets USD/USDC/USDT0 at zero, no trustline), the exchange
providers are all disabled and a quote is refused, the key inventory is enabled with the OpenBao
protector but holds nothing (fingerprints only, no secret-shaped values), and the admin event feed is
the audit trail of the run — accounts created, seeds provisioned, policy updated, issuer key
generated, cards certified, payments settled — with no seed, password or JWT in any payload, payment
events carrying only the intent id, and the holder refused on the feed. 12 assertions.

### verify (`verify.sh`)

Re-checks every recorded fact against the **live** system, not the scorecard: health and migrations;
the four accounts, their custody mapping and funding; for each payment scenario the Horizon status,
the bridge's intent / `custodial_sign` row; the card program id against the issued card and its row;
the host lanes' records and artifacts; and that **every hash recorded by this run's scenarios is on
Horizon and successful** (the historical `state/testnet-txids.tsv` survives resets and is re-checked by
`scripts/txids.sh --check`). Exit 1 on any failure.

## 5. Everyday commands

| Command | What it does |
|---|---|
| `scripts/status.sh` | containers, bridge health, accounts and balances, intents, transactions, the card program, simulator/emulator status, the scorecard, last testnet ids |
| `scripts/txids.sh [--check] [--json]` | every testnet transaction id the suite created, with Horizon / stellar.expert URLs; `--check` re-confirms them on Horizon |
| `scripts/logs.sh [service\|simulator\|emulator]` | `compose logs -f` (default `impala-bridge`) or the host lanes' logs |
| `scripts/simulator.sh up\|down\|status\|probe` | the jcardsim card server (pid and log under `state/simulator/`) |
| `scripts/emulator.sh up\|down\|status\|screenshot <name>` | the AVD lifecycle; `DEMO_HEADLESS=0` for a window |
| `scripts/down.sh` | stop (volumes kept — but see the OpenBao note); also stops the simulator and emulator |
| `scripts/reset.sh [--yes]` | destroy containers, volumes and records; keeps `.env`, `state/keys` and `state/testnet-txids.tsv` |
| `scripts/run-all.sh --smoke` / `--only <step>` / `--skip <step>` / `--no-build` / `--keep` | subsets of the suite; Ctrl-C stops the simulator and emulator and writes an `interrupted` report; while a payment scenario is recorded `ambiguous`, no further payments are made until the record is resolved and deleted |
| `CONTAINER_ENGINE=podman scripts/…` | run anything against Podman (section 6) |

## 6. Docker and Podman

`CONTAINER_ENGINE` is auto-detected by `doctor.sh`/`prepare.sh` (docker if its daemon answers, else
podman) and persisted in `.env`; set it explicitly to choose. The compose file stays inside the
intersection both understand (fully qualified images, quoted environment values, exec-form
healthchecks, no `container_name`, network aliases only, YAML anchors, no `profiles`), images are
pre-built with the native CLI (`docker build` / `podman build --format docker`), `up.sh` drives the
phases itself instead of trusting `depends_on` conditions, the one-shot migration runs with
`compose run --rm --no-deps`, and the UI is recreated with `--no-deps` (podman-compose would otherwise
recreate OpenBao and orphan every seed). For Podman on macOS: `podman machine init --cpus 6 --memory
8192 --disk-size 80 && podman machine start` (the bridge's release build is killed in a 2 GiB machine);
leave `PODMAN_COMPOSE_PROVIDER` empty or force `podman-compose` / `docker-compose`. Docker and Podman
stacks cannot run at the same time (same ports); tear one down with the provider that created it.
Verified on both: OrbStack's Docker (the full suite) and a Podman 6.1 machine with the `docker-compose`
provider (`CONTAINER_ENGINE=podman scripts/run-all.sh --smoke --no-build`, then scenario 08 and
`verify.sh`): the stack came up in 17 s, the Payala stub ran from the bind-mounted directory on the public
node image, and every assertion that passed on Docker passed on Podman.

The bridge image is the repo's `impala-bridge/Dockerfile` with its `# syntax=` line dropped and the
`FROM` lines fully qualified (same digests), generated by `prepare.sh` into
`build/impala-bridge.Containerfile` so it cannot drift from the source; the build context is
`../impala-bridge` (its `.dockerignore` keeps `target/` out).

## 7. Things that fail silently, and what the kit does about them

| Symptom | Cause / what happens |
|---|---|
| every custodial payment or card certificate fails with a seed-protection error | OpenBao (dev mode, in-memory) restarted — `down.sh` + `up.sh`, a machine reboot — so its Transit key is gone and every sealed seed and the issuer key are undecryptable. `reset.sh --yes && up.sh && seed.sh` is the recovery; this is why `down.sh` warns. |
| the bridge container never becomes ready | no outbound HTTPS to Horizon testnet (the bridge exits after 5 tries), or the host port is taken. `logs.sh` shows the reason only because the OTLP collector exists: without `OTEL_EXPORTER_OTLP_ENDPOINT` the bridge logs nothing readable in a container. |
| `custodial_unconfigured` on a payment | caps are 0 on a fresh database; `seed.sh` sets them (100 XLM per tx, 1 000 XLM per account per day). |
| `429 rate_limited` / lockout | pre-auth 30/min per source, sign 5/min per account, 5 wrong passwords lock an identity for 15 min. Slow down; there is no API to clear a counter. |
| `transfer send` or `send` exits 3, or a `202` intent stays `ambiguous` | an **ambiguous** outcome: the payment may have been submitted. The scripts stop, record `status: ambiguous` and exit 3; `run-all.sh` makes no further payments until you resolve it (`impalactl activity list`, the intent, Horizon) and delete the record. |
| the card lane says the simulator is not serving the issued card | `simulator.sh down` (or a Gradle restart) destroyed the in-memory card; scenario 05 issues a new one. |
| `CardTransferE2ETest` / Android *Load card*, *Redeem* | out of scope: the bridge has no `/offline/*` lane. |
| testnet reset (accounts vanish) | `txids.sh --check` reports the missing hashes; `reset.sh --yes && up.sh && seed.sh`. |
| the admin UI shows a blank page or SSO fails | open exactly `http://localhost:3000`; the OIDC issuer is `http://localhost:8200`. |

## 8. Files

```
README.md                 this guide
compose.yaml              the stack (docker compose / podman compose) incl. the payala-stub service
.env.example → .env       engine, ports, generated secrets, fixed ids, demo constants, lane switches (gitignored)
payala-stub/              the in-repo stand-in for the Payala API: server.mjs (Node, no dependencies), server.test.mjs, README.md
config/openbao/openbao-init.sh     Transit key + OIDC test IdP + sso-config.json (one-shot)
config/otel/collector.yaml         OTLP → debug exporter
config/impala-ui/config.js         testnet-only UI config
scripts/lib.sh            shared helpers (engine selection, compose, bridge/Horizon helpers, emit_txid, integer money, records, assertions, JDK/Android helpers)
scripts/doctor.sh · prepare.sh · build.sh · up.sh · down.sh · reset.sh · logs.sh · status.sh · txids.sh
scripts/seed.sh           accounts, caps, custodial seeds, Friendbot, card issuer key
scripts/scenario-01..11-*.sh · verify.sh · run-all.sh
scripts/simulator.sh · emulator.sh
scripts/payala/           the relays, against the stub (lib-payala.sh, seed-payala.sh, payala-order.sh, reflect.sh, reflect-payala.sh, demo-payment.sh, test-payala-to-impala.sh)
recordings/demo.tape      vhs recording of a smoke run + txids --check
state/                    records/, artifacts/, testnet-txids.tsv, timings.tsv, report.{md,json}, impala.env, keys/   (generated, gitignored)
build/ bin/               generated, gitignored
```

CI (`.github/workflows/demo.yml`) lints the kit — `bash -n`, shellcheck (`-x -P SCRIPTDIR`, so the
`$(dirname "$0")`-relative sources are followed), `docker compose config`, the
generated Containerfile's pinned `FROM` lines, the Payala stub's `node --test`, and a grep that keeps the
proprietary Payala API out of the kit — because the suite itself needs testnet, an engine, a JDK and an
emulator. To record a console run:
`cd ~/Documents && vhs /path/to/impala/demo/recordings/demo.tape`.
