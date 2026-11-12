# Impala demo suite — the whole system on Stellar testnet

A self-contained kit that stands up Impala on a laptop and walks it through real **Stellar testnet**
money flows, with every claim checked by a script and every testnet transaction id printed in full
(Horizon and stellar.expert links) and logged. It uses the three mechanisms the project is built on:

| Mechanism | What runs there | Why |
|---|---|---|
| **Docker or Podman** — one `compose.yaml`, project `impala-suite` | postgres 16, redis 7, OpenBao (dev mode: Transit seal + OIDC test IdP), an OTLP collector, `impala-migrate` (the operator-run `RUN_MODE=migrate` step), `impala-bridge` built from this checkout, `impala-ui` (nginx), and `payala-stub` — an in-repo stand-in for the Payala API (`payala-stub/`: one dependency-free Node module on the public `node:22-alpine` image; the proprietary Payala API is not part of the demo) | the server of record and its dependencies are containers in every real deployment |
| **JavaCard simulator** — host JVM 17 | the real `ImpalaApplet` (applet 0.3: a P-256 card key and an Ed25519 "Stellar key") on jcardsim behind a TCP APDU socket (`impala-card :simulator:serve`), issued by the issuance ceremony (`tools/issue`) against the bridge's card program. The simulated card is a CAP on **hardware of a chosen class**: a JavaCard 3.0.5 card (`jc305`, the default) or a JavaCard 3.2 card (`jc32`) | jcardsim is the oracle every card test already uses; no reader or card needed |
| **Android emulator** — API 34, Google APIs, arm64, headless by default | the demo app's `tnet` flavor reaching the bridge at `10.0.2.2:8080` and the simulated card through `adb reverse`; `CardLoginUiTest` drives the real login screen, and the card login it makes is a SEP-10 sign-in | the phone is the holder's device; the emulator has no NFC, so the debug TCP card transport stands in |

Plus the two CLIs built from this checkout: `lumencli` (a self-custody wallet) and `impalactl` (the
operator client). It generalises the external Payala ↔ Impala kit: the relay scenarios from that kit are
included, running against the Payala stub instead of the proprietary Payala API.

**SEP-10 runs through all three.** The stack's bridge serves SEP-10 (Stellar Web Authentication) for
card keys: `seed.sh` generates and activates its signing key, the issuance ceremony registers the
card's Stellar key, the phone signs in with it (scenario 07), scenario 12 walks the bridge's SEP-10 API
and its refusals, and scenario 13 signs the same card in at a SEP-10 server nobody here wrote (the SDF
reference anchor on testnet, by default) and uses the token it gets there. The legacy card login
(`SIGN_AUTH`) stays in use next to it: scenario 06 is that lane, a card without a Stellar key and an
operator's card take it in scenario 12, and `DEMO_SEP10=false` runs the whole suite on it. Section 5
explains the set-up.

**Two hardware classes.** A card that signs in with SEP-10 is either a JavaCard 3.0.5 card, where the
default CAP does Ed25519 in software through the card's ECDH engine, or a card with EdDSA of its own
(JavaCard 3.1 and 3.2), where the native CAP uses that. The simulator is both: `DEMO_CARD_PLATFORM`
(`jc305` by default, `jc32` for a JavaCard 3.2 card) chooses the hardware of the card that is issued
and that the phone taps, and whatever it is set to, the SEP-10 lanes of scenarios 12 and 13 sign in
with a card of each class in every run. Section 5 has the details.

```
 host scripts (bash 3.2 / curl / jq / openssl)        ┌─ host JVM 17 ──────────────────────────────┐
   scripts/run-all.sh ──► doctor → prepare → build    │ jcardsim ImpalaApplet  :9443  ◄── tools/issue│
      → up → seed → scenario-01..13 → verify          │ Android emulator (API 34) ──adb reverse──┘   │
      every testnet tx id → state/testnet-txids.tsv   │   tnet app ──► 10.0.2.2:8080                 │
                                                      └──────────────────────────────────────────────┘
 ┌──────────────────── compose project impala-suite (docker or podman) ────────────────────────────┐
 │ impala-ui :3000 ──► impala-bridge :8080 ──► Stellar testnet (Horizon)                             │
 │                     │ postgres · redis · openbao :8200 (Transit + OIDC) · otel-collector           │
 │                     │ impala-migrate (one-shot RUN_MODE=migrate)                                   │
│ payala-stub :4000 — the in-repo stand-in for the Payala API (the relays' counterparty)             │
 └───────────────────────────────────────────────────────────────────────────────────────────────────┘
   SEP-10: the bridge's home domain is 10.0.2.2:8080 (its name on the emulator; the host aliases it).
   Scenario 13 also signs the card in at a third-party testnet server: testanchor.stellar.org
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

`run-all.sh` is `doctor → prepare → build → up → seed → scenario-01 … scenario-13 → verify`, each a
script you can run on its own (section 4). It writes `state/report.md` and `state/report.json`, and
`scripts/txids.sh --check` re-confirms every testnet hash on Horizon afterwards. Two tiers:

| Tier | What runs | Time (M3 Pro, OrbStack) |
|---|---|---|
| `--smoke` | stack, accounts, the SEP-10 signing key, the custodial payment, roles, reserve/events, verify — no Gradle, no emulator | ≈1½ min warm (those steps took 96 s inside the full run below; `seed.sh` is 62 s of it, see section 5); ≈4½ min cold (the bridge image is a Rust release build, 167 s measured) |
| default (full) | smoke + wallet and operator CLIs, card issuance, JVM card login, the emulator, SEP-10 at the bridge and at a third-party server, the Payala relays against the stub, Soroban | ≈8¾ min warm (525 s measured on 2026-11-12, the optional scardutil step included; four 61 s pre-auth quiet windows are 244 s of it); 20–30 min cold (card SDK + app compile, WASM build) |

Every scenario is re-runnable. The payment scenarios are *re-runnable, not idempotent*: each run is a
new testnet payment (only scenario 02's keyed replay proves idempotency).

Prerequisites (`doctor.sh` checks them and says what each missing one disables):

- a container engine: Docker with Compose v2 (verified with OrbStack on macOS 14 arm64) **or**
  Podman ≥ 5 with `podman-compose` or a `docker-compose` v2 binary as its compose provider;
- `bash` 3.2+, `curl`, `jq`, `openssl`, `git`, `tar`; Go 1.26+ (the CLIs are built from source); `python3` for the card lanes (the simulator probe, and the SEP-10 challenge reader of scenarios 12 and 13: standard library only); a Rust toolchain for scenario 09 (`cargo` runs the contract tests; the WASM build needs rustup's stable toolchain with the `wasm32-unknown-unknown` target, otherwise it is skipped with a notice) — `doctor.sh` reports what each missing one disables;
- outbound HTTPS to `horizon-testnet.stellar.org` and `friendbot.stellar.org` (the bridge refuses to boot without Horizon);
- for scenario 13: outbound HTTPS to the third-party SEP-10 servers in `DEMO_SEP10_THIRD_PARTY` (default `testanchor.stellar.org`). A server that cannot be reached is reported and skipped, not failed;
- for the card lanes: **JDK 17** to launch Gradle (`JAVA17_HOME` or `/usr/libexec/java_home -v 17`; the Kotlin toolchain 21 is provisioned automatically) and the Android SDK location the repo's Gradle projects already use (`local.properties`);
- for the emulator lane: an Android SDK with `emulator/`, `platform-tools/adb`, `cmdline-tools/latest` and the
  `system-images;android-34;google_apis;arm64-v8a` image (`DEMO_INSTALL_SDK=1` lets `scripts/emulator.sh up` install the missing pieces with `sdkmanager`), and `impala-android-demo/app/google-services.json` (copy the `.example`);
- optional: a [scardutil](https://github.com/Financial-Empowerment-Partners/scardutil) checkout (`SCARDUTIL_DIR`) for the fleet check, `stellar-cli` for the Soroban testnet tests, `vhs` for the recording. Node is **not** needed on the host: the Payala stub runs in its container (`node --test demo/payala-stub/server.test.mjs` runs its own tests wherever Node ≥ 20 exists).

Ports, all bound to `127.0.0.1`: `3000` UI, `8080` bridge, `8200` OpenBao, `9443` the simulated card,
`4000` the Payala stub. `up.sh` refuses to start while another stack (the repo's
`impala-bridge/docker-compose.yml`, the external kit, or the other engine) holds them. They can be
moved in `.env` (`BRIDGE_PORT`, `SIM_PORT`, `PAYALA_PORT`, …); the bridge port is part of the SEP-10
home domain (`10.0.2.2:<BRIDGE_PORT>`) and of the URL the Android app is built for (section 5).

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

`seed.sh` also arms SEP-10: it generates the bridge's SEP-10 signing key (generate-only, sealed by
OpenBao like the seeds), waits until the bridge has opened it, and activates it. The key takes over
after the activation delay (120 s); the scenarios that need it wait for that. For SEP-10 the two kinds
of account differ on purpose: the holder's card signs in with it, the admin's card never does (the
bridge refuses SEP-10 to any account with a privileged role, and scenario 12 shows the refusal and the
legacy login that follows).

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

The scorecard at the end of `run-all.sh` (also `state/report.md`; this one is a warm run from a clean
state, `reset.sh --yes` then `run-all.sh --no-build`, on 2026-11-12, with `SCARDUTIL_DIR` set so that
scenario 05 also runs its fleet check — the smoke scenarios run first, then the host lanes; four 61 s
pre-auth quiet windows are inside the total):

```
── scorecard (525 s) ──
  doctor                           passed          1s
  prepare                          passed          0s
  build                            skipped         0s  --no-build
  up                               passed         16s
  seed                             passed         62s
  scenario-01-stack                passed          1s  21/21 assertions
  scenario-02-custodial-payment    passed          8s  11/11 assertions; tx a516bbf71a5e…
  scenario-10-roles                passed          2s  36/36 assertions
  scenario-11-reserve-events       passed          1s  14/14 assertions
  scenario-03-wallet-cli           passed         18s  10/10 assertions; tx b716c5a3f87b…
  scenario-04-operator-cli         passed          5s  13/13 assertions; tx 28c94606deaf…
  scenario-05-card-issue           passed         18s  27/27 assertions
  scenario-06-card-login-jvm       passed         66s  5/5 assertions
  scenario-07-android-emulator     passed         39s  11/11 assertions
  scenario-12-sep10-bridge         passed          7s  31/31 assertions
  scenario-13-sep10-third-party    passed          6s  10/10 assertions
  scenario-08-payala-relay         passed         15s  21/21 assertions; tx 073a04ee4919…
  scenario-09-soroban              passed          7s  5/5 assertions
  verify                           passed          5s
```

That run issued the holder's card on the default hardware, a JavaCard 3.0.5 card. The card lanes were
also run on a JavaCard 3.2 card the same day (`DEMO_CARD_PLATFORM=jc32`: scenario 05 24/24 without the
fleet step, scenario 07 11/11, scenario 13 10/10 with that card signing in at the third-party server).

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
discover orphaned seeds. For SEP-10: the admin API reports it enabled with the home domain
`10.0.2.2:<bridge port>` and a live key ring, one signing key is active or activated and waiting out its
delay, the public routes are mounted (`stellar.toml` answers 200, or 503 until the key takes over, never
404), and the UI serves the signing-key panel. With `DEMO_SEP10=false` the check is the opposite one:
`stellar.toml` answers 404. 21 assertions.

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

`scripts/simulator.sh up` starts the real `ImpalaApplet` on jcardsim (`:simulator:serve`, JDK 17) as
the CAP and hardware `DEMO_CARD_PLATFORM` asks for (the default CAP on a JavaCard 3.0.5 card unless
told otherwise; a simulator left running as another card is restarted) and
probes it (`SELECT`, `GET_VERSION` → applet 0.3; the checks read the expected version from the applet's
`BuildConfig.java`). The issuance tool then runs the whole ceremony over
TCP for the holder — INITIALIZE (the card generates its P-256 key and its Ed25519 "Stellar key"),
per-card SCP03 keys derived from the KMK, `POST /card`, a **bridge-issued card certificate** signed by
the program's issuer key (sealed by OpenBao), PERSONALIZE A/B/C, master and user PINs, and last the
registration of the Stellar key (`PUT /card/stellar-key`, never fatal) — and prints the signed-off record:

```
  card_id=b1e1806f63729438ad04f909ce09b5ab
  account_uuid=10000000-0000-4000-8000-000000000006
  program_id=bc3e3afe4f0c495da99c691e10a436fe
  currency=XLM
  cert_id=f77776dd58e9f0f507c21b0ce97c412436224ae291f0f6e8a764f25cf6e4c713
  applet_version=0.3+00000000
  issuer_version=1
  issuer=bridge
  stellar_address=GDZSBM4I66NATGVDR5B6THBW3NNYVGPTDMJDQVUSTVN7WDKTJ5ICAOV6
  status=issued
```

`stellar_address` is the card's SEP-10 identity: the public half of the Ed25519 key the card generated
at INITIALIZE. Which engine made it follows the hardware: the software engine of the default CAP on a
JavaCard 3.0.5 card (`jc305`), the platform's own EdDSA of the native CAP on a JavaCard 3.2 card
(`jc32`). The scenario asks the card itself over the socket (`GET_STELLAR_KEY`) and asserts the engine
it reports and that its key is the address of the record. The bridge stores it only
after verifying the two signatures the card made at personalization (its P-256 key vouching for the
Stellar key, and the Stellar key proving possession, both bound to this account and card). From here
on this card signs in with SEP-10: on the phone in scenario 07, and at a third-party server in
scenario 13. **Never fund that address**: the card signs nothing but SEP-10 challenges, so nothing could
ever spend from it.

Assertions: the record says `issuer=bridge` (never the local test issuer) and names the holder's
account, the program id is the bridge's, the record carries the card's Stellar address and the tool
registered it as its last step, the card row exists for the holder with an EC key, no RSA key
and a certificate (`cert_issuer_version`, `issuer_cert_hex`, `certified_at`), **the row holds the
Stellar address and both cross-signatures**, the admin API lists the card as active with that address
(`GET /admin/accounts/{holder}/cards`), the event feed holds
`card.registered` and `custody.card_certified` for this card and exactly one
`custody.issuer_key_generated`, **re-running the ceremony is a no-op with the same record**
(`already-issued`) that leaves **exactly one `card.stellar_key_registered`** for the card (the re-run's
`PUT` changed nothing), and the simulator still serves the issued card. With `SCARDUTIL_DIR` set, the plaintext
dispatch sequence (`impala-card/scardutil/impala-dispatch.md`) also runs through scardutil — the same
file that runs on a fleet of physical cards (see `impala-card/scardutil/README.md`) — on two simulator
targets of their own, one per hardware class: both must pass, and the engine byte must read `01` on the
JavaCard 3.0.5 card and `02` on the JavaCard 3.2 card.
24 assertions (27 with scardutil). The card lives in the simulator process: `simulator.sh down` destroys it and the next
run issues a new one (the bridge keeps the old row). Certifying a card is a custody write, and the
bridge allows an operator five of those per minute: when the budget is used up (scenario 12 certifies
several cards) the scenario waits 61 s and repeats the ceremony once.

### 06 — card login, SDK lane on the JVM (`scenario-06-card-login-jvm.sh`)

`./gradlew :app:e2eTnetDebug` in `impala-android-demo` against this bridge: the app's real flow
classes (`LoginViewModel`, `CardsViewModel`) drive a jcardsim card issued by the ceremony in library
mode. `CardAuthE2ETest` proves card login end to end — challenge, `SIGN_AUTH`, `POST /auth/card`,
single-use challenges, unregistered cards → generic 401, foreign cards refused client-side, lockout
after five bad signatures (`DEMO_E2E_SLOW=1` adds the 61 s expiry case). `CardTransferE2ETest` is
reported **skipped**: the bridge has no `/offline/*` lane yet. The lane fails if the `TEST ISSUER`
banner appears (certificates must come from the bridge's program key). The operator password travels
by file and is deleted afterwards. JUnit XML is copied to `state/artifacts/e2e-jvm/`.

This is the **legacy lane, kept on purpose**: the stack's bridge offers SEP-10 and these cards hold a
Stellar key, but the test gives the flow no SEP-10 home domain (the client's `NOT_CONFIGURED` case),
so every login here is `SIGN_AUTH` and `POST /auth/card`. It shows that the Payala-compatible login is
untouched on a bridge that also serves SEP-10. The lane is narrowed with
`-Pe2e.tests=CardAuthE2ETest,CardTransferE2ETest`; the SEP-10 classes run in scenarios 12 and 13.

### 07 — the Android emulator (`scenario-07-android-emulator.sh`)

`scripts/emulator.sh up` creates the AVD `impala-demo-34` if needed (API 34, Google APIs, arm64,
`pixel_6`), boots it headless (≈30 s warm, up to 3 min), turns animations off. The simulated card is
wired with `adb reverse tcp:9443` and `debug.impala.tcp_card=127.0.0.1:9443`; the app reaches the
bridge at `10.0.2.2:8080` (the tnet flavor's cleartext allow-list). `connectedTnetDebugAndroidTest`
runs `CardLoginUiTest` with `cardAccount=<holder>`: it taps **Sign in with Card** on the real login
screen and asserts `MainActivity` is reached with the holder's account and `auth_provider = card`;
`CardRedeemUiTest` runs too so its honest skip (the offline lane is not deployed) shows in the report.

**That tap is a SEP-10 sign-in.** The app's SEP-10 home domain defaults to the host and port of its
bridge URL, which is the bridge's own home domain, so with the card in the field the phone fetches
`http://10.0.2.2:8080/.well-known/stellar.toml`, asks for a challenge for the card's Stellar address,
checks it, has the card sign it (`SIGN_SEP10`: the card parses the transaction itself), and posts it
back. The scenario first checks that the app is built for this stack's bridge
(`TESTNET_BRIDGE_BASE_URL` in `impala-android-demo/local.properties`), waits for the signing key, and
then asserts the mechanism from both ends: the test is run with `-e cardMechanism sep10` and requires
the app's Activity Log line "Card signed a SEP-10 challenge", and the bridge's log must hold
`sep10: card key <the card's address> signed in` for the holder. With `DEMO_SEP10=false` the same test
is run with `cardMechanism legacy` and asserts the legacy line instead. 11 assertions.

The phone neither knows nor cares what is under the card: with `DEMO_CARD_PLATFORM=jc32` the same tap
is answered by a JavaCard 3.2 card signing with its platform's EdDSA (scenario 05 issues it first), and
the same 11 assertions hold. Both were run on 2026-11-12.
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
`account.role_changed` events are emitted. The SEP-10 admin routes follow the same table, with no
capability of their own: the key-custodian and the auditor read the signing keys (`ReadKeys`), the
treasurer and a view-only account do not, neither the auditor nor the treasurer can generate or revoke
one (`ManageKeys`), and an account's card list is `ReadAccounts`. Read-mostly; no money moves.
36 assertions.

### 11 — what is deliberately unconfigured, as evidence (`scenario-11-reserve-events.sh`)

Read-only: the conversion reserve is *armed but inactive* (`GET /admin/exchange-reserve`:
`configured:false`, the three seeded buckets USD/USDC/USDT0 at zero, no trustline), the exchange
providers are all disabled and a quote is refused, the key inventory is enabled with the OpenBao
protector but holds nothing (fingerprints only, no secret-shaped values), and the admin event feed is
the audit trail of the run — accounts created, seeds provisioned, policy updated, issuer key
generated, cards certified, payments settled, the SEP-10 signing key generated and activated (versions
and fingerprints only, never the key's address) — with no seed, password or JWT in any payload, payment
events carrying only the intent id, and the holder refused on the feed. 14 assertions.

### 12 — SEP-10 sign-in with the bridge (`scenario-12-sep10-bridge.sh`)

Runs after scenario 07. A card's Stellar key signs the bridge's SEP-10 challenge and the bridge mints
the card's session. Four parts, 31 assertions:

1. **The signing key is in service.** The admin API reports SEP-10 enabled for the home domain, a live
   key ring, and exactly one key that is `active` and `opened` on this bridge instance (the scenario
   waits out the activation delay when `seed.sh` has just run); the event feed holds the key's custody
   trail with fingerprints and never an address.
2. **Discovery and the challenge, with curl.** `/.well-known/stellar.toml` names the active key as
   `SIGNING_KEY`, the endpoint and the testnet passphrase. `GET /auth/sep10?account=<the issued card's
   address>` answers a transaction that `scripts/sep10-challenge.py` reads field by field (plain XDR in
   the Python standard library: nothing shared with the bridge, the card or the app): sourced by the
   signing key, **sequence number 0**, time bounds of exactly the configured lifetime, two manage-data
   operations (`"<home domain> auth"` sourced by the client with a 64-character nonce, `web_auth_domain`
   sourced by the server) and exactly one signature. Every answer, refusals included, carries
   `Access-Control-Allow-Origin: *`, and the challenge is `no-store`. A malformed account, a memo and
   a body that is not a challenge are refused with 400; a challenge sent back without the client's
   signature gets the generic 401, with no token in the answer.
3. **The app's flow classes on the JVM** (`:app:e2eTnetDebug -Pe2e.tests=CardSep10E2ETest`). Cards
   issued by the ceremony sign in through `LoginViewModel.signInWithCardTap` with SEP-10, **one of
   each hardware class**: the default CAP on a simulated JavaCard 3.0.5 card (the software engine) and
   the native CAP on a simulated JavaCard 3.2 card (the platform's own EdDSA), and the session
   works; a signed challenge is accepted once, and a signature that is not the card's is refused; a
   card without a Stellar key (`none`) signs in with the legacy challenge on the same bridge; and
   **the admin's card is refused by SEP-10 and signs in the legacy way in the same tap** (the bridge
   never serves SEP-10 to an account with a privileged role; the session it gets through the legacy
   login carries the role `admin`).
4. **The bridge's own evidence.** Its log has a `sep10: card key G… signed in` line for each SEP-10
   sign-in and the refusal line for the admin; the event feed has exactly one
   `card.stellar_key_registered` for each card with a key; `registered_card_keys` counts them; and
   `GET /admin/accounts/{id}/cards` lists the lane holder's cards with their Stellar addresses.

Artifacts: `state/artifacts/e2e-sep10/` (JUnit XML and `sep10-bridge.json`: which card signed in by
which mechanism; no token is stored). With `DEMO_SEP10=false` the scenario records `skipped`.

### 13 — SEP-10 sign-in with third-party services (`scenario-13-sep10-third-party.sh`)

A card's Stellar key is an ordinary Stellar identity, so the card can sign in wherever SEP-10 is
spoken, not only at the bridge. For each home domain in `DEMO_SEP10_THIRD_PARTY` (testnet servers;
the default is the SDF reference anchor, `testanchor.stellar.org`):

1. **Discovery from the host.** Its `stellar.toml` offers a web-auth endpoint and a signing key and
   names the testnet passphrase, and its challenge, read by the same `sep10-challenge.py`, has the
   shape the card accepts: sequence 0, time bounds, manage-data only, the first operation `"… auth"`
   sourced by the client. A server that does not offer SEP-10 **on testnet** fails the scenario at
   this point: no challenge is requested from it and no card is asked to sign for it (tried with a
   pubnet anchor's home domain: one failed assertion, exit 1, the card lane never started).
2. **The card lane on the JVM** (`:app:e2eTnetDebug -Pe2e.tests=CardSep10ThirdPartyE2ETest`). Three
   cards sign in there through `CardSignIn`, the same class the app uses: **the holder's card from
   scenario 05**, over the simulator's socket (the card the bridge issued, with the key it uses at the
   bridge), and one jcardsim card per hardware class (a JavaCard 3.0.5 card on the software engine, a
   JavaCard 3.2 card on its platform's EdDSA). Each card parses the server's challenge with its
   own on-card rules, signs it, and receives the server's token, a JWT whose `sub` is the card's
   Stellar address.
3. **The token at work.** A SEP-24 route of that server (`/transactions?asset_code=…`) refuses the
   request without the token (401 or 403) and answers it with the token (200).

What leaves the laptop: the card's public Stellar address and its signature over the server's
challenge. No account id, no bridge token, nothing about the bridge. The report in
`state/artifacts/e2e-sep10-third-party/` holds addresses, the token's `iss` / `sub` / `iat` / `exp`
claims and status codes; the scenario asserts that it holds no token. A server that cannot be reached
is reported and skipped, and with none reachable (or an empty `DEMO_SEP10_THIRD_PARTY`) the scenario
records `skipped`; it does not need the bridge at all. 10 assertions with the default server, 7 more
for each further one: `DEMO_SEP10_THIRD_PARTY=testanchor.stellar.org,anchor-sep-server-dev.stellar.org`
(the reference anchor and SDF's development instance of the Anchor Platform) passed with 17 on
2026-11-12, all three cards signing in at both. Only the reference anchor is the default, because a
demo should not depend on a development server.

### verify (`verify.sh`)

Re-checks every recorded fact against the **live** system, not the scorecard: health and migrations;
the four accounts, their custody mapping and funding; for each payment scenario the Horizon status,
the bridge's intent / `custodial_sign` row; the card program id against the issued card and its row;
that SEP-10 is enabled for the home domain with a signing key active or scheduled, and that the issued
card's Stellar key is the one registered on its row; the host lanes' records and artifacts; and that
**every hash recorded by this run's scenarios is on Horizon and successful** (the historical `state/testnet-txids.tsv` survives resets and is re-checked by
`scripts/txids.sh --check`). Exit 1 on any failure.

## 5. SEP-10 in the demo

**What is switched on.** `compose.yaml` starts the bridge with `SEP10_ENABLED=true` (the `.env` key
`DEMO_SEP10`, default `true`) and `SEP10_WEB_AUTH_ENDPOINT=http://10.0.2.2:<BRIDGE_PORT>/auth/sep10`.
The bridge then serves three public routes: `/.well-known/stellar.toml`, and `GET` and `POST
/auth/sep10`. `seed.sh` does the operator's part through the admin API, the way the runbook has it
(`docs/runbooks/sep10.md`): `generate` (a pending key, sealed by OpenBao, never returned), wait until
`GET /admin/sep10/signing-keys` reports the key `opened` on this bridge, then `activate` with the typed
phrase. The key takes over 120 s later, by the bridge's own clock. The API and the dashboard's SEP-10
screens are described in `docs/sep10-api-and-admin-ui.md`; the bytes in `docs/sep10-card-keys.md`.

**One bridge, two names.** A SEP-10 server has one name, its home domain, and a client checks that the
challenge was made for that name. The phone is the client that matters here, and from the Android
emulator the host's bridge is `10.0.2.2:<BRIDGE_PORT>`, so that is the home domain. Clients on the host
reach the same listener at `127.0.0.1` and still have to *say* `10.0.2.2`:

| Client | How it keeps the name |
|---|---|
| the tnet app on the emulator | nothing to do: `10.0.2.2` is how it reaches the bridge anyway, and its SEP-10 home domain defaults to the host and port of its bridge URL |
| curl in the scenarios | `sep10_curl` in `scripts/lib.sh`: `curl --connect-to 10.0.2.2:<port>:127.0.0.1:<port>` |
| the JVM lane (`CardSep10E2ETest`) | `Sep10E2e.AliasedTransport`: requests for the home domain go to the bridge's host address, with the name unchanged |

Plain `http` is acceptable here and only here: the bridge takes an `http` web-auth endpoint only for
`localhost`, `127.0.0.1` and `10.0.2.2`, the app's tnet flavor allows cleartext only to `10.0.2.2`, and
SEP-10 on the bridge is testnet-only in this phase.

**The card's hardware.** A simulated card is a CAP on a card model (`impala-card/README.md`, "Simulated
hardware"): the JavaCard level it implements and which optional algorithms it really has. Two keys in
`.env` choose the card that `scripts/simulator.sh` serves to the issuance tool and to the phone:

| Key | Values |
|---|---|
| `DEMO_CARD_PLATFORM` | `jc305` (default): a JavaCard 3.0.5 card, no EdDSA API; the default CAP makes the Stellar key with its software engine. `jc32`: a JavaCard 3.2 card; the native CAP signs with the platform's EdDSA. Also `jc31`, `jc31-sha512`, `jc32-per-curve` (other ways a platform offers EdDSA), and the lesser cards (`jc305-no-xy`, `jc305-fixed-curves`, `jc32-no-eddsa`, …), which install as legacy cards |
| `DEMO_CARD_ED25519` | empty (default): the CAP an operator would load on that hardware. `soft`, `native` or `none` to name one, for example the default CAP on JavaCard 3.2 hardware |

`scripts/simulator.sh models` lists every card model. A CAP that the hardware does not load (the native
CAP on a JavaCard 3.0.5 card) is refused at `up` with what the CAP imports and what the card has, as a
card's loader refuses it. A lesser card is issued like any other and comes out without a Stellar key:
scenario 05 then stops at its Stellar-key assertions, which is what trying one is for; the SEP-10 lanes
need a card that has the key.

```bash
DEMO_CARD_PLATFORM=jc32 scripts/scenario-05-card-issue.sh        # restarts the simulator as a JavaCard 3.2 card and issues it
DEMO_CARD_PLATFORM=jc32 scripts/scenario-07-android-emulator.sh  # the phone taps that card
scripts/simulator.sh status                                      # … jc32 (JavaCard 3.2), CAP native
scripts/simulator.sh stellar                                     # native <the card's public key>
```

Set the key in `.env` to run the whole suite on that hardware. What each run covers either way:

| Lane | JavaCard 3.0.5 card (software engine) | JavaCard 3.2 card (platform EdDSA) |
|---|---|---|
| Issuance over TCP, the bridge's certificate and key registration (05) | when `DEMO_CARD_PLATFORM=jc305` | when `DEMO_CARD_PLATFORM=jc32` |
| The phone on the emulator (07) | when `jc305` | when `jc32` |
| SEP-10 at the bridge through the app's flow classes (12) | every run | every run |
| SEP-10 at third-party servers (13) | every run | every run |
| scardutil dispatch sequence (05, with `SCARDUTIL_DIR`) | every run | every run |

**The waits you will notice.**

| Wait | Where | Why |
|---|---|---|
| about 30 s, on a fresh database | `seed.sh`, before `activate` | The bridge allows an operator five custody writes per minute (seeds, the issuer key, the SEP-10 key and card certificates share the budget). `seed.sh` makes five and then wants a sixth, so it waits for the window and retries once |
| up to 30 s | `seed.sh`, before `activate` | The bridge's key ring reads new keys every 30 s, and activation is refused (409 `sep10_key_not_opened`) until it has opened the key |
| 120 s after `seed.sh` | scenarios 07 and 12, only when started that soon | The activation delay. Until it has passed, the public routes answer 503 and a card login falls back to the legacy challenge |
| 61 s, four times in a full run | `run-all.sh`, before scenarios 06, 07, 12 and 08 | Every host lane is one client source for the bridge's pre-auth budget (30 requests per minute); the quiet windows keep one lane's requests out of the next lane's minute |
| 61 s, sometimes | scenario 05, and the card lanes when they issue cards | The same custody budget: a card certificate is one of the five writes per minute |

**Try it by hand** (after `seed.sh`, and scenario 05 for the card's address):

```bash
PORT=8080                                              # BRIDGE_PORT in .env
c() { curl -sS --connect-to "10.0.2.2:$PORT:127.0.0.1:$PORT" "$@"; }
c "http://10.0.2.2:$PORT/.well-known/stellar.toml"
G="$(jq -r .stellar_address state/records/scenario-05-card-issue.json)"      # the issued card's Stellar address
c "http://10.0.2.2:$PORT/auth/sep10?account=$G" | jq -r .transaction \
  | python3 scripts/sep10-challenge.py | jq .          # the transaction the card is asked to sign
scripts/status.sh                                      # includes the SEP-10 key, key_ring_live and the card count
```

In the admin UI (`http://localhost:3000`, signed in as the admin): **Keys** shows the panel *SEP-10
signing key (card sign-in)* with the key `seed.sh` made, the line *This instance* reading "key ring
live; the active key is open: serving SEP-10", and the number of cards with a Stellar key. **Accounts**
→ the holder → *Cards* shows the issued card with its Stellar address and a SEP-10 badge; after scenario
12 the admin's own card is listed with the note that the bridge refuses SEP-10 for an account with a
privileged role.

**Switches** (`.env`):

| Key | Effect |
|---|---|
| `DEMO_SEP10=false`, then `scripts/up.sh` | The bridge runs without SEP-10: its public routes are 404 and `seed.sh` makes no signing key. Scenario 01 asserts the 404 (19 assertions then), scenario 07 asserts the legacy mechanism (10 assertions), scenario 12 records `skipped`. Scenario 13 still runs: it does not use the bridge. Setting it back to `true` and running `up.sh` again restores SEP-10 with the key that is already in the database |
| `DEMO_SEP10_THIRD_PARTY=a.example,b.example` | The **testnet** SEP-10 servers of scenario 13 (home domains, comma-separated). Empty skips the scenario; an unreachable server is skipped; one that is not a testnet SEP-10 server fails it |

What the demo does not show: SEP-10 on mainnet (the bridge refuses to enable it there), a signing-key
rotation, more than one bridge replica, and a physical card or phone. `docs/sep10-card-keys.md` §9 lists
what is verified and what is not.

## 6. Everyday commands

| Command | What it does |
|---|---|
| `scripts/status.sh` | containers, bridge health, accounts and balances, intents, transactions, the card program, SEP-10 (enabled, key ring, signing keys, cards with a Stellar key), simulator/emulator status, the scorecard, last testnet ids |
| `scripts/txids.sh [--check] [--json]` | every testnet transaction id the suite created, with Horizon / stellar.expert URLs; `--check` re-confirms them on Horizon |
| `scripts/logs.sh [service\|simulator\|emulator]` | `compose logs -f` (default `impala-bridge`) or the host lanes' logs |
| `scripts/simulator.sh up\|down\|restart\|status\|probe\|stellar\|hardware\|models` | the jcardsim card server (pid and log under `state/simulator/`): which hardware and CAP it serves, the card's Stellar key and engine, the list of card models |
| `scripts/emulator.sh up\|down\|status\|screenshot <name>` | the AVD lifecycle; `DEMO_HEADLESS=0` for a window |
| `scripts/down.sh` | stop (volumes kept — but see the OpenBao note); also stops the simulator and emulator |
| `scripts/reset.sh [--yes]` | destroy containers, volumes and records; keeps `.env`, `state/keys` and `state/testnet-txids.tsv` |
| `scripts/run-all.sh --smoke` / `--only <step>` / `--skip <step>` / `--no-build` / `--keep` | subsets of the suite (a step is a name from the scorecard, for example `--only scenario-12-sep10-bridge`); Ctrl-C stops the simulator and emulator and writes an `interrupted` report; while a payment scenario is recorded `ambiguous`, no further payments are made until the record is resolved and deleted |
| `CONTAINER_ENGINE=podman scripts/…` | run anything against Podman (section 7) |

## 7. Docker and Podman

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

## 8. Things that fail silently, and what the kit does about them

| Symptom | Cause / what happens |
|---|---|
| every custodial payment or card certificate fails with a seed-protection error | OpenBao (dev mode, in-memory) restarted — `down.sh` + `up.sh`, a machine reboot — so its Transit key is gone and every sealed seed and the issuer key are undecryptable. `reset.sh --yes && up.sh && seed.sh` is the recovery; this is why `down.sh` warns. |
| the bridge container never becomes ready | no outbound HTTPS to Horizon testnet (the bridge exits after 5 tries), or the host port is taken. `logs.sh` shows the reason only because the OTLP collector exists: without `OTEL_EXPORTER_OTLP_ENDPOINT` the bridge logs nothing readable in a container. |
| `custodial_unconfigured` on a payment | caps are 0 on a fresh database; `seed.sh` sets them (100 XLM per tx, 1 000 XLM per account per day). |
| `429 rate_limited` / lockout | pre-auth 30/min per source, sign 5/min per account, 5 wrong passwords lock an identity for 15 min. Slow down; there is no API to clear a counter. |
| `429` from the issuance tool at certification, or from `seed.sh` at the SEP-10 `activate` | the custody-write budget: five per minute per operator, shared by seeds, the issuer key, the SEP-10 signing key and card certificates. `seed.sh`, scenario 05 and the card lanes wait out the window and retry once; by hand, wait a minute. |
| the phone's card login used the legacy challenge although SEP-10 is on | the signing key was not in service: `seed.sh` activated it less than two minutes earlier (the public routes answer 503 until then, which is the client's "not offered" fallback), or it was never generated. `scripts/status.sh` shows the key and its state; scenarios 07 and 12 wait for it themselves. |
| scenario 07 fails on "the app is built for this bridge" | `BRIDGE_PORT` in `.env` is not the port in `TESTNET_BRIDGE_BASE_URL` of `impala-android-demo/local.properties`. Set that to `http://10.0.2.2:<BRIDGE_PORT>` (it is also the app's SEP-10 home domain) and rerun. |
| the app refuses the login with a challenge error instead of falling back | a challenge that fails the client checks (another home domain, key or network than expected) is an error by design, never a downgrade. Check `TESTNET_SEP10_HOME_DOMAIN` in the app's `local.properties`: unset, or equal to `10.0.2.2:<BRIDGE_PORT>`. |
| scenario 13 is `skipped` | the third-party server was not reachable from this host (or `DEMO_SEP10_THIRD_PARTY` is empty). `doctor.sh` reports reachability up front. |
| `transfer send` or `send` exits 3, or a `202` intent stays `ambiguous` | an **ambiguous** outcome: the payment may have been submitted. The scripts stop, record `status: ambiguous` and exit 3; `run-all.sh` makes no further payments until you resolve it (`impalactl activity list`, the intent, Horizon) and delete the record. |
| the card lane says the simulator is not serving the issued card | `simulator.sh down` (or a Gradle restart) destroyed the in-memory card; scenario 05 issues a new one. |
| `simulator.sh up` says the running simulator serves another card | a simulator is one card on one kind of hardware; `DEMO_CARD_PLATFORM` changed since it started. `scripts/simulator.sh restart` (the card it holds is lost), or run scenario 05, which restarts it and issues the new card. |
| `simulator.sh up` says a CAP "does not load on a JavaCard 3.0.5 card" | `DEMO_CARD_ED25519=native` with `DEMO_CARD_PLATFORM=jc305`: the native CAP imports the JavaCard 3.1 API. Use `jc31` or `jc32` hardware, or the default CAP. |
| scenario 05 fails on "record carries the card's Stellar address" | the card model is one that cannot make the key (a `jc305-no-…` card, `jc32-no-eddsa`): it is a legacy card, as designed. The SEP-10 scenarios need `jc305`, `jc31` or `jc32`. |
| `CardTransferE2ETest` / Android *Load card*, *Redeem* | out of scope: the bridge has no `/offline/*` lane. |
| testnet reset (accounts vanish) | `txids.sh --check` reports the missing hashes; `reset.sh --yes && up.sh && seed.sh`. |
| the admin UI shows a blank page or SSO fails | open exactly `http://localhost:3000`; the OIDC issuer is `http://localhost:8200`. |

## 9. Files

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
scripts/seed.sh           accounts, caps, custodial seeds, Friendbot, card issuer key, the SEP-10 signing key (generate, wait, activate)
scripts/scenario-01..13-*.sh · verify.sh · run-all.sh
scripts/sep10-challenge.py         reads a SEP-10 challenge field by field (Python standard library; no Stellar code)
scripts/testdata/sep10-challenge.{b64,json}   a challenge built by the bridge's own code and what the reader must say about it
scripts/simulator.sh · emulator.sh
scripts/payala/           the relays, against the stub (lib-payala.sh, seed-payala.sh, payala-order.sh, reflect.sh, reflect-payala.sh, demo-payment.sh, test-payala-to-impala.sh)
recordings/demo.tape      vhs recording of a smoke run + txids --check
state/                    records/, artifacts/, testnet-txids.tsv, timings.tsv, report.{md,json}, impala.env, keys/   (generated, gitignored)
build/ bin/               generated, gitignored
```

CI (`.github/workflows/demo.yml`) lints the kit — `bash -n`, shellcheck (`-x -P SCRIPTDIR`, so the
`$(dirname "$0")`-relative sources are followed), `docker compose config`, the
generated Containerfile's pinned `FROM` lines, the Payala stub's `node --test`, the SEP-10 challenge
reader against its fixture (which must be the bridge's own shared vector, `sep10/card_vectors.rs`), and
a grep that keeps the proprietary Payala API out of the kit — because the suite itself needs testnet, an
engine, a JDK and an emulator. To record a console run:
`cd ~/Documents && vhs /path/to/impala/demo/recordings/demo.tape`.
