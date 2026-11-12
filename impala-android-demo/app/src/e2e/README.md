# T1 end-to-end lane (`src/e2e`)

JVM tests that drive the app's real flow classes (`LoginViewModel`,
`CardsViewModel`, the transfer controllers) against a **live bridge**, with a
jcardsim card issued by the impala-card issuance ceremony (`tools/issue`,
library mode). They compile with the unit tests and skip unless
`IMPALA_E2E_BRIDGE_URL` is set.

```bash
# A DISPOSABLE bridge: migrations ≥ 039, Redis, KEY_IMPORT_ENABLED=true + an
# OpenBao/KMS protector (bridge-issued certificates), the operator id in
# ADMIN_ACCOUNT_IDS, and ALLOW_OPEN_REGISTRATION=true (the holders the tests
# create register their own passwords — never set this on a real deployment).
# The operator's account row must exist before its first login, e.g.
#   psql "$DATABASE_URL" -c "INSERT INTO impala_account (stellar_account_id, payala_account_id, first_name, last_name) VALUES ('<G…>', '<operator uuid>', 'E2E', 'Operator')"
export IMPALA_E2E_BRIDGE_URL=http://localhost:8080
export IMPALA_E2E_OPERATOR_ACCOUNT=<uuid listed in ADMIN_ACCOUNT_IDS>
export IMPALA_E2E_OPERATOR_PASSWORD_FILE=/path/to/operator-password   # or IMPALA_E2E_OPERATOR_TOKEN_FILE
./gradlew :app:e2eTnetDebug                       # IMPALA_E2E_SLOW=1 adds the 61 s challenge-expiry test
./gradlew :app:e2eTnetDebug -Pe2e.tests=CardAuthE2ETest,CardSep10E2ETest   # only these classes (simple names, or fully qualified)
```

For the SEP-10 classes, also:

```bash
# CardSep10E2ETest: a bridge with SEP10_ENABLED=true and an ACTIVE signing key (docs/runbooks/sep10.md).
# The value is the bridge's home domain, the host[:port] of its SEP10_WEB_AUTH_ENDPOINT. It may differ from
# the address in IMPALA_E2E_BRIDGE_URL (a demo stack names itself 10.0.2.2:8080 for the emulator): the lane
# then sends the requests to IMPALA_E2E_BRIDGE_URL and keeps the name (Sep10E2e.AliasedTransport).
export IMPALA_E2E_SEP10_HOME_DOMAIN=10.0.2.2:8080
# CardSep10ThirdPartyE2ETest: TESTNET SEP-10 servers to sign in to (home domains, comma-separated). Needs
# no bridge. A server on another network fails the test before anything is signed.
export IMPALA_E2E_SEP10_THIRD_PARTY=testanchor.stellar.org
export IMPALA_E2E_CARD_TCP=127.0.0.1:9443         # optional: a card behind a TCP APDU socket takes part too
export IMPALA_E2E_REPORT_DIR=/path/to/reports     # optional: sep10-bridge.json / sep10-third-party.json (no tokens)
```

| Test | What it proves |
|---|---|
| `CardAuthE2ETest` | E2E-1: a registered, issued card logs in through `LoginViewModel`; single-use challenges; unregistered cards get a generic 401; cards issued to another account are refused client-side; expiry; lockout after five verified-bad signatures |
| `CardTransferE2ETest` | E2E-2 (load + redeem): skipped until the bridge serves the offline lane (D-3) |
| `CardSep10E2ETest` | E2E-3: cards issued by the ceremony sign in through `LoginViewModel` with the bridge's SEP-10 endpoint, one per hardware class (the default CAP's software engine on a simulated JavaCard 3.0.5 card, the native CAP on a simulated JavaCard 3.2 card: `E2e.hardwareFor`), and the session works; a signed challenge is accepted once and a signature that is not the card's is refused (401); a card without a Stellar key signs in with the legacy challenge on the same bridge; the operator's card is refused by SEP-10 (privileged role) and signs in the legacy way in the same tap |
| `CardSep10ThirdPartyE2ETest` | E2E-4: for each server in `IMPALA_E2E_SEP10_THIRD_PARTY`, a jcardsim card per hardware class (JavaCard 3.0.5 and JavaCard 3.2, as above) and the card at `IMPALA_E2E_CARD_TCP`, when set (its hardware is whatever its simulator serves: `:simulator:serve --platform`) signs the server's challenge through `CardSignIn` and receives its token (a JWT whose `sub` is the card's Stellar address); the token then opens a SEP-24 route that refuses a request without it. An unreachable server is reported, not failed; with none reachable the test is skipped |

Each class skips, with the reason, when a variable it needs is missing: `CardAuthE2ETest` and
`CardSep10E2ETest` need `IMPALA_E2E_BRIDGE_URL`, the latter also `IMPALA_E2E_SEP10_HOME_DOMAIN`;
`CardSep10ThirdPartyE2ETest` needs only `IMPALA_E2E_SEP10_THIRD_PARTY`. The operator-card case of
`CardSep10E2ETest` needs the operator by account and password file (`IMPALA_E2E_OPERATOR_ACCOUNT`,
`IMPALA_E2E_OPERATOR_PASSWORD_FILE`), not only a token file: a card is issued to that account.
`CardAuthE2ETest` gives the
flow no SEP-10 client, so its logins are the legacy challenge even on a bridge that offers SEP-10:
together the classes show both mechanisms side by side. Issuing a card costs the operator one of the
bridge's five custody writes per minute; the lane waits 61 s and retries when the bridge answers 429.
The demo kit runs these classes as its scenarios 06, 12 and 13 (`demo/README.md`).

**Simulated hardware.** `E2e.blankCard(ed25519, platform)` makes the lane's cards: a CAP variant on a
card model of impala-card's simulator (`CardPlatform`: `JC305`, `JC32` and the lesser cards; see
`impala-card/README.md`, "Simulated hardware"). The reports (`sep10-bridge.json`,
`sep10-third-party.json`) carry `engine`, `platform` and `javacard` for each sign-in.

Without an operator (or without an issuer key and `KEY_IMPORT_ENABLED`), cards
are issued with a local **test issuer**: they log in (login checks the
registered key, not the certificate) but are never redeemable.
