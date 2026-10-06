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
```

| Test | What it proves |
|---|---|
| `CardAuthE2ETest` | E2E-1: a registered, issued card logs in through `LoginViewModel`; single-use challenges; unregistered cards get a generic 401; cards issued to another account are refused client-side; expiry; lockout after five verified-bad signatures |
| `CardTransferE2ETest` | E2E-2 (load + redeem): skipped until the bridge serves the offline lane (D-3) |

Without an operator (or without an issuer key and `KEY_IMPORT_ENABLED`), cards
are issued with a local **test issuer**: they log in (login checks the
registered key, not the certificate) but are never redeemable.
