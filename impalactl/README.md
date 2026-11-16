# Impala bridge command-line interface

`impalactl` drives the [impala-bridge](../impala-bridge) REST API from a
terminal or a script: force-sync accounts, create accounts (including custodial
ones), make transfers, inspect account status and activity, and sign in with
a password, a second factor (TOTP or a device key) or a card (SEP-10 or the
legacy card challenge).

It is a thin, typed client over the same contract as
[`impala-bridge/openapi.yaml`](../impala-bridge/openapi.yaml) — no database or
Redis access, no privileged side channel. Whatever your token is allowed to do,
`impalactl` can do; nothing more.

## Install

Requires Go 1.26+. The only dependency is `golang.org/x/term`, for no-echo
secret prompts.

```bash
go build -o impalactl .      # build a local binary
# or
go install .                 # install into $GOPATH/bin
```

## Pointing at a bridge

Every command runs against one bridge, resolved **flag → environment →
default**:

| Setting  | Flag                | Environment variable | Default                 |
| -------- | ------------------- | -------------------- | ----------------------- |
| Endpoint | `--endpoint <url>`  | `IMPALA_ENDPOINT`    | `http://localhost:8080` |
| Token    | `--token <jwt>`     | `IMPALA_TOKEN`       | stored credentials      |
| Timeout  | `--timeout <dur>`   | —                    | `45s`                   |

The default timeout deliberately exceeds the bridge's own 30-second request
deadline: a client that gives up at the same instant as the server loses the
server's verdict. With the headroom, a slow request ends with the bridge's own
answer (its 408, or a late 200/500) rather than a client-side cut. Setting
`--timeout` below 30s reintroduces that gap.

Check that you are talking to the right one (no credentials needed):

```bash
impalactl health
impalactl --endpoint https://bridge.example.com health
```

Global flags may appear before or after the command:
`impalactl --json account list` and `impalactl account list --json` are the same.

## Authenticating

```bash
impalactl login --username alice        # password from a no-echo prompt
```

The password is read from `$IMPALA_PASSWORD`, an interactive prompt, or stdin —
never from a command-line argument, since argv is visible to other processes and
lands in shell history.

Login stores the bridge's refresh/temporal token pair with `0600` permissions in
`$XDG_CONFIG_HOME/impalactl/credentials.json` (override the directory with
`$IMPALA_CONFIG_DIR`). Later commands reuse it and refresh the short-lived
temporal token automatically when it is within a minute of expiring.

Two details worth knowing:

- **Credentials are endpoint-scoped.** They record which bridge issued them and
  are never sent anywhere else, so pointing `--endpoint` at a different
  deployment fails loudly instead of leaking a production token into a test one.
- **Refresh tokens are single-use.** The bridge rotates them and treats a replay
  as theft, revoking the whole token family. `impalactl` persists each
  replacement before using it and serializes rotation between concurrent
  invocations with a lock file, so parallel scripts don't lock each other out.

```bash
impalactl whoami                        # account, role, factors, expiry — read locally, no network
impalactl logout                        # revoke this token and forget it
impalactl logout --all                  # revoke every token and session for the account
```

For CI, skip the store entirely and pass a temporal token directly:

```bash
export IMPALA_TOKEN="$(vault kv get -field=token secret/impala/ci)"
impalactl account list
```

### Multi-factor sessions

Every session records the factors the bridge verified for it (`amr`: `pwd`
password, `sc` card, `pin` card PIN, `otp` TOTP, `dev` device key, and the
derived `mfa` once two different factor kinds are present). An account the
bridge requires to be multi-factor (its own flag, or its role in
`MFA_REQUIRED_ROLES`) gets `403 mfa_required` from every route until the
session steps up; every command explains that refusal and names the fix. See
[`docs/mfa-card-pin-biometrics.md`](../docs/mfa-card-pin-biometrics.md).

```bash
impalactl mfa status                    # this session's factors, and whether they satisfy the account
impalactl mfa totp enroll               # prints the otpauth:// URI (it carries the shared secret) once
impalactl mfa step-up --totp            # code from $IMPALA_TOTP_CODE, a no-echo prompt, or stdin
impalactl login alice --totp            # password, then the code, in one command
impalactl mfa device enroll --label "ops laptop"
impalactl mfa step-up --device          # this machine's device key signs a fresh challenge
impalactl mfa device list               # marks this machine's key
impalactl mfa device revoke <key-id>    # also forgets this machine's copy
```

A step-up on a bearer session revokes the presented token family and returns a
new pair; `impalactl` replaces the stored credentials under the same lock it
uses for refresh rotation. A refused step-up (a wrong code, an unknown key)
changes nothing. With `--token`/`$IMPALA_TOKEN` the new pair cannot be stored,
so `mfa step-up` then requires `--json`, which prints it.

`mfa totp enroll` refuses to re-enroll an account that already has TOTP unless
`--replace` is given: the bridge replaces the secret at once, and the current
authenticator stops working. The enrollment is active immediately.

Governance (the summary is readable by the accounts-read roles; the rest is admin):

```bash
impalactl mfa admin show bob                    # factors on file: TOTP, device keys, cards (no secrets)
impalactl mfa admin mandate bob on              # require MFA; signs bob out everywhere
impalactl mfa admin mandate bob off
impalactl mfa admin revoke-device bob <key-id>  # recovery for a lost device
```

### Signing in with a card

`login --card` signs in with an Impala card over the impala-card simulator
transport (`tcp:HOST:PORT`, the socket `demo/scripts/simulator.sh` serves). It
is a port of the one reference flow, impala-lib's `CardSignIn`:

- A card with a Stellar key signs in with **SEP-10**: the endpoint's
  `stellar.toml`, a challenge for the card's address, the client checks (v1
  envelope, source = `SIGNING_KEY`, sequence 0, time bounds valid now, no
  memo, manage-data only, `"<home domain> auth"` sourced by the card key with
  a 64-byte nonce, `web_auth_domain`, exactly one valid server signature for
  the bridge's network), `SIGN_SEP10` on the card, and the signed envelope
  posted to the web-auth endpoint.
- It falls back to the **legacy card challenge** (`SIGN_AUTH`,
  `POST /auth/card`) in exactly three cases: SEP-10 is not offered (no
  `stellar.toml`, no endpoint or key in it, or 404/503), the server answers
  401 (the card's Stellar key is not registered, or the account holds a
  privileged role: the bridge never mints a privileged session over SEP-10),
  or `--no-sep10`. Any other failure (a 429, a challenge that fails a client
  check, a card refusal) is an error, never a downgrade.
- `--pin` verifies the card's user PIN (from `$IMPALA_CARD_PIN`, a no-echo
  prompt, or stdin) and sends the card's PIN proof, adding `pin` to the
  session. A card whose policy requires a sign-in PIN is refused before any
  request unless `--pin` is given; a wrong PIN is an error.
- `--device` adds this machine's device key for the card's account.

```bash
impalactl card info --card tcp:127.0.0.1:9443            # read-only: applet, ids, Stellar key, PIN policy
impalactl login --card tcp:127.0.0.1:9443 --pin
impalactl --endpoint http://127.0.0.1:8084 login --card tcp:127.0.0.1:9443 \
    --sep10-home-domain 10.0.2.2:8084                   # the demo bridge's SEP-10 name
```

The home domain is the NAME the challenge must be for; it defaults to the
`host[:port]` of `--endpoint`. `--sep10-home-domain` changes the name only:
every connection still goes to `--endpoint` (like a hosts-file entry), and the
`WEB_AUTH_ENDPOINT` in `stellar.toml` must be on the home domain, so a signed
challenge is never sent to any other host. What happened (card, mechanism,
fallback case, factors) is printed on stderr; tokens, PINs, nonces and
signatures never are.

## Commands

### Account status

```bash
impalactl account show G...             # the bridge's record for a Stellar address
impalactl account onchain G...          # live Horizon balances, sequence, signers
impalactl account reserves alice        # Payala reserve balances (defaults to your account)
impalactl account list --search ada     # paginated list of all accounts (admin, auditor, or key-custodian)
impalactl account list --page 2 --per-page 50
```

### Creating accounts

```bash
# Link an existing Stellar address to a Payala account.
impalactl account create \
  --stellar G... --account alice \
  --first-name Ada --last-name Lovelace --affiliation "Analytical Engines"

# Custodial account: the bridge generates the seed, protects it with the
# configured backend (KMS / Vault / OpenBao), and returns only the address.
impalactl account generate --account alice --first-name Ada --last-name Lovelace

# Custodial account from a seed you already hold. The seed is read from
# $IMPALA_SECRET_SEED, a no-echo prompt, or stdin — never from argv.
impalactl account import --account alice --first-name Ada --last-name Lovelace
```

### Force syncing

```bash
# Record a sync timestamp and reconcile against Soroban RPC (admin).
# Takes the Stellar address, not the Payala account id.
impalactl sync force G...

# Force a directory re-pull of an account's profile (admin; LDAP-sourced only).
impalactl sync profile alice

# Ingest a batch of offline Payala transactions (owner-only, idempotent).
impalactl sync payala --file batch.json
cat batch.json | impalactl sync payala --file -

# Switch an account between reserve and mirror sync (admin).
impalactl sync mode alice --mode mirror
impalactl sync mode alice --mode mirror --force    # leave reserve mode with a nonzero balance
```

A batch file is either a bare array of items or a full request object:

```json
[
  { "payala_tx_id": "tx1", "amount": -1500, "currency": "USD", "memo": "coffee" },
  { "payala_tx_id": "tx2", "amount": 200,   "currency": "USD" }
]
```

```json
{
  "account_id": "alice",
  "transactions": [
    { "payala_tx_id": "tx1", "amount": -1500, "currency": "USD" }
  ]
}
```

Amounts are signed integers in **minor units**; the sign is the direction
(`+` incoming, `-` outgoing). Parsing is strict — an unrecognized field is
rejected rather than silently dropped, because a dropped `amount` or `currency`
would corrupt the batch. The account id comes from `--account`, else the file,
else the logged-in account.

Batches are idempotent per `(account, payala_tx_id)`: re-submitting is safe and
is reported as `duplicates`. A replayed id whose stored amount or currency
differs from the submission is reported as `conflicting` and always warned about
on stderr — that is a ledger-integrity signal, not routine idempotency.

### Transfers

```bash
# Sign and submit an XLM payment from a custodial account. Real, irreversible.
impalactl transfer send --to G... --amount 12.5 --memo rent
impalactl transfer send --account alice --to G... --amount 12.5 --fee 500 --yes

# Record a dual-chain transaction. Bookkeeping only — nothing goes on-chain.
impalactl transfer record --payala-tx-id ptx1 --source-account G... \
  --payala-currency USD --memo kiosk
```

`transfer send` always prints the bridge URL and the Stellar network to stderr
before it does anything. On testnet it proceeds; on any other network it demands
a typed `yes` at an interactive terminal, and refuses outright when
non-interactive unless `--yes` is passed. A scripted mainnet payment therefore
has to opt in deliberately rather than by forgetting which bridge it was
pointed at.

**An unknown outcome is exit 3, not a failure.** The bridge signs and submits
inside the request, records the transaction row only *after* settlement, and
the endpoint has no idempotency key — so a timeout, a dropped connection, or a
5xx says nothing about whether the funds moved, and re-running "because it
failed" is how a payment gets made twice. When the answer does not prove the
payment refused, `transfer send` prints a notice naming the payment and the
checks to make, and exits **3**:

```
error: [408 http_error] Request Timeout

WARNING: the outcome of this payment is UNKNOWN.
The request reached (or may have reached) the bridge, and the error above does
not prove the payment was refused. The bridge signs and submits server-side, so
the payment MAY HAVE BEEN SUBMITTED and can still settle: a signed transaction
stays valid for up to 300 seconds.

  From:    alice
  To:      G...
  Amount:  12.5 XLM

DO NOT re-run this command until you know what happened: a re-run is a second
payment, not a retry. Check, in this order:

  1. impalactl activity list
     A new row (origin "api", created just now, the sending custodial address as
     its source) means the payment settled; "impalactl activity show <btxid>"
     gives its Stellar hash. Do not send again.
  2. The chain. The bridge records that row only AFTER settlement, and a bridge
     timeout can drop the record while the payment still lands — so an absent
     row is not proof. Check the sending account's sequence number and balance
     ("impalactl account onchain <G...>") and the destination's payments on
     Horizon.
  3. Wait out the 300-second window before concluding the payment did not
     happen; only then is it safe to send again.
```

What counts as ambiguous: the bridge's **408** (its request deadline fired
mid-handler, possibly inside the Horizon submit, which then completes on its
own — and drops the bookkeeping row), **500 `internal_error`** (the bridge
maps every ambiguous Horizon submission — a 504 timeout, a 5xx, an
undecodable answer — to this), **502/504 and any other 5xx** from something
in front of the bridge, a **client-side timeout**, a connection **dropped
after the request went out**, and a 2xx whose body could not be read. What
does not: **503 `service_unavailable`**, the bridge's *Retryable*, reserved
for failures that provably happened before anything was signed (a proxy's 503
likewise never forwarded the request); every other **4xx** — validation,
authentication, rate limiting; a `success: false` body; and a connection that
could **never be established** (refused, no such host), since not one byte
left the machine. Those stay exit 1 and may be retried or fixed as usual.

Scripts should treat exit 3 as "stop and page a human", never as "retry":

```bash
impalactl transfer send --to G... --amount 12.5 --yes
case $? in
  0) echo "sent" ;;
  3) echo "OUTCOME UNKNOWN — check activity and the chain; do not retry" >&2; exit 3 ;;
  *) echo "not sent" >&2; exit 1 ;;
esac
```

### Account activity

```bash
impalactl activity list                                  # transactions with review state
impalactl activity list --status escalated --flagged true
impalactl activity list --account G... --from 2026-08-01T00:00:00Z
impalactl activity list --search coffee --per-page 100
impalactl activity show <btxid>                          # one transaction in full
impalactl activity review <btxid> --status escalated --flagged --note "duplicate?"
impalactl activity events --since 42                     # admin event feed
```

Admins and auditors see every transaction; everyone else sees only transactions sourced from
accounts they own. `activity review` is a **full replacement** of the review
record: anything you don't pass is reset.

`activity events` prints the cursor to use next, so a poller is just:

```bash
cursor=0
while :; do
  cursor=$(impalactl activity events --since "$cursor" --json | jq '.events[-1].id // '"$cursor")
  sleep 30
done
```

### Bridge keys (admin or key-custodian; the list is auditor-readable)

Installs the credentials the bridge uses to move money. **Read
`docs/runbooks/import-keys.md` first** — importing a provider credential is
spend authority over the replenishment leg's outgoing treasury XLM.

```bash
impalactl keys list                                      # running, stored, and the gap
impalactl keys import changelly_crypto \
    --part-file private_key=/run/secrets/changelly.hex   # api_key is prompted for
impalactl keys import changelly_crypto --replace \
    --part-file private_key=/run/secrets/new.hex         # prompts for the confirm phrase
impalactl keys revoke owlpay                             # scrubs the stored ciphertext
impalactl stellar-seed generate --account bridge-reserve # the only way to seed the reserve
impalactl stellar-seed import --account svc-payouts      # seed via prompt/stdin/env
```

Three behaviours are worth knowing before you use these:

- **Imports only add.** If anything is already in effect — including a
  credential the deployment supplies through environment variables — the
  command refuses until you pass `--replace` *and* type the exact phrase the
  bridge names. The phrase includes the network, which is what catches the
  right key in the wrong environment.
- **Nothing takes effect until the bridge restarts.** Credentials are resolved
  once per process so every instance in the fleet switches together. `keys
  list` shows the gap.
- **Part values never touch argv.** `--part-file name=path` is the only way to
  pass a multi-line PEM; otherwise a part comes from
  `$IMPALA_KEY_<KIND>_<PART>` (e.g. `IMPALA_KEY_OWLPAY_API_KEY`) or a no-echo
  prompt. The kind is in the variable name deliberately: a shared
  `IMPALA_KEY_API_KEY` would let a value exported for one provider be submitted
  to another without anyone being asked, and both sides would accept it because
  both are well-formed opaque strings.

### SEP-10 signing key (status: admin, key-custodian, auditor; changes: admin, key-custodian)

The server signing key every SEP-10 client pins through `stellar.toml`. It is
generate-only, like the card issuer key. Read
[`docs/runbooks/sep10.md`](../docs/runbooks/sep10.md) first.

```bash
impalactl sep10 info                     # public: what stellar.toml publishes (404/503: not offered)
impalactl sep10 status                   # enabled, home domain, key ring, every key in full
impalactl sep10 key generate             # a pending version
impalactl sep10 key activate 2           # prompts for "activate sep10-signing <network>"
impalactl sep10 key revoke 1 --confirm-phrase "revoke sep10-signing testnet v1"
impalactl sep10 cards bob                # bob's cards and their Stellar addresses
```

Activation sends the active key's fingerprint as a compare-and-set, refuses
while the answering instance has not opened the new key, and takes over on
every instance at `activate_at`. Both phrases name the network the bridge
reports; like `keys import --replace`, `--yes` never stands in for them.

### Cards: issuance, cardholder PINs and the program key

`card setup` issues a card: it is a port of the reference issuance ceremony
(`impala-card/tools/issue`, `impala-card/docs/transfer-protocol.md` §5) and sends the card
exactly that tool's command sequence, after one `SELECT`. It needs two
tokens: the operator's (the stored session, `--token` or `$IMPALA_TOKEN`; it
needs keys-manage, i.e. admin or key-custodian) for the certificate, and the
card holder's (`$IMPALA_HOLDER_TOKEN`) for `POST /card` and
`PUT /card/stellar-key`, which are the holder's own requests. Without
`$IMPALA_HOLDER_TOKEN` the session's own token is used only when its subject
is `--account`; otherwise it is a usage error.

```bash
impalactl card issuer show                               # public: is the card program configured
impalactl card issuer generate                           # the first program key (generate-only)
export IMPALA_ISSUE_KMK=…  IMPALA_CARD_PIN=…  IMPALA_CARD_MASTER_PIN=…  IMPALA_HOLDER_TOKEN=…
impalactl card setup --card tcp:127.0.0.1:9443 --account 6f1d9c52-0b7e-4c3a-9e15-2a4b8c7d6e90 \
    [--currency XLM|USDC|USDT0] [--card-minor-scale 7] [--initial-counter 0] [--cap impala.cap]
```

In order, each step idempotent:

1. **Pre-flight, before the card is touched:** the holder token is checked (a
   token for another account is refused; a missing one is reported before any
   secret is asked for), `GET /card-issuer` must say the program is
   configured, `GET /network` names the network for the confirmation, and
   then every secret is read. There is no local role check: an operator
   session without keys-manage gets the bridge's 403 at the certificate, and
   the card is left initialized and registered for the next run.
2. `GET_VERSION` (0.2 or newer) and `GET_PERSONALIZATION`. A terminated card
   is refused. Unless `--yes`, what is about to happen is shown on stderr and
   confirmed (the usual rule: on testnet without a prompt, elsewhere only from
   a terminal or with `--yes`): it writes a certificate on the bridge and
   personalizes the card, neither of which can be undone.
3. `INITIALIZE` (unless done: the card generates its id, P-256 key and Stellar
   key), then the card id and key are read.
4. SCP03 (C-MAC, C-DEC, R-MAC, R-ENC) on the card's own keys, derived from the
   key master key as the reference tool derives them. A card still on its
   transport keys (the GP default keys, or `$IMPALA_SCP03_TRANSPORT_KEYS`) is
   first rotated to them (`APPLET_UPDATE`). A cryptogram that does not verify
   under a key set sends nothing more, so the wrong KMK is an error, never a
   lockout.
5. `POST /card` (holder), unless the operator's listing
   (`GET /admin/accounts/{account}/cards`) already shows the card active. Only
   a 500 or 409 is tolerated ("probably registered already": certification
   decides); any other refusal stops the run before the certificate. Then
   `POST /admin/cards/{id}/certificate` (operator; a 409
   from an earlier run that stopped before `PERSONALIZE` is retried once with
   `recertify`). The certificate is checked against `GET /card-issuer`, against
   a card bound to its program at install, and verified under the issuer key
   over the CERT message **before anything is sent to the card**.
6. `PERSONALIZE` identity, issuer key (skipped for a card bound at install),
   certificate; `PROVISION_PIN` master then user; the read-back must show
   personalized, PIN-provisioned and not on default keys.
7. The record is built from what the card reports now. The card's Stellar key
   is registered (`PUT /card/stellar-key`, holder) after both cross-signatures
   verify here; a refusal is not fatal: the card is issued and signs in with
   the legacy challenge until a re-run registers it (the record says so).

A personalized card changes nothing on the card: a re-run prints its record
(`already-issued`) and repeats only the Stellar key registration, which the
bridge answers with success, so a run whose last step was lost is finished.
A card personalized without its PINs (a run that stopped before
`PROVISION_PIN`; under ENFORCE such a card cannot sign) gets its PINs, after
the same confirmation: the run reports `issued` with no `issuer_version` (it
obtained no certificate). A
personalized card of another account is refused, naming both. A 429 at
certification is the custody budget (5 writes per 60 s per operator, shared
with seeds, issuer and SEP-10 keys): wait a minute and run the command again.

The secrets: the key master key from `$IMPALA_ISSUE_KMK` (32 hex, the
reference tool's variable, so both tools derive the same per-card keys), the
user PIN to provision from `$IMPALA_CARD_PIN` (4 digits, not `0000`) and the
master PIN from `$IMPALA_CARD_MASTER_PIN` (8 digits), each also from a no-echo
prompt or one stdin line, in that order; `$IMPALA_SCP03_TRANSPORT_KEYS` (96 hex
ENC ‖ MAC ‖ DEK) and `$IMPALA_HOLDER_TOKEN` from the environment only. Unlike
the reference tool there is no `--test-issuer` (every card here is certified by
the bridge) and no `--terminate`; use `impala-card/tools/issue` for those.

`--json` prints one object (an append-only schema): `card_id`, `account_id`,
`program_id`, `currency`, `cert_id`, `applet`, `applet_hash`, `cap_sha256`
(with `--cap`), `issuer_version` (omitted when nothing was certified),
`stellar_key` (`{address, engine, registered, note}`, `note` only when not
registered; `null` for a card without one) and `status` (`issued` or
`already-issued`).

The cardholder PIN commands (applet 0.4, a provisioned PIN):

```bash
impalactl card pin change --card tcp:127.0.0.1:9443       # $IMPALA_CARD_PIN, then $IMPALA_CARD_NEW_PIN
impalactl card pin policy on --card tcp:127.0.0.1:9443    # require the PIN to sign in (off: stop)
impalactl card pin reset --card tcp:127.0.0.1:9443        # $IMPALA_CARD_MASTER_PIN, then $IMPALA_CARD_NEW_PIN
```

`change` verifies the current PIN, sets the new one and verifies it once;
`policy` does nothing (and sends no PIN) when the card is already in the
requested state, and a requirement fixed at install never turns off; `reset`
sets a new user PIN with the master PIN, which also unblocks a blocked one.
The master PIN has 10 tries and no recovery. A PIN being set is asked twice
at a terminal. Each prints the card id and the resulting PIN state; `--json`
gives `{card_id, action, changed, user_verification}`. A wrong or blocked PIN
is an error naming the card's status word (`WRONG_PIN: 4 tries left`).

`card issuer generate` creates the program issuer key inside the bridge
(generate-only: it is sealed there and never exported). With a key active it
refuses unless `--rotate`, and a rotation needs the typed phrase
`replace card-issuer <network>` (or `--confirm-phrase`; `--yes` never stands
in for it) and sends the active fingerprint as a compare-and-set. A rotation
invalidates the program key on every card until each is re-personalized and
re-certified. Read [`docs/runbooks/card-issuer.md`](../docs/runbooks/card-issuer.md).

## Output and exit codes

Human-readable summaries by default; `--json` prints the server's response body
verbatim (only re-indented), so fields this CLI doesn't model are never dropped
and `jq` sees exactly what the bridge sent.

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| `0`  | Success                                                              |
| `1`  | Runtime failure — API error, validation failure, or degraded health. Nothing moved. |
| `2`  | Usage error — unknown command, missing or invalid flag               |
| `3`  | **Ambiguous outcome** of `transfer send`: a timeout, a dropped connection, or a 5xx that does not prove the payment was refused. It may have been submitted — do not retry blindly; see [Transfers](#transfers). |

API errors are rendered from the bridge's error envelope, keeping its code and
message: `error: [403 forbidden] Access denied`. Rate limits report the
`Retry-After` delay. Failures that never reached a bridge verdict — a timeout,
a refused connection, an unreadable answer — name the request instead:
`error: POST https://bridge.example.com/managed-account/sign: ...`.

## Security

- **Secrets are never command-line arguments.** The login password, Stellar
  seeds, TOTP codes, card PINs and the card key master key come from an
  environment variable (`$IMPALA_PASSWORD`, `$IMPALA_SECRET_SEED`,
  `$IMPALA_TOTP_CODE`, `$IMPALA_CARD_PIN`, `$IMPALA_CARD_NEW_PIN`,
  `$IMPALA_CARD_MASTER_PIN`, `$IMPALA_ISSUE_KMK`), a no-echo prompt, or stdin
  (one line each, in the order the command asks).
- **`card setup` checks before it writes.** Every secret, both tokens and the
  card program are checked before the card is touched; the certificate is
  verified here before the card sees it; the card's Stellar key signatures are
  verified before the bridge does. No secret, token, PIN or key is printed;
  the record carries ids and public keys only.
- **What `card setup` proves, and what it takes the card's word for.** The
  secure channel proves the card holds the keys (its cryptogram is checked
  before `EXTERNAL AUTHENTICATE` is sent, so a wrong key master key costs the
  card nothing), and every setup command reaches it encrypted and
  authenticated. The answers are another matter: the applet acknowledges the
  key rotation, `PERSONALIZE` and the PINs with a bare status word that carries
  no response MAC, and the read-back that follows is a plain read. For a card
  with a Stellar key the personalization is still evidenced cryptographically,
  because the card signs its two cross-signatures over the account only when it
  accepts the certificate, and they are verified here. For a card without one,
  and for the PINs on any card, success is what the card reports over the
  transport. Run the ceremony over a transport you trust, as with the reference
  tool; here that is the simulator's loopback socket. The KMK and the PINs are
  held as strings while the command runs and cannot be wiped from memory
  afterwards (the byte buffers derived from them are).
- **Stored tokens are `0600` inside a `0700` directory**, written atomically so
  a crash cannot leave a half-written credentials file, and scoped to the
  endpoint that issued them.
- **`login --json` prints the token pair** (that is the raw response body). Use
  it deliberately — piping it into a log or CI transcript exposes a credential.
- **A custodial seed never reaches this CLI.** `account generate` and
  `stellar-seed generate` return only the public address, and `transfer send`
  signs server-side; `account import` and `stellar-seed import` are the commands
  that send a seed, and they send it once.
- **`keys import` is the safe surface for provider credentials.** The admin UI
  can do the same thing, but a key pasted into a browser is exposed to
  extensions, autofill and session restore. Here a secret comes from a file,
  stdin, or a no-echo prompt.
- **A device key is a possession factor, nothing more.** `mfa device enroll`
  generates a P-256 key on this machine and keeps it `0600` under
  `$IMPALA_CONFIG_DIR/device-keys/`, one file per (endpoint, account); a file
  is never used for another pair. Anyone who can read the file holds the
  factor. It is declared to the bridge as `platform: impalactl`,
  `user_verification: none`: never biometric.
- **The TOTP URI is shown once.** `mfa totp enroll` prints the `otpauth://`
  URI on stdout (it carries the shared secret); nothing keeps a copy.
- **Card login keeps the card's secrets on the card.** The Stellar key signs
  only a challenge the card itself parsed; impalactl verifies the server's
  challenge before the card sees it and the card's signature before anything
  is sent. The simulator transport is cleartext (a PIN crosses it as four
  digits), so a non-loopback card address needs `--insecure-http`.
- **Client-side validation is convenience, not a boundary.** Address, seed and
  amount checks here mirror the bridge's own so mistakes fail before a round
  trip; the bridge re-validates everything, and it is the only authority on
  authorization.

## Development

```bash
go build ./...                                  # build
go test ./...                                   # run all tests
go test ./internal/cli -run TestTransferSend    # run one test
go vet ./...                                    # static checks
gofmt -l -w .                                   # format
```

The layout mirrors `lumencli`: `internal/bridge` holds the API client and the
wire types (mirroring `impala-bridge/src/models.rs`), `internal/config` the
credential store, and `internal/cli` the argument parsing and rendering. Command
functions take their I/O from the `App` struct rather than reaching for
`os.Stdout`/`os.Getenv`, so tests drive the whole CLI against buffers and an
`httptest` stub bridge.

The card commands are tested twice over. `internal/card/cardtest` is an
in-process fake card written from the applet's source (its own AES-CMAC and
SCP03 card side, the applet's status words and gates), which the error paths
and the interrupted states run against. And `card setup` replays sessions
recorded off the wire between the reference issuance tool and the real applet
on jcardsim (`internal/card/testdata/`, a JavaCard 3.0.5 and a JavaCard 3.2
card): every command must equal the recorded one, byte for byte and in order.
That is what keeps the two tools one ceremony. When the ceremony or the
applet's version changes, record them again
(`internal/card/testdata/record.sh`; see the README there).
