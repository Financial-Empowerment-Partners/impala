# Impala bridge command-line interface

`impalactl` drives the [impala-bridge](../impala-bridge) REST API from a
terminal or a script: force-sync accounts, create accounts (including custodial
ones), make transfers, and inspect account status and activity.

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
impalactl whoami                        # account, role, expiry — read locally, no network
impalactl logout                        # revoke this token and forget it
impalactl logout --all                  # revoke every token and session for the account
```

For CI, skip the store entirely and pass a temporal token directly:

```bash
export IMPALA_TOKEN="$(vault kv get -field=token secret/impala/ci)"
impalactl account list
```

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

- **Secrets are never command-line arguments.** The login password and Stellar
  seeds come from an environment variable (`$IMPALA_PASSWORD`,
  `$IMPALA_SECRET_SEED`), a no-echo prompt, or stdin.
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
