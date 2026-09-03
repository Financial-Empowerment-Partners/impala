# Stellar Lumens Command Line Interface

`lumencli` is a command-line wallet for **Stellar Lumens (XLM)**. It uses the
Stellar SDK to create accounts, show the public key associated with an account,
view balances, and send and receive lumens — on **mainnet** or **testnet**.

## Install

Requires Go 1.24+.

```bash
go build -o lumencli .      # build a local binary
# or
go install .                # install into $GOPATH/bin
```

## Networks

Every command runs against one network. Selection precedence is **flag → env →
default**, and the default is `mainnet`. The active network is always printed to
stderr before any operation that reads or moves funds.

| Setting        | Flag                     | Environment variable        |
| -------------- | ------------------------ | --------------------------- |
| Network        | `--network mainnet\|testnet` | `LUMEN_NETWORK`         |
| Horizon URL    | `--horizon-url <url>`    | `LUMEN_HORIZON_URL`         |
| Passphrase     | `--network-passphrase <s>` | `LUMEN_NETWORK_PASSPHRASE` |

`--network-passphrase` together with `--horizon-url` lets you point at a custom
network (e.g. Futurenet or a local Quickstart). Global flags may be given before
the command (`lumencli --network testnet balance G...`) or before a
subcommand's positional arguments (`lumencli balance --network testnet G...`).

## Commands

```
lumencli account new        Generate a new keypair (offline)
lumencli account address    Derive the public address (G...) from a secret seed
lumencli account create     Create & fund a new account on-ledger (spends XLM)
lumencli account fund       Fund an account via testnet Friendbot (testnet only)
lumencli balance <address>  Show the balances of an account
lumencli history <address>  Show the transaction history of an account
lumencli tx <hash>          Show one transaction: status, fee, memo, operations
lumencli send               Send XLM to another account
lumencli receive            Show your address for receiving XLM
lumencli version | help
```

`history` takes filtering and output flags — `--json`, `--csv`, `--summary`,
`--follow`, direction/counterparty/asset/time filters, and more. See
[Transaction history](#transaction-history) for the full reference.

### Examples (testnet)

```bash
# 1. Generate a keypair (offline — nothing is sent anywhere)
lumencli account new
#   Public key (address): G...
#   Secret seed:          S...

# 2. Fund it on testnet via Friendbot
lumencli --network testnet account fund --address G...

# 3. Check the balance
lumencli --network testnet balance G...

# 4. Create another account, funding it from yours (seed read from env, not argv)
export LUMEN_SECRET=S...your-funding-seed...
lumencli --network testnet account create --dest G...new... --amount 50

# 5. Send a payment with an optional memo
lumencli --network testnet send --to G...dest... --amount 25 --memo "thanks"

# 5b. Send to an exchange, which identifies the deposit by an id memo
lumencli --network testnet send --to G...exchange... --amount 25 \
  --memo-type id --memo 3141592653

# 6. Show your receiving address
lumencli receive --address G...

# 7. View the account's transaction history
lumencli --network testnet history G...
```

To run the same commands on mainnet, drop `--network testnet` (or set it to
`mainnet`). Friendbot is testnet-only; on mainnet a new account must be funded
by an existing account via `account create`.

## Transaction history

`history <address>` lists the operations that moved funds into or out of an
account — payments, path payments, account creations, and merges — newest
first, with the counterparty, memo, and transaction hash of each:

```
2026-08-31 20:14:37 UTC  received  25.0000000 XLM  (payment)
  From: GBOSTEH5XRAMOJWXIWIPJT5P6GOW6GYXQJ7GHORK3X2Z426BWGYFTVLA
  Memo: id 3141592653
  Tx:   73b0e6af59879f824e2b735e3081e27360ece25bd186ef95d36c5d27bc0fac70
```

By default the **entire** history is fetched, following Horizon's paging until
the account's first transaction. Addresses and transaction hashes are printed
in full, never abbreviated: history is what you consult when checking whether
a deposit arrived or where funds went, and a truncated identifier cannot be
pasted into an explorer or compared against a receipt. Amounts are shown in
the asset transferred (`XLM` for lumens, `CODE` otherwise). An `account merge`
shows `entire balance` — the ledger does not record the amount a merge moved.

A payment from the account **to itself** — the standard Stellar pattern for
converting one asset to another via a path payment — is shown as a
`converted` entry with both legs, and carries direction `self` in the
machine-readable output. Treating it as a plain send would book the outgoing
leg and silently drop the incoming one, corrupting every net figure computed
downstream.

`history` takes the account's `G...` address; an `M...` (muxed) address is
rejected with guidance, because Horizon indexes accounts, not muxed
sub-addresses. To isolate one muxed depositor, pass the `M...` address to
`--counterparty` on the pooled account's history.

### Flags

| Flag | Meaning |
| ---- | ------- |
| `--limit <n>` | Stop after the newest *n* entries (`0`, the default, means the full history). Stopping early is noted on stderr — and inside a `--summary` — so a truncated result cannot silently pass for a complete one. |
| `--failed` | Also list operations from failed transactions. These moved no funds and are marked `[FAILED — no funds moved]`; Horizon (and therefore the default listing) omits them. |
| `--json` | Write JSON Lines (one object per entry) instead of the human listing. |
| `--csv` | Write CSV instead of the human listing. Mutually exclusive with `--json`. |
| `--sent` / `--received` | Only entries in one direction. Mutually exclusive with each other (the default already shows both). `self` entries (conversions) are both a send and a receive, so they match either filter. |
| `--counterparty <G...\|M...>` | Only entries with this counterparty. See below for G vs. M semantics. |
| `--asset <native\|XLM\|CODE:ISSUER>` | Only entries moving this asset (either leg of a path payment). The issuer is required for non-native assets — see below. |
| `--since <t>` / `--until <t>` | Time range, inclusive at both ends. `YYYY-MM-DD` (UTC; a date-only `--until` covers that whole UTC day) or RFC3339. |
| `--summary` | Per-asset totals over the (filtered) range instead of the listing. No CSV form; combines with `--json`. Incompatible with `--follow` (totals need a finished range) and `--all-ops`. |
| `--all-ops` | List every operation type, not just the fund-moving kinds. Incompatible with the direction/counterparty/asset filters and `--follow` — see below. |
| `--follow` | After the listing, keep streaming new payments as they arrive (Ctrl+C to stop). Incompatible with `--until` (which bounds the past) and `--csv` (an export needs a finished range). |

Every meaningless flag combination is rejected up front with a clear error
rather than producing an accidental, silently-wrong behavior a script could
come to depend on.

**`--counterparty` — G vs. M matching.** A `G...` value matches the entry's
counterparty *account*. An `M...` value matches only the **exact muxed
address** the payment carried on the wire (on either side). This strictness is
the point: a muxed address identifies *one depositor* among the many sharing a
pooled account, so if an M input loosely matched the underlying account it
would match every depositor's payments — exactly the wrong answer when you are
checking whether *your* deposit arrived.

**`--asset` — the issuer is required.** `native` and `XLM` both mean the
lumen; anything else must be written `CODE:ISSUER` with the issuer's full
`G...` address. A bare code is rejected rather than matched loosely: asset
codes are **not unique** on Stellar — anyone can issue an asset named `USDC` —
and an issuer-less match could present a counterfeit asset as the real one.
For the same reason, the machine-readable outputs always render issued assets
with their full issuer. A native filter (`native`/`XLM`) also keeps account
merges — a merge moves exclusively the native lumen, and hiding it would
drop a fund movement exactly when you asked to see everything XLM.

**`--since` / `--until` — UTC semantics.** A bare date is interpreted as UTC:
`--since 2026-08-01 --until 2026-08-31` covers August, inclusive, in UTC. An
RFC3339 timestamp carries its own offset, so local-time precision is
available: `--since 2026-08-30T17:00:00-07:00` means 5 pm Pacific, exactly.

### What the listing covers — and what it omits

The default listing walks Horizon's **payments endpoint**: payments, path
payments, account creations, and account merges. That endpoint has known
blind spots, and this tool documents them rather than papering over them:

- **Claimable-balance operations** (`create_claimable_balance` /
  `claim_claimable_balance`) do not appear in it, even though they move funds.
- **Soroban contract transfers** (`invoke_host_function`) do not appear in it
  either — a token sent via a smart contract will not show.

`--all-ops` is the escape hatch: it walks the full operations endpoint
instead, so *every* operation the account was involved in is listed —
including the kinds above, trustline changes, offers, and anything newer.
Generic operations have no amount, direction, or counterparty, which is why
the direction/counterparty/asset filters refuse to combine with `--all-ops`:
they would silently drop every non-payment entry — a wrong answer about money
dressed as an empty result. Operation kinds the vendored Stellar SDK models
but lumencli gives no bespoke rendering are listed generically (type and
source account). A kind the SDK does not model at all — one newer than the
vendored SDK — makes the walk **fail loudly** with a decode error rather than
listing a silently incomplete page; the remedy is rebuilding against a newer
SDK. Either way, `--all-ops` completeness tracks the vendored SDK version.

### Machine-readable output

The `--json` and `--csv` schemas are a **compatibility promise**: scripts and
accounting exports depend on them across releases, so fields are
**append-only** — never renamed, retyped, or reordered.

`--json` writes JSON Lines: one object per entry, streamed as the walk
progresses. Fields:

| Field | Type | Present | Meaning |
| ----- | ---- | ------- | ------- |
| `id` | string | always | Horizon operation id |
| `paging_token` | string | always | Horizon cursor for this entry |
| `created_at` | string | always | Ledger close time, RFC3339, UTC |
| `type` | string | always | Wire operation type, e.g. `payment`, `path_payment_strict_send` |
| `direction` | string | always | `sent` \| `received` \| `self` \| `other` |
| `successful` | bool | always | Whether the parent transaction succeeded |
| `tx_hash` | string | always | Parent transaction hash |
| `ledger` | number | when the transaction join was present | Ledger sequence |
| `amount` | string | only when the exact value is in the record | Destination-leg amount, 7-decimal string |
| `asset` | object | with `amount` (also with `destination_min`, for the bound's asset) | `{"type":"native"}` or `{"type":...,"code":...,"issuer":...}` |
| `source_amount` | string | path payments, when the source leg is known | Source-leg amount, 7-decimal string |
| `source_asset` | object | with `source_amount` or `source_max` | Asset of the source leg |
| `source_max` | string | failed strict-receive path payments | The *bound* on the source leg — not an amount |
| `destination_min` | string | failed strict-send path payments | The *bound* on the destination leg — not an amount |
| `entire_balance` | bool (`true`) | account merges | The whole balance moved; the amount is not in the record |
| `counterparty` | string | fund-moving entries | The other account (`G...`) |
| `to_muxed` / `from_muxed` | string | when the wire carried one | Muxed (`M...`) form of the destination / source |
| `source_account` | string | generic operations (`--all-ops`) | The operation's source account |
| `memo` | object | when the transaction carried a memo | `{"type":...,"value":...}` — text verbatim, id decimal, hash/return as 64 hex digits |
| `memo_bytes` | string | when Horizon sanitized a text memo | Base64 of the raw memo bytes, so scripts can recover them exactly |

The amount semantics are strict, because these values flow into accounting:

- **Amounts are 7-decimal-place strings, never JSON numbers.** Parsing money
  through a float corrupts it; keep amounts as strings (or convert to integer
  stroops) in consuming code.
- `amount` and `source_amount` are present **only when they are exact
  values** — executed, or declared in the envelope of a failed operation
  whose `successful: false` already says nothing moved. The
  execution-determined leg of a **failed** path payment has no value: Horizon
  serializes it as a `"0.0000000"` placeholder, which is dropped, and the leg
  carries its bound instead — `source_max` for a failed strict-receive,
  `destination_min` for a failed strict-send. The envelope-fixed leg (the
  destination amount of a strict-receive, the source amount of a
  strict-send) stays: it is exact, and the failure is flagged by
  `successful`. Consumers doing money math must filter on `successful` —
  true for every operation kind, not just path payments.
- An account merge sets `entire_balance` and leaves every amount field empty —
  the ledger does not record what a merge moved.
- **There is deliberately no per-entry fee field.** Fees are per-*transaction*,
  and this listing is per-*operation*: a transaction with three payments would
  repeat its fee on all three entries, so the obvious
  `jq 'map(.fee) | add'` would double-count. Fees live in `tx <hash>` and in
  the deduplicated `--summary`.

`--csv` writes these columns, in order:

```
id, created_at, direction, type, amount, asset, source_amount, source_asset,
counterparty, to_muxed, from_muxed, memo_type, memo, tx_hash, successful
```

`asset` and `source_asset` are `native` or `CODE:ISSUER` (full issuer — a
short code alone would let a counterfeit asset pass for the real one in an
export). The amount columns hold strict decimals or nothing: the bounds and
wire placeholders of failed path payments and the unrecorded amount of a
merge are never written where a spreadsheet `SUM` would swallow them. Failed
rows (visible only under `--failed`) can still carry their envelope-declared
exact amounts with `successful` = `false` — exactly like a failed plain
payment — so a spreadsheet summing amounts must filter on the `successful`
column.

**Formula-injection guard.** Memo content is written by whoever sent the
payment — anyone can send dust with a memo of `=HYPERLINK(...)` — and the
documented use of `--csv` is opening the export in a spreadsheet, where cells
starting with `=` `+` `-` `@` or a tab execute as formulas. RFC-4180 quoting
(which the writer applies) does **not** stop that — Excel evaluates the cell
after unquoting — so such memo cells get a leading apostrophe, the spreadsheet
convention for "literal text".

**Empty results and errors.** An empty result is success: `--json` writes
nothing to stdout, `--csv` writes the header row only, and both exit 0 —
scripts should test for emptiness, not the exit code. A mid-walk error
(Horizon down, network drop) exits **1** with stdout truncated at the point of
failure, so a pipeline must check the exit status or a partial history can
pass for a complete one:

```bash
set -o pipefail
lumencli history G... --json | jq -r '.tx_hash' || {
  echo "history walk failed — do not trust the partial output" >&2
  exit 1
}
```

### Summary

`--summary` aggregates the (filtered) range into per-asset totals instead of
listing it. All arithmetic is exact — integer stroops, no floating point
anywhere near money — and each asset is keyed by `CODE:ISSUER` (or `native`),
so two assets sharing a code can never be summed together:

- **Per-asset lines** show received, sent, and net. A self-conversion books
  **both legs** — what left under the source asset and what arrived under the
  destination asset — so conversions net to zero only when the assets match.
- **The fee line** reads `Fees paid on the N listed transactions where this
  account was the fee payer` — and every word of that scope is load-bearing.
  It is deduplicated per transaction (a multi-operation transaction appears
  once), counts only transactions where the queried account actually paid the
  fee (a fee-bumped transaction someone else paid is excluded), and includes
  failed transactions whenever their records are visible (`--failed`) — their
  fees were charged regardless. It is **not** total fee accounting: the
  payments view only ever sees transactions containing fund-moving operations
  that touch this account, so a transaction that only burned a fee (or whose
  operations fall outside the view or your filters) cannot be counted from
  here. A complete fee audit needs the transactions endpoint, not this view.
- **Merges** carry no amount in the operation record, so a summary containing
  merges reports its totals as **lower bounds** and says so.
- **The coverage line** — `Summary of N entries from <oldest> to <newest>`,
  plus a truncation note when `--limit` stopped the walk — is part of stdout,
  not a stderr notice, because a redirected summary must never pass for a
  full-history total when it was filtered or truncated. Every summary
  describes exactly what it covers.

`--summary --json` emits one object with the same append-only discipline:
`account`, `entries`, `failed`, `truncated`, `oldest`, `newest`, `assets`
(each `{asset, received, sent, net}` — string decimals), `fees`
(`{listed_total, transactions}` — "listed" for the scope above), and
`merges_sent` / `merges_received`.

### Follow

`--follow` prints the backlog listing first, then keeps streaming new
payments as they arrive, rendering each with the same filters and format
(human or `--json`) as the listing. The stream resumes from the paging token
of the newest already-listed entry, so there is **no gap and no duplicate**
between the listing and the live tail — a payment landing while the listing
prints is not lost.

If the stream drops (network blip, Horizon restart), it reconnects with
exponential backoff, resuming from the last delivered entry — again no gap,
no duplicates — and each reconnect is announced on stderr. After **5
consecutive failures** the watch ends with an error and exit 1: silently
pretending to watch a real-money account is worse than stopping loudly. The
failure counter resets whenever an event arrives, so a long-running watch
survives any number of isolated drops — only a persistently unreachable
Horizon ends it.

Ctrl+C stops the watch cleanly and immediately, even on a quiet account (the
connection is torn down rather than waiting for the next event). A second
Ctrl+C during a slow shutdown force-kills the process the ordinary way.

## Transaction lookup

`tx <hash>` shows one transaction in full. The use case is pasting a hash
from a history entry, a receipt, or an explorer and seeing what it did:
status, ledger and close time, source account, fee, memo, and every operation
with **both** parties named (a transaction has no "my account" perspective).
`--json` emits a single object instead.

- A **failed** transaction is marked
  `FAILED — no funds moved; the fee was still charged` — the fee is the one
  part of a failed transaction that is real.
- A **fee-bump** transaction (someone else paid the fee) shows the fee as
  `paid by G...`; in JSON, `fee_payer` is present only in that case.

The hash is accepted in either case — explorers render hashes both ways.

### Scripting examples

Check the exit status in every pipeline (`set -o pipefail`): a mid-walk error
truncates stdout, and a partial history must not be mistaken for a complete
one.

Did the deposit with memo id `3141592653` arrive?

```bash
set -o pipefail
lumencli history G... --received --since 2026-08-01 --json \
  | jq -e 'select(.memo.type == "id" and .memo.value == "3141592653")' \
  && echo "deposit arrived"
```

Export a month to CSV for a spreadsheet (a date-only `--until` is inclusive
through the whole UTC day):

```bash
lumencli history G... --csv --since 2026-08-01 --until 2026-08-31 > 2026-08.csv
```

Monthly received total, computed by the exact-arithmetic summary rather than
by adding floats in `jq`:

```bash
set -o pipefail
lumencli history G... --summary --json --since 2026-08-01 --until 2026-08-31 \
  | jq -r '.assets[] | select(.asset.type == "native") | "received \(.received) XLM"'
```

Who did this account pay most often?

```bash
set -o pipefail
lumencli history G... --sent --json \
  | jq -r '.counterparty' | sort | uniq -c | sort -rn | head
```

> **Windows note:** output uses non-ASCII glyphs (`—`, `≤`, `≥`); they render
> fine in Windows Terminal, but garble on legacy codepages (e.g. `cmd.exe`
> without UTF-8).

## Memos

`send` and `account create` can attach a memo to the transaction. Stellar
supports four memo types; `--memo` carries the value and `--memo-type` selects
how it is encoded (default `text`):

| `--memo-type` | Value                                | Typical use                          |
| ------------- | ------------------------------------ | ------------------------------------ |
| `text`        | up to **28 bytes** of text           | a note to the recipient              |
| `id`          | unsigned 64-bit integer              | **exchange / custodial deposits**    |
| `hash`        | 64 hex digits (32 bytes)             | reference to another transaction     |
| `return`      | 64 hex digits (32 bytes)             | hash of the transaction being refunded |

```bash
lumencli send --to G... --amount 25 --memo "thanks"                  # text (default)
lumencli send --to G... --amount 25 --memo-type id --memo 3141592653  # id
lumencli send --to G... --amount 25 --memo-type hash --memo 0123...ef # 64 hex digits
```

### Missing-memo guard

A transfer that carries **no** memo to a destination believed to need one stops
with a warning and requires an explicit confirmation:

```
WARNING: this transfer carries no memo, but it declares on-ledger (SEP-0029)
that payments to it must carry a memo.
Deposits there are credited by their memo. Without one the funds usually cannot
be credited to you, and recovering them means contacting the operator's support.
Add one with --memo (for an exchange, usually --memo-type id).
Type "no memo" to send anyway:
```

Confirming is deliberately **separate from `--yes`**. `--yes` means "I know this
is mainnet", and it already appears in every non-interactive script; letting it
also wave through a missing memo would disarm this check everywhere it is most
needed. To send with no memo you must type `no memo` at the prompt, or pass
`--no-memo` when scripting.

A destination is believed to need a memo when either:

1. **It says so on-ledger.** The account sets the SEP-0029 data entry
   `config.memo_required`. This is authoritative — it comes from the account
   holder — and needs no maintenance here. `send` consults it before signing.
2. **It is on the built-in list** in `internal/stellar/memo_required.go`, for
   services that have not set the on-ledger flag. This list ships **empty**; see
   that file's comment for how to verify an address before adding one. It is for
   recognition only — never copy a destination address out of it.

Neither source is exhaustive, so **the absence of a warning is not a guarantee
that no memo is needed**. Check the recipient's deposit instructions.

`account create` consults only the list, since its destination cannot exist yet
and so cannot have declared anything.

Exchanges and other pooled accounts credit a deposit by its memo, so a missing
or wrong memo can lose the funds as surely as a wrong address. Accordingly:

- Naming a `--memo-type` without a `--memo` value is an error, never a silent
  no-memo transfer.
- The memo is named in the mainnet confirmation prompt and in the receipt line,
  so you see what will be attached before approving it.
- `text` memos are sent verbatim (their bytes are the message); the other types
  are trimmed of the whitespace copy-paste tends to pick up.
- The 28-byte text limit is bytes, not characters — non-ASCII memos run out of
  room sooner.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Success. An empty `history` result is a success too — test for emptiness, not the exit code. |
| `1`  | Failure: a validation error, a refused confirmation, a Horizon error, a mid-walk network error (stdout is truncated at the point of failure — see [Machine-readable output](#machine-readable-output)). Nothing moved. |
| `2`  | Usage error: unknown command, missing or invalid flag. |
| `3`  | **Ambiguous outcome** of a fund-moving command (`send`, `account create`): the transaction was signed and submitted, and the answer did not prove it rejected. It **may still be applied**. Do not re-run — see below. |

### Ambiguous submissions (exit 3)

A signed transaction is valid for **300 seconds** from the moment it is built.
Horizon's `POST /transactions` forwards it to the network and then waits for
it to be applied — but only for about 30 seconds, after which Horizon answers
**504 Timeout** with the transaction still pending. lumencli's own HTTP
timeout, a dropped connection, or a proxy giving up look the same from here.
None of these mean "not sent": the transaction can land at any point in the
rest of its window, whether or not anyone is still watching.

Re-running the command in that state is the trap. The re-run reloads the
account, sees the *next* sequence number, and builds a second, equally valid
transaction. If the first one lands too, the funds move twice.

So instead of a bare error, an ambiguous outcome prints a notice with the
full transaction hash (computed locally before submission, so it is known
even when Horizon never answered), the exact time until which the
transaction can still be applied, and the lookup to run — and exits **3**,
distinct from a plain failure so that a script cannot mistake "maybe paid"
for "not paid":

```
error: submit transaction: Timeout — Your request timed out before completing. ...

WARNING: the outcome of this payment is UNKNOWN.
The transaction was signed and handed to Horizon, and the error above does not
prove it was rejected: it MAY STILL BE APPLIED at any moment until its time
bound expires.

  Transaction hash: 7b1f0c...  (64 hex digits, never abbreviated)
  Valid until:      2026-09-03 12:04:47 UTC (in 287s)

DO NOT re-run this command until you know what happened. A re-run signs a NEW
transaction with the next sequence number; if the first one is applied as well,
the funds move twice. Look the transaction up with:

  lumencli tx 7b1f0c... --network mainnet

A "not found" answer inside the window proves nothing — the transaction can
still be applied later. Keep checking until the time bound has passed; only
then does "not found" mean it was never applied and it is safe to try again.
```

The procedure is exactly what the notice says:

1. Run the printed `lumencli tx <hash>` command. If it shows the transaction,
   it was applied (check `Status:` — a failed transaction moved nothing but
   its fee). Do not send again.
2. If it is **not found**, wait and check again. Inside the window this
   proves nothing: Horizon may still be holding the transaction, and it can
   land seconds later.
3. Once the `Valid until` time has passed, a not-found answer is definitive
   — the transaction can no longer be applied — and re-running is safe.

Only a **definitive rejection** is a plain exit 1: a Horizon 400 carrying
result codes (`tx_bad_seq`, `tx_insufficient_fee`, `op_underfunded`, ...),
any other 4xx verdict, or a connection that could never be established, so
that no byte of the request left the machine. Everything else — Horizon's
504, a 5xx, a 429 or 503 (which may come from anything between here and
Horizon), a client-side timeout, a reset, an undecodable answer — is exit 3.
The rule errs towards "check" because the cost of a needless check is a
minute, and the cost of a needless retry is the payment.

Scripts should treat exit 3 as "stop and page a human", never as "retry":

```bash
lumencli send --to G... --amount 25 --yes
case $? in
  0) echo "sent" ;;
  3) echo "OUTCOME UNKNOWN — see the hash on stderr; do not retry" >&2; exit 3 ;;
  *) echo "not sent" >&2; exit 1 ;;
esac
```

## Security

This is a wallet for real money, so key handling matters:

- **Secret seeds are never taken as command-line arguments** (argv is visible to
  other processes and shell history). Commands that need a seed read it from the
  `LUMEN_SECRET` environment variable, an interactive no-echo prompt, or piped
  stdin.
- `account new` prints the secret seed to stdout so you can save it — store it
  securely and never share it. Anyone with the seed controls the funds.
- The active network is always echoed before a fund-moving operation, so you
  cannot silently spend mainnet funds while thinking you are on testnet.
- The provided `.gitignore` excludes common key/secret file patterns.

## Development

The `Makefile` bundles every check; plain `go` commands work too.

```bash
make build          # static, version-stamped ./lumencli for the host
make test           # go test ./...
make race           # tests under the race detector
make vet fmt-check  # static checks / formatting gate
make cross          # cross-build all six release targets into dist/
make verify         # fmt-check + vet + test + race + build (offline, host only)
make verify-linux   # full test suite on linux/arm64 AND linux/amd64 in Docker,
                    # then smoke-runs any cross-built linux binaries in dist/
make vulncheck      # govulncheck gate (needs network + jq; not part of verify)
make verify-all     # verify + verify-linux + vulncheck
```

`verify-linux` rides [OrbStack](https://orbstack.dev) on macOS: the arm64 leg
runs natively (with `-race`), the amd64 leg through Rosetta — which is why
that leg skips the race detector (TSan is unsupported under emulation; native
amd64 race coverage comes from CI's ubuntu runner instead). Every `docker run`
pins `--platform` explicitly, because a bare image tag silently resolves to
whichever architecture was pulled last.

CI lives in `.github/workflows/lumencli.yml`: format/vet/race-test on Ubuntu,
plain tests on Windows, the vulnerability gate, and a cross-compile job that
uploads all six platform binaries. It is path-filtered to `lumencli/**`, so a
weekly scheduled run re-checks dependencies for new vulnerability advisories
that would otherwise surface only on the next code change. The gate itself is
`scripts/vulncheck.sh`: a pinned `govulncheck` whose symbol-level findings
fail the job unless they are on the script's accept list — each accepted
finding carries its justification in the script, so a known, assessed,
unfixable transitive finding cannot turn the job permanently red (which would
only train everyone to ignore it), while anything new still fails.

`scripts/testnet-smoke.sh` is an opt-in end-to-end exercise against real
testnet Horizon (Friendbot funding, a create + payment with an id memo, then
invariant checks over `history`, `--json`, `--summary`, and `tx`). It is
deliberately not in CI — a public network is a flake source, not a merge gate.
Its `--record` flag refreshes `internal/cli/testdata/live_payments_page.json`,
the recorded real-Horizon page that keeps the hand-built test fixtures honest.

The machine-readable history schemas (`--json`, `--csv`, `--summary --json`)
are an append-only compatibility promise — see
[Machine-readable output](#machine-readable-output). A change that renames,
retypes, or reorders a field is a breaking change to every script built on
them — add fields, never alter existing ones. The golden-file tests under
`internal/cli/testdata/` enforce this: `go test ./internal/cli -update`
regenerates them, and a diff in review is a schema change to justify.
