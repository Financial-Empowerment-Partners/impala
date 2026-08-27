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
lumencli send               Send XLM to another account
lumencli receive            Show your address for receiving XLM
lumencli version | help
```

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
```

To run the same commands on mainnet, drop `--network testnet` (or set it to
`mainnet`). Friendbot is testnet-only; on mainnet a new account must be funded
by an existing account via `account create`.

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

```bash
go build ./...                       # build
go test ./...                        # run all tests
go test -run '^TestResolve' ./internal/netcfg   # run a single test / package
go vet ./...                         # static checks
gofmt -l -w .                        # format
```
