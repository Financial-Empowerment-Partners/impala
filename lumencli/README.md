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

# 6. Show your receiving address
lumencli receive --address G...
```

To run the same commands on mainnet, drop `--network testnet` (or set it to
`mainnet`). Friendbot is testnet-only; on mainnet a new account must be funded
by an existing account via `account create`.

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
