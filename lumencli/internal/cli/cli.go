// Package cli implements the lumencli command-line interface: argument
// parsing, command dispatch, and rendering. Network and key handling live in
// sibling packages (netcfg, wallet, stellar); this package wires them to flags
// and stdio.
package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// version identifies a build. It is a var so release builds can stamp it:
//
//	go build -ldflags "-X lumencli/internal/cli.version=..."
var version = "0.2.0"

var usage = `lumencli ` + version + ` — a command-line wallet for Stellar Lumens (XLM)

Usage:
  lumencli [global flags] <command> [flags]

Commands:
  account new        Generate a new keypair (offline)
  account address    Derive the public address (G...) from a secret seed
  account create     Create & fund a new account on-ledger (spends real XLM)
  account fund       Fund an account via testnet Friendbot (testnet only)
  balance <address>  Show the balances of an account
  history <address>  Show the transaction history of an account
  tx <hash>          Show one transaction: status, fee, memo, operations
  send               Send XLM to another account
  receive            Show your address for receiving XLM
  version            Print the version
  help               Show this help

Global flags (may appear before or after the command):
  --network <name>          mainnet | testnet  (default: mainnet; or $%s)
  --horizon-url <url>       Override the Horizon endpoint (also $%s)
  --network-passphrase <s>  Override the network passphrase (also $%s)

  Supply both --horizon-url and --network-passphrase with any --network name to
  target a custom network (e.g. futurenet or a local Horizon).

Fund-moving commands (send, account create) require an explicit confirmation on
mainnet; pass --yes to skip the prompt for non-interactive use.

History (history <address>):
  --limit <n>       Stop after the newest n entries (0 = full history)
  --failed          Also list operations from failed transactions
  --json | --csv    Machine-readable output (JSON Lines / CSV)
  --sent | --received           Only one direction
  --counterparty <G...|M...>    Only entries with this counterparty
  --asset <native|XLM|CODE:ISSUER>  Only entries moving this asset
  --since <t> | --until <t>     Time range: YYYY-MM-DD (UTC) or RFC3339
  --summary         Per-asset totals over the range instead of the listing
  --all-ops         Every operation type, not just the fund-moving kinds
  --follow          Keep streaming new payments after the listing (Ctrl+C stops)

  The default listing covers the fund-moving operations (payments, path
  payments, account creations, merges). See the README for the full flag
  reference, the JSON/CSV schemas, and what the default listing omits.

Memos (send, account create):
  --memo <value>            Attach a memo to the transaction
  --memo-type <type>        text | id | hash | return  (default: text)
  --no-memo                 Send with no memo to a destination that needs one

  text is up to 28 bytes; id is an unsigned 64-bit integer; hash and return are
  64 hex digits (32 bytes). Exchanges and other pooled accounts identify your
  deposit by its memo — usually an id — so a missing or wrong memo can lose the
  funds as surely as a wrong address. The memo is echoed in the mainnet
  confirmation prompt.

  A memo-less transfer to a destination believed to need one stops and warns.
  Confirming is separate from --yes: type "no memo" at the prompt, or pass
  --no-memo when scripting. The check knows a destination needs a memo if it
  says so on-ledger (SEP-0029) or is on a short built-in list; neither is
  exhaustive, so no warning is not a guarantee that no memo is needed.

Secrets:
  Commands needing a secret seed read it from $%s, or interactively from the
  terminal (no echo) — never from a command-line argument, since argv is
  visible to other processes and shell history.

Exit codes:
  0 success   1 failure   2 usage error
  3 ambiguous outcome: a fund-moving command submitted a transaction and got
    no definite answer (Horizon timeout, dropped connection). The transaction
    MAY STILL BE APPLIED; the notice names its hash. Do not re-run until
    "lumencli tx <hash>" has settled the question — see the README.
`

// App holds the I/O streams and environment the CLI runs against. Keeping these
// as fields (rather than reaching for os.Stdout/os.Getenv directly) makes the
// commands testable.
type App struct {
	in     io.Reader
	out    io.Writer
	err    io.Writer
	getenv func(string) string

	lines *bufio.Reader // shared by every prompt; see lineReader

	// signalCtx overrides the Ctrl+C context used by history --follow; nil
	// means the real signal handler. Tests set it to drive cancellation.
	signalCtx func() (context.Context, context.CancelFunc)

	// horizonTimeout overrides the per-request Horizon timeout; zero means
	// the production default. Tests set it to exercise the client-side
	// timeout path without waiting out the real bound.
	horizonTimeout time.Duration
}

// horizon returns the Horizon client for net. Every command goes through
// here so the test-only timeout override applies uniformly.
func (a *App) horizon(net netcfg.Network) *stellar.Client {
	return stellar.NewWithTimeout(net, a.horizonTimeout)
}

// lineReader returns the one buffered reader over a.in that all prompts share.
// A fresh bufio.Reader per prompt would be a bug: it can buffer well past its
// own line, swallowing the input meant for the next prompt — and a send does
// prompt twice (the memo warning, then the mainnet confirmation).
func (a *App) lineReader() *bufio.Reader {
	if a.lines == nil {
		a.lines = bufio.NewReader(a.in)
	}
	return a.lines
}

// Run is the process entry point. It returns the exit code.
func Run(args []string) int {
	app := &App{in: os.Stdin, out: os.Stdout, err: os.Stderr, getenv: os.Getenv}
	return app.run(args)
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprintf(w, usage,
		netcfg.EnvNetwork, netcfg.EnvHorizonURL, netcfg.EnvPassphrase, EnvSecret)
}

func (a *App) run(args []string) int {
	global := flag.NewFlagSet("lumencli", flag.ContinueOnError)
	global.SetOutput(a.err)
	global.Usage = func() { a.printUsage(a.err) }

	var opts netcfg.Options
	bindNetworkFlags(global, &opts)

	if err := global.Parse(args); err != nil {
		return parseCode(err)
	}

	rest := global.Args()
	if len(rest) == 0 {
		a.printUsage(a.err)
		return 2
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		a.printUsage(a.out)
		return 0
	case "version", "--version":
		fmt.Fprintln(a.out, version)
		return 0
	case "account":
		return a.runAccount(opts, cmdArgs)
	case "balance":
		return a.runBalance(opts, cmdArgs)
	case "history":
		return a.runHistory(opts, cmdArgs)
	case "tx":
		return a.runTx(opts, cmdArgs)
	case "send":
		return a.runSend(opts, cmdArgs)
	case "receive":
		return a.runReceive(opts, cmdArgs)
	default:
		fmt.Fprintf(a.err, "error: unknown command %q\n\n", cmd)
		a.printUsage(a.err)
		return 2
	}
}

// bindNetworkFlags registers the global network flags on fs, defaulting to the
// values already present in opts. This lets the flags work whether they appear
// before the command (parsed by the global set) or after it (parsed by a
// subcommand's set), with the later occurrence winning.
func bindNetworkFlags(fs *flag.FlagSet, opts *netcfg.Options) {
	fs.StringVar(&opts.Network, "network", opts.Network, "network: mainnet | testnet")
	fs.StringVar(&opts.HorizonURL, "horizon-url", opts.HorizonURL, "override Horizon endpoint URL")
	fs.StringVar(&opts.Passphrase, "network-passphrase", opts.Passphrase, "override network passphrase")
}

// resolveNetwork turns flag/env options into a concrete network.
func (a *App) resolveNetwork(opts netcfg.Options) (netcfg.Network, error) {
	return netcfg.Resolve(opts, a.getenv)
}

// announce prints the active network to stderr so the user always knows which
// network an operation touched, even when stdout is redirected.
func (a *App) announce(net netcfg.Network) {
	fmt.Fprintf(a.err, "Network: %s\n", net)
}

// fail prints an error to stderr and returns the error exit code.
func (a *App) fail(format string, args ...any) int {
	fmt.Fprintf(a.err, "error: "+format+"\n", args...)
	return 1
}

// newFlagSet builds a subcommand flag set that reports errors to a.err.
func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.err)
	return fs
}

// parseCode maps a flag-parse error to an exit code: 0 when the user asked for
// help (-h/--help), 2 for any genuine parse error.
func parseCode(err error) int {
	if err == flag.ErrHelp {
		return 0
	}
	return 2
}

// parseArgs parses fs while allowing flags and positional arguments to be
// interleaved (GNU-style permutation), so a flag may appear after a positional
// — e.g. `balance G... --network testnet`. The Go flag package alone stops at
// the first non-flag token; this loop collects positionals and keeps parsing.
// It returns the collected positional arguments in order.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}
