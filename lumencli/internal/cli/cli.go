// Package cli implements the lumencli command-line interface: argument
// parsing, command dispatch, and rendering. Network and key handling live in
// sibling packages (netcfg, wallet, stellar); this package wires them to flags
// and stdio.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"lumencli/internal/netcfg"
)

const version = "0.1.0"

const usage = `lumencli ` + version + ` — a command-line wallet for Stellar Lumens (XLM)

Usage:
  lumencli [global flags] <command> [flags]

Commands:
  account new        Generate a new keypair (offline)
  account address    Derive the public address (G...) from a secret seed
  account create     Create & fund a new account on-ledger (spends real XLM)
  account fund       Fund an account via testnet Friendbot (testnet only)
  balance <address>  Show the balances of an account
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

Secrets:
  Commands needing a secret seed read it from $%s, or interactively from the
  terminal (no echo) — never from a command-line argument, since argv is
  visible to other processes and shell history.
`

// App holds the I/O streams and environment the CLI runs against. Keeping these
// as fields (rather than reaching for os.Stdout/os.Getenv directly) makes the
// commands testable.
type App struct {
	in     io.Reader
	out    io.Writer
	err    io.Writer
	getenv func(string) string
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
