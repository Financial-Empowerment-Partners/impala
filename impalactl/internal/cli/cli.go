// Package cli implements the impalactl command-line interface: argument
// parsing, command dispatch, and rendering. The REST calls live in
// internal/bridge and credential handling in internal/config; this package
// wires them to flags and stdio.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

const version = "0.1.0"

// defaultTimeout comfortably exceeds the bridge's own request deadline, so a
// slow-but-working call is not cut off on the client side.
const defaultTimeout = 30 * time.Second

const usage = `impalactl ` + version + ` — command-line client for the Impala bridge API

Usage:
  impalactl [global flags] <command> [subcommand] [flags]

Authentication:
  login                      Obtain and store API tokens
  logout                     Revoke the current token (--all for every device)
  whoami                     Show the stored identity, role and token expiry

Accounts:
  account create             Link a Stellar account to a Payala account
  account generate           Create a custodial account (seed generated server-side)
  account import             Place an existing Stellar seed under custody
  account show <G...>        Show an account's bridge record
  account onchain <G...>     Show live on-chain balances and signers
  account reserves <id>      Show Payala reserve balances
  account list               List accounts (admin)

Syncing:
  sync force <G...>          Force a sync + Soroban RPC reconcile (admin)
  sync profile <id>          Force a directory profile re-pull (admin, LDAP)
  sync payala                Ingest a batch of offline Payala transactions
  sync mode <id>             Switch an account between reserve and mirror (admin)

Transfers:
  transfer send              Sign and submit an XLM payment (moves real funds)
  transfer record            Record a dual-chain transaction (bookkeeping only)

Activity:
  activity list              List transactions with their review state
  activity show <btxid>      Show one transaction in full
  activity review <btxid>    Set review status / flag / note (admin)
  activity events            Read the admin event feed (admin)

Bridge keys (admin) — installs the credentials that move money:
  keys list                  Show provider credentials: running, stored, gap
  keys import <kind>         Import or replace a provider credential set
  keys revoke <kind>         Revoke a stored credential (not at the provider)
  stellar-seed generate      Provision a custodial seed the bridge generates
  stellar-seed import        Place an existing Stellar seed under custody

Other:
  health                     Show bridge health, version and network
  version                    Print the impalactl version
  help                       Show this help

Global flags (may appear before or after the command):
  --endpoint <url>     Bridge base URL, or $%s
                       (default %s)
  --token <jwt>        Bearer temporal token, or $%s
                       (bypasses stored credentials)
  --timeout <dur>      Per-request timeout (default %s)
  --json               Print the server's raw JSON instead of a summary
  --yes                Skip confirmation prompts (needed for scripted transfers)
  --insecure-http      Allow plain HTTP to a non-loopback endpoint
                       (credentials travel in cleartext; or $%s)

Credentials from ` + "`login`" + ` are stored with 0600 permissions under
$XDG_CONFIG_HOME/impalactl (override with $%s) and are
scoped to the endpoint that issued them, so a token is never sent to a
different bridge.

Secrets are never read from argv, which is visible to other processes and to
shell history. The login password comes from $%s, an
interactive no-echo prompt, or stdin; a Stellar seed from $%s
the same way. Credential parts for "keys import" come from
--part-file name=path (the only way to pass a multi-line PEM),
$IMPALA_KEY_<PART>, or a no-echo prompt.

Importing a credential installs spend authority: replenishment sends real
reserve XLM to the pay-in address the active provider account names. Imports
ADD by default; replacing anything in effect needs --replace plus the exact
confirmation phrase the bridge names, and takes effect only at the next
rolling restart. See docs/runbooks/import-keys.md.
`

// App holds the I/O streams and environment the CLI runs against. Keeping
// these as fields (rather than reaching for os.Stdout/os.Getenv directly)
// makes the commands testable.
type App struct {
	in     io.Reader
	out    io.Writer
	err    io.Writer
	getenv func(string) string
}

// options are the global flags, resolved against the environment when used.
type options struct {
	endpoint     string
	token        string
	timeout      time.Duration
	json         bool
	yes          bool
	insecureHTTP bool
}

// Run is the process entry point. It returns the exit code.
func Run(args []string) int {
	app := &App{in: os.Stdin, out: os.Stdout, err: os.Stderr, getenv: os.Getenv}
	return app.run(args)
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprintf(w, usage,
		config.EnvEndpoint, bridge.DefaultEndpoint, config.EnvToken, defaultTimeout,
		bridge.EnvAllowHTTP,
		config.EnvConfigDir, config.EnvPassword, config.EnvSecretSeed)
}

func (a *App) run(args []string) int {
	global := flag.NewFlagSet("impalactl", flag.ContinueOnError)
	global.SetOutput(a.err)
	global.Usage = func() { a.printUsage(a.err) }

	opts := options{timeout: defaultTimeout}
	bindGlobalFlags(global, &opts)

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
	case "login":
		return a.runLogin(opts, cmdArgs)
	case "logout":
		return a.runLogout(opts, cmdArgs)
	case "whoami":
		return a.runWhoami(opts, cmdArgs)
	case "account":
		return a.runAccount(opts, cmdArgs)
	case "sync":
		return a.runSync(opts, cmdArgs)
	case "transfer":
		return a.runTransfer(opts, cmdArgs)
	case "activity":
		return a.runActivity(opts, cmdArgs)
	case "keys":
		return a.runKeys(opts, cmdArgs)
	case "stellar-seed":
		return a.runStellarSeed(opts, cmdArgs)
	case "health":
		return a.runHealth(opts, cmdArgs)
	default:
		fmt.Fprintf(a.err, "error: unknown command %q\n\n", cmd)
		a.printUsage(a.err)
		return 2
	}
}

// bindGlobalFlags registers the global flags on fs, defaulting to the values
// already present in opts. This lets them work whether they appear before the
// command (parsed by the global set) or after it (parsed by a subcommand's
// set), with the later occurrence winning.
func bindGlobalFlags(fs *flag.FlagSet, opts *options) {
	fs.StringVar(&opts.endpoint, "endpoint", opts.endpoint, "bridge base URL")
	fs.StringVar(&opts.token, "token", opts.token, "bearer temporal token (bypasses stored credentials)")
	fs.DurationVar(&opts.timeout, "timeout", opts.timeout, "per-request timeout")
	fs.BoolVar(&opts.json, "json", opts.json, "print the server's raw JSON response")
	fs.BoolVar(&opts.yes, "yes", opts.yes, "skip confirmation prompts")
	fs.BoolVar(&opts.insecureHTTP, "insecure-http", opts.insecureHTTP,
		"allow plain HTTP to a non-loopback endpoint (sends credentials in cleartext)")
}

// fail prints an error to stderr and returns the error exit code.
func (a *App) fail(format string, args ...any) int {
	fmt.Fprintf(a.err, "error: "+format+"\n", args...)
	return 1
}

// usageErr prints a usage error and returns the usage exit code.
func (a *App) usageErr(format string, args ...any) int {
	fmt.Fprintf(a.err, "error: "+format+"\n", args...)
	return 2
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
// — e.g. `account show G... --json`. The Go flag package alone stops at the
// first non-flag token; this loop collects positionals and keeps parsing.
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

// subUsage prints the subcommand list for a command group.
func (a *App) subUsage(w io.Writer, group string, lines []string) {
	fmt.Fprintf(w, "Usage: impalactl %s <subcommand> [flags]\n\nSubcommands:\n", group)
	for _, line := range lines {
		fmt.Fprintf(w, "  %s\n", line)
	}
}
