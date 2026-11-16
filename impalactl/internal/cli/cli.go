// Package cli implements the impalactl command-line interface: argument
// parsing, command dispatch, and rendering. The REST calls live in
// internal/bridge and credential handling in internal/config; this package
// wires them to flags and stdio.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

const version = "0.3.0"

// bridgeRequestDeadline mirrors the bridge's REQUEST_TIMEOUT_SECS default:
// the point at which its TimeoutLayer abandons a handler and answers 408.
const bridgeRequestDeadline = 30 * time.Second

// defaultTimeout is the per-request client timeout. It must EXCEED
// bridgeRequestDeadline, and by enough for the bridge's answer to travel
// back: a client that gives up at the same instant as the server loses the
// server's verdict — for a payment, possibly a success — and is left with
// nothing but "timed out". With the headroom, the bridge's own 408 (or its
// 200/500) arrives instead of a client-side cut, so the outcome is at least
// the bridge's to report. The bridge's Horizon client also times out at 30s,
// so a submission that is slow because Horizon is slow surfaces as the
// bridge's 500 within this bound rather than as our timeout.
const defaultTimeout = bridgeRequestDeadline + 15*time.Second

// exitAmbiguous is the exit code for a money-moving command whose outcome is
// unknown: the request reached (or may have reached) the bridge, and the
// answer did not prove the payment refused. It is distinct from 1 so that a
// script cannot mistake "maybe paid" for "not paid" and re-run.
const exitAmbiguous = 3

const usage = `impalactl ` + version + ` — command-line client for the Impala bridge API

Usage:
  impalactl [global flags] <command> [subcommand] [flags]

Authentication:
  login                      Sign in with a password and store API tokens
                             (--totp | --device adds a second factor)
  login --card tcp:HOST:PORT Sign in with a card: SEP-10, or the legacy card
                             challenge (--pin adds the card PIN factor)
  logout                     Revoke the current token (--all for every device)
  whoami                     Show the stored identity, role, factors and expiry

Multi-factor:
  mfa status                 Show this session's factors (amr) and the account's requirement
  mfa step-up --totp|--device
                             Add a factor; the new tokens replace the stored ones
  mfa totp enroll            Enroll TOTP (prints the otpauth URI, shown once)
  mfa device enroll|list|revoke
                             A P-256 key on this machine as a possession factor
  mfa admin show <id>        An account's factor summary (accounts-read roles)
  mfa admin mandate <id> on|off
                             Require MFA for an account (admin; on signs it out)
  mfa admin revoke-device <id> <key-id>
                             Recovery for a lost device key (admin)

SEP-10 (card sign-in with Stellar Web Authentication):
  sep10 info                 What the endpoint's stellar.toml publishes (public)
  sep10 status               Signing keys, home domain and key ring (admin, key-custodian, auditor)
  sep10 key generate         Create a pending server signing key (admin, key-custodian)
  sep10 key activate <ver>   Schedule a pending key to take over (typed phrase)
  sep10 key revoke <ver>     Revoke a key at once (typed phrase)
  sep10 cards <account-id>   An account's cards and their Stellar addresses

Cards (the impala-card simulator transport, tcp:HOST:PORT):
  card info --card tcp:HOST:PORT
                             Read-only: applet, ids, state, Stellar key, PIN policy
  card setup --card tcp:HOST:PORT --account <uuid>
                             Issue a card: SCP03 keys, certificate, PERSONALIZE,
                             PINs, Stellar key (admin or key-custodian + the holder)
  card pin change|reset      The holder changes the PIN; the master PIN resets it
  card pin policy on|off     Require (or stop requiring) the PIN to sign in
  card issuer show           Is the card program configured (public)
  card issuer generate       Create (or --rotate) the program issuer key (generate-only)

Accounts:
  account create             Link a Stellar account to a Payala account
  account generate           Create a custodial account (seed generated server-side)
  account import             Place an existing Stellar seed under custody
  account show <G...>        Show an account's bridge record
  account onchain <G...>     Show live on-chain balances and signers
  account reserves <id>      Show Payala reserve balances
  account list               List accounts (admin, auditor, or key-custodian)

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
  activity events            Read the admin event feed (admin or auditor)

Bridge keys (admin or key-custodian) — installs the credentials that move money:
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
the same way; a TOTP code from $IMPALA_TOTP_CODE and a card PIN from
$IMPALA_CARD_PIN the same way. Credential parts for "keys import" come from
--part-file name=path (the only way to pass a multi-line PEM),
$IMPALA_KEY_<PART>, or a no-echo prompt. "card setup" reads the key master
key from $IMPALA_ISSUE_KMK, the PINs it provisions from $IMPALA_CARD_PIN and
$IMPALA_CARD_MASTER_PIN (each also from a prompt or stdin), and the holder's
token from $IMPALA_HOLDER_TOKEN; "card pin" a new PIN from $IMPALA_CARD_NEW_PIN.

Importing a credential installs spend authority: replenishment sends real
reserve XLM to the pay-in address the active provider account names. Imports
ADD by default; replacing anything in effect needs --replace plus the exact
confirmation phrase the bridge names, and takes effect only at the next
rolling restart. See docs/runbooks/import-keys.md.

Exit codes: 0 success, 1 failure, 2 usage error, 3 ambiguous outcome — a
"transfer send" that timed out or failed without proof the payment was
refused. The payment MAY have been submitted; do not re-run until the notice's
checks have settled it. See the README.
`

// App holds the I/O streams and environment the CLI runs against. Keeping
// these as fields (rather than reaching for os.Stdout/os.Getenv directly)
// makes the commands testable.
type App struct {
	in     io.Reader
	out    io.Writer
	err    io.Writer
	getenv func(string) string

	// lines buffers non-interactive reads of in (see stdinLines).
	lines *bufio.Reader
	// now is the clock (SEP-10 challenge time bounds); nil means time.Now.
	now func() time.Time
	// rand is the randomness a card setup sends to the card (the INITIALIZE
	// seed, the SCP03 host challenges) and nothing else; nil means
	// crypto/rand.Reader.
	rand io.Reader
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
	case "mfa":
		return a.runMFA(opts, cmdArgs)
	case "sep10":
		return a.runSep10(opts, cmdArgs)
	case "card":
		return a.runCard(opts, cmdArgs)
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
//
// It is also the one place a multi-factor refusal is explained: whichever
// command hit it, an error argument carrying the bridge's mfa_required or
// mfa_reauth_required code gets a line saying what happened and which
// command fixes it.
func (a *App) fail(format string, args ...any) int {
	fmt.Fprintf(a.err, "error: "+format+"\n", args...)
	for _, arg := range args {
		if err, ok := arg.(error); ok {
			if hint := mfaHint(err); hint != "" {
				fmt.Fprintln(a.err, hint)
				break
			}
		}
	}
	return 1
}

// mfaHint explains the bridge's multi-factor refusals, or returns "".
func mfaHint(err error) string {
	if bridge.StatusCode(err) != http.StatusForbidden {
		return ""
	}
	switch bridge.ErrorCode(err) {
	case bridge.CodeMFARequired:
		return "hint: this account must be multi-factor and this session is not (or its last " +
			"verification has aged out). Add a factor with `impalactl mfa step-up --totp` or " +
			"`impalactl mfa step-up --device` (or sign in again with `impalactl login ... --totp`), " +
			"then retry. `impalactl mfa status` shows the session's factors."
	case bridge.CodeMFAReauthRequired:
		return "hint: changing sign-in factors on this account needs a multi-factor session verified " +
			"within the last 15 minutes. Step up now with `impalactl mfa step-up --totp` or " +
			"`--device`, then retry."
	}
	return ""
}

// clock returns the current time (a.now when a test set it).
func (a *App) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
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
