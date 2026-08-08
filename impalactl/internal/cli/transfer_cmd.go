package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"impalactl/internal/bridge"
)

var transferSubcommands = []string{
	"send                Sign and submit an XLM payment from a custodial account (moves real funds)",
	"record              Record a dual-chain transaction (bookkeeping only)",
}

func (a *App) runTransfer(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "transfer", transferSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "transfer", transferSubcommands)
		return 0
	case "send":
		return a.runTransferSend(opts, rest)
	case "record":
		return a.runTransferRecord(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "transfer", transferSubcommands)
		return 2
	}
}

// runTransferSend signs and submits an XLM payment from a custodial account
// (POST /managed-account/sign). This is irreversible once submitted.
func (a *App) runTransferSend(opts options, args []string) int {
	fs := a.newFlagSet("transfer send")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "sending Payala account id (defaults to the logged-in account)")
	to := fs.String("to", "", "destination Stellar account id (G..., required)")
	amount := fs.String("amount", "", "amount of XLM to send, e.g. 12.5 (required)")
	memo := fs.String("memo", "", "optional text memo")
	fee := fs.Int64("fee", 0, "optional fee in stroops (bridge default when unset)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("transfer send takes no positional arguments")
	}

	dest := strings.TrimSpace(*to)
	amt := strings.TrimSpace(*amount)
	if dest == "" || amt == "" {
		return a.usageErr("transfer send requires --to and --amount")
	}
	if err := validateStellarAccountID(dest); err != nil {
		return a.fail("%v", err)
	}
	if err := validateAmount(amt); err != nil {
		return a.fail("%v", err)
	}
	if *fee < 0 {
		return a.usageErr("--fee must not be negative")
	}

	payalaID := a.resolveOwnerAccount(opts, *account)
	if payalaID == "" {
		return a.usageErr("transfer send requires --account (the sending Payala account id)")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}

	// Always show which bridge and which network before moving funds, even
	// when stdout is redirected — the same discipline lumencli follows.
	network := "unknown"
	if info, _, err := c.Network(context.Background()); err == nil {
		network = info.StellarNetwork
	} else {
		fmt.Fprintf(a.err, "warning: could not read the bridge's network (%v); treating it as live\n", err)
	}
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)

	summary := fmt.Sprintf("send %s XLM from %s to %s", amt, payalaID, dest)
	if err := a.confirm(network, summary, opts.yes); err != nil {
		return a.fail("%v", err)
	}

	req := bridge.SignSubmitRequest{
		PayalaAccountID: payalaID,
		Destination:     dest,
		Amount:          amt,
		Memo:            *memo,
	}
	if *fee > 0 {
		f := uint32(*fee)
		req.Fee = &f
	}

	res, raw, err := c.SignAndSubmit(context.Background(), req)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"From:", payalaID},
			{"To:", dest},
			{"Amount:", amt + " XLM"},
			{"Stellar hash:", dash(res.StellarHash)},
			{"Bridge tx id:", dash(res.BTxID)},
		})
	})
}

// runTransferRecord records a dual-chain transaction (POST /transaction).
// Nothing is submitted on-chain; this is the ledger-linking record.
func (a *App) runTransferRecord(opts options, args []string) int {
	fs := a.newFlagSet("transfer record")
	bindGlobalFlags(fs, &opts)
	stellarTxID := fs.String("stellar-tx-id", "", "Stellar transaction id")
	payalaTxID := fs.String("payala-tx-id", "", "Payala transaction id")
	stellarHash := fs.String("stellar-hash", "", "Stellar transaction hash (hex)")
	sourceAccount := fs.String("source-account", "", "source Stellar account id (G...)")
	stellarFee := fs.Int64("stellar-fee", -1, "fee charged, in stroops")
	stellarMaxFee := fs.Int64("stellar-max-fee", -1, "maximum fee offered, in stroops")
	memo := fs.String("memo", "", "memo (max 256 characters)")
	signatures := fs.String("signatures", "", "signatures blob")
	preconditions := fs.String("preconditions", "", "preconditions blob")
	payalaCurrency := fs.String("payala-currency", "", "Payala currency code (e.g. USD)")
	payalaDigest := fs.String("payala-digest", "", "Payala digest")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("transfer record takes no positional arguments")
	}
	if strings.TrimSpace(*stellarTxID) == "" && strings.TrimSpace(*payalaTxID) == "" {
		return a.usageErr("transfer record requires at least one of --stellar-tx-id or --payala-tx-id")
	}
	if src := strings.TrimSpace(*sourceAccount); src != "" {
		if err := validateStellarAccountID(src); err != nil {
			return a.fail("%v", err)
		}
	}

	req := bridge.CreateTransactionRequest{
		StellarTxID:    strings.TrimSpace(*stellarTxID),
		PayalaTxID:     strings.TrimSpace(*payalaTxID),
		StellarHash:    strings.TrimSpace(*stellarHash),
		SourceAccount:  strings.TrimSpace(*sourceAccount),
		Memo:           *memo,
		Signatures:     *signatures,
		Preconditions:  *preconditions,
		PayalaCurrency: *payalaCurrency,
		PayalaDigest:   *payalaDigest,
	}
	if *stellarFee >= 0 {
		req.StellarFee = stellarFee
	}
	if *stellarMaxFee >= 0 {
		req.StellarMaxFee = stellarMaxFee
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.CreateTransaction(context.Background(), req)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Bridge tx id:", dash(res.BTxID)},
			{"Stellar tx id:", dash(req.StellarTxID)},
			{"Payala tx id:", dash(req.PayalaTxID)},
		})
	})
}
