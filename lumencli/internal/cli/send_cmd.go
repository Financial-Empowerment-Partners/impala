package cli

import (
	"fmt"
	"strings"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
	"lumencli/internal/wallet"
)

// runSend sends XLM from the signer's account to a destination address.
func (a *App) runSend(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("send")
	bindNetworkFlags(fs, &opts)
	to := fs.String("to", "", "destination account address (G...)")
	amount := fs.String("amount", "", "amount of XLM to send (e.g. 12.5)")
	memo := fs.String("memo", "", "optional text memo (max 28 bytes)")
	assumeYes := fs.Bool("yes", false, "skip the mainnet confirmation prompt (for non-interactive use)")
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}

	dest := strings.TrimSpace(*to)
	amt := strings.TrimSpace(*amount)
	if dest == "" || amt == "" {
		return a.fail("send requires --to and --amount")
	}
	if err := wallet.ValidateAddress(dest); err != nil {
		return a.fail("%v", err)
	}
	if err := stellar.ValidateAmount(amt); err != nil {
		return a.fail("%v", err)
	}

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)
	if err := a.confirmSpend(net, fmt.Sprintf("send %s XLM to %s", amt, dest), *assumeYes); err != nil {
		return a.fail("%v", err)
	}

	secret, err := a.readSecret("Enter sender secret seed (S...): ")
	if err != nil {
		return a.fail("%v", err)
	}
	source, err := wallet.ParseSecret(secret)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Signing from: %s\n", source.Address())

	hash, err := stellar.New(net).SendPayment(source, dest, amt, *memo)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.out, "Sent %s XLM to %s\nTransaction: %s\n", amt, dest, hash)
	return 0
}
