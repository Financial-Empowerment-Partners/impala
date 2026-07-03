package cli

import (
	"fmt"
	"strings"

	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// runBalance shows every balance held by an account. The account address is a
// positional argument: `lumencli balance G...`.
func (a *App) runBalance(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("balance")
	bindNetworkFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli balance [flags] <account-address>")
	}
	address := strings.TrimSpace(rest[0])

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)

	acct, err := stellar.New(net).AccountInfo(address)
	if err != nil {
		return a.fail("%v", err)
	}

	fmt.Fprintf(a.out, "Account: %s\n", address)
	fmt.Fprintln(a.out, "Balances:")
	for _, b := range acct.Balances {
		fmt.Fprintf(a.out, "  %-12s %s\n", assetLabel(b), b.Balance)
	}
	return 0
}

// assetLabel renders a human-friendly label for a balance line. The native
// lumen has asset type "native"; other assets carry a code (e.g. "USDC").
func assetLabel(b hProtocol.Balance) string {
	switch {
	case b.Type == "native":
		return "XLM"
	case b.Code != "":
		return b.Code
	default:
		return b.Type
	}
}
