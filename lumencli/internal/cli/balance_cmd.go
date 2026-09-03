package cli

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"

	"lumencli/internal/netcfg"
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

	acct, err := a.horizon(net).AccountInfo(address)
	if err != nil {
		return a.fail("%v", err)
	}

	fmt.Fprintf(a.out, "Account: %s\n", address)
	fmt.Fprintln(a.out, "Balances:")
	for _, b := range acct.Balances {
		fmt.Fprintf(a.out, "  %-12s %s\n", assetLabel(b.Asset), b.Balance)
	}
	return 0
}

// assetLabel renders a human-friendly label for an asset. The native lumen
// has asset type "native"; other assets carry a code (e.g. "USDC").
func assetLabel(a base.Asset) string {
	switch {
	case a.Type == "native":
		return "XLM"
	case a.Code != "":
		return a.Code
	default:
		return a.Type
	}
}
