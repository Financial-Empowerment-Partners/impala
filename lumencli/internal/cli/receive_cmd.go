package cli

import (
	"fmt"
	"strings"

	"lumencli/internal/netcfg"
	"lumencli/internal/wallet"
)

// runReceive prints the address others should send XLM to. Receiving needs no
// transaction — funds sent to the address simply arrive. The address can be
// given with --address, or derived offline from a secret seed.
func (a *App) runReceive(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("receive")
	// receive is offline, but bind the network flags so they are accepted (and
	// ignored) in any position, matching the documented "before or after" rule.
	bindNetworkFlags(fs, &opts)
	addr := fs.String("address", "", "your public address (G...); if omitted, derived from your secret seed")
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}

	address := strings.TrimSpace(*addr)
	if address == "" {
		secret, err := a.readSecret("Enter your secret seed to derive your address (S...): ")
		if err != nil {
			return a.fail("%v", err)
		}
		address, err = wallet.AddressFromSecret(secret)
		if err != nil {
			return a.fail("%v", err)
		}
	} else if err := wallet.ValidateAddress(address); err != nil {
		return a.fail("%v", err)
	}

	fmt.Fprintln(a.out, "Share this address to receive XLM:")
	fmt.Fprintln(a.out, address)
	fmt.Fprintln(a.err, "\nReceiving requires no transaction — funds sent here arrive automatically.")
	fmt.Fprintln(a.err, "If this account is brand new, the first payment must use 'account create'")
	fmt.Fprintln(a.err, "with a starting balance, not 'send'.")
	return 0
}
