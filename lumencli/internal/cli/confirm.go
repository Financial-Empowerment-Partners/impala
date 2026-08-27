package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"lumencli/internal/netcfg"
)

// confirmSpend gates an irreversible, fund-moving operation.
//
// Testnet never needs confirmation. On any other network (mainnet or a custom
// network, which may be real) it requires an explicit "yes": from an
// interactive terminal it prompts; otherwise it refuses unless assumeYes (the
// --yes flag) was supplied, so scripted real-money spends must opt in
// deliberately rather than by forgetting --network.
func (a *App) confirmSpend(net netcfg.Network, summary string, assumeYes bool) error {
	if net.IsTestnet || assumeYes {
		return nil
	}
	label := strings.ToUpper(net.Name)

	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(a.err, "About to %s on %s — REAL FUNDS.\nType \"yes\" to proceed: ", summary, label)
		line, err := a.lineReader().ReadString('\n')
		if err != nil {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if strings.TrimSpace(line) != "yes" {
			return fmt.Errorf("aborted: confirmation not given")
		}
		return nil
	}

	return fmt.Errorf("refusing to %s on %s without confirmation; pass --yes for non-interactive use", summary, label)
}
