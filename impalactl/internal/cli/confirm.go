package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// confirm gates an irreversible operation.
//
// Testnet never needs confirmation. On any other network (pubnet, or an
// unknown one, which may be real) it requires an explicit "yes": from an
// interactive terminal it prompts; otherwise it refuses unless assumeYes (the
// --yes flag) was supplied, so a scripted real-money transfer has to opt in
// deliberately rather than by forgetting which bridge it is pointed at.
func (a *App) confirm(network, summary string, assumeYes bool) error {
	if network == "testnet" || assumeYes {
		return nil
	}
	label := strings.ToUpper(dash(network))

	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(a.err, "About to %s on %s — REAL FUNDS.\nType \"yes\" to proceed: ", summary, label)
		line, err := bufio.NewReader(a.in).ReadString('\n')
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
