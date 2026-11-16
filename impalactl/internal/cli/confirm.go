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
	return a.confirmStake(network, summary, stakeFunds, assumeYes)
}

// stakeFunds is what a money-moving command puts at stake.
const stakeFunds = "REAL FUNDS"

// confirmPrompt is the interactive question: what is about to happen, where,
// and what is at stake.
func confirmPrompt(summary, label, stake string) string {
	return fmt.Sprintf("About to %s on %s — %s.\nType \"yes\" to proceed: ", summary, label, stake)
}

// confirmStake is confirm for a command whose stake is not funds (issuing a
// card, generating a key): the same rule, its own words.
func (a *App) confirmStake(network, summary, stake string, assumeYes bool) error {
	if network == "testnet" || assumeYes {
		return nil
	}
	label := strings.ToUpper(dash(network))

	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.err, confirmPrompt(summary, label, stake))
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
