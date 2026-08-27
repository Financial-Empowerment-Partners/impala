package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// noMemoPhrase is what the user must type to send with no memo to a
// destination that needs one. It is deliberately not "yes": that is the
// mainnet confirmation's answer, and a send asks both questions in a row.
// Reusing the word would let one habit answer both.
const noMemoPhrase = "no memo"

// memoFlags is the --memo / --memo-type pair shared by the fund-moving
// commands (send, account create).
type memoFlags struct {
	value    *string
	typeName *string
	noMemo   *bool
}

// bindMemoFlags registers the memo flags on fs. The type defaults to text, so
// a bare `--memo "thanks"` keeps working as it always has.
func bindMemoFlags(fs *flag.FlagSet) memoFlags {
	return memoFlags{
		value:    fs.String("memo", "", "memo to attach to the transaction"),
		typeName: fs.String("memo-type", "", "memo type: "+strings.Join(stellar.MemoTypes, " | ")+" (default text)"),
		noMemo:   fs.Bool("no-memo", false, "send with no memo even if the destination is known to require one"),
	}
}

// memo validates the flags into a memo to attach, or nil for none.
func (m memoFlags) memo() (stellar.Memo, error) {
	return stellar.ParseMemo(strings.TrimSpace(*m.typeName), *m.value)
}

// withMemo renders a memo as a clause to append to a one-line summary, or ""
// when there is no memo.
func withMemo(m stellar.Memo) string {
	if d := stellar.DescribeMemo(m); d != "" {
		return " with " + d
	}
	return ""
}

// confirmMissingMemo gates a transfer that carries no memo to a destination
// believed to need one. Such a destination is shared by every customer of the
// service behind it, and the memo is the only thing identifying which one a
// payment belongs to: the funds arrive, are credited to nobody, and getting
// them back means opening a support ticket — if it is possible at all.
//
// checkLedger consults the destination's own SEP-0029 declaration. account
// create passes false: its destination must not exist yet, so there is no
// account to have declared anything, and asking would only cost a round-trip.
//
// The override is --no-memo, deliberately separate from --yes. --yes means "I
// know this is mainnet"; letting it also wave through a missing memo would
// silently disarm this check for every script that already passes it.
func (a *App) confirmMissingMemo(net netcfg.Network, dest string, memo stellar.Memo, allowNoMemo, checkLedger bool) error {
	if memo != nil {
		return nil
	}

	var reason string
	switch label, known := stellar.KnownMemoRequired(dest); {
	case known:
		reason = fmt.Sprintf("it is a known %s deposit address", label)
	case checkLedger:
		required, err := stellar.New(net).MemoRequiredOnLedger(dest)
		if err != nil {
			// Say so rather than proceeding as if the answer were "no": a
			// check that silently fails open is worse than none, because it
			// still reads as reassurance.
			fmt.Fprintf(a.err, "warning: could not check whether %s requires a memo: %v\n", dest, err)
			return nil
		}
		if required {
			reason = "it declares on-ledger (SEP-0029) that payments to it must carry a memo"
		}
	}
	if reason == "" {
		return nil
	}

	fmt.Fprintf(a.err, "\nWARNING: this transfer carries no memo, but %s.\n", reason)
	fmt.Fprintln(a.err, "Deposits there are credited by their memo. Without one the funds usually cannot")
	fmt.Fprintln(a.err, "be credited to you, and recovering them means contacting the operator's support.")
	fmt.Fprintln(a.err, "Add one with --memo (for an exchange, usually --memo-type id).")

	if allowNoMemo {
		fmt.Fprintln(a.err, "Continuing without a memo: --no-memo was given.")
		return nil
	}
	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(a.err, "Type %q to send anyway: ", noMemoPhrase)
		line, err := a.lineReader().ReadString('\n')
		if err != nil {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if strings.TrimSpace(line) != noMemoPhrase {
			return fmt.Errorf("aborted: confirmation not given")
		}
		return nil
	}
	return fmt.Errorf(
		"refusing to transfer to %s without a memo; add --memo, or pass --no-memo to send without one anyway", dest)
}
