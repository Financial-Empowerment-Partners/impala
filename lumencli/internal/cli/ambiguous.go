package cli

import (
	"fmt"
	"math"
	"strings"
	"time"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// exitAmbiguous is the exit code for a fund-moving command whose outcome is
// unknown: the transaction was signed and submitted, and the answer did not
// prove it rejected. It is distinct from 1 so that a script cannot mistake
// "maybe paid" for "not paid" and re-run — the re-run would be a second
// payment.
const exitAmbiguous = 3

// failAmbiguous reports an ambiguous submission: the error itself, then a
// notice naming the full transaction hash, the time bound until which the
// transaction can still be applied, and the exact lookup that settles the
// question. Everything goes to stderr — stdout stays empty on failure, as
// for every other error — and the exit code is exitAmbiguous.
//
// The wording is deliberately blunt. The natural reaction to "error: Timeout"
// is to try again, and for a payment that reaction is the one thing that
// must not happen until the first attempt's fate is known.
func (a *App) failAmbiguous(net netcfg.Network, what string, e *stellar.AmbiguousSubmitError) int {
	fmt.Fprintf(a.err, "error: %v\n", e.Cause)

	fmt.Fprintf(a.err, "\nWARNING: the outcome of this %s is UNKNOWN.\n", what)
	fmt.Fprintln(a.err, "The transaction was signed and handed to Horizon, and the error above does not")
	fmt.Fprintln(a.err, "prove it was rejected: it MAY STILL BE APPLIED at any moment until its time")
	fmt.Fprintln(a.err, "bound expires.")
	fmt.Fprintf(a.err, "\n  Transaction hash: %s\n", e.Hash)
	fmt.Fprintf(a.err, "  Valid until:      %s\n", describeMaxTime(e.MaxTime, time.Now()))

	fmt.Fprintln(a.err, "\nDO NOT re-run this command until you know what happened. A re-run signs a NEW")
	fmt.Fprintln(a.err, "transaction with the next sequence number; if the first one is applied as well,")
	fmt.Fprintln(a.err, "the funds move twice. Look the transaction up with:")
	fmt.Fprintf(a.err, "\n  %s\n\n", txLookupCommand(net, e.Hash))
	if time.Now().Before(e.MaxTime) {
		fmt.Fprintln(a.err, "A \"not found\" answer inside the window proves nothing — the transaction can")
		fmt.Fprintln(a.err, "still be applied later. Keep checking until the time bound has passed; only")
		fmt.Fprintln(a.err, "then does \"not found\" mean it was never applied and it is safe to try again.")
	} else {
		fmt.Fprintln(a.err, "The time bound has already passed, so the answer is now definitive: \"not")
		fmt.Fprintln(a.err, "found\" means the transaction was never applied and it is safe to try again;")
		fmt.Fprintln(a.err, "anything else means it was.")
	}
	return exitAmbiguous
}

// describeMaxTime renders a time bound as an absolute UTC instant plus the
// seconds remaining from now, so the reader has both the deadline to compare
// against a clock and the wait to expect. Seconds are rounded up: a bound
// "in 0s" that has not quite passed must not read as expired.
func describeMaxTime(maxTime, now time.Time) string {
	stamp := maxTime.UTC().Format("2006-01-02 15:04:05 UTC")
	remaining := maxTime.Sub(now)
	if remaining <= 0 {
		return stamp + " (already passed)"
	}
	return fmt.Sprintf("%s (in %ds)", stamp, int64(math.Ceil(remaining.Seconds())))
}

// txLookupCommand builds the `lumencli tx` invocation that targets the same
// Horizon the transaction was submitted to. A named network needs only its
// name — plus the URL if it was overridden — while a custom network needs
// both overrides, since that is how it was selected in the first place.
func txLookupCommand(net netcfg.Network, hash string) string {
	parts := []string{"lumencli", "tx", hash}
	switch net.Name {
	case netcfg.NameMainnet, netcfg.NameTestnet:
		parts = append(parts, "--network", net.Name)
		defaultURL := netcfg.MainnetHorizonURL
		if net.Name == netcfg.NameTestnet {
			defaultURL = netcfg.TestnetHorizonURL
		}
		if net.HorizonURL != defaultURL {
			parts = append(parts, "--horizon-url", net.HorizonURL)
		}
	default:
		parts = append(parts, "--horizon-url", net.HorizonURL, "--network-passphrase", shellQuote(net.Passphrase))
	}
	return strings.Join(parts, " ")
}

// shellQuote single-quotes s for pasting into a POSIX shell; a network
// passphrase carries spaces and a semicolon.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
