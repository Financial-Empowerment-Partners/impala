package cli

import (
	"fmt"
)

// bridgeTxValiditySecs mirrors the bridge signer's TX_TIMEOUT_SECS: a
// transaction the bridge signs stays valid on the network for this long. It
// bounds the window in which a payment of unknown outcome can still settle.
const bridgeTxValiditySecs = 300

// failAmbiguousTransfer reports a `transfer send` whose outcome is unknown.
//
// The bridge does the signing and the Horizon submission server-side, in the
// same request, and records the transaction row only AFTER settlement. So
// from here a timeout or a 5xx says nothing about whether funds moved — and
// the bridge's own request deadline can fire mid-submission, which drops the
// bookkeeping while the payment still lands. The notice therefore names the
// payment, says what to check and in what order, and exits distinctly.
// Everything goes to stderr; stdout stays empty, as on every other failure.
func (a *App) failAmbiguousTransfer(err error, from, to, amount string) int {
	fmt.Fprintf(a.err, "error: %v\n", err)

	fmt.Fprintln(a.err, "\nWARNING: the outcome of this payment is UNKNOWN.")
	fmt.Fprintln(a.err, "The request reached (or may have reached) the bridge, and the error above does")
	fmt.Fprintln(a.err, "not prove the payment was refused. The bridge signs and submits server-side, so")
	fmt.Fprintln(a.err, "the payment MAY HAVE BEEN SUBMITTED and can still settle: a signed transaction")
	fmt.Fprintf(a.err, "stays valid for up to %d seconds.\n", bridgeTxValiditySecs)
	fmt.Fprintf(a.err, "\n  From:    %s\n  To:      %s\n  Amount:  %s XLM\n", from, to, amount)

	fmt.Fprintln(a.err, "\nDO NOT re-run this command until you know what happened: a re-run is a second")
	fmt.Fprintln(a.err, "payment, not a retry. Check, in this order:")
	fmt.Fprintln(a.err, "\n  1. impalactl activity list")
	fmt.Fprintln(a.err, "     A new row (origin \"api\", created just now, the sending custodial address as")
	fmt.Fprintln(a.err, "     its source) means the payment settled; \"impalactl activity show <btxid>\"")
	fmt.Fprintln(a.err, "     gives its Stellar hash. Do not send again.")
	fmt.Fprintln(a.err, "  2. The chain. The bridge records that row only AFTER settlement, and a bridge")
	fmt.Fprintln(a.err, "     timeout can drop the record while the payment still lands — so an absent")
	fmt.Fprintln(a.err, "     row is not proof. Check the sending account's sequence number and balance")
	fmt.Fprintln(a.err, "     (\"impalactl account onchain <G...>\") and the destination's payments on")
	fmt.Fprintln(a.err, "     Horizon.")
	fmt.Fprintf(a.err, "  3. Wait out the %d-second window before concluding the payment did not\n", bridgeTxValiditySecs)
	fmt.Fprintln(a.err, "     happen; only then is it safe to send again.")
	return exitAmbiguous
}
