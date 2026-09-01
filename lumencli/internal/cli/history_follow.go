package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// followDrainWait bounds how long the command waits for the stream goroutine
// after cancellation. The context-bound transport tears the connection down
// on cancel, so the goroutine normally exits immediately; the bound only
// prevents a pathological transport from wedging exit.
const followDrainWait = 2 * time.Second

// followSignals returns the context that ends a --follow watch. The default
// ends on Ctrl+C (SIGINT) or SIGTERM; tests override the hook to drive
// cancellation deterministically. The returned stop func restores default
// signal behavior, so a second Ctrl+C after a slow shutdown kills the
// process the ordinary way.
func (a *App) followSignals() (context.Context, context.CancelFunc) {
	if a.signalCtx != nil {
		return a.signalCtx()
	}
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// runFollow streams new payments after the backlog listing, rendering each
// arriving entry with the same filters and format as the listing. cursor is
// the paging token of the newest already-listed operation ("0" when the
// account had none — streaming from the beginning replays nothing for an
// empty history and leaves no gap for a payment landing right now).
//
// Cancellation is prompt by construction: the render loop runs in a
// goroutine while this function waits on the signal context, and the
// stream's HTTP client is bound to that context, so Ctrl+C tears down the
// connection rather than waiting for the next event to arrive on a quiet
// account.
func (a *App) runFollow(net netcfg.Network, address, cursor string, includeFailed bool, filter *historyFilter, render func(historyEntry)) int {
	fmt.Fprintln(a.err, "\nWatching for new payments (Ctrl+C to stop)...")

	ctx, stop := a.followSignals()
	defer stop()

	done := make(chan error, 1)
	go func() {
		done <- stellar.New(net).WatchPayments(ctx, address, cursor, includeFailed,
			func(op operations.Operation) bool {
				e := entryFromOp(address, op)
				if filter.match(e) {
					render(e)
				}
				return true
			},
			func(attempt int, err error) {
				fmt.Fprintf(a.err, "stream interrupted (%v); reconnecting from the last entry (attempt %d)...\n", err, attempt)
			})
	}()

	select {
	case err := <-done:
		if err != nil {
			return a.fail("%v", err)
		}
		return 0
	case <-ctx.Done():
		stop() // restore default signal handling: a second Ctrl+C force-kills
		select {
		case <-done:
		case <-time.After(followDrainWait):
		}
		fmt.Fprintln(a.err, "Stopped.")
		return 0
	}
}
