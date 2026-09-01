package stellar

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/wallet"
)

// maxStreamRetries is how many consecutive stream failures WatchPayments
// tolerates before giving up. The counter resets whenever an event arrives
// and whenever a connection stays healthy for healthyStreamAge, so a
// long-running watch survives any number of isolated drops — only a
// persistently unreachable Horizon ends it.
const maxStreamRetries = 5

// healthyStreamAge is how long a connection must live for its eventual
// failure to count as isolated rather than consecutive. Without it, a quiet
// watch (no events for hours) would accumulate one strike per transient drop
// across a whole day and die on the fifth — exactly the deposit-watching use
// case the retry loop exists to protect. A var so tests can compress time.
var healthyStreamAge = time.Minute

// streamBaseBackoff and streamBackoffCap bound the exponential wait between
// reconnect attempts. Vars so tests can compress time.
var (
	streamBaseBackoff = time.Second
	streamBackoffCap  = 30 * time.Second
)

// rapidReconnectLimit bounds the SDK's internal reconnect loop. The SDK
// reconnects immediately and forever on a clean EOF (no backoff, no error),
// so an endpoint that answers 2xx and closes at once — or serves a non-SSE
// body, which the SSE decoder silently treats as empty — would otherwise spin
// a tight connect loop that WatchPayments never sees. The transport counts
// consecutive connections spun up faster than rapidReconnectWindow with no
// event delivered between them; a healthy quiet stream holds one long-lived
// connection and never trips this.
const rapidReconnectLimit = 10

var rapidReconnectWindow = 2 * time.Second

// ctxTransport binds every request to a context and polices reconnect
// frequency. The SDK's SSE stream builds its request without a context
// (verified in horizonclient's streamConnection), so cancellation is
// otherwise only noticed between line reads — on a quiet account, Ctrl+C
// would hang until the next event arrives. Binding the context here makes
// cancel tear down the connection, which unblocks the read immediately.
//
// The fields are touched only from the stream's own goroutine (the SDK issues
// stream requests sequentially) plus lastEvent writes from the event handler,
// which the SDK also calls on that same goroutine.
type ctxTransport struct {
	base http.RoundTripper
	ctx  context.Context

	lastConnect time.Time
	rapid       int
	gotEvent    *bool // set by the event handler; resets the rapid counter
}

func (t *ctxTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	now := time.Now()
	if *t.gotEvent {
		*t.gotEvent = false
		t.rapid = 0
	} else if !t.lastConnect.IsZero() && now.Sub(t.lastConnect) < rapidReconnectWindow {
		t.rapid++
		if t.rapid >= rapidReconnectLimit {
			t.rapid = 0
			return nil, fmt.Errorf("stream reconnecting too rapidly with no events (is %s really an SSE endpoint?)", req.URL.Host)
		}
	} else {
		t.rapid = 0
	}
	t.lastConnect = now
	return t.base.RoundTrip(req.WithContext(t.ctx))
}

// newStreamingHorizon builds a Horizon client for long-lived SSE streams.
//
// It deliberately has no overall timeout: http.Client.Timeout bounds the
// entire body read, which would kill any stream after 30 seconds (the SDK's
// stream reads the SSE body through this client — see the comment in its
// streamConnection). Instead, the connection-establishing phases get their
// own bounds, so a black-holed dial or a proxy that never answers still fails
// promptly; only the event read is unbounded, and the context cancels that.
func newStreamingHorizon(ctx context.Context, horizonURL string, gotEvent *bool) *horizonclient.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // match every other Horizon request
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &horizonclient.Client{
		HorizonURL: horizonURL,
		HTTP:       &http.Client{Transport: &ctxTransport{base: transport, ctx: ctx, gotEvent: gotEvent}},
		AppName:    "lumencli",
		AppVersion: appVersion,
	}
}

// WatchPayments streams accountID's new payments as they arrive, calling onOp
// for each until ctx is cancelled or onOp returns false. cursor is the paging
// token to resume after ("0" streams everything the account ever received —
// callers pass the newest already-listed token so nothing is missed between
// listing and streaming); an empty cursor means "from now", which can miss
// events that land before the stream connects.
//
// The SDK's stream survives only clean EOFs (it reconnects itself, resuming
// from the last event's token). Any transport error — a dropped connection, a
// Horizon 503 — terminates it, so this wraps it in a retry loop that resumes
// from the last delivered token: no events are lost across a reconnect, and
// no duplicates are delivered. onRetry is told about each reconnect so the
// caller can surface it; after maxStreamRetries consecutive failures the
// watch ends with an error, since silently pretending to watch is worse than
// stopping loudly.
func (c *Client) WatchPayments(ctx context.Context, accountID, cursor string, includeFailed bool, onOp func(operations.Operation) bool, onRetry func(attempt int, err error)) error {
	if err := wallet.ValidateAddress(accountID); err != nil {
		return err
	}

	// An inner context lets onOp end the watch cleanly: cancelling it tears
	// down the SSE connection via ctxTransport, which unblocks the SDK's read.
	inner, cancel := context.WithCancel(ctx)
	defer cancel()
	gotEvent := false
	horizon := newStreamingHorizon(inner, c.net.HorizonURL, &gotEvent)

	lastCursor := cursor
	failures := 0
	for {
		connected := time.Now()
		err := horizon.StreamPayments(inner, horizonclient.OperationRequest{
			ForAccount:    accountID,
			Cursor:        lastCursor,
			IncludeFailed: includeFailed,
			Join:          "transactions",
		}, func(op operations.Operation) {
			lastCursor = op.PagingToken()
			failures = 0
			gotEvent = true
			if !onOp(op) {
				cancel()
			}
		})

		if inner.Err() != nil {
			return nil // cancelled: by the caller (Ctrl+C) or by onOp — a clean end either way
		}
		if err == nil {
			// The SDK's stream only returns nil on context cancellation,
			// handled above; treat an unexpected nil as a clean end too.
			return nil
		}
		if time.Since(connected) >= healthyStreamAge {
			// The connection lived long enough that this failure is an
			// isolated drop, not part of a losing streak — even if no event
			// happened to arrive while it was up.
			failures = 0
		}
		failures++
		if failures >= maxStreamRetries {
			return fmt.Errorf("stream failed %d times in a row (last error: %v); events may have been missed", failures, err)
		}
		if onRetry != nil {
			onRetry(failures, err)
		}
		backoff := streamBaseBackoff << (failures - 1)
		if backoff > streamBackoffCap {
			backoff = streamBackoffCap
		}
		select {
		case <-inner.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}
