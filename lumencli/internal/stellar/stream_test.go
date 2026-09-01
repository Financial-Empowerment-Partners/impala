package stellar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/netcfg"
)

// compressStreamTime shrinks the retry timings so exhaustion tests run in
// milliseconds instead of the production 1+2+4+8s backoff train.
func compressStreamTime(t *testing.T) {
	t.Helper()
	oldBackoff, oldAge, oldWindow := streamBaseBackoff, healthyStreamAge, rapidReconnectWindow
	streamBaseBackoff = time.Millisecond
	healthyStreamAge = time.Hour // never reached in these tests unless a test lowers it
	t.Cleanup(func() {
		streamBaseBackoff, healthyStreamAge, rapidReconnectWindow = oldBackoff, oldAge, oldWindow
	})
}

func testAccount(t *testing.T) string {
	t.Helper()
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp.Address()
}

func watchClient(url string) *Client {
	return New(netcfg.Network{Name: "testnet", HorizonURL: url, Passphrase: "x", IsTestnet: true})
}

// paymentEvent is a minimal payment record the SDK's stream decoder accepts.
func paymentEvent(id string) string {
	return fmt.Sprintf(`{"id":%q,"paging_token":%q,"transaction_successful":true,`+
		`"source_account":"G","type":"payment","type_i":1,"created_at":"2026-08-30T14:02:11Z",`+
		`"transaction_hash":"h","asset_type":"native","from":"GA","to":"GB","amount":"1.0000000"}`, id, id)
}

// TestWatchPaymentsExhaustionExitsLoudly pins the give-up contract: after
// maxStreamRetries consecutive failures the watch ends with the
// events-may-have-been-missed error rather than silently pretending to watch.
func TestWatchPaymentsExhaustionExitsLoudly(t *testing.T) {
	compressStreamTime(t)
	var mu sync.Mutex
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	retries := 0
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := watchClient(srv.URL).WatchPayments(ctx, testAccount(t), "0", false,
		func(operations.Operation) bool { return true },
		func(attempt int, err error) { retries++ })
	if err == nil || !strings.Contains(err.Error(), "events may have been missed") {
		t.Fatalf("err = %v, want the loud exhaustion error", err)
	}
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got != maxStreamRetries {
		t.Errorf("made %d attempts, want %d", got, maxStreamRetries)
	}
	if retries != maxStreamRetries-1 {
		t.Errorf("onRetry called %d times, want %d (the final failure returns instead of retrying)", retries, maxStreamRetries-1)
	}
}

// TestWatchPaymentsEventResetsFailures: a delivered event proves the stream
// works, so the failure streak restarts — isolated drops with events between
// them never add up to exhaustion.
func TestWatchPaymentsEventResetsFailures(t *testing.T) {
	compressStreamTime(t)
	// Fail maxStreamRetries-1 times, deliver one event (then drop the
	// connection abruptly, starting a second streak), fail
	// maxStreamRetries-2 more times, then deliver again: without the
	// in-handler reset the streaks add up past the cap and the watch dies;
	// with it, both streaks stay below the cap and the second event ends the
	// watch cleanly via onOp returning false.
	var mu sync.Mutex
	conn := 0
	fail := maxStreamRetries - 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conn++
		n := conn
		mu.Unlock()
		switch {
		case n <= fail || (n > fail+1 && n <= 2*fail):
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case n == fail+1:
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			fmt.Fprintf(w, "retry: 10\nid: tok-a\ndata: %s\n\n", paymentEvent("tok-a"))
			fl.Flush()
			panic(http.ErrAbortHandler) // abrupt drop => transport error, streak restarts at 1
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			fmt.Fprintf(w, "retry: 10\nid: tok-b\ndata: %s\n\n", paymentEvent("tok-b"))
			fl.Flush()
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)

	events := 0
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := watchClient(srv.URL).WatchPayments(ctx, testAccount(t), "0", false,
		func(op operations.Operation) bool {
			events++
			return events < 2 // stop after the second delivered event
		}, nil)
	if err != nil {
		t.Fatalf("watch died despite events between failure streaks: %v", err)
	}
	if events != 2 {
		t.Errorf("delivered %d events, want 2", events)
	}
}

// TestWatchPaymentsCursorResumesAfterError: reconnects resume from the last
// delivered token, so no event is lost or duplicated across a drop.
func TestWatchPaymentsCursorResumesAfterError(t *testing.T) {
	compressStreamTime(t)
	var mu sync.Mutex
	conn := 0
	cursors := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conn++
		n := conn
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		fl.Flush()
		if n == 1 {
			fmt.Fprintf(w, "retry: 10\nid: tok-1\ndata: %s\n\n", paymentEvent("tok-1"))
			fl.Flush()
			// Abort abruptly mid-stream so the SDK surfaces a transport error
			// (a clean EOF would be handled inside the SDK and not exercise
			// the caller retry loop).
			panic(http.ErrAbortHandler)
		}
		fmt.Fprintf(w, "retry: 10\nid: tok-2\ndata: %s\n\n", paymentEvent("tok-2"))
		fl.Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	var seen []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := watchClient(srv.URL).WatchPayments(ctx, testAccount(t), "start", false,
		func(op operations.Operation) bool {
			seen = append(seen, op.PagingToken())
			return op.PagingToken() != "tok-2"
		}, nil)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if len(seen) != 2 || seen[0] != "tok-1" || seen[1] != "tok-2" {
		t.Errorf("events = %v, want [tok-1 tok-2] (no loss, no duplicates)", seen)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cursors) < 2 || cursors[0] != "start" || cursors[1] != "tok-1" {
		t.Errorf("cursors = %v, want [start tok-1 ...] (resume from the last delivered token)", cursors)
	}
}

// TestWatchPaymentsRapidReconnectGuard: an endpoint that answers 2xx and
// closes immediately drives the SDK's internal zero-delay reconnect loop,
// which never surfaces an error on its own — the transport guard must turn
// the spin into a failure the retry loop (and eventually the user) can see.
func TestWatchPaymentsRapidReconnectGuard(t *testing.T) {
	compressStreamTime(t)
	var mu sync.Mutex
	conns := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conns++
		mu.Unlock()
		// 200 with an instantly-closed, non-SSE body: a clean EOF to the SDK.
		w.Header().Set("Content-Type", "text/event-stream")
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := watchClient(srv.URL).WatchPayments(ctx, testAccount(t), "0", false,
		func(operations.Operation) bool { return true }, nil)
	if err == nil {
		t.Fatal("a hot reconnect loop ended without an error")
	}
	mu.Lock()
	got := conns
	mu.Unlock()
	// The guard trips after rapidReconnectLimit rapid connects, then the
	// retry loop retries the whole stream; the total is bounded well below
	// an unchecked spin.
	if max := maxStreamRetries * (rapidReconnectLimit + 1); got > max {
		t.Errorf("made %d connections, want at most %d — the guard did not bound the spin", got, max)
	}
}
