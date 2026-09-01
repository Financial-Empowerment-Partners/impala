package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"lumencli/internal/wallet"
)

// followTestDeadline bounds every follow test: the command runs concurrently
// and must never be waited on without a deadline.
const followTestDeadline = 10 * time.Second

// syncBuffer is a goroutine-safe output buffer: the follow tests poll stdout
// and stderr while the stream's render goroutine is still writing them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// followRun is one in-flight `history --follow` invocation.
type followRun struct {
	t         *testing.T
	ctx       context.Context    // per-test deadline
	cancel    context.CancelFunc // the test's Ctrl+C
	out, errb *syncBuffer
	code      chan int
}

// startFollow launches the command in a goroutine and wires the App's
// signal-context hook so the test delivers Ctrl+C by calling r.cancel. The
// follow context descends from the test deadline, so a test failure (or the
// deadline itself) also tears down the stream — the fake's SSE handlers
// unblock and the server can close.
func startFollow(t *testing.T, args []string) *followRun {
	t.Helper()
	ctx, cancelTest := context.WithTimeout(t.Context(), followTestDeadline)
	t.Cleanup(cancelTest)
	followCtx, followCancel := context.WithCancel(ctx)
	t.Cleanup(followCancel)

	out, errb := &syncBuffer{}, &syncBuffer{}
	app := &App{
		in:        strings.NewReader(""),
		out:       out,
		err:       errb,
		getenv:    func(string) string { return "" },
		signalCtx: func() (context.Context, context.CancelFunc) { return followCtx, followCancel },
	}
	r := &followRun{t: t, ctx: ctx, cancel: followCancel, out: out, errb: errb, code: make(chan int, 1)}
	go func() { r.code <- app.run(args) }()
	return r
}

// wait blocks until the command exits and returns its code and output. The
// buffers must not be inspected as plain strings before this returns (or
// outside waitFor's polling), since the render goroutine may still write.
func (r *followRun) wait() (code int, stdout, stderr string) {
	r.t.Helper()
	select {
	case code = <-r.code:
		return code, r.out.String(), r.errb.String()
	case <-r.ctx.Done():
		r.t.Fatalf("follow command did not exit before the test deadline\nstdout:\n%s\nstderr:\n%s",
			r.out.String(), r.errb.String())
		return 0, "", ""
	}
}

// waitFor polls until cond holds, failing at the test deadline. Polling is the
// only ordering mechanism the tests use — no sleep is load-bearing.
func (r *followRun) waitFor(what string, cond func() bool) {
	r.t.Helper()
	for !cond() {
		select {
		case <-r.ctx.Done():
			r.t.Fatalf("timed out waiting for %s\nstdout:\n%s\nstderr:\n%s",
				what, r.out.String(), r.errb.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// waitForOutput polls until stdout contains substr.
func (r *followRun) waitForOutput(substr string) {
	r.t.Helper()
	r.waitFor(fmt.Sprintf("stdout to contain %q", substr), func() bool {
		return strings.Contains(r.out.String(), substr)
	})
}

// serveFollowRoute registers ONE handler for an account's payments path
// serving both faces the follow command needs: the backlog pages (plain
// requests) and the SSE stream (requests the SDK marks with Accept:
// text/event-stream). Both hit the same path and the harness maps one handler
// per path, so the dispatch lives here rather than in the harness.
func serveFollowRoute(f *horizonFake, path string, pages map[string]string, script func(*sseConn)) {
	var mu sync.Mutex
	conns := 0
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			body, ok := pages[r.URL.Query().Get("cursor")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/hal+json")
			fmt.Fprint(w, body)
			return
		}
		mu.Lock()
		conns++
		n := conns
		mu.Unlock()
		fl, ok := w.(http.Flusher)
		if !ok {
			f.t.Error("response writer is not a flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl.Flush()
		script(&sseConn{N: n, Cursor: r.URL.Query().Get("cursor"), w: w, fl: fl, r: r})
	})
}

// TestFollowBacklogThenLive is the headline behaviour: the backlog lists
// first, the watch notice separates it from the live tail, and a payment
// arriving on the stream renders like any listed entry. The stream must
// resume from the newest backlog paging token — a "now" cursor would drop a
// payment landing between the listing and the connect.
func TestFollowBacklogThenLive(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	newest := payment("5", other, mine, "25.0000000", "hash-backlog-new")
	older := payment("4", mine, other, "10.0000000", "hash-backlog-old")
	live := payment("6", other, mine, "7.0000000", "hash-live")
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{newest.JSON(t), older.JSON(t)}),
	}, func(c *sseConn) {
		if c.N == 1 {
			c.event("6", live.JSON(t))
		}
		c.wait()
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	r.waitForOutput("hash-live")
	r.cancel()
	code, stdout, stderr := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	for _, want := range []string{"hash-backlog-new", "hash-backlog-old", "2 entries shown."} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	// The live entry renders after the backlog summary — which is printed
	// before the watch notice — so it can only have arrived via the stream.
	if strings.Index(stdout, "2 entries shown.") > strings.Index(stdout, "hash-live") {
		t.Errorf("live entry rendered before the backlog finished:\n%s", stdout)
	}
	if !strings.Contains(stdout, "received  7.0000000 XLM  (payment)") {
		t.Errorf("live entry not rendered like a listed one:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Watching for new payments") {
		t.Errorf("stderr %q missing the watch notice", stderr)
	}
	if !strings.Contains(stderr, "Stopped.") {
		t.Errorf("stderr %q missing the stop notice", stderr)
	}

	reqs := f.requests(paymentsPath(mine))
	if len(reqs) < 2 {
		t.Fatalf("got %d requests, want backlog page + stream", len(reqs))
	}
	if got := reqs[1].Get("cursor"); got != "5" {
		t.Errorf("stream cursor = %q, want %q (the newest backlog paging token)", got, "5")
	}
}

// TestFollowEmptyBacklogStreamsFromStart: with no history at all the stream
// must start from cursor "0" — streaming from the beginning replays nothing
// for an empty account and leaves no gap for a payment landing right now,
// where the SDK's default "now" cursor could miss one.
func TestFollowEmptyBacklogStreamsFromStart(t *testing.T) {
	mine, _ := historyAddrs(t)
	f := newHorizonFake(t)
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", nil),
	}, func(c *sseConn) { c.wait() })

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	r.waitFor("the stream request", func() bool { return len(f.requests(paymentsPath(mine))) >= 2 })
	r.cancel()
	code, stdout, _ := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "(no transactions)") {
		t.Errorf("stdout %q missing the empty-backlog notice", stdout)
	}
	if got := f.requests(paymentsPath(mine))[1].Get("cursor"); got != "0" {
		t.Errorf("stream cursor = %q, want %q", got, "0")
	}
}

// TestFollowAppliesFiltersToLiveEntries: the live tail goes through the same
// filter as the listing — a --counterparty watch must not render everyone
// else's payments. The non-matching event is served first, so by the time the
// matching one has rendered it was provably considered and dropped.
func TestFollowAppliesFiltersToLiveEntries(t *testing.T) {
	mine, other := historyAddrs(t)
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	stranger := kp.Address()
	f := newHorizonFake(t)

	noMatch := payment("10", stranger, mine, "1.0000000", "hash-nomatch")
	match := payment("11", other, mine, "2.0000000", "hash-match")
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", nil),
	}, func(c *sseConn) {
		if c.N == 1 {
			c.event("10", noMatch.JSON(t))
			c.event("11", match.JSON(t))
		}
		c.wait()
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow", "--counterparty", other))
	r.waitForOutput("hash-match")
	r.cancel()
	code, stdout, _ := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(stdout, "hash-nomatch") || strings.Contains(stdout, stranger) {
		t.Errorf("filtered-out live entry rendered:\n%s", stdout)
	}
	if !strings.Contains(stdout, "(no entries match the filters)") {
		t.Errorf("stdout %q missing the filtered empty-backlog notice", stdout)
	}
}

// TestFollowJSONEmitsParsableLines: --follow --json keeps the JSONL contract
// for live entries — one parseable object per line on stdout, notices on
// stderr only.
func TestFollowJSONEmitsParsableLines(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	backlog := payment("1", other, mine, "3.0000000", "hash-backlog-json")
	live := payment("2", other, mine, "4.0000000", "hash-live-json")
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{backlog.JSON(t)}),
	}, func(c *sseConn) {
		if c.N == 1 {
			c.event("2", live.JSON(t))
		}
		c.wait()
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow", "--json"))
	r.waitForOutput("hash-live-json")
	r.cancel()
	code, stdout, _ := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSONL lines, want 2 (backlog + live):\n%s", len(lines), stdout)
	}
	var entries []map[string]any
	for i, line := range lines {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i+1, err, line)
		}
		entries = append(entries, e)
	}
	if got := entries[1]["tx_hash"]; got != "hash-live-json" {
		t.Errorf("live line tx_hash = %v, want hash-live-json", got)
	}
	if got := entries[1]["amount"]; got != "4.0000000" {
		t.Errorf("live line amount = %v, want the 7-decimal string", got)
	}
}

// TestFollowReconnectResumesFromLastToken: a dropped connection (a genuine
// transport error, forced here by an RST close after the event was rendered)
// must surface one reconnect notice and resume from the last DELIVERED
// paging token — resuming from anywhere later could silently skip a payment.
func TestFollowReconnectResumesFromLastToken(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	backlog := payment("1", other, mine, "1.0000000", "hash-backlog")
	live := payment("tok1", other, mine, "2.0000000", "hash-live-1")
	gotLive := make(chan struct{})     // closed once the live entry has rendered
	reconnected := make(chan struct{}) // closed when the post-retry connection arrives
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{backlog.JSON(t)}),
	}, func(c *sseConn) {
		switch c.N {
		case 1:
			c.event("tok1", live.JSON(t))
			// Only after the client has provably consumed the event may the
			// connection be killed — an RST races with unread receive buffers.
			select {
			case <-gotLive:
			case <-c.r.Context().Done():
				return
			}
			// A plain close reads as a clean EOF, which the SDK survives on
			// its own; an RST (linger 0) is a transport error, which is what
			// forces the WatchPayments retry path under test.
			hj, ok := c.w.(http.Hijacker)
			if !ok {
				f.t.Error("response writer is not a hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				f.t.Errorf("hijack: %v", err)
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetLinger(0)
			} else {
				f.t.Errorf("hijacked conn is %T, want *net.TCPConn", conn)
			}
			conn.Close()
		case 2:
			close(reconnected)
			c.wait()
		default:
			c.wait()
		}
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	r.waitForOutput("hash-live-1")
	close(gotLive)
	select {
	case <-reconnected:
	case <-r.ctx.Done():
		t.Fatalf("no reconnect before the test deadline\nstderr:\n%s", r.errb.String())
	}
	r.cancel()
	code, _, stderr := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	reqs := f.requests(paymentsPath(mine))
	if len(reqs) < 3 {
		t.Fatalf("got %d requests, want backlog + stream + reconnect", len(reqs))
	}
	if got := reqs[2].Get("cursor"); got != "tok1" {
		t.Errorf("reconnect cursor = %q, want %q (the last delivered token)", got, "tok1")
	}
	if got := strings.Count(stderr, "reconnecting"); got != 1 {
		t.Errorf("stderr has %d reconnect notices, want exactly 1:\n%s", got, stderr)
	}
	if !strings.Contains(stderr, "(attempt 1)") {
		t.Errorf("stderr %q does not name attempt 1", stderr)
	}
}

// TestFollowRetryNoticeAndPromptCancel: a stream that fails before delivering
// any event surfaces a reconnect notice, and Ctrl+C during the retry backoff
// exits promptly instead of sleeping the backoff out. (Full retry exhaustion
// is not driven end-to-end here: its 1+2+4+8s of mandatory backoff is not
// unit-test material.)
func TestFollowRetryNoticeAndPromptCancel(t *testing.T) {
	start := time.Now()
	mine, _ := historyAddrs(t)
	f := newHorizonFake(t)

	firstFail := make(chan struct{})
	var once sync.Once
	f.handle(paymentsPath(mine), func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			w.Header().Set("Content-Type", "application/hal+json")
			fmt.Fprint(w, pageJSON("", nil))
			return
		}
		// Refusing the stream before any event is the abrupt failure: the SDK
		// reports a bad status as an error, never as a clean EOF.
		once.Do(func() { close(firstFail) })
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	select {
	case <-firstFail:
	case <-r.ctx.Done():
		t.Fatal("stream request never arrived")
	}
	r.waitFor("the reconnect notice", func() bool {
		return strings.Contains(r.errb.String(), "(attempt 1)")
	})

	// The watch is now in (or entering) its 1s backoff; cancel must not wait
	// the backoff out.
	cancelled := time.Now()
	r.cancel()
	code, _, stderr := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	if elapsed := time.Since(cancelled); elapsed >= 900*time.Millisecond {
		t.Errorf("cancel during backoff took %v, want well under the 1s backoff", elapsed)
	}
	if !strings.Contains(stderr, "reconnecting") {
		t.Errorf("stderr %q missing the reconnect notice", stderr)
	}
	if !strings.Contains(stderr, "Stopped.") {
		t.Errorf("stderr %q missing the stop notice", stderr)
	}
	// Sanity: nothing sat through the retry train (1+2+4+8s to exhaustion).
	if total := time.Since(start); total >= 5*time.Second {
		t.Errorf("test took %v, must stay well under the cumulative backoff", total)
	}
}

// TestFollowCancelUnblocksQuietStream pins the ctxTransport guarantee: on a
// stream with no events at all, Ctrl+C tears down the blocked read and the
// command returns promptly. The bound sits below followDrainWait — a
// transport that ignored the cancel would exit only via the drain timeout.
func TestFollowCancelUnblocksQuietStream(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	backlog := payment("1", other, mine, "1.0000000", "hash-quiet-backlog")
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{backlog.JSON(t)}),
	}, func(c *sseConn) {
		c.keepalive()
		c.wait()
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	r.waitFor("the stream request", func() bool { return len(f.requests(paymentsPath(mine))) >= 2 })
	cancelled := time.Now()
	r.cancel()
	code, _, stderr := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	if elapsed := time.Since(cancelled); elapsed >= time.Second {
		t.Errorf("cancel on a quiet stream took %v, want well under followDrainWait", elapsed)
	}
	if !strings.Contains(stderr, "Stopped.") {
		t.Errorf("stderr %q missing the stop notice", stderr)
	}
}

// TestFollowSurvivesKeepaliveGap: a quiet spell between keepalives must not
// make the client kill and re-dial the stream — the streaming client
// deliberately has no whole-body timeout (that lives only on the paging
// client). One connection, with the event arriving after the gap, pins it.
func TestFollowSurvivesKeepaliveGap(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	backlog := payment("1", other, mine, "1.0000000", "hash-gap-backlog")
	after := payment("2", other, mine, "6.0000000", "hash-after-gap")
	serveFollowRoute(f, paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{backlog.JSON(t)}),
	}, func(c *sseConn) {
		if c.N == 1 {
			c.keepalive()
			time.Sleep(150 * time.Millisecond) // a real quiet gap on the wire
			c.event("2", after.JSON(t))
		}
		c.wait()
	})

	r := startFollow(t, historyArgs(f.URL(), mine, "--follow"))
	r.waitForOutput("hash-after-gap")
	r.cancel()
	code, _, stderr := r.wait()

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, stderr)
	}
	if got := len(f.requests(paymentsPath(mine))); got != 2 {
		t.Errorf("made %d requests, want 2 (backlog + ONE stream connection)", got)
	}
}
