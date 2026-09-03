package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newTestClient wires a client to a test server with a short timeout.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRejectsInvalidEndpoints(t *testing.T) {
	for _, endpoint := range []string{"", "   ", "localhost:8080", "ftp://host", "http://"} {
		if _, err := New(endpoint, time.Second, false); err == nil {
			t.Errorf("New(%q) = nil error, want an error", endpoint)
		}
	}
}

func TestNewNormalizesEndpoint(t *testing.T) {
	c, err := New("  https://bridge.example.com/  ", time.Second, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, want := c.Endpoint(), "https://bridge.example.com"; got != want {
		t.Errorf("Endpoint() = %q, want %q", got, want)
	}
}

func TestCallSendsBearerAndJSONBody(t *testing.T) {
	var gotAuth, gotMethod, gotPath, gotQuery, gotContentType, gotBody string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"message":"Sync timestamp recorded","timestamp":"2026-08-07T12:00:00Z"}`)
	})
	c.SetToken("tok-123")

	res, raw, err := c.ForceSync(context.Background(), "GAAAA")
	if err != nil {
		t.Fatalf("ForceSync: %v", err)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok-123")
	}
	if gotMethod != http.MethodPost || gotPath != "/sync" {
		t.Errorf("request = %s %s, want POST /sync", gotMethod, gotPath)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want empty", gotQuery)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if want := `{"account_id":"GAAAA"}`; strings.TrimSpace(gotBody) != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
	if res.Timestamp != "2026-08-07T12:00:00Z" {
		t.Errorf("Timestamp = %q", res.Timestamp)
	}
	if !strings.Contains(string(raw), "Sync timestamp recorded") {
		t.Errorf("raw body not returned verbatim: %s", raw)
	}
}

func TestCallOmitsAuthorizationWhenUnauthenticated(t *testing.T) {
	var hadAuth bool
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		io.WriteString(w, `{"status":"healthy","database":"ok","redis":"ok","stellar_network":"testnet"}`)
	})
	if _, _, err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if hadAuth {
		t.Error("Authorization header sent on an unauthenticated call")
	}
}

func TestAPIErrorFromEnvelope(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":{"code":"not_found","message":"Account not found"}}`)
	})

	_, _, err := c.GetAccount(context.Background(), "GAAAA")
	if err == nil {
		t.Fatal("GetAccount succeeded, want an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T, want *APIError", err)
	}
	if apiErr.Status != http.StatusNotFound || apiErr.Code != "not_found" || apiErr.Message != "Account not found" {
		t.Errorf("APIError = %+v", apiErr)
	}
	if got, want := err.Error(), "[404 not_found] Account not found"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if StatusCode(err) != http.StatusNotFound {
		t.Errorf("StatusCode = %d", StatusCode(err))
	}
	if IsUnauthorized(err) {
		t.Error("IsUnauthorized = true for a 404")
	}
}

func TestAPIErrorRateLimited(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":{"code":"rate_limited","message":"Too many requests, please try again later"}}`)
	})

	_, _, err := c.GetAccount(context.Background(), "GAAAA")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T, want *APIError", err)
	}
	if apiErr.RetryAfter != 42 {
		t.Errorf("RetryAfter = %d, want 42", apiErr.RetryAfter)
	}
	if !strings.Contains(err.Error(), "retry after 42s") {
		t.Errorf("Error() = %q, want it to mention the retry delay", err.Error())
	}
}

func TestAPIErrorWithoutEnvelope(t *testing.T) {
	// A proxy or load balancer can answer with something that isn't the
	// bridge's error envelope; the raw body must still reach the user.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>502 Bad Gateway</html>")
	})

	_, _, err := c.GetAccount(context.Background(), "GAAAA")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "Bad Gateway") {
		t.Errorf("Error() = %q, want the status and body", err.Error())
	}
}

func TestIsUnauthorized(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"code":"unauthorized","message":"Authentication required"}}`)
	})
	_, _, err := c.Token(context.Background(), TokenRequest{RefreshToken: "rt"})
	if !IsUnauthorized(err) {
		t.Errorf("IsUnauthorized(%v) = false, want true", err)
	}
}

func TestSuccessFalseIsAnError(t *testing.T) {
	// The bridge reports several failures as HTTP 200 + success:false. Those
	// must not be mistaken for a completed operation.
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"success":false,"message":"An account with this identifier already exists"}`)
	})

	res, _, err := c.CreateAccount(context.Background(), CreateAccountRequest{})
	if err == nil {
		t.Fatal("CreateAccount returned nil error for success:false")
	}
	if err.Error() != "An account with this identifier already exists" {
		t.Errorf("error = %q", err.Error())
	}
	if res == nil || res.Success {
		t.Errorf("response = %+v, want the decoded success:false body", res)
	}
}

func TestListTransactionsQuery(t *testing.T) {
	var got string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Encode()
		io.WriteString(w, `{"data":[],"page":1,"per_page":20,"total":0}`)
	})

	flagged := false
	_, _, err := c.ListTransactions(context.Background(), ListTransactionsOptions{
		Page:          2,
		PerPage:       50,
		Status:        "escalated",
		Flagged:       &flagged,
		SourceAccount: "GSRC",
		From:          "2026-01-01T00:00:00Z",
		To:            "2026-02-01T00:00:00Z",
		Query:         "coffee",
	})
	if err != nil {
		t.Fatalf("ListTransactions: %v", err)
	}
	want := "flagged=false&from=2026-01-01T00%3A00%3A00Z&page=2&per_page=50&q=coffee&source_account=GSRC&status=escalated&to=2026-02-01T00%3A00%3A00Z"
	if got != want {
		t.Errorf("query = %q\nwant     %q", got, want)
	}
}

func TestListTransactionsOmitsUnsetFilters(t *testing.T) {
	// A nil Flagged must not become flagged=false, which would silently hide
	// every flagged transaction.
	var got string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		io.WriteString(w, `{"data":[],"page":1,"per_page":20,"total":0}`)
	})
	if _, _, err := c.ListTransactions(context.Background(), ListTransactionsOptions{}); err != nil {
		t.Fatalf("ListTransactions: %v", err)
	}
	if got != "" {
		t.Errorf("query = %q, want empty", got)
	}
}

func TestPathParametersAreEscaped(t *testing.T) {
	var gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		io.WriteString(w, `{"account_id":"a b","sync_mode":"reserve","reserves":[]}`)
	})
	if _, _, err := c.GetReserves(context.Background(), "a b/c"); err != nil {
		t.Fatalf("GetReserves: %v", err)
	}
	if gotPath != "/reserves/a%20b%2Fc" {
		t.Errorf("path = %q, want the id escaped into a single segment", gotPath)
	}
}

func TestSyncPayalaBody(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"success":true,"message":"Sync batch applied","batch_id":"b1","sync_mode":"reserve",
			"received":1,"applied":1,"duplicates":0,"conflicting":0,"net_deltas":{"USD":-1500},"reserve_balances":[]}`)
	})

	res, _, err := c.SyncPayala(context.Background(), PayalaSyncRequest{
		AccountID:    "alice",
		Transactions: []PayalaSyncItem{{PayalaTxID: "tx1", Amount: -1500, Currency: "USD"}},
	})
	if err != nil {
		t.Fatalf("SyncPayala: %v", err)
	}
	if got["account_id"] != "alice" {
		t.Errorf("account_id = %v", got["account_id"])
	}
	items, ok := got["transactions"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("transactions = %v", got["transactions"])
	}
	item := items[0].(map[string]any)
	if item["amount"] != float64(-1500) || item["currency"] != "USD" {
		t.Errorf("item = %v", item)
	}
	// Optional per-item fields must be omitted rather than sent as "".
	if _, present := item["memo"]; present {
		t.Error("empty memo was serialized; want it omitted")
	}
	if res.NetDeltas["USD"] != -1500 {
		t.Errorf("net_deltas = %v", res.NetDeltas)
	}
}

func TestSetSyncModeOmitsForceWhenFalse(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"success":true,"message":"Sync mode updated","account_id":"alice","sync_mode":"mirror"}`)
	})

	if _, _, err := c.SetSyncMode(context.Background(), "alice", "mirror", false); err != nil {
		t.Fatalf("SetSyncMode: %v", err)
	}
	if _, present := got["force"]; present {
		t.Errorf("force was sent when not requested: %v", got)
	}
	if got["sync_mode"] != "mirror" {
		t.Errorf("sync_mode = %v", got["sync_mode"])
	}
}

func TestPageDecoding(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"payala_account_id":"alice","stellar_account_id":"GA","first_name":"Ada",
			"last_name":"Lovelace","middle_name":null,"role":"admin","sync_mode":"reserve",
			"profile_source":"local","created_at":"2026-01-01T00:00:00Z"}],"page":1,"per_page":20,"total":1}`)
	})

	page, _, err := c.ListAccounts(context.Background(), ListAccountsOptions{})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(page.Data) != 1 || page.Total != 1 {
		t.Fatalf("page = %+v", page)
	}
	if page.Data[0].MiddleName != nil {
		t.Errorf("null middle_name decoded as %v, want nil", *page.Data[0].MiddleName)
	}
}

func TestResultErr(t *testing.T) {
	if err := (Result{Success: true}).Err(); err != nil {
		t.Errorf("success Result returned %v", err)
	}
	if err := (Result{Message: "boom"}).Err(); err == nil || err.Error() != "boom" {
		t.Errorf("failure Result returned %v", err)
	}
	if err := (Result{}).Err(); err == nil {
		t.Error("failure Result with no message returned nil")
	}
}

func TestNewRefusesCleartextToNonLoopback(t *testing.T) {
	// Every request carries a bearer credential — the login password, the
	// single-use refresh token, the temporal JWT, or an imported seed — so a
	// plain-HTTP endpoint on the network must not be reachable by accident.
	for _, endpoint := range []string{
		"http://bridge.internal.example.com:8080",
		"http://10.0.0.5:8080",
		"http://192.168.1.10",
	} {
		if _, err := New(endpoint, time.Second, false); err == nil {
			t.Errorf("New(%q) allowed cleartext to a non-loopback host", endpoint)
		}
	}
}

func TestNewAllowsCleartextToLoopback(t *testing.T) {
	// The documented development default must keep working.
	for _, endpoint := range []string{
		"http://localhost:8080",
		"http://LocalHost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		if _, err := New(endpoint, time.Second, false); err != nil {
			t.Errorf("New(%q) = %v, want it allowed", endpoint, err)
		}
	}
}

func TestNewAllowsCleartextWithExplicitOptIn(t *testing.T) {
	if _, err := New("http://bridge.internal.example.com", time.Second, true); err != nil {
		t.Errorf("explicit opt-in still refused: %v", err)
	}
}

func TestNewAlwaysAllowsHTTPS(t *testing.T) {
	if _, err := New("https://bridge.example.com", time.Second, false); err != nil {
		t.Errorf("https endpoint refused: %v", err)
	}
}

// ── outcome classification ─────────────────────────────────────────────

// TestIsAmbiguousOutcomeByStatus pins the verdict table for bridge
// responses: only 503 (the bridge's provably-pre-submit Retryable) and the
// ordinary 4xx refusals prove nothing happened; 408 and every other 5xx
// leave the payment's fate open.
func TestIsAmbiguousOutcomeByStatus(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   bool
	}{
		{http.StatusBadRequest, "bad_request", false},
		{http.StatusUnauthorized, "unauthorized", false},
		{http.StatusForbidden, "forbidden", false},
		{http.StatusNotFound, "not_found", false},
		{http.StatusConflict, "conflict", false},
		{http.StatusTooManyRequests, "rate_limited", false},
		{http.StatusRequestTimeout, "", true}, // the bridge's deadline: empty body, no envelope
		{http.StatusInternalServerError, "internal_error", true},
		{http.StatusBadGateway, "", true},
		{http.StatusServiceUnavailable, "service_unavailable", false},
		{http.StatusGatewayTimeout, "", true},
		{520, "", true}, // a CDN's "origin returned an unknown error"
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s", tc.status, tc.code), func(t *testing.T) {
			err := error(&APIError{Status: tc.status, Code: tc.code})
			if got := IsAmbiguousOutcome(err); got != tc.want {
				t.Errorf("IsAmbiguousOutcome(%v) = %v, want %v", err, got, tc.want)
			}
			// Wrapping (as the CLI's session layer does) must not change the verdict.
			if got := IsAmbiguousOutcome(fmt.Errorf("wrapped: %w", err)); got != tc.want {
				t.Errorf("wrapped IsAmbiguousOutcome = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsAmbiguousOutcomeByPhase pins the transport side: a request that was
// never built or never connected is safe to retry; anything after the
// connection existed is not.
func TestIsAmbiguousOutcomeByPhase(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"build", &RequestError{Phase: PhaseBuild, Err: errors.New("encode request: boom")}, false},
		{"send: dial refused", &RequestError{Phase: PhaseSend, Err: &url.Error{Op: "Post", Err: dial}}, false},
		{"send: no such host", &RequestError{Phase: PhaseSend, Err: &url.Error{Op: "Post", Err: &net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}}}, false},
		{"send: client timeout", &RequestError{Phase: PhaseSend, Err: &url.Error{Op: "Post", Err: context.DeadlineExceeded}}, true},
		{"send: reset", &RequestError{Phase: PhaseSend, Err: &url.Error{Op: "Post", Err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}}, true},
		{"send: EOF", &RequestError{Phase: PhaseSend, Err: &url.Error{Op: "Post", Err: io.EOF}}, true},
		{"read", &RequestError{Phase: PhaseRead, Err: io.ErrUnexpectedEOF}, true},
		{"decode", &RequestError{Phase: PhaseDecode, Err: errors.New("invalid character")}, true},
		{"success:false verdict", errors.New("Invalid destination"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAmbiguousOutcome(tc.err); got != tc.want {
				t.Errorf("IsAmbiguousOutcome(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestCallFailuresAreTyped drives the real client through each transport
// failure and checks both the phase and the message the operator sees.
func TestCallFailuresAreTyped(t *testing.T) {
	t.Run("undecodable 2xx", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html>not json</html>")
		})
		_, _, err := c.SignAndSubmit(context.Background(), SignSubmitRequest{})
		var reqErr *RequestError
		if !errors.As(err, &reqErr) || reqErr.Phase != PhaseDecode {
			t.Fatalf("error = %v (%T), want a PhaseDecode RequestError", err, err)
		}
		if !strings.HasPrefix(err.Error(), "decode response from POST ") {
			t.Errorf("message = %q", err.Error())
		}
		if !IsAmbiguousOutcome(err) {
			t.Error("a success we could not read must be ambiguous")
		}
	})

	t.Run("hang past the client timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Drain the body first: the server only watches for the client
			// going away once the request has been read, and the context
			// is what lets the handler (and the server's Close) return.
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
		}))
		t.Cleanup(srv.Close)
		c, err := New(srv.URL, 200*time.Millisecond, false)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, _, err = c.SignAndSubmit(context.Background(), SignSubmitRequest{})
		if time.Since(start) > 5*time.Second {
			t.Fatalf("call took %s: the timeout did not apply", time.Since(start))
		}
		var reqErr *RequestError
		if !errors.As(err, &reqErr) || reqErr.Phase != PhaseSend {
			t.Fatalf("error = %v (%T), want a PhaseSend RequestError", err, err)
		}
		if !strings.HasPrefix(err.Error(), "POST "+srv.URL+"/managed-account/sign: ") {
			t.Errorf("message = %q", err.Error())
		}
		if !IsAmbiguousOutcome(err) {
			t.Error("a timeout awaiting the response must be ambiguous")
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing listens on the port any more
		c, err := New(url, time.Second, false)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = c.SignAndSubmit(context.Background(), SignSubmitRequest{})
		var reqErr *RequestError
		if !errors.As(err, &reqErr) || reqErr.Phase != PhaseSend {
			t.Fatalf("error = %v (%T), want a PhaseSend RequestError", err, err)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("error = %v, want it to carry ECONNREFUSED", err)
		}
		if IsAmbiguousOutcome(err) {
			t.Error("a connection that was never made cannot have delivered a payment")
		}
	})

	t.Run("dropped mid-response", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close()
		})
		_, _, err := c.SignAndSubmit(context.Background(), SignSubmitRequest{})
		var reqErr *RequestError
		if !errors.As(err, &reqErr) || reqErr.Phase != PhaseSend {
			t.Fatalf("error = %v (%T), want a PhaseSend RequestError", err, err)
		}
		if !IsAmbiguousOutcome(err) {
			t.Error("a connection dropped after the request went out must be ambiguous")
		}
	})

	t.Run("bridge 408 without envelope", func(t *testing.T) {
		// tower-http's TimeoutLayer answers with a bare status and no body.
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusRequestTimeout)
		})
		_, _, err := c.SignAndSubmit(context.Background(), SignSubmitRequest{})
		if got, want := err.Error(), "[408 http_error] Request Timeout"; got != want {
			t.Errorf("message = %q, want %q", got, want)
		}
		if !IsAmbiguousOutcome(err) {
			t.Error("the bridge's own deadline firing mid-handler must be ambiguous")
		}
	})
}
