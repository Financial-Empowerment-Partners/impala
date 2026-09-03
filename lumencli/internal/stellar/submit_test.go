package stellar

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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/network"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	sdkerrors "github.com/stellar/go-stellar-sdk/support/errors"
	"github.com/stellar/go-stellar-sdk/support/render/problem"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"lumencli/internal/netcfg"
	"lumencli/internal/wallet"
)

// horizonProblem synthesizes the error the SDK returns for a Horizon problem
// response with the given status and extras.
func horizonProblem(status int, typ, title string, extras map[string]interface{}) error {
	return &horizonclient.Error{
		Response: &http.Response{StatusCode: status},
		Problem:  problem.P{Type: typ, Title: title, Status: status, Extras: extras},
	}
}

// txFailed is Horizon's 400 transaction_failed problem for the given codes —
// the shape wrapHorizonError reads the codes out of.
func txFailed(txCode string, opCodes ...string) error {
	codes := map[string]interface{}{"transaction": txCode}
	if len(opCodes) > 0 {
		codes["operations"] = opCodes
	}
	return horizonProblem(400, "https://stellar.org/horizon-errors/transaction_failed", "Transaction Failed",
		map[string]interface{}{"result_codes": codes, "result_xdr": "AAAA", "envelope_xdr": "AAAA"})
}

// timeoutNetError is a net.Error with Timeout() true that is NOT a
// *net.OpError — the shape http.Client produces when its own Timeout fires
// while awaiting headers.
type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "Client.Timeout exceeded while awaiting headers" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return false }

// TestSubmitOutcomeUnknownClassification pins the rule that decides between
// "rejected, retry freely" and "unknown, stop and look": only a Horizon 4xx
// verdict (other than 408/429) and a never-connected dial failure count as
// proof that nothing landed.
func TestSubmitOutcomeUnknownClassification(t *testing.T) {
	post := func(inner error) error {
		return &url.Error{Op: "Post", URL: "https://horizon.example/transactions", Err: inner}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Horizon's own verdicts.
		{"504 timeout: forwarded, still pending", horizonProblem(504, "https://stellar.org/horizon-errors/timeout", "Timeout", nil), true},
		{"503 service unavailable", horizonProblem(503, "https://stellar.org/horizon-errors/server_error", "Service Unavailable", nil), true},
		{"500 server error", horizonProblem(500, "https://stellar.org/horizon-errors/server_error", "Internal Server Error", nil), true},
		{"502 from a proxy, problem-shaped", horizonProblem(502, "about:blank", "Bad Gateway", nil), true},
		{"429 rate limited", horizonProblem(429, "https://stellar.org/horizon-errors/rate_limit_exceeded", "Rate Limit Exceeded", nil), true},
		{"408 request timeout", horizonProblem(408, "about:blank", "Request Timeout", nil), true},
		{"400 tx_bad_seq", txFailed("tx_bad_seq"), false},
		{"400 tx_insufficient_fee", txFailed("tx_insufficient_fee"), false},
		{"400 tx_failed with op codes", txFailed("tx_failed", "op_underfunded"), false},
		{"400 malformed envelope", horizonProblem(400, "https://stellar.org/horizon-errors/transaction_malformed", "Transaction Malformed", nil), false},
		{"401", horizonProblem(401, "about:blank", "Unauthorized", nil), false},
		{"403", horizonProblem(403, "about:blank", "Forbidden", nil), false},
		{"404", horizonProblem(404, "https://stellar.org/horizon-errors/not_found", "Resource Missing", nil), false},
		{"405 submission disabled", horizonProblem(405, "https://stellar.org/horizon-errors/transaction_submission_disabled", "Transaction Submission Disabled", nil), false},
		{"410 gone", horizonProblem(410, "about:blank", "Gone", nil), false},
		// The SDK wraps with pkg/errors in places; the verdict must survive it.
		{"wrapped 400 verdict", sdkerrors.Wrap(txFailed("tx_bad_seq"), "sending request to horizon"), false},
		{"wrapped 504", sdkerrors.Wrap(horizonProblem(504, "https://stellar.org/horizon-errors/timeout", "Timeout", nil), "sending request to horizon"), true},
		// Transport: only a dial failure proves nothing was sent.
		{"dial refused", post(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}), false},
		{"dial no such host", post(&net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "horizon.example", IsNotFound: true}}), false},
		{"dial timeout", post(&net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "i/o timeout", IsTimeout: true}}), false},
		{"read reset", post(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"write broken pipe", post(&net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE}), true},
		{"client timeout awaiting headers", post(timeoutNetError{}), true},
		{"context deadline exceeded", post(context.DeadlineExceeded), true},
		{"unexpected EOF", post(io.ErrUnexpectedEOF), true},
		{"2xx body undecodable", sdkerrors.Wrap(io.ErrUnexpectedEOF, "error decoding response"), true},
		{"problem body undecodable", sdkerrors.Wrap(errors.New("invalid character '<'"), "error decoding horizon.Problem"), true},
		{"bare unknown error", errors.New("something else"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := submitOutcomeUnknown(tc.err); got != tc.want {
				t.Errorf("submitOutcomeUnknown(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---- a fake Horizon for the submit path ------------------------------------

// accountJSON builds an honest account record: it must round-trip through
// the SDK's Account type with the sequence intact (on the wire the sequence
// is a JSON string; a fixture sending a number would describe a Horizon that
// does not exist).
func accountJSON(t *testing.T, address string, sequence int64) string {
	t.Helper()
	m := map[string]interface{}{
		"id":                   address,
		"account_id":           address,
		"sequence":             fmt.Sprint(sequence),
		"subentry_count":       0,
		"last_modified_ledger": 100,
		"last_modified_time":   "2026-08-30T14:02:11Z",
		"thresholds":           map[string]int{"low_threshold": 0, "med_threshold": 0, "high_threshold": 0},
		"flags":                map[string]bool{"auth_required": false, "auth_revocable": false, "auth_immutable": false, "auth_clawback_enabled": false},
		"balances":             []map[string]string{{"balance": "100.0000000", "asset_type": "native"}},
		"signers":              []map[string]interface{}{{"key": address, "weight": 1, "type": "ed25519_public_key"}},
		"data":                 map[string]string{},
		"num_sponsoring":       0,
		"num_sponsored":        0,
		"paging_token":         address,
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal account: %v", err)
	}
	var acct hProtocol.Account
	if err := json.Unmarshal(raw, &acct); err != nil {
		t.Fatalf("account record does not round-trip through the SDK type (dishonest fixture): %v\n%s", err, raw)
	}
	if acct.AccountID != address || acct.Sequence != sequence {
		t.Fatalf("account round-trip mismatch: got %s/%d\n%s", acct.AccountID, acct.Sequence, raw)
	}
	return string(raw)
}

// problemJSON renders a Horizon problem document and proves it decodes back
// to the same problem — with, when result codes are supplied, the codes
// readable through the SDK's own accessor, which is what the CLI's error
// rendering uses.
func problemJSON(t *testing.T, p problem.P) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal problem: %v", err)
	}
	var back problem.P
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("problem does not round-trip (dishonest fixture): %v\n%s", err, raw)
	}
	if back.Status != p.Status || back.Type != p.Type || back.Title != p.Title {
		t.Fatalf("problem round-trip mismatch:\n%s", raw)
	}
	if _, has := p.Extras["result_codes"]; has {
		herr := &horizonclient.Error{Problem: back}
		codes, err := herr.ResultCodes()
		if err != nil || codes.TransactionCode == "" {
			t.Fatalf("result_codes not readable through the SDK (dishonest fixture): %v\n%s", err, raw)
		}
	}
	return string(raw)
}

// submittedTxJSON is the success body of POST /transactions: a transaction
// record echoing the hash. It must round-trip through the SDK type with the
// hash intact.
func submittedTxJSON(t *testing.T, hash, source, envelope string) string {
	t.Helper()
	m := map[string]interface{}{
		"id":                      hash,
		"paging_token":            "12884905984",
		"successful":              true,
		"hash":                    hash,
		"ledger":                  1234,
		"created_at":              "2026-08-30T14:02:11Z",
		"source_account":          source,
		"source_account_sequence": "2",
		"fee_account":             source,
		"fee_charged":             "100",
		"max_fee":                 "100",
		"operation_count":         1,
		"envelope_xdr":            envelope,
		"result_xdr":              "AAAA",
		"fee_meta_xdr":            "AAAA",
		"memo_type":               "none",
		"signatures":              []string{"c2ln"},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal transaction: %v", err)
	}
	var tx hProtocol.Transaction
	if err := json.Unmarshal(raw, &tx); err != nil {
		t.Fatalf("transaction record does not round-trip through the SDK type (dishonest fixture): %v\n%s", err, raw)
	}
	if tx.Hash != hash || !tx.Successful {
		t.Fatalf("transaction round-trip mismatch:\n%s", raw)
	}
	return string(raw)
}

// envelopeHash decodes a submitted base64 envelope and returns its testnet
// hash and upper time bound — the values the CLI must have reported.
func envelopeHash(t *testing.T, xdr string) (hash string, maxTime int64) {
	t.Helper()
	generic, err := txnbuild.TransactionFromXDR(xdr)
	if err != nil {
		t.Fatalf("submitted envelope does not decode: %v", err)
	}
	tx, ok := generic.Transaction()
	if !ok {
		t.Fatal("submitted envelope is not a plain transaction")
	}
	hash, err = tx.HashHex(network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("hash submitted envelope: %v", err)
	}
	return hash, tx.Timebounds().MaxTime
}

// submitFake is a Horizon serving one funded source account and a scripted
// POST /transactions. It records every submitted envelope and fails the test
// if the SDK's SEP-0029 lookup is ever attempted.
type submitFake struct {
	t      *testing.T
	srv    *httptest.Server
	source string

	mu        sync.Mutex
	envelopes []string
	respond   func(w http.ResponseWriter, r *http.Request, xdr string)
}

func newSubmitFake(t *testing.T, source string, respond func(w http.ResponseWriter, r *http.Request, xdr string)) *submitFake {
	t.Helper()
	f := &submitFake{t: t, source: source, respond: respond}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /accounts/"+source, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, accountJSON(t, source, 1))
	})
	mux.HandleFunc("GET /accounts/{id}/data/{key}", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the SDK's memo-required lookup ran (%s): SkipMemoRequiredCheck is not in effect", r.URL.Path)
		http.NotFound(w, r)
	})
	mux.HandleFunc("POST /transactions", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("submit: parse form: %v", err)
		}
		xdr := r.PostForm.Get("tx")
		if xdr == "" {
			t.Errorf("submit: no tx form field")
		}
		f.mu.Lock()
		f.envelopes = append(f.envelopes, xdr)
		f.mu.Unlock()
		f.respond(w, r, xdr)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *submitFake) submitted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.envelopes...)
}

func (f *submitFake) network() netcfg.Network {
	return netcfg.Network{Name: netcfg.NameTestnet, HorizonURL: f.srv.URL, Passphrase: network.TestNetworkPassphrase, IsTestnet: true}
}

func testKeys(t *testing.T) (source, dest string, seed string) {
	t.Helper()
	src, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dst, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return src.Address(), dst.Address(), src.Seed()
}

func requireAmbiguous(t *testing.T, err error) *AmbiguousSubmitError {
	t.Helper()
	var amb *AmbiguousSubmitError
	if !errors.As(err, &amb) {
		t.Fatalf("error %v (%T) is not an *AmbiguousSubmitError", err, err)
	}
	return amb
}

// TestSendPaymentSuccessReturnsLocalHash: the happy path returns the hash of
// the envelope actually posted, and the SDK's memo lookup never runs.
func TestSendPaymentSuccessReturnsLocalHash(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		hash, _ := envelopeHash(t, xdr)
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, submittedTxJSON(t, hash, source, xdr))
	})
	kp, err := wallet.ParseSecret(seed)
	if err != nil {
		t.Fatal(err)
	}

	got, err := New(f.network()).SendPayment(kp, dest, "10", nil)
	if err != nil {
		t.Fatalf("SendPayment: %v", err)
	}
	envs := f.submitted()
	if len(envs) != 1 {
		t.Fatalf("submitted %d envelopes, want 1", len(envs))
	}
	if want, _ := envelopeHash(t, envs[0]); got != want {
		t.Errorf("returned hash %s, want the submitted envelope's %s", got, want)
	}
}

// TestSendPaymentHorizonTimeoutIsAmbiguous: Horizon's 504 means "forwarded,
// still pending" — the result must carry the real hash and time bound.
func TestSendPaymentHorizonTimeoutIsAmbiguous(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(504)
		fmt.Fprint(w, problemJSON(t, problem.P{
			Type: "https://stellar.org/horizon-errors/timeout", Title: "Timeout", Status: 504,
			Detail: "Your request timed out before completing.",
		}))
	})
	kp, _ := wallet.ParseSecret(seed)

	before := time.Now()
	_, err := New(f.network()).SendPayment(kp, dest, "10", nil)
	amb := requireAmbiguous(t, err)

	envs := f.submitted()
	if len(envs) != 1 {
		t.Fatalf("submitted %d envelopes, want 1", len(envs))
	}
	hash, maxTime := envelopeHash(t, envs[0])
	if amb.Hash != hash {
		t.Errorf("Hash = %s, want the submitted envelope's %s", amb.Hash, hash)
	}
	if amb.MaxTime.Unix() != maxTime {
		t.Errorf("MaxTime = %d, want the envelope's %d", amb.MaxTime.Unix(), maxTime)
	}
	// The bound is the validity window measured from build time.
	if lo, hi := before.Unix()+txTimeoutSeconds-2, time.Now().Unix()+txTimeoutSeconds; maxTime < lo || maxTime > hi {
		t.Errorf("MaxTime %d outside [%d, %d]", maxTime, lo, hi)
	}
	if !strings.Contains(err.Error(), "Timeout") {
		t.Errorf("error %q does not name the Horizon problem", err)
	}
}

// TestSendPaymentClientTimeoutIsAmbiguous: Horizon never answers and the
// client's own timeout fires. The request was delivered, so this is the
// same unknown outcome, with the same hash.
func TestSendPaymentClientTimeoutIsAmbiguous(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		<-r.Context().Done() // hang until the client gives up
	})
	kp, _ := wallet.ParseSecret(seed)

	start := time.Now()
	_, err := NewWithTimeout(f.network(), 200*time.Millisecond).SendPayment(kp, dest, "10", nil)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("submit took %s: the timeout override did not apply", time.Since(start))
	}
	amb := requireAmbiguous(t, err)
	if hash, _ := envelopeHash(t, f.submitted()[0]); amb.Hash != hash {
		t.Errorf("Hash = %s, want %s", amb.Hash, hash)
	}
}

// TestSendPaymentRejectionIsPlain: a 400 with result codes is Horizon saying
// the transaction cannot land — a plain error naming the codes, never an
// ambiguous one.
func TestSendPaymentRejectionIsPlain(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(400)
		fmt.Fprint(w, problemJSON(t, problem.P{
			Type: "https://stellar.org/horizon-errors/transaction_failed", Title: "Transaction Failed", Status: 400,
			Extras: map[string]interface{}{
				"result_codes": map[string]interface{}{"transaction": "tx_bad_seq"},
				"result_xdr":   "AAAAAAAAAGT////7AAAAAA==",
				"envelope_xdr": xdr,
			},
		}))
	})
	kp, _ := wallet.ParseSecret(seed)

	_, err := New(f.network()).SendPayment(kp, dest, "10", nil)
	if err == nil {
		t.Fatal("SendPayment succeeded on a 400")
	}
	var amb *AmbiguousSubmitError
	if errors.As(err, &amb) {
		t.Fatalf("a definitive rejection was classified as ambiguous: %v", err)
	}
	if !strings.Contains(err.Error(), "tx_bad_seq") {
		t.Errorf("error %q does not name the result code", err)
	}
}

// roundTripFunc adapts a function into an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestSendPaymentDialFailureIsPlain: when the connection for the POST is
// never established, nothing was sent, and the error is a plain one — the
// user may simply retry.
func TestSendPaymentDialFailureIsPlain(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		t.Error("the POST reached the server despite the simulated dial failure")
	})
	kp, _ := wallet.ParseSecret(seed)

	c := New(f.network())
	real := http.DefaultTransport
	c.horizon.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		return real.RoundTrip(r)
	})}

	_, err := c.SendPayment(kp, dest, "10", nil)
	if err == nil {
		t.Fatal("SendPayment succeeded")
	}
	var amb *AmbiguousSubmitError
	if errors.As(err, &amb) {
		t.Fatalf("a never-connected dial failure was classified as ambiguous: %v", err)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("error %v does not carry the dial failure", err)
	}
}

// TestSendPaymentHashMismatchIsAmbiguous: a 200 acknowledging some OTHER hash
// is neither a confirmation nor a rejection of the transaction sent, so it
// is refused as ambiguous with the local hash — never reported as success.
func TestSendPaymentHashMismatchIsAmbiguous(t *testing.T) {
	source, dest, seed := testKeys(t)
	other := strings.Repeat("ab", 32)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, submittedTxJSON(t, other, source, xdr))
	})
	kp, _ := wallet.ParseSecret(seed)

	_, err := New(f.network()).SendPayment(kp, dest, "10", nil)
	amb := requireAmbiguous(t, err)
	if hash, _ := envelopeHash(t, f.submitted()[0]); amb.Hash != hash {
		t.Errorf("Hash = %s, want the local %s", amb.Hash, hash)
	}
	if !strings.Contains(err.Error(), other) {
		t.Errorf("error %q does not name the acknowledged hash", err)
	}
}

// TestCreateAccountSharesTheSubmitPath: account create goes through the same
// classification — a Horizon 504 is ambiguous with the real hash.
func TestCreateAccountSharesTheSubmitPath(t *testing.T) {
	source, dest, seed := testKeys(t)
	f := newSubmitFake(t, source, func(w http.ResponseWriter, r *http.Request, xdr string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(504)
		fmt.Fprint(w, problemJSON(t, problem.P{Type: "https://stellar.org/horizon-errors/timeout", Title: "Timeout", Status: 504}))
	})
	kp, _ := wallet.ParseSecret(seed)

	_, err := New(f.network()).CreateAccount(kp, dest, "10", nil)
	amb := requireAmbiguous(t, err)
	if hash, _ := envelopeHash(t, f.submitted()[0]); amb.Hash != hash {
		t.Errorf("Hash = %s, want %s", amb.Hash, hash)
	}
}
