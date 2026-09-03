package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/network"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/support/render/problem"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
	"lumencli/internal/wallet"
)

// ---- honest fixtures for the submit path -----------------------------------

// submitAccountJSON builds an account record that round-trips through the
// SDK's Account type with the sequence intact. On the wire the sequence is
// a JSON string; a fixture sending a number would describe a Horizon that
// does not exist. data carries SEP-0029 style entries (base64 values).
func submitAccountJSON(t *testing.T, address string, sequence int64, data map[string]string) string {
	t.Helper()
	if data == nil {
		data = map[string]string{}
	}
	m := map[string]any{
		"id":                   address,
		"account_id":           address,
		"sequence":             strconv.FormatInt(sequence, 10),
		"subentry_count":       0,
		"last_modified_ledger": 100,
		"last_modified_time":   "2026-08-30T14:02:11Z",
		"thresholds":           map[string]int{"low_threshold": 0, "med_threshold": 0, "high_threshold": 0},
		"flags":                map[string]bool{"auth_required": false, "auth_revocable": false, "auth_immutable": false, "auth_clawback_enabled": false},
		"balances":             []map[string]string{{"balance": "100.0000000", "asset_type": "native"}},
		"signers":              []map[string]any{{"key": address, "weight": 1, "type": "ed25519_public_key"}},
		"data":                 data,
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
	if acct.AccountID != address || acct.Sequence != sequence || len(acct.Data) != len(data) {
		t.Fatalf("account round-trip mismatch:\n%s", raw)
	}
	return string(raw)
}

// submitProblemJSON renders a Horizon problem document and proves it decodes
// back to the same problem, with any result codes readable through the SDK's
// accessor — the one the CLI's error rendering uses.
func submitProblemJSON(t *testing.T, p problem.P) string {
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
		codes, err := (&horizonclient.Error{Problem: back}).ResultCodes()
		if err != nil || codes.TransactionCode == "" {
			t.Fatalf("result_codes not readable through the SDK (dishonest fixture): %v\n%s", err, raw)
		}
	}
	return string(raw)
}

// submitTxJSON is the success body of POST /transactions, echoing the hash;
// it must round-trip through the SDK's Transaction type.
func submitTxJSON(t *testing.T, hash, source, envelope string) string {
	t.Helper()
	m := map[string]any{
		"id": hash, "paging_token": "12884905984", "successful": true, "hash": hash, "ledger": 1234,
		"created_at": "2026-08-30T14:02:11Z", "source_account": source, "source_account_sequence": "2",
		"fee_account": source, "fee_charged": "100", "max_fee": "100", "operation_count": 1,
		"envelope_xdr": envelope, "result_xdr": "AAAA", "fee_meta_xdr": "AAAA", "memo_type": "none",
		"signatures": []string{"c2ln"},
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

// submittedEnvelope decodes a posted base64 envelope into the values the
// CLI must have reported: its testnet hash and its upper time bound.
func submittedEnvelope(t *testing.T, xdr string) (hash string, maxTime time.Time) {
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
	return hash, time.Unix(tx.Timebounds().MaxTime, 0).UTC()
}

// submitResponder scripts the fake's answer to POST /transactions.
type submitResponder func(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string)

// respondSuccess acknowledges the envelope with its own hash.
func respondSuccess(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string) {
	hash, _ := submittedEnvelope(t, xdr)
	w.Header().Set("Content-Type", "application/hal+json")
	fmt.Fprint(w, submitTxJSON(t, hash, source, xdr))
}

// respondHorizonTimeout is Horizon's 504: the transaction was forwarded to
// the network and had not been applied when Horizon gave up waiting.
func respondHorizonTimeout(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusGatewayTimeout)
	fmt.Fprint(w, submitProblemJSON(t, problem.P{
		Type: "https://stellar.org/horizon-errors/timeout", Title: "Timeout", Status: 504,
		Detail: "Your request timed out before completing. Please try your request again. " +
			"If you are submitting a transaction make sure you are sending exactly the same transaction (with the same sequence number).",
	}))
}

// respondHang never answers; the client's own timeout ends the wait.
func respondHang(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string) {
	<-r.Context().Done()
}

// respondDrop tears the connection down mid-response.
func respondDrop(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("response writer cannot hijack")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	conn.Close()
}

// respondBadSeq is Horizon's definitive 400 for a stale sequence number.
func respondBadSeq(t *testing.T, w http.ResponseWriter, r *http.Request, source, xdr string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, submitProblemJSON(t, problem.P{
		Type: "https://stellar.org/horizon-errors/transaction_failed", Title: "Transaction Failed", Status: 400,
		Detail: "The transaction failed when submitted to the stellar network.",
		Extras: map[string]any{
			"result_codes": map[string]any{"transaction": "tx_bad_seq"},
			"result_xdr":   "AAAAAAAAAGT////7AAAAAA==",
			"envelope_xdr": xdr,
		},
	}))
}

// submitHarness is a fake Horizon for the fund-moving commands: a funded
// source account, a destination account (send's memo guard consults it), a
// scripted POST /transactions that records every envelope, and a tripwire on
// the SDK's SEP-0029 lookup, which lumencli must never let run.
type submitHarness struct {
	f      *horizonFake
	source string
	dest   string
	seed   string

	mu        sync.Mutex
	envelopes []string
}

func newSubmitHarness(t *testing.T, destData map[string]string, respond submitResponder) *submitHarness {
	t.Helper()
	src, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dst, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	h := &submitHarness{f: newHorizonFake(t), source: src.Address(), dest: dst.Address(), seed: src.Seed()}

	srcBody := submitAccountJSON(t, h.source, 1, nil)
	h.f.handle("GET /accounts/"+h.source, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, srcBody)
	})
	dstBody := submitAccountJSON(t, h.dest, 7, destData)
	h.f.handle("GET /accounts/"+h.dest, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, dstBody)
	})
	h.f.handle("GET /accounts/{id}/data/{key}", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the SDK's memo-required lookup ran (%s): the submit must skip it, lumencli has its own guard", r.URL.Path)
		http.NotFound(w, r)
	})
	h.f.handle("POST /transactions", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("submit: parse form: %v", err)
		}
		xdr := r.PostForm.Get("tx")
		if xdr == "" {
			t.Errorf("submit: no tx form field")
		}
		h.mu.Lock()
		h.envelopes = append(h.envelopes, xdr)
		h.mu.Unlock()
		respond(t, w, r, h.source, xdr)
	})
	return h
}

// submitted returns the one envelope the command posted.
func (h *submitHarness) submitted(t *testing.T) string {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.envelopes) != 1 {
		t.Fatalf("submitted %d envelopes, want exactly 1", len(h.envelopes))
	}
	return h.envelopes[0]
}

// args builds the command line for one of the two fund-moving commands
// against the fake, on testnet (so the spend confirmation stays out of the
// way) with the seed supplied through the environment.
func (h *submitHarness) args(command string, extra ...string) []string {
	var args []string
	switch command {
	case "send":
		args = []string{"send", "--to", h.dest}
	case "account create":
		args = []string{"account", "create", "--dest", h.dest}
	default:
		panic("unknown command " + command)
	}
	args = append(args, "--amount", "10", "--network", "testnet", "--horizon-url", h.f.URL())
	return append(args, extra...)
}

func (h *submitHarness) env() map[string]string { return map[string]string{EnvSecret: h.seed} }

// fundMovingCommands are the two commands that sign and submit.
var fundMovingCommands = []struct {
	command string
	what    string // how the notice names the operation
}{
	{"send", "payment"},
	{"account create", "account creation"},
}

// remainingPattern matches the countdown in the notice's time-bound line.
var remainingPattern = regexp.MustCompile(`\(in (\d+)s\)`)

// requireAmbiguousNotice checks everything the ambiguous-outcome notice must
// carry: the full hash of the envelope actually posted, the time bound from
// that envelope, the may-still-be-applied warning, the do-not-re-run
// instruction, and the exact lookup command targeting the same Horizon.
func requireAmbiguousNotice(t *testing.T, h *submitHarness, what, stderr string) {
	t.Helper()
	hash, maxTime := submittedEnvelope(t, h.submitted(t))
	for _, want := range []string{
		"WARNING: the outcome of this " + what + " is UNKNOWN",
		"MAY STILL BE APPLIED",
		"Transaction hash: " + hash,
		"Valid until:      " + maxTime.Format("2006-01-02 15:04:05 UTC") + " (in ",
		"DO NOT re-run this command",
		"lumencli tx " + hash + " --network testnet --horizon-url " + h.f.URL(),
		`A "not found" answer inside the window proves nothing`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	m := remainingPattern.FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("stderr has no remaining-seconds countdown:\n%s", stderr)
	}
	if secs, _ := strconv.Atoi(m[1]); secs < 1 || secs > 300 {
		t.Errorf("remaining seconds = %d, want within the 300s validity window", secs)
	}
}

// TestSubmitHorizonTimeoutIsAmbiguous is the headline case from the double
// spend: Horizon answers 504 Timeout, the transaction is still pending, and
// the CLI must say so — hash, window, lookup, exit 3 — instead of "error".
func TestSubmitHorizonTimeoutIsAmbiguous(t *testing.T) {
	for _, tc := range fundMovingCommands {
		t.Run(tc.command, func(t *testing.T) {
			h := newSubmitHarness(t, nil, respondHorizonTimeout)
			app, out, errb := newTestApp("", h.env())
			if code := app.run(h.args(tc.command)); code != exitAmbiguous {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitAmbiguous, errb.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q not empty on an ambiguous outcome", out.String())
			}
			es := errb.String()
			if !strings.Contains(es, "error: submit transaction: Timeout") {
				t.Errorf("stderr does not lead with the Horizon error:\n%s", es)
			}
			requireAmbiguousNotice(t, h, tc.what, es)
		})
	}
}

// TestSubmitClientTimeoutIsAmbiguous: Horizon never answers and the client's
// own timeout fires. The request was delivered, so the outcome is just as
// unknown, and the notice is the same.
func TestSubmitClientTimeoutIsAmbiguous(t *testing.T) {
	for _, tc := range fundMovingCommands {
		t.Run(tc.command, func(t *testing.T) {
			h := newSubmitHarness(t, nil, respondHang)
			app, out, errb := newTestApp("", h.env())
			app.horizonTimeout = 200 * time.Millisecond

			start := time.Now()
			code := app.run(h.args(tc.command))
			if time.Since(start) > 5*time.Second {
				t.Fatalf("command took %s: the timeout override did not apply", time.Since(start))
			}
			if code != exitAmbiguous {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitAmbiguous, errb.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q not empty on an ambiguous outcome", out.String())
			}
			requireAmbiguousNotice(t, h, tc.what, errb.String())
		})
	}
}

// TestSubmitDroppedConnectionIsAmbiguous: the connection dies after the
// request went out — a transport error, not a Horizon verdict.
func TestSubmitDroppedConnectionIsAmbiguous(t *testing.T) {
	for _, tc := range fundMovingCommands {
		t.Run(tc.command, func(t *testing.T) {
			h := newSubmitHarness(t, nil, respondDrop)
			app, _, errb := newTestApp("", h.env())
			if code := app.run(h.args(tc.command)); code != exitAmbiguous {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitAmbiguous, errb.String())
			}
			requireAmbiguousNotice(t, h, tc.what, errb.String())
		})
	}
}

// TestSubmitRejectionIsPlainFailure: a 400 with result codes is Horizon's
// proof that the transaction cannot land. That stays an ordinary exit 1
// naming the code, with none of the ambiguity wording — a script must be
// able to retry a tx_bad_seq without a manual check.
func TestSubmitRejectionIsPlainFailure(t *testing.T) {
	for _, tc := range fundMovingCommands {
		t.Run(tc.command, func(t *testing.T) {
			h := newSubmitHarness(t, nil, respondBadSeq)
			app, out, errb := newTestApp("", h.env())
			if code := app.run(h.args(tc.command)); code != 1 {
				t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, errb.String())
			}
			h.submitted(t) // it did reach the submit
			es := errb.String()
			if !strings.Contains(es, "tx_bad_seq") {
				t.Errorf("stderr does not name the result code:\n%s", es)
			}
			for _, absent := range []string{"UNKNOWN", "MAY STILL BE APPLIED", "DO NOT re-run"} {
				if strings.Contains(es, absent) {
					t.Errorf("a definitive rejection carries the ambiguity wording %q:\n%s", absent, es)
				}
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q not empty on failure", out.String())
			}
		})
	}
}

// TestSubmitSuccessPrintsTheHash: the receipt names the hash of the envelope
// that was actually posted, and the SDK's memo lookup never ran.
func TestSubmitSuccessPrintsTheHash(t *testing.T) {
	for _, tc := range fundMovingCommands {
		t.Run(tc.command, func(t *testing.T) {
			h := newSubmitHarness(t, nil, respondSuccess)
			app, out, errb := newTestApp("", h.env())
			if code := app.run(h.args(tc.command)); code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, errb.String())
			}
			hash, _ := submittedEnvelope(t, h.submitted(t))
			if !strings.Contains(out.String(), "Transaction: "+hash) {
				t.Errorf("stdout %q does not carry the submitted envelope's hash %s", out.String(), hash)
			}
			if strings.Contains(errb.String(), "WARNING") {
				t.Errorf("a successful submit warned:\n%s", errb.String())
			}
		})
	}
}

// TestSendNoMemoOverrideReachesSubmit pins that --no-memo means what the
// documentation says. The SDK's own SEP-0029 check used to run inside
// SubmitTransaction and re-refuse the transfer after lumencli's guard had
// been explicitly overridden; the submit now skips it, so the override
// actually overrides — and the guard itself still fired first.
func TestSendNoMemoOverrideReachesSubmit(t *testing.T) {
	declared := map[string]string{"config.memo_required": base64.StdEncoding.EncodeToString([]byte("1"))}
	h := newSubmitHarness(t, declared, respondSuccess)
	app, out, errb := newTestApp("", h.env())
	if code := app.run(h.args("send", "--no-memo")); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, errb.String())
	}
	es := errb.String()
	if !strings.Contains(es, "WARNING: this transfer carries no memo") || !strings.Contains(es, "--no-memo was given") {
		t.Errorf("lumencli's own memo guard did not run before the submit:\n%s", es)
	}
	hash, _ := submittedEnvelope(t, h.submitted(t))
	if !strings.Contains(out.String(), "Transaction: "+hash) {
		t.Errorf("stdout %q does not carry the hash", out.String())
	}
}

// TestSendMemoGuardStillRefusesBeforeSubmit: skipping the SDK's check must
// not have weakened lumencli's — a memo-less send to a declared destination
// is still refused, and nothing is ever posted.
func TestSendMemoGuardStillRefusesBeforeSubmit(t *testing.T) {
	declared := map[string]string{"config.memo_required": base64.StdEncoding.EncodeToString([]byte("1"))}
	h := newSubmitHarness(t, declared, respondSuccess)
	app, _, errb := newTestApp("", h.env())
	if code := app.run(h.args("send")); code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr:\n%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "refusing") {
		t.Errorf("stderr %q missing the refusal", errb.String())
	}
	if got := len(h.f.requests("/transactions")); got != 0 {
		t.Errorf("POST /transactions was hit %d times despite the memo refusal", got)
	}
}

// ---- pure helpers ----------------------------------------------------------

func TestDescribeMaxTime(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		max  time.Time
		want string
	}{
		{"whole seconds", now.Add(287 * time.Second), "2026-09-03 12:04:47 UTC (in 287s)"},
		{"rounds up", now.Add(1500 * time.Millisecond), "2026-09-03 12:00:01 UTC (in 2s)"},
		{"just under a second is not expired", now.Add(10 * time.Millisecond), "2026-09-03 12:00:00 UTC (in 1s)"},
		{"expired", now.Add(-time.Second), "2026-09-03 11:59:59 UTC (already passed)"},
		{"exactly now", now, "2026-09-03 12:00:00 UTC (already passed)"},
		{"non-UTC input rendered in UTC", now.Add(60 * time.Second).In(time.FixedZone("x", -7*3600)), "2026-09-03 12:01:00 UTC (in 60s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeMaxTime(tc.max, now); got != tc.want {
				t.Errorf("describeMaxTime = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTxLookupCommand(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		net  netcfg.Network
		want string
	}{
		{"mainnet default", netcfg.Network{Name: netcfg.NameMainnet, HorizonURL: netcfg.MainnetHorizonURL},
			"lumencli tx " + hash + " --network mainnet"},
		{"testnet default", netcfg.Network{Name: netcfg.NameTestnet, HorizonURL: netcfg.TestnetHorizonURL, IsTestnet: true},
			"lumencli tx " + hash + " --network testnet"},
		{"testnet with overridden horizon", netcfg.Network{Name: netcfg.NameTestnet, HorizonURL: "http://127.0.0.1:8000", IsTestnet: true},
			"lumencli tx " + hash + " --network testnet --horizon-url http://127.0.0.1:8000"},
		{"custom network needs both overrides", netcfg.Network{Name: netcfg.NameCustom, HorizonURL: "https://h.example", Passphrase: "Test SDF Future Network ; October 2022"},
			"lumencli tx " + hash + " --horizon-url https://h.example --network-passphrase 'Test SDF Future Network ; October 2022'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := txLookupCommand(tc.net, hash); got != tc.want {
				t.Errorf("txLookupCommand =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}

// TestAmbiguousNoticeAfterTheWindow: when the bound has already passed by
// the time the notice prints, it must say the lookup is now definitive
// rather than telling the user to keep waiting.
func TestAmbiguousNoticeAfterTheWindow(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	net := netcfg.Network{Name: netcfg.NameTestnet, HorizonURL: netcfg.TestnetHorizonURL, IsTestnet: true}
	hash := strings.Repeat("cd", 32)
	code := app.failAmbiguous(net, "payment", &stellar.AmbiguousSubmitError{
		Hash: hash, MaxTime: time.Now().Add(-time.Minute), Cause: errors.New("submit transaction: Timeout"),
	})
	if code != exitAmbiguous {
		t.Fatalf("exit code = %d, want %d", code, exitAmbiguous)
	}
	es := errb.String()
	for _, want := range []string{"(already passed)", "The time bound has already passed", "Transaction hash: " + hash} {
		if !strings.Contains(es, want) {
			t.Errorf("stderr missing %q:\n%s", want, es)
		}
	}
	if strings.Contains(es, "Keep checking") {
		t.Errorf("an expired window still tells the user to keep waiting:\n%s", es)
	}
}
