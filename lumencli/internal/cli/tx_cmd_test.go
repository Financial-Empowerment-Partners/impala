package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
)

// txTestHash is a canonical (lowercase) 64-hex-digit transaction hash.
var txTestHash = strings.Repeat("ab", 32)

func txArgs(url, hash string, extra ...string) []string {
	return append([]string{
		"tx", "--network", "testnet", "--horizon-url", url, hash,
	}, extra...)
}

// runTxOK runs a tx command against the fake and requires exit 0.
func runTxOK(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	app, out, errb := newTestApp("", nil)
	if code := app.run(args); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, errb.String())
	}
	return out.String(), errb.String()
}

// txRec builds one /transactions/{hash} record. On the wire fee_charged,
// max_fee, and source_account_sequence are JSON STRINGS (the SDK decodes them
// through ,string tags — protocols/horizon/main.go); the round-trip below
// rejects a fixture that gets that wrong.
type txRec struct {
	Hash       string
	Failed     bool
	Ledger     int32
	CreatedAt  string // default 2026-08-30T14:02:11Z
	Source     string
	FeeCharged int64
	FeeAccount string // "" = the source paid its own fee
	MemoType   string // "" = "none"
	Memo       string
	OpCount    int32
}

func (x txRec) JSON(t *testing.T) string {
	t.Helper()
	created := x.CreatedAt
	if created == "" {
		created = "2026-08-30T14:02:11Z"
	}
	feeAccount := x.FeeAccount
	if feeAccount == "" {
		feeAccount = x.Source
	}
	memoType := x.MemoType
	if memoType == "" {
		memoType = "none"
	}
	m := map[string]any{
		"id":                      x.Hash,
		"paging_token":            "12884905984",
		"successful":              !x.Failed,
		"hash":                    x.Hash,
		"ledger":                  x.Ledger,
		"created_at":              created,
		"source_account":          x.Source,
		"source_account_sequence": "3239174710021",
		"fee_account":             feeAccount,
		"fee_charged":             strconv.FormatInt(x.FeeCharged, 10),
		"max_fee":                 "100000",
		"operation_count":         x.OpCount,
		"envelope_xdr":            "AAAA",
		"result_xdr":              "AAAA",
		"fee_meta_xdr":            "AAAA",
		"memo_type":               memoType,
		"signatures":              []string{"c2ln"},
	}
	if x.Memo != "" {
		m["memo"] = x.Memo
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal transaction record: %v", err)
	}
	var tx hProtocol.Transaction
	if err := json.Unmarshal(raw, &tx); err != nil {
		t.Fatalf("transaction record does not round-trip through the SDK type (dishonest fixture): %v\n%s", err, raw)
	}
	if tx.Hash != x.Hash || tx.FeeCharged != x.FeeCharged || tx.Successful == x.Failed {
		t.Fatalf("transaction record round-trip mismatch:\n%s", raw)
	}
	return string(raw)
}

// serveTx registers the detail and operations routes for one transaction.
func serveTx(t *testing.T, f *horizonFake, rec txRec, ops ...opRec) {
	t.Helper()
	body := rec.JSON(t)
	f.handle("/transactions/"+rec.Hash, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, body)
	})
	var records []string
	for _, op := range ops {
		records = append(records, op.JSON(t))
	}
	f.servePages("/transactions/"+rec.Hash+"/operations", map[string]string{
		"": pageJSON("", records),
	})
}

// TestTxRendersHappyPath is the headline behaviour: hash, status, ledger and
// close time, source, the fee as a 7-decimal XLM amount, the memo, and the
// operation list in absolute (both-parties) form.
func TestTxRendersHappyPath(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	serveTx(t, f, txRec{
		Hash: txTestHash, Ledger: 1234, Source: mine, FeeCharged: 100,
		MemoType: "id", Memo: "3141592653", OpCount: 1,
	}, payment("op-1", mine, other, "25.0000000", txTestHash))

	s, _ := runTxOK(t, txArgs(f.URL(), txTestHash)...)
	for _, want := range []string{
		"Transaction: " + txTestHash,
		"Status:      succeeded",
		"Ledger:      1234, closed 2026-08-30 14:02:11 UTC",
		"Source:      " + mine,
		"Fee:         0.0000100 XLM",
		"Memo:        id 3141592653",
		"Operations (1):",
		"1. payment: " + mine + " -> " + other + "  25.0000000 XLM",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}

	// The operations fetch must include failed operations (what a failed
	// transaction tried to do is what a lookup is for) at the full page size.
	q := f.requests("/transactions/" + txTestHash + "/operations")[0]
	if got := q.Get("include_failed"); got != "true" {
		t.Errorf("operations include_failed = %q, want true", got)
	}
	if got := q.Get("limit"); got != "200" {
		t.Errorf("operations limit = %q, want 200", got)
	}
}

// TestTxMarksFailed: a failed transaction must say so — and say that the fee
// was charged anyway, since that is the one part of it that did move funds.
func TestTxMarksFailed(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	op := payment("op-1", mine, other, "9.0000000", txTestHash)
	op.Failed = true
	op.Tx.Successful = false
	serveTx(t, f, txRec{
		Hash: txTestHash, Failed: true, Ledger: 77, Source: mine, FeeCharged: 100, OpCount: 1,
	}, op)

	s, _ := runTxOK(t, txArgs(f.URL(), txTestHash)...)
	if !strings.Contains(s, "Status:      FAILED — no funds moved; the fee was still charged") {
		t.Errorf("failed transaction not marked:\n%s", s)
	}
	if !strings.Contains(s, "Fee:         0.0000100 XLM") {
		t.Errorf("fee line missing on a failed transaction:\n%s", s)
	}
}

// TestTxFeeBump: when fee_account differs from the source the fee was paid by
// someone else — the human form names the payer and the JSON carries
// fee_payer.
func TestTxFeeBump(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	serveTx(t, f, txRec{
		Hash: txTestHash, Ledger: 12, Source: mine, FeeCharged: 200, FeeAccount: other, OpCount: 1,
	}, payment("op-1", mine, other, "1.0000000", txTestHash))

	s, _ := runTxOK(t, txArgs(f.URL(), txTestHash)...)
	if !strings.Contains(s, "Fee:         0.0000200 XLM (paid by "+other+")") {
		t.Errorf("fee-bump payer not named:\n%s", s)
	}

	j, _ := runTxOK(t, txArgs(f.URL(), txTestHash, "--json")...)
	var obj map[string]any
	if err := json.Unmarshal([]byte(j), &obj); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", err, j)
	}
	if got := obj["fee_payer"]; got != other {
		t.Errorf("fee_payer = %v, want %q", got, other)
	}
}

// TestTxHashInputNormalized: a pasted hash arrives in whatever case and
// whitespace the explorer or receipt used; the request must go out in the
// canonical lowercase form.
func TestTxHashInputNormalized(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	serveTx(t, f, txRec{
		Hash: txTestHash, Ledger: 5, Source: mine, FeeCharged: 100, OpCount: 1,
	}, payment("op-1", mine, other, "2.0000000", txTestHash))

	s, _ := runTxOK(t, txArgs(f.URL(), "  "+strings.ToUpper(txTestHash)+"  ")...)
	if !strings.Contains(s, "Transaction: "+txTestHash) {
		t.Errorf("output does not show the canonical hash:\n%s", s)
	}
	if got := len(f.requests("/transactions/" + txTestHash)); got != 1 {
		t.Errorf("lowercase detail route hit %d times, want 1", got)
	}
}

// TestTxRejectsMalformedHash: a malformed paste fails before any network
// call, with stdout left empty.
func TestTxRejectsMalformedHash(t *testing.T) {
	srv := httptest.NewServer(failIfHit(t)) // any request = bug: validation must fail first
	t.Cleanup(srv.Close)

	cases := []struct {
		name string
		hash string
	}{
		{"short", "abc123"},
		{"non-hex", strings.Repeat("zx", 32)},
		{"63 digits", strings.Repeat("a", 63)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			app, out, errb := newTestApp("", nil)
			if code := app.run(txArgs(srv.URL, tt.hash)); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if !strings.Contains(errb.String(), "invalid transaction hash") {
				t.Errorf("stderr %q missing the hash validation error", errb.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q not empty on a validation error", out.String())
			}
		})
	}
}

// TestTxNotFound maps Horizon's 404 to a message naming the network — the
// usual cause is looking a mainnet hash up on testnet or vice versa.
func TestTxNotFound(t *testing.T) {
	f := newHorizonFake(t)
	f.serveError("/transactions/"+txTestHash, 404)

	app, out, errb := newTestApp("", nil)
	if code := app.run(txArgs(f.URL(), txTestHash)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "not found on testnet") {
		t.Errorf("stderr %q missing the not-found message", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q not empty on failure", out.String())
	}
}

// TestTxJSON pins the --json object: one parseable object, string amounts,
// per-shape operation fields, and the memo in canonical encoding — Horizon
// delivers a hash memo base64-encoded, the output carries the 64 hex digits
// the user typed at --memo.
func TestTxJSON(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	memoRaw := bytes.Repeat([]byte{0xab}, 32)
	pay := payment("op-1", mine, other, "25.0000000", txTestHash)
	created := opRec{
		ID: "op-2", Type: "create_account", TypeI: typeCreateAccount,
		Source: other, TxHash: txTestHash,
		Funder: other, Account: mine, StartingBalance: "100.0000000",
	}
	serveTx(t, f, txRec{
		Hash: txTestHash, Ledger: 999, Source: mine, FeeCharged: 100,
		MemoType: "hash", Memo: base64.StdEncoding.EncodeToString(memoRaw), OpCount: 2,
	}, pay, created)

	s, _ := runTxOK(t, txArgs(f.URL(), txTestHash, "--json")...)
	var obj struct {
		Hash       string           `json:"hash"`
		Successful bool             `json:"successful"`
		Ledger     int32            `json:"ledger"`
		CreatedAt  string           `json:"created_at"`
		Source     string           `json:"source"`
		FeeCharged string           `json:"fee_charged"`
		Memo       *jsonMemo        `json:"memo"`
		Operations []map[string]any `json:"operations"`
	}
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		t.Fatalf("--json output is not a single valid object: %v\n%s", err, s)
	}
	if obj.Hash != txTestHash || !obj.Successful || obj.Ledger != 999 || obj.Source != mine {
		t.Errorf("object header wrong: %+v", obj)
	}
	if obj.CreatedAt != "2026-08-30T14:02:11Z" {
		t.Errorf("created_at = %q, want RFC3339 UTC", obj.CreatedAt)
	}
	if obj.FeeCharged != "0.0000100" {
		t.Errorf("fee_charged = %q, want the 7-decimal string", obj.FeeCharged)
	}
	if obj.Memo == nil || obj.Memo.Type != "hash" || obj.Memo.Value != strings.Repeat("ab", 32) {
		t.Errorf("memo = %+v, want hash memo as 64 hex digits", obj.Memo)
	}
	// A raw re-parse catches fee_payer sneaking in for a non-fee-bump tx.
	var raw map[string]any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["fee_payer"]; ok {
		t.Errorf("fee_payer present though the source paid its own fee:\n%s", s)
	}

	if len(obj.Operations) != 2 {
		t.Fatalf("got %d operations, want 2:\n%s", len(obj.Operations), s)
	}
	p := obj.Operations[0]
	if p["type"] != "payment" || p["from"] != mine || p["to"] != other || p["amount"] != "25.0000000" {
		t.Errorf("payment op shape wrong: %v", p)
	}
	if asset, ok := p["asset"].(map[string]any); !ok || asset["type"] != "native" {
		t.Errorf("payment op asset = %v, want {type: native}", p["asset"])
	}
	c := obj.Operations[1]
	if c["type"] != "create_account" || c["from"] != other || c["to"] != mine || c["starting_balance"] != "100.0000000" {
		t.Errorf("create_account op shape wrong: %v", c)
	}
	// create_account funds in XLM by definition; no amount/asset fields.
	if _, ok := c["amount"]; ok {
		t.Errorf("create_account op carries an amount field: %v", c)
	}
	if _, ok := c["asset"]; ok {
		t.Errorf("create_account op carries an asset field: %v", c)
	}
}

// TestTxRendersMultiOpNumbered: a multi-operation transaction lists every
// operation, numbered 1..N in ledger order.
func TestTxRendersMultiOpNumbered(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	pay := payment("op-1", mine, other, "5.0000000", txTestHash)
	created := opRec{
		ID: "op-2", Type: "create_account", TypeI: typeCreateAccount,
		Source: other, TxHash: txTestHash,
		Funder: other, Account: mine, StartingBalance: "100.0000000",
	}
	merged := opRec{
		ID: "op-3", Type: "account_merge", TypeI: typeAccountMerge,
		Source: mine, TxHash: txTestHash,
		Account: mine, Into: other,
	}
	serveTx(t, f, txRec{
		Hash: txTestHash, Ledger: 42, Source: mine, FeeCharged: 300, OpCount: 3,
	}, pay, created, merged)

	s, _ := runTxOK(t, txArgs(f.URL(), txTestHash)...)
	for _, want := range []string{
		"Operations (3):",
		"  1. payment: " + mine + " -> " + other + "  5.0000000 XLM",
		"  2. create account: " + other + " funded " + mine + " with 100.0000000 XLM",
		"  3. account merge: " + mine + " merged into " + other + " (entire balance)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}
