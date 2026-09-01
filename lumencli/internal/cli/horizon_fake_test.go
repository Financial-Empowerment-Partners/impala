package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
)

// update regenerates golden files: go test ./internal/cli -update
var update = flag.Bool("update", false, "rewrite golden files")

// horizonFake is the one fake Horizon shared by the history/tx/follow tests:
// route registration, per-route query capture, cursor-keyed paging, and SSE
// streaming. Unknown cursors 404 (turning a paging bug into a hard error) and
// unknown paths 404.
type horizonFake struct {
	t   *testing.T
	srv *httptest.Server
	mux *http.ServeMux

	mu      sync.Mutex
	queries map[string][]url.Values
}

func newHorizonFake(t *testing.T) *horizonFake {
	t.Helper()
	f := &horizonFake{t: t, mux: http.NewServeMux(), queries: make(map[string][]url.Values)}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries[r.URL.Path] = append(f.queries[r.URL.Path], r.URL.Query())
		f.mu.Unlock()
		f.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *horizonFake) URL() string { return f.srv.URL }

// requests returns the captured queries for path, oldest first.
func (f *horizonFake) requests(path string) []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.queries[path]...)
}

func (f *horizonFake) handle(path string, h http.HandlerFunc) { f.mux.HandleFunc(path, h) }

// servePages serves a paged collection at path from cursor -> page body (""
// is the first page). The map is consulted at request time, so pages whose
// next links embed the server's own URL can be added after startup.
func (f *horizonFake) servePages(path string, pages map[string]string) {
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Query().Get("cursor")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, body)
	})
}

// serveError serves an RFC 7807 problem document with the given status. A
// 404 carries Horizon's canonical not_found problem type, which is what the
// SDK's IsNotFoundError matches on.
func (f *horizonFake) serveError(path string, status int) {
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		typ := "about:blank"
		if status == http.StatusNotFound {
			typ = "https://stellar.org/horizon-errors/not_found"
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"type":%q,"title":"fake error","status":%d}`, typ, status)
	})
}

// sseConn is one SSE connection handed to a stream script.
type sseConn struct {
	N      int // 1-based connection count for this route
	Cursor string
	w      http.ResponseWriter
	fl     http.Flusher
	r      *http.Request
}

// event sends one SSE event carrying a serialized operation record. The id
// line matters: the SDK resumes from it after its own clean-EOF reconnects.
// The retry line precedes it, matching real Horizon's field order — the
// vendored SSE decoder has an upstream bug where a retry line OVERWRITES the
// event id, so putting retry last would corrupt every id to "10".
func (c *sseConn) event(id, data string) {
	fmt.Fprintf(c.w, "retry: 10\nid: %s\ndata: %s\n\n", id, strings.ReplaceAll(data, "\n", ""))
	c.fl.Flush()
}

// keepalive sends the comment line Horizon uses as a heartbeat.
func (c *sseConn) keepalive() {
	fmt.Fprint(c.w, ": keepalive\n\n")
	c.fl.Flush()
}

// wait blocks until the client goes away (context cancelled / connection
// torn down), emulating a quiet stream with no events.
func (c *sseConn) wait() { <-c.r.Context().Done() }

// serveSSE registers an SSE route. script runs once per connection; returning
// ends that connection (a clean EOF from the client's point of view, which
// the SDK answers by reconnecting with the last event's cursor — scripts
// must expect repeat connections).
func (f *horizonFake) serveSSE(path string, script func(c *sseConn)) {
	var conns int
	var mu sync.Mutex
	f.handle(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			http.Error(w, "not a stream request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		conns++
		n := conns
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fl, ok := w.(http.Flusher)
		if !ok {
			f.t.Fatal("response writer is not a flusher")
		}
		fl.Flush()
		script(&sseConn{N: n, Cursor: r.URL.Query().Get("cursor"), w: w, fl: fl, r: r})
	})
}

// ---- record builders ------------------------------------------------------

// txJoin is the joined transaction of an operation record.
type txJoin struct {
	Hash       string
	Successful bool
	Ledger     int32
	MemoType   string // "" = no memo_type field at all
	Memo       string
	MemoBytes  string
	FeeCharged int64
	FeeAccount string
}

// opRec builds one Horizon operation record. Zero fields are omitted from
// the JSON; TypeI selects the shape (1 payment, 0 create_account, 8 merge,
// 2 strict-receive path payment, 13 strict-send path payment, or any other
// known type for generic records).
type opRec struct {
	ID        string
	Type      string
	TypeI     int32
	Failed    bool // transaction_successful: !Failed
	Source    string
	CreatedAt string // default 2026-08-30T14:02:11Z
	TxHash    string
	Tx        *txJoin

	From, To, Amount             string
	FromMuxed, ToMuxed           string
	AssetType                    string // default "native" for payment shapes
	AssetCode, AssetIssuer       string
	SourceAmount, SourceMax      string
	DestinationMin               string
	SrcAssetType                 string
	SrcAssetCode, SrcAssetIssuer string

	Funder, Account, StartingBalance string
	Into                             string
}

// requiredWireKeys lists, per operation type, the fields real Horizon always
// serializes (the SDK structs carry them without omitempty, so they are on
// the wire even when zero — a failed path payment's execution-determined leg
// arrives as "0.0000000", never absent). A fixture missing one describes JSON
// that cannot occur, and the suite would then certify code paths real data
// never takes.
var requiredWireKeys = map[int32][]string{
	typePayment:           {"from", "to", "amount", "asset_type"},
	typePathStrictReceive: {"from", "to", "amount", "asset_type", "source_amount", "source_max", "source_asset_type"},
	typePathStrictSend:    {"from", "to", "amount", "asset_type", "source_amount", "destination_min", "source_asset_type"},
	typeCreateAccount:     {"funder", "account", "starting_balance"},
	typeAccountMerge:      {"account", "into"},
}

// JSON renders the record and passes it through the honesty gate before it
// may be served: (1) the SDK's own unmarshaller must accept it (rejecting an
// unknown type_i or a mistyped value); (2) every key must survive a re-marshal
// of the typed result, catching misspelled field names the SDK's plain
// json.Unmarshal would silently ignore; (3) the type's always-on-the-wire
// fields must be present, so fixtures cannot describe field-omission shapes
// real Horizon never produces.
func (o opRec) JSON(t *testing.T) string {
	t.Helper()
	m := map[string]any{
		"id":                     o.ID,
		"paging_token":           o.ID,
		"transaction_successful": !o.Failed,
		"source_account":         o.Source,
		"type":                   o.Type,
		"type_i":                 o.TypeI,
		"created_at":             o.CreatedAt,
		"transaction_hash":       o.TxHash,
	}
	if m["created_at"] == "" {
		m["created_at"] = "2026-08-30T14:02:11Z"
	}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("from", o.From)
	set("to", o.To)
	set("amount", o.Amount)
	set("from_muxed", o.FromMuxed)
	set("to_muxed", o.ToMuxed)
	set("asset_type", o.AssetType)
	set("asset_code", o.AssetCode)
	set("asset_issuer", o.AssetIssuer)
	set("source_amount", o.SourceAmount)
	set("source_max", o.SourceMax)
	set("destination_min", o.DestinationMin)
	set("source_asset_type", o.SrcAssetType)
	set("source_asset_code", o.SrcAssetCode)
	set("source_asset_issuer", o.SrcAssetIssuer)
	set("funder", o.Funder)
	set("account", o.Account)
	set("starting_balance", o.StartingBalance)
	set("into", o.Into)
	if o.Tx != nil {
		tx := map[string]any{
			"hash":        o.Tx.Hash,
			"successful":  o.Tx.Successful,
			"ledger":      o.Tx.Ledger,
			"fee_charged": fmt.Sprint(o.Tx.FeeCharged),
			"fee_account": o.Tx.FeeAccount,
		}
		if o.Tx.MemoType != "" {
			tx["memo_type"] = o.Tx.MemoType
		}
		if o.Tx.Memo != "" {
			tx["memo"] = o.Tx.Memo
		}
		if o.Tx.MemoBytes != "" {
			tx["memo_bytes"] = o.Tx.MemoBytes
		}
		m["transaction"] = tx
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	op, err := operations.UnmarshalOperation(o.TypeI, raw)
	if err != nil {
		t.Fatalf("record %s does not round-trip through the SDK unmarshaller (dishonest fixture): %v\n%s", o.ID, err, raw)
	}
	// Re-marshal the typed result and require every fixture key to reappear:
	// the SDK's plain json.Unmarshal ignores unknown keys, so this is what
	// actually catches a misspelled field name.
	remarshaled, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("re-marshal record %s: %v", o.ID, err)
	}
	var echoed map[string]json.RawMessage
	if err := json.Unmarshal(remarshaled, &echoed); err != nil {
		t.Fatalf("decode re-marshaled record %s: %v", o.ID, err)
	}
	for k := range m {
		if _, ok := echoed[k]; !ok {
			t.Fatalf("record %s: field %q is not part of the SDK's %s shape (misspelled fixture field?)", o.ID, k, o.Type)
		}
	}
	for _, k := range requiredWireKeys[o.TypeI] {
		if _, ok := m[k]; !ok {
			t.Fatalf("record %s: field %q missing, but real Horizon always sends it for %s (even when zero — pass the placeholder explicitly)", o.ID, k, o.Type)
		}
	}
	return string(raw)
}

// Type tags for the payment-shaped operations, matching the SDK's TypeNames.
const (
	typeCreateAccount     = 0
	typePayment           = 1
	typePathStrictReceive = 2
	typeAccountMerge      = 8
	typeManageData        = 10
	typePathStrictSend    = 13
)

// payment builds a successful native-XLM payment with a joined transaction.
func payment(id, from, to, amt, hash string) opRec {
	return opRec{
		ID: id, Type: "payment", TypeI: typePayment,
		Source: from, TxHash: hash, From: from, To: to, Amount: amt, AssetType: "native",
		Tx: &txJoin{Hash: hash, Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: from, Ledger: 1234},
	}
}

// pageJSON assembles one Horizon HAL page; next is the absolute URL of the
// next page, "" for the last.
func pageJSON(next string, records []string) string {
	links := "{}"
	if next != "" {
		links = fmt.Sprintf(`{"next": {"href": %q}}`, next)
	}
	return fmt.Sprintf(`{"_links": %s, "_embedded": {"records": [%s]}}`, links, strings.Join(records, ","))
}

// failIfHit is a handler for servers that must never receive a request —
// used to prove validation happens before any network call.
func failIfHit(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s: validation must fail before any network call", r.URL)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
}

// paymentsPath is the payments route for an account on the fake.
func paymentsPath(address string) string { return "/accounts/" + address + "/payments" }

// operationsPath is the all-ops route for an account on the fake.
func operationsPath(address string) string { return "/accounts/" + address + "/operations" }
