package cli

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"lumencli/internal/wallet"
)

// historyAddrs generates the account under test plus a counterparty.
func historyAddrs(t *testing.T) (mine, other string) {
	t.Helper()
	kp1, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	kp2, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return kp1.Address(), kp2.Address()
}

func historyArgs(url, address string, extra ...string) []string {
	return append([]string{
		"history", "--network", "testnet", "--horizon-url", url, address,
	}, extra...)
}

// runHistoryOK runs a history command against the fake and requires exit 0.
func runHistoryOK(t *testing.T, url string, args ...string) (stdout, stderr string) {
	t.Helper()
	app, out, errb := newTestApp("", nil)
	if code := app.run(args); code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, errb.String())
	}
	_ = url
	return out.String(), errb.String()
}

// TestHistoryRendersEntries is the headline behaviour: each fund-moving
// operation renders with its direction relative to the queried account, the
// amount, the full counterparty address, the memo, and the full transaction
// hash.
func TestHistoryRendersEntries(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	received := payment("1", other, mine, "25.0000000", "hash-received")
	received.Tx.MemoType, received.Tx.Memo = "text", "thanks"
	sent := payment("2", mine, other, "10.0000000", "hash-sent")
	sent.Tx.MemoType, sent.Tx.Memo = "id", "3141592653"
	created := opRec{
		ID: "3", Type: "create_account", TypeI: typeCreateAccount,
		Source: other, TxHash: "hash-created",
		Funder: other, Account: mine, StartingBalance: "100.0000000",
		CreatedAt: "2026-08-29T09:00:00Z",
		Tx:        &txJoin{Hash: "hash-created", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: other},
	}
	merged := opRec{
		ID: "4", Type: "account_merge", TypeI: typeAccountMerge,
		Source: mine, TxHash: "hash-merged",
		Account: mine, Into: other,
		CreatedAt: "2026-08-28T08:00:00Z",
		Tx:        &txJoin{Hash: "hash-merged", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: mine},
	}
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{received.JSON(t), sent.JSON(t), created.JSON(t), merged.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine)...)
	for _, want := range []string{
		"Account: " + mine,
		"History (newest first):",
		"received  25.0000000 XLM  (payment)",
		"  From: " + other,
		`  Memo: text "thanks"`,
		"  Tx:   hash-received",
		"sent  10.0000000 XLM  (payment)",
		"  To:   " + other,
		"  Memo: id 3141592653",
		"received  100.0000000 XLM  (account created)",
		"sent  entire balance  (account merge)",
		"2026-08-30 14:02:11 UTC",
		"4 entries shown.",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

// TestHistoryFollowsPaging locks in the "full" in full history: a first page
// at Horizon's page limit must be followed to the next page rather than
// silently truncated.
func TestHistoryFollowsPaging(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	next := f.URL() + paymentsPath(mine) + "?cursor=c2"
	f.servePages(paymentsPath(mine), map[string]string{
		"":   pageJSON(next, first),
		"c2": pageJSON("", []string{payment("oldest", mine, other, "2.0000000", "hash-oldest").JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine)...)
	if !strings.Contains(s, "201 entries shown.") {
		t.Errorf("output did not include the second page:\n%s", lastLines(s, 5))
	}
	if !strings.Contains(s, "hash-oldest") {
		t.Errorf("output missing the entry from the second page")
	}
}

// TestHistoryExactPageMultiple pins the end-of-history heuristic when the
// total is an exact multiple of the page size: the walk must fetch the empty
// final page and stop cleanly, not error or loop.
func TestHistoryExactPageMultiple(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	next := f.URL() + paymentsPath(mine) + "?cursor=c2"
	f.servePages(paymentsPath(mine), map[string]string{
		"":   pageJSON(next, first),
		"c2": pageJSON("", nil),
	})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine)...)
	if !strings.Contains(s, "200 entries shown.") {
		t.Errorf("exact-multiple history mis-listed:\n%s", lastLines(s, 5))
	}
	if got := len(f.requests(paymentsPath(mine))); got != 2 {
		t.Errorf("made %d page requests, want 2 (full page then empty page)", got)
	}
}

// TestHistoryLimitStops confirms --limit ends the walk early — without
// fetching further pages — and says so on stderr.
func TestHistoryLimitStops(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON(f.URL()+paymentsPath(mine)+"?cursor=c2", first),
	})

	app, out, errb := newTestApp("", nil)
	if code := app.run(historyArgs(f.URL(), mine, "--limit", "2")); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "2 entries shown.") {
		t.Errorf("output did not stop at the limit:\n%s", lastLines(out.String(), 5))
	}
	if !strings.Contains(errb.String(), "Stopped at --limit 2") {
		t.Errorf("stderr %q missing the truncation notice", errb.String())
	}
	if got := len(f.requests(paymentsPath(mine))); got != 1 {
		t.Errorf("made %d page requests, want 1 (limit must stop the paging)", got)
	}
}

// TestHistoryLimitAtPageBoundary: --limit equal to the page size stops after
// the next page's first record is seen (one extra request, no third).
func TestHistoryLimitAtPageBoundary(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	next := f.URL() + paymentsPath(mine) + "?cursor=c2"
	f.servePages(paymentsPath(mine), map[string]string{
		"":   pageJSON(next, first),
		"c2": pageJSON("", []string{payment("x", other, mine, "1.0000000", "hash-x").JSON(t)}),
	})

	s, errs := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--limit", "200")...)
	if !strings.Contains(s, "200 entries shown.") {
		t.Errorf("limit at page boundary mis-listed:\n%s", lastLines(s, 5))
	}
	if !strings.Contains(errs, "Stopped at --limit 200") {
		t.Errorf("stderr %q missing the truncation notice", errs)
	}
	if got := len(f.requests(paymentsPath(mine))); got != 2 {
		t.Errorf("made %d page requests, want 2", got)
	}
}

// TestHistoryQueryShape pins the Horizon query: full pages, newest first,
// transactions joined for memos; failed transactions only on request.
func TestHistoryQueryShape(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{payment("1", other, mine, "1.0000000", "h").JSON(t)}),
	})

	runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine)...)
	q := f.requests(paymentsPath(mine))[0]
	if got := q.Get("limit"); got != "200" {
		t.Errorf("limit = %q, want 200", got)
	}
	if got := q.Get("order"); got != "desc" {
		t.Errorf("order = %q, want desc", got)
	}
	if got := q.Get("join"); got != "transactions" {
		t.Errorf("join = %q, want transactions", got)
	}
	if got := q.Get("include_failed"); got == "true" {
		t.Errorf("include_failed sent without --failed")
	}

	runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--failed")...)
	if got := f.requests(paymentsPath(mine))[1].Get("include_failed"); got != "true" {
		t.Errorf("include_failed = %q with --failed, want true", got)
	}
}

// TestHistoryAllOpsQueriesOperationsEndpoint: --all-ops walks /operations and
// renders non-payment kinds generically instead of dropping them.
func TestHistoryAllOpsQueriesOperationsEndpoint(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	data := opRec{
		ID: "1", Type: "manage_data", TypeI: typeManageData,
		Source: mine, TxHash: "hash-data",
		Tx: &txJoin{Hash: "hash-data", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: mine},
	}
	pay := payment("2", other, mine, "5.0000000", "hash-pay")
	f.servePages(operationsPath(mine), map[string]string{
		"": pageJSON("", []string{data.JSON(t), pay.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--all-ops")...)
	if len(f.requests(paymentsPath(mine))) != 0 {
		t.Errorf("--all-ops still hit the payments endpoint")
	}
	for _, want := range []string{"involved  (manage_data)", "Source: " + mine, "received  5.0000000 XLM"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

// TestHistoryAllOpsJSONShape pins the documented --json schema for generic
// operations: direction "other", source_account present, and none of the
// payment-shaped fields — alongside an unchanged payment entry.
func TestHistoryAllOpsJSONShape(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	data := opRec{
		ID: "1", Type: "manage_data", TypeI: typeManageData,
		Source: mine, TxHash: "hash-data",
		Tx: &txJoin{Hash: "hash-data", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: mine},
	}
	pay := payment("2", other, mine, "5.0000000", "hash-pay")
	f.servePages(operationsPath(mine), map[string]string{
		"": pageJSON("", []string{data.JSON(t), pay.JSON(t)}),
	})

	out, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--all-ops", "--json")...)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d JSON lines, want 2", len(lines))
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &generic); err != nil {
		t.Fatalf("generic line does not parse: %v", err)
	}
	if generic["direction"] != "other" || generic["type"] != "manage_data" || generic["source_account"] != mine {
		t.Errorf("generic entry shape wrong: %v", generic)
	}
	for _, k := range []string{"amount", "asset", "counterparty", "source_amount"} {
		if _, ok := generic[k]; ok {
			t.Errorf("generic entry must not carry %q: %v", k, generic)
		}
	}
	var pv map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &pv); err != nil {
		t.Fatalf("payment line does not parse: %v", err)
	}
	if pv["direction"] != "received" || pv["amount"] != "5.0000000" || pv["counterparty"] != other {
		t.Errorf("payment entry changed under --all-ops: %v", pv)
	}
}

// TestHistoryAssetNativeKeepsMerges: an account merge moves exclusively the
// native lumen, so --asset XLM must keep merge entries — silently dropping a
// fund movement is a wrong answer about money.
func TestHistoryAssetNativeKeepsMerges(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	merge := opRec{
		ID: "1", Type: "account_merge", TypeI: typeAccountMerge,
		Source: other, TxHash: "hash-merge",
		Account: other, Into: mine,
		Tx: &txJoin{Hash: "hash-merge", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: other},
	}
	usdc := payment("2", other, mine, "5.0000000", "hash-usdc")
	usdc.AssetType, usdc.AssetCode, usdc.AssetIssuer = "credit_alphanum4", "USDC", other
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{merge.JSON(t), usdc.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--asset", "XLM")...)
	if !strings.Contains(s, "received  entire balance  (account merge)") {
		t.Errorf("--asset XLM dropped the account merge:\n%s", s)
	}
	if strings.Contains(s, "USDC") {
		t.Errorf("--asset XLM kept a USDC payment:\n%s", s)
	}
	// The issued-asset filter keeps merges out: they move no USDC.
	s2, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--asset", "USDC:"+other)...)
	if strings.Contains(s2, "account merge") {
		t.Errorf("an issued-asset filter must not match a merge:\n%s", s2)
	}
}

// TestHistoryMarksFailed: an operation from a failed transaction must not
// read like money that moved.
func TestHistoryMarksFailed(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	p := payment("1", mine, other, "10.0000000", "hash-failed")
	p.Failed = true
	p.Tx.Successful = false
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", []string{p.JSON(t)})})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine, "--failed")...)
	if !strings.Contains(s, "[FAILED — no funds moved]") {
		t.Errorf("failed transaction not marked:\n%s", s)
	}
}

func TestHistoryEmptyAccount(t *testing.T) {
	mine, _ := historyAddrs(t)
	f := newHorizonFake(t)
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", nil)})

	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), mine)...)
	if !strings.Contains(s, "(no transactions)") {
		t.Errorf("output %q missing the empty notice", s)
	}
}

// TestHistoryAccountNotFound maps Horizon's 404 to the same friendly
// explanation the balance command gives, with stdout left empty.
func TestHistoryAccountNotFound(t *testing.T) {
	mine, _ := historyAddrs(t)
	f := newHorizonFake(t)
	f.serveError(paymentsPath(mine), 404)

	app, out, errb := newTestApp("", nil)
	if code := app.run(historyArgs(f.URL(), mine)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "does not exist") {
		t.Errorf("stderr %q missing the friendly not-found message", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q not empty on failure (header printed too early?)", out.String())
	}
}

// TestHistoryMidWalkErrorFailsLoudly: a Horizon error on a later page must
// exit 1 — a truncated JSONL stream that exits 0 would read as complete.
func TestHistoryMidWalkErrorFailsLoudly(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	// The next-page URL points at a route that serves a 500.
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON(f.URL()+"/broken", first),
	})
	f.serveError("/broken", 500)

	app, _, errb := newTestApp("", nil)
	if code := app.run(historyArgs(f.URL(), mine, "--json")); code != 1 {
		t.Fatalf("exit code = %d, want 1 on a mid-walk error", code)
	}
	if !strings.Contains(errb.String(), "fetch history") {
		t.Errorf("stderr %q missing the fetch error", errb.String())
	}
}

func TestHistoryRequiresOneAddress(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"history"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "usage") {
		t.Errorf("stderr %q missing usage hint", errb.String())
	}
}

func TestHistoryRejectsBadAddress(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"history", "--network", "testnet", "not-an-address"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "invalid account address") {
		t.Errorf("stderr %q missing address validation error", errb.String())
	}
}

func TestHistoryRejectsMuxedAddress(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"history", "--network", "testnet",
		"MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "G... address") {
		t.Errorf("stderr %q missing the muxed-address explanation", errb.String())
	}
}

func TestHistoryRejectsNegativeLimit(t *testing.T) {
	mine, _ := historyAddrs(t)
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"history", "--network", "testnet", "--limit", "-1", mine}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "--limit") {
		t.Errorf("stderr %q missing the limit complaint", errb.String())
	}
}

// TestHistoryFlagMatrix pins every rejected flag combination: each must be a
// clear error before any network call, never an accidental behavior.
func TestHistoryFlagMatrix(t *testing.T) {
	mine, other := historyAddrs(t)
	srv := httptest.NewServer(failIfHit(t)) // any request = bug: flags must fail first
	t.Cleanup(srv.Close)

	cases := []struct {
		name   string
		args   []string
		errHas string
	}{
		{"json+csv", []string{"--json", "--csv"}, "mutually exclusive"},
		{"sent+received", []string{"--sent", "--received"}, "mutually exclusive"},
		{"summary+csv", []string{"--summary", "--csv"}, "no CSV form"},
		{"summary+follow", []string{"--summary", "--follow"}, "mutually exclusive"},
		{"summary+all-ops", []string{"--summary", "--all-ops"}, "fund-moving history only"},
		{"all-ops+sent", []string{"--all-ops", "--sent"}, "no direction"},
		{"all-ops+counterparty", []string{"--all-ops", "--counterparty", other}, "no counterparty"},
		{"all-ops+asset", []string{"--all-ops", "--asset", "XLM"}, "move no asset"},
		{"all-ops+follow", []string{"--all-ops", "--follow"}, "payments only"},
		{"follow+until", []string{"--follow", "--until", "2026-01-01"}, "drop one"},
		{"follow+csv", []string{"--follow", "--csv"}, "finished range"},
		{"bad asset", []string{"--asset", "USDC"}, "issuer is required"},
		{"bad since", []string{"--since", "yesterday"}, "invalid --since"},
		{"until before since", []string{"--since", "2026-02-01", "--until", "2026-01-01"}, "--until is before --since"},
		{"bad counterparty", []string{"--counterparty", "nope"}, "invalid account address"},
		{"bad muxed counterparty", []string{"--counterparty", "MNOPE"}, "invalid muxed address"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			app, out, errb := newTestApp("", nil)
			args := append(historyArgs(srv.URL, mine), tt.args...)
			if code := app.run(args); code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if !strings.Contains(errb.String(), tt.errHas) {
				t.Errorf("stderr %q missing %q", errb.String(), tt.errHas)
			}
			if out.Len() != 0 {
				t.Errorf("stdout %q not empty on a flag error", out.String())
			}
		})
	}
}

// lastLines returns up to n trailing non-empty lines of s, for terse failure
// messages when the full output would be hundreds of entries.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
