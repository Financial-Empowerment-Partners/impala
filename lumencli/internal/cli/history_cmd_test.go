package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lumencli/internal/wallet"
)

// historyServer serves the payments endpoint for one account from a map of
// cursor → page body ("" is the first page, with no cursor). The map is read
// at request time, so pages whose next-links must embed the server's own URL
// can be added after the server is started. Queries received are appended to
// *gotQueries when it is non-nil.
func historyServer(t *testing.T, address string, pages map[string]string, gotQueries *[]url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/accounts/"+address+"/payments" {
			http.NotFound(w, r)
			return
		}
		if gotQueries != nil {
			*gotQueries = append(*gotQueries, r.URL.Query())
		}
		body, ok := pages[r.URL.Query().Get("cursor")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/hal+json")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// pageJSON assembles one Horizon HAL page. next is the absolute URL of the
// next page, or "" when this is the last one.
func pageJSON(next string, records []string) string {
	links := "{}"
	if next != "" {
		links = fmt.Sprintf(`{"next": {"href": %q}}`, next)
	}
	return fmt.Sprintf(`{"_links": %s, "_embedded": {"records": [%s]}}`, links, strings.Join(records, ","))
}

// paymentRecord builds a native-XLM payment operation with a joined
// transaction carrying the given memo (memoType "none" for no memo).
func paymentRecord(id, from, to, amount, hash, memoType, memo string, successful bool) string {
	return fmt.Sprintf(`{
		"id": %q, "paging_token": %q, "transaction_successful": %v,
		"source_account": %q, "type": "payment", "type_i": 1,
		"created_at": "2026-08-30T14:02:11Z", "transaction_hash": %q,
		"asset_type": "native", "from": %q, "to": %q, "amount": %q,
		"transaction": {"hash": %q, "successful": %v, "memo_type": %q, "memo": %q}}`,
		id, id, successful, from, hash, from, to, amount, hash, successful, memoType, memo)
}

func createAccountRecord(id, funder, account, startingBalance, hash string) string {
	return fmt.Sprintf(`{
		"id": %q, "paging_token": %q, "transaction_successful": true,
		"source_account": %q, "type": "create_account", "type_i": 0,
		"created_at": "2026-08-29T09:00:00Z", "transaction_hash": %q,
		"starting_balance": %q, "funder": %q, "account": %q,
		"transaction": {"hash": %q, "successful": true, "memo_type": "none"}}`,
		id, id, funder, hash, startingBalance, funder, account, hash)
}

func accountMergeRecord(id, account, into, hash string) string {
	return fmt.Sprintf(`{
		"id": %q, "paging_token": %q, "transaction_successful": true,
		"source_account": %q, "type": "account_merge", "type_i": 8,
		"created_at": "2026-08-28T08:00:00Z", "transaction_hash": %q,
		"account": %q, "into": %q,
		"transaction": {"hash": %q, "successful": true, "memo_type": "none"}}`,
		id, id, account, hash, account, into, hash)
}

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

func historyArgs(srv *httptest.Server, address string, extra ...string) []string {
	return append([]string{
		"history", "--network", "testnet", "--horizon-url", srv.URL, address,
	}, extra...)
}

// TestHistoryRendersEntries is the headline behaviour: each fund-moving
// operation renders with its direction relative to the queried account, the
// amount, the full counterparty address, the memo, and the full transaction
// hash.
func TestHistoryRendersEntries(t *testing.T) {
	mine, other := historyAddrs(t)
	pages := map[string]string{}
	srv := historyServer(t, mine, pages, nil)
	pages[""] = pageJSON("", []string{
		paymentRecord("1", other, mine, "25.0000000", "hash-received", "text", "thanks", true),
		paymentRecord("2", mine, other, "10.0000000", "hash-sent", "id", "3141592653", true),
		createAccountRecord("3", other, mine, "100.0000000", "hash-created"),
		accountMergeRecord("4", mine, other, "hash-merged"),
	})

	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine)); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	s := out.String()
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
	pages := map[string]string{}
	srv := historyServer(t, mine, pages, nil)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, paymentRecord(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i), "none", "", true))
	}
	next := srv.URL + "/accounts/" + mine + "/payments?cursor=c2"
	pages[""] = pageJSON(next, first)
	pages["c2"] = pageJSON("", []string{
		paymentRecord("oldest", mine, other, "2.0000000", "hash-oldest", "none", "", true),
	})

	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine)); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	s := out.String()
	if !strings.Contains(s, "201 entries shown.") {
		t.Errorf("output did not include the second page:\n%s", lastLines(s, 5))
	}
	if !strings.Contains(s, "hash-oldest") {
		t.Errorf("output missing the entry from the second page")
	}
}

// TestHistoryLimitStops confirms --limit ends the walk early — without
// fetching further pages — and says so on stderr.
func TestHistoryLimitStops(t *testing.T) {
	mine, other := historyAddrs(t)
	pages := map[string]string{}
	var queries []url.Values
	srv := historyServer(t, mine, pages, &queries)

	var first []string
	for i := 0; i < 200; i++ {
		first = append(first, paymentRecord(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i), "none", "", true))
	}
	pages[""] = pageJSON(srv.URL+"/accounts/"+mine+"/payments?cursor=c2", first)

	app, out, errb := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine, "--limit", "2")); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "2 entries shown.") {
		t.Errorf("output did not stop at the limit:\n%s", lastLines(out.String(), 5))
	}
	if !strings.Contains(errb.String(), "Stopped at --limit 2") {
		t.Errorf("stderr %q missing the truncation notice", errb.String())
	}
	if len(queries) != 1 {
		t.Errorf("made %d page requests, want 1 (limit must stop the paging)", len(queries))
	}
}

// TestHistoryQueryShape pins the Horizon query: full pages, newest first,
// transactions joined for memos; failed transactions only on request.
func TestHistoryQueryShape(t *testing.T) {
	mine, other := historyAddrs(t)
	pages := map[string]string{}
	var queries []url.Values
	srv := historyServer(t, mine, pages, &queries)
	pages[""] = pageJSON("", []string{
		paymentRecord("1", other, mine, "1.0000000", "h", "none", "", true),
	})

	app, _, _ := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine)); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	q := queries[0]
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

	app2, _, _ := newTestApp("", nil)
	if code := app2.run(historyArgs(srv, mine, "--failed")); code != 0 {
		t.Fatalf("--failed run: exit code = %d, want 0", code)
	}
	if got := queries[1].Get("include_failed"); got != "true" {
		t.Errorf("include_failed = %q with --failed, want true", got)
	}
}

// TestHistoryMarksFailed: an operation from a failed transaction must not
// read like money that moved.
func TestHistoryMarksFailed(t *testing.T) {
	mine, other := historyAddrs(t)
	pages := map[string]string{}
	srv := historyServer(t, mine, pages, nil)
	pages[""] = pageJSON("", []string{
		paymentRecord("1", mine, other, "10.0000000", "hash-failed", "none", "", false),
	})

	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine, "--failed")); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "[FAILED — no funds moved]") {
		t.Errorf("failed transaction not marked:\n%s", out.String())
	}
}

func TestHistoryEmptyAccount(t *testing.T) {
	mine, _ := historyAddrs(t)
	pages := map[string]string{"": pageJSON("", nil)}
	srv := historyServer(t, mine, pages, nil)

	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine)); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "(no transactions)") {
		t.Errorf("output %q missing the empty notice", out.String())
	}
}

// TestHistoryAccountNotFound maps Horizon's 404 to the same friendly
// explanation the balance command gives.
func TestHistoryAccountNotFound(t *testing.T) {
	mine, _ := historyAddrs(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"type": "https://stellar.org/horizon-errors/not_found", "title": "Resource Missing", "status": 404}`)
	}))
	t.Cleanup(srv.Close)

	app, out, errb := newTestApp("", nil)
	if code := app.run(historyArgs(srv, mine)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "does not exist") {
		t.Errorf("stderr %q missing the friendly not-found message", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q not empty on failure (header printed too early?)", out.String())
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

// lastLines returns up to n trailing non-empty lines of s, for terse failure
// messages when the full output would be hundreds of entries.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
