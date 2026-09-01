package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The recorded fixture is a real testnet Horizon response
// (/accounts/{id}/payments?join=transactions&limit=200&order=desc), captured
// verbatim by scripts/testnet-smoke.sh --record. Running it through the full
// command keeps the hand-built opRec fixtures honest: if real Horizon JSON
// ever disagrees with what the fakes serve — a field rename, a type change,
// muxed ids as strings — this test breaks while the fakes would happily keep
// passing.
//
// The assertions derive from the fixture itself (account, entry count,
// memos), so a --record refresh with a new throwaway account needs no test
// edit.
func TestHistoryRendersRecordedHorizonPage(t *testing.T) {
	raw, err := os.ReadFile("testdata/live_payments_page.json")
	if err != nil {
		t.Fatalf("read recorded fixture: %v", err)
	}
	var page struct {
		Links struct {
			Self struct{ Href string } `json:"self"`
		} `json:"_links"`
		Embedded struct {
			Records []struct {
				Type        string `json:"type"`
				Hash        string `json:"transaction_hash"`
				Transaction struct {
					MemoType string `json:"memo_type"`
					Memo     string `json:"memo"`
				} `json:"transaction"`
			} `json:"records"`
		} `json:"_embedded"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("recorded fixture is not a Horizon page: %v", err)
	}
	m := regexp.MustCompile(`/accounts/(G[A-Z2-7]{55})/payments`).FindStringSubmatch(page.Links.Self.Href)
	if m == nil {
		t.Fatalf("cannot derive the account from the fixture's self link %q", page.Links.Self.Href)
	}
	account := m[1]
	if len(page.Embedded.Records) == 0 {
		t.Fatal("recorded fixture has no records; re-record with scripts/testnet-smoke.sh --record")
	}

	f := newHorizonFake(t)
	f.servePages(paymentsPath(account), map[string]string{"": string(raw)})

	// Human listing: every recorded operation renders — its transaction hash
	// appears — and any id memo the fixture carries shows canonically.
	s, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), account)...)
	for _, r := range page.Embedded.Records {
		if !strings.Contains(s, r.Hash) {
			t.Errorf("entry with tx %s missing from the listing:\n%s", r.Hash, s)
		}
		if r.Transaction.MemoType == "id" && !strings.Contains(s, "Memo: id "+r.Transaction.Memo) {
			t.Errorf("id memo %s not rendered canonically", r.Transaction.Memo)
		}
	}

	// The JSON pipeline over the same real page: one parseable line per
	// record, each with the required fields and the joined ledger intact.
	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(f.URL(), account, "--json")); code != 0 {
		t.Fatalf("--json over recorded page: exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(page.Embedded.Records) {
		t.Fatalf("got %d JSON lines, want %d", len(lines), len(page.Embedded.Records))
	}
	for i, line := range lines {
		var e struct {
			ID        string `json:"id"`
			Direction string `json:"direction"`
			TxHash    string `json:"tx_hash"`
			Ledger    int32  `json:"ledger"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("JSON line %d does not parse: %v", i, err)
		}
		if e.ID == "" || e.Direction == "" || e.TxHash == "" {
			t.Errorf("line %d missing required fields: %s", i, line)
		}
		if e.Ledger == 0 {
			t.Errorf("line %d: joined transaction's ledger did not survive the real wire shape", i)
		}
	}
}
