package cli

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/amount"
)

// summaryArgs is historyArgs plus --summary.
func summaryArgs(url, address string, extra ...string) []string {
	return append(historyArgs(url, address, "--summary"), extra...)
}

// TestHistorySummaryFeeDedupe is the bug class the fee design exists to
// prevent: a transaction with three payment operations repeats its joined fee
// on every record, and naive per-record accumulation would triple the fee.
// The fee must count once per transaction hash.
func TestHistorySummaryFeeDedupe(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	var recs []string
	for i := 1; i <= 3; i++ {
		p := payment(fmt.Sprint(i), mine, other, "10.0000000", "hash-multi")
		p.Tx.FeeCharged = 300
		recs = append(recs, p.JSON(t))
	}
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", recs)})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	if want := "Fees paid on the 1 listed transactions where this account was the fee payer: 0.0000300 XLM"; !strings.Contains(s, want) {
		t.Errorf("fee line not deduplicated by tx hash; want %q in:\n%s", want, s)
	}
	// All three operations still count as entries and as sent amounts — only
	// the fee is per-transaction.
	for _, want := range []string{
		"Summary of 3 entries from 2026-08-30 14:02:11 UTC to 2026-08-30 14:02:11 UTC",
		"  native: received 0.0000000, sent 30.0000000, net -30.0000000",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

// TestHistorySummaryFeeAttribution: only transactions where the queried
// account is the fee payer count. A received payment whose fee the sender paid
// contributes nothing; a fee-bump (fee account = queried account, operation
// sourced by someone else) does count.
func TestHistorySummaryFeeAttribution(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	plain := payment("1", other, mine, "25.0000000", "hash-plain") // fee payer: the sender
	bump := payment("2", other, mine, "5.0000000", "hash-bump")
	bump.Tx.FeeAccount = mine // fee-bump: this account paid for someone else's operation
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{plain.JSON(t), bump.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	if want := "Fees paid on the 1 listed transactions where this account was the fee payer: 0.0000100 XLM"; !strings.Contains(s, want) {
		t.Errorf("fee attribution wrong; want %q in:\n%s", want, s)
	}
}

// TestHistorySummaryFailed: with --failed a failed sent payment's amount stays
// out of the totals, but its fee — charged regardless — counts, and the failed
// line appears. Without --failed the walk must not ask Horizon for failed
// records at all.
func TestHistorySummaryFailed(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	ok := payment("1", mine, other, "5.0000000", "hash-ok")
	bad := payment("2", mine, other, "10.0000000", "hash-bad")
	bad.Failed = true
	bad.Tx.Successful = false
	// Horizon omits failed records unless include_failed=true; the fake
	// mirrors that so the test proves which set the CLI asked for.
	successOnly := pageJSON("", []string{ok.JSON(t)})
	withFailed := pageJSON("", []string{ok.JSON(t), bad.JSON(t)})
	f.handle(paymentsPath(mine), func(w http.ResponseWriter, r *http.Request) {
		body := successOnly
		if r.URL.Query().Get("include_failed") == "true" {
			body = withFailed
		}
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprint(w, body)
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	if strings.Contains(s, "Failed operations") {
		t.Errorf("failed line without --failed:\n%s", s)
	}
	if want := "Fees paid on the 1 listed transactions where this account was the fee payer: 0.0000100 XLM"; !strings.Contains(s, want) {
		t.Errorf("output missing %q:\n%s", want, s)
	}

	s, _ = runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine, "--failed")...)
	for _, want := range []string{
		// The failed 10 XLM moved nothing: sent stays 5.
		"  native: received 0.0000000, sent 5.0000000, net -5.0000000",
		// Its fee was charged: both transactions count.
		"Fees paid on the 2 listed transactions where this account was the fee payer: 0.0000200 XLM",
		"Failed operations: 1 (no funds moved; fees were still charged where this account paid them)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}

	reqs := f.requests(paymentsPath(mine))
	if len(reqs) != 2 {
		t.Fatalf("made %d requests, want 2", len(reqs))
	}
	if got := reqs[0].Get("include_failed"); got == "true" {
		t.Errorf("include_failed sent without --failed")
	}
	if got := reqs[1].Get("include_failed"); got != "true" {
		t.Errorf("include_failed = %q with --failed, want true", got)
	}
}

// TestHistorySummarySelfConversion: a self path payment is a conversion — the
// source leg books as sent under the source asset and the destination leg as
// received under the destination asset. Booking only the sent leg would
// corrupt every net figure.
func TestHistorySummarySelfConversion(t *testing.T) {
	mine, issuer := historyAddrs(t)
	f := newHorizonFake(t)

	conv := opRec{
		ID: "1", Type: "path_payment_strict_send", TypeI: typePathStrictSend,
		Source: mine, TxHash: "hash-conv",
		From: mine, To: mine,
		Amount: "25.0000000", AssetType: "credit_alphanum4", AssetCode: "USDC", AssetIssuer: issuer,
		SourceAmount: "100.0000000", DestinationMin: "24.0000000", SrcAssetType: "native",
		Tx: &txJoin{Hash: "hash-conv", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: issuer, Ledger: 10},
	}
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", []string{conv.JSON(t)})})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	native := "  native: received 0.0000000, sent 100.0000000, net -100.0000000"
	usdc := "  USDC:" + issuer + ": received 25.0000000, sent 0.0000000, net +25.0000000"
	for _, want := range []string{native, usdc} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Index(s, native) > strings.Index(s, usdc) {
		t.Errorf("native must sort before issued assets:\n%s", s)
	}
}

// TestHistorySummarySelfPaymentNetsToZero: a plain self payment books both
// legs in the same bucket — sent 10 and received 10, net exactly zero (and
// rendered without a sign).
func TestHistorySummarySelfPaymentNetsToZero(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	p := payment("1", mine, mine, "10.0000000", "hash-self")
	p.Tx.FeeAccount = other
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", []string{p.JSON(t)})})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	if want := "  native: received 10.0000000, sent 10.0000000, net 0.0000000"; !strings.Contains(s, want) {
		t.Errorf("self payment must book both legs; want %q in:\n%s", want, s)
	}
}

// TestHistorySummaryCounterfeitSeparation: the same code from two issuers is
// two assets. Buckets key on the full CODE:ISSUER and must never merge — a
// combined line would present a counterfeit as the real asset.
func TestHistorySummaryCounterfeitSeparation(t *testing.T) {
	mine, other := historyAddrs(t)
	issuerA, issuerB := historyAddrs(t)
	f := newHorizonFake(t)

	real := payment("1", other, mine, "25.0000000", "hash-real")
	real.AssetType, real.AssetCode, real.AssetIssuer = "credit_alphanum4", "USDC", issuerA
	fake := payment("2", other, mine, "10.0000000", "hash-fake")
	fake.AssetType, fake.AssetCode, fake.AssetIssuer = "credit_alphanum4", "USDC", issuerB
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{real.JSON(t), fake.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	for _, want := range []string{
		"  USDC:" + issuerA + ": received 25.0000000, sent 0.0000000, net +25.0000000",
		"  USDC:" + issuerB + ": received 10.0000000, sent 0.0000000, net +10.0000000",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "35.0000000") {
		t.Errorf("USDC totals merged across issuers:\n%s", s)
	}
}

// TestHistorySummaryMerges: merged amounts are not in the operation record, so
// merges count on their own line — never in the asset totals — and the line
// says the totals are lower bounds.
func TestHistorySummaryMerges(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	out := opRec{
		ID: "1", Type: "account_merge", TypeI: typeAccountMerge,
		Source: mine, TxHash: "hash-out",
		Account: mine, Into: other,
		Tx: &txJoin{Hash: "hash-out", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: other},
	}
	in := opRec{
		ID: "2", Type: "account_merge", TypeI: typeAccountMerge,
		Source: other, TxHash: "hash-in",
		Account: other, Into: mine,
		Tx: &txJoin{Hash: "hash-in", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: other},
	}
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{out.JSON(t), in.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	want := "Merges: 1 sent, 1 received — merged amounts are not in the operation record, so the totals above are lower bounds"
	if !strings.Contains(s, want) {
		t.Errorf("output missing %q:\n%s", want, s)
	}
	if strings.Contains(s, "native:") {
		t.Errorf("merge booked an amount into the asset totals:\n%s", s)
	}
}

// TestHistorySummaryCoverageAndLimit: the coverage line carries the entry
// count, the oldest/newest bounds, and the truncation marker; --limit N stops
// both the aggregation and the paging.
func TestHistorySummaryCoverageAndLimit(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	newest := payment("1", other, mine, "1.0000000", "hash-1")
	newest.CreatedAt = "2026-08-30T12:00:00Z"
	older := payment("2", other, mine, "1.0000000", "hash-2")
	older.CreatedAt = "2026-08-30T11:00:00Z"
	first := []string{newest.JSON(t), older.JSON(t)}
	for i := 3; i <= 200; i++ {
		first = append(first, payment(fmt.Sprint(i), other, mine, "1.0000000", fmt.Sprintf("hash-%d", i)).JSON(t))
	}
	// The second page holds a poison record: if the walk pages past the limit
	// and aggregates it, the totals below break too.
	f.servePages(paymentsPath(mine), map[string]string{
		"":   pageJSON(f.URL()+paymentsPath(mine)+"?cursor=c2", first),
		"c2": pageJSON("", []string{payment("999", other, mine, "999.0000000", "hash-999").JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine, "--limit", "2")...)
	for _, want := range []string{
		"Summary of 2 entries from 2026-08-30 11:00:00 UTC to 2026-08-30 12:00:00 UTC (truncated at --limit 2; older entries exist)",
		"  native: received 2.0000000, sent 0.0000000, net +2.0000000",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
	if got := len(f.requests(paymentsPath(mine))); got != 1 {
		t.Errorf("made %d page requests, want 1 (limit must stop the paging)", got)
	}
}

// TestHistorySummaryJSON pins the --summary --json object: one JSON object,
// assets ordered native first then code/issuer, correct deduplicated fees,
// and the truncated flag under --limit. Field names are asserted against
// independent literals — the schema is an append-only contract.
func TestHistorySummaryJSON(t *testing.T) {
	mine, other := historyAddrs(t)
	issuerP, issuerQ := historyAddrs(t)
	if issuerP > issuerQ {
		issuerP, issuerQ = issuerQ, issuerP
	}
	issuerY, _ := historyAddrs(t)
	f := newHorizonFake(t)

	usdcQ := payment("1", other, mine, "25.0000000", "hash-q")
	usdcQ.AssetType, usdcQ.AssetCode, usdcQ.AssetIssuer = "credit_alphanum4", "USDC", issuerQ
	sent := payment("2", mine, other, "1.0000000", "hash-sent") // fee payer: this account
	aaa := payment("3", other, mine, "7.0000000", "hash-aaa")
	aaa.AssetType, aaa.AssetCode, aaa.AssetIssuer = "credit_alphanum4", "AAA", issuerY
	usdcP := payment("4", other, mine, "3.0000000", "hash-p")
	usdcP.AssetType, usdcP.AssetCode, usdcP.AssetIssuer = "credit_alphanum4", "USDC", issuerP
	native := payment("5", other, mine, "5.0000000", "hash-native")
	poison := payment("6", other, mine, "999.0000000", "hash-poison") // beyond --limit 5
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{usdcQ.JSON(t), sent.JSON(t), aaa.JSON(t), usdcP.JSON(t), native.JSON(t), poison.JSON(t)}),
	})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine, "--json", "--limit", "5")...)
	if strings.Contains(strings.TrimSpace(s), "\n") {
		t.Fatalf("--summary --json must be a single object:\n%s", s)
	}
	var got struct {
		Account   string `json:"account"`
		Entries   int    `json:"entries"`
		Failed    int    `json:"failed"`
		Truncated bool   `json:"truncated"`
		Oldest    string `json:"oldest"`
		Newest    string `json:"newest"`
		Assets    []struct {
			Asset struct {
				Type   string `json:"type"`
				Code   string `json:"code"`
				Issuer string `json:"issuer"`
			} `json:"asset"`
			Received string `json:"received"`
			Sent     string `json:"sent"`
			Net      string `json:"net"`
		} `json:"assets"`
		Fees struct {
			ListedTotal  string `json:"listed_total"`
			Transactions int    `json:"transactions"`
		} `json:"fees"`
	}
	if err := json.Unmarshal([]byte(s), &got); err != nil {
		t.Fatalf("summary JSON does not parse: %v\n%s", err, s)
	}

	if got.Account != mine || got.Entries != 5 || got.Failed != 0 {
		t.Errorf("account/entries/failed = %q/%d/%d, want %q/5/0", got.Account, got.Entries, got.Failed, mine)
	}
	if !got.Truncated {
		t.Errorf("truncated = false under --limit 5 with more entries")
	}
	if got.Oldest != "2026-08-30T14:02:11Z" || got.Newest != "2026-08-30T14:02:11Z" {
		t.Errorf("oldest/newest = %q/%q, want RFC3339 fixture times", got.Oldest, got.Newest)
	}
	if got.Fees.ListedTotal != "0.0000100" || got.Fees.Transactions != 1 {
		t.Errorf("fees = %q over %d transactions, want 0.0000100 over 1", got.Fees.ListedTotal, got.Fees.Transactions)
	}
	if len(got.Assets) != 4 {
		t.Fatalf("assets length = %d, want 4:\n%s", len(got.Assets), s)
	}
	if a := got.Assets[0]; a.Asset.Type != "native" || a.Received != "5.0000000" || a.Sent != "1.0000000" || a.Net != "4.0000000" {
		t.Errorf("assets[0] = %+v, want native received 5, sent 1, net 4", a)
	}
	if a := got.Assets[1]; a.Asset.Code != "AAA" || a.Asset.Issuer != issuerY {
		t.Errorf("assets[1] = %+v, want AAA:%s (codes sort after native)", a, issuerY)
	}
	if a := got.Assets[2]; a.Asset.Code != "USDC" || a.Asset.Issuer != issuerP {
		t.Errorf("assets[2] = %+v, want USDC:%s (lower issuer first)", a, issuerP)
	}
	if a := got.Assets[3]; a.Asset.Code != "USDC" || a.Asset.Issuer != issuerQ {
		t.Errorf("assets[3] = %+v, want USDC:%s", a, issuerQ)
	}
}

// TestStroopsToDecimal pins stroopsToDecimal against the SDK's own formatter
// for int64-range values, the sign for negative values with a zero integer
// part (the classic formatting bug), and a beyond-int64 sum.
func TestStroopsToDecimal(t *testing.T) {
	// Differential: for every int64-range value the SDK formatter is the
	// ground truth.
	for _, v := range []int64{
		0, 1, 9999999, 10000000, 12345678901, 9000000000000000000,
		-1, -12345678901,
	} {
		if got, want := stroopsToDecimal(big.NewInt(v)), amount.StringFromInt64(v); got != want {
			t.Errorf("stroopsToDecimal(%d) = %q, SDK says %q", v, got, want)
		}
	}
	// Sign correctness when the integer part is zero: -1 stroop is a negative
	// number even though its quotient is 0.
	exact := []struct {
		v    int64
		want string
	}{
		{-1, "-0.0000001"},
		{-12345678901, "-1234.5678901"},
	}
	for _, tt := range exact {
		if got := stroopsToDecimal(big.NewInt(tt.v)); got != tt.want {
			t.Errorf("stroopsToDecimal(%d) = %q, want %q", tt.v, got, tt.want)
		}
	}
	// Beyond int64 — the reason the summary sums in big.Int: 2^63 stroops.
	huge := new(big.Int).Lsh(big.NewInt(1), 63)
	if got, want := stroopsToDecimal(huge), "922337203685.4775808"; got != want {
		t.Errorf("stroopsToDecimal(2^63) = %q, want %q", got, want)
	}
}

// TestHistorySummaryMalformedAmount: an amount Horizon should never send must
// fail the command loudly — exit 1 with no summary on stdout — never feed a
// silent zero into the totals.
func TestHistorySummaryMalformedAmount(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)
	f.servePages(paymentsPath(mine), map[string]string{
		"": pageJSON("", []string{payment("1", other, mine, "abc", "hash-bad").JSON(t)}),
	})

	app, out, errb := newTestApp("", nil)
	if code := app.run(summaryArgs(f.URL(), mine)); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "malformed amount") {
		t.Errorf("stderr %q missing the malformed-amount error", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout %q not empty on a malformed amount", out.String())
	}
}

// TestHistorySummaryReceivedTotalProperty: for any set of received payments,
// the summary's received total is exactly the big.Int sum of their stroop
// values — no rounding, no float drift, at any count.
func TestHistorySummaryReceivedTotalProperty(t *testing.T) {
	mine, other := historyAddrs(t)
	f := newHorizonFake(t)

	rng := rand.New(rand.NewSource(42))
	sum := new(big.Int)
	var recs []string
	for i := 0; i < 60; i++ {
		v := rng.Int63n(9_000_000_000_000_000)
		sum.Add(sum, big.NewInt(v))
		recs = append(recs, payment(fmt.Sprint(i+1), other, mine, amount.StringFromInt64(v), fmt.Sprintf("hash-%d", i+1)).JSON(t))
	}
	f.servePages(paymentsPath(mine), map[string]string{"": pageJSON("", recs)})

	s, _ := runHistoryOK(t, f.URL(), summaryArgs(f.URL(), mine)...)
	want := fmt.Sprintf("  native: received %s, sent 0.0000000, net +%s",
		stroopsToDecimal(sum), stroopsToDecimal(sum))
	if !strings.Contains(s, want) {
		t.Errorf("received total is not the exact stroop sum; want %q in:\n%s", want, s)
	}
}
