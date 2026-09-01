package cli

import (
	"fmt"
	"io"
	"math/big"
	"sort"
	"time"

	"github.com/stellar/go-stellar-sdk/amount"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
)

// summaryAccum aggregates a filtered history walk into per-asset totals.
//
// All arithmetic is exact: amounts parse to int64 stroops via the SDK's own
// parser and are summed in big.Int — no floating point anywhere near money.
// Failed operations moved no funds, so their amounts never enter the totals
// (they are counted, and their fees are real: see addFee). Self transfers
// contribute both legs — the conversion pattern (a path payment to self)
// books what left under the source asset and what arrived under the
// destination asset, netting to zero only when the assets match.
type summaryAccum struct {
	entries   int
	failed    int
	truncated bool

	oldest, newest time.Time

	buckets map[assetKey]*assetTotals

	// Fees are per-transaction while the walk is per-operation: a transaction
	// with three payments appears three times with the same joined fee, so
	// accumulation dedupes by transaction hash. Only transactions where the
	// queried account is the fee payer count, and failed transactions count
	// too whenever their records are visible — their fees were charged
	// regardless.
	fees    *big.Int
	feeTxs  int
	seenFee map[string]bool

	mergesSent     int
	mergesReceived int
}

type assetKey struct {
	Type, Code, Issuer string
}

type assetTotals struct {
	received, sent *big.Int
}

func newSummaryAccum() *summaryAccum {
	return &summaryAccum{
		buckets: make(map[assetKey]*assetTotals),
		fees:    new(big.Int),
		seenFee: make(map[string]bool),
	}
}

// add folds one filtered entry into the totals.
func (s *summaryAccum) add(address string, e historyEntry) error {
	s.entries++
	if s.newest.IsZero() || e.CreatedAt.After(s.newest) {
		s.newest = e.CreatedAt
	}
	if s.oldest.IsZero() || e.CreatedAt.Before(s.oldest) {
		s.oldest = e.CreatedAt
	}
	if err := s.addFee(address, e); err != nil {
		return err
	}

	if !e.Successful {
		s.failed++
		return nil
	}
	if e.EntireBalance {
		switch e.Direction {
		case dirSent:
			s.mergesSent++
		case dirReceived:
			s.mergesReceived++
		}
		return nil
	}

	// The sent leg: for path payments the source amount under the source
	// asset; otherwise the single amount. The received leg: the destination
	// amount. Self entries book both, everyone else exactly one.
	if e.Direction == dirSent || e.Direction == dirSelf {
		if e.SourceAmount != "" {
			if err := s.bucket(e.SourceAsset).addTo(sentSide, e.SourceAmount); err != nil {
				return err
			}
		} else if e.Amount != "" {
			if err := s.bucket(e.Asset).addTo(sentSide, e.Amount); err != nil {
				return err
			}
		}
	}
	if e.Direction == dirReceived || e.Direction == dirSelf {
		if e.Amount != "" {
			if err := s.bucket(e.Asset).addTo(receivedSide, e.Amount); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *summaryAccum) addFee(address string, e historyEntry) error {
	if e.FeePayer != address || e.TxHash == "" || s.seenFee[e.TxHash] {
		return nil
	}
	s.seenFee[e.TxHash] = true
	s.fees.Add(s.fees, big.NewInt(e.FeeCharged))
	s.feeTxs++
	return nil
}

const (
	receivedSide = "received"
	sentSide     = "sent"
)

func (s *summaryAccum) bucket(a base.Asset) *assetTotals {
	k := assetKey{Type: a.Type, Code: a.Code, Issuer: a.Issuer}
	b := s.buckets[k]
	if b == nil {
		b = &assetTotals{received: new(big.Int), sent: new(big.Int)}
		s.buckets[k] = b
	}
	return b
}

func (t *assetTotals) addTo(side, amt string) error {
	v, err := amount.ParseInt64(amt)
	if err != nil {
		return fmt.Errorf("malformed amount %q from Horizon: %v", amt, err)
	}
	if side == receivedSide {
		t.received.Add(t.received, big.NewInt(v))
	} else {
		t.sent.Add(t.sent, big.NewInt(v))
	}
	return nil
}

// sortedKeys orders the buckets deterministically: the native lumen first,
// then issued assets by code, then issuer.
func (s *summaryAccum) sortedKeys() []assetKey {
	keys := make([]assetKey, 0, len(s.buckets))
	for k := range s.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if (keys[i].Type == "native") != (keys[j].Type == "native") {
			return keys[i].Type == "native"
		}
		if keys[i].Code != keys[j].Code {
			return keys[i].Code < keys[j].Code
		}
		return keys[i].Issuer < keys[j].Issuer
	})
	return keys
}

// stroopsToDecimal renders a stroop count as a signed 7-decimal string. It
// exists because big.Int sums can hold what amount.StringFromInt64 cannot;
// for int64-range values the two agree exactly (pinned by a differential
// test).
func stroopsToDecimal(v *big.Int) string {
	sign := ""
	abs := new(big.Int).Abs(v)
	if v.Sign() < 0 {
		sign = "-"
	}
	quo, rem := new(big.Int).QuoRem(abs, big.NewInt(10_000_000), new(big.Int))
	return fmt.Sprintf("%s%s.%07d", sign, quo.String(), rem.Int64())
}

// signedDecimal is stroopsToDecimal with an explicit + on positive values,
// for net figures.
func signedDecimal(v *big.Int) string {
	if v.Sign() > 0 {
		return "+" + stroopsToDecimal(v)
	}
	return stroopsToDecimal(v)
}

// timeRange renders the coverage line's bounds.
func timeRange(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

// renderSummaryText writes the human summary. The coverage line is part of
// the output on stdout — not a stderr notice — because a redirected summary
// must never pass for a full-history total when it was filtered or truncated.
func (s *summaryAccum) renderSummaryText(w io.Writer, address string, limit int) {
	fmt.Fprintf(w, "Account: %s\n", address)
	if s.entries == 0 {
		fmt.Fprintln(w, "Summary: no entries")
		return
	}
	coverage := fmt.Sprintf("Summary of %d entries from %s to %s", s.entries, timeRange(s.oldest), timeRange(s.newest))
	if s.truncated {
		coverage += fmt.Sprintf(" (truncated at --limit %d; older entries exist)", limit)
	}
	fmt.Fprintln(w, coverage)

	for _, k := range s.sortedKeys() {
		b := s.buckets[k]
		net := new(big.Int).Sub(b.received, b.sent)
		fmt.Fprintf(w, "  %s: received %s, sent %s, net %s\n",
			assetSpecString(base.Asset{Type: k.Type, Code: k.Code, Issuer: k.Issuer}),
			stroopsToDecimal(b.received), stroopsToDecimal(b.sent), signedDecimal(net))
	}

	if s.feeTxs > 0 {
		fmt.Fprintf(w, "Fees paid on the %d listed transactions where this account was the fee payer: %s XLM\n",
			s.feeTxs, stroopsToDecimal(s.fees))
	}
	if s.mergesSent > 0 || s.mergesReceived > 0 {
		fmt.Fprintf(w, "Merges: %d sent, %d received — merged amounts are not in the operation record, so the totals above are lower bounds\n",
			s.mergesSent, s.mergesReceived)
	}
	if s.failed > 0 {
		fmt.Fprintf(w, "Failed operations: %d (no funds moved; fees were still charged where this account paid them)\n", s.failed)
	}
}

// jsonSummary is the --summary --json object. Like the listing schema, its
// fields are append-only.
type jsonSummary struct {
	Account        string            `json:"account"`
	Entries        int               `json:"entries"`
	Failed         int               `json:"failed"`
	Truncated      bool              `json:"truncated"`
	Oldest         string            `json:"oldest,omitempty"`
	Newest         string            `json:"newest,omitempty"`
	Assets         []jsonAssetTotals `json:"assets"`
	Fees           jsonFees          `json:"fees"`
	MergesSent     int               `json:"merges_sent"`
	MergesReceived int               `json:"merges_received"`
}

type jsonAssetTotals struct {
	Asset    jsonAsset `json:"asset"`
	Received string    `json:"received"`
	Sent     string    `json:"sent"`
	Net      string    `json:"net"`
}

// jsonFees covers only the listed transactions where the queried account was
// the fee payer, deduplicated by transaction — the name says "listed" because
// transactions outside the payments view (fee-only, or filtered out) are not
// included.
type jsonFees struct {
	ListedTotal  string `json:"listed_total"`
	Transactions int    `json:"transactions"`
}

func (s *summaryAccum) toJSON(address string) jsonSummary {
	out := jsonSummary{
		Account:        address,
		Entries:        s.entries,
		Failed:         s.failed,
		Truncated:      s.truncated,
		Assets:         []jsonAssetTotals{},
		Fees:           jsonFees{ListedTotal: stroopsToDecimal(s.fees), Transactions: s.feeTxs},
		MergesSent:     s.mergesSent,
		MergesReceived: s.mergesReceived,
	}
	if s.entries > 0 {
		out.Oldest = s.oldest.UTC().Format(time.RFC3339)
		out.Newest = s.newest.UTC().Format(time.RFC3339)
	}
	for _, k := range s.sortedKeys() {
		b := s.buckets[k]
		out.Assets = append(out.Assets, jsonAssetTotals{
			Asset:    jsonAsset{Type: k.Type, Code: k.Code, Issuer: k.Issuer},
			Received: stroopsToDecimal(b.received),
			Sent:     stroopsToDecimal(b.sent),
			Net:      stroopsToDecimal(new(big.Int).Sub(b.received, b.sent)),
		})
	}
	return out
}
