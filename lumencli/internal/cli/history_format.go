package cli

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
)

// The machine-readable history formats. Their schemas are a compatibility
// promise: scripts and accounting exports depend on them across releases, so
// fields are append-only — never renamed, retyped, or reordered — and the
// golden-file tests pin the exact bytes.

// jsonAsset is an asset in JSON output: {"type":"native"} for the lumen,
// {"type":...,"code":...,"issuer":...} for issued assets.
type jsonAsset struct {
	Type   string `json:"type"`
	Code   string `json:"code,omitempty"`
	Issuer string `json:"issuer,omitempty"`
}

// jsonMemo mirrors entryMemo: the value is in canonical display encoding
// (text verbatim, id decimal, hash/return as 64 hex digits).
type jsonMemo struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// jsonEntry is one --json history line. Amount fields are 7-decimal strings,
// present only when the exact value is in the operation record (see
// historyEntry); "amounts are strings, never JSON numbers" is part of the
// contract, since float parsing corrupts money values.
//
// There is deliberately no per-entry fee field: fees are per-transaction, and
// a multi-operation transaction repeats on every one of its entries — any
// obvious `jq 'map(.fee) | add'` would double-count. Fees live in the tx
// command and the deduplicated --summary.
type jsonEntry struct {
	ID             string     `json:"id"`
	PagingToken    string     `json:"paging_token"`
	CreatedAt      string     `json:"created_at"`
	Type           string     `json:"type"`
	Direction      string     `json:"direction"`
	Successful     bool       `json:"successful"`
	TxHash         string     `json:"tx_hash"`
	Ledger         int32      `json:"ledger,omitempty"`
	Amount         string     `json:"amount,omitempty"`
	Asset          *jsonAsset `json:"asset,omitempty"`
	SourceAmount   string     `json:"source_amount,omitempty"`
	SourceAsset    *jsonAsset `json:"source_asset,omitempty"`
	SourceMax      string     `json:"source_max,omitempty"`
	DestinationMin string     `json:"destination_min,omitempty"`
	EntireBalance  bool       `json:"entire_balance,omitempty"`
	Counterparty   string     `json:"counterparty,omitempty"`
	ToMuxed        string     `json:"to_muxed,omitempty"`
	FromMuxed      string     `json:"from_muxed,omitempty"`
	SourceAccount  string     `json:"source_account,omitempty"`
	Memo           *jsonMemo  `json:"memo,omitempty"`
	MemoBytes      string     `json:"memo_bytes,omitempty"`
}

func toJSONAsset(a base.Asset) *jsonAsset {
	if a.Type == "" {
		return nil
	}
	return &jsonAsset{Type: a.Type, Code: a.Code, Issuer: a.Issuer}
}

func toJSONEntry(e historyEntry) jsonEntry {
	j := jsonEntry{
		ID:             e.ID,
		PagingToken:    e.PagingToken,
		CreatedAt:      e.CreatedAt.UTC().Format(time.RFC3339),
		Type:           e.Type,
		Direction:      e.Direction,
		Successful:     e.Successful,
		TxHash:         e.TxHash,
		Ledger:         e.Ledger,
		SourceMax:      e.SourceMax,
		DestinationMin: e.DestinationMin,
		EntireBalance:  e.EntireBalance,
		Counterparty:   e.Counterparty,
		ToMuxed:        e.ToMuxed,
		FromMuxed:      e.FromMuxed,
		SourceAccount:  e.SourceAccount,
		MemoBytes:      e.MemoBytes,
	}
	if e.Amount != "" {
		j.Amount, j.Asset = e.Amount, toJSONAsset(e.Asset)
	} else if e.DestinationMin != "" {
		j.Asset = toJSONAsset(e.Asset) // the bound's asset
	}
	if e.SourceAmount != "" || e.SourceMax != "" {
		j.SourceAmount, j.SourceAsset = e.SourceAmount, toJSONAsset(e.SourceAsset)
	}
	if e.Memo != nil {
		j.Memo = &jsonMemo{Type: e.Memo.Type, Value: e.Memo.Value}
	}
	return j
}

// newJSONEncoder builds the encoder used for all JSON output: no HTML
// escaping, so memo text passes through byte-for-byte.
func newJSONEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc
}

// csvHeader is the CSV schema, append-only like the JSON one.
var csvHeader = []string{
	"id", "created_at", "direction", "type",
	"amount", "asset", "source_amount", "source_asset",
	"counterparty", "to_muxed", "from_muxed",
	"memo_type", "memo", "tx_hash", "successful",
}

// csvRecord renders one entry as a CSV row. The amount columns hold strict
// decimals or nothing — the bounds of failed path payments and the
// unrecorded amount of a merge are never written where a spreadsheet SUM
// would swallow them.
func csvRecord(e historyEntry) []string {
	var amount, asset string
	if e.Amount != "" {
		amount, asset = e.Amount, assetSpecString(e.Asset)
	}
	var srcAmount, srcAsset string
	if e.SourceAmount != "" {
		srcAmount, srcAsset = e.SourceAmount, assetSpecString(e.SourceAsset)
	}
	var memoType, memoValue string
	if e.Memo != nil {
		memoType, memoValue = e.Memo.Type, csvGuard(e.Memo.Value)
	}
	return []string{
		e.ID, e.CreatedAt.UTC().Format(time.RFC3339), e.Direction, e.Type,
		amount, asset, srcAmount, srcAsset,
		e.Counterparty, e.ToMuxed, e.FromMuxed,
		memoType, memoValue, e.TxHash, strconv.FormatBool(e.Successful),
	}
}

// csvGuard defuses spreadsheet formula injection. Memo content is written by
// whoever sent the payment — anyone can send dust with a memo of
// "=HYPERLINK(...)" — and the documented use of --csv is opening the export
// in a spreadsheet, where cells starting with = + - @ or a tab execute as
// formulas. RFC-4180 quoting (which encoding/csv applies) does not stop
// that, so such cells get a leading apostrophe, the spreadsheet convention
// for "literal text".
func csvGuard(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t':
		return "'" + s
	}
	return s
}

// assetSpecString renders an asset unambiguously: "native", or CODE:ISSUER
// with the full issuer address. The short code alone would let a counterfeit
// asset (same code, different issuer) pass for the real one in an export.
func assetSpecString(a base.Asset) string {
	if a.Type == "native" {
		return "native"
	}
	if a.Type == "" {
		return ""
	}
	return a.Code + ":" + a.Issuer
}

// csvWriter wraps encoding/csv with lazy header emission: the header is
// written before the first row, or by close() for an empty result — so a
// successful empty listing yields a header-only CSV while a failed walk
// leaves stdout empty, matching the listing's lazy-header invariant.
type csvWriter struct {
	w          *csv.Writer
	headerDone bool
}

func newCSVWriter(w io.Writer) *csvWriter {
	return &csvWriter{w: csv.NewWriter(w)}
}

func (c *csvWriter) write(e historyEntry) error {
	if !c.headerDone {
		if err := c.w.Write(csvHeader); err != nil {
			return err
		}
		c.headerDone = true
	}
	return c.w.Write(csvRecord(e))
}

// close flushes, emitting the header even when no rows were written.
func (c *csvWriter) close() error {
	if !c.headerDone {
		if err := c.w.Write(csvHeader); err != nil {
			return err
		}
		c.headerDone = true
	}
	c.w.Flush()
	return c.w.Error()
}
