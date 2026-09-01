package cli

import (
	"encoding/base64"
	"encoding/hex"
	"time"

	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
)

// Directions of a history entry relative to the queried account.
//
// "self" is a transfer from the account to itself — most commonly a path
// payment to self, which is the standard Stellar pattern for converting one
// asset to another. Treating it as plain "sent" would book the outgoing leg
// and silently drop the incoming one, corrupting every net figure downstream.
// "other" marks operations with no fund-moving perspective (the generic kinds
// listed by --all-ops); they are never counted in summary totals.
const (
	dirSent     = "sent"
	dirReceived = "received"
	dirSelf     = "self"
	dirOther    = "other"
)

// historyEntry is one history line, reduced from a Horizon operation once and
// then shared by every renderer (text, JSON, CSV), the filters, and the
// summary — so the four can never disagree about what an operation means.
//
// Amount semantics are strict, because these values flow into accounting:
// Amount is the destination-leg amount and SourceAmount the source-leg amount
// (for path payments; equal legs collapse to Amount alone), each present only
// when it is an exact value — either executed, or declared in the envelope of
// a failed operation whose Successful flag already says nothing moved. The
// execution-determined leg of a FAILED path payment has no value (Horizon
// sends a "0.0000000" placeholder, which must never surface as an amount):
// that leg carries its bound instead — SourceMax or DestinationMin — in its
// own field. An account merge moves the account's entire remaining balance,
// which the operation record does not carry: EntireBalance marks it and every
// amount field stays empty.
type historyEntry struct {
	ID          string
	PagingToken string
	CreatedAt   time.Time
	Type        string // wire operation type, e.g. "payment"
	Direction   string // dirSent | dirReceived | dirSelf | dirOther

	Amount         string     // destination-leg amount (7-dp decimal), "" when not exactly known
	Asset          base.Asset // asset of Amount; zero value when Amount is ""
	SourceAmount   string     // source-leg amount for path payments, "" when absent or unknown
	SourceAsset    base.Asset
	SourceMax      string // failed strict-receive path payment: bound on the source leg
	DestinationMin string // failed strict-send path payment: bound on the destination leg
	EntireBalance  bool   // account_merge: the whole balance moved, amount not in the record

	Counterparty  string // the other account (G...), "" for generic operations
	ToMuxed       string // muxed (M...) form of the payment's destination, when the wire carried one
	FromMuxed     string // muxed (M...) form of the payment's source, when the wire carried one
	SourceAccount string // operation source, shown for generic operations

	TxHash     string
	Successful bool
	Ledger     int32 // from the joined transaction; 0 when the join was absent

	Memo      *entryMemo
	MemoBytes string // base64 raw bytes of a text memo Horizon sanitized, when sent

	// Fee fields of the parent transaction, for summary fee accounting only.
	// Fees are per-transaction, not per-operation: a transaction with several
	// operations repeats these on every entry, so consumers must deduplicate
	// by TxHash — which is why no per-entry fee appears in the JSON output.
	FeeCharged int64
	FeePayer   string
}

// entryMemo is a transaction memo in canonical display encoding: text
// verbatim, id as a decimal string, hash and return as the 64 hex digits the
// user typed at --memo (Horizon delivers those base64-encoded).
type entryMemo struct {
	Type  string
	Value string
}

// String renders the memo the way the send command describes one, e.g.
// `text "thanks"` or `id 3141592653`.
func (m *entryMemo) String() string {
	if m == nil {
		return ""
	}
	if m.Type == "text" {
		return `text "` + m.Value + `"`
	}
	return m.Type + " " + m.Value
}

// entryFromOp reduces op to a history entry from the perspective of address.
func entryFromOp(address string, op operations.Operation) historyEntry {
	b := op.GetBase()
	e := historyEntry{
		ID:          b.ID,
		PagingToken: b.PT,
		CreatedAt:   b.LedgerCloseTime,
		Type:        b.Type,
		Direction:   dirOther,
		TxHash:      b.TransactionHash,
		Successful:  b.TransactionSuccessful,
	}
	if tx := b.Transaction; tx != nil {
		e.Ledger = tx.Ledger
		e.FeeCharged = tx.FeeCharged
		e.FeePayer = tx.FeeAccount
		e.Memo, e.MemoBytes = memoFromTransaction(tx)
	}

	native := base.Asset{Type: "native"}
	switch v := op.(type) {
	case operations.Payment:
		e.Direction = direction(address, v.From, v.To)
		e.Amount, e.Asset = v.Amount, v.Asset
		e.ToMuxed, e.FromMuxed = v.ToMuxed, v.FromMuxed
		e.Counterparty = pickCounterparty(e.Direction, v.From, v.To)

	case operations.PathPayment: // strict receive: destination amount fixed, source bounded
		e.Direction = direction(address, v.From, v.To)
		e.Amount, e.Asset = v.Amount, v.Asset
		e.SourceAsset = base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer}
		// The source amount is determined by execution, so a failed operation
		// has none — but Horizon still serializes the field, as a "0.0000000"
		// placeholder (the SDK structs have no omitempty; verified against
		// live Horizon). Discriminate on the transaction outcome, never on
		// field presence: on failure the placeholder is dropped and the
		// SourceMax bound — the only true statement about the source leg —
		// is carried instead. The fixed destination amount stays: it is
		// envelope-declared and exact, and Successful=false marks that it
		// never moved.
		if b.TransactionSuccessful {
			e.SourceAmount = v.SourceAmount
		} else {
			e.SourceMax = v.SourceMax
		}
		e.ToMuxed, e.FromMuxed = v.ToMuxed, v.FromMuxed
		e.Counterparty = pickCounterparty(e.Direction, v.From, v.To)

	case operations.PathPaymentStrictSend: // source amount fixed, destination bounded
		e.Direction = direction(address, v.From, v.To)
		e.SourceAmount = v.SourceAmount
		e.SourceAsset = base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer}
		e.Asset = v.Asset
		// Mirror image of the strict-receive case: the destination amount is
		// execution-determined, and a failed operation carries a "0.0000000"
		// placeholder for it on the wire. Keep the fixed source amount, and
		// on failure replace the placeholder with the DestinationMin bound.
		if b.TransactionSuccessful {
			e.Amount = v.Amount
		} else {
			e.DestinationMin = v.DestinationMin
		}
		e.ToMuxed, e.FromMuxed = v.ToMuxed, v.FromMuxed
		e.Counterparty = pickCounterparty(e.Direction, v.From, v.To)

	case operations.CreateAccount:
		e.Direction = direction(address, v.Funder, v.Account)
		e.Amount, e.Asset = v.StartingBalance, native
		e.FromMuxed = v.FunderMuxed
		e.Counterparty = pickCounterparty(e.Direction, v.Funder, v.Account)

	case operations.AccountMerge:
		e.Direction = direction(address, v.Account, v.Into)
		e.EntireBalance = true
		e.ToMuxed, e.FromMuxed = v.IntoMuxed, v.AccountMuxed
		e.Counterparty = pickCounterparty(e.Direction, v.Account, v.Into)

	default:
		// Operation kinds the SDK models but lumencli gives no bespoke
		// rendering (--all-ops): keep them visible rather than dropping them.
		// A kind the SDK does not model never reaches here — the SDK fails
		// the whole page decode, which EachOperation surfaces as an error.
		e.SourceAccount = b.SourceAccount
	}
	return e
}

// direction classifies a transfer from `from` to `to` relative to address.
func direction(address, from, to string) string {
	switch {
	case from == address && to == address:
		return dirSelf
	case from == address:
		return dirSent
	case to == address:
		return dirReceived
	default:
		// The account participated some other way (e.g. as the operation
		// source of a transfer between two other accounts).
		return dirOther
	}
}

// pickCounterparty selects the other party of a transfer: the recipient of a
// sent entry, the sender of a received one.
func pickCounterparty(dir, from, to string) string {
	switch dir {
	case dirSent, dirSelf:
		return to
	case dirReceived:
		return from
	default:
		return ""
	}
}

// memoFromTransaction converts a joined transaction's memo to canonical
// display encoding. Horizon sends hash and return memos base64-encoded; they
// are normalized to the hex digits the user typed at --memo. A text memo with
// bytes Horizon sanitized additionally carries memo_bytes (base64), passed
// through so scripts can recover the exact bytes.
func memoFromTransaction(tx *hProtocol.Transaction) (*entryMemo, string) {
	if tx == nil {
		return nil, ""
	}
	switch tx.MemoType {
	case "", "none":
		return nil, ""
	case "hash", "return":
		if raw, err := base64.StdEncoding.DecodeString(tx.Memo); err == nil {
			return &entryMemo{Type: tx.MemoType, Value: hex.EncodeToString(raw)}, ""
		}
		return &entryMemo{Type: tx.MemoType, Value: tx.Memo}, ""
	default: // text, id, and any future type
		return &entryMemo{Type: tx.MemoType, Value: tx.Memo}, tx.MemoBytes
	}
}
