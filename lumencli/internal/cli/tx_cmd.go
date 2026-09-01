package cli

import (
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/amount"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// runTx shows one transaction in full: `lumencli tx <hash>`. The use case is
// pasting a hash from a history entry, a receipt, or an explorer and seeing
// what it did — including a failed transaction, whose fee was charged even
// though its operations moved nothing.
func (a *App) runTx(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("tx")
	bindNetworkFlags(fs, &opts)
	jsonOut := fs.Bool("json", false, "write a single JSON object instead of the human form")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli tx [flags] <transaction-hash>")
	}
	// Validate the hash shape before any network call (accepts either case —
	// explorers render hashes both ways).
	hash, err := stellar.NormalizeTxHash(rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)

	tx, ops, err := stellar.New(net).TransactionInfo(hash)
	if err != nil {
		return a.fail("%v", err)
	}

	if *jsonOut {
		if err := newJSONEncoder(a.out).Encode(toJSONTx(tx, ops)); err != nil {
			return a.fail("write json: %v", err)
		}
		return 0
	}
	renderTx(a, tx, ops)
	return 0
}

func renderTx(a *App, tx hProtocol.Transaction, ops []operations.Operation) {
	fmt.Fprintf(a.out, "Transaction: %s\n", tx.Hash)
	if tx.Successful {
		fmt.Fprintln(a.out, "Status:      succeeded")
	} else {
		fmt.Fprintln(a.out, "Status:      FAILED — no funds moved; the fee was still charged")
	}
	fmt.Fprintf(a.out, "Ledger:      %d, closed %s UTC\n", tx.Ledger, tx.LedgerCloseTime.UTC().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(a.out, "Source:      %s\n", tx.Account)
	fee := fmt.Sprintf("Fee:         %s XLM", amount.StringFromInt64(tx.FeeCharged))
	if tx.FeeAccount != "" && tx.FeeAccount != tx.Account {
		// A fee-bump transaction: someone else paid the fee.
		fee += fmt.Sprintf(" (paid by %s)", tx.FeeAccount)
	}
	fmt.Fprintln(a.out, fee)
	if m, _ := memoFromTransaction(&tx); m != nil {
		fmt.Fprintf(a.out, "Memo:        %s\n", m.String())
	}
	fmt.Fprintf(a.out, "Operations (%d):\n", tx.OperationCount)
	for i, op := range ops {
		fmt.Fprintf(a.out, "  %d. ", i+1)
		renderTxOp(a.out, op)
	}
}

// jsonTx is the tx --json object. Operations appear in absolute form (both
// parties named) since a transaction has no "my account" perspective.
type jsonTx struct {
	Hash       string     `json:"hash"`
	Successful bool       `json:"successful"`
	Ledger     int32      `json:"ledger"`
	CreatedAt  string     `json:"created_at"`
	Source     string     `json:"source"`
	FeeCharged string     `json:"fee_charged"`
	FeePayer   string     `json:"fee_payer,omitempty"` // only when not the source (fee bump)
	Memo       *jsonMemo  `json:"memo,omitempty"`
	MemoBytes  string     `json:"memo_bytes,omitempty"`
	Operations []jsonTxOp `json:"operations"`
}

type jsonTxOp struct {
	ID              string     `json:"id"`
	Type            string     `json:"type"`
	From            string     `json:"from,omitempty"`
	To              string     `json:"to,omitempty"`
	Amount          string     `json:"amount,omitempty"`
	Asset           *jsonAsset `json:"asset,omitempty"`
	SourceAmount    string     `json:"source_amount,omitempty"`
	SourceAsset     *jsonAsset `json:"source_asset,omitempty"`
	SourceMax       string     `json:"source_max,omitempty"`
	DestinationMin  string     `json:"destination_min,omitempty"`
	StartingBalance string     `json:"starting_balance,omitempty"`
	Into            string     `json:"into,omitempty"`
	SourceAccount   string     `json:"source_account,omitempty"`
}

func toJSONTx(tx hProtocol.Transaction, ops []operations.Operation) jsonTx {
	out := jsonTx{
		Hash:       tx.Hash,
		Successful: tx.Successful,
		Ledger:     tx.Ledger,
		CreatedAt:  tx.LedgerCloseTime.UTC().Format(time.RFC3339),
		Source:     tx.Account,
		FeeCharged: amount.StringFromInt64(tx.FeeCharged),
		Operations: []jsonTxOp{},
	}
	if tx.FeeAccount != "" && tx.FeeAccount != tx.Account {
		out.FeePayer = tx.FeeAccount
	}
	if m, bytes := memoFromTransaction(&tx); m != nil {
		out.Memo = &jsonMemo{Type: m.Type, Value: m.Value}
		out.MemoBytes = bytes
	}
	for _, op := range ops {
		out.Operations = append(out.Operations, toJSONTxOp(op))
	}
	return out
}

func toJSONTxOp(op operations.Operation) jsonTxOp {
	b := op.GetBase()
	j := jsonTxOp{ID: b.ID, Type: b.Type}
	switch v := op.(type) {
	case operations.Payment:
		j.From, j.To, j.Amount, j.Asset = v.From, v.To, v.Amount, toJSONAsset(v.Asset)
	case operations.PathPayment:
		// Same outcome discrimination as entryFromOp: a failed operation's
		// execution-determined leg is a "0.0000000" wire placeholder, dropped
		// in favor of its bound.
		j.From, j.To = v.From, v.To
		j.Amount, j.Asset = v.Amount, toJSONAsset(v.Asset)
		j.SourceAsset = toJSONAsset(base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer})
		if v.TransactionSuccessful {
			j.SourceAmount = v.SourceAmount
		} else {
			j.SourceMax = v.SourceMax
		}
	case operations.PathPaymentStrictSend:
		j.From, j.To = v.From, v.To
		j.SourceAmount = v.SourceAmount
		j.SourceAsset = toJSONAsset(base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer})
		j.Asset = toJSONAsset(v.Asset)
		if v.TransactionSuccessful {
			j.Amount = v.Amount
		} else {
			j.DestinationMin = v.DestinationMin
		}
	case operations.CreateAccount:
		j.From, j.To, j.StartingBalance = v.Funder, v.Account, v.StartingBalance
	case operations.AccountMerge:
		j.From, j.Into = v.Account, v.Into
	default:
		j.SourceAccount = b.SourceAccount
	}
	return j
}
