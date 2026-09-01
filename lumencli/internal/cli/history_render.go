package cli

import (
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
)

// kindLabel names an entry's operation for the human listing.
func kindLabel(e historyEntry) string {
	switch e.Type {
	case "payment":
		return "payment"
	case "path_payment_strict_receive", "path_payment_strict_send":
		return "path payment"
	case "create_account":
		if e.Direction == dirReceived {
			return "account created"
		}
		return "created account"
	case "account_merge":
		return "account merge"
	default:
		return e.Type
	}
}

// headline renders the direction and amount part of an entry's first line.
// Self path payments read as the conversion they are; the bound leg of a
// failed path payment shows marked as a bound (≤/≥), never as an amount.
func headline(e historyEntry) string {
	// Displayable legs: the exact amount when one exists, else the bound.
	src := ""
	switch {
	case e.SourceAmount != "":
		src = e.SourceAmount + " " + assetLabel(e.SourceAsset)
	case e.SourceMax != "":
		src = "≤ " + e.SourceMax + " " + assetLabel(e.SourceAsset)
	}
	dst := ""
	switch {
	case e.Amount != "":
		dst = e.Amount + " " + assetLabel(e.Asset)
	case e.DestinationMin != "":
		dst = "≥ " + e.DestinationMin + " " + assetLabel(e.Asset)
	}

	switch e.Direction {
	case dirSelf:
		switch {
		case e.EntireBalance:
			return "self  entire balance"
		case src != "" && dst != "": // a path payment to self is a conversion
			return "converted  " + src + " -> " + dst
		default:
			return "self  " + dst
		}
	case dirSent:
		if e.EntireBalance {
			return "sent  entire balance"
		}
		// What left the account: the source leg for path payments, the
		// single amount otherwise.
		if src != "" {
			return "sent  " + src
		}
		return "sent  " + dst
	case dirReceived:
		if e.EntireBalance {
			return "received  entire balance"
		}
		return "received  " + dst
	default:
		return "involved"
	}
}

// renderEntry writes one history entry as a short human block:
//
//	2026-08-30 14:02:11 UTC  received  25.0000000 XLM  (payment)
//	  From: GABC...FULL...XYZ
//	  Memo: id 3141592653
//	  Tx:   3a0f...full hash...
//
// Identifiers are never truncated: history is what you consult when checking
// whether a deposit arrived or where funds went, and an abbreviated address
// or hash cannot be pasted into an explorer or compared to a receipt.
func renderEntry(w io.Writer, e historyEntry) {
	line := e.CreatedAt.UTC().Format("2006-01-02 15:04:05") + " UTC  " + headline(e)
	line += "  (" + kindLabel(e) + ")"
	if !e.Successful {
		line += "  [FAILED — no funds moved]"
	}
	fmt.Fprintln(w, line)

	switch e.Direction {
	case dirSent, dirSelf:
		fmt.Fprintf(w, "  %-5s %s\n", "To:", e.Counterparty)
	case dirReceived:
		fmt.Fprintf(w, "  %-5s %s\n", "From:", e.Counterparty)
	default:
		if e.SourceAccount != "" {
			fmt.Fprintf(w, "  Source: %s\n", e.SourceAccount)
		}
	}
	// The muxed (M...) forms identify one depositor among the many sharing a
	// pooled account — exactly the information history is consulted for.
	if e.ToMuxed != "" {
		fmt.Fprintf(w, "  To (muxed):   %s\n", e.ToMuxed)
	}
	if e.FromMuxed != "" {
		fmt.Fprintf(w, "  From (muxed): %s\n", e.FromMuxed)
	}
	if m := e.Memo.String(); m != "" {
		fmt.Fprintf(w, "  %-5s %s\n", "Memo:", m)
	}
	fmt.Fprintf(w, "  %-5s %s\n", "Tx:", e.TxHash)
}

// renderTxOp writes one operation of a transaction in absolute form — a
// transaction has no "my account" perspective, so both parties are named:
//
//	payment: GSRC... -> GDST...  25.0000000 XLM
func renderTxOp(w io.Writer, op operations.Operation) {
	switch v := op.(type) {
	case operations.Payment:
		fmt.Fprintf(w, "payment: %s -> %s  %s %s\n", v.From, v.To, v.Amount, assetLabel(v.Asset))
	case operations.PathPayment:
		// The source amount of a failed strict-receive is a "0.0000000" wire
		// placeholder, not a value: show the bound instead. Same outcome
		// discrimination as entryFromOp.
		src := assetLabel(base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer})
		paid := v.SourceAmount
		if !v.TransactionSuccessful {
			paid = "≤ " + v.SourceMax
		}
		fmt.Fprintf(w, "path payment: %s -> %s  %s %s -> %s %s\n",
			v.From, v.To, paid, src, v.Amount, assetLabel(v.Asset))
	case operations.PathPaymentStrictSend:
		src := assetLabel(base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode, Issuer: v.SourceAssetIssuer})
		got := v.Amount
		if !v.TransactionSuccessful {
			got = "≥ " + v.DestinationMin
		}
		fmt.Fprintf(w, "path payment: %s -> %s  %s %s -> %s %s\n",
			v.From, v.To, v.SourceAmount, src, got, assetLabel(v.Asset))
	case operations.CreateAccount:
		fmt.Fprintf(w, "create account: %s funded %s with %s XLM\n", v.Funder, v.Account, v.StartingBalance)
	case operations.AccountMerge:
		fmt.Fprintf(w, "account merge: %s merged into %s (entire balance)\n", v.Account, v.Into)
	default:
		b := op.GetBase()
		fmt.Fprintf(w, "%s (source %s)\n", b.Type, b.SourceAccount)
	}
}
