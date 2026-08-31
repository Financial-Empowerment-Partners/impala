package cli

import (
	"encoding/base64"
	"fmt"
	"strings"

	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
)

// runHistory lists an account's transaction history, newest first:
// `lumencli history G...`. By default it walks the account's entire history;
// --limit stops after that many entries.
//
// The listing comes from Horizon's payments endpoint, so it shows the
// operations that move funds — payments, path payments, account creations and
// merges — each with its counterparty, memo, and transaction hash. Amounts
// come with full identifiers untruncated: history is what you consult when
// checking whether a deposit arrived or where funds went, and an abbreviated
// address or hash cannot be pasted into an explorer or compared to a receipt.
func (a *App) runHistory(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("history")
	bindNetworkFlags(fs, &opts)
	limit := fs.Int("limit", 0, "stop after this many entries (0 = the full history)")
	includeFailed := fs.Bool("failed", false, "also list operations from failed transactions")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.fail("usage: lumencli history [flags] <account-address>")
	}
	if *limit < 0 {
		return a.fail("--limit must be 0 (the full history) or positive")
	}
	address := strings.TrimSpace(rest[0])

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)

	// The header prints on the first entry, not up front, so a failed fetch
	// (bad address, absent account) leaves stdout empty rather than topped
	// with a header for a listing that never came.
	headerPrinted := false
	printHeader := func() {
		if !headerPrinted {
			fmt.Fprintf(a.out, "Account: %s\nHistory (newest first):\n", address)
			headerPrinted = true
		}
	}

	shown, truncated := 0, false
	walkErr := stellar.New(net).EachPayment(address, *includeFailed, func(op operations.Operation) bool {
		if *limit > 0 && shown == *limit {
			truncated = true
			return false
		}
		printHeader()
		fmt.Fprintln(a.out)
		a.printHistoryOp(address, op)
		shown++
		return true
	})
	if walkErr != nil {
		return a.fail("%v", walkErr)
	}

	if shown == 0 {
		printHeader()
		fmt.Fprintln(a.out, "  (no transactions)")
		return 0
	}
	entries := "entries"
	if shown == 1 {
		entries = "entry"
	}
	fmt.Fprintf(a.out, "\n%d %s shown.\n", shown, entries)
	if truncated {
		fmt.Fprintf(a.err, "Stopped at --limit %d; older entries may exist.\n", *limit)
	}
	return 0
}

// printHistoryOp renders one history entry as a short block:
//
//	2026-08-30 14:02:11 UTC  received  25.0000000 XLM  (payment)
//	  From: GABC...FULL...XYZ
//	  Memo: text "thanks"
//	  Tx:   3a0f...full hash...
func (a *App) printHistoryOp(address string, op operations.Operation) {
	b := op.GetBase()
	kind, direction, amount, partyLabel, party := describeHistoryOp(address, op)

	line := b.LedgerCloseTime.UTC().Format("2006-01-02 15:04:05") + " UTC  " + direction
	if amount != "" {
		line += "  " + amount
	}
	line += "  (" + kind + ")"
	if !b.TransactionSuccessful {
		line += "  [FAILED — no funds moved]"
	}
	fmt.Fprintln(a.out, line)
	if party != "" {
		fmt.Fprintf(a.out, "  %-5s %s\n", partyLabel+":", party)
	}
	if memo := transactionMemo(b.Transaction); memo != "" {
		fmt.Fprintf(a.out, "  %-5s %s\n", "Memo:", memo)
	}
	fmt.Fprintf(a.out, "  %-5s %s\n", "Tx:", b.TransactionHash)
}

// describeHistoryOp reduces a payment-shaped operation to one history line:
// what kind of movement it was, whether address sent or received, how much,
// and who the counterparty was. address is the account whose history is being
// listed, so direction is relative to it. A payment from an account to itself
// reads as "sent" — the To line then shows the same address, which says it
// plainly enough.
func describeHistoryOp(address string, op operations.Operation) (kind, direction, amount, partyLabel, party string) {
	native := base.Asset{Type: "native"}
	switch v := op.(type) {
	case operations.Payment:
		if v.From == address {
			return "payment", "sent", amountLabel(v.Amount, v.Asset), "To", v.To
		}
		return "payment", "received", amountLabel(v.Amount, v.Asset), "From", v.From

	case operations.PathPayment: // strict receive
		if v.From == address {
			// SourceAmount is what was actually paid; it is absent when the
			// transaction failed, where SourceMax bounds what would have been.
			amt := v.SourceAmount
			if amt == "" {
				amt = "≤ " + v.SourceMax
			}
			srcAsset := base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode}
			return "path payment", "sent", amountLabel(amt, srcAsset), "To", v.To
		}
		return "path payment", "received", amountLabel(v.Amount, v.Asset), "From", v.From

	case operations.PathPaymentStrictSend:
		if v.From == address {
			srcAsset := base.Asset{Type: v.SourceAssetType, Code: v.SourceAssetCode}
			return "path payment", "sent", amountLabel(v.SourceAmount, srcAsset), "To", v.To
		}
		amt := v.Amount // absent on a failed transaction; DestinationMin bounds it
		if amt == "" {
			amt = "≥ " + v.DestinationMin
		}
		return "path payment", "received", amountLabel(amt, v.Asset), "From", v.From

	case operations.CreateAccount:
		if v.Funder == address {
			return "created account", "sent", amountLabel(v.StartingBalance, native), "To", v.Account
		}
		return "account created", "received", amountLabel(v.StartingBalance, native), "From", v.Funder

	case operations.AccountMerge:
		// A merge moves the account's whole remaining balance; the amount is
		// not part of the operation record.
		if v.Account == address {
			return "account merge", "sent", "entire balance", "To", v.Into
		}
		return "account merge", "received", "entire balance", "From", v.Account

	default:
		// The payments endpoint can grow new operation kinds; show what is
		// known rather than dropping the entry.
		b := op.GetBase()
		return b.GetType(), "involved", "", "Source", b.SourceAccount
	}
}

// amountLabel renders "25.0000000 XLM" from an amount and its asset.
func amountLabel(amount string, asset base.Asset) string {
	return amount + " " + assetLabel(asset)
}

// transactionMemo renders the memo of a history entry's transaction, or ""
// for none. tx is the joined transaction; hash and return memos arrive
// base64-encoded and are shown as the hex digits the user typed at --memo.
func transactionMemo(tx *hProtocol.Transaction) string {
	if tx == nil {
		return ""
	}
	switch tx.MemoType {
	case "", "none":
		return ""
	case "text":
		return fmt.Sprintf("text %q", tx.Memo)
	case "hash", "return":
		if raw, err := base64.StdEncoding.DecodeString(tx.Memo); err == nil {
			return fmt.Sprintf("%s %x", tx.MemoType, raw)
		}
		return tx.MemoType + " " + tx.Memo
	default: // id, and any future type
		return tx.MemoType + " " + tx.Memo
	}
}
