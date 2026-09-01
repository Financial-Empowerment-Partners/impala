package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
	"github.com/stellar/go-stellar-sdk/strkey"
)

// opFromRec round-trips an opRec through the SDK's own unmarshaller, so every
// entry test runs on an operations.Operation the real client code could
// actually receive — never a hand-built struct the wire could not produce.
func opFromRec(t *testing.T, o opRec) operations.Operation {
	t.Helper()
	op, err := operations.UnmarshalOperation(o.TypeI, []byte(o.JSON(t)))
	if err != nil {
		t.Fatalf("unmarshal record %s: %v", o.ID, err)
	}
	return op
}

// opFromRecWith is opFromRec plus wire fields the opRec builder does not
// model (e.g. funder_muxed). The assertions on the resulting entry keep the
// extra field names honest: a typo'd key decodes to nothing and fails there.
func opFromRecWith(t *testing.T, o opRec, extra map[string]any) operations.Operation {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(o.JSON(t)), &m); err != nil {
		t.Fatalf("decode record %s: %v", o.ID, err)
	}
	for k, v := range extra {
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal record %s: %v", o.ID, err)
	}
	op, err := operations.UnmarshalOperation(o.TypeI, raw)
	if err != nil {
		t.Fatalf("unmarshal record %s with extras: %v", o.ID, err)
	}
	return op
}

// muxedFor builds a valid M... address multiplexing id onto the account g.
func muxedFor(t *testing.T, g string, id uint64) string {
	t.Helper()
	var m strkey.MuxedAccount
	m.SetID(id)
	if err := m.SetAccountID(g); err != nil {
		t.Fatalf("SetAccountID(%s): %v", g, err)
	}
	addr, err := m.Address()
	if err != nil {
		t.Fatalf("muxed address: %v", err)
	}
	return addr
}

// pathReceiveRec is a successful strict-receive path payment: from paid USDC,
// to received a fixed amount of XLM.
func pathReceiveRec(id, from, to string) opRec {
	return opRec{
		ID: id, Type: "path_payment_strict_receive", TypeI: typePathStrictReceive,
		Source: from, TxHash: "h-" + id,
		From: from, To: to,
		Amount: "50.0000000", AssetType: "native",
		SourceAmount: "3.0000000", SourceMax: "3.5000000",
		SrcAssetType: "credit_alphanum4", SrcAssetCode: "USDC", SrcAssetIssuer: assetIssuer,
	}
}

// pathSendRec is a successful strict-send path payment: from paid a fixed
// amount of USDC, to received XLM.
func pathSendRec(id, from, to string) opRec {
	return opRec{
		ID: id, Type: "path_payment_strict_send", TypeI: typePathStrictSend,
		Source: from, TxHash: "h-" + id,
		From: from, To: to,
		Amount: "50.0000000", AssetType: "native",
		SourceAmount: "3.0000000", DestinationMin: "45.0000000",
		SrcAssetType: "credit_alphanum4", SrcAssetCode: "USDC", SrcAssetIssuer: assetIssuer,
	}
}

func createRec(id, funder, account string) opRec {
	return opRec{
		ID: id, Type: "create_account", TypeI: typeCreateAccount,
		Source: funder, TxHash: "h-" + id,
		Funder: funder, Account: account, StartingBalance: "100.0000000",
	}
}

func mergeRec(id, account, into string) opRec {
	return opRec{
		ID: id, Type: "account_merge", TypeI: typeAccountMerge,
		Source: account, TxHash: "h-" + id,
		Account: account, Into: into,
	}
}

// TestEntryDirection pins the direction and counterparty for every
// fund-moving shape from both sides, the self case that books both legs, and
// the submitter-only case: Horizon lists an operation on the submitting
// account's history even when that account is neither side of the transfer,
// which must classify as "other" with no counterparty.
func TestEntryDirection(t *testing.T) {
	mine, other := historyAddrs(t)
	_, third := historyAddrs(t)

	submitterOnly := payment("14", other, third, "5.0000000", "h-14")
	submitterOnly.Source = mine // mine only submitted the transaction

	cases := []struct {
		name string
		rec  opRec
		dir  string
		cp   string
	}{
		{"payment sent", payment("1", mine, other, "5.0000000", "h-1"), dirSent, other},
		{"payment received", payment("2", other, mine, "5.0000000", "h-2"), dirReceived, other},
		{"payment to self", payment("3", mine, mine, "5.0000000", "h-3"), dirSelf, mine},
		{"strict receive sent", pathReceiveRec("4", mine, other), dirSent, other},
		{"strict receive received", pathReceiveRec("5", other, mine), dirReceived, other},
		{"strict receive to self (conversion)", pathReceiveRec("6", mine, mine), dirSelf, mine},
		{"strict send sent", pathSendRec("7", mine, other), dirSent, other},
		{"strict send received", pathSendRec("8", other, mine), dirReceived, other},
		{"strict send to self (conversion)", pathSendRec("9", mine, mine), dirSelf, mine},
		{"create_account as funder", createRec("10", mine, other), dirSent, other},
		{"create_account as the created account", createRec("11", other, mine), dirReceived, other},
		{"account_merge merged away", mergeRec("12", mine, other), dirSent, other},
		{"account_merge absorbed", mergeRec("13", other, mine), dirReceived, other},
		{"transaction submitter only", submitterOnly, dirOther, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := entryFromOp(mine, opFromRec(t, tt.rec))
			if e.Direction != tt.dir {
				t.Errorf("Direction = %q, want %q", e.Direction, tt.dir)
			}
			if e.Counterparty != tt.cp {
				t.Errorf("Counterparty = %q, want %q", e.Counterparty, tt.cp)
			}
		})
	}
}

// TestEntrySubmitterOnlyNeverBooksFunds: a payment between two other accounts
// that this account merely submitted must contribute nothing to the summary
// totals — booking it would invent money the account never touched.
func TestEntrySubmitterOnlyNeverBooksFunds(t *testing.T) {
	mine, other := historyAddrs(t)
	_, third := historyAddrs(t)
	rec := payment("1", other, third, "5.0000000", "h-1")
	rec.Source = mine

	e := entryFromOp(mine, opFromRec(t, rec))
	if e.Direction != dirOther || e.Counterparty != "" {
		t.Fatalf("Direction, Counterparty = %q, %q, want %q, \"\"", e.Direction, e.Counterparty, dirOther)
	}
	acc := newSummaryAccum()
	if err := acc.add(mine, e); err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(acc.buckets) != 0 {
		t.Errorf("submitter-only payment booked funds: %d asset buckets, want 0", len(acc.buckets))
	}
}

// TestEntryAmountStrictness pins the amount-vs-bound separation: a bound from
// a failed path payment lives in its own field and never masquerades as an
// amount, and a merge's unrecorded balance leaves every amount field empty.
func TestEntryAmountStrictness(t *testing.T) {
	mine, other := historyAddrs(t)

	// Real Horizon serializes the execution-determined leg of a FAILED path
	// payment as a "0.0000000" placeholder, never as an absent field (the SDK
	// structs have no omitempty) — the entry must drop the placeholder and
	// carry the bound instead.
	failedReceive := pathReceiveRec("2", mine, other)
	failedReceive.Failed = true
	failedReceive.SourceAmount = "0.0000000"
	failedReceive.SourceMax = "3.5000000"

	failedSend := pathSendRec("3", other, mine)
	failedSend.Failed = true
	failedSend.Amount = "0.0000000"
	failedSend.DestinationMin = "45.0000000"

	cases := []struct {
		name                               string
		rec                                opRec
		amount, srcAmount, srcMax, destMin string
		entire                             bool
		assetType                          string
	}{
		{"successful strict receive has both amounts",
			pathReceiveRec("1", mine, other), "50.0000000", "3.0000000", "", "", false, "native"},
		{"failed strict receive keeps the bound out of the amounts",
			failedReceive, "50.0000000", "", "3.5000000", "", false, "native"},
		{"failed strict send keeps the bound out of the amounts",
			failedSend, "", "3.0000000", "", "45.0000000", false, "native"},
		{"account merge moves the whole unrecorded balance",
			mergeRec("4", mine, other), "", "", "", "", true, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := entryFromOp(mine, opFromRec(t, tt.rec))
			if e.Amount != tt.amount {
				t.Errorf("Amount = %q, want %q", e.Amount, tt.amount)
			}
			if e.SourceAmount != tt.srcAmount {
				t.Errorf("SourceAmount = %q, want %q", e.SourceAmount, tt.srcAmount)
			}
			if e.SourceMax != tt.srcMax {
				t.Errorf("SourceMax = %q, want %q", e.SourceMax, tt.srcMax)
			}
			if e.DestinationMin != tt.destMin {
				t.Errorf("DestinationMin = %q, want %q", e.DestinationMin, tt.destMin)
			}
			if e.EntireBalance != tt.entire {
				t.Errorf("EntireBalance = %v, want %v", e.EntireBalance, tt.entire)
			}
			if e.Asset.Type != tt.assetType {
				t.Errorf("Asset.Type = %q, want %q", e.Asset.Type, tt.assetType)
			}
			if e.Successful != !tt.rec.Failed {
				t.Errorf("Successful = %v, want %v", e.Successful, !tt.rec.Failed)
			}
		})
	}
}

// TestEntryMuxedPassthrough: the exact muxed forms the wire carried reach the
// entry — they identify one depositor among the many sharing a pooled account.
func TestEntryMuxedPassthrough(t *testing.T) {
	mine, other := historyAddrs(t)
	fromMux := muxedFor(t, other, 1)
	toMux := muxedFor(t, mine, 2)

	p := payment("1", other, mine, "5.0000000", "h-1")
	p.FromMuxed, p.ToMuxed = fromMux, toMux
	e := entryFromOp(mine, opFromRec(t, p))
	if e.FromMuxed != fromMux {
		t.Errorf("FromMuxed = %q, want %q", e.FromMuxed, fromMux)
	}
	if e.ToMuxed != toMux {
		t.Errorf("ToMuxed = %q, want %q", e.ToMuxed, toMux)
	}

	// create_account carries the funder's muxed form as funder_muxed, which
	// the opRec builder does not model; it lands on the entry's from side.
	c := createRec("2", other, mine)
	e = entryFromOp(mine, opFromRecWith(t, c, map[string]any{"funder_muxed": fromMux}))
	if e.FromMuxed != fromMux {
		t.Errorf("FromMuxed = %q, want %q (funder_muxed)", e.FromMuxed, fromMux)
	}
	if e.ToMuxed != "" {
		t.Errorf("ToMuxed = %q, want empty for create_account", e.ToMuxed)
	}
}

// TestMemoFromTransaction pins the canonical display encoding: text verbatim,
// id decimal, hash/return normalized from Horizon's base64 to the lowercase
// hex digits the user typed at --memo.
func TestMemoFromTransaction(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	// Hardcoded, not computed with hex.EncodeToString: the test must pin the
	// lowercase-hex encoding independently of the implementation.
	const wantHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if got := hex.EncodeToString(raw); got != wantHex {
		t.Fatalf("fixture self-check: hex = %q, want %q", got, wantHex)
	}

	cases := []struct {
		name      string
		tx        *hProtocol.Transaction
		want      *entryMemo
		wantBytes string
	}{
		{"nil transaction", nil, nil, ""},
		{"absent memo type", &hProtocol.Transaction{}, nil, ""},
		{"none", &hProtocol.Transaction{MemoType: "none"}, nil, ""},
		{"text verbatim",
			&hProtocol.Transaction{MemoType: "text", Memo: "thanks"},
			&entryMemo{Type: "text", Value: "thanks"}, ""},
		{"text with sanitized bytes passed through",
			&hProtocol.Transaction{MemoType: "text", Memo: "than?s", MemoBytes: "dGhhbj9z"},
			&entryMemo{Type: "text", Value: "than?s"}, "dGhhbj9z"},
		{"id decimal",
			&hProtocol.Transaction{MemoType: "id", Memo: "3141592653"},
			&entryMemo{Type: "id", Value: "3141592653"}, ""},
		{"hash normalized to hex",
			&hProtocol.Transaction{MemoType: "hash", Memo: b64},
			&entryMemo{Type: "hash", Value: wantHex}, ""},
		{"return normalized to hex",
			&hProtocol.Transaction{MemoType: "return", Memo: b64},
			&entryMemo{Type: "return", Value: wantHex}, ""},
		{"invalid base64 falls back to the raw string",
			&hProtocol.Transaction{MemoType: "hash", Memo: "not base64!"},
			&entryMemo{Type: "hash", Value: "not base64!"}, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, gotBytes := memoFromTransaction(tt.tx)
			if (got == nil) != (tt.want == nil) {
				t.Fatalf("memo = %+v, want %+v", got, tt.want)
			}
			if got != nil && (got.Type != tt.want.Type || got.Value != tt.want.Value) {
				t.Errorf("memo = %+v, want %+v", *got, *tt.want)
			}
			if gotBytes != tt.wantBytes {
				t.Errorf("memo bytes = %q, want %q", gotBytes, tt.wantBytes)
			}
		})
	}
}

// TestEntryMemoString pins the display forms the send command also uses.
func TestEntryMemoString(t *testing.T) {
	var nilMemo *entryMemo
	if got := nilMemo.String(); got != "" {
		t.Errorf("nil memo String() = %q, want empty", got)
	}
	if got := (&entryMemo{Type: "text", Value: "x"}).String(); got != `text "x"` {
		t.Errorf("text memo String() = %q, want %q", got, `text "x"`)
	}
	if got := (&entryMemo{Type: "id", Value: "314"}).String(); got != "id 314" {
		t.Errorf("id memo String() = %q, want %q", got, "id 314")
	}
}

// TestEntryJoinedTxFields: ledger, fee, and memo come from the joined
// transaction; an absent join (no join=transactions) leaves them zero rather
// than inventing values.
func TestEntryJoinedTxFields(t *testing.T) {
	mine, other := historyAddrs(t)

	joined := payment("1", other, mine, "5.0000000", "h-1")
	joined.Tx.Ledger = 4242
	joined.Tx.FeeCharged = 100
	joined.Tx.FeeAccount = other
	joined.Tx.MemoType, joined.Tx.Memo = "id", "7"
	e := entryFromOp(mine, opFromRec(t, joined))
	if e.Ledger != 4242 {
		t.Errorf("Ledger = %d, want 4242", e.Ledger)
	}
	if e.FeeCharged != 100 {
		t.Errorf("FeeCharged = %d, want 100", e.FeeCharged)
	}
	if e.FeePayer != other {
		t.Errorf("FeePayer = %q, want %q", e.FeePayer, other)
	}
	if e.Memo == nil || e.Memo.Type != "id" || e.Memo.Value != "7" {
		t.Errorf("Memo = %+v, want id 7", e.Memo)
	}

	bare := payment("2", other, mine, "5.0000000", "h-2")
	bare.Tx = nil
	e = entryFromOp(mine, opFromRec(t, bare))
	if e.Ledger != 0 || e.FeeCharged != 0 || e.FeePayer != "" || e.Memo != nil {
		t.Errorf("absent join populated tx fields: Ledger=%d FeeCharged=%d FeePayer=%q Memo=%+v",
			e.Ledger, e.FeeCharged, e.FeePayer, e.Memo)
	}
	if e.TxHash != "h-2" || !e.Successful {
		t.Errorf("base fields lost without the join: TxHash=%q Successful=%v", e.TxHash, e.Successful)
	}
}
