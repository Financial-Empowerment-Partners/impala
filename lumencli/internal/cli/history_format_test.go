package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/protocols/horizon/base"
)

// The machine-readable schemas (jsonEntry, csvHeader) are append-only
// contracts, so their exact bytes are pinned by golden files. The fixture
// accounts are hardcoded: wallet.Generate would change the bytes on every
// run, and a golden needs stable output. Both are real, strkey-valid testnet
// addresses.
const (
	goldenMine  = "GBOSTEH5XRAMOJWXIWIPJT5P6GOW6GYXQJ7GHORK3X2Z426BWGYFTVLA"
	goldenOther = "GDYA6SPRCGPVLXFAXDJ6TFLZJ24QYAFW3CHFTUKP64CMKSWFFFIC7RB3"

	// goldenIssuer issues the fixture's USDC (the testnet USDC issuer).
	goldenIssuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"

	// goldenOtherMuxed is goldenOther multiplexed with id 42 — the underlying
	// account must match, since Horizon only emits to_muxed for the to account.
	goldenOtherMuxed = "MDYA6SPRCGPVLXFAXDJ6TFLZJ24QYAFW3CHFTUKP64CMKSWFFFIC6AAAAAAAAAAAFJHWA"

	// goldenFormulaMemo is attacker-controlled memo content: anyone can send
	// dust carrying it. The CSV cell must be guarded, the JSON value must not.
	goldenFormulaMemo = `=HYPERLINK("http://evil")`
)

// goldenMemoRaw is the known 32-byte hash-memo payload; the fixture carries
// its base64 (as Horizon sends it) and the output must carry its hex.
func goldenMemoRaw() []byte {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	return raw
}

// goldenHistoryFake serves one fixed page (newest first, fixed timestamps)
// covering every amount semantic the formats must get right: exact amounts,
// path-payment legs, failed-operation bounds, a merge's unrecorded amount,
// issued assets, muxed destinations, and hostile or binary memos.
func goldenHistoryFake(t *testing.T) *horizonFake {
	t.Helper()

	// 1. Received payment with a text memo.
	recv := payment("1", goldenOther, goldenMine, "25.0000000", "hash-recv-text")
	recv.CreatedAt = "2026-08-30T12:09:00Z"
	recv.Tx.MemoType, recv.Tx.Memo = "text", "thanks for lunch"

	// 2. Sent payment with an id memo and a muxed destination.
	sent := payment("2", goldenMine, goldenOther, "50.0000000", "hash-sent-muxed")
	sent.CreatedAt = "2026-08-30T12:08:00Z"
	sent.ToMuxed = goldenOtherMuxed
	sent.Tx.MemoType, sent.Tx.Memo = "id", "3141592653"

	// 3. Self path payment (strict send): the standard conversion pattern,
	// XLM out and issued USDC back in. Both legs carry exact amounts.
	selfConvert := opRec{
		ID: "3", Type: "path_payment_strict_send", TypeI: typePathStrictSend,
		Source: goldenMine, TxHash: "hash-self-convert",
		From: goldenMine, To: goldenMine,
		Amount: "98.7654321", AssetType: "credit_alphanum4", AssetCode: "USDC", AssetIssuer: goldenIssuer,
		SourceAmount: "100.0000000", DestinationMin: "95.0000000", SrcAssetType: "native",
		CreatedAt: "2026-08-30T12:07:00Z",
		Tx:        &txJoin{Hash: "hash-self-convert", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: goldenMine, Ledger: 1234},
	}

	// 4. Failed strict-receive sent path payment, in the shape real Horizon
	// serves: the fixed destination amount (exact, envelope-declared) plus a
	// "0.0000000" placeholder for the never-executed source leg — the entry
	// must keep the former, drop the latter, and carry the SourceMax bound.
	failedRecv := opRec{
		ID: "4", Type: "path_payment_strict_receive", TypeI: typePathStrictReceive, Failed: true,
		Source: goldenMine, TxHash: "hash-failed-recv",
		From: goldenMine, To: goldenOther,
		Amount: "17.5000000", AssetType: "credit_alphanum4", AssetCode: "USDC", AssetIssuer: goldenIssuer,
		SourceAmount: "0.0000000", SourceMax: "20.0000000", SrcAssetType: "native",
		CreatedAt: "2026-08-30T12:06:00Z",
		Tx:        &txJoin{Hash: "hash-failed-recv", Successful: false, MemoType: "none", FeeCharged: 100, FeeAccount: goldenMine, Ledger: 1234},
	}

	// 5. Failed strict-send received path payment: the source leg is exact
	// (fixed by the sender), the destination leg knows only DestinationMin.
	failedSend := opRec{
		ID: "5", Type: "path_payment_strict_send", TypeI: typePathStrictSend, Failed: true,
		Source: goldenOther, TxHash: "hash-failed-send",
		From: goldenOther, To: goldenMine,
		Amount: "0.0000000", AssetType: "native",
		DestinationMin: "6.5000000",
		SourceAmount:   "7.0000000", SrcAssetType: "credit_alphanum4", SrcAssetCode: "USDC", SrcAssetIssuer: goldenIssuer,
		CreatedAt: "2026-08-30T12:05:00Z",
		Tx:        &txJoin{Hash: "hash-failed-send", Successful: false, MemoType: "none", FeeCharged: 100, FeeAccount: goldenOther, Ledger: 1234},
	}

	// 6. Account merge sent: the whole balance moved, but the amount is not in
	// the operation record — entire_balance marks it, no amount anywhere.
	merge := opRec{
		ID: "6", Type: "account_merge", TypeI: typeAccountMerge,
		Source: goldenMine, TxHash: "hash-merge",
		Account: goldenMine, Into: goldenOther,
		CreatedAt: "2026-08-30T12:04:00Z",
		Tx:        &txJoin{Hash: "hash-merge", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: goldenMine, Ledger: 1234},
	}

	// 7. Received payment of an issued asset.
	usdc := opRec{
		ID: "7", Type: "payment", TypeI: typePayment,
		Source: goldenOther, TxHash: "hash-usdc",
		From: goldenOther, To: goldenMine,
		Amount: "12.5000000", AssetType: "credit_alphanum4", AssetCode: "USDC", AssetIssuer: goldenIssuer,
		CreatedAt: "2026-08-30T12:03:00Z",
		Tx:        &txJoin{Hash: "hash-usdc", Successful: true, MemoType: "none", FeeCharged: 100, FeeAccount: goldenOther, Ledger: 1234},
	}

	// 8. Dust payment whose text memo is a spreadsheet formula.
	formula := payment("8", goldenOther, goldenMine, "0.0000001", "hash-formula")
	formula.CreatedAt = "2026-08-30T12:02:00Z"
	formula.Tx.MemoType, formula.Tx.Memo = "text", goldenFormulaMemo

	// 9. Hash-memo payment: Horizon sends the memo base64-encoded.
	hashMemo := payment("9", goldenOther, goldenMine, "3.0000000", "hash-memo-hash")
	hashMemo.CreatedAt = "2026-08-30T12:01:00Z"
	hashMemo.Tx.MemoType, hashMemo.Tx.Memo = "hash", base64.StdEncoding.EncodeToString(goldenMemoRaw())

	f := newHorizonFake(t)
	f.servePages(paymentsPath(goldenMine), map[string]string{
		"": pageJSON("", []string{
			recv.JSON(t), sent.JSON(t), selfConvert.JSON(t), failedRecv.JSON(t),
			failedSend.JSON(t), merge.JSON(t), usdc.JSON(t), formula.JSON(t), hashMemo.JSON(t),
		}),
	})
	return f
}

// checkGolden compares got byte-for-byte against testdata/name; -update
// rewrites the file instead.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test ./internal/cli -update to regenerate)", path, err)
	}
	if !bytes.Equal([]byte(got), want) {
		t.Errorf("output differs from %s (run -update after verifying the change is intended)\ngot:\n%s\nwant:\n%s", path, got, want)
	}
}

// strictDecimal is the amount contract: 7 fractional digits, no sign, no
// exponent — the only shape the formats may emit for money.
var strictDecimal = regexp.MustCompile(`^[0-9]+\.[0-9]{7}$`)

// TestHistoryGoldenJSON pins the --json bytes and, independently of the
// golden file, the semantic invariants of every line — so regenerating with
// -update can never enshrine wrong output.
func TestHistoryGoldenJSON(t *testing.T) {
	f := goldenHistoryFake(t)
	out, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), goldenMine, "--failed", "--json")...)
	checkGolden(t, "history_json.golden", out)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 9 {
		t.Fatalf("got %d JSON lines, want 9", len(lines))
	}
	byID := make(map[string]map[string]any)
	var order []string
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i+1, err, line)
		}
		for _, k := range []string{"id", "paging_token", "created_at", "type", "direction", "tx_hash"} {
			if s, _ := m[k].(string); s == "" {
				t.Errorf("line %d: required field %q missing or empty:\n%s", i+1, k, line)
			}
		}
		if _, ok := m["successful"].(bool); !ok {
			t.Errorf("line %d: required field \"successful\" missing or not a bool:\n%s", i+1, line)
		}
		for _, k := range []string{"amount", "source_amount", "source_max", "destination_min"} {
			if v, present := m[k]; present {
				s, ok := v.(string)
				if !ok || !strictDecimal.MatchString(s) {
					t.Errorf("line %d: %s = %v is not a strict 7-decimal string", i+1, k, v)
				}
			}
		}
		id, _ := m["id"].(string)
		byID[id] = m
		order = append(order, id)
	}
	// Page order (newest first) must be preserved.
	if want := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}; !slices.Equal(order, want) {
		t.Errorf("entry order = %v, want %v", order, want)
	}

	memo := func(m map[string]any) map[string]any { mm, _ := m["memo"].(map[string]any); return mm }
	asset := func(m map[string]any, k string) map[string]any { mm, _ := m[k].(map[string]any); return mm }
	has := func(m map[string]any, k string) bool { _, ok := m[k]; return ok }

	// 1: received, text memo verbatim.
	e := byID["1"]
	if e["direction"] != "received" || memo(e)["type"] != "text" || memo(e)["value"] != "thanks for lunch" {
		t.Errorf("entry 1 wrong: %v", e)
	}
	// 2: sent, muxed destination on the wire must reach the output.
	e = byID["2"]
	if e["direction"] != "sent" || e["to_muxed"] != goldenOtherMuxed {
		t.Errorf("entry 2: to_muxed = %v, want %s", e["to_muxed"], goldenOtherMuxed)
	}
	if memo(e)["type"] != "id" || memo(e)["value"] != "3141592653" {
		t.Errorf("entry 2 memo wrong: %v", memo(e))
	}
	// 3: self conversion books both legs with exact amounts.
	e = byID["3"]
	if e["direction"] != "self" {
		t.Errorf("entry 3 direction = %v, want self", e["direction"])
	}
	if e["amount"] != "98.7654321" || asset(e, "asset")["code"] != "USDC" || asset(e, "asset")["issuer"] != goldenIssuer {
		t.Errorf("entry 3 destination leg wrong: %v", e)
	}
	if e["source_amount"] != "100.0000000" || asset(e, "source_asset")["type"] != "native" {
		t.Errorf("entry 3 source leg wrong: %v", e)
	}
	// 4: failed strict receive — the fixed destination amount stays (exact,
	// envelope-declared; successful=false says it never moved), the
	// execution-determined source leg carries only its bound: the wire's
	// "0.0000000" placeholder must never surface as source_amount.
	e = byID["4"]
	if e["successful"] != false || e["source_max"] != "20.0000000" {
		t.Errorf("entry 4 wrong: %v", e)
	}
	if e["amount"] != "17.5000000" || asset(e, "asset")["code"] != "USDC" {
		t.Errorf("entry 4 must keep the fixed destination amount: %v", e)
	}
	if has(e, "source_amount") {
		t.Errorf("entry 4 must not carry source_amount (a placeholder is not an amount): %v", e)
	}
	// 5: failed strict send — the fixed source amount stays, the destination
	// leg carries only destination_min: the wire's "0.0000000" amount
	// placeholder must never surface.
	e = byID["5"]
	if e["destination_min"] != "6.5000000" || asset(e, "asset")["type"] != "native" {
		t.Errorf("entry 5 wrong: %v", e)
	}
	if e["source_amount"] != "7.0000000" {
		t.Errorf("entry 5 must keep the fixed source amount: %v", e)
	}
	if has(e, "amount") {
		t.Errorf("entry 5 must not carry amount (a placeholder is not an amount): %v", e)
	}
	// 6: merge — entire_balance, no amount and no asset anywhere.
	e = byID["6"]
	if e["entire_balance"] != true {
		t.Errorf("entry 6 entire_balance = %v, want true", e["entire_balance"])
	}
	if has(e, "amount") || has(e, "asset") || has(e, "source_amount") || has(e, "source_max") || has(e, "destination_min") {
		t.Errorf("entry 6 must carry no amount or asset field: %v", e)
	}
	// 7: issued asset with its full issuer.
	e = byID["7"]
	if asset(e, "asset")["code"] != "USDC" || asset(e, "asset")["issuer"] != goldenIssuer {
		t.Errorf("entry 7 asset wrong: %v", e)
	}
	// 8: JSON memo is the exact bytes — the CSV guard must not leak in.
	e = byID["8"]
	if memo(e)["value"] != goldenFormulaMemo {
		t.Errorf("entry 8 memo = %q, want unguarded %q", memo(e)["value"], goldenFormulaMemo)
	}
	// 9: hash memo normalized from Horizon's base64 to canonical hex.
	e = byID["9"]
	wantHex := hex.EncodeToString(goldenMemoRaw())
	if memo(e)["type"] != "hash" || memo(e)["value"] != wantHex {
		t.Errorf("entry 9 memo = %v, want hash %s", memo(e), wantHex)
	}
	if v, _ := memo(e)["value"].(string); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(v) {
		t.Errorf("entry 9 memo value %q is not 64 hex digits", v)
	}
}

// TestHistoryGoldenCSV pins the --csv bytes and the invariants that make the
// export safe to open in a spreadsheet.
func TestHistoryGoldenCSV(t *testing.T) {
	f := goldenHistoryFake(t)
	out, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), goldenMine, "--failed", "--csv")...)
	checkGolden(t, "history_csv.golden", out)

	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("output does not parse back as CSV: %v", err)
	}
	if len(rows) != 10 {
		t.Fatalf("got %d CSV rows, want header + 9", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Fatalf("header has %d columns, want %d", len(rows[0]), len(csvHeader))
	}
	col := make(map[string]int)
	for i, name := range rows[0] {
		if name != csvHeader[i] {
			t.Errorf("header column %d = %q, want %q", i, name, csvHeader[i])
		}
		col[name] = i
	}
	byID := make(map[string][]string)
	for i, row := range rows[1:] {
		if len(row) != len(csvHeader) {
			t.Errorf("row %d has %d cells, want %d", i+1, len(row), len(csvHeader))
			continue
		}
		byID[row[col["id"]]] = row
		// No cell of any row may start like a formula: memo cells are guarded
		// and nothing else may drift into a guardable shape unnoticed.
		for j, cell := range row {
			if cell != "" && strings.ContainsAny(cell[:1], "=+-@\t") {
				t.Errorf("row %d column %q cell %q starts like a spreadsheet formula", i+1, csvHeader[j], cell)
			}
		}
	}

	// 2: the muxed destination has its own column.
	if got := byID["2"][col["to_muxed"]]; got != goldenOtherMuxed {
		t.Errorf("entry 2 to_muxed = %q, want %q", got, goldenOtherMuxed)
	}
	// 3: a self conversion fills both amount column pairs.
	row := byID["3"]
	if row[col["amount"]] != "98.7654321" || row[col["asset"]] != "USDC:"+goldenIssuer ||
		row[col["source_amount"]] != "100.0000000" || row[col["source_asset"]] != "native" {
		t.Errorf("entry 3 amount cells wrong: %v", row)
	}
	// 4: failed strict receive — the fixed destination amount stays (exact,
	// with successful=false in its own column), while the source cells stay
	// empty: neither the wire's "0.0000000" placeholder nor the SourceMax
	// bound may land where a SUM would eat them.
	row = byID["4"]
	if row[col["amount"]] != "17.5000000" || row[col["asset"]] != "USDC:"+goldenIssuer {
		t.Errorf("entry 4 must keep the fixed destination amount: %v", row)
	}
	if row[col["source_amount"]] != "" || row[col["source_asset"]] != "" {
		t.Errorf("entry 4 source cells not empty (bounds and placeholders are not amounts): %v", row)
	}
	if strings.Contains(out, "20.0000000") {
		t.Errorf("the failed operation's bound 20.0000000 leaked into the CSV")
	}
	for id, r := range byID {
		for _, k := range []string{"amount", "source_amount"} {
			if r[col[k]] == "0.0000000" {
				t.Errorf("entry %s %s is the wire placeholder 0.0000000 — placeholders are not amounts", id, k)
			}
		}
	}
	if got := byID["4"][col["successful"]]; got != "false" {
		t.Errorf("entry 4 successful = %q, want false", got)
	}
	// 5: failed strict send — the exact source leg stays, the destination
	// amount cells stay empty.
	row = byID["5"]
	if row[col["amount"]] != "" || row[col["asset"]] != "" {
		t.Errorf("entry 5 destination amount cells not empty: %v", row)
	}
	if row[col["source_amount"]] != "7.0000000" || row[col["source_asset"]] != "USDC:"+goldenIssuer {
		t.Errorf("entry 5 source leg wrong: %v", row)
	}
	// 6: a merge writes no amount at all.
	row = byID["6"]
	for _, k := range []string{"amount", "asset", "source_amount", "source_asset"} {
		if row[col[k]] != "" {
			t.Errorf("entry 6 %s = %q, want empty (merged amount is not in the record)", k, row[col[k]])
		}
	}
	// 7: issued assets always carry the full issuer, never the bare code.
	if got := byID["7"][col["asset"]]; got != "USDC:"+goldenIssuer {
		t.Errorf("entry 7 asset = %q, want the full CODE:ISSUER form", got)
	}
	// 8: the formula memo cell carries the leading-apostrophe guard.
	if got := byID["8"][col["memo"]]; got != "'"+goldenFormulaMemo {
		t.Errorf("entry 8 memo cell = %q, want guarded %q", got, "'"+goldenFormulaMemo)
	}
}

// TestHistoryGoldenText pins the human listing's bytes plus the lines whose
// wording carries the money semantics.
func TestHistoryGoldenText(t *testing.T) {
	f := goldenHistoryFake(t)
	out, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), goldenMine, "--failed")...)
	checkGolden(t, "history_text.golden", out)

	for _, want := range []string{
		"Account: " + goldenMine,
		"History (newest first):",
		"received  25.0000000 XLM  (payment)",
		"converted  100.0000000 XLM -> 98.7654321 USDC  (path payment)",
		"sent  ≤ 20.0000000 XLM  (path payment)  [FAILED — no funds moved]",
		"received  ≥ 6.5000000 XLM  (path payment)  [FAILED — no funds moved]",
		"sent  entire balance  (account merge)",
		"To (muxed):   " + goldenOtherMuxed,
		`Memo: text "thanks for lunch"`,
		"Memo: id 3141592653",
		"Memo: hash " + hex.EncodeToString(goldenMemoRaw()),
		"9 entries shown.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing missing %q:\n%s", want, out)
		}
	}
}

// TestCSVGuard pins the guard character set: exactly the prefixes
// spreadsheets execute, and nothing else — guarding a plain amount would
// corrupt the export it is meant to protect.
func TestCSVGuard(t *testing.T) {
	cases := []struct{ in, want string }{
		{"=x", "'=x"},
		{"+x", "'+x"},
		{"-x", "'-x"},
		{"@x", "'@x"},
		{"\tx", "'\tx"},
		{"x=", "x="},
		{"", ""},
		{"25.0000000", "25.0000000"},
	}
	for _, tt := range cases {
		if got := csvGuard(tt.in); got != tt.want {
			t.Errorf("csvGuard(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestHistoryMachineFormatsEmpty: an empty history is a complete, valid
// result — empty JSONL, a header-only CSV, and no human banner in either.
func TestHistoryMachineFormatsEmpty(t *testing.T) {
	f := newHorizonFake(t)
	f.servePages(paymentsPath(goldenMine), map[string]string{"": pageJSON("", nil)})

	out, _ := runHistoryOK(t, f.URL(), historyArgs(f.URL(), goldenMine, "--json")...)
	if out != "" {
		t.Errorf("--json stdout for an empty history = %q, want empty", out)
	}

	out, _ = runHistoryOK(t, f.URL(), historyArgs(f.URL(), goldenMine, "--csv")...)
	if want := strings.Join(csvHeader, ",") + "\n"; out != want {
		t.Errorf("--csv stdout for an empty history = %q, want the bare header %q", out, want)
	}
}

// TestHistoryCSVErrorLeavesStdoutEmpty: a failed walk must not emit even the
// header — a partial machine-readable stream must not look complete.
func TestHistoryCSVErrorLeavesStdoutEmpty(t *testing.T) {
	f := newHorizonFake(t)
	f.serveError(paymentsPath(goldenMine), 500)

	app, out, _ := newTestApp("", nil)
	if code := app.run(historyArgs(f.URL(), goldenMine, "--csv")); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a failed walk", out.String())
	}
}

// TestAssetSpecString: exports name assets unambiguously — the full issuer,
// never a forgeable bare code; a zero asset renders as nothing.
func TestAssetSpecString(t *testing.T) {
	cases := []struct {
		in   base.Asset
		want string
	}{
		{base.Asset{Type: "native"}, "native"},
		{base.Asset{Type: "credit_alphanum4", Code: "USDC", Issuer: goldenIssuer}, "USDC:" + goldenIssuer},
		{base.Asset{}, ""},
	}
	for _, tt := range cases {
		if got := assetSpecString(tt.in); got != tt.want {
			t.Errorf("assetSpecString(%+v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestJSONEncoderNoHTMLEscape: memo bytes must survive verbatim — Go's
// default encoder would rewrite < & > as \u003c \u0026 \u003e.
func TestJSONEncoderNoHTMLEscape(t *testing.T) {
	e := historyEntry{Memo: &entryMemo{Type: "text", Value: "<&>"}}
	var buf bytes.Buffer
	if err := newJSONEncoder(&buf).Encode(toJSONEntry(e)); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(buf.String(), `"value":"<&>"`) {
		t.Errorf("memo value not verbatim in %q", buf.String())
	}
	if strings.Contains(buf.String(), `\u`) {
		t.Errorf("output %q contains escaped characters", buf.String())
	}
}
