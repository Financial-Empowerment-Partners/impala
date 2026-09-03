package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"impalactl/internal/config"
)

// authed returns a harness pre-seeded with valid credentials for its stub.
func authed(t *testing.T, stdin string, handler http.Handler) *harness {
	t.Helper()
	h := newHarness(t, stdin, handler)
	h.seedCredentials(t, &config.Credentials{
		AccountID:     "alice",
		Role:          "admin",
		TemporalToken: token(t, "alice", "admin", time.Hour),
		RefreshToken:  "refresh",
	})
	return h
}

// ── account ────────────────────────────────────────────────────────────

const testStellarID = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

func TestAccountShowRendersRecord(t *testing.T) {
	rec := &recorder{response: `{
		"payala_account_id":"alice","stellar_account_id":"` + testStellarID + `",
		"first_name":"Ada","middle_name":"B","last_name":"Lovelace","nickname":null,
		"affiliation":"Analytical Engines","gender":null,"role":"admin",
		"sync_mode":"reserve","profile_source":"ldap",
		"profile_synced_at":"2026-08-01T00:00:00Z","created_at":"2026-01-01T00:00:00Z"}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "show", testStellarID); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.path != "/account" || rec.query != "stellar_account_id="+testStellarID {
		t.Errorf("request = %s?%s", rec.path, rec.query)
	}
	out := h.stdout()
	for _, want := range []string{"alice", "Ada B Lovelace", "Analytical Engines", "admin", "reserve", "ldap"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
	// Absent optional fields render as a dash, not as "<nil>" or empty.
	if !strings.Contains(out, "Nickname:") || strings.Contains(out, "<nil>") {
		t.Errorf("optional field rendering = %q", out)
	}
}

func TestAccountShowValidatesLocally(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "show", "alice"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if rec.calls != 0 {
		t.Error("a malformed Stellar id was sent to the bridge")
	}
	if !strings.Contains(h.stderr(), "56 characters") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestAccountCreateSendsProfile(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Account created successfully"}`}
	h := authed(t, "", rec.handler())

	code := h.run("account", "create",
		"--stellar", testStellarID, "--account", "alice",
		"--first-name", "Ada", "--last-name", "Lovelace", "--affiliation", "AE")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.method != http.MethodPost || rec.path != "/account" {
		t.Errorf("request = %s %s", rec.method, rec.path)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(rec.body), &body); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if body["stellar_account_id"] != testStellarID || body["payala_account_id"] != "alice" {
		t.Errorf("body = %v", body)
	}
	if body["first_name"] != "Ada" || body["last_name"] != "Lovelace" || body["affiliation"] != "AE" {
		t.Errorf("body = %v", body)
	}
	// Unset optional fields are omitted, not sent as empty strings.
	for _, absent := range []string{"middle_name", "nickname", "gender"} {
		if _, present := body[absent]; present {
			t.Errorf("empty %s was serialized", absent)
		}
	}
}

func TestAccountCreateRequiresNames(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())

	code := h.run("account", "create", "--stellar", testStellarID, "--account", "alice", "--first-name", "Ada")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if rec.calls != 0 {
		t.Error("an incomplete profile was sent to the bridge")
	}
}

func TestAccountGenerateDefaultsToTheLoggedInAccount(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Managed account created successfully","stellar_account_id":"` + testStellarID + `"}`}
	h := authed(t, "", rec.handler())

	code := h.run("account", "generate", "--first-name", "Ada", "--last-name", "Lovelace")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["payala_account_id"] != "alice" {
		t.Errorf("payala_account_id = %v, want the logged-in account", body["payala_account_id"])
	}
	if !strings.Contains(h.stdout(), testStellarID) {
		t.Errorf("output = %q, want the new address", h.stdout())
	}
}

func TestAccountImportReadsSeedFromStdin(t *testing.T) {
	const seed = "SBLGRLAOWPJPQEBVZLPZUAJDQJZBZHY6QSMFXVDF2YAV5NM7QOMPLDBM"
	rec := &recorder{response: `{"success":true,"message":"Managed account imported successfully","stellar_account_id":"` + testStellarID + `"}`}
	h := authed(t, seed+"\n", rec.handler())

	code := h.run("account", "import", "--account", "alice", "--first-name", "Ada", "--last-name", "Lovelace")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["secret_seed"] != seed {
		t.Errorf("secret_seed = %v", body["secret_seed"])
	}
	// The seed must never be echoed back to the operator's terminal.
	if strings.Contains(h.stdout()+h.stderr(), seed) {
		t.Error("the secret seed appeared in the CLI output")
	}
}

func TestAccountImportRejectsMalformedSeed(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "not-a-seed\n", rec.handler())

	code := h.run("account", "import", "--account", "alice", "--first-name", "Ada", "--last-name", "Lovelace")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if rec.calls != 0 {
		t.Error("a malformed seed was sent to the bridge")
	}
}

func TestAccountListRendersTableAndFooter(t *testing.T) {
	rec := &recorder{response: `{"data":[
		{"payala_account_id":"alice","stellar_account_id":"` + testStellarID + `","first_name":"Ada",
		 "last_name":"Lovelace","middle_name":null,"nickname":null,"affiliation":null,"gender":null,
		 "role":"admin","sync_mode":"reserve","profile_source":"local","created_at":"2026-01-01T00:00:00Z"}],
		"page":2,"per_page":1,"total":3}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "list", "--page", "2", "--per-page", "1", "--search", "ada"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.query != "page=2&per_page=1&search=ada" {
		t.Errorf("query = %q", rec.query)
	}
	out := h.stdout()
	if !strings.Contains(out, "PAYALA ID") || !strings.Contains(out, "alice") {
		t.Errorf("table = %q", out)
	}
	if !strings.Contains(out, "Showing 1 of 3 accounts (page 2 of 3)") {
		t.Errorf("footer = %q", out)
	}
}

func TestAccountListEmpty(t *testing.T) {
	rec := &recorder{response: `{"data":[],"page":1,"per_page":20,"total":0}`}
	h := authed(t, "", rec.handler())
	if code := h.run("account", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stdout(), "No accounts found.") {
		t.Errorf("output = %q", h.stdout())
	}
}

func TestAccountReservesDefaultsToTheLoggedInAccount(t *testing.T) {
	rec := &recorder{response: `{"account_id":"alice","sync_mode":"reserve","reserves":[
		{"currency":"USD","balance":-1500,"updated_at":"2026-08-01T00:00:00Z"}]}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "reserves"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.path != "/reserves/alice" {
		t.Errorf("path = %q", rec.path)
	}
	if !strings.Contains(h.stdout(), "-1500") {
		t.Errorf("output = %q", h.stdout())
	}
}

func TestAccountOnchainRendersBalances(t *testing.T) {
	rec := &recorder{response: `{"stellar_account_id":"` + testStellarID + `","exists":true,
		"sequence":"12345","native_balance":"100.5","subentry_count":2,
		"balances":[{"asset_type":"native","balance":"100.5"},
		            {"asset_type":"credit_alphanum4","asset_code":"USDC","asset_issuer":"` + testStellarID + `","balance":"25"}],
		"signers":[{"key":"` + testStellarID + `","weight":1,"type":"ed25519_public_key"}]}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "onchain", testStellarID); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	out := h.stdout()
	for _, want := range []string{"XLM", "USDC", "100.5", "Signers:", "ed25519_public_key"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

// ── sync ───────────────────────────────────────────────────────────────

func TestSyncForceRequiresAStellarAddress(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())

	// /sync names its field account_id but validates it as a G-address; the
	// CLI should say so rather than forwarding a Payala id.
	if code := h.run("sync", "force", "alice"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if rec.calls != 0 {
		t.Error("a Payala id was sent to /sync")
	}
	if !strings.Contains(h.stderr(), "Stellar address") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestSyncForce(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Sync timestamp recorded","timestamp":"2026-08-07T12:00:00.000000Z"}`}
	h := authed(t, "", rec.handler())

	if code := h.run("sync", "force", testStellarID); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.method != http.MethodPost || rec.path != "/sync" {
		t.Errorf("request = %s %s", rec.method, rec.path)
	}
	if !strings.Contains(h.stdout(), "2026-08-07T12:00:00.000000Z") {
		t.Errorf("output = %q", h.stdout())
	}
}

func TestSyncProfile(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Profile synced from LDAP","profile_source":"ldap",
		"profile_synced_at":"2026-08-07T12:00:00Z",
		"profile":{"first_name":"Ada","middle_name":null,"last_name":"Lovelace","affiliation":"AE"}}`}
	h := authed(t, "", rec.handler())

	if code := h.run("sync", "profile", "alice"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.path != "/admin/accounts/alice/sync-profile" {
		t.Errorf("path = %q", rec.path)
	}
	if !strings.Contains(h.stdout(), "Lovelace") {
		t.Errorf("output = %q", h.stdout())
	}
}

func TestSyncModeValidatesLocally(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())

	if code := h.run("sync", "mode", "alice", "--mode", "sideways"); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if rec.calls != 0 {
		t.Error("an invalid sync mode was sent to the bridge")
	}
}

func TestSyncModeSendsForce(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Sync mode updated","account_id":"alice","sync_mode":"mirror"}`}
	h := authed(t, "", rec.handler())

	if code := h.run("sync", "mode", "alice", "--mode", "mirror", "--force"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.method != http.MethodPut || rec.path != "/admin/accounts/alice/sync-mode" {
		t.Errorf("request = %s %s", rec.method, rec.path)
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["force"] != true || body["sync_mode"] != "mirror" {
		t.Errorf("body = %v", body)
	}
}

const syncResponse = `{"success":true,"message":"Sync batch applied","batch_id":"b-1","sync_mode":"reserve",
	"received":2,"applied":2,"duplicates":0,"conflicting":0,
	"net_deltas":{"USD":-1300},"reserve_balances":[{"currency":"USD","balance":-1300,"updated_at":null}]}`

func TestSyncPayalaFromFile(t *testing.T) {
	rec := &recorder{response: syncResponse}
	h := authed(t, "", rec.handler())

	path := filepath.Join(t.TempDir(), "batch.json")
	batch := `[{"payala_tx_id":"tx1","amount":-1500,"currency":"USD","memo":"coffee"},
	           {"payala_tx_id":"tx2","amount":200,"currency":"USD"}]`
	if err := os.WriteFile(path, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := h.run("sync", "payala", "--file", path); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.path != "/sync/payala" {
		t.Errorf("path = %q", rec.path)
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["account_id"] != "alice" {
		t.Errorf("account_id = %v, want the logged-in account", body["account_id"])
	}
	if items, ok := body["transactions"].([]any); !ok || len(items) != 2 {
		t.Fatalf("transactions = %v", body["transactions"])
	}
	out := h.stdout()
	if !strings.Contains(out, "Applied:") || !strings.Contains(out, "-1300") {
		t.Errorf("output = %q", out)
	}
}

func TestSyncPayalaFromStdinWithFullRequest(t *testing.T) {
	rec := &recorder{response: syncResponse}
	batch := `{"account_id":"bob","transactions":[{"payala_tx_id":"tx1","amount":-1500,"currency":"USD"}]}`
	h := newHarness(t, batch, rec.handler())
	// No --account: the id in the file is used as-is.
	h.env[config.EnvToken] = token(t, "alice", "admin", time.Hour)

	if code := h.run("sync", "payala", "--file", "-"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["account_id"] != "bob" {
		t.Errorf("account_id = %v, want the value from the file", body["account_id"])
	}
}

func TestSyncPayalaAccountPrecedence(t *testing.T) {
	// An explicit --account overrides the file; the file overrides the
	// logged-in default (covered by TestSyncPayalaFromStdinWithFullRequest).
	rec := &recorder{response: syncResponse}
	batch := `{"account_id":"bob","transactions":[{"payala_tx_id":"tx1","amount":-1500,"currency":"USD"}]}`
	h := authed(t, batch, rec.handler())

	if code := h.run("sync", "payala", "--file", "-", "--account", "carol"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["account_id"] != "carol" {
		t.Errorf("account_id = %v, want the --account value", body["account_id"])
	}
}

func TestSyncPayalaRejectsUnknownFields(t *testing.T) {
	rec := &recorder{response: syncResponse}
	h := authed(t, "", rec.handler())

	path := filepath.Join(t.TempDir(), "batch.json")
	// `payala_txid` is a typo for `payala_tx_id`; accepting it silently would
	// submit a batch with an empty transaction id.
	if err := os.WriteFile(path, []byte(`[{"payala_txid":"tx1","amount":-1500,"currency":"USD"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := h.run("sync", "payala", "--file", path); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if rec.calls != 0 {
		t.Error("a batch with an unknown field was submitted")
	}
	if !strings.Contains(h.stderr(), "payala_txid") {
		t.Errorf("stderr = %q, want the offending field named", h.stderr())
	}
}

func TestSyncPayalaWarnsAboutConflictingReplays(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Sync batch applied","batch_id":"b-1","sync_mode":"mirror",
		"received":2,"applied":1,"duplicates":1,"conflicting":1,"net_deltas":{},"reserve_balances":[]}`}
	h := authed(t, "", rec.handler())

	path := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(path, []byte(`[{"payala_tx_id":"tx1","amount":1,"currency":"USD"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	if code := h.run("sync", "payala", "--file", path, "--json"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	// The integrity warning must reach stderr even when stdout is JSON being
	// piped into another tool.
	if !strings.Contains(h.stderr(), "different amount or currency") {
		t.Errorf("stderr = %q, want the conflicting-replay warning", h.stderr())
	}
}

func TestSyncPayalaRequiresAFile(t *testing.T) {
	h := authed(t, "", nil)
	if code := h.run("sync", "payala"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// ── transfer ───────────────────────────────────────────────────────────

// transferMux serves /network plus /managed-account/sign, recording the sign
// request.
func transferMux(network string, rec *recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"stellar_network":     network,
			"stellar_horizon_url": "https://horizon.example.com",
			"stellar_rpc_url":     "https://rpc.example.com",
			"network_passphrase":  "passphrase",
		})
	})
	rec.response = `{"success":true,"message":"Payment signed and submitted","stellar_hash":"abc123","btxid":"b-1"}`
	mux.Handle("POST /managed-account/sign", rec.handler())
	return mux
}

func TestTransferSendRefusesUnconfirmedOnPubnet(t *testing.T) {
	rec := &recorder{}
	h := authed(t, "", transferMux("pubnet", rec))

	code := h.run("transfer", "send", "--to", testStellarID, "--amount", "10.5")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if rec.calls != 0 {
		t.Error("a pubnet payment was submitted without confirmation")
	}
	if !strings.Contains(h.stderr(), "--yes") {
		t.Errorf("stderr = %q, want the --yes hint", h.stderr())
	}
	// The operator must always be able to see which network was at stake.
	if !strings.Contains(h.stderr(), "PUBNET") {
		t.Errorf("stderr = %q, want the network named", h.stderr())
	}
}

func TestTransferSendProceedsWithYes(t *testing.T) {
	rec := &recorder{}
	h := authed(t, "", transferMux("pubnet", rec))

	code := h.run("transfer", "send", "--to", testStellarID, "--amount", "10.5", "--memo", "rent", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["destination"] != testStellarID || body["amount"] != "10.5" || body["memo"] != "rent" {
		t.Errorf("body = %v", body)
	}
	if body["payala_account_id"] != "alice" {
		t.Errorf("payala_account_id = %v", body["payala_account_id"])
	}
	if _, present := body["fee"]; present {
		t.Error("an unset fee was serialized")
	}
	if !strings.Contains(h.stdout(), "abc123") {
		t.Errorf("output = %q, want the transaction hash", h.stdout())
	}
}

func TestTransferSendOnTestnetNeedsNoConfirmation(t *testing.T) {
	rec := &recorder{}
	h := authed(t, "", transferMux("testnet", rec))

	code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.calls != 1 {
		t.Errorf("sign calls = %d, want 1", rec.calls)
	}
}

func TestTransferSendValidatesAmountAndDestination(t *testing.T) {
	for _, tc := range []struct{ name, to, amount string }{
		{"bad destination", "alice", "1"},
		{"non-numeric amount", testStellarID, "ten"},
		{"zero amount", testStellarID, "0.0"},
		{"too much precision", testStellarID, "1.123456789"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			h := authed(t, "", transferMux("testnet", rec))
			if code := h.run("transfer", "send", "--to", tc.to, "--amount", tc.amount, "--yes"); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if rec.calls != 0 {
				t.Error("an invalid payment was submitted")
			}
		})
	}
}

func TestTransferSendSendsFeeWhenGiven(t *testing.T) {
	rec := &recorder{}
	h := authed(t, "", transferMux("testnet", rec))

	if code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1", "--fee", "500"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["fee"] != float64(500) {
		t.Errorf("fee = %v, want 500", body["fee"])
	}
}

func TestTransferRecordRequiresATransactionID(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())

	if code := h.run("transfer", "record", "--memo", "orphan"); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if rec.calls != 0 {
		t.Error("a transaction with no id was submitted")
	}
}

func TestTransferRecord(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Transaction created successfully","btxid":"b-9"}`}
	h := authed(t, "", rec.handler())

	code := h.run("transfer", "record",
		"--payala-tx-id", "ptx1", "--source-account", testStellarID,
		"--payala-currency", "USD", "--stellar-fee", "0", "--memo", "kiosk")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["payala_tx_id"] != "ptx1" || body["payala_currency"] != "USD" {
		t.Errorf("body = %v", body)
	}
	// An explicit zero fee is meaningful and must survive; an unset one is not sent.
	if body["stellar_fee"] != float64(0) {
		t.Errorf("stellar_fee = %v, want 0", body["stellar_fee"])
	}
	if _, present := body["stellar_max_fee"]; present {
		t.Error("an unset stellar_max_fee was serialized")
	}
	if !strings.Contains(h.stdout(), "b-9") {
		t.Errorf("output = %q", h.stdout())
	}
}

// ── activity ───────────────────────────────────────────────────────────

func TestActivityListRendersTable(t *testing.T) {
	rec := &recorder{response: `{"data":[{"btxid":"b-1","stellar_tx_id":null,"payala_tx_id":"ptx1",
		"stellar_hash":null,"source_account":"` + testStellarID + `","stellar_fee":null,"stellar_max_fee":null,
		"memo":"a very long memo that should be clipped in the table output","payala_currency":"USD",
		"payala_amount":-1500,"origin":"payala_sync","created_at":"2026-08-01T00:00:00Z",
		"flagged":true,"status":"escalated","note":"check","reviewed_by":"alice","reviewed_at":"2026-08-02T00:00:00Z"}],
		"page":1,"per_page":20,"total":1}`}
	h := authed(t, "", rec.handler())

	code := h.run("activity", "list", "--status", "escalated", "--flagged", "true", "--search", "memo")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.query != "flagged=true&q=memo&status=escalated" {
		t.Errorf("query = %q", rec.query)
	}
	out := h.stdout()
	for _, want := range []string{"BTXID", "b-1", "escalated", "payala_sync", "-1500", "USD"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
	if !strings.Contains(out, "…") {
		t.Errorf("long memo was not clipped: %q", out)
	}
	// The full btxid must stay copy-pasteable into `activity show`.
	if !strings.Contains(out, "b-1") {
		t.Errorf("btxid was mangled: %q", out)
	}
}

func TestActivityListRejectsInvalidFilters(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := authed(t, "", rec.handler())
	if code := h.run("activity", "list", "--status", "bogus"); code != 2 {
		t.Errorf("invalid status exit = %d, want 2", code)
	}

	h2 := authed(t, "", rec.handler())
	if code := h2.run("activity", "list", "--flagged", "maybe"); code != 2 {
		t.Errorf("invalid flagged exit = %d, want 2", code)
	}
	if rec.calls != 0 {
		t.Error("an invalid filter was sent to the bridge")
	}
}

func TestActivityShow(t *testing.T) {
	rec := &recorder{response: `{"btxid":"b-1","stellar_tx_id":"stx","payala_tx_id":null,"stellar_hash":"deadbeef",
		"source_account":"` + testStellarID + `","stellar_fee":100,"stellar_max_fee":200,"memo":"kiosk",
		"signatures":null,"preconditions":null,"payala_currency":null,"payala_digest":null,"payala_amount":null,
		"origin":"api","created_at":"2026-08-01T00:00:00Z","flagged":false,"status":"unreviewed",
		"note":null,"reviewed_by":null,"reviewed_at":null}`}
	h := authed(t, "", rec.handler())

	if code := h.run("activity", "show", "b-1"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.path != "/transaction/b-1" {
		t.Errorf("path = %q", rec.path)
	}
	out := h.stdout()
	for _, want := range []string{"deadbeef", "kiosk", "unreviewed", "100"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestActivityReviewSendsFullState(t *testing.T) {
	rec := &recorder{response: `{"success":true,"message":"Review updated successfully","btxid":"b-1","flagged":true,"status":"escalated"}`}
	h := authed(t, "", rec.handler())

	code := h.run("activity", "review", "b-1", "--status", "escalated", "--flagged", "--note", "suspicious")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.method != http.MethodPut || rec.path != "/transaction/b-1/review" {
		t.Errorf("request = %s %s", rec.method, rec.path)
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["flagged"] != true || body["status"] != "escalated" || body["note"] != "suspicious" {
		t.Errorf("body = %v", body)
	}
}

func TestActivityReviewAlwaysSendsFlagged(t *testing.T) {
	// The endpoint replaces the whole review record, so an omitted flag would
	// silently clear it; sending it explicitly keeps the stored state honest.
	rec := &recorder{response: `{"success":true,"message":"Review updated successfully","btxid":"b-1","flagged":false,"status":"cleared"}`}
	h := authed(t, "", rec.handler())

	if code := h.run("activity", "review", "b-1", "--status", "cleared"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if flagged, present := body["flagged"]; !present || flagged != false {
		t.Errorf("body = %v, want an explicit flagged:false", body)
	}
}

func TestActivityEventsPrintsNextCursor(t *testing.T) {
	rec := &recorder{response: `{"events":[
		{"id":7,"event_type":"account.created","account_id":"alice","payload":{"stellar_account_id":"GA"},"created_at":"2026-08-01T00:00:00Z"},
		{"id":9,"event_type":"transaction.created","account_id":"bob","payload":{"btxid":"b-1"},"created_at":"2026-08-02T00:00:00Z"}]}`}
	h := authed(t, "", rec.handler())

	if code := h.run("activity", "events", "--since", "3", "--limit", "50"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.query != "limit=50&since=3" {
		t.Errorf("query = %q", rec.query)
	}
	out := h.stdout()
	if !strings.Contains(out, "account.created") || !strings.Contains(out, "transaction.created") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "--since 9") {
		t.Errorf("output = %q, want the next cursor", out)
	}
}

func TestActivityEventsEmpty(t *testing.T) {
	rec := &recorder{response: `{"events":[]}`}
	h := authed(t, "", rec.handler())
	if code := h.run("activity", "events"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stdout(), "No events.") {
		t.Errorf("output = %q", h.stdout())
	}
}

// ── health and error rendering ─────────────────────────────────────────

func TestHealthDegradedExitsNonZero(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"degraded","database":"ok","redis":"error","stellar_network":"testnet"}`))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"impala-bridge","version":"0.0.0","build_date":"today","rustc_version":"1.91","schema_version":"1.0.3"}`))
	})
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stellar_network":"testnet","stellar_horizon_url":"h","stellar_rpc_url":"r","network_passphrase":"p"}`))
	})

	h := newHarness(t, "", mux)
	if code := h.run("health"); code != 1 {
		t.Fatalf("degraded health exit = %d, want 1", code)
	}
	out := h.stdout()
	for _, want := range []string{"degraded", "impala-bridge 0.0.0", "1.0.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestHealthNeedsNoCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["Authorization"]; present {
			t.Error("health sent an Authorization header")
		}
		w.Write([]byte(`{"status":"healthy","database":"ok","redis":"ok","stellar_network":"testnet"}`))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })

	h := newHarness(t, "", mux) // no credentials seeded
	if code := h.run("health"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
}

func TestServerErrorsAreReported(t *testing.T) {
	rec := &recorder{
		status:   http.StatusForbidden,
		response: `{"error":{"code":"forbidden","message":"Access denied"}}`,
	}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "[403 forbidden] Access denied") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if h.stdout() != "" {
		t.Errorf("stdout = %q, want it empty on failure", h.stdout())
	}
}

func TestJSONOutputIsVerbatim(t *testing.T) {
	// Fields this CLI doesn't model must survive --json untouched.
	rec := &recorder{response: `{"payala_account_id":"alice","stellar_account_id":"` + testStellarID + `",
		"first_name":"Ada","last_name":"Lovelace","role":"admin","sync_mode":"reserve",
		"profile_source":"local","future_field":"kept"}`}
	h := authed(t, "", rec.handler())

	if code := h.run("account", "show", testStellarID, "--json"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stdout(), `"future_field": "kept"`) {
		t.Errorf("output = %q, want the unmodelled field preserved", h.stdout())
	}
}

func TestTransferSendRejectsOutOfRangeFee(t *testing.T) {
	// The wire field is uint32; an unchecked conversion wraps silently, so a
	// fat-fingered fee would be sent as a different number than the operator
	// saw at the prompt.
	rec := &recorder{}
	h := authed(t, "", transferMux("testnet", rec))

	if code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1", "--fee", "4294967296"); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if rec.calls != 0 {
		t.Error("a payment with an out-of-range fee was submitted")
	}
}

func TestTransferSendAcceptsMaxFee(t *testing.T) {
	rec := &recorder{}
	h := authed(t, "", transferMux("testnet", rec))

	if code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1", "--fee", "4294967295"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var body map[string]any
	json.Unmarshal([]byte(rec.body), &body)
	if body["fee"] != float64(4294967295) {
		t.Errorf("fee = %v, want 4294967295", body["fee"])
	}
}

func TestCleartextEndpointIsRefused(t *testing.T) {
	// Guards the whole CLI, not just login: the bearer token rides every call.
	h := newHarness(t, "", nil)
	h.env[config.EnvEndpoint] = "http://bridge.internal.example.com:8080"
	h.env[config.EnvToken] = token(t, "alice", "admin", time.Hour)

	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "plain HTTP") {
		t.Errorf("stderr = %q, want the cleartext refusal", h.stderr())
	}
}

func TestCleartextEndpointAllowedWithOptIn(t *testing.T) {
	rec := &recorder{response: `{"data":[],"page":1,"per_page":20,"total":0}`}
	h := newHarness(t, "", rec.handler())
	h.env[config.EnvToken] = token(t, "alice", "admin", time.Hour)

	// The stub is on loopback, so exercise the opt-in path via the flag: it
	// must not interfere with an otherwise valid request.
	if code := h.run("account", "list", "--insecure-http"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.calls != 1 {
		t.Errorf("calls = %d, want 1", rec.calls)
	}
}

// ── transfer send: ambiguous outcomes ──────────────────────────────────

// transferMuxWith serves /network (testnet, so no confirmation prompt) plus
// a scripted /managed-account/sign.
func transferMuxWith(sign http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"stellar_network": "testnet", "stellar_horizon_url": "https://horizon.example.com",
			"stellar_rpc_url": "https://rpc.example.com", "network_passphrase": "passphrase",
		})
	})
	mux.HandleFunc("POST /managed-account/sign", sign)
	return mux
}

// envelope answers with the bridge's error envelope.
func envelope(status int, code, message string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, message)
	}
}

// ambiguityWording is what the notice must say — and what a definitive
// failure must never say.
var ambiguityWording = []string{"outcome of this payment is UNKNOWN", "MAY HAVE BEEN SUBMITTED", "DO NOT re-run"}

// TestTransferSendAmbiguousOutcomesExitThree is the double-spend guard: a
// timeout, a dropped connection, or a 5xx from the sign endpoint must not
// read as "not sent". The notice names the payment and the checks to make,
// and the exit code is distinct so a script cannot retry on it.
func TestTransferSendAmbiguousOutcomesExitThree(t *testing.T) {
	cases := []struct {
		name    string
		sign    http.HandlerFunc
		args    []string
		errText string // what the leading error line must contain
	}{
		{"bridge 504 with envelope", envelope(http.StatusGatewayTimeout, "gateway_timeout", "upstream timed out"), nil, "[504 gateway_timeout]"},
		{"bridge 500 internal_error (its ambiguous Horizon submit)", envelope(http.StatusInternalServerError, "internal_error", "transaction signing failed"), nil, "[500 internal_error]"},
		{"bridge 408 from its request deadline, empty body", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusRequestTimeout)
		}, nil, "[408 http_error] Request Timeout"},
		{"proxy 502 html", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "<html>502 Bad Gateway</html>")
		}, nil, "[502 http_error]"},
		{"hang past the client timeout", func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body) // the server watches for the client leaving only once the body is read
			<-r.Context().Done()
		}, []string{"--timeout", "200ms"}, "/managed-account/sign"},
		{"connection dropped mid-response", func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close()
		}, nil, "/managed-account/sign"},
		{"2xx that is not the expected JSON", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html>ok?</html>")
		}, nil, "decode response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := authed(t, "", transferMuxWith(tc.sign))
			args := append([]string{"transfer", "send", "--to", testStellarID, "--amount", "10.5", "--memo", "rent"}, tc.args...)

			start := time.Now()
			code := h.run(args...)
			if time.Since(start) > 10*time.Second {
				t.Fatalf("command took %s", time.Since(start))
			}
			if code != exitAmbiguous {
				t.Fatalf("exit = %d, want %d\nstderr:\n%s", code, exitAmbiguous, h.stderr())
			}
			if h.stdout() != "" {
				t.Errorf("stdout = %q, want it empty on an unknown outcome", h.stdout())
			}
			es := h.stderr()
			if !strings.Contains(es, "error: ") || !strings.Contains(es, tc.errText) {
				t.Errorf("stderr does not lead with the underlying error %q:\n%s", tc.errText, es)
			}
			for _, want := range append(ambiguityWording,
				"From:    alice", "To:      "+testStellarID, "Amount:  10.5 XLM",
				"impalactl activity list", "impalactl activity show <btxid>", "impalactl account onchain",
				"300 seconds", "300-second window",
			) {
				if !strings.Contains(es, want) {
					t.Errorf("stderr missing %q:\n%s", want, es)
				}
			}
		})
	}
}

// TestTransferSendDefinitiveFailuresExitOne: verdicts that prove nothing
// happened stay plain exit-1 failures with none of the ambiguity wording —
// a script must be able to retry a 503 or fix a 400 without a manual check.
func TestTransferSendDefinitiveFailuresExitOne(t *testing.T) {
	cases := []struct {
		name    string
		sign    http.HandlerFunc
		errText string
	}{
		{"503 service_unavailable: the bridge's pre-submit Retryable", envelope(http.StatusServiceUnavailable, "service_unavailable", "transaction preparation failed before submission"), "[503 service_unavailable]"},
		{"400 bad_request", envelope(http.StatusBadRequest, "bad_request", "invalid destination address"), "[400 bad_request]"},
		{"403 forbidden", envelope(http.StatusForbidden, "forbidden", "Access denied"), "[403 forbidden]"},
		{"429 rate_limited", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "12")
			envelope(http.StatusTooManyRequests, "rate_limited", "Too many requests, please try again later")(w, r)
		}, "[429 rate_limited]"},
		{"200 success:false", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"success":false,"message":"Stellar transaction rejected: {\"transaction\":\"tx_bad_seq\"}"}`)
		}, "tx_bad_seq"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := authed(t, "", transferMuxWith(tc.sign))
			if code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1"); code != 1 {
				t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, h.stderr())
			}
			es := h.stderr()
			if !strings.Contains(es, tc.errText) {
				t.Errorf("stderr missing %q:\n%s", tc.errText, es)
			}
			for _, absent := range ambiguityWording {
				if strings.Contains(es, absent) {
					t.Errorf("a definitive failure carries the ambiguity wording %q:\n%s", absent, es)
				}
			}
		})
	}
}

// TestTransferSendConnectionRefusedIsPlain: when no connection could be
// made, nothing was sent, and the failure is an ordinary one.
func TestTransferSendConnectionRefusedIsPlain(t *testing.T) {
	h := authed(t, "", transferMuxWith(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request reached a server that was supposed to be closed")
	}))
	h.srv.Close() // nothing listens on the port any more; the stored credentials still name it

	// /network is unreachable too, so the CLI treats the network as live and
	// needs --yes; that path must still classify the sign failure correctly.
	if code := h.run("transfer", "send", "--to", testStellarID, "--amount", "1", "--yes"); code != 1 {
		t.Fatalf("exit = %d, want 1\nstderr:\n%s", code, h.stderr())
	}
	es := h.stderr()
	if !strings.Contains(es, "connection refused") {
		t.Errorf("stderr does not report the dial failure:\n%s", es)
	}
	for _, absent := range ambiguityWording {
		if strings.Contains(es, absent) {
			t.Errorf("a never-connected failure carries the ambiguity wording %q:\n%s", absent, es)
		}
	}
}

// TestDefaultTimeoutExceedsBridgeDeadline pins the relationship the timeout
// comment promises: the client must outlast the bridge's own deadline by a
// margin, or it cuts the bridge off just as the verdict is being written.
func TestDefaultTimeoutExceedsBridgeDeadline(t *testing.T) {
	if defaultTimeout < bridgeRequestDeadline+10*time.Second {
		t.Errorf("defaultTimeout %s does not clear the bridge's %s deadline by 10s", defaultTimeout, bridgeRequestDeadline)
	}
	h := newHarness(t, "", nil)
	h.run("help")
	if !strings.Contains(h.stdout(), "(default "+defaultTimeout.String()+")") {
		t.Errorf("help does not state the default timeout %s:\n%s", defaultTimeout, h.stdout())
	}
}
