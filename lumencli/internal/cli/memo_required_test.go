package cli

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lumencli/internal/wallet"
)

// fakeHorizon serves just enough of the account endpoint to drive the
// destination-side memo check. memoRequired controls whether the account
// carries the SEP-0029 data entry.
func fakeHorizon(t *testing.T, address string, memoRequired bool) *httptest.Server {
	t.Helper()
	data := "{}"
	if memoRequired {
		data = fmt.Sprintf(`{"config.memo_required": %q}`, base64.StdEncoding.EncodeToString([]byte("1")))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/accounts/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/hal+json")
		fmt.Fprintf(w, `{
			"id": %q, "account_id": %q, "sequence": "1",
			"balances": [{"balance": "100.0000000", "asset_type": "native"}],
			"data": %s
		}`, address, address, data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sendArgs targets the fake Horizon while keeping IsTestnet true, so the
// mainnet spend confirmation stays out of the way and the memo guard is the
// only gate under test.
func sendArgs(srv *httptest.Server, dest string, extra ...string) []string {
	return append([]string{
		"send", "--network", "testnet", "--horizon-url", srv.URL,
		"--to", dest, "--amount", "10",
	}, extra...)
}

// TestSendRefusesMemolessToDeclaredDestination is the headline behaviour: a
// destination that declares it needs a memo must stop a memo-less send, and
// must do so before the secret is read.
func TestSendRefusesMemolessToDeclaredDestination(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := fakeHorizon(t, kp.Address(), true)

	app, _, errb := newTestApp("", nil)
	if code := app.run(sendArgs(srv, kp.Address())); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	es := errb.String()
	for _, want := range []string{"WARNING", "carries no memo", "SEP-0029", "refusing", "--no-memo"} {
		if !strings.Contains(es, want) {
			t.Errorf("stderr missing %q:\n%s", want, es)
		}
	}
	if strings.Contains(es, "Signing from") {
		t.Errorf("read the secret despite the missing memo:\n%s", es)
	}
}

// TestSendYesDoesNotBypassMemoGuard is the crux of "explicit confirmation":
// --yes already appears in every non-interactive script, so it must not double
// as consent to send without a memo.
func TestSendYesDoesNotBypassMemoGuard(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := fakeHorizon(t, kp.Address(), true)

	app, _, errb := newTestApp("", nil)
	if code := app.run(sendArgs(srv, kp.Address(), "--yes")); code != 1 {
		t.Fatalf("--yes bypassed the memo guard: exit code = %d, want 1", code)
	}
	if es := errb.String(); !strings.Contains(es, "refusing") {
		t.Errorf("stderr %q missing the refusal", es)
	}
}

// TestSendNoMemoFlagOverrides confirms the dedicated override does let the
// transfer through — past the guard and on to the (unfaked) signing path.
func TestSendNoMemoFlagOverrides(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := fakeHorizon(t, kp.Address(), true)

	app, _, errb := newTestApp("", nil)
	code := app.run(sendArgs(srv, kp.Address(), "--no-memo"))
	es := errb.String()
	if !strings.Contains(es, "--no-memo was given") {
		t.Errorf("stderr %q does not record the override", es)
	}
	// It proceeded past the guard: the next step asks for the secret, which
	// this app has no way to supply.
	if !strings.Contains(es, "no secret provided") {
		t.Errorf("did not proceed past the memo guard (exit %d):\n%s", code, es)
	}
}

// TestSendWithMemoSkipsTheGuard: supplying a memo is the whole point, and must
// not trigger the warning.
func TestSendWithMemoSkipsTheGuard(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := fakeHorizon(t, kp.Address(), true)

	app, _, errb := newTestApp("", nil)
	app.run(sendArgs(srv, kp.Address(), "--memo-type", "id", "--memo", "42"))
	if es := errb.String(); strings.Contains(es, "WARNING") {
		t.Errorf("warned despite a memo being supplied:\n%s", es)
	}
}

// TestSendUndeclaredDestinationIsUnaffected: an ordinary destination that
// declares nothing must behave exactly as before.
func TestSendUndeclaredDestinationIsUnaffected(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := fakeHorizon(t, kp.Address(), false)

	app, _, errb := newTestApp("", nil)
	app.run(sendArgs(srv, kp.Address()))
	if es := errb.String(); strings.Contains(es, "WARNING") {
		t.Errorf("warned about a destination that declares no requirement:\n%s", es)
	}
}

// TestSendReportsUnreachableCheck: when the destination check cannot be made,
// the send proceeds — but says so, rather than reading like a clean bill of
// health.
func TestSendReportsUnreachableCheck(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"type":"server_error"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	app, _, errb := newTestApp("", nil)
	app.run(sendArgs(srv, kp.Address()))
	es := errb.String()
	if !strings.Contains(es, "could not check whether") {
		t.Errorf("stderr %q does not report the failed check", es)
	}
	if !strings.Contains(es, "no secret provided") {
		t.Errorf("a failed check blocked the send instead of proceeding with a notice:\n%s", es)
	}
}
