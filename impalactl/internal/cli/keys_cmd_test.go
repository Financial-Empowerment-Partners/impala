package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyStub routes the three calls a key command makes: the credential listing,
// the network lookup, and the mutation. It records the mutation body so the
// tests can assert exactly what the CLI decided to send — which is the point,
// because the confirmation rules are the feature.
type keyStub struct {
	listing  string
	network  string
	response string
	status   int

	mutations int
	lastPath  string
	lastBody  string
}

func (s *keyStub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/admin/keys" && req.Method == http.MethodGet:
			w.Write([]byte(s.listing))
		case req.URL.Path == "/network":
			network := s.network
			if network == "" {
				network = "testnet"
			}
			w.Write([]byte(`{"stellar_network":"` + network + `","stellar_horizon_url":"h","stellar_network_passphrase":"p"}`))
		default:
			body := new(bytes.Buffer)
			body.ReadFrom(req.Body)
			s.mutations++
			s.lastPath = req.URL.Path
			s.lastBody = body.String()
			if s.status != 0 {
				w.WriteHeader(s.status)
			}
			w.Write([]byte(s.response))
		}
	}
}

// listing builds a GET /admin/keys body for one credential kind.
func listing(t *testing.T, enabled bool, view map[string]any) string {
	t.Helper()
	base := map[string]any{
		"kind":                  "changelly_crypto",
		"parts":                 []string{"api_key", "private_key"},
		"required_parts":        []string{"api_key", "private_key"},
		"effective_source":      "unconfigured",
		"active":                false,
		"env_vars_set":          []string{},
		"per_part_fingerprints": map[string]string{},
		"pending_restart":       false,
		"in_flight_count":       0,
		"history":               []any{},
	}
	for k, v := range view {
		base[k] = v
	}
	// The bridge derives this from the stored row, falling back to whatever is
	// running; mirror that here so the fixture cannot drift from the contract.
	if _, ok := base["replace_target_fingerprint"]; !ok {
		if stored, ok := base["stored_fingerprint"]; ok {
			base["replace_target_fingerprint"] = stored
		} else if eff, ok := base["effective_fingerprint"]; ok {
			base["replace_target_fingerprint"] = eff
		}
	}
	body, err := json.Marshal(map[string]any{
		"enabled":            enabled,
		"protection_backend": "kms",
		"degraded":           false,
		"keys":               []any{base},
	})
	if err != nil {
		t.Fatalf("marshal listing: %v", err)
	}
	return string(body)
}

const okAction = `{"success":true,"message":"stored","kind":"changelly_crypto",` +
	`"version":1,"set_fingerprint":"newfp","effective_after":"rolling_restart"}`

func TestKeysImportAddsWhenNothingIsInEffect(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, nil), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	if code := h.run("keys", "import", "changelly_crypto"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if stub.mutations != 1 || stub.lastPath != "/admin/keys/changelly_crypto" {
		t.Fatalf("mutation = %d %s", stub.mutations, stub.lastPath)
	}
	// An addition must not claim to be a replacement: the flag lands in the
	// bridge's audit event.
	if strings.Contains(stub.lastBody, `"replace"`) {
		t.Errorf("an add sent a replace flag: %s", stub.lastBody)
	}
	if !strings.Contains(stub.lastBody, "live-key") {
		t.Errorf("body missing the part: %s", stub.lastBody)
	}
}

func TestKeysImportRefusesToReplaceWithoutTheFlag(t *testing.T) {
	// The add-only default, measured against what is EFFECTIVE — here an
	// environment credential with no stored row at all.
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "env",
		"effective_fingerprint": "oldfp",
		"active":                true,
		"env_vars_set":          []string{"CHANGELLY_API_KEY"},
		"confirm_phrase":        "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	if code := h.run("keys", "import", "changelly_crypto"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("a replacement was sent without --replace")
	}
	if !strings.Contains(h.stderr(), "already exists") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestKeysImportRefusesNonInteractiveReplaceWithoutThePhrase(t *testing.T) {
	// --yes waives the interactive prompt, not the operator's statement of
	// what they are replacing.
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "db",
		"effective_fingerprint": "oldfp",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	if code := h.run("keys", "import", "changelly_crypto", "--replace", "--yes"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("a replacement was sent without a confirmation phrase")
	}
	if !strings.Contains(h.stderr(), "replace changelly_crypto pubnet") {
		t.Errorf("stderr should name the required phrase: %q", h.stderr())
	}
}

func TestKeysImportRejectsAPhraseForTheWrongNetwork(t *testing.T) {
	// The commonest operator error is the right key in the wrong environment,
	// and the network inside the phrase is the only place it is caught.
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "db",
		"effective_fingerprint": "oldfp",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	code := h.run("keys", "import", "changelly_crypto", "--replace",
		"--confirm-phrase", "replace changelly_crypto testnet", "--yes")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("a mismatched phrase reached the bridge")
	}
}

func TestKeysImportSendsTheCompareAndSwapToken(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "db",
		"effective_fingerprint": "oldfp",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	code := h.run("keys", "import", "changelly_crypto", "--replace",
		"--confirm-phrase", "replace changelly_crypto pubnet", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(stub.lastBody), &sent); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if sent["replace"] != true {
		t.Error("replace flag not sent")
	}
	// The fingerprint comes from the bridge's own answer, never from a value
	// the operator typed or the client composed.
	if sent["expected_fingerprint"] != "oldfp" {
		t.Errorf("expected_fingerprint = %v", sent["expected_fingerprint"])
	}
	if sent["confirm_phrase"] != "replace changelly_crypto pubnet" {
		t.Errorf("confirm_phrase = %v", sent["confirm_phrase"])
	}
}

func TestKeysImportRefusesWhileOrdersAreInFlight(t *testing.T) {
	// Re-pointing at a different provider account makes every in-flight
	// provider reference unreachable, stranding anything already sent.
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "db",
		"effective_fingerprint": "oldfp",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
		"in_flight_count":       4,
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	code := h.run("keys", "import", "changelly_crypto", "--replace",
		"--confirm-phrase", "replace changelly_crypto pubnet", "--yes")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("a replacement was sent while orders were in flight")
	}
	if !strings.Contains(h.stderr(), "stranded") {
		t.Errorf("stderr = %q", h.stderr())
	}

	// The acknowledgement flag lets it through, and is passed on.
	code = h.run("keys", "import", "changelly_crypto", "--replace",
		"--confirm-phrase", "replace changelly_crypto pubnet",
		"--strand-in-flight", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(stub.lastBody, `"strand_in_flight":true`) {
		t.Errorf("body = %s", stub.lastBody)
	}
}

func TestKeysImportReadsAMultiLinePemFromAFile(t *testing.T) {
	// A PEM cannot come through the prompt or the stdin fallback, both of
	// which read a single line — so --part-file is the only route for it.
	pem := "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	stub := &keyStub{listing: listing(t, true, nil), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"

	code := h.run("keys", "import", "changelly_crypto", "--part-file", "private_key="+path)
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(stub.lastBody), &sent); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	parts := sent["parts"].(map[string]any)
	if !strings.Contains(parts["private_key"].(string), "BEGIN PRIVATE KEY") {
		t.Errorf("pem not sent intact: %v", parts["private_key"])
	}
	// Newlines must survive; a PEM that lost them will not parse server-side.
	if !strings.Contains(parts["private_key"].(string), "\n") {
		t.Error("pem newlines were lost")
	}
}

func TestKeysImportRejectsAnUnknownPartFile(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, nil), response: okAction}
	h := authed(t, "", stub.handler())

	code := h.run("keys", "import", "changelly_crypto", "--part-file", "privat_key=/dev/null")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stub.mutations != 0 {
		t.Error("an unknown part reached the bridge")
	}
}

func TestKeysImportRefusesWhenTheFeatureIsOff(t *testing.T) {
	stub := &keyStub{listing: listing(t, false, nil), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	if code := h.run("keys", "import", "changelly_crypto"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("an import was attempted with the feature disabled")
	}
}

func TestKeysImportRejectsAnUnknownKind(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, nil), response: okAction}
	h := authed(t, "", stub.handler())

	if code := h.run("keys", "import", "changelly"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "unknown credential kind") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestKeysListShowsTheGapBetweenStoredAndRunning(t *testing.T) {
	stored := 3
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "env",
		"effective_fingerprint": "runningfp",
		"active":                true,
		"stored_fingerprint":    "storedfp",
		"stored_version":        stored,
		"stored_state":          "active",
		"pending_restart":       true,
		"env_vars_set":          []string{"CHANGELLY_API_KEY"},
	})}
	h := authed(t, "", stub.handler())

	if code := h.run("keys", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	out := h.stdout()
	for _, want := range []string{"runningfp", "storedfp", "roll the deployment", "CHANGELLY_API_KEY"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestKeysListWarnsWhenImportIsDisabled(t *testing.T) {
	stub := &keyStub{listing: listing(t, false, nil)}
	h := authed(t, "", stub.handler())

	if code := h.run("keys", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stdout(), "NOT in use") {
		t.Errorf("output = %q", h.stdout())
	}
}

func TestKeysRevokeRefusesWithNothingStored(t *testing.T) {
	// Revoke acts on the stored row; an environment credential is removed
	// from the deployment, not through this API.
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "env",
		"effective_fingerprint": "envfp",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())

	if code := h.run("keys", "revoke", "changelly_crypto", "--yes"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("revoke was sent with nothing stored")
	}
}

func TestKeysRevokeNamesTheFallbackBeforeConfirming(t *testing.T) {
	stored := 1
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":      "db",
		"effective_fingerprint": "storedfp",
		"stored_fingerprint":    "storedfp",
		"stored_version":        stored,
		"stored_state":          "active",
		"active":                true,
		"confirm_phrase":        "replace changelly_crypto pubnet",
		"env_vars_set":          []string{"CHANGELLY_API_KEY"},
	}), response: okAction}
	h := authed(t, "", stub.handler())

	code := h.run("keys", "revoke", "changelly_crypto",
		"--confirm-phrase", "replace changelly_crypto pubnet", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	// The surprise worth naming: revocation quietly hands the provider back to
	// an older environment key.
	if !strings.Contains(h.stderr(), "DIFFERENT key takes over") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if !strings.Contains(h.stderr(), "does NOT revoke the key at the provider") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if !strings.Contains(stub.lastBody, `"confirm_next_source":true`) {
		t.Errorf("body = %s", stub.lastBody)
	}
}

func TestSeedImportNeverTakesTheSeedFromArgv(t *testing.T) {
	// The seed is read from the environment, a no-echo prompt, or stdin —
	// argv is readable by every process on the machine.
	stub := &keyStub{listing: listing(t, true, nil),
		response: `{"success":true,"message":"stored","stellar_account_id":"G","effective_after":"immediately"}`}
	h := authed(t, "", stub.handler())

	if code := h.run("stellar-seed", "import", "--account", "svc"); code != 1 {
		t.Fatalf("exit = %d, want 1 (no seed supplied)", code)
	}
	if stub.mutations != 0 {
		t.Error("import proceeded with no seed")
	}
}

func TestSeedImportValidatesTheSeedLocally(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, nil), response: `{}`}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_SECRET_SEED"] = "not-a-seed"

	if code := h.run("stellar-seed", "import", "--account", "svc"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("a malformed seed was sent to the bridge")
	}
}

func TestSeedImportReplaceRequiresTheExpectedAddress(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, nil), response: `{}`}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_SECRET_SEED"] = strings.Repeat("A", 55) // shape-checked below
	h.env["IMPALA_SECRET_SEED"] = "S" + strings.Repeat("A", 55)

	if code := h.run("stellar-seed", "import", "--account", "svc", "--replace", "--yes"); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if stub.mutations != 0 {
		t.Error("a replacement was sent without the expected address")
	}
}

// A bare IMPALA_KEY_API_KEY meant the same thing for every provider, so an
// operator with one exported for Changelly who then ran an OwlPay import would
// submit the wrong credential without being asked — and neither side could
// detect it, because both values are well-formed opaque strings.
func TestPartEnvVarsAreNamespacedByKind(t *testing.T) {
	if partEnvName("changelly_crypto", "api_key") == partEnvName("owlpay", "api_key") {
		t.Fatal("two providers share an environment variable for the same part")
	}
	if got := partEnvName("owlpay", "webhook_secret"); got != "IMPALA_KEY_OWLPAY_WEBHOOK_SECRET" {
		t.Errorf("partEnvName = %q", got)
	}
}

func TestKeysImportIgnoresAnotherProvidersEnvVar(t *testing.T) {
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"kind":           "owlpay",
		"parts":          []string{"api_key", "webhook_secret"},
		"required_parts": []string{"api_key"},
	}), response: okAction}
	h := authed(t, "", stub.handler())
	// Exported for a DIFFERENT provider; must not be picked up here.
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "changelly-key"

	// No owlpay key available and stdin is empty, so the prompt fallback fails
	// rather than silently submitting the Changelly one.
	if code := h.run("keys", "import", "owlpay"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("another provider's credential was submitted")
	}
}

func TestKeysImportReplacesAStoredButNotRunningCredential(t *testing.T) {
	// The case that used to deadlock: imported, not yet activated. Nothing is
	// running from the database, but the stored row is what a replacement
	// supersedes — and what the server's compare-and-swap acts on.
	stored := 1
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":   "unconfigured",
		"active":             false,
		"stored_fingerprint": "storedfp",
		"stored_version":     stored,
		"stored_state":       "active",
		"pending_restart":    true,
		"confirm_phrase":     "replace changelly_crypto pubnet",
	}), response: okAction}
	h := authed(t, "", stub.handler())
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_API_KEY"] = "live-key"
	h.env["IMPALA_KEY_CHANGELLY_CRYPTO_PRIVATE_KEY"] = "deadbeef"

	// Without --replace it must refuse, even though nothing is running.
	if code := h.run("keys", "import", "changelly_crypto"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Fatal("a replacement was sent without --replace")
	}

	code := h.run("keys", "import", "changelly_crypto", "--replace",
		"--confirm-phrase", "replace changelly_crypto pubnet", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(stub.lastBody, `"expected_fingerprint":"storedfp"`) {
		t.Errorf("CAS token should be the stored row: %s", stub.lastBody)
	}
}

func TestKeysRevokeRefusesWhileOrdersAreInFlight(t *testing.T) {
	stored := 1
	stub := &keyStub{listing: listing(t, true, map[string]any{
		"effective_source":   "db",
		"stored_fingerprint": "storedfp",
		"stored_version":     stored,
		"stored_state":       "active",
		"active":             true,
		"confirm_phrase":     "replace changelly_crypto pubnet",
		"in_flight_count":    3,
	}), response: okAction}
	h := authed(t, "", stub.handler())

	code := h.run("keys", "revoke", "changelly_crypto",
		"--confirm-phrase", "replace changelly_crypto pubnet", "--yes")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if stub.mutations != 0 {
		t.Error("revoke was sent while orders were in flight")
	}

	code = h.run("keys", "revoke", "changelly_crypto",
		"--confirm-phrase", "replace changelly_crypto pubnet",
		"--strand-in-flight", "--yes")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(stub.lastBody, `"strand_in_flight":true`) {
		t.Errorf("body = %s", stub.lastBody)
	}
}

func TestPartFileFlagParsing(t *testing.T) {
	p := partFiles{}
	if err := p.Set("private_key=/tmp/k.pem"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if p["private_key"] != "/tmp/k.pem" {
		t.Errorf("parsed = %v", p)
	}
	for _, bad := range []string{"", "private_key", "=path", "name="} {
		if err := p.Set(bad); err == nil {
			t.Errorf("Set(%q) should fail", bad)
		}
	}
}
