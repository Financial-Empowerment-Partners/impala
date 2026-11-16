package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"impalactl/internal/config"
)

const (
	vecServerAddr = "GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR"
	vecCardAddr   = "GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF"
)

type sep10Stub struct {
	status   string
	toml     string
	tomlCode int
	role     string
	posts    int
	lastPath string
	lastBody map[string]any
}

func (s *sep10Stub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/sep10/signing-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(s.status))
	})
	mux.HandleFunc("POST /admin/sep10/signing-keys/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		s.posts++
		s.lastPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&s.lastBody)
		switch {
		case strings.HasSuffix(r.URL.Path, "/generate"):
			w.WriteHeader(201)
			w.Write([]byte(`{"version":3,"state":"pending","public_address":"` + vecCardAddr + `","fingerprint":"fp3"}`))
		case strings.HasSuffix(r.URL.Path, "/activate"):
			w.Write([]byte(`{"version":2,"state":"pending","activate_at":"2026-11-15T10:02:00+00:00"}`))
		default:
			w.Write([]byte(`{"version":1,"state":"revoked"}`))
		}
	})
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"stellar_network":"testnet","network_passphrase":"Test SDF Network ; September 2015"}`))
	})
	mux.HandleFunc("GET /.well-known/stellar.toml", func(w http.ResponseWriter, r *http.Request) {
		if s.tomlCode != 0 {
			w.WriteHeader(s.tomlCode)
			return
		}
		w.Write([]byte(s.toml))
	})
	mux.HandleFunc("GET /admin/accounts/{id}/cards", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cards":[{"card_id":"ea94fa5b0f6b2abc1626bc50c0bd5e17","active":true,` +
			`"created_at":"2026-11-12T10:00:00+00:00","deleted_at":null,"stellar_address":"` + vecCardAddr + `"},` +
			`{"card_id":"0011223344556677","active":false,"created_at":null,"deleted_at":"2026-11-13T00:00:00+00:00","stellar_address":null}]}`))
	})
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		role := s.role
		if role == "" {
			role = "view-only"
		}
		w.Write([]byte(`{"data":[{"payala_account_id":"bob-2","role":"admin"},{"payala_account_id":"bob","role":"` +
			role + `","allowlisted":false}],"page":1,"per_page":100,"total":2}`))
	})
	return mux
}

func statusJSON(network string, keys ...string) string {
	return `{"enabled":true,"home_domain":"127.0.0.1:8084","web_auth_endpoint":"http://127.0.0.1:8084/auth/sep10",` +
		`"network":"` + network + `","network_passphrase":"Test SDF Network ; September 2015","challenge_ttl_secs":300,` +
		`"registered_card_keys":4,"key_ring_live":true,"keys":[` + strings.Join(keys, ",") + `]}`
}

func keyJSON(version, state, address, fp, activateAt string, opened string) string {
	at := "null"
	if activateAt != "" {
		at = `"` + activateAt + `"`
	}
	return `{"version":` + version + `,"state":"` + state + `","public_address":"` + address +
		`","fingerprint":"` + fp + `","generated_by":"ops","generated_at":"2026-11-01T09:00:00+00:00",` +
		`"activate_at":` + at + `,"superseded_at":null,"revoked_at":null,"opened":` + opened + `}`
}

func sep10Harness(t *testing.T, s *sep10Stub) *harness {
	h := newHarness(t, "", s.handler())
	h.seedCredentials(t, &config.Credentials{AccountID: "ops",
		TemporalToken: token(t, "ops", "key-custodian", time.Hour), RefreshToken: "r"})
	return h
}

func twoKeys(opened string) string {
	return statusJSON("testnet",
		keyJSON("2", "pending", vecCardAddr, "fp2", "", opened),
		keyJSON("1", "active", vecServerAddr, "fp1", "2026-11-01T09:05:00+00:00", "true"))
}

// ── status ─────────────────────────────────────────────────────────────

func TestSep10StatusPrintsIdentifiersInFull(t *testing.T) {
	s := &sep10Stub{status: twoKeys("true")}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "status"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	for _, want := range []string{vecServerAddr, vecCardAddr, "fp1", "v2  pending", "127.0.0.1:8084", "Key ring:"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("status missing %q:\n%s", want, h.stdout())
		}
	}
}

func TestSep10StatusNoticesANoActiveKey(t *testing.T) {
	s := &sep10Stub{status: statusJSON("testnet", keyJSON("1", "pending", vecCardAddr, "fp", "", "true"))}
	h := sep10Harness(t, s)
	h.run("sep10", "status")
	if !strings.Contains(h.stdout(), "no signing key is active") {
		t.Errorf("stdout = %s", h.stdout())
	}
}

// ── activate / revoke: the typed phrase ────────────────────────────────

func TestSep10ActivateNeedsTheExactPhrase(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no phrase, non-interactive", nil},
		{"--yes does not stand in for it", []string{"--yes"}},
		{"wrong phrase", []string{"--confirm-phrase", "activate sep10-signing pubnet"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &sep10Stub{status: twoKeys("true")}
			h := sep10Harness(t, s)
			if code := h.run(append([]string{"sep10", "key", "activate", "2"}, tc.args...)...); code != 1 {
				t.Fatalf("exit = %d", code)
			}
			if s.posts != 0 {
				t.Error("activation sent without the phrase")
			}
			if !strings.Contains(h.stderr(), `"activate sep10-signing testnet"`) {
				t.Errorf("stderr does not name the phrase: %s", h.stderr())
			}
		})
	}
}

func TestSep10ActivateSendsTheCompareAndSetAndPhrase(t *testing.T) {
	s := &sep10Stub{status: twoKeys("true")}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "key", "activate", "2", "--confirm-phrase", "activate sep10-signing testnet"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if s.lastPath != "/admin/sep10/signing-keys/2/activate" {
		t.Errorf("path = %s", s.lastPath)
	}
	if s.lastBody["confirm_supersede"] != "fp1" || s.lastBody["confirm_phrase"] != "activate sep10-signing testnet" {
		t.Errorf("body = %v", s.lastBody)
	}
	if !strings.Contains(h.stderr(), "supersedes v1") || !strings.Contains(h.stdout(), "2026-11-15T10:02:00") {
		t.Errorf("stderr = %s stdout = %s", h.stderr(), h.stdout())
	}
}

func TestSep10ActivateFirstKeySupersedesNone(t *testing.T) {
	s := &sep10Stub{status: statusJSON("testnet", keyJSON("1", "pending", vecCardAddr, "fp", "", "null"))}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "key", "activate", "1", "--confirm-phrase", "activate sep10-signing testnet"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if s.lastBody["confirm_supersede"] != "none" {
		t.Errorf("body = %v", s.lastBody)
	}
}

func TestSep10ActivateRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		status, version, want string
	}{
		"not opened here": {twoKeys("false"), "2", "has not opened version 2"},
		"not pending":     {twoKeys("true"), "1", "only a pending key"},
		"unknown version": {twoKeys("true"), "9", "no SEP-10 signing key version 9"},
		"already scheduled": {statusJSON("testnet", keyJSON("2", "pending", vecCardAddr, "fp2",
			"2026-11-15T10:00:00+00:00", "true")), "2", "already scheduled"},
		"no usable network": {statusJSON("", keyJSON("2", "pending", vecCardAddr, "fp2", "", "true")), "2",
			"usable network name"},
		"two active keys": {statusJSON("testnet", keyJSON("3", "pending", vecCardAddr, "fp3", "", "true"),
			keyJSON("2", "active", vecCardAddr, "fp2", "x", "true"), keyJSON("1", "active", vecServerAddr, "fp1", "x", "true")),
			"3", "2 active keys"},
	} {
		t.Run(name, func(t *testing.T) {
			s := &sep10Stub{status: tc.status}
			h := sep10Harness(t, s)
			if code := h.run("sep10", "key", "activate", tc.version, "--confirm-phrase", "activate sep10-signing testnet"); code != 1 {
				t.Fatalf("exit = %d", code)
			}
			if s.posts != 0 || !strings.Contains(h.stderr(), tc.want) {
				t.Errorf("posts = %d stderr = %s", s.posts, h.stderr())
			}
		})
	}
}

func TestSep10RevokeTheActiveKeySaysSignInStops(t *testing.T) {
	s := &sep10Stub{status: twoKeys("true")}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "key", "revoke", "1"); code != 1 {
		t.Fatalf("exit without phrase = %d", code)
	}
	if !strings.Contains(h.stderr(), `"revoke sep10-signing testnet v1"`) || !strings.Contains(h.stderr(), "ACTIVE key") {
		t.Errorf("stderr = %s", h.stderr())
	}
	if code := h.run("sep10", "key", "revoke", "v1", "--confirm-phrase", "revoke sep10-signing testnet v1"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if s.lastPath != "/admin/sep10/signing-keys/1/revoke" || s.lastBody["confirm_phrase"] != "revoke sep10-signing testnet v1" {
		t.Errorf("path = %s body = %v", s.lastPath, s.lastBody)
	}
}

func TestSep10GeneratePrintsTheNewKey(t *testing.T) {
	s := &sep10Stub{status: twoKeys("true")}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "key", "generate"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stdout(), vecCardAddr) || !strings.Contains(h.stderr(), "sep10 key activate 3") {
		t.Errorf("stdout = %s stderr = %s", h.stdout(), h.stderr())
	}
}

// ── cards ──────────────────────────────────────────────────────────────

func TestSep10CardsNotesAPrivilegedAccount(t *testing.T) {
	s := &sep10Stub{role: "treasurer"}
	h := sep10Harness(t, s)
	if code := h.run("sep10", "cards", "bob"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	for _, want := range []string{"ea94fa5b0f6b2abc1626bc50c0bd5e17", vecCardAddr + " (SEP-10)", "privileged role", "deleted"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("missing %q:\n%s", want, h.stdout())
		}
	}
	s2 := &sep10Stub{role: "device"}
	h2 := sep10Harness(t, s2)
	h2.run("sep10", "cards", "bob")
	if strings.Contains(h2.stdout(), "privileged role") {
		t.Error("note shown for an unprivileged account")
	}
}

// The refused-role set must be exactly the roles holding any capability in
// the shared role/capability fixture (what auth::role_is_privileged tests).
func TestSep10RefusedRolesMatchTheSharedFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "impala-ui", "tests", "fixtures", "role-capabilities.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("shared fixture not available (%v)", err)
	}
	var fixture struct {
		Capabilities map[string][]string `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, roles := range fixture.Capabilities {
		for _, r := range roles {
			want[r] = true
		}
	}
	var got, exp []string
	for r := range sep10RefusedRoles {
		got = append(got, r)
	}
	for r := range want {
		exp = append(exp, r)
	}
	sort.Strings(got)
	sort.Strings(exp)
	if strings.Join(got, ",") != strings.Join(exp, ",") {
		t.Fatalf("refused roles %v, fixture's privileged roles %v", got, exp)
	}
}

// ── info ───────────────────────────────────────────────────────────────

func TestSep10Info(t *testing.T) {
	good := "NETWORK_PASSPHRASE = \"Test SDF Network ; September 2015\"\nSIGNING_KEY = \"" + vecServerAddr +
		"\"\nWEB_AUTH_ENDPOINT = \"http://10.0.2.2:8084/auth/sep10\"\n"
	t.Run("offered", func(t *testing.T) {
		h := newHarness(t, "", (&sep10Stub{toml: good}).handler())
		if code := h.run("sep10", "info"); code != 0 {
			t.Fatalf("exit = %d: %s", code, h.stderr())
		}
		for _, want := range []string{vecServerAddr, "10.0.2.2:8084", "--sep10-home-domain 10.0.2.2:8084"} {
			if !strings.Contains(h.stdout(), want) {
				t.Errorf("missing %q:\n%s", want, h.stdout())
			}
		}
	})
	for _, code := range []int{404, 503} {
		h := newHarness(t, "", (&sep10Stub{tomlCode: code}).handler())
		if exit := h.run("sep10", "info"); exit != 0 {
			t.Errorf("HTTP %d exit = %d: %s", code, exit, h.stderr())
		}
		if !strings.Contains(h.stdout(), "not offered") || h.stderr() != "" {
			t.Errorf("HTTP %d: stdout = %q stderr = %q", code, h.stdout(), h.stderr())
		}
	}
	h := newHarness(t, "", (&sep10Stub{toml: "NETWORK_PASSPHRASE = \"x\"\n"}).handler())
	if exit := h.run("sep10", "info"); exit != 0 || !strings.Contains(h.stdout(), "not offered") {
		t.Errorf("toml without keys: exit %d, %q", exit, h.stdout())
	}
	bad := strings.Replace(good, vecServerAddr, vecServerAddr[:55]+"A", 1)
	h = newHarness(t, "", (&sep10Stub{toml: bad}).handler())
	if exit := h.run("sep10", "info"); exit != 1 {
		t.Errorf("bad signing key exit = %d", exit)
	}
}

func TestNewGroupsListTheirSubcommandsAndHelpNamesThem(t *testing.T) {
	for _, group := range []string{"mfa", "sep10", "card"} {
		h := newHarness(t, "", nil)
		if code := h.run(group); code != 2 || !strings.Contains(h.stderr(), "impalactl "+group+" <subcommand>") {
			t.Errorf("%s: exit %d, %q", group, code, h.stderr())
		}
	}
	h := newHarness(t, "", nil)
	h.run("help")
	for _, want := range []string{"mfa step-up", "login --card", "sep10 key activate", "card info", "card setup",
		"card pin change", "card issuer generate", "IMPALA_TOTP_CODE", "IMPALA_CARD_PIN", "IMPALA_ISSUE_KMK",
		"IMPALA_CARD_MASTER_PIN", "IMPALA_HOLDER_TOKEN", "IMPALA_CARD_NEW_PIN"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("help lacks %q", want)
		}
	}
	if version != "0.3.0" {
		t.Errorf("version = %s", version)
	}
}
