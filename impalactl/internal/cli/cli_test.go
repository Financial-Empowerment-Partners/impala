package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"impalactl/internal/config"
)

// harness runs the CLI against buffers, a temporary credential store, and an
// optional stub bridge.
type harness struct {
	app *App
	out *bytes.Buffer
	err *bytes.Buffer
	env map[string]string
	dir string
	srv *httptest.Server
}

func newHarness(t *testing.T, stdin string, handler http.Handler) *harness {
	t.Helper()
	h := &harness{
		out: &bytes.Buffer{},
		err: &bytes.Buffer{},
		env: map[string]string{},
		dir: filepath.Join(t.TempDir(), "impalactl"),
	}
	h.env[config.EnvConfigDir] = h.dir
	if handler != nil {
		h.srv = httptest.NewServer(handler)
		t.Cleanup(h.srv.Close)
		h.env[config.EnvEndpoint] = h.srv.URL
	}
	h.app = &App{
		in:     strings.NewReader(stdin),
		out:    h.out,
		err:    h.err,
		getenv: func(key string) string { return h.env[key] },
	}
	return h
}

func (h *harness) run(args ...string) int { return h.app.run(args) }

func (h *harness) stdout() string { return h.out.String() }
func (h *harness) stderr() string { return h.err.String() }

// store returns a store over the harness's credential directory.
func (h *harness) store(t *testing.T) *config.Store {
	t.Helper()
	store, err := config.NewStore(h.app.getenv)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// seedCredentials writes credentials for the stub bridge as `login` would.
func (h *harness) seedCredentials(t *testing.T, creds *config.Credentials) {
	t.Helper()
	if creds.Endpoint == "" && h.srv != nil {
		creds.Endpoint = h.srv.URL
	}
	if err := h.store(t).Save(creds); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
}

// token builds an unsigned JWT with the given subject, role and expiry. The
// CLI only reads these claims locally; the stub bridge accepts any bearer.
func token(t *testing.T, sub, role string, expiresIn time.Duration) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"sub": sub, "role": role, "token_type": "temporal",
		"iat": time.Now().Unix(), "exp": time.Now().Add(expiresIn).Unix(),
		"jti": "jti", "fid": "fid", "iss": "impala-bridge", "aud": "impala-api",
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// jsonHandler serves a fixed JSON body for any request, recording the last one.
type recorder struct {
	calls    int
	method   string
	path     string
	query    string
	auth     string
	body     string
	status   int
	response string
}

func (r *recorder) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body := new(bytes.Buffer)
		body.ReadFrom(req.Body)
		r.calls++
		r.method, r.path, r.query = req.Method, req.URL.Path, req.URL.RawQuery
		r.auth = req.Header.Get("Authorization")
		r.body = body.String()
		if r.status != 0 {
			w.WriteHeader(r.status)
		}
		w.Write([]byte(r.response))
	}
}

// ── dispatch ───────────────────────────────────────────────────────────

func TestHelpExitsZero(t *testing.T) {
	h := newHarness(t, "", nil)
	if code := h.run("help"); code != 0 {
		t.Errorf("help exit = %d, want 0", code)
	}
	if !strings.Contains(h.stdout(), "command-line client for the Impala bridge API") {
		t.Errorf("help output = %q", h.stdout())
	}
}

func TestNoArgsPrintsUsageToStderr(t *testing.T) {
	h := newHarness(t, "", nil)
	if code := h.run(); code != 2 {
		t.Errorf("no-args exit = %d, want 2", code)
	}
	if h.stdout() != "" {
		t.Errorf("usage went to stdout: %q", h.stdout())
	}
	if !strings.Contains(h.stderr(), "Usage:") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t, "", nil)
	if code := h.run("version"); code != 0 {
		t.Errorf("version exit = %d", code)
	}
	if strings.TrimSpace(h.stdout()) != version {
		t.Errorf("version output = %q, want %q", h.stdout(), version)
	}
}

func TestUnknownCommandAndSubcommand(t *testing.T) {
	h := newHarness(t, "", nil)
	if code := h.run("nope"); code != 2 {
		t.Errorf("unknown command exit = %d, want 2", code)
	}
	h2 := newHarness(t, "", nil)
	if code := h2.run("account", "nope"); code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
	if !strings.Contains(h2.stderr(), "unknown subcommand") {
		t.Errorf("stderr = %q", h2.stderr())
	}
}

func TestSubcommandGroupsListTheirSubcommands(t *testing.T) {
	for _, group := range []string{"account", "sync", "transfer", "activity"} {
		h := newHarness(t, "", nil)
		if code := h.run(group); code != 2 {
			t.Errorf("%s with no subcommand exit = %d, want 2", group, code)
		}
		if !strings.Contains(h.stderr(), "impalactl "+group+" <subcommand>") {
			t.Errorf("%s usage = %q", group, h.stderr())
		}
	}
}

// ── flag placement ─────────────────────────────────────────────────────

func TestGlobalFlagsWorkBeforeAndAfterTheCommand(t *testing.T) {
	rec := &recorder{response: `{"status":"healthy","database":"ok","redis":"ok","stellar_network":"testnet"}`}
	mux := http.NewServeMux()
	mux.Handle("GET /health", rec.handler())
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })

	for _, args := range [][]string{
		{"--json", "health"},
		{"health", "--json"},
	} {
		h := newHarness(t, "", mux)
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v exit = %d: %s", args, code, h.stderr())
		}
		if !strings.Contains(h.stdout(), `"health"`) {
			t.Errorf("%v produced non-JSON output: %q", args, h.stdout())
		}
	}
}

// ── authentication ─────────────────────────────────────────────────────

func TestLoginStoresCredentials(t *testing.T) {
	temporal := token(t, "alice", "admin", time.Hour)
	var gotBody map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "Refresh token issued",
			"refresh_token": "refresh-1", "temporal_token": temporal,
		})
	})

	h := newHarness(t, "hunter2hunter2\n", mux)
	if code := h.run("login", "--username", "alice"); code != 0 {
		t.Fatalf("login exit = %d: %s", code, h.stderr())
	}
	if gotBody["username"] != "alice" || gotBody["password"] != "hunter2hunter2" {
		t.Errorf("token request = %v", gotBody)
	}
	if _, present := gotBody["refresh_token"]; present {
		t.Error("password login sent a refresh_token field")
	}

	creds, err := h.store(t).Load()
	if err != nil || creds == nil {
		t.Fatalf("Load = (%v, %v)", creds, err)
	}
	if creds.AccountID != "alice" || creds.Role != "admin" {
		t.Errorf("stored identity = %+v", creds)
	}
	if creds.TemporalToken != temporal || creds.RefreshToken != "refresh-1" {
		t.Error("stored token pair does not match the response")
	}
	if creds.Endpoint != h.srv.URL {
		t.Errorf("stored endpoint = %q, want %q", creds.Endpoint, h.srv.URL)
	}
	if !strings.Contains(h.stdout(), "alice") {
		t.Errorf("login output = %q", h.stdout())
	}
	// The password must not be echoed anywhere.
	if strings.Contains(h.stdout()+h.stderr(), "hunter2hunter2") {
		t.Error("the password appeared in the CLI output")
	}
}

func TestLoginTakesPasswordFromEnvironment(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["password"] != "from-env" {
			t.Errorf("password = %q, want the environment value", body["password"])
		}
		json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "ok",
			"refresh_token": "r", "temporal_token": token(t, "bob", "view-only", time.Hour),
		})
	})

	h := newHarness(t, "", mux)
	h.env[config.EnvPassword] = "from-env"
	if code := h.run("login", "bob"); code != 0 {
		t.Fatalf("login exit = %d: %s", code, h.stderr())
	}
}

func TestLoginFailureIsNotStored(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": false, "message": "Invalid credentials"})
	})

	h := newHarness(t, "wrong-password\n", mux)
	if code := h.run("login", "--username", "alice"); code != 1 {
		t.Fatalf("failed login exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "Invalid credentials") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if creds, _ := h.store(t).Load(); creds != nil {
		t.Error("credentials were stored despite a failed login")
	}
}

func TestCommandsRequireCredentials(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := newHarness(t, "", rec.handler())

	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "not logged in") {
		t.Errorf("stderr = %q, want a 'not logged in' hint", h.stderr())
	}
	if rec.calls != 0 {
		t.Error("an unauthenticated request was sent to the bridge")
	}
}

func TestCredentialsAreEndpointScoped(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := newHarness(t, "", rec.handler())
	h.seedCredentials(t, &config.Credentials{
		Endpoint:      "https://other-bridge.example.com",
		AccountID:     "alice",
		TemporalToken: token(t, "alice", "admin", time.Hour),
		RefreshToken:  "r",
	})

	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "other-bridge.example.com") {
		t.Errorf("stderr = %q, want the mismatch explained", h.stderr())
	}
	if rec.calls != 0 {
		t.Error("a token issued by another bridge was sent to this one")
	}
}

func TestExplicitTokenBypassesTheStore(t *testing.T) {
	rec := &recorder{response: `{"data":[],"page":1,"per_page":20,"total":0}`}
	h := newHarness(t, "", rec.handler())

	if code := h.run("account", "list", "--token", "explicit-token"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.auth != "Bearer explicit-token" {
		t.Errorf("Authorization = %q", rec.auth)
	}
}

func TestEnvironmentTokenIsUsed(t *testing.T) {
	rec := &recorder{response: `{"data":[],"page":1,"per_page":20,"total":0}`}
	h := newHarness(t, "", rec.handler())
	h.env[config.EnvToken] = "env-token"

	if code := h.run("account", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if rec.auth != "Bearer env-token" {
		t.Errorf("Authorization = %q", rec.auth)
	}
}

func TestExpiredTokenIsRefreshedAndPersisted(t *testing.T) {
	fresh := token(t, "alice", "admin", time.Hour)
	var refreshBody map[string]string
	var listAuth string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&refreshBody)
		json.NewEncoder(w).Encode(map[string]any{
			"success": true, "message": "Tokens issued",
			"refresh_token": "refresh-2", "temporal_token": fresh,
		})
	})
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		listAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"data":[],"page":1,"per_page":20,"total":0}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID:     "alice",
		TemporalToken: token(t, "alice", "admin", -time.Minute), // already expired
		RefreshToken:  "refresh-1",
	})

	if code := h.run("account", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if refreshBody["refresh_token"] != "refresh-1" {
		t.Errorf("refresh request = %v, want the stored refresh token", refreshBody)
	}
	if listAuth != "Bearer "+fresh {
		t.Error("the request did not carry the refreshed temporal token")
	}

	// Rotation is single-use server-side: the replacement must be on disk, or
	// the next invocation would replay a burned token and lose the family.
	creds, err := h.store(t).Load()
	if err != nil || creds == nil {
		t.Fatalf("Load = (%v, %v)", creds, err)
	}
	if creds.RefreshToken != "refresh-2" || creds.TemporalToken != fresh {
		t.Errorf("stored credentials were not updated: %+v", creds)
	}
}

func TestValidTokenIsNotRefreshed(t *testing.T) {
	refreshes := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		refreshes++
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[],"page":1,"per_page":20,"total":0}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID:     "alice",
		TemporalToken: token(t, "alice", "admin", time.Hour),
		RefreshToken:  "refresh-1",
	})

	if code := h.run("account", "list"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if refreshes != 0 {
		t.Errorf("a still-valid token was refreshed %d time(s)", refreshes)
	}
}

func TestRejectedRefreshClearsCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"code":"unauthorized","message":"Authentication required"}}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID:     "alice",
		TemporalToken: token(t, "alice", "admin", -time.Hour),
		RefreshToken:  "revoked",
	})

	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "impalactl login") {
		t.Errorf("stderr = %q, want it to point at login", h.stderr())
	}
	if creds, _ := h.store(t).Load(); creds != nil {
		t.Error("dead credentials were left on disk")
	}
}

func TestWhoamiIsOffline(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := newHarness(t, "", rec.handler())
	h.seedCredentials(t, &config.Credentials{
		AccountID:     "alice",
		Role:          "admin",
		TemporalToken: token(t, "alice", "admin", 30*time.Minute),
		RefreshToken:  "r",
	})

	if code := h.run("whoami"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	out := h.stdout()
	for _, want := range []string{"alice", "admin", "temporal", h.srv.URL} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami output %q missing %q", out, want)
		}
	}
	if rec.calls != 0 {
		t.Error("whoami contacted the bridge; it should read the local token only")
	}
}

func TestWhoamiWithoutCredentials(t *testing.T) {
	h := newHarness(t, "", nil)
	if code := h.run("whoami"); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestLogoutRevokesAndForgets(t *testing.T) {
	var logoutAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		logoutAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"success":true,"message":"Token revoked successfully"}`))
	})

	temporal := token(t, "alice", "admin", time.Hour)
	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{AccountID: "alice", TemporalToken: temporal, RefreshToken: "r"})

	if code := h.run("logout"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if logoutAuth != "Bearer "+temporal {
		t.Errorf("logout Authorization = %q", logoutAuth)
	}
	if creds, _ := h.store(t).Load(); creds != nil {
		t.Error("credentials survived logout")
	}
	if _, err := os.Stat(h.store(t).Path()); !os.IsNotExist(err) {
		t.Error("credentials file survived logout")
	}
}

func TestLogoutWithoutCredentialsSucceeds(t *testing.T) {
	rec := &recorder{response: `{}`}
	h := newHarness(t, "", rec.handler())
	if code := h.run("logout"); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(h.stdout(), "Not logged in") {
		t.Errorf("stdout = %q", h.stdout())
	}
	if rec.calls != 0 {
		t.Error("logout contacted the bridge with no credentials")
	}
}

func TestLogoutForgetsCredentialsEvenWhenRevocationFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"code":"internal_error","message":"Redis error"}}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID: "alice", TemporalToken: token(t, "alice", "admin", time.Hour), RefreshToken: "r",
	})

	if code := h.run("logout"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if creds, _ := h.store(t).Load(); creds != nil {
		t.Error("credentials were kept after an explicit logout")
	}
	// The operator must know the token is still live server-side.
	if !strings.Contains(h.stderr(), "stays valid until it expires") {
		t.Errorf("stderr = %q, want the un-revoked token called out", h.stderr())
	}
}

func TestLogoutDoesNotTouchTheStoreForAnExplicitToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"message":"Token revoked successfully"}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID: "alice", TemporalToken: token(t, "alice", "admin", time.Hour), RefreshToken: "r",
	})

	if code := h.run("logout", "--token", "someone-elses-token"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if creds, _ := h.store(t).Load(); creds == nil {
		t.Error("revoking an explicitly supplied token deleted the stored credentials")
	}
}

func TestLogoutAllUsesTheEverywhereEndpoint(t *testing.T) {
	called := ""
	mux := http.NewServeMux()
	mux.HandleFunc("POST /logout/all", func(w http.ResponseWriter, r *http.Request) {
		called = r.URL.Path
		w.Write([]byte(`{"success":true,"message":"All tokens and sessions revoked"}`))
	})

	h := newHarness(t, "", mux)
	h.seedCredentials(t, &config.Credentials{
		AccountID: "alice", TemporalToken: token(t, "alice", "admin", time.Hour), RefreshToken: "r",
	})

	if code := h.run("logout", "--all"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if called != "/logout/all" {
		t.Errorf("called %q, want /logout/all", called)
	}
}
