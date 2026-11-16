package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"impalactl/internal/config"
	"impalactl/internal/devicekey"
)

// mfaToken builds an unsigned JWT carrying the assurance claims.
func mfaToken(t *testing.T, sub, role string, amr []string, mfr bool, expiresIn time.Duration) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"sub": sub, "role": role, "token_type": "temporal",
		"iat": time.Now().Unix(), "exp": time.Now().Add(expiresIn).Unix(),
		"jti": "jti", "fid": "fid", "iss": "impala-bridge", "aud": "impala-api",
		"amr": amr, "auth_time": time.Now().Unix(), "mfr": mfr,
	})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// mfaBridge is a stub bridge for the MFA routes that verifies what it is
// sent the way the bridge does: the TOTP code, and the device-key assertion
// rebuilt from the token's account, the purpose and the challenge it issued.
type mfaBridge struct {
	t       *testing.T
	account string
	totp    string
	mfr     bool

	mu         sync.Mutex
	challenges map[string]bool
	devices    map[string]string // key id -> public key hex
	totpOn     bool
	stepUps    int
	lastBody   map[string]any
	enrollBody map[string]any
	policy     *bool
	// stepUpStatus forces a status for POST /mfa/step-up.
	stepUpStatus int
	// protected403 is the error code a protected route answers with.
	protected403 string
}

func newMFABridge(t *testing.T) *mfaBridge {
	return &mfaBridge{t: t, account: "alice", totp: "123456",
		challenges: map[string]bool{}, devices: map[string]string{}}
}

func (b *mfaBridge) readJSON(r *http.Request) map[string]any {
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

func (b *mfaBridge) verifyDevice(pubHex string, purpose byte, challengeHex, sigHex string) bool {
	if !b.challenges[challengeHex] {
		return false
	}
	delete(b.challenges, challengeHex)
	pubBytes, _ := hex.DecodeString(pubHex)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubBytes)
	if err != nil {
		return false
	}
	ch, _ := hex.DecodeString(challengeHex)
	msg, err := devicekey.Message(purpose, b.account, ch)
	if err != nil {
		return false
	}
	sig, _ := hex.DecodeString(sigHex)
	d := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, d[:], sig)
}

func (b *mfaBridge) handler() http.Handler {
	mux := http.NewServeMux()
	writeErr := func(w http.ResponseWriter, status int, code, msg string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":{"code":%q,"message":%q}}`, code, msg)
	}
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "ok",
			"refresh_token":  "refresh-pwd",
			"temporal_token": mfaToken(b.t, b.account, "view-only", []string{"pwd"}, b.mfr, time.Hour)})
	})
	mux.HandleFunc("GET /mfa/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"amr":["pwd"],"auth_time":1800000000,"mfa":false,"required":true,` +
			`"required_by_role":false,"satisfied":false,"max_age_secs":43200}`))
	})
	mux.HandleFunc("POST /mfa/challenge", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		ch := fmt.Sprintf("%064x", len(b.challenges)+1+b.stepUps*7)
		b.challenges[ch] = true
		fmt.Fprintf(w, `{"challenge":%q,"expires_in":120}`, ch)
	})
	mux.HandleFunc("POST /mfa/step-up", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body := b.readJSON(r)
		b.lastBody = body
		if b.stepUpStatus != 0 {
			writeErr(w, b.stepUpStatus, "unauthorized", "Authentication required")
			return
		}
		ok := false
		var amr []string
		switch body["mfa_type"] {
		case "totp":
			ok = body["code"] == b.totp
			amr = []string{"mfa", "otp", "pwd"}
		case "device":
			key, _ := body["key_id"].(string)
			ch, _ := body["challenge"].(string)
			sig, _ := body["device_signature"].(string)
			ok = b.devices[key] != "" && b.verifyDevice(b.devices[key], devicekey.PurposeStepUp, ch, sig)
			amr = []string{"dev", "mfa", "pwd"}
		}
		if !ok {
			writeErr(w, 401, "unauthorized", "Authentication required")
			return
		}
		b.stepUps++
		json.NewEncoder(w).Encode(map[string]any{"success": true, "amr": amr, "message": "Step-up complete",
			"refresh_token":  fmt.Sprintf("refresh-stepped-%d", b.stepUps),
			"temporal_token": mfaToken(b.t, b.account, "view-only", amr, b.mfr, time.Hour)})
	})
	mux.HandleFunc("GET /mfa", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("account_id") != b.account {
			writeErr(w, 403, "forbidden", "Access denied")
			return
		}
		if b.totpOn {
			fmt.Fprintf(w, `[{"account_id":%q,"mfa_type":"totp","enabled":true,"configured":true}]`, b.account)
			return
		}
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("POST /mfa", func(w http.ResponseWriter, r *http.Request) {
		body := b.readJSON(r)
		if body["account_id"] != b.account || body["mfa_type"] != "totp" {
			writeErr(w, 400, "bad_request", "bad")
			return
		}
		b.totpOn = true
		w.Write([]byte(`{"success":true,"message":"MFA enrolled successfully",` +
			`"provisioning_uri":"otpauth://totp/Impala:alice?secret=JBSWY3DPEHPK3PXP&issuer=Impala"}`))
	})
	mux.HandleFunc("GET /mfa/device-keys", func(w http.ResponseWriter, r *http.Request) {
		var out []map[string]any
		for id := range b.devices {
			out = append(out, map[string]any{"key_id": id, "label": "x", "platform": "impalactl",
				"user_verification": "none", "created_at_unix": 1800000000})
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /mfa/device-keys", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.protected403 != "" {
			writeErr(w, 403, b.protected403, "Changing factors needs a recent multi-factor sign-in")
			return
		}
		body := b.readJSON(r)
		b.enrollBody = body
		pub, _ := body["public_key"].(string)
		ch, _ := body["challenge"].(string)
		sig, _ := body["signature"].(string)
		if !b.verifyDevice(pub, devicekey.PurposeEnroll, ch, sig) {
			writeErr(w, 401, "unauthorized", "Authentication required")
			return
		}
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", len(b.devices)+1)
		b.devices[id] = pub
		fmt.Fprintf(w, `{"success":true,"key_id":%q}`, id)
	})
	mux.HandleFunc("DELETE /mfa/device-keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if b.devices[id] == "" {
			writeErr(w, 404, "not_found", "Device key not found")
			return
		}
		delete(b.devices, id)
		w.Write([]byte(`{"success":true}`))
	})
	mux.HandleFunc("PUT /admin/accounts/{id}/mfa-policy", func(w http.ResponseWriter, r *http.Request) {
		body := b.readJSON(r)
		req, _ := body["required"].(bool)
		b.policy = &req
		fmt.Fprintf(w, `{"success":true,"required":%v}`, req)
	})
	mux.HandleFunc("GET /admin/accounts/{id}/mfa", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"account_id":%q,"mfa_required":true,"totp_enrolled":true,"cards":2,`+
			`"device_keys":[{"key_id":"k-1","label":null,"platform":"impalactl","user_verification":"none","created_at_unix":1}]}`,
			r.PathValue("id"))
	})
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		code := b.protected403
		if code == "" {
			code = "mfa_required"
		}
		writeErr(w, 403, code, "This account must complete multi-factor authentication; step up at /mfa/step-up")
	})
	return mux
}

func (b *mfaBridge) seed(t *testing.T, h *harness) {
	h.seedCredentials(t, &config.Credentials{
		AccountID:     b.account,
		TemporalToken: mfaToken(t, b.account, "view-only", []string{"pwd"}, b.mfr, time.Hour),
		RefreshToken:  "refresh-old",
	})
}

// ── step-up ────────────────────────────────────────────────────────────

func TestStepUpTOTPReplacesTheStoredPair(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	h.env[config.EnvTOTPCode] = "123456"

	if code := h.run("mfa", "step-up", "--totp"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.lastBody["mfa_type"] != "totp" || b.lastBody["code"] != "123456" {
		t.Errorf("step-up body = %v", b.lastBody)
	}
	creds, _ := h.store(t).Load()
	if creds == nil || creds.RefreshToken != "refresh-stepped-1" {
		t.Fatalf("stored pair not replaced: %+v", creds)
	}
	if !strings.Contains(creds.TemporalToken, ".") || creds.AccountID != "alice" || creds.Endpoint != h.srv.URL {
		t.Errorf("stored credentials = %+v", creds)
	}
	if !strings.Contains(h.stdout(), "mfa otp pwd") {
		t.Errorf("stdout = %q", h.stdout())
	}
	if strings.Contains(h.stdout()+h.stderr(), "123456") {
		t.Error("the TOTP code was echoed")
	}
}

func TestStepUpRefusedKeepsTheSessionAndSaysSo(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	before, _ := h.store(t).Load()
	h.env[config.EnvTOTPCode] = "654321" // wrong

	if code := h.run("mfa", "step-up", "--totp"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(h.stderr(), "step-up refused") || !strings.Contains(h.stderr(), "Nothing changed") {
		t.Errorf("stderr = %q", h.stderr())
	}
	after, _ := h.store(t).Load()
	if after == nil || after.RefreshToken != before.RefreshToken || after.TemporalToken != before.TemporalToken {
		t.Error("a refused step-up changed the stored credentials")
	}
}

func TestStepUpTOTPFormatIsCheckedBeforeAnyRequest(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	h.env[config.EnvTOTPCode] = "12ab56"
	if code := h.run("mfa", "step-up", "--totp"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if b.lastBody != nil {
		t.Error("a malformed code was sent")
	}
	if !strings.Contains(h.stderr(), "6 digits") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestStepUpTakesTheCodeFromStdin(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "123456\n", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "step-up", "--totp"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
}

func TestStepUpFlagsAreExclusiveAndRequired(t *testing.T) {
	for _, args := range [][]string{
		{"mfa", "step-up"},
		{"mfa", "step-up", "--totp", "--device"},
	} {
		h := newHarness(t, "", nil)
		if code := h.run(args...); code != 2 {
			t.Errorf("%v exit = %d, want 2", args, code)
		}
	}
}

// With a caller-supplied token, the new pair cannot be stored, and printing it
// silently would hand out a credential: --json is the explicit opt-in.
func TestStepUpWithAnExplicitTokenNeedsJSON(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	h.env[config.EnvToken] = mfaToken(t, "alice", "view-only", []string{"pwd"}, false, time.Hour)
	h.env[config.EnvTOTPCode] = "123456"
	if code := h.run("mfa", "step-up", "--totp"); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if b.lastBody != nil {
		t.Error("a step-up was sent")
	}
	h2 := newHarness(t, "", b.handler())
	h2.env[config.EnvToken] = h.env[config.EnvToken]
	h2.env[config.EnvTOTPCode] = "123456"
	if code := h2.run("mfa", "step-up", "--totp", "--json"); code != 0 {
		t.Fatalf("--json exit = %d: %s", code, h2.stderr())
	}
	if creds, _ := h2.store(t).Load(); creds != nil {
		t.Error("an explicit token's step-up wrote the credential store")
	}
}

// ── the mfa_required mapping (one place: App.fail) ─────────────────────

func TestMFARequiredRefusalNamesTheFix(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("account", "list"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "[403 mfa_required]") || !strings.Contains(h.stderr(), "impalactl mfa step-up --totp") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestMFAReauthRefusalNamesTheFix(t *testing.T) {
	b := newMFABridge(t)
	b.protected403 = "mfa_reauth_required"
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "device", "enroll"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "15 minutes") || !strings.Contains(h.stderr(), "mfa step-up") {
		t.Errorf("stderr = %q", h.stderr())
	}
	// A refused enrollment keeps no private key around.
	if _, err := os.Stat(h.store(t).DeviceKeyPath(h.srv.URL, "alice")); !os.IsNotExist(err) {
		t.Errorf("key file left behind after a refusal: %v", err)
	}
}

func TestOtherForbiddenErrorsGetNoMFAHint(t *testing.T) {
	err := fmt.Errorf("x")
	if mfaHint(err) != "" {
		t.Error("hint for a plain error")
	}
}

// ── device keys ────────────────────────────────────────────────────────

func TestDeviceEnrollThenStepUp(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)

	if code := h.run("mfa", "device", "enroll", "--label", "ops laptop"); code != 0 {
		t.Fatalf("enroll exit = %d: %s", code, h.stderr())
	}
	if b.enrollBody["platform"] != "impalactl" || b.enrollBody["user_verification"] != "none" ||
		b.enrollBody["label"] != "ops laptop" {
		t.Errorf("enroll body = %v", b.enrollBody)
	}
	path := h.store(t).DeviceKeyPath(h.srv.URL, "alice")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o", info.Mode().Perm())
	}
	key, err := h.store(t).LoadDeviceKey(h.srv.URL, "alice")
	if err != nil || key == nil || key.KeyID == "" {
		t.Fatalf("stored key = %+v, %v", key, err)
	}
	if strings.Contains(h.stdout()+h.stderr(), key.PrivateKey) {
		t.Error("the private key was printed")
	}
	if !strings.Contains(h.stderr(), "possession factor") || !strings.Contains(h.stderr(), "never biometric") {
		t.Errorf("stderr = %q", h.stderr())
	}

	h.out.Reset()
	h.err.Reset()
	if code := h.run("mfa", "step-up", "--device"); code != 0 {
		t.Fatalf("step-up exit = %d: %s", code, h.stderr())
	}
	creds, _ := h.store(t).Load()
	if creds.RefreshToken != "refresh-stepped-1" {
		t.Errorf("stored pair not replaced: %+v", creds)
	}
	if b.lastBody["key_id"] != key.KeyID {
		t.Errorf("step-up body = %v", b.lastBody)
	}

	// The list marks this machine's key.
	h.out.Reset()
	if code := h.run("mfa", "device", "list"); code != 0 {
		t.Fatalf("list exit = %d", code)
	}
	if !strings.Contains(h.stdout(), key.KeyID+" (this machine)") {
		t.Errorf("list = %q", h.stdout())
	}

	// A second enrollment is refused while this one exists.
	if code := h.run("mfa", "device", "enroll"); code != 1 {
		t.Errorf("second enroll exit = %d, want 1", code)
	}

	// Revoking it removes this machine's copy too.
	h.err.Reset()
	if code := h.run("mfa", "device", "revoke", key.KeyID); code != 0 {
		t.Fatalf("revoke exit = %d: %s", code, h.stderr())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("revoked key still on disk")
	}
}

func TestDeviceKeyIsScopedToEndpointAndAccount(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "device", "enroll"); code != 0 {
		t.Fatalf("enroll exit = %d: %s", code, h.stderr())
	}
	// Another account at the same endpoint has no key on this machine.
	b.account = "bob"
	h.seedCredentials(t, &config.Credentials{AccountID: "bob",
		TemporalToken: mfaToken(t, "bob", "view-only", []string{"pwd"}, false, time.Hour), RefreshToken: "r"})
	h.err.Reset()
	if code := h.run("mfa", "step-up", "--device"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "holds no device key for bob") {
		t.Errorf("stderr = %q", h.stderr())
	}
	// And a key file copied into another pair's slot is refused, not used.
	store := h.store(t)
	alice, _ := store.LoadDeviceKey(h.srv.URL, "alice")
	data, _ := json.Marshal(alice)
	bobPath := store.DeviceKeyPath(h.srv.URL, "bob")
	os.WriteFile(bobPath, data, 0o600)
	if _, err := store.LoadDeviceKey(h.srv.URL, "bob"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("transplanted key: %v", err)
	}
}

func TestDeviceEnrollRefusedKeepsNoKey(t *testing.T) {
	b := newMFABridge(t)
	b.stepUpStatus = 0
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	b.account = "someone-else" // the bridge rebuilds the message for another account: 401
	if code := h.run("mfa", "device", "enroll"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if _, err := os.Stat(h.store(t).DeviceKeyPath(h.srv.URL, "alice")); !os.IsNotExist(err) {
		t.Error("a refused enrollment left its key on disk")
	}
}

// ── totp enroll ────────────────────────────────────────────────────────

func TestTOTPEnrollPrintsTheURIOnceAndRefusesASilentReplace(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "totp", "enroll"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if strings.TrimSpace(h.stdout()) != "otpauth://totp/Impala:alice?secret=JBSWY3DPEHPK3PXP&issuer=Impala" {
		t.Errorf("stdout = %q", h.stdout())
	}
	if !strings.Contains(h.stderr(), "shared secret") || !strings.Contains(h.stderr(), "ONCE") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if strings.Contains(h.stderr(), "JBSWY3DPEHPK3PXP") {
		t.Error("the secret leaked to stderr")
	}

	h.out.Reset()
	h.err.Reset()
	if code := h.run("mfa", "totp", "enroll"); code != 1 {
		t.Fatalf("re-enroll without --replace exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "--replace") || h.stdout() != "" {
		t.Errorf("stderr = %q stdout = %q", h.stderr(), h.stdout())
	}
	if code := h.run("mfa", "totp", "enroll", "--replace"); code != 0 {
		t.Fatalf("--replace exit = %d", code)
	}
}

// ── login and whoami ───────────────────────────────────────────────────

func TestLoginNoticeWhenTheAccountMustBeMultiFactor(t *testing.T) {
	b := newMFABridge(t)
	b.mfr = true
	h := newHarness(t, "pw\n", b.handler())
	if code := h.run("login", "alice"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stderr(), "must be multi-factor") || !strings.Contains(h.stderr(), "impalactl mfa step-up") {
		t.Errorf("stderr = %q", h.stderr())
	}
}

func TestLoginWithTOTPStepsUpInTheSameCommand(t *testing.T) {
	b := newMFABridge(t)
	b.mfr = true
	h := newHarness(t, "pw\n123456\n", b.handler()) // password, then the code: one pipe
	if code := h.run("login", "alice", "--totp"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	creds, _ := h.store(t).Load()
	if creds == nil || creds.RefreshToken != "refresh-stepped-1" {
		t.Fatalf("stored = %+v", creds)
	}
	if strings.Contains(h.stderr(), "must be multi-factor") {
		t.Error("notice printed although the login stepped up")
	}
	if !strings.Contains(h.stdout(), "Multi-factor:") || !strings.Contains(h.stdout(), "yes") {
		t.Errorf("stdout = %q", h.stdout())
	}
}

func TestWhoamiShowsTheSessionAssurance(t *testing.T) {
	h := newHarness(t, "", nil)
	h.seedCredentials(t, &config.Credentials{Endpoint: "http://localhost:8080", AccountID: "alice",
		TemporalToken: mfaToken(t, "alice", "admin", []string{"mfa", "otp", "pwd"}, true, time.Hour), RefreshToken: "r"})
	if code := h.run("whoami"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	for _, want := range []string{"mfa otp pwd", "Multi-factor:", "MFA required:", "Verified at:"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("whoami missing %q:\n%s", want, h.stdout())
		}
	}
}

// ── admin ──────────────────────────────────────────────────────────────

func TestAdminMandateSaysItSignsTheAccountOut(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "admin", "mandate", "bob", "on"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.policy == nil || !*b.policy {
		t.Error("PUT body did not carry required=true")
	}
	if !strings.Contains(h.stderr(), "signs bob out everywhere") {
		t.Errorf("stderr = %q", h.stderr())
	}
	if code := h.run("mfa", "admin", "mandate", "bob", "maybe"); code != 2 {
		t.Errorf("bad value exit = %d", code)
	}
}

func TestAdminShowRendersTheSummary(t *testing.T) {
	b := newMFABridge(t)
	h := newHarness(t, "", b.handler())
	b.seed(t, h)
	if code := h.run("mfa", "admin", "show", "bob"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	for _, want := range []string{"bob", "TOTP enrolled:", "k-1"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("missing %q in %q", want, h.stdout())
		}
	}
}
