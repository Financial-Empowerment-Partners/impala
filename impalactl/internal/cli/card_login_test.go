package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"impalactl/internal/card"
	"impalactl/internal/card/cardtest"
	"impalactl/internal/config"
	"impalactl/internal/devicekey"
	"impalactl/internal/sep10"
	"impalactl/internal/sep10/sep10test"
)

const testnetPassphrase = "Test SDF Network ; September 2015"

// cardBridge is a stub bridge for card sign-in that checks what it receives
// the way the bridge does: the server and card Ed25519 signatures over the
// challenge hash, the card's ECDSA signature over the legacy message, PIN
// proofs and device assertions over the value the card signed.
type cardBridge struct {
	t      *testing.T
	card   *cardtest.Card
	server ed25519.PrivateKey
	home   string // the SEP-10 home domain the bridge serves under

	tomlStatus      int
	tomlBody        string
	webAuth         string // WEB_AUTH_ENDPOINT override
	challengeStatus int
	postStatus      int
	mutate          func(*sep10test.Spec)
	registered      bool // the card's Stellar key is registered
	tokenAccount    string
	deviceKey       []byte // registered device public key (65 bytes)
	deviceKeyID     string

	mu          sync.Mutex
	requests    int
	tomlGets    int
	challenges  int
	sep10Posts  int
	legacyPosts int
	hosts       []string
	issued      [][]byte
	legacyCh    []string
	lastExtras  map[string]string
}

func newCardBridge(t *testing.T, c *cardtest.Card) *cardBridge {
	_, server, _ := ed25519.GenerateKey(rand.Reader)
	return &cardBridge{t: t, card: c, server: server, registered: true}
}

func (b *cardBridge) account() string { return card.FormatUUID(b.card.Account[:]) }

func (b *cardBridge) token(amr []string) string {
	sub := b.tokenAccount
	if sub == "" {
		sub = b.account()
	}
	return mfaToken(b.t, sub, "view-only", amr, false, time.Hour)
}

func (b *cardBridge) verifyECDSA(tag string, challenge []byte, sigHex string) bool {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b.card.ECPub())
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	msg := append(append([]byte(tag), b.card.Account[:]...), challenge...)
	h := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

func (b *cardBridge) verifyDevice(purpose byte, challenge []byte, sigHex string) bool {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b.deviceKey)
	if err != nil {
		return false
	}
	sig, _ := hex.DecodeString(sigHex)
	msg, err := devicekey.Message(purpose, b.account(), challenge)
	if err != nil {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

// extras checks the optional factors and returns the amr they add, or false.
func (b *cardBridge) extras(body map[string]string, challenge []byte, purpose byte) ([]string, bool) {
	var amr []string
	if p := body["pin_proof"]; p != "" {
		if !b.verifyECDSA("IMPALA-APIN:", challenge, p) {
			return nil, false
		}
		amr = append(amr, "pin")
	}
	if k := body["device_key_id"]; k != "" {
		if k != b.deviceKeyID || !b.verifyDevice(purpose, challenge, body["device_signature"]) {
			return nil, false
		}
		amr = append(amr, "dev")
	}
	return amr, true
}

func (b *cardBridge) handler() http.Handler {
	mux := http.NewServeMux()
	status := func(w http.ResponseWriter, code int) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":{"code":"x","message":"HTTP %d"}}`, code)
	}
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"stellar_network":"testnet","network_passphrase":%q}`, testnetPassphrase)
	})
	mux.HandleFunc("GET /.well-known/stellar.toml", func(w http.ResponseWriter, r *http.Request) {
		b.tomlGets++
		if b.tomlStatus != 0 {
			status(w, b.tomlStatus)
			return
		}
		if b.tomlBody != "" {
			w.Write([]byte(b.tomlBody))
			return
		}
		addr, _ := sep10.EncodeAccountID(b.server.Public().(ed25519.PublicKey))
		web := b.webAuth
		if web == "" {
			web = "http://" + b.home + "/auth/sep10"
		}
		fmt.Fprintf(w, "NETWORK_PASSPHRASE = %q\nSIGNING_KEY = %q\nWEB_AUTH_ENDPOINT = %q\n", testnetPassphrase, addr, web)
	})
	mux.HandleFunc("GET /auth/sep10", func(w http.ResponseWriter, r *http.Request) {
		b.challenges++
		if b.challengeStatus != 0 {
			status(w, b.challengeStatus)
			return
		}
		if r.URL.Query().Get("home_domain") != b.home {
			status(w, 400)
			return
		}
		client, err := sep10.DecodeAccountID(r.URL.Query().Get("account"))
		if err != nil {
			status(w, 400)
			return
		}
		spec := sep10test.Standard(b.server, client, b.home, b.home, testnetPassphrase, time.Now().Unix(), 300)
		if b.mutate != nil {
			b.mutate(&spec)
		}
		b.issued = append(b.issued, spec.Transaction())
		json.NewEncoder(w).Encode(map[string]string{"transaction": spec.Build(), "network_passphrase": testnetPassphrase})
	})
	mux.HandleFunc("POST /auth/sep10", func(w http.ResponseWriter, r *http.Request) {
		b.sep10Posts++
		if b.postStatus != 0 {
			status(w, b.postStatus)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		b.lastExtras = body
		raw, err := base64.StdEncoding.DecodeString(body["transaction"])
		if err != nil || len(b.issued) == 0 {
			status(w, 400)
			return
		}
		tx := b.issued[len(b.issued)-1]
		d, ok := sep10test.DecodeSigned(body["transaction"], len(tx))
		if !ok || !bytes.Equal(d.Tx, tx) || len(d.Signatures) != 2 || !bytes.HasPrefix(raw, []byte{0, 0, 0, 2}) {
			status(w, 400)
			return
		}
		hash := sep10.TransactionHash(testnetPassphrase, tx)
		serverPub := b.server.Public().(ed25519.PublicKey)
		cardPub := b.card.StellarPub()
		if !ed25519.Verify(serverPub, hash[:], d.Signatures[0]) || !bytes.Equal(d.Hints[1], cardPub[28:]) ||
			!ed25519.Verify(cardPub, hash[:], d.Signatures[1]) {
			status(w, 401)
			return
		}
		if !b.registered {
			status(w, 401)
			return
		}
		extra, ok := b.extras(body, hash[:], devicekey.PurposeSep10SignIn)
		if !ok {
			status(w, 401)
			return
		}
		amr := append([]string{"sc"}, extra...)
		if len(extra) > 0 {
			amr = append(amr, "mfa")
		}
		tok := b.token(amr)
		json.NewEncoder(w).Encode(map[string]any{"token": tok, "success": true, "message": "ok",
			"refresh_token": "refresh-sep10", "temporal_token": tok})
	})
	mux.HandleFunc("POST /auth/card/challenge", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["card_id"] != hex.EncodeToString(b.card.CardID[:]) {
			status(w, 400)
			return
		}
		ch := make([]byte, 32)
		rand.Read(ch)
		b.legacyCh = append(b.legacyCh, hex.EncodeToString(ch))
		fmt.Fprintf(w, `{"success":true,"challenge":%q,"expires_in":60}`, hex.EncodeToString(ch))
	})
	mux.HandleFunc("POST /auth/card", func(w http.ResponseWriter, r *http.Request) {
		b.legacyPosts++
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		b.lastExtras = body
		if len(b.legacyCh) == 0 {
			status(w, 401)
			return
		}
		ch, _ := hex.DecodeString(b.legacyCh[len(b.legacyCh)-1])
		if !b.verifyECDSA("IMPALA-AUTH:", ch, body["signature"]) {
			status(w, 401)
			return
		}
		extra, ok := b.extras(body, ch, devicekey.PurposeCardSignIn)
		if !ok {
			status(w, 401)
			return
		}
		amr := append([]string{"sc"}, extra...)
		if len(extra) > 0 {
			amr = append(amr, "mfa")
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "ok",
			"refresh_token": "refresh-legacy", "temporal_token": b.token(amr)})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.requests++
		b.hosts = append(b.hosts, r.Method+" "+r.URL.Path+" @"+r.Host)
		mux.ServeHTTP(w, r)
	})
}

// cardHarness starts the fake card and the fake bridge, home domain = the
// bridge's own host:port.
func cardHarness(t *testing.T, setup func(*cardtest.Card, *cardBridge)) (*harness, *cardtest.Card, *cardBridge, string) {
	t.Helper()
	c := cardtest.New(t)
	b := newCardBridge(t, c)
	h := newHarness(t, "", b.handler())
	b.home = strings.TrimPrefix(h.srv.URL, "http://")
	if setup != nil {
		setup(c, b)
	}
	return h, c, b, c.Start(t)
}

func noTokensIn(t *testing.T, h *harness) {
	t.Helper()
	if strings.Contains(h.stderr(), "refresh-") || strings.Contains(h.stderr(), "e30.") {
		t.Errorf("a token reached stderr: %s", h.stderr())
	}
}

// ── the fallback rule ──────────────────────────────────────────────────

func TestFallbackForPinsEveryCase(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want sep10Fallback
	}{
		{"toml without endpoint or key", &sep10.ClientError{Kind: sep10.NotOffered}, fallbackNotOffered},
		{"HTTP 404", &sep10.HTTPError{Status: 404}, fallbackNotOffered},
		{"HTTP 503", &sep10.HTTPError{Status: 503}, fallbackNotOffered},
		{"HTTP 401", &sep10.HTTPError{Status: 401}, fallbackNotRegistered},
		{"wrapped 401", fmt.Errorf("x: %w", &sep10.HTTPError{Status: 401}), fallbackNotRegistered},
		{"HTTP 429", &sep10.HTTPError{Status: 429}, noFallback},
		{"HTTP 400", &sep10.HTTPError{Status: 400}, noFallback},
		{"HTTP 403", &sep10.HTTPError{Status: 403}, noFallback},
		{"HTTP 500", &sep10.HTTPError{Status: 500}, noFallback},
		{"HTTP 302", &sep10.HTTPError{Status: 302}, noFallback},
		{"toml invalid", &sep10.ClientError{Kind: sep10.TomlInvalid}, noFallback},
		{"insecure endpoint", &sep10.ClientError{Kind: sep10.InsecureEndpoint}, noFallback},
		{"web-auth on another host", &sep10.ClientError{Kind: sep10.HostMismatch}, noFallback},
		{"response invalid", &sep10.ClientError{Kind: sep10.ResponseInvalid}, noFallback},
		{"challenge check", &sep10.ChallengeError{Reason: sep10.ReasonServerSignature}, noFallback},
		{"network mismatch", &sep10.ChallengeError{Reason: sep10.ReasonNetwork}, noFallback},
		{"card refusal", &card.Error{SW: 0x6243}, noFallback},
		{"card transport", &card.TransportError{Err: io.EOF}, noFallback},
		{"transport", &net.OpError{Op: "dial", Err: errors.New("refused")}, noFallback},
		{"other", errors.New("anything"), noFallback},
	}
	for _, tc := range cases {
		if got := fallbackFor(tc.err); got != tc.want {
			t.Errorf("%s: fallbackFor = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// ── SEP-10 ─────────────────────────────────────────────────────────────

func TestCardLoginWithSEP10(t *testing.T) {
	h, c, b, spec := cardHarness(t, nil)
	if code := h.run("login", "--card", spec); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.sep10Posts != 1 || b.legacyPosts != 0 {
		t.Errorf("sep10 posts %d, legacy posts %d", b.sep10Posts, b.legacyPosts)
	}
	creds, _ := h.store(t).Load()
	if creds == nil || creds.RefreshToken != "refresh-sep10" || creds.AccountID != b.account() || creds.Endpoint != h.srv.URL {
		t.Fatalf("stored = %+v", creds)
	}
	addr, _ := sep10.EncodeAccountID(c.StellarPub())
	for _, want := range []string{"Mechanism: SEP-10", addr, hex.EncodeToString(c.CardID[:]), "Factors:   sc"} {
		if !strings.Contains(h.stderr(), want) {
			t.Errorf("stderr missing %q:\n%s", want, h.stderr())
		}
	}
	if !strings.Contains(h.stdout(), "Logged in as:") {
		t.Errorf("stdout = %s", h.stdout())
	}
	noTokensIn(t, h)
	// The applet's SEP-10 parts: BEGIN = network id + as much as fits (never
	// the last byte), CONTINUE of 255, FINISH at least one byte.
	parts := c.Sep10Parts()
	if len(parts) < 2 || parts[0] > 255 || parts[len(parts)-1] < 1 {
		t.Errorf("SIGN_SEP10 parts = %v", parts)
	}
}

func TestCardLoginWithSEP10AndPIN(t *testing.T) {
	h, c, b, spec := cardHarness(t, nil)
	h.env[config.EnvCardPIN] = "1234"
	if code := h.run("login", "--card", spec, "--pin"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.lastExtras["pin_proof"] == "" {
		t.Error("no PIN proof posted")
	}
	if !strings.Contains(h.stderr(), "sc pin mfa") {
		t.Errorf("stderr = %s", h.stderr())
	}
	if !c.Received("VERIFY_PIN") || strings.Contains(h.stdout()+h.stderr(), "1234") {
		t.Error("PIN not verified on the card, or echoed")
	}
}

func TestCardLoginWithADeviceKey(t *testing.T) {
	h, _, b, spec := cardHarness(t, nil)
	priv, _ := devicekey.Generate()
	pub, _ := devicekey.PublicKeyHex(&priv.PublicKey)
	enc, _ := devicekey.MarshalPrivate(priv)
	b.deviceKey, _ = hex.DecodeString(pub)
	b.deviceKeyID = "00000000-0000-4000-8000-000000000001"
	if err := h.store(t).SaveDeviceKey(&config.DeviceKey{Endpoint: h.srv.URL, AccountID: b.account(),
		KeyID: b.deviceKeyID, PrivateKey: enc, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	if code := h.run("login", "--card", spec, "--device"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.lastExtras["device_key_id"] != b.deviceKeyID || !strings.Contains(h.stderr(), "sc dev mfa") {
		t.Errorf("extras = %v stderr = %s", b.lastExtras, h.stderr())
	}
	// The legacy path signs the card challenge with purpose 0x03.
	h.err.Reset()
	if code := h.run("login", "--card", spec, "--device", "--no-sep10"); code != 0 {
		t.Fatalf("legacy exit = %d: %s", code, h.stderr())
	}
	if !strings.Contains(h.stderr(), "sc dev mfa") {
		t.Errorf("stderr = %s", h.stderr())
	}
}

// ── PIN ────────────────────────────────────────────────────────────────

func TestCardLoginRefusesAPinRequiredCardWithoutPinBeforeAnyRequest(t *testing.T) {
	h, c, b, spec := cardHarness(t, func(c *cardtest.Card, _ *cardBridge) { c.RequirePIN = true })
	if code := h.run("login", "--card", spec); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if b.requests != 0 {
		t.Errorf("%d requests reached the bridge: %v", b.requests, b.hosts)
	}
	if !strings.Contains(h.stderr(), "requires its user PIN") || !strings.Contains(h.stderr(), "--pin") {
		t.Errorf("stderr = %s", h.stderr())
	}
	if c.Received("SIGN_") {
		t.Error("the card was asked to sign")
	}
	// With the PIN it signs in.
	h.err.Reset()
	h.env[config.EnvCardPIN] = "1234"
	if code := h.run("login", "--card", spec, "--pin"); code != 0 {
		t.Fatalf("with PIN exit = %d: %s", code, h.stderr())
	}
}

func TestCardLoginWrongPinIsAnErrorNotADowngrade(t *testing.T) {
	h, c, b, spec := cardHarness(t, nil)
	h.env[config.EnvCardPIN] = "9999"
	if code := h.run("login", "--card", spec, "--pin"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if b.requests != 0 || c.Received("SIGN_") {
		t.Errorf("requests %d, card log %v", b.requests, c.Log())
	}
	if !strings.Contains(h.stderr(), "verify the user PIN") || !strings.Contains(h.stderr(), "SW 69C4") ||
		!strings.Contains(h.stderr(), "4 tries left") {
		t.Errorf("stderr = %s", h.stderr())
	}
	if c.TriesLeft() != 4 {
		t.Errorf("tries = %d", c.TriesLeft())
	}
	if strings.Contains(h.stderr(), "9999") {
		t.Error("PIN echoed")
	}
}

func TestCardLoginPinOnACardWithoutProvisionedPin(t *testing.T) {
	h, _, b, spec := cardHarness(t, func(c *cardtest.Card, _ *cardBridge) { c.PIN = "" })
	h.env[config.EnvCardPIN] = "1234"
	if code := h.run("login", "--card", spec, "--pin"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if b.requests != 0 || !strings.Contains(h.stderr(), "no provisioned user PIN") {
		t.Errorf("requests %d stderr %s", b.requests, h.stderr())
	}
}

// ── fallbacks (exactly three) ──────────────────────────────────────────

func TestCardLoginFallsBackInExactlyTheThreeCases(t *testing.T) {
	for name, tc := range map[string]struct {
		setup  func(*cardtest.Card, *cardBridge)
		args   []string
		want   string
		noToml bool
	}{
		"toml 404":            {setup: func(_ *cardtest.Card, b *cardBridge) { b.tomlStatus = 404 }, want: "not offered"},
		"toml 503":            {setup: func(_ *cardtest.Card, b *cardBridge) { b.tomlStatus = 503 }, want: "not offered"},
		"challenge 503":       {setup: func(_ *cardtest.Card, b *cardBridge) { b.challengeStatus = 503 }, want: "not offered"},
		"toml without key":    {setup: func(_ *cardtest.Card, b *cardBridge) { b.tomlBody = "WEB_AUTH_ENDPOINT = \"http://x/a\"\n" }, want: "not offered"},
		"unregistered key":    {setup: func(_ *cardtest.Card, b *cardBridge) { b.registered = false }, want: "refused with 401"},
		"--no-sep10":          {args: []string{"--no-sep10"}, want: "not configured", noToml: true},
		"card without a key":  {setup: func(c *cardtest.Card, _ *cardBridge) { c.Stellar = nil }, want: "has no Stellar key", noToml: true},
		"privileged account?": {setup: func(_ *cardtest.Card, b *cardBridge) { b.postStatus = 401 }, want: "privileged role"},
	} {
		t.Run(name, func(t *testing.T) {
			h, _, b, spec := cardHarness(t, tc.setup)
			if code := h.run(append([]string{"login", "--card", spec}, tc.args...)...); code != 0 {
				t.Fatalf("exit = %d: %s", code, h.stderr())
			}
			if b.legacyPosts != 1 {
				t.Errorf("legacy posts = %d", b.legacyPosts)
			}
			if !strings.Contains(h.stderr(), tc.want) || !strings.Contains(h.stderr(), "legacy card challenge") {
				t.Errorf("stderr = %s", h.stderr())
			}
			if tc.noToml && b.tomlGets != 0 {
				t.Error("stellar.toml fetched")
			}
			creds, _ := h.store(t).Load()
			if creds == nil || creds.RefreshToken != "refresh-legacy" {
				t.Errorf("stored = %+v", creds)
			}
		})
	}
}

func TestCardLoginNeverDowngradesOnAnyOtherFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		setup     func(*cardtest.Card, *cardBridge)
		want      string
		cardAsked bool // the card was asked to sign SEP-10
	}{
		"challenge 429": {setup: func(_ *cardtest.Card, b *cardBridge) { b.challengeStatus = 429 }, want: "HTTP 429"},
		"challenge 500": {setup: func(_ *cardtest.Card, b *cardBridge) { b.challengeStatus = 500 }, want: "HTTP 500"},
		"post 500":      {setup: func(_ *cardtest.Card, b *cardBridge) { b.postStatus = 500 }, want: "HTTP 500", cardAsked: true},
		"post 429":      {setup: func(_ *cardtest.Card, b *cardBridge) { b.postStatus = 429 }, want: "HTTP 429", cardAsked: true},
		"sequence 1": {setup: func(_ *cardtest.Card, b *cardBridge) {
			b.mutate = func(s *sep10test.Spec) { s.Seq = 1 }
		}, want: "SEQUENCE"},
		"server signature": {setup: func(_ *cardtest.Card, b *cardBridge) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			b.mutate = func(s *sep10test.Spec) { s.SignWith = other }
		}, want: "SERVER_SIGNATURE"},
		"wrong home domain op": {setup: func(_ *cardtest.Card, b *cardBridge) {
			b.mutate = func(s *sep10test.Spec) { s.Ops[0].Name = "evil.example auth" }
		}, want: "HOME_DOMAIN_KEY"},
		"expired": {setup: func(_ *cardtest.Card, b *cardBridge) {
			b.mutate = func(s *sep10test.Spec) { s.MinTime -= 1000; s.MaxTime -= 1000 }
		}, want: "TIME_BOUNDS_EXPIRED"},
		"network in toml": {setup: func(_ *cardtest.Card, b *cardBridge) {
			addr, _ := sep10.EncodeAccountID(b.server.Public().(ed25519.PublicKey))
			b.tomlBody = "NETWORK_PASSPHRASE = \"Public Global Stellar Network ; September 2015\"\nSIGNING_KEY = \"" + addr +
				"\"\nWEB_AUTH_ENDPOINT = \"http://" + b.home + "/auth/sep10\"\n"
		}, want: "NETWORK"},
		"card refuses": {setup: func(c *cardtest.Card, _ *cardBridge) {
			c.Force[0x3802] = 0x6243
		}, want: "SW 6243", cardAsked: true},
		"toml invalid": {setup: func(_ *cardtest.Card, b *cardBridge) { b.tomlBody = "SIGNING_KEY = 'x'\n" }, want: "TOML_INVALID"},
	} {
		t.Run(name, func(t *testing.T) {
			h, c, b, spec := cardHarness(t, tc.setup)
			if code := h.run("login", "--card", spec); code != 1 {
				t.Fatalf("exit = %d: %s", code, h.stderr())
			}
			if b.legacyPosts != 0 {
				t.Error("fell back to the legacy challenge")
			}
			if !strings.Contains(h.stderr(), tc.want) {
				t.Errorf("stderr lacks %q: %s", tc.want, h.stderr())
			}
			if got := c.Received("SIGN_SEP10"); got != tc.cardAsked {
				t.Errorf("card asked to sign SEP-10 = %v, want %v", got, tc.cardAsked)
			}
			if creds, _ := h.store(t).Load(); creds != nil {
				t.Error("credentials stored")
			}
		})
	}
}

func TestCardRefusalNamesTheStepAndStatusWord(t *testing.T) {
	h, _, _, spec := cardHarness(t, func(c *cardtest.Card, _ *cardBridge) { c.Force[0x3802] = 0x6244 })
	h.run("login", "--card", spec)
	if !strings.Contains(h.stderr(), "sign the SEP-10 challenge (SIGN_SEP10 FINISH): SW 6244 SEP10_NOT_AUTH_CHALLENGE") {
		t.Errorf("stderr = %s", h.stderr())
	}
}

// ── home domain ────────────────────────────────────────────────────────

func TestCardLoginRefusesAWebAuthEndpointOnAnotherHost(t *testing.T) {
	h, c, b, spec := cardHarness(t, func(_ *cardtest.Card, b *cardBridge) {
		b.webAuth = "http://evil.example:8084/auth/sep10"
	})
	if code := h.run("login", "--card", spec); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if b.challenges != 0 || b.sep10Posts != 0 || b.legacyPosts != 0 || c.Received("SIGN_SEP10") {
		t.Errorf("challenges %d posts %d legacy %d", b.challenges, b.sep10Posts, b.legacyPosts)
	}
	if !strings.Contains(h.stderr(), "HOST_MISMATCH") || !strings.Contains(h.stderr(), "--sep10-home-domain evil.example:8084") {
		t.Errorf("stderr = %s", h.stderr())
	}
}

// The demo's bridge is named 10.0.2.2:8084 (the emulator's name for the host)
// but reached at 127.0.0.1: --sep10-home-domain changes the NAME only, and
// every connection still goes to --endpoint.
func TestCardLoginWithAnAliasedHomeDomain(t *testing.T) {
	h, _, b, spec := cardHarness(t, func(_ *cardtest.Card, b *cardBridge) { b.home = "10.0.2.2:8084" })
	if code := h.run("login", "--card", spec, "--sep10-home-domain", "10.0.2.2:8084"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	if b.sep10Posts != 1 {
		t.Fatalf("sep10 posts = %d", b.sep10Posts)
	}
	seen := strings.Join(b.hosts, "\n")
	for _, want := range []string{"GET /.well-known/stellar.toml @10.0.2.2:8084", "GET /auth/sep10 @10.0.2.2:8084",
		"POST /auth/sep10 @10.0.2.2:8084"} {
		if !strings.Contains(seen, want) {
			t.Errorf("missing %q in\n%s", want, seen)
		}
	}
	// Without the flag the name is the endpoint's, and the toml's endpoint on
	// 10.0.2.2:8084 is another host: refused, with the fix named.
	h2, _, b2, spec2 := cardHarness(t, func(_ *cardtest.Card, b *cardBridge) {
		b.webAuth = "http://10.0.2.2:8084/auth/sep10"
	})
	if code := h2.run("login", "--card", spec2); code != 1 || b2.challenges != 0 {
		t.Fatalf("exit = %d challenges %d", code, b2.challenges)
	}
	if !strings.Contains(h2.stderr(), "--sep10-home-domain 10.0.2.2:8084") {
		t.Errorf("stderr = %s", h2.stderr())
	}
}

func TestCardLoginRefusesATokenForAnotherAccount(t *testing.T) {
	h, _, _, spec := cardHarness(t, func(_ *cardtest.Card, b *cardBridge) { b.tokenAccount = "someone-else" })
	if code := h.run("login", "--card", spec); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if creds, _ := h.store(t).Load(); creds != nil {
		t.Error("stored")
	}
}

func TestCardLoginRefusesARemoteCardWithoutInsecureHTTP(t *testing.T) {
	h := newHarness(t, "", http.NotFoundHandler())
	if code := h.run("login", "--card", "tcp:192.0.2.1:9025"); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "cleartext") {
		t.Errorf("stderr = %s", h.stderr())
	}
}

func TestCardLoginFlagRules(t *testing.T) {
	for _, args := range [][]string{
		{"login", "--pin"},
		{"login", "--no-sep10", "alice"},
		{"login", "--card", "tcp:127.0.0.1:1", "alice"},
		{"login", "--card", "tcp:127.0.0.1:1", "--totp"},
		{"login", "--card", "tcp:127.0.0.1:1", "--no-sep10", "--sep10-home-domain", "x"},
	} {
		h := newHarness(t, "", http.NotFoundHandler())
		if code := h.run(args...); code != 2 {
			t.Errorf("%v exit = %d, want 2 (%s)", args, code, h.stderr())
		}
	}
}

// ── card info ──────────────────────────────────────────────────────────

func TestCardInfo(t *testing.T) {
	c := cardtest.New(t)
	c.RequirePIN = true
	spec := c.Start(t)
	h := newHarness(t, "", nil)
	if code := h.run("card", "info", "--card", spec); code != 0 {
		t.Fatalf("exit = %d: %s", code, h.stderr())
	}
	addr, _ := sep10.EncodeAccountID(c.StellarPub())
	for _, want := range []string{"0.4", "ea94fa5b0f6b2abc1626bc50c0bd5e17", "00112233-4455-6677-8899-aabbccddeeff",
		"personalized", addr, "soft engine", "REQUIRED to sign in", "5 tries left", "SEP-10"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("missing %q:\n%s", want, h.stdout())
		}
	}
	if strings.Contains(h.stdout(), "Test Holder") {
		t.Error("the cardholder name was printed")
	}
	for _, l := range c.Log() {
		if strings.HasPrefix(l, "SIGN_") || strings.HasPrefix(l, "VERIFY_PIN") {
			t.Errorf("card info sent %s", l)
		}
	}
	// An applet 0.3 card: no PIN policy to report.
	c3 := cardtest.New(t)
	c3.Minor = 3
	h3 := newHarness(t, "", nil)
	if code := h3.run("card", "info", "--card", c3.Start(t), "--json"); code != 0 {
		t.Fatalf("exit = %d: %s", code, h3.stderr())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(h3.stdout()), &got); err != nil || got["user_verification"] != nil {
		t.Errorf("json = %s (%v)", h3.stdout(), err)
	}
}
