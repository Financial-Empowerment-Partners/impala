package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Deterministic test keys (raw seeds derived from fixed labels), so golden
// files can name them. They hold nothing on any network.
func testKey(label string) *keypair.Full {
	seed := sha256.Sum256([]byte("lumencli sep10 test key: " + label))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		panic(err)
	}
	return kp
}

var (
	sep10ServerKP = testKey("server")
	sep10WalletKP = testKey("wallet")
	sep10OtherKP  = testKey("other")
)

// The fake's fixed token times, so the issued JWT (and every golden holding
// it) is deterministic.
const (
	sep10FakeIat = 1763200000
	sep10FakeExp = 1763286400
)

// sep10Fake is a SEP-10 server. Its challenges come from the SDK's own
// txnbuild.BuildChallengeTx — the builder real Go servers use — and its token
// endpoint verifies the signed challenge with txnbuild.VerifyChallengeTxSigners,
// exactly as a real server does, so a test cannot certify a challenge no
// server would produce or a signature no server would accept. A refusal test
// starts from such a challenge and changes one property (mutate), re-signing
// it with the server key unless the test is about the signature.
type sep10Fake struct {
	t   *testing.T
	srv *httptest.Server

	home          string // the home domain the server is configured with
	endpoint      string // WEB_AUTH_ENDPOINT
	webAuthDomain string
	server        *keypair.Full
	signFor       string // passphrase the fake signs challenges under

	toml           string // the stellar.toml served; "" selects the default
	respPassphrase string // network_passphrase in the challenge response; "" = signFor, "-" = omit
	mutate         func(env *xdr.TransactionEnvelope)
	resignWith     *keypair.Full // re-signs mutated challenges; nil = server; set noResign to skip
	noResign       bool
	tokenStatus    int    // non-zero: answer the POST with this status and tokenBody
	tokenBody      string // raw body for tokenStatus

	mu      sync.Mutex
	queries []url.Values
	issued  []string
	posted  []string
	tokens  []string
}

// newSep10Fake starts an https fake for the home domain example.com (the
// name httptest's certificate is issued for). The App reaches it through
// sep10FakeClient, which dials the fake whatever host a URL names.
func newSep10Fake(t *testing.T) *sep10Fake {
	t.Helper()
	f := &sep10Fake{
		t: t, home: "example.com", endpoint: "https://example.com/auth", webAuthDomain: "example.com",
		server: sep10ServerKP, signFor: network.TestNetworkPassphrase,
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// newSep10LoopbackFake starts a plain-http fake on 127.0.0.1: the loopback
// exception of the transport policy. The home domain is its host:port.
func newSep10LoopbackFake(t *testing.T) *sep10Fake {
	t.Helper()
	f := &sep10Fake{t: t, server: sep10ServerKP, signFor: network.TestNetworkPassphrase}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.home = f.srv.Listener.Addr().String()
	f.endpoint = "http://" + f.home + "/auth"
	f.webAuthDomain = f.home
	return f
}

// app builds a test App wired to the fake.
func (f *sep10Fake) app(stdin string, env map[string]string) (*App, *bytes.Buffer, *bytes.Buffer) {
	app, out, errb := newTestApp(stdin, env)
	if f.srv.TLS != nil {
		app.sep10HTTP = f.client()
	}
	return app, out, errb
}

func (f *sep10Fake) client() *http.Client {
	tr := f.srv.Client().Transport.(*http.Transport).Clone()
	addr := f.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, netw, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, netw, addr)
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (f *sep10Fake) defaultTOML() string {
	return fmt.Sprintf("# fake anchor\nVERSION = \"2.0.0\"\nNETWORK_PASSPHRASE = %q\nWEB_AUTH_ENDPOINT = %q\nSIGNING_KEY = %q\n\n[DOCUMENTATION]\nORG_NAME = \"Fake\"\n",
		f.signFor, f.endpoint, f.server.Address())
}

func (f *sep10Fake) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/stellar.toml" && r.Method == http.MethodGet:
		body := f.toml
		if body == "" {
			body = f.defaultTOML()
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	case r.URL.Path == "/auth" && r.Method == http.MethodGet:
		f.challenge(w, r)
	case r.URL.Path == "/auth" && r.Method == http.MethodPost:
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *sep10Fake) challenge(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()
	tx, err := txnbuild.BuildChallengeTx(f.server.Seed(), q.Get("account"), f.webAuthDomain, f.home, f.signFor, 5*time.Minute, nil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	b64, err := tx.Base64()
	if err != nil {
		f.t.Errorf("fake: encode challenge: %v", err)
		return
	}
	if f.mutate != nil {
		b64 = f.applyMutation(b64)
	}
	f.mu.Lock()
	f.issued = append(f.issued, b64)
	f.mu.Unlock()
	resp := map[string]string{"transaction": b64}
	switch f.respPassphrase {
	case "":
		resp["network_passphrase"] = f.signFor
	case "-":
	default:
		resp["network_passphrase"] = f.respPassphrase
	}
	writeJSON(w, http.StatusOK, resp)
}

func (f *sep10Fake) applyMutation(b64 string) string {
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(b64, &env); err != nil {
		f.t.Fatalf("fake: decode own challenge: %v", err)
	}
	f.mutate(&env)
	if !f.noResign {
		signer := f.resignWith
		if signer == nil {
			signer = f.server
		}
		hash, err := network.HashTransactionInEnvelope(env, f.signFor)
		if err != nil {
			f.t.Fatalf("fake: hash: %v", err)
		}
		sig, err := signer.SignDecorated(hash[:])
		if err != nil {
			f.t.Fatalf("fake: sign: %v", err)
		}
		switch env.Type {
		case xdr.EnvelopeTypeEnvelopeTypeTxV0:
			env.V0.Signatures = []xdr.DecoratedSignature{sig}
		default:
			env.V1.Signatures = []xdr.DecoratedSignature{sig}
		}
	}
	out, err := xdr.MarshalBase64(env)
	if err != nil {
		f.t.Fatalf("fake: encode: %v", err)
	}
	return out
}

func (f *sep10Fake) token(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transaction string `json:"transaction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	f.mu.Lock()
	f.posted = append(f.posted, req.Transaction)
	f.mu.Unlock()
	if f.tokenStatus != 0 {
		w.WriteHeader(f.tokenStatus)
		_, _ = w.Write([]byte(f.tokenBody))
		return
	}
	// Verify the way a real server does: structure, the server's own
	// signature, and the client account's signature, every signature
	// accounted for.
	_, client, _, _, err := txnbuild.ReadChallengeTx(req.Transaction, f.server.Address(), f.signFor, f.webAuthDomain, []string{f.home})
	if err == nil {
		_, err = txnbuild.VerifyChallengeTxSigners(req.Transaction, f.server.Address(), f.signFor, f.webAuthDomain, []string{f.home}, client)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	tok := fakeJWT(f.endpoint, client)
	f.mu.Lock()
	f.tokens = append(f.tokens, tok)
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// fakeJWT issues an HS256 JWT the way SEP-10 servers do (iss = the endpoint,
// sub = the account), with fixed times so it is deterministic.
func fakeJWT(iss, sub string) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc([]byte(fmt.Sprintf(`{"iss":%q,"sub":%q,"iat":%d,"exp":%d,"jti":"fake"}`, iss, sub, sep10FakeIat, sep10FakeExp)))
	mac := hmac.New(sha256.New, []byte("fake server secret"))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + enc(mac.Sum(nil))
}

func (f *sep10Fake) snapshot() (queries []url.Values, issued, posted, tokens []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.queries...), append([]string(nil), f.issued...),
		append([]string(nil), f.posted...), append([]string(nil), f.tokens...)
}
