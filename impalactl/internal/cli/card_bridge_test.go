package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"impalactl/internal/sep10"
)

// issueBridge is a stub bridge for the card program and issuance routes that
// checks what it receives the way the bridge does (handlers/card.rs,
// admin_card_issuer.rs, card_issuer.rs, sep10/binding.rs): bearer tokens per
// route, the owner rule of POST /card, lowercase hex shapes, write-once
// certificates (409 without recertify), certificates really signed with a
// P-256 issuer key over the CERT message, and the Stellar key's two
// cross-signatures verified before they are stored.
type issueBridge struct {
	t             *testing.T
	operator      string // the operator's bearer token (ManageKeys)
	holder        string // the holder's bearer token
	holderAccount string
	network       string

	configured  bool
	issuer      *ecdsa.PrivateKey // nil: fixedCert answers every certification
	issuerHex   string
	programID   []byte
	fixedCert   []byte
	version     int
	fingerprint string

	postCardStatus  int
	postCardCode    string
	listStatus      int
	certifyStatuses []int // answered in order before certification proceeds
	issuerOverride  string
	programOverride string
	corruptCert     bool
	putStatus       int
	generateStatus  int

	mu       sync.Mutex
	cards    map[string]*issuedCard
	calls    []string
	bodies   []string
	generate []string // generate request bodies
}

type issuedCard struct {
	account, ecPub, cert, stellar string
	recertified                   bool
}

const (
	setupAccount   = "6f1d9c52-0b7e-4c3a-9e15-2a4b8c7d6e90"
	operatorSub    = "0a0a0a0a-1111-4222-8333-444444444444"
	recordedKMK    = "000102030405060708090a0b0c0d0e0f"
	recordedPIN    = "4821"
	recordedMaster = "31415926"
)

func newIssueBridge(t *testing.T) *issueBridge {
	b := &issueBridge{
		t:             t,
		operator:      token(t, operatorSub, "key-custodian", time.Hour),
		holder:        token(t, setupAccount, "view-only", time.Hour),
		holderAccount: setupAccount,
		network:       "testnet",
		configured:    true,
		version:       1,
		cards:         map[string]*issuedCard{},
	}
	b.newKey()
	return b
}

func (b *issueBridge) newKey() {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.t.Fatal(err)
	}
	pub, _ := k.PublicKey.ECDH()
	b.issuer, b.issuerHex = k, hex.EncodeToString(pub.Bytes())
	sum := sha256.Sum256(pub.Bytes())
	b.fingerprint = hex.EncodeToString(sum[:8])
	if b.programID == nil {
		b.programID = make([]byte, 16)
		_, _ = rand.Read(b.programID)
	}
}

func (b *issueBridge) called(prefix string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (b *issueBridge) card(id string) *issuedCard {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cards[id]
}

var lowerHex = regexp.MustCompile(`^[0-9a-f]+$`)

func certMessage(program, account []byte, currency string, pub []byte) []byte {
	tags := map[string]string{"XLM": "XLM\x00", "USDC": "USDC", "USDT0": "UST0"}
	m := append([]byte("IMPALA-CERT:\x01"), program...)
	m = append(m, account...)
	m = append(m, tags[currency]...)
	return append(m, pub...)
}

func (b *issueBridge) handler() http.Handler {
	mux := http.NewServeMux()
	fail := func(w http.ResponseWriter, status int, code string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"error":{"code":%q,"message":"HTTP %d %s"}}`, code, status, code)
	}
	auth := func(r *http.Request, tok string) bool { return r.Header.Get("Authorization") == "Bearer "+tok }
	record := func(r *http.Request) map[string]any {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := json.Marshal(body)
		b.calls = append(b.calls, r.Method+" "+r.URL.Path)
		b.bodies = append(b.bodies, string(raw))
		return body
	}
	mux.HandleFunc("GET /network", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"stellar_network":%q,"network_passphrase":%q}`, b.network, testnetPassphrase)
	})
	mux.HandleFunc("GET /card-issuer", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.calls = append(b.calls, "GET /card-issuer")
		if !b.configured {
			fmt.Fprint(w, `{"configured":false}`)
			return
		}
		fmt.Fprintf(w, `{"configured":true,"version":%d,"public_key_hex":%q,"fingerprint":%q,`+
			`"redemption_uuid":"9e1f0000-0000-4000-8000-00000000abcd","program_id_hex":%q}`,
			b.version, b.issuerHex, b.fingerprint, hex.EncodeToString(b.programID))
	})
	mux.HandleFunc("POST /card", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body := record(r)
		if !auth(r, b.holder) {
			fail(w, 401, "unauthorized")
			return
		}
		if body["account_id"] != b.holderAccount {
			fail(w, 403, "forbidden")
			return
		}
		id, _ := body["card_id"].(string)
		pub, _ := body["ec_pubkey"].(string)
		if len(id) != 32 || !lowerHex.MatchString(id) || len(pub) != 130 || !lowerHex.MatchString(pub) {
			b.t.Errorf("POST /card shapes: %v", body)
			fail(w, 400, "bad_request")
			return
		}
		if b.postCardStatus != 0 {
			code := b.postCardCode
			if code == "" {
				code = "x"
			}
			fail(w, b.postCardStatus, code)
			return
		}
		if b.cards[id] != nil {
			fail(w, 500, "internal_error") // the unique violation's generic answer
			return
		}
		b.cards[id] = &issuedCard{account: b.holderAccount, ecPub: pub}
		fmt.Fprint(w, `{"success":true,"message":"Card created successfully"}`)
	})
	mux.HandleFunc("GET /admin/accounts/{account}/cards", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.calls = append(b.calls, "GET /admin/accounts/cards")
		if !auth(r, b.operator) {
			fail(w, 403, "forbidden")
			return
		}
		if b.listStatus != 0 {
			fail(w, b.listStatus, "x")
			return
		}
		var rows []string
		for id, c := range b.cards {
			if c.account == r.PathValue("account") {
				rows = append(rows, fmt.Sprintf(`{"card_id":%q,"active":true,"stellar_address":null}`, id))
			}
		}
		fmt.Fprintf(w, `{"cards":[%s]}`, strings.Join(rows, ","))
	})
	mux.HandleFunc("POST /admin/cards/{id}/certificate", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body := record(r)
		if !auth(r, b.operator) {
			fail(w, 403, "forbidden")
			return
		}
		if len(b.certifyStatuses) > 0 {
			st := b.certifyStatuses[0]
			b.certifyStatuses = b.certifyStatuses[1:]
			if st == 429 {
				w.Header().Set("Retry-After", "60")
			}
			fail(w, st, "rate_limited")
			return
		}
		id := r.PathValue("id")
		cur, _ := body["currency"].(string)
		scale, ok := body["card_minor_scale"].(float64)
		recertify, _ := body["recertify"].(bool)
		if (cur != "XLM" && cur != "USDC" && cur != "USDT0") || !ok || scale < 0 || scale > 7 {
			fail(w, 400, "bad_request")
			return
		}
		c := b.cards[id]
		if c == nil {
			fail(w, 404, "not_found")
			return
		}
		if c.cert != "" && !recertify {
			fail(w, 409, "conflict")
			return
		}
		account, _ := hex.DecodeString(strings.ReplaceAll(c.account, "-", ""))
		pub, _ := hex.DecodeString(c.ecPub)
		msg := certMessage(b.programID, account, cur, pub)
		cert := b.fixedCert
		if b.issuer != nil {
			h := sha256.Sum256(msg)
			cert, _ = ecdsa.SignASN1(rand.Reader, b.issuer, h[:])
		}
		if b.corruptCert {
			cert = append([]byte(nil), cert...)
			cert[len(cert)-1] ^= 0x01
		}
		c.cert, c.recertified = hex.EncodeToString(cert), recertify
		issuer, program := b.issuerHex, hex.EncodeToString(b.programID)
		if b.issuerOverride != "" {
			issuer = b.issuerOverride
		}
		if b.programOverride != "" {
			program = b.programOverride
		}
		h := sha256.Sum256(msg)
		fmt.Fprintf(w, `{"card_id":%q,"issuer_version":%d,"issuer_cert_hex":%q,"cert_message_hex":%q,`+
			`"cert_id":%q,"issuer_public_key_hex":%q,"program_id_hex":%q,"currency":%q,"card_minor_scale":%d,"replaced":%v}`,
			id, b.version, c.cert, hex.EncodeToString(msg), hex.EncodeToString(h[:]), issuer, program, cur, int(scale), recertify)
	})
	mux.HandleFunc("PUT /card/stellar-key", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		body := record(r)
		if !auth(r, b.holder) {
			fail(w, 401, "unauthorized")
			return
		}
		if b.putStatus != 0 {
			fail(w, b.putStatus, "x")
			return
		}
		id, _ := body["card_id"].(string)
		c := b.cards[id]
		if c == nil || c.account != b.holderAccount {
			fail(w, 404, "not_found")
			return
		}
		addr, _ := body["stellar_address"].(string)
		bsig, _ := body["stellar_binding_sig"].(string)
		psig, _ := body["stellar_proof_sig"].(string)
		if !lowerHex.MatchString(bsig) || len(psig) != 128 || !lowerHex.MatchString(psig) || !b.bindingVerifies(c, id, addr, bsig, psig) {
			fail(w, 400, "invalid_stellar_binding")
			return
		}
		switch {
		case c.stellar == addr:
			fmt.Fprint(w, `{"success":true,"message":"Stellar key already registered"}`)
		case c.stellar != "":
			fail(w, 409, "stellar_key_already_set")
		default:
			c.stellar = addr
			fmt.Fprint(w, `{"success":true,"message":"Stellar key registered"}`)
		}
	})
	mux.HandleFunc("POST /admin/card-issuer/generate", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		raw := new(strings.Builder)
		var body map[string]string
		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&body)
		enc, _ := json.Marshal(body)
		raw.Write(enc)
		b.generate = append(b.generate, raw.String())
		if !auth(r, b.operator) {
			fail(w, 403, "forbidden")
			return
		}
		if b.generateStatus != 0 {
			if b.generateStatus == 429 {
				w.Header().Set("Retry-After", "60")
			}
			fail(w, b.generateStatus, "rate_limited")
			return
		}
		replaced := false
		if b.configured {
			if body["confirm_supersede"] != b.fingerprint || body["confirm_phrase"] != "replace card-issuer "+b.network {
				fail(w, 409, "conflict")
				return
			}
			replaced = true
			b.version++
		}
		b.configured = true
		b.newKey()
		fmt.Fprintf(w, `{"version":%d,"public_key_hex":%q,"fingerprint":%q,"redemption_uuid":"9e1f0000-0000-4000-8000-00000000abcd",`+
			`"program_id_hex":%q,"replaced":%v,"note":"The key was generated inside the bridge."}`,
			b.version, b.issuerHex, b.fingerprint, hex.EncodeToString(b.programID), replaced)
	})
	return mux
}

// bindingVerifies is sep10/binding.rs: both cross-signatures over the
// messages rebuilt from the stored card row.
func (b *issueBridge) bindingVerifies(c *issuedCard, id, addr, bsigHex, psigHex string) bool {
	stellar, err := sep10.DecodeAccountID(addr)
	if err != nil {
		return false
	}
	account, _ := hex.DecodeString(strings.ReplaceAll(c.account, "-", ""))
	cardID, _ := hex.DecodeString(id)
	ecPub, _ := hex.DecodeString(c.ecPub)
	bsig, _ := hex.DecodeString(bsigHex)
	psig, _ := hex.DecodeString(psigHex)
	ec, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecPub)
	if err != nil {
		return false
	}
	binding := append(append(append([]byte("IMPALA-SKEY:\x01"), account...), cardID...), stellar...)
	h := sha256.Sum256(binding)
	proof := append(append(append([]byte("IMPALA-SKEY:\x02"), account...), cardID...), ecPub...)
	return ecdsa.VerifyASN1(ec, h[:], bsig) && ed25519.Verify(ed25519.PublicKey(stellar), proof, psig)
}
