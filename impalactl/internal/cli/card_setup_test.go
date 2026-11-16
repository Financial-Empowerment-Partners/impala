package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"impalactl/internal/card"
	"impalactl/internal/card/cardtest"
	"impalactl/internal/config"
)

// The ceremony against the fake card (the applet's provisioning half) and a
// bridge that really signs certificates.

type setupEnv struct {
	h    *harness
	c    *cardtest.Card
	b    *issueBridge
	spec string
}

func newSetupEnv(t *testing.T, c *cardtest.Card, setup func(*issueBridge)) *setupEnv {
	t.Helper()
	b := newIssueBridge(t)
	if setup != nil {
		setup(b)
	}
	h := newHarness(t, "", b.handler())
	h.env[config.EnvIssueKMK] = recordedKMK
	h.env[config.EnvCardPIN] = recordedPIN
	h.env[config.EnvCardMasterPIN] = recordedMaster
	h.env[config.EnvToken] = b.operator
	h.env[config.EnvHolderToken] = b.holder
	return &setupEnv{h: h, c: c, b: b, spec: c.Start(t)}
}

func (e *setupEnv) run(extra ...string) int {
	return e.h.run(append([]string{"card", "setup", "--card", e.spec, "--account", setupAccount}, extra...)...)
}

// again starts a fresh harness (new output buffers) over the same card and bridge.
func (e *setupEnv) again(t *testing.T) {
	t.Helper()
	env := e.h.env
	srv := e.h.srv
	e.h = newHarness(t, "", nil)
	e.h.srv = srv
	for k, v := range env {
		e.h.env[k] = v
	}
}

func (e *setupEnv) record(t *testing.T) cardSetupRecord {
	t.Helper()
	var r cardSetupRecord
	if err := json.Unmarshal(e.h.out.Bytes(), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, e.h.stdout())
	}
	return r
}

func (e *setupEnv) noSecrets(t *testing.T) {
	t.Helper()
	noSecretsIn(t, e.h, recordedKMK, recordedPIN, recordedMaster, e.b.operator, e.b.holder)
}

func perCardKeys(t *testing.T, kmkHex string, cardID [16]byte) [48]byte {
	t.Helper()
	kmk, _ := hex.DecodeString(kmkHex)
	k, err := card.CardKeys(kmk, cardID[:])
	if err != nil {
		t.Fatal(err)
	}
	var out [48]byte
	copy(out[0:], k.ENC[:])
	copy(out[16:], k.MAC[:])
	copy(out[32:], k.DEK[:])
	return out
}

// initialize puts a blank fake card in the state INITIALIZE leaves.
func initialize(t *testing.T, c *cardtest.Card) {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, st, _ := ed25519.GenerateKey(rand.Reader)
	c.EC, c.Stellar = ec, st
	c.Flags |= cardtest.FlagInitialized
}

func commands(c *cardtest.Card) string {
	var names []string
	for _, l := range c.Log() {
		names = append(names, strings.TrimSuffix(strings.TrimSuffix(l, " P1=00"), " P1=04"))
	}
	return strings.Join(names, " ")
}

func TestCardSetupIssuesAFactoryCard(t *testing.T) {
	c := cardtest.NewBlank(t)
	e := newSetupEnv(t, c, nil)
	if code := e.run("--json", "--currency", "USDC", "--card-minor-scale", "6", "--initial-counter", "9"); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
	}
	want := "SELECT GET_VERSION GET_PERSONALIZATION INITIALIZE GET_USER_DATA GET_EC_PUB_KEY " +
		"INITIALIZE_UPDATE INITIALIZE_UPDATE EXTERNAL_AUTHENTICATE P1=33 APPLET_UPDATE INITIALIZE_UPDATE EXTERNAL_AUTHENTICATE P1=33 " +
		"PERSONALIZE P1=01 PERSONALIZE P1=02 PERSONALIZE P1=03 PROVISION_PIN PROVISION_PIN " +
		"GET_PERSONALIZATION GET_STELLAR_KEY GET_USER_DATA GET_EC_PUB_KEY"
	if got := commands(c); got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
	rec := e.record(t)
	var cardID, account [16]byte
	var pin, master string
	var keys [48]byte
	var counter uint32
	var flags byte
	c.With(func(c *cardtest.Card) {
		cardID, account, pin, master, keys, counter, flags = c.CardID, c.Account, c.PIN, c.MasterPIN, c.StaticKeys, c.Counter, c.Flags
	})
	if rec.CardID != hex.EncodeToString(cardID[:]) || rec.AccountID != setupAccount || card.FormatUUID(account[:]) != setupAccount ||
		rec.Currency != "USDC" || rec.Status != setupIssued || rec.IssuerVersion == nil || *rec.IssuerVersion != 1 ||
		rec.ProgramID != hex.EncodeToString(e.b.programID) {
		t.Errorf("record %+v", rec)
	}
	if pin != recordedPIN || master != recordedMaster || counter != 9 || flags&cardtest.FlagDefaultKeys != 0 {
		t.Errorf("card: pin %q master %q counter %d flags %02x", pin, master, counter, flags)
	}
	if keys != perCardKeys(t, recordedKMK, cardID) {
		t.Error("the card's SCP03 keys are not the per-card keys")
	}
	if rec.StellarKey == nil || !rec.StellarKey.Registered || rec.StellarKey.Note != "" || rec.StellarKey.Engine != "soft" {
		t.Errorf("stellar %+v", rec.StellarKey)
	}
	bc := e.b.card(rec.CardID)
	if bc == nil || bc.cert == "" || bc.stellar != rec.StellarKey.Address || bc.recertified {
		t.Errorf("bridge row %+v", bc)
	}
	if !strings.Contains(e.b.bodies[1], `"card_minor_scale":6`) || !strings.Contains(e.b.bodies[1], `"currency":"USDC"`) ||
		strings.Contains(e.b.bodies[1], "recertify") {
		t.Errorf("certify body %s", e.b.bodies[1])
	}
	for _, n := range []string{"initialized (card key generated)", "card " + rec.CardID,
		"SCP03 keys rotated to per-card keys (APPLET_UPDATE seq 0x0001)", "registered with the bridge (POST /card)",
		"personalized", "PINs provisioned", "Stellar key registered with the bridge (PUT /card/stellar-key)"} {
		if !strings.Contains(e.h.stderr(), n) {
			t.Errorf("stderr lacks %q:\n%s", n, e.h.stderr())
		}
	}
	e.noSecrets(t)

	// The re-run changes nothing on the card and repeats the registration.
	e.again(t)
	before := len(c.Log())
	if code := e.run("--json"); code != 0 {
		t.Fatalf("re-run exit = %d:\n%s", code, e.h.stderr())
	}
	if got := strings.Join(c.Log()[before:], " "); got != "SELECT P1=04 GET_VERSION P1=00 GET_PERSONALIZATION P1=00 "+
		"GET_STELLAR_KEY P1=00 GET_USER_DATA P1=00 GET_EC_PUB_KEY P1=00" {
		t.Errorf("re-run commands: %s", got)
	}
	again := e.record(t)
	if again.Status != setupAlreadyIssued || again.IssuerVersion != nil || again.CertID != rec.CertID ||
		again.StellarKey == nil || !again.StellarKey.Registered {
		t.Errorf("re-run record %+v", again)
	}
	if e.b.called("POST /admin/cards/") != 1 {
		t.Error("the re-run certified again")
	}
	e.noSecrets(t)
}

func TestCardSetupHumanRecordAndCapHash(t *testing.T) {
	c := cardtest.NewBlank(t)
	e := newSetupEnv(t, c, nil)
	capPath := filepath.Join(t.TempDir(), "impala.cap")
	if err := os.WriteFile(capPath, []byte("cap bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := e.run("--cap", capPath); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
	}
	for _, want := range []string{"Card id:", "Certificate id:", "CAP sha256:",
		"e58caf8ab15ded9fb22b2b356505ce625e9074522596b516abc0d3194c0f224f", "Issuer version:  1", "Status:          issued",
		"registered: SEP-10 sign-in"} {
		if !strings.Contains(e.h.stdout(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, e.h.stdout())
		}
	}
	e.noSecrets(t)
}

// Every torn state resumes.
func TestCardSetupResumesATornIssuance(t *testing.T) {
	t.Run("initialized on the default keys", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		initialize(t, c)
		e := newSetupEnv(t, c, nil)
		if code := e.run(); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		if c.Received("INITIALIZE P1") || c.Count("APPLET_UPDATE") != 1 {
			t.Errorf("commands: %s", commands(c))
		}
	})
	t.Run("initialized on the per-card keys", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		initialize(t, c)
		c.InstallKeys(perCardKeys(t, recordedKMK, c.CardID))
		e := newSetupEnv(t, c, nil)
		if code := e.run(); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		if c.Received("APPLET_UPDATE") || c.Count("INITIALIZE_UPDATE") != 1 || !strings.Contains(e.h.stderr(), "SCP03 open on per-card keys") {
			t.Errorf("commands: %s\n%s", commands(c), e.h.stderr())
		}
	})
	t.Run("certified by an earlier run", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		initialize(t, c)
		e := newSetupEnv(t, c, func(b *issueBridge) {
			b.cards[hex.EncodeToString(c.CardID[:])] = &issuedCard{account: setupAccount,
				ecPub: hex.EncodeToString(c.ECPub()), cert: "3006020101020101"}
		})
		if code := e.run("--json"); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		if !strings.Contains(e.h.stderr(), "already registered with the bridge (POST /card not repeated)") ||
			e.b.called("POST /card") != 0 || !strings.Contains(e.h.stderr(), "recertifying") ||
			!e.b.card(hex.EncodeToString(c.CardID[:])).recertified || e.b.called("POST /admin/cards/") != 2 {
			t.Errorf("stderr:\n%s", e.h.stderr())
		}
		if e.record(t).Status != setupIssued {
			t.Error("status")
		}
	})
	t.Run("personalized without its PINs", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		c.Force[0x7000] = 0x6F00 // the first PROVISION_PIN tears
		e := newSetupEnv(t, c, nil)
		if code := e.run(); code != 1 {
			t.Fatalf("torn run exit = %d:\n%s", code, e.h.stderr())
		}
		var flags byte
		var pin string
		c.With(func(c *cardtest.Card) { delete(c.Force, 0x7000); flags, pin = c.Flags, c.PIN })
		if flags&cardtest.FlagPersonalized == 0 || pin != "" {
			t.Fatalf("the torn card: flags %02x pin %q", flags, pin)
		}
		// Under ENFORCE such a card cannot sign (as the real applet answers).
		cd, err := e.h.app.dialCard(options{timeout: 5 * time.Second}, e.spec, "")
		if err != nil {
			t.Fatal(err)
		}
		_, aerr := cd.SignAuth(make([]byte, 32), false)
		_, serr := cd.SignSep10(make([]byte, 32), make([]byte, 64))
		cd.Close()
		if card.SWOf(aerr) != 0x6985 || card.SWOf(serr) != 0x6985 {
			t.Errorf("SIGN_AUTH %v, SIGN_SEP10 %v on a card without a PIN under ENFORCE", aerr, serr)
		}
		e.again(t)
		before := len(c.Log())
		if code := e.run("--json"); code != 0 {
			t.Fatalf("resume exit = %d:\n%s", code, e.h.stderr())
		}
		got := strings.Join(c.Log()[before:], " ")
		want := "SELECT P1=04 GET_VERSION P1=00 GET_PERSONALIZATION P1=00 GET_USER_DATA P1=00 INITIALIZE_UPDATE P1=00 " +
			"EXTERNAL_AUTHENTICATE P1=33 PROVISION_PIN P1=00 PROVISION_PIN P1=00 GET_PERSONALIZATION P1=00 " +
			"GET_STELLAR_KEY P1=00 GET_USER_DATA P1=00 GET_EC_PUB_KEY P1=00"
		if got != want {
			t.Errorf("resume commands:\n got %s\nwant %s", got, want)
		}
		c.With(func(c *cardtest.Card) { pin = c.PIN })
		rec := e.record(t)
		if pin != recordedPIN || rec.Status != setupIssued || rec.IssuerVersion != nil || e.b.called("POST /admin/cards/") != 1 ||
			!strings.Contains(e.h.stderr(), "PINs provisioned (finishing a ceremony that stopped after PERSONALIZE)") {
			t.Errorf("pin %q, record %+v, stderr:\n%s", pin, rec, e.h.stderr())
		}
		if rec.StellarKey == nil || !rec.StellarKey.Registered {
			t.Errorf("stellar %+v", rec.StellarKey)
		}
		e.noSecrets(t)
	})
	t.Run("a 429 at certification, then a re-run", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		e := newSetupEnv(t, c, func(b *issueBridge) { b.certifyStatuses = []int{429} })
		if code := e.run(); code != 1 {
			t.Fatalf("exit = %d", code)
		}
		if !strings.Contains(e.h.stderr(), "share one budget of 5 per 60 s per operator") ||
			!strings.Contains(e.h.stderr(), "continues where it stopped") || c.Received("PERSONALIZE") {
			t.Errorf("stderr:\n%s", e.h.stderr())
		}
		e.again(t)
		if code := e.run(); code != 0 {
			t.Fatalf("re-run exit = %d:\n%s", code, e.h.stderr())
		}
		if c.Count("APPLET_UPDATE") != 1 {
			t.Errorf("the keys were rotated twice: %s", commands(c))
		}
	})
}

func TestCardSetupRefusals(t *testing.T) {
	cases := map[string]struct {
		card   func(t *testing.T) *cardtest.Card
		bridge func(*issueBridge)
		env    map[string]string
		want   string
		// sent: the card must not have received any of these.
		never []string
	}{
		"terminated card": {
			card: func(t *testing.T) *cardtest.Card {
				c := cardtest.NewBlank(t)
				c.Flags |= cardtest.FlagTerminated
				return c
			},
			want: "terminated", never: []string{"INITIALIZE", "GET_USER_DATA"},
		},
		"applet 0.1": {
			card: func(t *testing.T) *cardtest.Card { c := cardtest.NewBlank(t); c.Minor = 1; return c },
			want: "older than 0.2", never: []string{"GET_PERSONALIZATION"},
		},
		"a program-bound card of another program": {
			card: func(t *testing.T) *cardtest.Card {
				c := cardtest.NewBlank(t)
				keys := [48]byte{1}
				c.InstallKeys(keys)
				other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				pub, _ := other.PublicKey.ECDH()
				c.BindProgram([16]byte{9, 9, 9}, pub.Bytes())
				return c
			},
			env:  map[string]string{config.EnvSCP03TransportKeys: hex.EncodeToString(append([]byte{1}, make([]byte, 47)...))},
			want: "bound at install to program 09090900000000000000000000000000", never: []string{"PERSONALIZE"},
		},
		"an issuer key that differs from GET /card-issuer": {
			card:   cardtest.NewBlank,
			bridge: func(b *issueBridge) { b.issuerOverride = "04" + strings.Repeat("ab", 64) },
			want:   "differs from GET /card-issuer", never: []string{"PERSONALIZE"},
		},
		"a program id that differs from GET /card-issuer": {
			card:   cardtest.NewBlank,
			bridge: func(b *issueBridge) { b.programOverride = strings.Repeat("cd", 16) },
			want:   "program id", never: []string{"PERSONALIZE"},
		},
		"a certificate that does not verify": {
			card:   cardtest.NewBlank,
			bridge: func(b *issueBridge) { b.corruptCert = true },
			want:   "does not verify under the issuer key over the CERT message: nothing was sent to the card",
			never:  []string{"PERSONALIZE"},
		},
		"no card program": {
			card:   cardtest.NewBlank,
			bridge: func(b *issueBridge) { b.configured = false },
			want:   "`impalactl card issuer generate`", never: []string{"SELECT"},
		},
		"a holder token for another account": {
			card:  cardtest.NewBlank,
			env:   map[string]string{config.EnvHolderToken: token(t, "11111111-2222-4333-8444-555555555555", "view-only", time.Hour)},
			want:  "is a token for account 11111111-2222-4333-8444-555555555555, not --account " + setupAccount,
			never: []string{"SELECT"},
		},
		"the wrong KMK on a rotated card": {
			card: func(t *testing.T) *cardtest.Card {
				c := cardtest.NewBlank(t)
				initialize(t, c)
				c.InstallKeys(perCardKeys(t, "ffeeddccbbaa99887766554433221100", c.CardID))
				return c
			},
			want:  "neither on the keys $IMPALA_ISSUE_KMK derives for it nor on the transport keys",
			never: []string{"EXTERNAL_AUTHENTICATE", "APPLET_UPDATE", "PERSONALIZE"},
		},
		"confirmation declined on a live network": {
			card:   cardtest.NewBlank,
			bridge: func(b *issueBridge) { b.network = "pubnet" },
			want:   "refusing to issue this card on PUBNET without confirmation",
			never:  []string{"INITIALIZE", "GET_USER_DATA", "INITIALIZE_UPDATE"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := tc.card(t)
			e := newSetupEnv(t, c, tc.bridge)
			for k, v := range tc.env {
				e.h.env[k] = v
			}
			if code := e.run(); code != 1 {
				t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
			}
			if !strings.Contains(e.h.stderr(), tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, e.h.stderr())
			}
			for _, n := range tc.never {
				if c.Received(n + " ") {
					t.Errorf("the card received %s: %s", n, commands(c))
				}
			}
			e.noSecrets(t)
		})
	}
}

func TestCardSetupConfirmationShowsWhatHappens(t *testing.T) {
	c := cardtest.NewBlank(t)
	e := newSetupEnv(t, c, func(b *issueBridge) { b.network = "pubnet" })
	if code := e.run(); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if got := commands(c); got != "SELECT GET_VERSION GET_PERSONALIZATION" {
		t.Errorf("commands before the confirmation: %s", got)
	}
	for _, want := range []string{"blank", setupAccount, "network pubnet", "XLM, card minor scale 7",
		"writes a certificate on the bridge and personalizes the card; neither can be undone"} {
		if strings.Contains(e.h.stderr(), "FUNDS") {
			t.Errorf("a card issuance talks about funds:\n%s", e.h.stderr())
		}
		if !strings.Contains(e.h.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, e.h.stderr())
		}
	}
	e.again(t)
	if code := e.run("--yes"); code != 0 {
		t.Fatalf("--yes exit = %d:\n%s", code, e.h.stderr())
	}
	if strings.Contains(e.h.stderr(), "neither can be undone") {
		t.Error("--yes still printed the confirmation summary")
	}
}

func TestCardSetupProgramBoundCardSkipsPartB(t *testing.T) {
	c := cardtest.NewBlank(t)
	var keys [48]byte
	_, _ = rand.Read(keys[:])
	c.InstallKeys(keys)
	e := newSetupEnv(t, c, nil)
	pub, _ := e.b.issuer.PublicKey.ECDH()
	var program [16]byte
	copy(program[:], e.b.programID)
	c.With(func(c *cardtest.Card) { c.BindProgram(program, pub.Bytes()) })
	e.h.env[config.EnvSCP03TransportKeys] = hex.EncodeToString(keys[:])
	if code := e.run(); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
	}
	if c.Received("PERSONALIZE P1=02") || !c.Received("PERSONALIZE P1=03") || c.Count("APPLET_UPDATE") != 1 {
		t.Errorf("commands: %s", commands(c))
	}
}

func TestCardSetupBridgeRefusalsThatAreNotFatal(t *testing.T) {
	t.Run("POST /card answers 500, certification fine", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		initialize(t, c)
		e := newSetupEnv(t, c, func(b *issueBridge) {
			b.cards[hex.EncodeToString(c.CardID[:])] = &issuedCard{account: setupAccount, ecPub: hex.EncodeToString(c.ECPub())}
			b.listStatus = 503 // the listing fails, so the POST is made
		})
		if code := e.run(); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		if !strings.Contains(e.h.stderr(), "POST /card refused (HTTP 500): the card is probably registered already; "+
			"continuing (certification requires the card row)") {
			t.Errorf("stderr:\n%s", e.h.stderr())
		}
	})
	t.Run("PUT /card/stellar-key refused", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		e := newSetupEnv(t, c, func(b *issueBridge) { b.putStatus = 409 })
		if code := e.run("--json"); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		rec := e.record(t)
		if rec.StellarKey == nil || rec.StellarKey.Registered || !strings.Contains(rec.StellarKey.Note, "legacy challenge") ||
			rec.Status != setupIssued || !strings.Contains(e.h.stderr(), "PUT /card/stellar-key failed") {
			t.Errorf("record %+v\n%s", rec, e.h.stderr())
		}
	})
	t.Run("a card without a Stellar key", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		c.NoStellarEngine = true
		e := newSetupEnv(t, c, nil)
		if code := e.run("--json"); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		var got map[string]any
		_ = json.Unmarshal(e.h.out.Bytes(), &got)
		if v, ok := got["stellar_key"]; !ok || v != nil || c.Received("GET_STELLAR_KEY") || e.b.called("PUT ") != 0 {
			t.Errorf("record %s", e.h.stdout())
		}
	})
}

// Only 500 and 409 from POST /card are "probably registered already"; any
// other refusal stops the ceremony before the certificate is requested.
func TestCardSetupFatalRegistrationRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		want   string
	}{
		{400, "bad_request", "POST /card, HTTP 400"},
		{401, "unauthorized", "the holder's token is not accepted"},
		{403, "forbidden", "the bridge refused the holder's request"},
		{403, "mfa_required", "hint: this account must be multi-factor"},
		{429, "rate_limited", "POST /card, HTTP 429"},
	} {
		c := cardtest.NewBlank(t)
		e := newSetupEnv(t, c, func(b *issueBridge) { b.postCardStatus, b.postCardCode = tc.status, tc.code })
		if code := e.run(); code != 1 {
			t.Fatalf("%d %s: exit = %d", tc.status, tc.code, code)
		}
		if !strings.Contains(e.h.stderr(), tc.want) || e.b.called("POST /admin/cards/") != 0 || c.Received("PERSONALIZE") {
			t.Errorf("%d %s: stderr:\n%s", tc.status, tc.code, e.h.stderr())
		}
	}
}

// A session without keys-manage is not refused locally: the bridge answers
// 403 at the certificate, the card is left initialized, rotated and
// registered, and the operator's next run finishes it.
func TestCardSetupResumesAfterAHolderOnlyRun(t *testing.T) {
	c := cardtest.NewBlank(t)
	e := newSetupEnv(t, c, nil)
	e.h.env[config.EnvToken] = e.b.holder
	delete(e.h.env, config.EnvHolderToken)
	if code := e.run(); code != 1 {
		t.Fatalf("holder-only exit = %d:\n%s", code, e.h.stderr())
	}
	if !strings.Contains(e.h.stderr(), "403") || !strings.Contains(e.h.stderr(), "registered with the bridge (POST /card)") ||
		c.Received("PERSONALIZE") || c.Count("APPLET_UPDATE") != 1 {
		t.Fatalf("holder-only run:\n%s\n%s", e.h.stderr(), commands(c))
	}
	e.again(t)
	e.h.env[config.EnvToken] = e.b.operator
	e.h.env[config.EnvHolderToken] = e.b.holder
	if code := e.run("--json"); code != 0 {
		t.Fatalf("operator exit = %d:\n%s", code, e.h.stderr())
	}
	stderr := e.h.stderr()
	if !strings.Contains(stderr, "SCP03 open on per-card keys") || strings.Contains(stderr, "initialized (card key generated)") ||
		strings.Contains(stderr, "keys rotated") || !strings.Contains(stderr, "POST /card not repeated") ||
		e.b.called("POST /card") != 1 {
		t.Errorf("operator run:\n%s", stderr)
	}
	if rec := e.record(t); rec.Status != setupIssued || rec.StellarKey == nil || !rec.StellarKey.Registered {
		t.Errorf("record %+v", rec)
	}
}

func TestCardSetupHolderTokenRules(t *testing.T) {
	t.Run("unset, and the session is the holder", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		both := token(t, setupAccount, "admin", time.Hour)
		e := newSetupEnv(t, c, func(b *issueBridge) { b.operator, b.holder = both, both })
		delete(e.h.env, config.EnvHolderToken)
		if code := e.run(); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
		}
		e.noSecrets(t)
	})
	for name, value := range map[string]string{"unset": "", "set but empty": "  "} {
		t.Run(name+", and the session is someone else", func(t *testing.T) {
			c := cardtest.NewBlank(t)
			e := newSetupEnv(t, c, nil)
			e.h.env[config.EnvHolderToken] = value
			// No secret is set either: the missing token is reported first, without a prompt.
			for _, k := range []string{config.EnvIssueKMK, config.EnvCardPIN, config.EnvCardMasterPIN} {
				delete(e.h.env, k)
			}
			if code := e.run(); code != 2 {
				t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
			}
			if !strings.Contains(e.h.stderr(), "set $IMPALA_HOLDER_TOKEN") || strings.Contains(e.h.stderr(), "secret") ||
				strings.Contains(e.h.stderr(), "KMK") || len(c.Log()) != 0 || e.b.called("") != 0 {
				t.Errorf("stderr:\n%s\ncard: %v", e.h.stderr(), c.Log())
			}
		})
	}
	t.Run("an empty IMPALA_TOKEN is unset too", func(t *testing.T) {
		c := cardtest.NewBlank(t)
		e := newSetupEnv(t, c, nil)
		e.h.env[config.EnvToken] = " "
		if code := e.run(); code != 1 || !strings.Contains(e.h.stderr(), "not logged in") || len(c.Log()) != 0 {
			t.Errorf("exit = %d:\n%s", code, e.h.stderr())
		}
	})
}

func TestCardSetupRefusesACardIssuedToAnotherAccount(t *testing.T) {
	c := cardtest.New(t) // personalized for 00112233-…
	e := newSetupEnv(t, c, nil)
	if code := e.run(); code != 1 {
		t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
	}
	if !strings.Contains(e.h.stderr(), "is issued to account 00112233-4455-6677-8899-aabbccddeeff, not --account "+setupAccount) {
		t.Errorf("stderr:\n%s", e.h.stderr())
	}
	if e.b.called("POST") != 0 || e.b.called("PUT") != 0 {
		t.Error("a bridge write was made")
	}
}

func TestCardSetupUsageAndSecrets(t *testing.T) {
	c := cardtest.NewBlank(t)
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"--account", "nope"}, nil, "--account must be a UUID"},
		{[]string{"--account", setupAccount, "--currency", "EUR"}, nil, "--currency"},
		{[]string{"--account", setupAccount, "--card-minor-scale", "8"}, nil, "--card-minor-scale"},
		{[]string{"--account", setupAccount, "--initial-counter", "2147483648"}, nil, "--initial-counter"},
		{[]string{"--account", setupAccount}, map[string]string{config.EnvIssueKMK: "abcd"}, "$IMPALA_ISSUE_KMK must be 32 hex"},
		{[]string{"--account", setupAccount}, map[string]string{config.EnvCardPIN: "0000"}, "not all zeros"},
		{[]string{"--account", setupAccount}, map[string]string{config.EnvCardMasterPIN: "1234"}, "must be 8 digits"},
		{[]string{"--account", setupAccount}, map[string]string{config.EnvSCP03TransportKeys: "00"}, "96 hex"},
		{[]string{"--account", setupAccount, "--kmk", recordedKMK}, nil, "flag provided but not defined"},
	} {
		e := newSetupEnv(t, c, nil)
		for k, v := range tc.env {
			e.h.env[k] = v
		}
		code := e.h.run(append([]string{"card", "setup", "--card", e.spec}, tc.args...)...)
		if code != 2 || !strings.Contains(e.h.stderr(), tc.want) {
			t.Errorf("%v: exit %d, stderr %q", tc.args, code, e.h.stderr())
		}
		for _, v := range tc.env {
			if len(v) > 2 && strings.Contains(e.h.stderr(), v) {
				t.Errorf("%v: the value reached stderr", tc.args)
			}
		}
	}
	if len(c.Log()) != 0 {
		t.Errorf("a usage error touched the card: %v", c.Log())
	}
}

// The three secrets also come from stdin, one line each, in order.
func TestCardSetupReadsTheSecretsFromStdin(t *testing.T) {
	c := cardtest.NewBlank(t)
	e := newSetupEnv(t, c, nil)
	for _, k := range []string{config.EnvIssueKMK, config.EnvCardPIN, config.EnvCardMasterPIN} {
		delete(e.h.env, k)
	}
	e.h.app.in = strings.NewReader(recordedKMK + "\n" + recordedPIN + "\n" + recordedMaster + "\n")
	if code := e.run(); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, e.h.stderr())
	}
	var pin, master string
	c.With(func(c *cardtest.Card) { pin, master = c.PIN, c.MasterPIN })
	if pin != recordedPIN || master != recordedMaster {
		t.Errorf("pin %q master %q", pin, master)
	}
	e.noSecrets(t)
}

// The --json record is an append-only schema: these keys, in this order.
func TestCardSetupRecordSchemaIsPinned(t *testing.T) {
	one := 1
	b, _ := json.Marshal(cardSetupRecord{CardID: "c", AccountID: "a", ProgramID: "p", Currency: "XLM", CertID: "i",
		Applet: "0.4", AppletHash: "h", CapSHA256: "s", IssuerVersion: &one,
		StellarKey: &cardSetupStellar{Address: "G", Engine: "soft", Registered: false, Note: "n"}, Status: "issued"})
	want := `{"card_id":"c","account_id":"a","program_id":"p","currency":"XLM","cert_id":"i","applet":"0.4",` +
		`"applet_hash":"h","cap_sha256":"s","issuer_version":1,"stellar_key":{"address":"G","engine":"soft",` +
		`"registered":false,"note":"n"},"status":"issued"}`
	if string(b) != want {
		t.Errorf("schema:\n got %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(cardSetupRecord{Status: "already-issued"})
	if !strings.Contains(string(b), `"stellar_key":null`) || strings.Contains(string(b), "cap_sha256") ||
		strings.Contains(string(b), "issuer_version") {
		t.Errorf("omissions: %s", b)
	}
}
