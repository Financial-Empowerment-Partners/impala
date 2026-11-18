package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"lumencli/internal/card/cardtest"
)

// startCard serves a fake issued card (cardtest.New), changed by setup when
// given, and returns it with its spec.
func startCard(t *testing.T, setup func(*cardtest.Card)) (*cardtest.Card, string) {
	t.Helper()
	fc := cardtest.New()
	if setup != nil {
		setup(fc)
	}
	return fc, fc.Start(t)
}

func cardAddress(t *testing.T, fc *cardtest.Card) string {
	t.Helper()
	addr, err := strkey.Encode(strkey.VersionByteAccountID, fc.StellarPub())
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// assertNoPIN fails if the card PIN appears in any output.
func assertNoPIN(t *testing.T, out, errOut string) {
	t.Helper()
	if strings.Contains(out, cardtest.TestPIN) || strings.Contains(errOut, cardtest.TestPIN) {
		t.Error("the card PIN appears in the output")
	}
}

func TestSep10LoginWithCard(t *testing.T) {
	f := newSep10Fake(t)
	fc, spec := startCard(t, nil)
	addr := cardAddress(t, fc)
	// A seed in the environment is not used: with --card, the card signs.
	app, out, errb := f.app("", walletEnv())
	if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	queries, issued, posted, tokens := f.snapshot()
	if len(issued) != 1 || len(posted) != 1 || len(tokens) != 1 {
		t.Fatalf("issued=%d posted=%d tokens=%d, want 1 each", len(issued), len(posted), len(tokens))
	}
	if got, want := out.String(), tokens[0]+"\n"; got != want {
		t.Errorf("stdout = %q, want the token alone", got)
	}
	if q := queries[0]; q.Get("account") != addr {
		t.Errorf("the challenge was asked for %s, want the card's address %s", q.Get("account"), addr)
	}
	stderr := errb.String()
	assertNoSecrets(t, out.String(), stderr, tokens[0])
	for _, want := range []string{
		"Card:        " + spec + " (applet 0.4, soft Ed25519 engine)",
		"Account:     " + addr + " (the card's Stellar key)",
		"the card signed the challenge and the server returned a token",
		"sub: " + addr,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if fc.Received("VERIFY_PIN") || fc.Received("GET_USER_DATA") || fc.Received("SIGN_AUTH") {
		t.Errorf("unexpected card commands: %v", fc.Log())
	}
	// The fake server verified the card's signature (it issued a token for
	// the card's account); the posted envelope is the issued one plus the
	// card's decorated signature, and the card got the SDK's part split.
	var issuedEnv, postedEnv xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(issued[0], &issuedEnv); err != nil {
		t.Fatal(err)
	}
	if err := xdr.SafeUnmarshalBase64(posted[0], &postedEnv); err != nil {
		t.Fatal(err)
	}
	sigs := postedEnv.Signatures()
	if len(sigs) != 2 || !bytes.Equal(sigs[1].Hint[:], fc.StellarPub()[28:]) {
		t.Errorf("posted signatures = %d, want the server's plus the card's", len(sigs))
	}
	ih, _ := network.HashTransactionInEnvelope(issuedEnv, network.TestNetworkPassphrase)
	ph, _ := network.HashTransactionInEnvelope(postedEnv, network.TestNetworkPassphrase)
	if ih != ph {
		t.Error("the posted transaction differs from the issued one")
	}
	if parts := fc.Sep10Parts(); len(parts) != 2 || parts[0] != 255 {
		t.Errorf("SIGN_SEP10 parts = %v, want BEGIN of 255 bytes then FINISH", parts)
	}
}

func TestSep10LoginWithCardGoldenJSON(t *testing.T) {
	f := newSep10Fake(t)
	_, spec := startCard(t, nil)
	app, out, errb := f.app("", nil)
	if code := app.run([]string{"--network", "testnet", "sep10", "login", "--json", "--card", spec, "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	checkGolden(t, "sep10_login_card_json.golden", out.String())
	var v jsonSep10Login
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Card == nil || v.Card.Applet != "0.4" || v.Card.Engine != "soft" {
		t.Errorf("card = %+v", v.Card)
	}
}

func TestSep10LoginWithCardPIN(t *testing.T) {
	requirePIN := func(c *cardtest.Card) { c.RequirePIN = true }
	pinEnv := func(pin string) map[string]string { return map[string]string{EnvCardPIN: pin} }

	t.Run("required, not given: refused before any challenge", func(t *testing.T) {
		f := newSep10Fake(t)
		fc, spec := startCard(t, requirePIN)
		app, out, errb := f.app("", pinEnv(cardtest.TestPIN))
		if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "example.com"}); code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		if !strings.Contains(errb.String(), "the card requires its user PIN to sign in: pass --pin") {
			t.Errorf("stderr:\n%s", errb)
		}
		if q, _, _, _ := f.snapshot(); len(q) != 0 || out.Len() != 0 || fc.Received("VERIFY_PIN") || fc.Received("SIGN_SEP10") {
			t.Errorf("challenges=%d stdout=%q log=%v", len(q), out, fc.Log())
		}
	})
	for _, tc := range []struct {
		name  string
		stdin string
		env   map[string]string
	}{
		{"required, from the environment", "", pinEnv(cardtest.TestPIN)},
		{"required, from stdin", cardtest.TestPIN + "\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			fc, spec := startCard(t, requirePIN)
			app, out, errb := f.app(tc.stdin, tc.env)
			if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "--pin", "example.com"}); code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", code, errb)
			}
			if _, _, _, tokens := f.snapshot(); len(tokens) != 1 || out.String() != tokens[0]+"\n" {
				t.Errorf("stdout = %q", out)
			}
			log := strings.Join(fc.Log(), " | ")
			if v, s := strings.Index(log, "VERIFY_PIN"), strings.Index(log, "SIGN_SEP10"); v < 0 || s < v {
				t.Errorf("VERIFY_PIN must come before SIGN_SEP10: %s", log)
			}
			if !strings.Contains(errb.String(), "Card PIN:    verified") {
				t.Errorf("stderr:\n%s", errb)
			}
			assertNoPIN(t, out.String(), errb.String())
		})
	}
	t.Run("wrong PIN", func(t *testing.T) {
		f := newSep10Fake(t)
		fc, spec := startCard(t, requirePIN)
		app, out, errb := f.app("", pinEnv("0000"))
		if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "--pin", "example.com"}); code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		if !strings.Contains(errb.String(), "SW 69C4 WRONG_PIN: 4 tries left") {
			t.Errorf("stderr:\n%s", errb)
		}
		if _, _, posted, _ := f.snapshot(); len(posted) != 0 || out.Len() != 0 || fc.Received("SIGN_SEP10") {
			t.Errorf("posted=%d stdout=%q log=%v", len(posted), out, fc.Log())
		}
		if fc.TriesLeft() != 4 {
			t.Errorf("tries left = %d, want 4", fc.TriesLeft())
		}
		assertNoPIN(t, out.String(), errb.String())
	})
	t.Run("not required, given anyway", func(t *testing.T) {
		f := newSep10Fake(t)
		fc, spec := startCard(t, nil)
		app, _, errb := f.app("", pinEnv(cardtest.TestPIN))
		if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "--pin", "example.com"}); code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", code, errb)
		}
		if !fc.Received("VERIFY_PIN") {
			t.Error("--pin did not verify the PIN")
		}
	})
	t.Run("not four digits", func(t *testing.T) {
		f := newSep10Fake(t)
		fc, spec := startCard(t, requirePIN)
		app, _, errb := f.app("", pinEnv("48211"))
		if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "--pin", "example.com"}); code != 1 {
			t.Fatalf("exit %d, want 1", code)
		}
		if !strings.Contains(errb.String(), "the card's user PIN is 4 digits") || fc.Received("VERIFY_PIN") {
			t.Errorf("stderr:\n%s\nlog: %v", errb, fc.Log())
		}
		if q, _, _, _ := f.snapshot(); len(q) != 0 {
			t.Errorf("%d challenges requested", len(q))
		}
	})
}

// TestSep10LoginCardRefusedBeforeAnyChallenge: a card that would refuse to
// sign (the applet's own guards, read from what it reports), or a PIN it
// cannot use, stops the sign-in before any challenge is requested.
func TestSep10LoginCardRefusedBeforeAnyChallenge(t *testing.T) {
	closed := func() string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		return "tcp:" + addr
	}()
	cases := []struct {
		name  string
		setup func(*cardtest.Card)
		extra []string
		spec  string // overrides the fake card's spec
		want  string
	}{
		{"no Stellar key", func(c *cardtest.Card) { c.Stellar = nil }, nil, "", "the card has no Stellar key (applet 0.4"},
		{"applet 0.2", func(c *cardtest.Card) { c.Minor = 2 }, nil, "", "the card has no Stellar key (applet 0.2"},
		{"not personalized", func(c *cardtest.Card) { c.Flags = cardtest.FlagInitialized }, nil, "", "not personalized (state initialized)"},
		{"terminated", func(c *cardtest.Card) { c.Flags |= cardtest.FlagTerminated }, nil, "", "the card is terminated"},
		{"provisioning gate", func(c *cardtest.Card) { c.Flags |= cardtest.FlagEnforce; c.PIN = "" }, nil, "", "the provisioning gate"},
		{"--pin on applet 0.3", func(c *cardtest.Card) { c.Minor = 3 }, []string{"--pin"}, "", "applet 0.3, which has no sign-in PIN"},
		{"--pin without a provisioned PIN", func(c *cardtest.Card) { c.PIN = "" }, []string{"--pin"}, "", "no provisioned user PIN"},
		{"--pin on a blocked PIN", func(c *cardtest.Card) { c.SetTries(0) }, []string{"--pin"}, "", "blocked"},
		{"a required PIN that is blocked", func(c *cardtest.Card) { c.RequirePIN = true; c.SetTries(0) }, nil, "",
			"requires its user PIN to sign in, and the PIN is blocked"},
		{"another applet's AID", nil, []string{"--aid", "A000000003000000"}, "", "APPLET_NOT_FOUND"},
		{"no card there", nil, nil, closed, "connect to the card at " + closed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			fc, spec := startCard(t, tc.setup)
			if tc.spec != "" {
				spec = tc.spec
			}
			args := append([]string{"--network", "testnet", "sep10", "login", "--card", spec}, tc.extra...)
			app, out, errb := f.app("", map[string]string{EnvCardPIN: cardtest.TestPIN})
			if code := app.run(append(args, "example.com")); code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errb)
			}
			if q, _, _, _ := f.snapshot(); len(q) != 0 || out.Len() != 0 {
				t.Errorf("challenges=%d stdout=%q, want none", len(q), out)
			}
			if fc.Received("SIGN_SEP10") || fc.Received("VERIFY_PIN") {
				t.Errorf("the card was asked to sign or verify: %v", fc.Log())
			}
		})
	}
}

// TestSep10LoginCardRefusals: refusals once a challenge is in hand. Nothing
// is ever posted.
func TestSep10LoginCardRefusals(t *testing.T) {
	serverOp := func(name string) xdr.Operation {
		v := xdr.DataValue("x")
		return xdr.Operation{
			SourceAccount: xdr.MustMuxedAddressPtr(sep10ServerKP.Address()),
			Body:          xdr.OperationBody{Type: xdr.OperationTypeManageData, ManageDataOp: &xdr.ManageDataOp{DataName: xdr.String64(name), DataValue: &v}},
		}
	}
	cases := []struct {
		name       string
		card       func(*cardtest.Card)
		server     func(*sep10Fake)
		want       string
		cardSigned bool // whether SIGN_SEP10 reached the card
	}{
		{"the card refuses the challenge", func(c *cardtest.Card) { c.Force = map[uint16]uint16{0x3802: 0x6243} }, nil,
			"SW 6243 SEP10_WRONG_ACCOUNT", true},
		{"the card's signature does not verify", func(c *cardtest.Card) { c.BadSignature = true }, nil,
			"does not verify under its Stellar key", true},
		{"a challenge beyond the card's limits", nil, func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				for _, n := range []string{"a", "b", "c", "d"} {
					env.V1.Tx.Operations = append(env.V1.Tx.Operations, serverOp(n))
				}
			}
		}, "the card signs a challenge of at most 5 operations; this one has 6", false},
		{"a challenge for another account", nil, func(f *sep10Fake) {
			f.mutate = func(env *xdr.TransactionEnvelope) {
				env.V1.Tx.Operations[0].SourceAccount = xdr.MustMuxedAddressPtr(sep10OtherKP.Address())
			}
		}, "not this wallet's account", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSep10Fake(t)
			if tc.server != nil {
				tc.server(f)
			}
			fc, spec := startCard(t, tc.card)
			app, out, errb := f.app("", nil)
			if code := app.run([]string{"--network", "testnet", "sep10", "login", "--card", spec, "example.com"}); code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, errb)
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr missing %q:\n%s", tc.want, errb)
			}
			if _, issued, posted, _ := f.snapshot(); len(issued) != 1 || len(posted) != 0 || out.Len() != 0 {
				t.Errorf("issued=%d posted=%d stdout=%q: a refused challenge must never be sent", len(issued), len(posted), out)
			}
			if got := fc.Received("SIGN_SEP10"); got != tc.cardSigned {
				t.Errorf("SIGN_SEP10 sent = %v, want %v (log %v)", got, tc.cardSigned, fc.Log())
			}
		})
	}
}

// TestSep10CardSignInIsTestnetOnly: on any other network the sign-in is
// refused before the server or the card is contacted.
func TestSep10CardSignInIsTestnetOnly(t *testing.T) {
	for _, netArgs := range [][]string{
		nil, // the default: mainnet
		{"--network", "mainnet"},
		{"--network", "futurenet", "--horizon-url", "https://horizon-futurenet.stellar.org", "--network-passphrase", "Test SDF Future Network ; October 2022"},
	} {
		f := newSep10Fake(t)
		fc, spec := startCard(t, nil)
		app, out, errb := f.app("", nil)
		args := append(append([]string{}, netArgs...), "sep10", "login", "--card", spec, "example.com")
		if code := app.run(args); code != 1 {
			t.Fatalf("%v: exit %d, want 1", netArgs, code)
		}
		if !strings.Contains(errb.String(), "refusing card sign-in on") || strings.Contains(errb.String(), "Home domain:") {
			t.Errorf("%v: stderr:\n%s", netArgs, errb)
		}
		if q, _, _, _ := f.snapshot(); len(q) != 0 || out.Len() != 0 || len(fc.Log()) != 0 {
			t.Errorf("%v: challenges=%d stdout=%q card log=%v", netArgs, len(q), out, fc.Log())
		}
	}
}

func TestSep10CardFlagUsage(t *testing.T) {
	fc, spec := startCard(t, nil)
	addr := cardAddress(t, fc)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--network", "testnet", "sep10", "login", "--card", "tcp:10.0.2.2:9443", "example.com"}, "a loopback address only"},
		{[]string{"--network", "testnet", "sep10", "login", "--card", "tcp:card.example:9443", "example.com"}, "a loopback address only"},
		{[]string{"--network", "testnet", "sep10", "login", "--card", "127.0.0.1:9443", "example.com"}, "expected tcp:HOST:PORT"},
		{[]string{"--network", "testnet", "sep10", "login", "--card", spec, "--aid", "0102", "example.com"}, "--aid must be 5..16 bytes of hex"},
		{[]string{"--network", "testnet", "sep10", "login", "--aid", "0102030405", "example.com"}, "--aid applies only with --card"},
		{[]string{"--network", "testnet", "sep10", "login", "--pin", "example.com"}, "--pin applies only with --card"},
		{[]string{"--network", "testnet", "sep10", "challenge", "--account", addr, "--card", spec, "example.com"}, "--account and --card are exclusive"},
		{[]string{"card", "info"}, "usage: lumencli card info"},
		{[]string{"card", "info", "--card", spec, "extra"}, "usage: lumencli card info"},
		{[]string{"card"}, "card requires a subcommand"},
		{[]string{"card", "frob"}, `unknown card subcommand "frob"`},
	}
	for _, tc := range cases {
		app, _, errb := newTestApp("", nil)
		if code := app.run(tc.args); code != 1 {
			t.Errorf("%v: exit %d, want 1", tc.args, code)
		}
		if !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: stderr missing %q:\n%s", tc.args, tc.want, errb)
		}
	}
	if len(fc.Log()) != 0 {
		t.Errorf("a usage error reached the card: %v", fc.Log())
	}
}

func TestSep10ChallengeWithCard(t *testing.T) {
	f := newSep10Fake(t)
	fc, spec := startCard(t, nil)
	addr := cardAddress(t, fc)
	app, out, errb := f.app("", nil)
	if code := app.run([]string{"--network", "testnet", "sep10", "challenge", "--card", spec, "example.com"}); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, errb)
	}
	if q, _, posted, _ := f.snapshot(); len(q) != 1 || q[0].Get("account") != addr || len(posted) != 0 {
		t.Errorf("challenges=%d posted=%d", len(q), len(posted))
	}
	if fc.Received("SIGN_SEP10") || fc.Received("VERIFY_PIN") {
		t.Errorf("the card was asked to sign: %v", fc.Log())
	}
	if want := "     Source: " + addr + " (the card's Stellar key)"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout missing %q:\n%s", want, out)
	}
	for _, want := range []string{"Nothing was signed.", "within the card's limits; the card would sign it (sep10 login --card)"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errb)
		}
	}

	t.Run("json", func(t *testing.T) {
		app, out, errb := f.app("", nil)
		if code := app.run([]string{"--network", "testnet", "sep10", "challenge", "--json", "--card", spec, "example.com"}); code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", code, errb)
		}
		var v jsonSep10Challenge
		if err := json.Unmarshal(out.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if v.Account != addr || v.Card == nil || v.Card.Engine != "soft" || v.Challenge.Operations[0].SourceAccount != addr {
			t.Errorf("account=%s card=%+v", v.Account, v.Card)
		}
	})
	t.Run("a card that cannot sign yet", func(t *testing.T) {
		_, spec := startCard(t, func(c *cardtest.Card) { c.Flags = cardtest.FlagInitialized })
		app, _, errb := f.app("", nil)
		if code := app.run([]string{"--network", "testnet", "sep10", "challenge", "--card", spec, "example.com"}); code != 0 {
			t.Fatalf("exit %d, stderr:\n%s", code, errb)
		}
		if !strings.Contains(errb.String(), "but the card would not sign it now: the card is not personalized") {
			t.Errorf("stderr:\n%s", errb)
		}
	})
}

// cardSpecPlaceholder makes a card-info output independent of the fake's port.
func cardSpecPlaceholder(got, spec string) string {
	return strings.ReplaceAll(got, spec, "tcp:127.0.0.1:PORT")
}

func TestCardInfoGolden(t *testing.T) {
	fc, spec := startCard(t, nil)
	for _, tc := range []struct {
		golden string
		args   []string
	}{
		{"card_info_text.golden", []string{"card", "info", "--card", spec}},
		{"card_info_json.golden", []string{"card", "info", "--json", "--card", spec}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			app, out, errb := newTestApp("", nil)
			if code := app.run(tc.args); code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", code, errb)
			}
			checkGolden(t, tc.golden, cardSpecPlaceholder(out.String(), spec))
			if !strings.Contains(errb.String(), "Never send funds to the card's Stellar address") {
				t.Errorf("stderr:\n%s", errb)
			}
		})
	}
	// Reading a card is read-only: no signing, no PIN, no cardholder data.
	for _, l := range fc.Log() {
		switch strings.Fields(l)[0] {
		case "SELECT", "GET_VERSION", "GET_PERSONALIZATION", "GET_STELLAR_KEY", "GET_USER_VERIFICATION":
		default:
			t.Errorf("card info sent %s", l)
		}
	}
}

func TestCardInfoStates(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*cardtest.Card)
		want  []string
		warn  bool // the never-fund warning (only for a card with a Stellar key)
	}{
		{"a legacy card", func(c *cardtest.Card) { c.Stellar = nil }, []string{
			"Stellar key:  none", "SEP-10:       cannot sign: the card has no Stellar key (applet 0.4",
		}, false},
		{"applet 0.3", func(c *cardtest.Card) { c.Minor = 3 }, []string{
			"User PIN:     not reported (an applet older than 0.4 has no sign-in PIN policy)", "SEP-10:       signs challenges for",
		}, true},
		{"PIN required, fixed", func(c *cardtest.Card) { c.RequirePIN, c.FixedPIN = true, true }, []string{
			"User PIN:     provisioned, 5 tries left; required to sign in (fixed at install)", "with its user PIN (sep10 login --card --pin)",
		}, true},
		{"PIN required and blocked", func(c *cardtest.Card) { c.RequirePIN = true; c.SetTries(0) }, []string{
			"User PIN:     provisioned, 0 tries left; required to sign in", "SEP-10:       cannot sign: the card requires its user PIN to sign in, and the PIN is blocked",
		}, true},
		{"initialized, not personalized", func(c *cardtest.Card) { c.Flags = cardtest.FlagInitialized }, []string{
			"State:        initialized (flags: initialized, pin-provisioned, stellar-key)",
			"(soft engine, not yet bound (the card is not personalized))",
			"SEP-10:       cannot sign: the card is not personalized (state initialized)",
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, spec := startCard(t, tc.setup)
			app, out, errb := newTestApp("", nil)
			if code := app.run([]string{"card", "info", "--card", spec}); code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", code, errb)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("stdout missing %q:\n%s", want, out)
				}
			}
			if got := strings.Contains(errb.String(), "Never send funds"); got != tc.warn {
				t.Errorf("never-fund warning = %v, want %v", got, tc.warn)
			}
		})
	}
}
