package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"

	"impalactl/internal/bridge"
	"impalactl/internal/card"
	"impalactl/internal/config"
	"impalactl/internal/devicekey"
	"impalactl/internal/sep10"
)

// Card sign-in: a Go port of impala-lib's CardSignIn.signIn, the one
// reference flow (docs/sep10-card-keys.md §5, docs/mfa-card-pin-biometrics.md
// §7).
//
// A card with a Stellar key signs in with SEP-10: stellar.toml, a challenge
// for the card's address, the client checks, SIGN_SEP10 on the card, and the
// signed envelope posted to the web-auth endpoint. Any other card, and a card
// whose server cannot take SEP-10 (exactly the cases of fallbackFor), signs
// the legacy challenge (SIGN_AUTH, POST /auth/card) in the same session.
// Everything else is an error, never a downgrade.

// cardLoginFlags are the `login --card` flags.
type cardLoginFlags struct {
	card       string
	aid        string
	pin        bool
	homeDomain string
	noSep10    bool
}

func (f *cardLoginFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.card, "card", "", "sign in with a card: tcp:HOST:PORT (the impala-card simulator transport)")
	fs.StringVar(&f.aid, "aid", "", "applet AID to SELECT (hex; default the testnet applet "+card.DefaultAID+")")
	fs.BoolVar(&f.pin, "pin", false, "verify the card's user PIN ($"+config.EnvCardPIN+", prompt, or stdin) and add the PIN factor")
	fs.StringVar(&f.homeDomain, "sep10-home-domain", "", "the SEP-10 home domain NAME (default: host[:port] of --endpoint)")
	fs.BoolVar(&f.noSep10, "no-sep10", false, "do not try SEP-10: sign in with the legacy card challenge")
}

// used reports whether any card-only flag was given.
func (f *cardLoginFlags) used() bool {
	return f.aid != "" || f.pin || f.homeDomain != "" || f.noSep10
}

// sep10Fallback is why a card with a Stellar key signed in the legacy way.
type sep10Fallback string

const (
	noFallback sep10Fallback = ""
	// fallbackNotConfigured: --no-sep10 (the app's "no SEP-10 home domain").
	fallbackNotConfigured sep10Fallback = "not configured (--no-sep10)"
	// fallbackNotOffered: no stellar.toml, none of its endpoint or key, or the
	// server answered 404 / 503.
	fallbackNotOffered sep10Fallback = "not offered by the server"
	// fallbackNotRegistered: 401 at the web-auth endpoint. The bridge does not
	// know this Stellar key, or refuses SEP-10 to this (privileged) account;
	// it gives the same answer for both by design.
	fallbackNotRegistered sep10Fallback = "refused with 401 (the card's Stellar key is not registered, or the account holds a privileged role)"
)

// fallbackFor is the whole downgrade rule, in one place (CardSignIn.fallbackFor):
//   - stellar.toml without a web-auth endpoint or signing key: not offered;
//   - HTTP 404 or 503 from the server: not offered;
//   - HTTP 401: not registered;
//   - anything else (429, other statuses, transport errors, a challenge that
//     fails a client check, a home-domain mismatch, a card refusal): no
//     fallback; the error is reported.
func fallbackFor(err error) sep10Fallback {
	var ce *sep10.ClientError
	if errors.As(err, &ce) {
		if ce.Kind == sep10.NotOffered {
			return fallbackNotOffered
		}
		return noFallback
	}
	var he *sep10.HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case 404, 503:
			return fallbackNotOffered
		case 401:
			return fallbackNotRegistered
		}
	}
	return noFallback
}

var aidPattern = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}){5,16}$`)

// checkCardSpec validates a card address and AID without touching the card:
// a non-loopback card needs --insecure-http (the transport is cleartext).
// It returns the AID to SELECT.
func (a *App) checkCardSpec(opts options, spec, aid string) (string, error) {
	if _, _, err := card.ParseSpec(spec); err != nil {
		return "", err
	}
	if !card.IsLoopback(spec) && !a.allowInsecureHTTP(opts) {
		return "", fmt.Errorf("refusing a card at %s: the simulator transport is cleartext (a PIN crosses it "+
			"as four digits); use a loopback address, or pass --insecure-http if the path is genuinely trusted", spec)
	}
	if aid == "" {
		aid = card.DefaultAID
	}
	if !aidPattern.MatchString(aid) {
		return "", fmt.Errorf("--aid must be 5..16 bytes of hex, got %q", aid)
	}
	return aid, nil
}

// dialCard checks the address, dials and SELECTs the applet; nothing else
// is sent.
func (a *App) dialCard(opts options, spec, aid string) (*card.Card, error) {
	aid, err := a.checkCardSpec(opts, spec, aid)
	if err != nil {
		return nil, err
	}
	timeout := opts.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	t, err := card.DialTCP(spec, timeout)
	if err != nil {
		return nil, err
	}
	cd := card.New(t)
	if err := cd.Select(aid); err != nil {
		cd.Close()
		return nil, err
	}
	return cd, nil
}

// openCard dials, SELECTs and reads the identity.
func (a *App) openCard(opts options, spec, aid string) (*card.Card, *card.Identity, error) {
	cd, err := a.dialCard(opts, spec, aid)
	if err != nil {
		return nil, nil, err
	}
	id, err := card.ReadIdentity(cd)
	if err != nil {
		cd.Close()
		return nil, nil, err
	}
	return cd, id, nil
}

// cardSignIn is what a sign-in produced.
type cardSignIn struct {
	temporal, refresh string
	raw               []byte
	mechanism         string
	fallback          sep10Fallback
	stellarAddress    string
}

func (a *App) runCardLogin(opts options, f cardLoginFlags, device bool) int {
	ctx := context.Background()
	c, err := a.newClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	homeDomain := strings.TrimSpace(f.homeDomain)
	if !f.noSep10 {
		if homeDomain == "" {
			if homeDomain, err = sep10.HomeDomainOf(c.Endpoint()); err != nil {
				return a.fail("%v", err)
			}
		}
		if !sep10.IsValidHomeDomain(homeDomain) {
			return a.usageErr("--sep10-home-domain %q is not a lowercase host[:port]", homeDomain)
		}
	} else if homeDomain != "" {
		return a.usageErr("--sep10-home-domain and --no-sep10 are exclusive")
	}

	// The PIN is read before anything touches the card or the network.
	pin := ""
	if f.pin {
		if pin, err = a.readSecret(config.EnvCardPIN, "Card PIN: "); err != nil {
			return a.fail("%v", err)
		}
		if len(pin) != 4 || strings.Trim(pin, "0123456789") != "" {
			return a.fail("the card's user PIN is 4 digits")
		}
	}

	cd, id, err := a.openCard(opts, f.card, f.aid)
	if err != nil {
		return a.fail("%v", err)
	}
	defer cd.Close()
	if err := id.RequireSigner(); err != nil {
		return a.fail("%v", err)
	}
	account := id.AccountUUID()

	// Cardholder verification (applet 0.4). A card that requires a sign-in
	// PIN is refused here, before any request, unless one was given. A given
	// PIN is verified now so a PIN proof can be made; a wrong or blocked PIN
	// is an error, never a downgrade to a PIN-less sign-in.
	uv, err := cd.GetUserVerification()
	if err != nil {
		return a.fail("%v", err)
	}
	if uv != nil && uv.SignInPinRequired && !f.pin {
		return a.fail("card %s requires its user PIN to sign in: pass --pin", id.WireCardID())
	}
	pinVerified := false
	if f.pin {
		switch {
		case uv == nil:
			return a.fail("card %s runs applet %s, which cannot prove a PIN (0.4 or newer is needed): drop --pin",
				id.WireCardID(), id.Version)
		case !uv.PinProvisioned:
			return a.fail("card %s has no provisioned user PIN, so it cannot prove one: drop --pin", id.WireCardID())
		}
		if err := cd.VerifyUserPIN(pin); err != nil {
			return a.fail("%v", err)
		}
		pinVerified = true
	}

	var devKey *config.DeviceKey
	if device {
		if devKey, err = a.deviceKeyFor(c.Endpoint(), account); err != nil {
			return a.fail("%v", err)
		}
	}
	x := &cardExtras{cd: cd, pinVerified: pinVerified, devKey: devKey, account: account}

	var res *cardSignIn
	switch {
	case !id.HasStellarKey():
		res, err = a.legacyCardSignIn(ctx, c, id, x, noFallback)
	case f.noSep10:
		res, err = a.legacyCardSignIn(ctx, c, id, x, fallbackNotConfigured)
	default:
		key, kerr := cd.GetStellarKey()
		if kerr != nil {
			return a.fail("%v", kerr)
		}
		if key == nil {
			// The flag said yes and the read says no: not a card to guess about.
			return a.fail("card %s advertises a Stellar key but GET_STELLAR_KEY has none (SW 623C)", id.WireCardID())
		}
		res, err = a.sep10CardSignIn(ctx, c, opts, homeDomain, key, x)
		if err != nil {
			fb := fallbackFor(err)
			if fb == noFallback {
				return a.fail("SEP-10 sign-in failed: %v", err)
			}
			fmt.Fprintf(a.err, "SEP-10 not used: %s (%v); signing in with the legacy card challenge\n", fb, err)
			res, err = a.legacyCardSignIn(ctx, c, id, x, fb)
			if res != nil {
				res.stellarAddress, _ = sep10.EncodeAccountID(key.PublicKey)
			}
		}
	}
	if err != nil {
		return a.fail("card sign-in failed: %v", err)
	}

	claims, err := bridge.ParseClaims(res.temporal)
	if err != nil {
		return a.fail("the bridge's token is unreadable: %v", err)
	}
	if !sameUUID(claims.Subject, account) {
		return a.fail("the bridge signed in account %s, not the card's account %s: nothing was stored",
			claims.Subject, account)
	}
	fmt.Fprintf(a.err, "Card:      %s (account %s, applet %s)\n", id.WireCardID(), account, id.Version)
	switch {
	case res.mechanism == "SEP-10":
		fmt.Fprintf(a.err, "Mechanism: SEP-10 (Stellar key %s)\n", res.stellarAddress)
	case res.fallback != noFallback:
		// The key's address is named when the tap read it (a fallback after SEP-10 was tried);
		// with --no-sep10 it was never read, and an empty placeholder would say nothing.
		key := "a Stellar key"
		if res.stellarAddress != "" {
			key = "a Stellar key (" + res.stellarAddress + ")"
		}
		fmt.Fprintf(a.err, "Mechanism: legacy card challenge; the card has %s but SEP-10 was %s\n", key, res.fallback)
	default:
		fmt.Fprintln(a.err, "Mechanism: legacy card challenge (the card has no Stellar key)")
	}
	fmt.Fprintf(a.err, "Factors:   %s\n", amrText(claims.Amr))
	if claims.MFARequired && !claims.HasMFA() {
		fmt.Fprintln(a.err, "notice: this account must be multi-factor; sign in again with --pin, or step up "+
			"with `impalactl mfa step-up --totp|--device`")
	}
	return a.finishLogin(opts, c, account, res.temporal, res.refresh, res.raw, "")
}

func sameUUID(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "-", "")) }
	return a != "" && norm(a) == norm(b)
}

// cardExtras makes the optional MFA extras over the value the card signed:
// the PIN proof (SIGN_AUTH P1=01, only after VERIFY_PIN) and the device
// assertion (purpose card / SEP-10 sign-in).
type cardExtras struct {
	cd          *card.Card
	pinVerified bool
	devKey      *config.DeviceKey
	account     string
}

func (x *cardExtras) make(purpose byte, challenge []byte) (pinProof, keyID, devSig string, err error) {
	if x.pinVerified {
		p, err := x.cd.SignAuth(challenge, true)
		if err != nil {
			return "", "", "", err
		}
		pinProof = hex.EncodeToString(p)
	}
	if x.devKey != nil {
		if len(challenge) != devicekey.ChallengeLength {
			return "", "", "", fmt.Errorf("the device key signs 32-byte challenges; this one is %d bytes", len(challenge))
		}
		priv, err := devicekey.ParsePrivate(x.devKey.PrivateKey, x.devKey.PublicKey)
		if err != nil {
			return "", "", "", err
		}
		if devSig, err = devicekey.Assert(priv, purpose, x.account, challenge); err != nil {
			return "", "", "", err
		}
		keyID = x.devKey.KeyID
	}
	return pinProof, keyID, devSig, nil
}

func (a *App) sep10CardSignIn(ctx context.Context, c *bridge.Client, opts options, homeDomain string,
	key *card.StellarKey, x *cardExtras) (*cardSignIn, error) {
	// The network the challenge must be for is the bridge's own; stellar.toml
	// and the challenge response must name the same one.
	network, _, err := c.Network(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the bridge's network: %w", err)
	}
	if network.NetworkPassphrase == "" {
		return nil, errors.New("the bridge reported no network passphrase")
	}
	timeout := opts.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	sc, err := sep10.NewClient(c.Endpoint(), homeDomain, network.NetworkPassphrase, timeout,
		func() int64 { return a.clock().Unix() })
	if err != nil {
		return nil, err
	}
	prepared, err := sc.Prepare(ctx, key.PublicKey)
	if err != nil {
		return nil, err
	}
	ch := prepared.Challenge
	tx := ch.TransactionBytes()
	if len(tx) > card.MaxSep10Transaction {
		return nil, fmt.Errorf("the challenge is %d bytes; a card signs at most %d", len(tx), card.MaxSep10Transaction)
	}
	sig, err := x.cd.SignSep10(ch.NetworkID(), tx)
	if err != nil {
		return nil, err
	}
	// Another card than the one the challenge was issued for, or a broken
	// engine: never hand the server a signature that cannot verify.
	if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), ch.Hash(), sig) {
		return nil, errors.New("the card's SEP-10 signature does not verify under its Stellar key")
	}
	envelope, err := ch.SignedEnvelope(sig)
	if err != nil {
		return nil, err
	}
	pinProof, keyID, devSig, err := x.make(devicekey.PurposeSep10SignIn, ch.Hash())
	if err != nil {
		return nil, err
	}
	raw, tok, err := sc.Submit(ctx, prepared.WebAuthEndpoint, envelope, sep10.Extras{
		PinProof: pinProof, DeviceKeyID: keyID, DeviceSignature: devSig,
	})
	if err != nil {
		return nil, err
	}
	if tok.TemporalToken == "" || tok.RefreshToken == "" {
		return nil, errors.New("the SEP-10 token response has no token pair")
	}
	addr, _ := sep10.EncodeAccountID(key.PublicKey)
	return &cardSignIn{temporal: tok.TemporalToken, refresh: tok.RefreshToken, raw: raw,
		mechanism: "SEP-10", stellarAddress: addr}, nil
}

func (a *App) legacyCardSignIn(ctx context.Context, c *bridge.Client, id *card.Identity, x *cardExtras,
	fb sep10Fallback) (*cardSignIn, error) {
	ch, _, err := c.CardChallenge(ctx, id.WireCardID())
	if err != nil {
		return nil, fmt.Errorf("card challenge: %w", err)
	}
	challenge, err := hex.DecodeString(ch.Challenge)
	if err != nil || len(challenge) < 8 || len(challenge) > 64 {
		return nil, errors.New("the bridge's card challenge is not 8..64 bytes of hex")
	}
	sig, err := x.cd.SignAuth(challenge, false)
	if err != nil {
		return nil, err
	}
	req := bridge.CardTokenRequest{CardID: id.WireCardID(), Signature: hex.EncodeToString(sig)}
	if x.pinVerified {
		p, err := x.cd.SignAuth(challenge, true)
		if err != nil {
			return nil, err
		}
		req.PinProof = hex.EncodeToString(p)
	}
	if x.devKey != nil {
		_, keyID, devSig, err := (&cardExtras{devKey: x.devKey, account: x.account}).make(devicekey.PurposeCardSignIn, challenge)
		if err != nil {
			return nil, err
		}
		req.DeviceKeyID, req.DeviceSignature = keyID, devSig
	}
	resp, raw, err := c.CardToken(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.TemporalToken == "" || resp.RefreshToken == "" {
		return nil, errors.New("the bridge returned no token pair")
	}
	return &cardSignIn{temporal: resp.TemporalToken, refresh: resp.RefreshToken, raw: raw,
		mechanism: "legacy", fallback: fb}, nil
}
