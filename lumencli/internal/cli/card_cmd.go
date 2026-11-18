package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"

	"lumencli/internal/card"
	"lumencli/internal/netcfg"
	"lumencli/internal/sep10"
)

// The Impala card is a JavaCard applet (applet 0.3 and newer) whose second,
// Ed25519 key — the card's Stellar key — signs SEP-10 challenges and nothing
// else (docs/sep10-card-keys.md in the Impala repository). lumencli uses it
// for that one thing: `sep10 login --card` has the card sign a server's
// challenge in place of the wallet's seed. `card info` shows what a card
// reports about itself, and `sep10 challenge --card` fetches and checks a
// challenge for it without signing.
//
// lumencli is a SEP-10 client and nothing more here: it never talks to the
// Impala bridge's legacy card challenge (SIGN_AUTH, POST /auth/card), so
// there is no fallback to downgrade to — a card that cannot sign a SEP-10
// challenge is an error — and it sends no Impala-specific sign-in extras
// (the bridge's PIN proof or device key; impalactl login --card does those).

// cardTimeout bounds the dial and each exchange with the card. A software
// Ed25519 signature on a JavaCard 3.0.5 card may take seconds.
const cardTimeout = 30 * time.Second

// cardFlags are the flags of every command that talks to a card.
type cardFlags struct {
	spec string
	aid  string
}

func (f *cardFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.spec, "card", "", "an Impala card: tcp:HOST:PORT (the impala-card simulator transport; loopback only)")
	fs.StringVar(&f.aid, "aid", "", "the card applet's AID to SELECT, hex (default "+card.DefaultAID+")")
}

// used reports whether a card was named.
func (f *cardFlags) used() bool { return strings.TrimSpace(f.spec) != "" }

// check validates the flags without touching the card. The simulator
// transport is cleartext and unauthenticated: a PIN crosses it as four
// digits, and a signed challenge is a bearer credential until the server
// consumes it, so a card is reached on a loopback address only — the same
// line the SEP-10 client draws for plain http.
func (f *cardFlags) check() error {
	spec, aid := strings.TrimSpace(f.spec), strings.TrimSpace(f.aid)
	if spec == "" {
		if aid != "" {
			return errors.New("--aid applies only with --card")
		}
		return nil
	}
	if _, _, err := card.ParseSpec(spec); err != nil {
		return err
	}
	if !card.IsLoopback(spec) {
		return fmt.Errorf("refusing the card at %s: the card transport is cleartext, so lumencli reaches a card on a loopback address only "+
			"(forward a remote simulator over ssh, e.g. ssh -L 9443:127.0.0.1:9443 HOST, and use tcp:127.0.0.1:9443)", spec)
	}
	if aid != "" && !card.ValidAID(aid) {
		return fmt.Errorf("--aid must be 5..16 bytes of hex, got %q", aid)
	}
	return nil
}

// cardSession is an open card: the applet SELECTed and what it reports about
// itself read.
type cardSession struct {
	spec    string
	cd      *card.Card
	version card.Version
	pers    *card.Personalization
	key     *card.StellarKey       // nil: the card has no Stellar key
	uv      *card.UserVerification // nil: an applet older than 0.4
}

// openCard dials the card, SELECTs the applet and reads its version, state,
// Stellar key and PIN policy: public reads, which change nothing on the card.
// The cardholder data (GET_USER_DATA) is never read.
func (a *App) openCard(f cardFlags) (*cardSession, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	spec := strings.TrimSpace(f.spec)
	aid := strings.TrimSpace(f.aid)
	if aid == "" {
		aid = card.DefaultAID
	}
	t, err := card.DialTCP(spec, cardTimeout)
	if err != nil {
		return nil, err
	}
	s := &cardSession{spec: spec, cd: card.New(t)}
	if err := s.read(aid); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *cardSession) read(aid string) (err error) {
	if err = s.cd.Select(aid); err != nil {
		return err
	}
	if s.version, err = s.cd.GetVersion(); err != nil {
		return err
	}
	if s.pers, err = s.cd.GetPersonalization(); err != nil {
		return err
	}
	if s.key, err = s.cd.GetStellarKey(); err != nil {
		return err
	}
	s.uv, err = s.cd.GetUserVerification()
	return err
}

func (s *cardSession) close() { _ = s.cd.Close() }

// refusal says why the card would refuse to sign a SEP-10 challenge, or ""
// when it would sign one (with its user PIN, when pinRequired). These are
// the applet's own SIGN_SEP10 guards (terminated, personalized, the
// provisioning gate, a Stellar key), judged from what the card reports, so
// such a card is refused before any challenge is requested.
func (s *cardSession) refusal() string {
	p := s.pers
	switch {
	case p.Terminated():
		return "the card is terminated and never signs again"
	case !p.Personalized():
		return fmt.Sprintf("the card is not personalized (state %s): it signs nothing until it is issued", card.StateName(p.State))
	case p.ProvisioningEnforced() && !p.PinProvisioned():
		return "the card has not been given its user PIN (the provisioning gate): it signs nothing until its issuance is finished"
	case s.key == nil && p.AdvertisesStellarKey():
		return "the card advertises a Stellar key, but GET_STELLAR_KEY reports none"
	case s.key == nil:
		return fmt.Sprintf("the card has no Stellar key (applet %s; applets 0.3 and newer make one where the card's platform offers Ed25519)", s.version)
	case s.pinRequired() && s.uv.TriesLeft == 0:
		return "the card requires its user PIN to sign in, and the PIN is blocked (no tries left): it must be reset with the card's master PIN"
	}
	return ""
}

// pinRequired reports whether the card's sign-in policy requires its user
// PIN (applet 0.4), without which SIGN_SEP10 answers PIN_REQUIRED.
func (s *cardSession) pinRequired() bool { return s.uv != nil && s.uv.SignInPinRequired }

// describe is the one-line description of the card for notices.
func (s *cardSession) describe() string {
	if s.key == nil {
		return fmt.Sprintf("%s (applet %s, no Stellar key)", s.spec, s.version)
	}
	return fmt.Sprintf("%s (applet %s, %s Ed25519 engine)", s.spec, s.version, s.key.EngineName())
}

// jsonCard is the card object of the sep10 login and challenge --json
// output, present only when a card was used.
func (s *cardSession) jsonCard() *jsonSep10Card {
	return &jsonSep10Card{Applet: s.version.String(), Engine: s.key.EngineName()}
}

// challengeSigner signs a checked challenge: the wallet's seed, or a card.
type challengeSigner interface {
	account() string
	sign(ch *sep10.Challenge) (string, error)
}

type seedSigner struct{ kp *keypair.Full }

func (s seedSigner) account() string                          { return s.kp.Address() }
func (s seedSigner) sign(ch *sep10.Challenge) (string, error) { return ch.Sign(s.kp) }

// cardSigner has the card sign: the challenge goes to the card only after
// every client check and the card's own limits passed (ForCard), the PIN is
// verified on the card just before it signs, and the card's signature is
// verified under its key before the envelope is built (Envelope).
type cardSigner struct {
	s      *cardSession
	pin    string // "" without --pin
	notice io.Writer
}

func (c *cardSigner) account() string { return c.s.key.Address() }

func (c *cardSigner) sign(ch *sep10.Challenge) (string, error) {
	cs, err := ch.ForCard(c.s.key.PublicKey)
	if err != nil {
		return "", err
	}
	if c.pin != "" {
		err := c.s.cd.VerifyUserPIN(c.pin)
		c.pin = ""
		if err != nil {
			return "", err
		}
		fmt.Fprintln(c.notice, "Card PIN:    verified")
	}
	sig, err := c.s.cd.SignSep10(cs.NetworkID, cs.Transaction)
	if err != nil {
		return "", err
	}
	return cs.Envelope(sig)
}

// cardSignerFor opens the card for a sign-in. A card that would refuse to
// sign is refused here, before any challenge is requested, and so is a PIN
// it cannot use. With pin, the PIN is read here ($LUMEN_CARD_PIN, a no-echo
// prompt, or one line of stdin) — after the card said it has one — and
// verified on the card only once a challenge has passed every check.
func (a *App) cardSignerFor(f cardFlags, pin bool) (*cardSigner, error) {
	s, err := a.openCard(f)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(a.err, "Card:        %s\n", s.describe())
	refuse := func(format string, args ...any) (*cardSigner, error) {
		s.close()
		return nil, fmt.Errorf(format, args...)
	}
	if why := s.refusal(); why != "" {
		return refuse("the card cannot sign in: %s", why)
	}
	switch {
	case s.pinRequired() && !pin:
		return refuse("the card requires its user PIN to sign in: pass --pin")
	case pin && s.uv == nil:
		return refuse("the card runs applet %s, which has no sign-in PIN (applet 0.4 and newer): drop --pin", s.version)
	case pin && !s.uv.PinProvisioned:
		return refuse("the card has no provisioned user PIN: drop --pin")
	case pin && s.uv.TriesLeft == 0:
		return refuse("the card's user PIN is blocked (no tries left): it must be reset with the card's master PIN")
	}
	c := &cardSigner{s: s, notice: a.err}
	if pin {
		p, err := a.readSecretFrom(EnvCardPIN, "the PIN", "Enter the card's user PIN: ")
		if err != nil {
			return refuse("%v", err)
		}
		if len(p) != 4 || strings.Trim(p, "0123456789") != "" {
			return refuse("the card's user PIN is 4 digits")
		}
		c.pin = p
	}
	return c, nil
}

// --- card info -------------------------------------------------------------

func (a *App) runCard(opts netcfg.Options, args []string) int {
	if len(args) == 0 {
		return a.fail("card requires a subcommand: info")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "info":
		return a.cardInfo(opts, rest)
	default:
		return a.fail("unknown card subcommand %q (want: info)", sub)
	}
}

// cardInfo shows what a card reports about itself: the applet, its state,
// the Stellar key, the PIN policy, and whether it can sign a SEP-10
// challenge now. It is offline: reading a card contacts no network.
func (a *App) cardInfo(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("card info")
	bindNetworkFlags(fs, &opts) // accepted, like every command's; no network is contacted
	var cf cardFlags
	cf.bind(fs)
	jsonOut := fs.Bool("json", false, "write a single JSON object instead of the human form")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 0 || !cf.used() {
		return a.fail("usage: lumencli card info --card tcp:HOST:PORT [--aid HEX] [--json]")
	}
	s, err := a.openCard(cf)
	if err != nil {
		return a.fail("%v", err)
	}
	defer s.close()

	info := jsonCardInfo{
		Applet:     s.version.String(),
		AppletHash: s.version.Hash,
		State:      card.StateName(s.pers.State),
		Flags:      card.FlagNames(s.pers.Flags),
		Sep10:      jsonCardSep10{CanSign: s.refusal() == "", PinRequired: s.pinRequired(), Refusal: s.refusal()},
	}
	if s.key != nil {
		info.StellarKey = &jsonCardKey{Address: s.key.Address(), Engine: s.key.EngineName(), Bound: s.key.Bound}
	}
	if s.uv != nil {
		info.UserVerification = &jsonCardUV{
			SignInPinRequired: s.uv.SignInPinRequired, SignInPinFixed: s.uv.SignInPinFixed,
			PinProvisioned: s.uv.PinProvisioned, TriesLeft: s.uv.TriesLeft,
		}
	}

	if *jsonOut {
		if err := newJSONEncoder(a.out).Encode(info); err != nil {
			return a.fail("write json: %v", err)
		}
	} else {
		renderCardInfo(a.out, s.spec, info)
	}
	if s.key != nil {
		fmt.Fprintln(a.err, "Never send funds to the card's Stellar address: the card signs SEP-10 challenges and nothing else, so nothing could ever move them.")
	}
	return 0
}

func renderCardInfo(w io.Writer, spec string, info jsonCardInfo) {
	flags := strings.Join(info.Flags, ", ")
	if flags == "" {
		flags = "none"
	}
	fmt.Fprintf(w, "Card:         %s\n", spec)
	fmt.Fprintf(w, "Applet:       %s (build %s)\n", info.Applet, info.AppletHash)
	fmt.Fprintf(w, "State:        %s (flags: %s)\n", info.State, flags)
	if k := info.StellarKey; k != nil {
		bound := "bound to the card's P-256 key"
		if !k.Bound {
			bound = "not yet bound (the card is not personalized)"
		}
		fmt.Fprintf(w, "Stellar key:  %s (%s engine, %s)\n", k.Address, k.Engine, bound)
	} else {
		fmt.Fprintln(w, "Stellar key:  none")
	}
	switch uv := info.UserVerification; {
	case uv == nil:
		fmt.Fprintln(w, "User PIN:     not reported (an applet older than 0.4 has no sign-in PIN policy)")
	case !uv.PinProvisioned:
		fmt.Fprintln(w, "User PIN:     none provisioned")
	default:
		policy := "not required to sign in"
		if uv.SignInPinRequired {
			policy = "required to sign in"
			if uv.SignInPinFixed {
				policy += " (fixed at install)"
			}
		}
		fmt.Fprintf(w, "User PIN:     provisioned, %d tries left; %s\n", uv.TriesLeft, policy)
	}
	switch {
	case !info.Sep10.CanSign:
		fmt.Fprintf(w, "SEP-10:       cannot sign: %s\n", info.Sep10.Refusal)
	case info.Sep10.PinRequired:
		fmt.Fprintf(w, "SEP-10:       signs challenges for %s with its user PIN (sep10 login --card --pin)\n", info.StellarKey.Address)
	default:
		fmt.Fprintf(w, "SEP-10:       signs challenges for %s (sep10 login --card)\n", info.StellarKey.Address)
	}
}

// The card info --json object. Like every machine-readable output of this
// tool it is an append-only contract, pinned by a golden file. It carries no
// cardholder data and no signature.
type jsonCardInfo struct {
	Applet           string        `json:"applet"`
	AppletHash       string        `json:"applet_hash"`
	State            string        `json:"state"`
	Flags            []string      `json:"flags"`
	StellarKey       *jsonCardKey  `json:"stellar_key"`       // null: no Stellar key
	UserVerification *jsonCardUV   `json:"user_verification"` // null: an applet older than 0.4
	Sep10            jsonCardSep10 `json:"sep10"`
}

type jsonCardKey struct {
	Address string `json:"address"`
	Engine  string `json:"engine"`
	Bound   bool   `json:"bound"`
}

type jsonCardUV struct {
	SignInPinRequired bool `json:"sign_in_pin_required"`
	SignInPinFixed    bool `json:"sign_in_pin_fixed"`
	PinProvisioned    bool `json:"pin_provisioned"`
	TriesLeft         int  `json:"tries_left"`
}

// jsonCardSep10: can_sign is whether the card would sign a SEP-10 challenge
// now (with its PIN when pin_required); refusal says why not, as human text
// (not a stable code).
type jsonCardSep10 struct {
	CanSign     bool   `json:"can_sign"`
	PinRequired bool   `json:"pin_required"`
	Refusal     string `json:"refusal,omitempty"`
}
