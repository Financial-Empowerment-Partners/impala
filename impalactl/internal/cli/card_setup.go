package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"impalactl/internal/bridge"
	"impalactl/internal/card"
	"impalactl/internal/config"
	"impalactl/internal/sep10"
)

// `card setup`: the card issuance ceremony, a port of the reference tool
// (impala-card tools/issue IssuanceCeremony.run, docs/transfer-protocol.md
// §5) that sends the card exactly the reference's command sequence after
// one SELECT. Idempotent per step: every torn state resumes.
//
// Fresh card: GET_VERSION, GET_PERSONALIZATION, [confirmation], INITIALIZE
// (unless initialized), GET_USER_DATA, GET_EC_PUB_KEY, SCP03 on the per-card
// keys (rotating to them from the transport keys first when the card is still
// on those), the certificate from the bridge (checked here before anything
// reaches the card), PERSONALIZE A [B] C, PROVISION_PIN master + user, the
// read-back, GET_STELLAR_KEY (flag 0x80), GET_USER_DATA, GET_EC_PUB_KEY, then
// the Stellar key registration (PUT /card/stellar-key).
//
// A personalized card changes nothing on the card (a re-run repeats only the
// Stellar key registration, which the bridge answers with success), except a
// card personalized without its PINs, whose PINs are provisioned.

const cardSetupUsage = "usage: impalactl card setup --card tcp:HOST:PORT --account UUID [--currency XLM|USDC|USDT0] " +
	"[--card-minor-scale 0..7] [--initial-counter N] [--cap FILE] [--aid HEX]"

// cardSetupRecord is `card setup --json`: an append-only schema.
type cardSetupRecord struct {
	CardID        string            `json:"card_id"`
	AccountID     string            `json:"account_id"`
	ProgramID     string            `json:"program_id"`
	Currency      string            `json:"currency"`
	CertID        string            `json:"cert_id"`
	Applet        string            `json:"applet"`
	AppletHash    string            `json:"applet_hash"`
	CapSHA256     string            `json:"cap_sha256,omitempty"`
	IssuerVersion *int              `json:"issuer_version,omitempty"`
	StellarKey    *cardSetupStellar `json:"stellar_key"`
	Status        string            `json:"status"`
}

type cardSetupStellar struct {
	Address    string `json:"address"`
	Engine     string `json:"engine"`
	Registered bool   `json:"registered"`
	Note       string `json:"note,omitempty"`
}

const (
	setupIssued        = "issued"
	setupAlreadyIssued = "already-issued"
)

// random is the randomness sent to the card.
func (a *App) random() io.Reader {
	if a.rand != nil {
		return a.rand
	}
	return rand.Reader
}

// stdinIsTerminal reports whether a.in is an interactive terminal.
func (a *App) stdinIsTerminal() bool {
	f, ok := a.in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readNewSecret reads a secret being set: from the environment or a pipe
// like readSecret, and from a terminal twice, refusing two different entries.
func (a *App) readNewSecret(envName, prompt, again string) (string, error) {
	if strings.TrimSpace(a.getenv(envName)) != "" || !a.stdinIsTerminal() {
		return a.readSecret(envName, prompt)
	}
	first, err := a.readSecret(envName, prompt)
	if err != nil {
		return "", err
	}
	second, err := a.readSecret(envName, again)
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("the two entries differ")
	}
	return first, nil
}

// parseUUID reads a dashed (8-4-4-4-12) or plain 32-hex UUID.
func parseUUID(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) == 36 {
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return nil, false
		}
		s = strings.ReplaceAll(s, "-", "")
	}
	if len(s) != 32 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// custodyHint explains a 429 from a custody write.
func custodyHint(err error) string {
	if bridge.StatusCode(err) != http.StatusTooManyRequests {
		return ""
	}
	return "hint: key-custody writes (certificates, issuer keys, seeds, SEP-10 keys) share one budget of 5 per " +
		"60 s per operator; wait a minute and run the command again: it continues where it stopped"
}

// setupSecrets are the ceremony's secrets, read before the card is touched.
type setupSecrets struct {
	kmk       []byte
	userPIN   string
	masterPIN string
	transport card.SCP03Keys
}

func (s *setupSecrets) wipe() {
	clear(s.kmk)
	s.transport.Wipe()
	s.userPIN, s.masterPIN = "", ""
}

// readSetupSecrets reads, in this order: the KMK, the user PIN, the master
// PIN (each from its variable, a no-echo prompt, or one stdin line), and the
// transport keys (environment only). An error is a usage error; it never
// contains the value.
func (a *App) readSetupSecrets() (*setupSecrets, error) {
	s := &setupSecrets{transport: card.DefaultSCP03Keys()}
	kmkHex, err := a.readSecret(config.EnvIssueKMK, "Key master key (KMK, 32 hex): ")
	if err != nil {
		return nil, err
	}
	if s.kmk, err = hex.DecodeString(kmkHex); err != nil || len(s.kmk) != 16 {
		clear(s.kmk)
		return nil, fmt.Errorf("$%s must be 32 hex characters (16 bytes)", config.EnvIssueKMK)
	}
	if s.userPIN, err = a.readNewSecret(config.EnvCardPIN, "New card PIN (4 digits): ", "Repeat the card PIN: "); err != nil {
		s.wipe()
		return nil, err
	}
	if !card.ValidUserPIN(s.userPIN) {
		s.wipe()
		return nil, fmt.Errorf("$%s must be 4 digits, not all zeros (the PIN-less request marker)", config.EnvCardPIN)
	}
	if s.masterPIN, err = a.readNewSecret(config.EnvCardMasterPIN, "Card master PIN (8 digits): ", "Repeat the master PIN: "); err != nil {
		s.wipe()
		return nil, err
	}
	if !card.ValidMasterPIN(s.masterPIN) {
		s.wipe()
		return nil, fmt.Errorf("$%s must be 8 digits", config.EnvCardMasterPIN)
	}
	if v := strings.TrimSpace(a.getenv(config.EnvSCP03TransportKeys)); v != "" {
		b, err := hex.DecodeString(v)
		if err == nil {
			s.transport, err = card.ParseSCP03Keys(b)
		}
		clear(b)
		if err != nil {
			s.wipe()
			return nil, fmt.Errorf("$%s must be 96 hex characters (ENC ‖ MAC ‖ DEK)", config.EnvSCP03TransportKeys)
		}
	}
	return s, nil
}

// cardSetup is one ceremony.
type cardSetup struct {
	a    *App
	opts options
	ctx  context.Context
	cd   *card.Card
	rnd  io.Reader
	sec  *setupSecrets

	op, holder    *bridge.Client
	holderAccount string // the account_id POST /card names (the holder's subject)
	network       string

	account    []byte // --account
	accountStr string // --account, canonical
	currency   string
	tag        []byte
	scale      int
	counter    uint32
	capSHA     string

	issuer    *bridge.CardIssuerInfo
	issuerPub []byte
	programID []byte
}

func (s *cardSetup) notice(format string, args ...any) {
	fmt.Fprintf(s.a.err, format+"\n", args...)
}

func (a *App) runCardSetup(opts options, args []string) int {
	fs := a.newFlagSet("card setup")
	bindGlobalFlags(fs, &opts)
	spec := fs.String("card", "", "the card: tcp:HOST:PORT (the impala-card simulator transport)")
	aid := fs.String("aid", "", "applet AID to SELECT (hex; default "+card.DefaultAID+")")
	accountFlag := fs.String("account", "", "the bridge account (payala_account_id, a UUID) the card is issued to")
	currency := fs.String("currency", "XLM", "the card's currency: XLM, USDC or USDT0")
	scale := fs.Int("card-minor-scale", 7, "the card minor-unit scale the certificate records (0..7)")
	counter := fs.Int64("initial-counter", 0, "receive-counter floor (replacement cards; 0..2147483647)")
	capFile := fs.String("cap", "", "CAP file whose sha256 goes into the record")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 || *spec == "" || *accountFlag == "" {
		return a.usageErr("%s", cardSetupUsage)
	}
	account, ok := parseUUID(*accountFlag)
	if !ok || bytes.Equal(account, make([]byte, 16)) {
		return a.usageErr("--account must be a UUID (the card signs in with the account UUID it carries)")
	}
	tag, ok := card.CurrencyTag(*currency)
	if !ok {
		return a.usageErr("--currency must be XLM, USDC or USDT0")
	}
	if *scale < 0 || *scale > 7 {
		return a.usageErr("--card-minor-scale must be 0..7")
	}
	if *counter < 0 || *counter > 0x7FFFFFFF {
		return a.usageErr("--initial-counter must be 0..2147483647")
	}
	if _, _, err := card.ParseSpec(*spec); err != nil {
		return a.usageErr("%v", err)
	}
	if *aid != "" && !aidPattern.MatchString(*aid) {
		return a.usageErr("--aid must be 5..16 bytes of hex, got %q", *aid)
	}
	aidHex, err := a.checkCardSpec(opts, *spec, *aid)
	if err != nil {
		return a.fail("%v", err)
	}
	capSHA := ""
	if *capFile != "" {
		b, err := os.ReadFile(*capFile)
		if err != nil {
			return a.usageErr("--cap: %v", err)
		}
		sum := sha256.Sum256(b)
		capSHA = hex.EncodeToString(sum[:])
	}

	s := &cardSetup{
		a: a, opts: opts, ctx: context.Background(), rnd: a.random(),
		account: account, accountStr: card.FormatUUID(account), currency: *currency, tag: tag,
		scale: *scale, counter: uint32(*counter), capSHA: capSHA,
	}
	// Pre-flight, before the card is touched: the tokens, the card program
	// and the network first (a missing holder token is reported before any
	// secret is asked for), then every secret.
	if s.op, err = a.authClient(opts); err != nil {
		return a.fail("%v", err)
	}
	if code := s.resolveHolder(); code != 0 {
		return code
	}
	if code := s.readIssuer(); code != 0 {
		return code
	}
	s.network = a.bridgeNetwork(s.op)
	if s.sec, err = a.readSetupSecrets(); err != nil {
		return a.usageErr("%v", err)
	}
	defer s.sec.wipe()

	if s.cd, err = a.dialCard(opts, *spec, aidHex); err != nil {
		return a.fail("%v", err)
	}
	defer s.cd.Close()
	return s.run()
}

// resolveHolder picks the holder's client: $IMPALA_HOLDER_TOKEN, or the
// session's own token when its subject is --account.
func (s *cardSetup) resolveHolder() int {
	a := s.a
	if tok := strings.TrimSpace(a.getenv(config.EnvHolderToken)); tok != "" {
		s.holderAccount = s.accountStr
		if claims, err := bridge.ParseClaims(tok); err == nil {
			if !sameUUID(claims.Subject, s.accountStr) {
				return a.fail("$%s is a token for account %s, not --account %s: nothing was sent to the card or the bridge",
					config.EnvHolderToken, dash(claims.Subject), s.accountStr)
			}
			s.holderAccount = claims.Subject
		}
		c, err := a.newClient(s.opts)
		if err != nil {
			return a.fail("%v", err)
		}
		c.SetToken(tok)
		s.holder = c
		return 0
	}
	claims, err := s.op.TokenClaims()
	if err != nil || !sameUUID(claims.Subject, s.accountStr) {
		subject := "an unreadable subject"
		if err == nil {
			subject = "account " + dash(claims.Subject)
		}
		return a.usageErr("set $%s to the card holder's token: the session's own token is for %s, not --account %s "+
			"(POST /card and PUT /card/stellar-key are the holder's own requests)", config.EnvHolderToken, subject, s.accountStr)
	}
	s.holder, s.holderAccount = s.op, claims.Subject
	return 0
}

// readIssuer reads GET /card-issuer: the program must be configured.
func (s *cardSetup) readIssuer() int {
	a := s.a
	info, _, err := s.op.CardIssuer(s.ctx)
	if err != nil {
		return a.fail("read the card program (GET /card-issuer): %v", err)
	}
	if !info.Configured {
		return a.fail("the bridge has no card issuer key (GET /card-issuer: configured=false): run " +
			"`impalactl card issuer generate` first (admin or key-custodian)")
	}
	pub, err := hex.DecodeString(info.PublicKeyHex)
	if err != nil || len(pub) != 65 || pub[0] != 0x04 {
		return a.fail("GET /card-issuer: public_key_hex is not a 65-byte uncompressed P-256 point")
	}
	program, err := hex.DecodeString(info.ProgramIDHex)
	if err != nil || len(program) != 16 {
		return a.fail("GET /card-issuer: program_id_hex is not 16 bytes of hex")
	}
	s.issuer, s.issuerPub, s.programID = info, pub, program
	return 0
}

func (s *cardSetup) run() int {
	a, cd := s.a, s.cd
	v, err := cd.GetVersion()
	if err != nil {
		return a.fail("%v", err)
	}
	if !v.AtLeast(0, 2) {
		return a.fail("the card runs applet %s, older than 0.2 (the certified transfer protocol): it cannot be issued", v)
	}
	p, err := cd.GetPersonalization()
	if err != nil {
		return a.fail("%v", err)
	}
	if p.Terminated() {
		return a.fail("the card is terminated: it can never be issued again")
	}
	if p.Personalized() {
		return s.issued(v, p)
	}

	state := "blank (its card id and keys are generated at INITIALIZE)"
	if p.Initialized() {
		state = "initialized, not personalized (its card id is read next)"
	}
	if code := s.confirm(state, "This writes a certificate on the bridge and personalizes the card; neither can be undone.",
		"it writes a certificate on the bridge and personalizes the card"); code != 0 {
		return code
	}

	if !p.Initialized() {
		if err := cd.Initialize(s.rnd); err != nil {
			return a.fail("%v", err)
		}
		s.notice("initialized (card key generated)")
	}
	_, cardID, err := cd.GetUserData()
	if err != nil {
		return a.fail("%v", err)
	}
	pub, err := cd.GetECPubKey()
	if err != nil {
		return a.fail("%v", err)
	}
	wire := hex.EncodeToString(cardID)
	s.notice("card %s", wire)

	perCard, err := card.CardKeys(s.sec.kmk, cardID)
	if err != nil {
		return a.fail("%v", err)
	}
	defer perCard.Wipe()
	sc, err := s.openPerCard(&perCard)
	if err != nil {
		return a.fail("%v", err)
	}
	defer sc.Close()

	certDER, version, code := s.certificate(wire, pub, p)
	if code != 0 {
		return code
	}
	identity, err := card.IdentityPart(s.account, s.tag, s.programID, s.counter)
	if err != nil {
		return a.fail("%v", err)
	}
	issuerPart := s.issuerPub
	if p.ProgramBound() {
		issuerPart = nil // bound at install: part B is refused
	}
	if err := sc.Personalize(identity, issuerPart, certDER); err != nil {
		return a.fail("%v", err)
	}
	s.notice("personalized")
	if err := sc.ProvisionPINs(s.sec.masterPIN, s.sec.userPIN); err != nil {
		return a.fail("%v", err)
	}
	s.notice("PINs provisioned")
	sc.Close()

	p, code = s.readBack()
	if code != 0 {
		return code
	}
	return s.finish(v, p, setupIssued, &version)
}

// confirm shows what is about to happen (unless --yes) and asks.
func (s *cardSetup) confirm(state, effect, stake string) int {
	a := s.a
	if !s.opts.yes {
		kv(a.err, [][2]string{
			{"Card:", state},
			{"Account:", s.accountStr},
			{"Bridge:", fmt.Sprintf("%s (network %s)", s.op.Endpoint(), dash(s.network))},
			{"Currency:", fmt.Sprintf("%s, card minor scale %d", s.currency, s.scale)},
		})
		fmt.Fprintln(a.err, effect)
	}
	if err := a.confirmStake(s.network, "issue this card", stake, s.opts.yes); err != nil {
		return a.fail("%v", err)
	}
	return 0
}

// issued handles a personalized card: nothing changes on it, except the PINs
// of a card personalized without them.
func (s *cardSetup) issued(v card.Version, p *card.Personalization) int {
	if !p.PinProvisioned() {
		return s.finishPINs(v, p)
	}
	key, account, cardID, pub, code := s.readIdentity(p)
	if code != 0 {
		return code
	}
	if code := s.checkIssuedTo(account, cardID, p); code != 0 {
		return code
	}
	s.notice("card %s is already personalized; nothing to do on the card", hex.EncodeToString(cardID))
	return s.finishWith(v, p, key, account, cardID, pub, setupAlreadyIssued, nil)
}

// checkIssuedTo refuses a personalized card of another account.
func (s *cardSetup) checkIssuedTo(account, cardID []byte, p *card.Personalization) int {
	if !bytes.Equal(account, s.account) {
		return s.a.fail("card %s is issued to account %s, not --account %s: nothing was changed",
			hex.EncodeToString(cardID), card.FormatUUID(account), s.accountStr)
	}
	if onCard := card.CurrencyCode(p.Currency); onCard != s.currency {
		s.notice("note: the card's currency is %s, not --currency %s (a personalized card keeps its own)", onCard, s.currency)
	}
	return 0
}

// finishPINs finishes a card torn between PERSONALIZE and PROVISION_PIN
// (under ENFORCE such a card cannot sign at all): GET_USER_DATA for the card
// id, SCP03 on the per-card keys, PROVISION_PIN master and user, the
// read-back, then the record and the Stellar key as on the no-op path. It
// obtains no certificate, so the record has no issuer_version.
func (s *cardSetup) finishPINs(v card.Version, p *card.Personalization) int {
	a := s.a
	account, cardID, err := s.cd.GetUserData()
	if err != nil {
		return a.fail("%v", err)
	}
	if code := s.checkIssuedTo(account, cardID, p); code != 0 {
		return code
	}
	s.notice("card %s is personalized but has no PINs (an issuance that stopped after PERSONALIZE)",
		hex.EncodeToString(cardID))
	if code := s.confirm("personalized; only its PINs are missing",
		"This provisions the card's master and user PINs; it cannot be undone.",
		"it provisions the card's PINs"); code != 0 {
		return code
	}
	perCard, err := card.CardKeys(s.sec.kmk, cardID)
	if err != nil {
		return a.fail("%v", err)
	}
	defer perCard.Wipe()
	sc, err := s.cd.OpenSecureChannel(&perCard, s.rnd)
	var ce *card.CryptogramError
	if errors.As(err, &ce) {
		return a.fail("the card does not open SCP03 on the keys $%s derives for it: the wrong KMK, or a card "+
			"issued by another program; nothing was changed", config.EnvIssueKMK)
	}
	if err != nil {
		return a.fail("%v", err)
	}
	defer sc.Close()
	s.notice("SCP03 open on per-card keys")
	if err := sc.ProvisionPINs(s.sec.masterPIN, s.sec.userPIN); err != nil {
		return a.fail("%v", err)
	}
	s.notice("PINs provisioned (finishing a ceremony that stopped after PERSONALIZE)")
	sc.Close()
	p, code := s.readBack()
	if code != 0 {
		return code
	}
	return s.finish(v, p, setupIssued, nil)
}

// readBack checks GET_PERSONALIZATION after the ceremony.
func (s *cardSetup) readBack() (*card.Personalization, int) {
	p, err := s.cd.GetPersonalization()
	if err != nil {
		return nil, s.a.fail("%v", err)
	}
	if !p.Personalized() || !p.PinProvisioned() || p.Flags&card.FlagSCP03KeysDefault != 0 {
		return nil, s.a.fail("the read-back does not show personalized, pin-provisioned and not "+
			"scp03-default-keys (flags: %s)", strings.Join(card.FlagNames(p.Flags), ", "))
	}
	return p, 0
}

// readIdentity is the record's reads: GET_STELLAR_KEY (flag 0x80),
// GET_USER_DATA, GET_EC_PUB_KEY: the record is what the card reports now.
func (s *cardSetup) readIdentity(p *card.Personalization) (*card.StellarKey, []byte, []byte, []byte, int) {
	a, cd := s.a, s.cd
	var key *card.StellarKey
	if p.Flags&card.FlagStellarKey != 0 {
		var err error
		if key, err = cd.GetStellarKey(); err != nil {
			return nil, nil, nil, nil, a.fail("%v", err)
		}
		if key == nil {
			s.notice("the card advertises a Stellar key but GET_STELLAR_KEY has none: it signs in with the legacy challenge")
		}
	}
	account, cardID, err := cd.GetUserData()
	if err != nil {
		return nil, nil, nil, nil, a.fail("%v", err)
	}
	pub, err := cd.GetECPubKey()
	if err != nil {
		return nil, nil, nil, nil, a.fail("%v", err)
	}
	return key, account, cardID, pub, 0
}

// openPerCard opens SCP03 on the per-card keys; a card still on its
// transport keys is rotated to them first (APPLET_UPDATE). Only a cryptogram
// mismatch moves on to the next key set, and a mismatch sends nothing more.
func (s *cardSetup) openPerCard(perCard *card.SCP03Keys) (*card.SecureChannel, error) {
	var ce *card.CryptogramError
	sc, err := s.cd.OpenSecureChannel(perCard, s.rnd)
	if err == nil {
		s.notice("SCP03 open on per-card keys")
		return sc, nil
	}
	if !errors.As(err, &ce) {
		return nil, err
	}
	tsc, err := s.cd.OpenSecureChannel(&s.sec.transport, s.rnd)
	if errors.As(err, &ce) {
		which := "the GP default keys"
		if strings.TrimSpace(s.a.getenv(config.EnvSCP03TransportKeys)) != "" {
			which = "$" + config.EnvSCP03TransportKeys
		}
		return nil, fmt.Errorf("the card opens SCP03 neither on the keys $%s derives for it nor on the transport "+
			"keys (%s): the wrong KMK, or the wrong transport keys; nothing was changed", config.EnvIssueKMK, which)
	}
	if err != nil {
		return nil, err
	}
	err = tsc.RotateKeys(perCard)
	tsc.Close()
	if err != nil {
		return nil, err
	}
	s.notice("SCP03 keys rotated to per-card keys (APPLET_UPDATE seq 0x0001)")
	return s.cd.OpenSecureChannel(perCard, s.rnd)
}

// register makes sure the bridge has the card row: a card the operator's
// listing already shows active is not POSTed again (the bridge would answer a
// repeat with a generic 500, an ERROR line in its log). Otherwise POST /card
// under the holder's token; only 500 and 409 (the card is probably registered
// already) are tolerated, since certification decides; any other refusal is
// fatal before the certificate is requested.
func (s *cardSetup) register(wire string, pub []byte) int {
	a := s.a
	if list, _, err := s.op.AccountCards(s.ctx, s.holderAccount); err == nil {
		for _, c := range list.Cards {
			if c.Active && strings.EqualFold(c.CardID, wire) {
				s.notice("already registered with the bridge (POST /card not repeated)")
				return 0
			}
		}
	}
	_, err := s.holder.RegisterCard(s.ctx, bridge.RegisterCardRequest{
		AccountID: s.holderAccount, CardID: wire, ECPubKey: hex.EncodeToString(pub),
	})
	if err == nil {
		s.notice("registered with the bridge (POST /card)")
		return 0
	}
	switch st := bridge.StatusCode(err); st {
	case http.StatusInternalServerError, http.StatusConflict:
		s.notice("POST /card refused (HTTP %d): the card is probably registered already; continuing "+
			"(certification requires the card row)", st)
		return 0
	case http.StatusUnauthorized:
		return a.fail("register the card (POST /card, HTTP 401): the holder's token is not accepted: %v", err)
	case http.StatusForbidden:
		return a.fail("register the card (POST /card, HTTP 403): the bridge refused the holder's request: %v", err)
	case 0:
		return a.fail("register the card (POST /card): %v", err)
	default:
		code := a.fail("register the card (POST /card, HTTP %d): %v", st, err)
		if hint := custodyHint(err); hint != "" {
			fmt.Fprintln(a.err, "hint: the bridge rate-limits card registrations; wait a minute and run the command again")
		}
		return code
	}
}

// certificate registers the card (holder) and has the bridge certify it
// (operator), then checks the answer against GET /card-issuer and the card,
// and verifies the certificate here, all before anything reaches the card.
func (s *cardSetup) certificate(wire string, pub []byte, p *card.Personalization) ([]byte, int, int) {
	a := s.a
	if code := s.register(wire, pub); code != 0 {
		return nil, 0, code
	}

	req := bridge.CertifyCardRequest{Currency: s.currency, CardMinorScale: s.scale}
	resp, _, err := s.op.CertifyCard(s.ctx, wire, req)
	if bridge.StatusCode(err) == http.StatusConflict {
		// An earlier run certified the card and stopped before PERSONALIZE
		// committed: the card is not personalized, so a fresh certificate
		// over the same CERT message is safe.
		s.notice("card already certified by an earlier run; recertifying")
		req.Recertify = true
		resp, _, err = s.op.CertifyCard(s.ctx, wire, req)
	}
	if err != nil {
		code := a.fail("certify the card (POST /admin/cards/%s/certificate): %v", wire, err)
		if hint := custodyHint(err); hint != "" {
			fmt.Fprintln(a.err, hint)
		}
		return nil, 0, code
	}

	refuse := func(format string, args ...any) ([]byte, int, int) {
		return nil, 0, a.fail(format+": nothing was sent to the card", args...)
	}
	if !strings.EqualFold(resp.IssuerPublicKeyHex, s.issuer.PublicKeyHex) {
		return refuse("the certificate's issuer key differs from GET /card-issuer (was the key rotated during the ceremony?)")
	}
	programHex := resp.ProgramIDHex
	if programHex == "" {
		programHex = s.issuer.ProgramIDHex
	}
	if !strings.EqualFold(programHex, s.issuer.ProgramIDHex) {
		return refuse("the certificate's program id %s differs from GET /card-issuer's %s", programHex, s.issuer.ProgramIDHex)
	}
	if p.ProgramBound() {
		if !bytes.Equal(p.ProgramID, s.programID) {
			return refuse("the card is bound at install to program %s; the bridge's program is %s",
				hex.EncodeToString(p.ProgramID), hex.EncodeToString(s.programID))
		}
		if p.IssuerPubKey != nil && !bytes.Equal(p.IssuerPubKey, s.issuerPub) {
			return refuse("the card's installed program key is not the bridge's issuer key")
		}
	}
	der, err := hex.DecodeString(resp.IssuerCertHex)
	if trimmed, terr := card.TrimDER(der); err != nil || terr != nil || len(trimmed) != len(der) {
		return refuse("the bridge's certificate is not a DER signature of 8..72 bytes")
	}
	msg, err := card.CertMessage(s.programID, s.account, s.tag, pub)
	if err != nil {
		return refuse("%v", err)
	}
	issuer, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), s.issuerPub)
	h := sha256.Sum256(msg)
	if err != nil || !ecdsa.VerifyASN1(issuer, h[:], der) {
		return refuse("the certificate does not verify under the issuer key over the CERT message")
	}
	return der, resp.IssuerVersion, 0
}

// finish reads the record's identity and completes the ceremony.
func (s *cardSetup) finish(v card.Version, p *card.Personalization, status string, issuerVersion *int) int {
	key, account, cardID, pub, code := s.readIdentity(p)
	if code != 0 {
		return code
	}
	return s.finishWith(v, p, key, account, cardID, pub, status, issuerVersion)
}

func (s *cardSetup) finishWith(v card.Version, p *card.Personalization, key *card.StellarKey,
	account, cardID, pub []byte, status string, issuerVersion *int) int {
	a := s.a
	certID, err := card.CertID(p.ProgramID, account, p.Currency, pub)
	if err != nil {
		return a.fail("%v", err)
	}
	rec := cardSetupRecord{
		CardID:        hex.EncodeToString(cardID),
		AccountID:     card.FormatUUID(account),
		ProgramID:     hex.EncodeToString(p.ProgramID),
		Currency:      card.CurrencyCode(p.Currency),
		CertID:        hex.EncodeToString(certID),
		Applet:        v.String(),
		AppletHash:    v.Hash,
		CapSHA256:     s.capSHA,
		IssuerVersion: issuerVersion,
		Status:        status,
	}
	if key != nil {
		if rec.StellarKey, err = s.registerStellarKey(key, account, cardID, pub); err != nil {
			return a.fail("%v", err)
		}
	}
	if s.opts.json {
		b, _ := json.Marshal(rec)
		return a.printJSON(b)
	}
	rows := [][2]string{
		{"Card id:", rec.CardID},
		{"Account:", rec.AccountID},
		{"Program:", rec.ProgramID},
		{"Currency:", rec.Currency},
		{"Certificate id:", rec.CertID},
		{"Applet:", fmt.Sprintf("%s (build %s)", rec.Applet, rec.AppletHash)},
	}
	if rec.CapSHA256 != "" {
		rows = append(rows, [2]string{"CAP sha256:", rec.CapSHA256})
	}
	if rec.IssuerVersion != nil {
		rows = append(rows, [2]string{"Issuer version:", strconv.Itoa(*rec.IssuerVersion)})
	}
	switch k := rec.StellarKey; {
	case k == nil:
		rows = append(rows, [2]string{"Stellar key:", "none (the card signs in with the legacy challenge)"})
	case k.Registered:
		rows = append(rows, [2]string{"Stellar key:", fmt.Sprintf("%s (%s engine, registered: SEP-10 sign-in)", k.Address, k.Engine)})
	default:
		rows = append(rows, [2]string{"Stellar key:", fmt.Sprintf("%s (%s engine, NOT registered: legacy sign-in until it is)", k.Address, k.Engine)})
	}
	rows = append(rows, [2]string{"Status:", rec.Status})
	kv(a.out, rows)
	return 0
}

// registerStellarKey checks the card's two cross-signatures here and
// registers the key with the bridge under the holder's token. Never fatal:
// a card whose key is not registered is fully issued and signs in with the
// legacy challenge.
func (s *cardSetup) registerStellarKey(key *card.StellarKey, account, cardID, pub []byte) (*cardSetupStellar, error) {
	addr, err := sep10.EncodeAccountID(key.PublicKey)
	if err != nil {
		return nil, err
	}
	out := &cardSetupStellar{Address: addr, Engine: key.EngineName()}
	s.notice("stellar key %s (%s engine)", addr, out.Engine)
	unregistered := func(note string) (*cardSetupStellar, error) {
		out.Note = note
		s.notice("%s", note)
		return out, nil
	}
	ec, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	bh := sha256.Sum256(card.BindingMessage(account, cardID, key.PublicKey))
	if perr != nil || key.BindingSig == nil || len(key.ProofSig) != 64 ||
		!ecdsa.VerifyASN1(ec, bh[:], key.BindingSig) ||
		!ed25519.Verify(ed25519.PublicKey(key.PublicKey), card.ProofMessage(account, cardID, pub), key.ProofSig) {
		return unregistered("the card's Stellar key signatures do not verify; NOT registered (the card signs in with " +
			"the legacy challenge)")
	}
	_, err = s.holder.SetCardStellarKey(s.ctx, bridge.SetCardStellarKeyRequest{
		CardID:            hex.EncodeToString(cardID),
		StellarAddress:    addr,
		StellarBindingSig: hex.EncodeToString(key.BindingSig),
		StellarProofSig:   hex.EncodeToString(key.ProofSig),
	})
	if err != nil {
		return unregistered(fmt.Sprintf("PUT /card/stellar-key failed (%v); the card is issued and signs in with the "+
			"legacy challenge until its Stellar key is registered (run `impalactl card setup` again, or register it "+
			"from the holder's app)", err))
	}
	out.Registered = true
	s.notice("Stellar key registered with the bridge (PUT /card/stellar-key)")
	return out, nil
}
