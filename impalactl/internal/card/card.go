package card

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Instruction bytes (impala-card/sdk Constants.kt; docs/apdu.md).
const (
	insSelect              byte = 0xA4
	insVerifyPIN           byte = 0x18
	insGetUserData         byte = 0x1E
	insGetECPubKey         byte = 0x24
	insSignAuth            byte = 0x25
	insGetPersonalization  byte = 0x34
	insGetStellarKey       byte = 0x37
	insSignSep10           byte = 0x38
	insGetUserVerification byte = 0x39
	insGetVersion          byte = 0x64

	p2UserPIN byte = 0x82

	p1SignAuthPlain    byte = 0x00
	p1SignAuthPinProof byte = 0x01

	p1Sep10Begin    byte = 0x00
	p1Sep10Continue byte = 0x01
	p1Sep10Finish   byte = 0x02

	maxShortAPDUData = 255
	// MaxSep10Transaction is the largest challenge transaction a card stages.
	MaxSep10Transaction = 640
)

// DefaultAID is the applet-instance AID of the testnet CAP
// (impala-lib ImpalaCardSession.TESTNET_APPLET_AID).
const DefaultAID = "01020304050607080102"

// Status words with a meaning worth naming.
const (
	SWOK                 uint16 = 0x9000
	SWNotSupported       uint16 = 0x6D00
	SWStellarKeyMissing  uint16 = 0x623C
	SWPinRequired        uint16 = 0x6690
	SWConditions         uint16 = 0x6985
	SWPinBlocked         uint16 = 0x69C0
	SWECKeyMissing       uint16 = 0x6230
	SWAppletNotFound     uint16 = 0x6A82
	SWAppletSelectFailed uint16 = 0x6999
)

var swNames = map[uint16]string{
	0x6300: "SCP03_AUTH_FAILED: the host cryptogram or its MAC does not verify",
	0x6230: "EC_CARD_KEY_MISSING: the card was never initialized",
	0x6234: "NOT_PERSONALIZED",
	0x6235: "ALREADY_PERSONALIZED",
	0x6236: "DEFAULT_SCP03_KEYS: the card is still on the GP default keys",
	0x6237: "PERSONALIZE_SEQUENCE: a part arrived out of order (the ceremony restarts from part A)",
	0x623B: "PROGRAM_ALREADY_BOUND: the card is bound to a program (another one, or at install)",
	0x6677: "CARD_DATA_SIGNATURE_INVALID: the certificate does not verify under the issuer key",
	0x6683: "CRYPTO_EXCEPTION",
	0x6684: "INVALID_AES_KEY: the GP default key is not a rotation target",
	0x6686: "ALREADY_INITIALIZED",
	0x6688: "SCP03_MAC_FAILED: the command MAC does not verify (the session is closed)",
	0x623C: "STELLAR_KEY_MISSING: the card has no Stellar key",
	0x6240: "SEP10_MALFORMED: the card's parser refused the transaction's shape",
	0x6241: "SEP10_SEQUENCE_NOT_ZERO",
	0x6242: "SEP10_NOT_MANAGE_DATA: an operation is not manage-data, or the count is wrong",
	0x6243: "SEP10_WRONG_ACCOUNT: the challenge is not addressed to this card's key",
	0x6244: "SEP10_NOT_AUTH_CHALLENGE: the first operation is not an \"… auth\" challenge",
	0x6245: "SEP10_NO_TIME_BOUNDS",
	0x6687: "CARD_TERMINATED",
	0x6690: "PIN_REQUIRED: the user PIN must be verified first",
	0x6691: "PIN_REJECTED",
	0x6700: "WRONG_LENGTH",
	0x6982: "SECURITY_STATUS_NOT_SATISFIED",
	0x6985: "CONDITIONS_NOT_SATISFIED (no provisioned PIN, a fixed policy, or a provisioning gate)",
	0x6A80: "WRONG_DATA",
	0x6A82: "APPLET_NOT_FOUND: no applet under this AID",
	0x6A86: "INCORRECT_P1P2",
	0x6999: "APPLET_SELECT_FAILED",
	0x6D00: "INS_NOT_SUPPORTED (another applet, or an older applet version)",
	0x6E00: "CLA_NOT_SUPPORTED",
	0x69C0: "PIN_BLOCKED: no tries left",
}

// SWName describes a status word.
func SWName(sw uint16) string {
	if sw > 0x69C0 && sw <= 0x69C9 {
		return fmt.Sprintf("WRONG_PIN: %d tries left", sw&0x0F)
	}
	if n, ok := swNames[sw]; ok {
		return n
	}
	return "unknown status"
}

// Error is a card refusal: the step of the flow, the command, and the status
// word the card answered.
type Error struct {
	Step    string
	Command string
	SW      uint16
}

func (e *Error) Error() string {
	return fmt.Sprintf("the card refused to %s (%s): SW %04X %s", e.Step, e.Command, e.SW, SWName(e.SW))
}

// TransportError is a failure of the exchange itself.
type TransportError struct {
	Step    string
	Command string
	Err     error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("card transport failed while trying to %s (%s): %v", e.Step, e.Command, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// ProtocolError is an answer of the wrong shape.
type ProtocolError struct {
	Step string
	Msg  string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("the card's answer while trying to %s is not usable: %s", e.Step, e.Msg)
}

// SWOf returns the status word of a card refusal, or 0.
func SWOf(err error) uint16 {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.SW
	}
	return 0
}

// Card is one applet session over a transport.
type Card struct {
	t Transport
}

// New wraps a transport.
func New(t Transport) *Card { return &Card{t: t} }

// Close closes the transport.
func (c *Card) Close() error { return c.t.Close() }

// exchange sends CLA INS P1 P2 [Lc data] (no Le, like the SDK's case 1 /
// case 3 commands) and returns the data of a 9000 answer.
func (c *Card) exchange(step, command string, cla, ins, p1, p2 byte, data []byte) ([]byte, error) {
	apdu := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		if len(data) > maxShortAPDUData {
			return nil, &ProtocolError{Step: step, Msg: "command data longer than a short APDU"}
		}
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
	}
	data, sw, err := c.transmit(step, command, apdu)
	if err != nil {
		return nil, err
	}
	if sw != SWOK {
		return nil, &Error{Step: step, Command: command, SW: sw}
	}
	return data, nil
}

// transmit sends one APDU, zeroes it, and splits the answer into data and
// status word.
func (c *Card) transmit(step, command string, apdu []byte) ([]byte, uint16, error) {
	resp, err := c.t.Transmit(apdu)
	// The command may carry a PIN or key material: never keep it around
	// longer than needed.
	clear(apdu)
	if err != nil {
		return nil, 0, &TransportError{Step: step, Command: command, Err: err}
	}
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	return resp[:len(resp)-2], sw, nil
}

// Select SELECTs the applet by AID (hex, 5..16 bytes).
func (c *Card) Select(aidHex string) error {
	aid, err := hex.DecodeString(aidHex)
	if err != nil || len(aid) < 5 || len(aid) > 16 {
		return fmt.Errorf("AID must be 5..16 bytes of hex, got %q", aidHex)
	}
	_, err = c.exchange("select the Impala applet", "SELECT "+aidHex, 0x00, insSelect, 0x04, 0x00, aid)
	return err
}

// Version is GET_VERSION.
type Version struct {
	Major, Minor, RevList uint16
	Hash                  string
}

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// AtLeast reports whether the applet is major.minor or newer.
func (v Version) AtLeast(major, minor uint16) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// GetVersion reads GET_VERSION (10 bytes).
func (c *Card) GetVersion() (Version, error) {
	const step = "read the applet version"
	d, err := c.exchange(step, "GET_VERSION", 0, insGetVersion, 0, 0, nil)
	if err != nil {
		return Version{}, err
	}
	if len(d) != 10 {
		return Version{}, &ProtocolError{step, fmt.Sprintf("%d bytes, expected 10", len(d))}
	}
	return Version{
		Major:   uint16(d[0])<<8 | uint16(d[1]),
		Minor:   uint16(d[2])<<8 | uint16(d[3]),
		RevList: uint16(d[4])<<8 | uint16(d[5]),
		Hash:    hex.EncodeToString(d[6:10]),
	}, nil
}

// Personalization states and flags (GET_PERSONALIZATION).
const (
	StateBlank        byte = 0x00
	StateInitialized  byte = 0x01
	StatePersonalized byte = 0x02
	StateTerminated   byte = 0xFF

	FlagInitialized         byte = 0x01
	FlagProgramBound        byte = 0x02
	FlagPersonalized        byte = 0x04
	FlagSCP03KeysDefault    byte = 0x08
	FlagPinProvisioned      byte = 0x10
	FlagProvisioningEnforce byte = 0x20
	FlagTerminated          byte = 0x40
	FlagStellarKey          byte = 0x80
)

// Personalization is GET_PERSONALIZATION (159 bytes).
type Personalization struct {
	State       byte
	Flags       byte
	ProgramID   []byte
	Currency    []byte
	Certificate bool
	// IssuerPubKey is the 65-byte program key (nil while the slot is zero).
	IssuerPubKey []byte
	// CertificateDER is the trimmed certificate (nil while the slot is zero,
	// or when the slot does not hold a DER signature).
	CertificateDER []byte
}

// Initialized, ProgramBound, Personalized, PinProvisioned, Terminated: the
// flag bits (and the state byte, for termination).
func (p *Personalization) Initialized() bool  { return p.Flags&FlagInitialized != 0 }
func (p *Personalization) ProgramBound() bool { return p.Flags&FlagProgramBound != 0 }
func (p *Personalization) Personalized() bool { return p.Flags&FlagPersonalized != 0 }
func (p *Personalization) PinProvisioned() bool {
	return p.Flags&FlagPinProvisioned != 0
}
func (p *Personalization) Terminated() bool {
	return p.State == StateTerminated || p.Flags&FlagTerminated != 0
}

// GetPersonalization reads GET_PERSONALIZATION.
func (c *Card) GetPersonalization() (*Personalization, error) {
	const step = "read the personalization"
	d, err := c.exchange(step, "GET_PERSONALIZATION", 0, insGetPersonalization, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	if len(d) != 159 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected 159", len(d))}
	}
	p := &Personalization{State: d[0], Flags: d[1], ProgramID: d[2:18], Currency: d[18:22]}
	if !allZero(d[22:87]) {
		p.IssuerPubKey = d[22:87]
	}
	if !allZero(d[87:159]) {
		p.Certificate = true
		p.CertificateDER, _ = TrimDER(d[87:159])
	}
	return p, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TrimDER trims a zero-padded slot (8..72 bytes) to the DER signature it
// carries: slot[1] + 2 bytes of a slot that starts 0x30 (TransferProtocol.trimDer).
func TrimDER(slot []byte) ([]byte, error) {
	if len(slot) < 8 || len(slot) > 72 || slot[0] != 0x30 {
		return nil, errors.New("not a DER signature slot")
	}
	n := int(slot[1]) + 2
	if n < 8 || n > len(slot) {
		return nil, errors.New("the DER length is outside the slot")
	}
	return append([]byte(nil), slot[:n]...), nil
}

// GetUserData reads GET_USER_DATA and returns the on-card account UUID and
// card UUID (16 bytes each). The cardholder name that follows is dropped:
// nothing here needs it.
func (c *Card) GetUserData() (account, cardID []byte, err error) {
	const step = "read the card's account and card id"
	d, err := c.exchange(step, "GET_USER_DATA", 0, insGetUserData, 0, 0, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(d) < 32 {
		return nil, nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected at least 32", len(d))}
	}
	return append([]byte(nil), d[0:16]...), append([]byte(nil), d[16:32]...), nil
}

// GetECPubKey reads the card's 65-byte uncompressed P-256 key.
func (c *Card) GetECPubKey() ([]byte, error) {
	const step = "read the card's P-256 key"
	d, err := c.exchange(step, "GET_EC_PUB_KEY", 0, insGetECPubKey, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	if len(d) != 65 || d[0] != 0x04 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected a 65-byte uncompressed point", len(d))}
	}
	return d, nil
}

// UserVerification is GET_USER_VERIFICATION (applet 0.4).
type UserVerification struct {
	SignInPinRequired bool
	SignInPinFixed    bool
	PinProvisioned    bool
	PinVerified       bool
	TriesLeft         int
}

// GetUserVerification reads GET_USER_VERIFICATION; nil for an applet older
// than 0.4 (0x6D00).
func (c *Card) GetUserVerification() (*UserVerification, error) {
	const step = "read the cardholder-verification policy"
	d, err := c.exchange(step, "GET_USER_VERIFICATION", 0, insGetUserVerification, 0, 0, nil)
	if SWOf(err) == SWNotSupported {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(d) != 4 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected 4", len(d))}
	}
	if d[0] != 0x01 {
		return nil, &ProtocolError{step, fmt.Sprintf("unknown format 0x%02x", d[0])}
	}
	return &UserVerification{
		SignInPinRequired: d[1]&0x01 != 0,
		SignInPinFixed:    d[1]&0x02 != 0,
		PinProvisioned:    d[1]&0x04 != 0,
		PinVerified:       d[3]&0x01 != 0,
		TriesLeft:         int(d[2]),
	}, nil
}

// StellarKey is GET_STELLAR_KEY (applet 0.3).
type StellarKey struct {
	Engine    byte
	PublicKey []byte
	Bound     bool
	// BindingSig is the card P-256 key's trimmed DER signature over the
	// binding message, ProofSig the Stellar key's 64-byte signature over the
	// proof message; nil while the card is not personalized.
	BindingSig []byte
	ProofSig   []byte
}

// EngineName names the Ed25519 engine.
func (k *StellarKey) EngineName() string {
	switch k.Engine {
	case 0x01:
		return "soft"
	case 0x02:
		return "native"
	}
	return fmt.Sprintf("unknown(0x%02X)", k.Engine)
}

// GetStellarKey reads the card's Stellar key; nil when the card has none
// (0x623C, or 0x6D00 on an applet older than 0.3).
func (c *Card) GetStellarKey() (*StellarKey, error) {
	const step = "read the card's Stellar key"
	d, err := c.exchange(step, "GET_STELLAR_KEY", 0, insGetStellarKey, 0, 0, nil)
	if sw := SWOf(err); sw == SWStellarKeyMissing || sw == SWNotSupported {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(d) != 169 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected 169", len(d))}
	}
	k := &StellarKey{Engine: d[0], PublicKey: append([]byte(nil), d[1:33]...), Bound: !allZero(d[33:169])}
	if !allZero(d[33:105]) {
		k.BindingSig, _ = TrimDER(d[33:105])
	}
	if !allZero(d[105:169]) {
		k.ProofSig = append([]byte(nil), d[105:169]...)
	}
	return k, nil
}

// VerifyUserPIN sends VERIFY_PIN (P2 0x82) with the PIN as four digit
// values. A wrong PIN answers 0x69Cn (n tries left), a blocked one 0x69C0.
func (c *Card) VerifyUserPIN(pin string) error {
	if len(pin) != 4 {
		return errors.New("the card's user PIN is 4 digits")
	}
	digits := make([]byte, 4)
	for i, r := range pin {
		if r < '0' || r > '9' {
			return errors.New("the card's user PIN is 4 digits")
		}
		digits[i] = byte(r - '0')
	}
	_, err := c.exchange("verify the user PIN", "VERIFY_PIN", 0, insVerifyPIN, 0, p2UserPIN, digits)
	for i := range digits {
		digits[i] = 0
	}
	return err
}

// SignAuth signs a bridge challenge (8..64 bytes) with SIGN_AUTH: plain
// ("IMPALA-AUTH:" ‖ account ‖ challenge), or with pinProof the PIN proof
// ("IMPALA-APIN:" ‖ account ‖ challenge, only while the user PIN is
// verified). Returns the DER signature.
func (c *Card) SignAuth(challenge []byte, pinProof bool) ([]byte, error) {
	if len(challenge) < 8 || len(challenge) > 64 {
		return nil, fmt.Errorf("a card challenge is 8..64 bytes, got %d", len(challenge))
	}
	p1, step, cmd := p1SignAuthPlain, "sign the sign-in challenge", "SIGN_AUTH P1=00"
	if pinProof {
		p1, step, cmd = p1SignAuthPinProof, "make the PIN proof", "SIGN_AUTH P1=01"
	}
	d, err := c.exchange(step, cmd, 0, insSignAuth, p1, 0, challenge)
	if err != nil {
		return nil, err
	}
	if len(d) < 8 || len(d) > 72 || d[0] != 0x30 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, not a DER ECDSA signature", len(d))}
	}
	return d, nil
}

// SignSep10 has the card sign a SEP-10 challenge transaction with its
// Stellar key (SIGN_SEP10), in the SDK's exact parts: BEGIN carries the
// network id and as much of the transaction as fits beside it but never the
// last byte, CONTINUE parts of 255 bytes, and FINISH at least one byte.
// The card parses the transaction itself and signs its hash. Returns the
// 64-byte signature.
func (c *Card) SignSep10(networkID, tx []byte) ([]byte, error) {
	if len(networkID) != 32 {
		return nil, errors.New("network id must be 32 bytes")
	}
	if len(tx) < 2 || len(tx) > MaxSep10Transaction {
		return nil, fmt.Errorf("the challenge transaction is %d bytes; a card signs 2..%d", len(tx), MaxSep10Transaction)
	}
	const step = "sign the SEP-10 challenge"
	sent := min(len(tx)-1, maxShortAPDUData-len(networkID))
	begin := append(append([]byte(nil), networkID...), tx[:sent]...)
	if _, err := c.exchange(step, "SIGN_SEP10 BEGIN", 0, insSignSep10, p1Sep10Begin, 0, begin); err != nil {
		return nil, err
	}
	for len(tx)-sent > maxShortAPDUData {
		if _, err := c.exchange(step, "SIGN_SEP10 CONTINUE", 0, insSignSep10, p1Sep10Continue, 0, tx[sent:sent+maxShortAPDUData]); err != nil {
			return nil, err
		}
		sent += maxShortAPDUData
	}
	d, err := c.exchange(step, "SIGN_SEP10 FINISH", 0, insSignSep10, p1Sep10Finish, 0, tx[sent:])
	if err != nil {
		return nil, err
	}
	if len(d) != 64 {
		return nil, &ProtocolError{step, fmt.Sprintf("%d bytes, expected a 64-byte signature", len(d))}
	}
	return d, nil
}

// Identity is what a sign-in needs to know about a card.
type Identity struct {
	Version         Version
	AccountID       []byte // 16-byte UUID
	CardID          []byte // 16-byte UUID
	ECPubKey        []byte // nil when the card has no EC key yet
	Personalization *Personalization
}

// WireCardID is the bridge's card_id: 32 lowercase hex characters.
func (id *Identity) WireCardID() string { return hex.EncodeToString(id.CardID) }

// AccountUUID is the account as the bridge stores it: lowercase dashed.
func (id *Identity) AccountUUID() string { return FormatUUID(id.AccountID) }

// HasStellarKey: GET_PERSONALIZATION flag 0x80 (applet 0.3+).
func (id *Identity) HasStellarKey() bool { return id.Personalization.Flags&FlagStellarKey != 0 }

// FormatUUID renders 16 bytes as a lowercase dashed UUID.
func FormatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return h
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ReadIdentity reads the identity with the SDK's order (CardIdentity.read):
// the version gate first, so a 0.1 applet fails before any newer command. A
// card without an EC key yet (0x6230) yields a nil ECPubKey.
func ReadIdentity(c *Card) (*Identity, error) {
	v, err := c.GetVersion()
	if err != nil {
		return nil, err
	}
	if !v.AtLeast(0, 2) {
		return nil, &ProtocolError{"read the applet version", fmt.Sprintf("applet %s is older than 0.2 and cannot sign in", v)}
	}
	p, err := c.GetPersonalization()
	if err != nil {
		return nil, err
	}
	account, cardID, err := c.GetUserData()
	if err != nil {
		return nil, err
	}
	pub, err := c.GetECPubKey()
	if SWOf(err) == SWECKeyMissing {
		pub, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Identity{Version: v, AccountID: account, CardID: cardID, ECPubKey: pub, Personalization: p}, nil
}

// RequireSigner fails unless the card can sign in: personalized, not
// terminated, with an EC key.
func (id *Identity) RequireSigner() error {
	p := id.Personalization
	switch {
	case p.State == StateTerminated || p.Flags&FlagTerminated != 0:
		return errors.New("the card is terminated and can never sign in")
	case p.State != StatePersonalized || id.ECPubKey == nil:
		return fmt.Errorf("the card is not personalized (state %s): issue it first", StateName(p.State))
	}
	return nil
}

// StateName names a personalization state.
func StateName(s byte) string {
	switch s {
	case StateBlank:
		return "blank"
	case StateInitialized:
		return "initialized"
	case StatePersonalized:
		return "personalized"
	case StateTerminated:
		return "terminated"
	}
	return fmt.Sprintf("0x%02X", s)
}

// FlagNames lists the set personalization flags.
func FlagNames(f byte) []string {
	names := []struct {
		bit  byte
		name string
	}{
		{FlagInitialized, "initialized"}, {FlagProgramBound, "program-bound"},
		{FlagPersonalized, "personalized"}, {FlagSCP03KeysDefault, "scp03-default-keys"},
		{FlagPinProvisioned, "pin-provisioned"}, {FlagProvisioningEnforce, "provisioning-enforced"},
		{FlagTerminated, "terminated"}, {FlagStellarKey, "stellar-key"},
	}
	var out []string
	for _, n := range names {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}
