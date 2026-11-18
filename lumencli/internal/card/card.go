package card

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
)

// Instruction bytes (impala-card/docs/apdu.md).
const (
	insSelect              byte = 0xA4
	insVerifyPIN           byte = 0x18
	insGetPersonalization  byte = 0x34
	insGetStellarKey       byte = 0x37
	insSignSep10           byte = 0x38
	insGetUserVerification byte = 0x39
	insGetVersion          byte = 0x64

	p2UserPIN byte = 0x82

	p1Sep10Begin    byte = 0x00
	p1Sep10Continue byte = 0x01
	p1Sep10Finish   byte = 0x02

	maxShortAPDUData = 255
)

// The card's SEP-10 limits (docs/sep10-card-keys.md §2): it stages at most
// MaxSep10Transaction bytes of a challenge transaction and accepts at most
// MaxSep10Operations operations in it.
const (
	MaxSep10Transaction = 640
	MaxSep10Operations  = 5
)

// DefaultAID is the applet-instance AID every Impala tool selects by default
// (impala-card applet/build.xml; impala-lib ImpalaCardSession).
const DefaultAID = "01020304050607080102"

// Status words with a meaning worth naming.
const (
	SWOK                uint16 = 0x9000
	SWNotSupported      uint16 = 0x6D00
	SWStellarKeyMissing uint16 = 0x623C
	SWPinBlocked        uint16 = 0x69C0
)

var swNames = map[uint16]string{
	0x6234: "NOT_PERSONALIZED: the card has not been issued",
	0x623C: "STELLAR_KEY_MISSING: the card has no Stellar key",
	0x6240: "SEP10_MALFORMED: the card's parser refused the transaction's shape",
	0x6241: "SEP10_SEQUENCE_NOT_ZERO",
	0x6242: "SEP10_NOT_MANAGE_DATA: an operation is not manage-data, or the count is wrong",
	0x6243: "SEP10_WRONG_ACCOUNT: the challenge is not addressed to this card's key",
	0x6244: "SEP10_NOT_AUTH_CHALLENGE: the first operation is not an \"… auth\" challenge",
	0x6245: "SEP10_NO_TIME_BOUNDS",
	0x6687: "CARD_TERMINATED",
	0x6690: "PIN_REQUIRED: the user PIN must be verified first",
	0x6700: "WRONG_LENGTH",
	0x6982: "SECURITY_STATUS_NOT_SATISFIED",
	0x6985: "CONDITIONS_NOT_SATISFIED (no provisioned PIN, the provisioning gate, or nothing staged)",
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

// exchange sends CLA INS P1 P2 [Lc data] (no Le, like the card SDK's case 1 /
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
	// The command may carry a PIN: never keep it around longer than needed.
	clear(apdu)
	if err != nil {
		return nil, 0, &TransportError{Step: step, Command: command, Err: err}
	}
	if len(resp) < 2 {
		return nil, 0, &ProtocolError{Step: step, Msg: "the response has no status word"}
	}
	sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	return resp[:len(resp)-2], sw, nil
}

// ValidAID reports whether aidHex is 5..16 bytes of hex (ISO 7816-5).
func ValidAID(aidHex string) bool {
	aid, err := hex.DecodeString(aidHex)
	return err == nil && len(aid) >= 5 && len(aid) <= 16
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

// Personalization is the part of GET_PERSONALIZATION (159 bytes) sign-in
// needs: the state byte and the flags. The program id, currency, issuer key
// and certificate that follow are the card program's business, not a
// wallet's, and are not kept.
type Personalization struct {
	State byte
	Flags byte
}

// Personalized, Terminated, PinProvisioned, ProvisioningEnforced and
// AdvertisesStellarKey read the flag bits (and the state byte, for
// termination).
func (p *Personalization) Personalized() bool {
	return p.State == StatePersonalized && p.Flags&FlagPersonalized != 0
}
func (p *Personalization) Terminated() bool {
	return p.State == StateTerminated || p.Flags&FlagTerminated != 0
}
func (p *Personalization) PinProvisioned() bool { return p.Flags&FlagPinProvisioned != 0 }
func (p *Personalization) ProvisioningEnforced() bool {
	return p.Flags&FlagProvisioningEnforce != 0
}
func (p *Personalization) AdvertisesStellarKey() bool { return p.Flags&FlagStellarKey != 0 }

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
	return &Personalization{State: d[0], Flags: d[1]}, nil
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
	out := []string{}
	for _, n := range names {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
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

// StellarKey is GET_STELLAR_KEY (applet 0.3): the card's Ed25519 key, which
// signs SEP-10 challenges and nothing else.
type StellarKey struct {
	Engine    byte
	PublicKey []byte // 32 bytes
	// Bound: both cross-signature slots are filled, which the card does only
	// once PERSONALIZE has committed (they bind the key to the card's P-256
	// key and account; the card program verifies them, a wallet need not).
	Bound bool
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

// Address is the key as a Stellar account id (G...).
func (k *StellarKey) Address() string {
	addr, err := strkey.Encode(strkey.VersionByteAccountID, k.PublicKey)
	if err != nil {
		// GetStellarKey only builds 32-byte keys, which always encode.
		panic(fmt.Sprintf("encode the card's Stellar key: %v", err))
	}
	return addr
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
	return &StellarKey{
		Engine:    d[0],
		PublicKey: append([]byte(nil), d[1:33]...),
		Bound:     !allZero(d[33:105]) && !allZero(d[105:169]),
	}, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
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
	clear(digits)
	return err
}

// SignSep10 has the card sign a SEP-10 challenge transaction with its
// Stellar key (SIGN_SEP10), in the card SDK's exact parts: BEGIN carries the
// network id and as much of the transaction as fits beside it but never the
// last byte, CONTINUE parts of 255 bytes, and FINISH at least one byte. The
// card parses the transaction itself, refuses anything but a SEP-10
// challenge for its own key, and signs
// SHA-256(networkID ‖ ENVELOPE_TYPE_TX ‖ tx). Returns the 64-byte signature.
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
