package card

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Issuance and cardholder-PIN commands (impala-card/sdk ImpalaSDK.kt:
// setSeed, personalize, provisionMasterPIN / provisionUserPIN,
// rotateScp03Keys, verifyMasterPin, updateUserPin, changeUserPin,
// setSignInPinRequired) with the byte layouts the applet checks
// (ImpalaApplet.java). PINs travel as digit values 0..9, never ASCII.

const (
	insInitialize      byte = 0x2C
	insUpdateUserPIN   byte = 0x19
	insSetSignInPolicy byte = 0x3A
	insChangeUserPIN   byte = 0x3B

	insProvisionPIN byte = 0x70
	insAppletUpdate byte = 0x71
	insPersonalize  byte = 0x72

	p2MasterPIN byte = 0x81

	p1PersonalizeIdentity    byte = 0x01
	p1PersonalizeIssuerKey   byte = 0x02
	p1PersonalizeCertificate byte = 0x03
)

// Initialize sends INITIALIZE with a 4-byte host seed read from rnd: the card
// generates its card id, its P-256 key and (applet 0.3+) its Stellar key.
// 0x6686: already initialized.
func (c *Card) Initialize(rnd io.Reader) error {
	seed := make([]byte, 4)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return fmt.Errorf("draw the INITIALIZE seed: %w", err)
	}
	_, err := c.exchange("initialize the card", "INITIALIZE", 0, insInitialize, 0, 0, seed)
	return err
}

// digits maps a PIN string of exactly n ASCII digits to digit values.
func digits(pin string, n int, what string) ([]byte, error) {
	if len(pin) != n {
		return nil, fmt.Errorf("the %s is %d digits", what, n)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		r := pin[i]
		if r < '0' || r > '9' {
			clear(out)
			return nil, fmt.Errorf("the %s is %d digits", what, n)
		}
		out[i] = r - '0'
	}
	return out, nil
}

// ValidUserPIN reports whether pin is a settable user PIN: 4 digits, not
// 0000 (the PIN-less request marker the card refuses).
func ValidUserPIN(pin string) bool {
	d, err := digits(pin, 4, "user PIN")
	if err != nil {
		return false
	}
	defer clear(d)
	return pin != "0000"
}

// ValidMasterPIN reports whether pin is 8 digits.
func ValidMasterPIN(pin string) bool {
	d, err := digits(pin, 8, "master PIN")
	clear(d)
	return err == nil
}

// RotateKeys replaces the card's static SCP03 keys (APPLET_UPDATE sequence
// 0x0001: 00 01 00 30 ‖ ENC ‖ MAC ‖ DEK) over an open channel. 0x6684: a GP
// default key as a target.
func (s *SecureChannel) RotateKeys(keys *SCP03Keys) error {
	data := make([]byte, 0, 52)
	data = append(data, 0x00, 0x01, 0x00, 0x30)
	data = append(data, keys.ENC[:]...)
	data = append(data, keys.MAC[:]...)
	data = append(data, keys.DEK[:]...)
	defer clear(data)
	_, err := s.Transmit("rotate the SCP03 keys", "APPLET_UPDATE seq 0x0001", insAppletUpdate, 0, 0, data)
	return err
}

// IdentityPart builds PERSONALIZE part A: account(16) ‖ currency tag(4) ‖
// programId(16) ‖ initialReceiveCounter (4, big-endian, MSB clear).
func IdentityPart(account, currency, programID []byte, initialCounter uint32) ([]byte, error) {
	switch {
	case len(account) != 16 || allZero(account):
		return nil, errors.New("the account must be a non-nil 16-byte UUID")
	case len(currency) != 4 || allZero(currency):
		return nil, errors.New("the currency tag must be 4 non-zero bytes")
	case len(programID) != 16 || allZero(programID):
		return nil, errors.New("the program id must be 16 non-zero bytes")
	case initialCounter&0x80000000 != 0:
		return nil, errors.New("the initial receive counter must be below 2^31")
	}
	out := make([]byte, 40)
	copy(out[0:16], account)
	copy(out[16:20], currency)
	copy(out[20:36], programID)
	binary.BigEndian.PutUint32(out[36:40], initialCounter)
	return out, nil
}

// Personalize sends PERSONALIZE part A (identity), part B (the issuer key;
// nil for a card bound to its program at install) and part C (the
// certificate DER), each over the channel.
func (s *SecureChannel) Personalize(identity, issuerPub, certDER []byte) error {
	const step = "personalize the card"
	if _, err := s.Transmit(step, "PERSONALIZE P1=01 (identity)", insPersonalize, p1PersonalizeIdentity, 0, identity); err != nil {
		return err
	}
	if issuerPub != nil {
		if _, err := s.Transmit(step, "PERSONALIZE P1=02 (issuer key)", insPersonalize, p1PersonalizeIssuerKey, 0, issuerPub); err != nil {
			return err
		}
	}
	_, err := s.Transmit(step, "PERSONALIZE P1=03 (certificate)", insPersonalize, p1PersonalizeCertificate, 0, certDER)
	return err
}

// ProvisionPINs sends PROVISION_PIN for the master PIN (81 08 ‖ 8 digits)
// then the user PIN (82 04 ‖ 4 digits). The user PIN lifts the ENFORCE gate.
func (s *SecureChannel) ProvisionPINs(masterPIN, userPIN string) error {
	const step = "provision the PINs"
	m, err := digits(masterPIN, 8, "master PIN")
	if err != nil {
		return err
	}
	defer clear(m)
	u, err := digits(userPIN, 4, "user PIN")
	if err != nil {
		return err
	}
	defer clear(u)
	md := append([]byte{p2MasterPIN, 8}, m...)
	defer clear(md)
	if _, err := s.Transmit(step, "PROVISION_PIN master", insProvisionPIN, 0, 0, md); err != nil {
		return err
	}
	ud := append([]byte{p2UserPIN, 4}, u...)
	defer clear(ud)
	_, err = s.Transmit(step, "PROVISION_PIN user", insProvisionPIN, 0, 0, ud)
	return err
}

// VerifyMasterPIN sends VERIFY_PIN (P2 0x81) with 8 digit values. The master
// PIN has 10 tries and nothing unblocks it: 0x69Cn names the tries left.
func (c *Card) VerifyMasterPIN(pin string) error {
	d, err := digits(pin, 8, "master PIN")
	if err != nil {
		return err
	}
	defer clear(d)
	_, err = c.exchange("verify the master PIN", "VERIFY_PIN master", 0, insVerifyPIN, 0, p2MasterPIN, d)
	return err
}

// UpdateUserPIN sets a new user PIN with the master PIN verified in this
// session (UPDATE_USER_PIN; 0x6985 otherwise). It resets the try counter, so
// it also unblocks a blocked PIN.
func (c *Card) UpdateUserPIN(pin string) error {
	d, err := digits(pin, 4, "user PIN")
	if err != nil {
		return err
	}
	defer clear(d)
	_, err = c.exchange("set the new user PIN", "UPDATE_USER_PIN", 0, insUpdateUserPIN, 0, p2UserPIN, d)
	return err
}

// ChangeUserPIN sets a new user PIN with the current one verified in this
// session (CHANGE_USER_PIN, applet 0.4). Afterwards the session is "not
// verified".
func (c *Card) ChangeUserPIN(pin string) error {
	d, err := digits(pin, 4, "user PIN")
	if err != nil {
		return err
	}
	defer clear(d)
	_, err = c.exchange("change the user PIN", "CHANGE_USER_PIN", 0, insChangeUserPIN, 0, 0, d)
	return err
}

// SetSignInPolicy turns the sign-in PIN requirement on or off
// (SET_SIGN_IN_POLICY, no data; the user PIN must be verified first).
func (c *Card) SetSignInPolicy(required bool) error {
	p1 := byte(0x00)
	if required {
		p1 = 0x01
	}
	_, err := c.exchange("set the sign-in PIN policy", fmt.Sprintf("SET_SIGN_IN_POLICY P1=%02X", p1),
		0, insSetSignInPolicy, p1, 0, nil)
	return err
}

// ── protocol messages ─────────────────────────────────────────────────

// CurrencyTag maps a bridge currency code to the card's 4-byte tag.
func CurrencyTag(code string) ([]byte, bool) {
	switch code {
	case "XLM":
		return []byte{0x58, 0x4C, 0x4D, 0x00}, true
	case "USDC":
		return []byte("USDC"), true
	case "USDT0":
		return []byte("UST0"), true
	}
	return nil, false
}

// CurrencyCode maps a card tag back to the bridge code; an unknown tag is
// shown as its printable text.
func CurrencyCode(tag []byte) string {
	for _, code := range []string{"XLM", "USDC", "USDT0"} {
		if t, _ := CurrencyTag(code); string(t) == string(tag) {
			return code
		}
	}
	end := len(tag)
	for end > 0 && tag[end-1] == 0 {
		end--
	}
	return string(tag[:end])
}

// CertMessage is the 114-byte CERT message the issuer signs:
// "IMPALA-CERT:" ‖ 0x01 ‖ programId(16) ‖ account(16) ‖ currency(4) ‖
// cardPub(65).
func CertMessage(programID, account, currency, cardPub []byte) ([]byte, error) {
	if len(programID) != 16 || len(account) != 16 || len(currency) != 4 || len(cardPub) != 65 || cardPub[0] != 0x04 {
		return nil, errors.New("CERT message: program id 16, account 16, currency 4, card key 65 bytes")
	}
	out := make([]byte, 0, 114)
	out = append(out, "IMPALA-CERT:"...)
	out = append(out, 0x01)
	out = append(out, programID...)
	out = append(out, account...)
	out = append(out, currency...)
	return append(out, cardPub...), nil
}

// CertID is SHA-256 of the CERT message: the bridge's registry key of a card
// certificate.
func CertID(programID, account, currency, cardPub []byte) ([]byte, error) {
	m, err := CertMessage(programID, account, currency, cardPub)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(m)
	return h[:], nil
}

// BindingMessage is SKEY message 0x01 (77 bytes), signed by the card's P-256
// key: "IMPALA-SKEY:" ‖ 0x01 ‖ account ‖ cardId ‖ stellarPub(32).
func BindingMessage(account, cardID, stellarPub []byte) []byte {
	out := append([]byte("IMPALA-SKEY:"), 0x01)
	out = append(out, account...)
	out = append(out, cardID...)
	return append(out, stellarPub...)
}

// ProofMessage is SKEY message 0x02 (110 bytes), signed by the card's
// Stellar key: "IMPALA-SKEY:" ‖ 0x02 ‖ account ‖ cardId ‖ ecPub(65).
func ProofMessage(account, cardID, ecPub []byte) []byte {
	out := append([]byte("IMPALA-SKEY:"), 0x02)
	out = append(out, account...)
	out = append(out, cardID...)
	return append(out, ecPub...)
}
