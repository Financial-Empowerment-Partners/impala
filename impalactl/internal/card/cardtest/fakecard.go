// Package cardtest is an in-process fake Impala card for tests: a TCP server
// speaking the simulator framing (2-byte big-endian length + APDU, and the
// same for data ‖ SW) and the applet commands impalactl uses, with real
// crypto (P-256 ECDSA for SIGN_AUTH and certificates, Ed25519 for
// SIGN_SEP10, AES for the SCP03 card side) and the card's own acceptance
// rules and status words, written from the applet (impala-card applet
// ImpalaApplet.java, SCP03.java, docs/sep10-card-keys.md §3.3), never from
// impalactl's host code: it shares no code with internal/card. It is not the
// applet; the real one runs on jcardsim (demo/scripts/simulator.sh), and the
// recorded sessions in internal/card/testdata pin the host against it. Test
// support only.
package cardtest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// Persistent GET_PERSONALIZATION flag bits the fake stores in Card.Flags.
// FlagPinProvisioned and FlagStellarKey are derived (from PIN and Stellar),
// and the state byte from the flags.
const (
	FlagInitialized  byte = 0x01
	FlagProgramBound byte = 0x02
	FlagPersonalized byte = 0x04
	FlagDefaultKeys  byte = 0x08
	FlagEnforce      byte = 0x20
	FlagTerminated   byte = 0x40
)

// DefaultMasterPIN is the master PIN the applet installs with.
const DefaultMasterPIN = "14117298"

// GPDefaultKey is the GlobalPlatform test key 40 41 .. 4F.
var GPDefaultKey = []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

// Card is the fake card's persistent state. Configure it before Start; read
// it afterwards through With (the card serves on its own goroutines).
type Card struct {
	AID          []byte
	Major, Minor uint16
	Flags        byte
	Account      [16]byte
	CardID       [16]byte
	ProgramID    [16]byte
	Currency     [4]byte
	IssuerPub    []byte // 65 bytes once bound to a program (install or PERSONALIZE)
	Cert         []byte // the certificate DER once personalized
	Counter      uint32 // the receive-counter floor PERSONALIZE set
	EC           *ecdsa.PrivateKey
	Stellar      ed25519.PrivateKey // nil: no Stellar key
	// NoStellarEngine: INITIALIZE creates no Stellar key (a build or a
	// platform without an Ed25519 engine: a legacy card).
	NoStellarEngine bool
	// PIN is the provisioned user PIN ("" = none provisioned).
	PIN string
	// MasterPIN is the 8-digit master PIN (DefaultMasterPIN until provisioned).
	MasterPIN string
	// RequirePIN sets the sign-in PIN policy; FixedPIN is the install flag
	// that keeps it on for good.
	RequirePIN, FixedPIN bool
	// StaticKeys is the SCP03 key set ENC ‖ MAC ‖ DEK.
	StaticKeys [48]byte
	// Force answers a command with a status word: key INS<<8 | P1.
	Force map[uint16]uint16

	mu          sync.Mutex
	tries       int
	masterTries int
	// unprovisioned is the user PIN value before one is provisioned (the
	// applet installs 1111, which UPDATE_USER_PIN can replace).
	unprovisioned string
	log           []string
	parts         []int // SIGN_SEP10 data lengths, in order
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ec
}

// New returns a personalized applet 0.4 card with fresh keys, a Stellar key,
// custom SCP03 keys and the provisioned PIN 1234.
func New(t *testing.T) *Card {
	t.Helper()
	_, st, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &Card{
		AID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2},
		Major: 0, Minor: 4,
		Flags:         FlagInitialized | FlagProgramBound | FlagPersonalized,
		EC:            newKey(t),
		Stellar:       st,
		PIN:           "1234",
		MasterPIN:     DefaultMasterPIN,
		tries:         5,
		masterTries:   10,
		unprovisioned: "1111",
		Force:         map[uint16]uint16{},
	}
	copy(c.Account[:], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(c.CardID[:], []byte{0xea, 0x94, 0xfa, 0x5b, 0x0f, 0x6b, 0x2a, 0xbc, 0x16, 0x26, 0xbc, 0x50, 0xc0, 0xbd, 0x5e, 0x17})
	copy(c.Currency[:], "XLM")
	_, _ = rand.Read(c.StaticKeys[:])
	return c
}

// NewBlank returns a factory-installed applet 0.4 card: blank (INITIALIZE
// generates its card id and keys), on the GP default SCP03 keys, under
// ENFORCE, not bound to a program, no PIN provisioned. Clear FlagEnforce for
// a card installed without it; see InstallKeys and BindProgram for the other
// install options.
func NewBlank(t *testing.T) *Card {
	t.Helper()
	c := &Card{
		AID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2},
		Major: 0, Minor: 4,
		Flags:         FlagDefaultKeys | FlagEnforce,
		MasterPIN:     DefaultMasterPIN,
		tries:         5,
		masterTries:   10,
		unprovisioned: "1111",
		Force:         map[uint16]uint16{},
	}
	_, _ = rand.Read(c.CardID[:])
	for i := 0; i < 3; i++ {
		copy(c.StaticKeys[16*i:], GPDefaultKey)
	}
	return c
}

// InstallKeys installs the card with custom SCP03 keys (the KEYS install
// flag) or sets them as if APPLET_UPDATE had rotated them.
func (c *Card) InstallKeys(keys [48]byte) {
	c.StaticKeys = keys
	c.Flags &^= FlagDefaultKeys
}

// BindProgram binds the card to a program at install (the PROGRAM install
// flag, which needs custom keys).
func (c *Card) BindProgram(programID [16]byte, issuerPub []byte) {
	c.ProgramID = programID
	c.IssuerPub = append([]byte(nil), issuerPub...)
	c.Flags |= FlagProgramBound
}

// With runs f with the card's state locked: the way to read or change the
// card while it serves.
func (c *Card) With(f func(c *Card)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

// ECPub is the card's 65-byte uncompressed P-256 key (nil before INITIALIZE).
func (c *Card) ECPub() []byte {
	if c.EC == nil {
		return nil
	}
	k, _ := c.EC.PublicKey.ECDH()
	return k.Bytes()
}

// StellarPub is the card's Ed25519 public key (nil without one).
func (c *Card) StellarPub() []byte {
	if c.Stellar == nil {
		return nil
	}
	return c.Stellar.Public().(ed25519.PublicKey)
}

// Log returns the commands the card received, as "NAME P1=xx" strings.
func (c *Card) Log() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.log...)
}

// Sep10Parts returns the data length of every SIGN_SEP10 part received.
func (c *Card) Sep10Parts() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.parts...)
}

// Received reports whether a command name appears in the log.
func (c *Card) Received(name string) bool {
	for _, l := range c.Log() {
		if strings.HasPrefix(l, name) {
			return true
		}
	}
	return false
}

// Count is how many logged commands start with name.
func (c *Card) Count(name string) int {
	n := 0
	for _, l := range c.Log() {
		if strings.HasPrefix(l, name) {
			n++
		}
	}
	return n
}

// TriesLeft is the user PIN try counter.
func (c *Card) TriesLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tries
}

// MasterTriesLeft is the master PIN try counter.
func (c *Card) MasterTriesLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.masterTries
}

// SetTries sets the user PIN try counter (0 blocks the PIN).
func (c *Card) SetTries(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tries = n
}

// Start serves the card on 127.0.0.1 and returns its "tcp:HOST:PORT" spec.
func (c *Card) Start(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	return "tcp:" + ln.Addr().String()
}

// session is per connection: selection, PIN state, the SCP03 session and the
// PERSONALIZE / SEP-10 stages are transient (CLEAR_ON_DESELECT, and the
// applet's deselect() resets the PINs and the channel).
type session struct {
	selected       bool
	pinVerified    bool
	masterVerified bool
	stage          []byte // SIGN_SEP10: networkId ‖ tx so far; nil = nothing staged

	// SCP03 (SCP03.java)
	chState               byte // 0 none, 1 initialized, 2 authenticated
	level                 byte
	senc, smac, srmac     []byte
	chain, counter        [16]byte
	hostChal, cardChal    []byte
	secured               bool
	stagedA, stagedB      bool
	identity, stagedIssue []byte
}

func (s *session) resetChannel() {
	s.chState, s.level, s.secured = 0, 0, false
	s.chain, s.counter = [16]byte{}, [16]byte{}
}

func (c *Card) serve(conn net.Conn) {
	defer conn.Close()
	s := &session{}
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		apdu := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(conn, apdu); err != nil {
			return
		}
		resp := c.process(s, apdu)
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func sw(v uint16, data ...[]byte) []byte {
	var out []byte
	for _, d := range data {
		out = append(out, d...)
	}
	return append(out, byte(v>>8), byte(v))
}

var names = map[byte]string{
	0xA4: "SELECT", 0x64: "GET_VERSION", 0x34: "GET_PERSONALIZATION", 0x1E: "GET_USER_DATA",
	0x24: "GET_EC_PUB_KEY", 0x39: "GET_USER_VERIFICATION", 0x37: "GET_STELLAR_KEY",
	0x18: "VERIFY_PIN", 0x25: "SIGN_AUTH", 0x38: "SIGN_SEP10",
	0x2C: "INITIALIZE", 0x19: "UPDATE_USER_PIN", 0x3A: "SET_SIGN_IN_POLICY", 0x3B: "CHANGE_USER_PIN",
	0x50: "INITIALIZE_UPDATE", 0x82: "EXTERNAL_AUTHENTICATE",
	0x70: "PROVISION_PIN", 0x71: "APPLET_UPDATE", 0x72: "PERSONALIZE",
}

func (c *Card) has(f byte) bool { return c.Flags&f != 0 }

func (c *Card) state() byte {
	switch {
	case c.has(FlagTerminated):
		return 0xFF
	case c.has(FlagPersonalized):
		return 0x02
	case c.has(FlagInitialized):
		return 0x01
	}
	return 0x00
}

func (c *Card) process(s *session, apdu []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(apdu) < 4 {
		return sw(0x6700)
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 4 {
		lc := int(apdu[4])
		if len(apdu) < 5+lc {
			return sw(0x6700)
		}
		data = apdu[5 : 5+lc]
	}
	name := names[ins]
	if name == "" {
		name = fmt.Sprintf("INS_%02X", ins)
	}
	c.log = append(c.log, fmt.Sprintf("%s P1=%02X", name, p1))

	// The stage survives only the next accepted BEGIN/CONTINUE part.
	staged := s.stage
	s.stage = nil
	s.secured = false

	if v, ok := c.Force[uint16(ins)<<8|uint16(p1)]; ok {
		return sw(v)
	}
	switch cla {
	case 0x00:
		if ins == 0xA4 {
			if p1 == 0x04 && bytes.Equal(data, c.AID) {
				*s = session{selected: true}
				return sw(0x9000)
			}
			return sw(0x6A82)
		}
	case 0x80, 0x84:
	default:
		return sw(0x6E00)
	}
	if !s.selected {
		return sw(0x6D00)
	}
	if cla == 0x80 {
		switch ins {
		case 0x50:
			s.stagedA, s.stagedB = false, false
			return c.initializeUpdate(s, data)
		case 0x82:
			return c.externalAuthenticate(s, p1, data)
		}
		return sw(0x6D00)
	}
	if cla == 0x84 {
		if ins == 0x82 {
			return c.externalAuthenticate(s, p1, data)
		}
		payload, v := c.unwrap(s, apdu[:4], data)
		if v != 0x9000 {
			return sw(v)
		}
		data = payload
		switch ins {
		case 0x70, 0x71, 0x72:
			if c.has(FlagTerminated) {
				return sw(0x6687)
			}
			switch ins {
			case 0x70:
				return sw(c.provisionPIN(data))
			case 0x71:
				return sw(c.appletUpdate(data))
			}
			return sw(c.personalize(s, p1, p2, data))
		case 0x34, 0x37, 0x38:
			return sw(0x6E00) // their payloads do not fit the wrap
		}
	}
	resp := c.standard(s, ins, p1, p2, data, staged)
	if s.secured && len(resp) > 2 && resp[len(resp)-2] == 0x90 && resp[len(resp)-1] == 0x00 {
		return append(c.wrap(s, resp[:len(resp)-2]), 0x90, 0x00)
	}
	return resp
}

// standard is the CLA 0x00 (or unwrapped CLA 0x84) dispatch.
func (c *Card) standard(s *session, ins, p1, p2 byte, data, staged []byte) []byte {
	v04 := c.Major > 0 || c.Minor >= 4
	v03 := c.Major > 0 || c.Minor >= 3
	terminated := c.has(FlagTerminated)
	switch ins {
	case 0x64:
		d := make([]byte, 10)
		binary.BigEndian.PutUint16(d[0:], c.Major)
		binary.BigEndian.PutUint16(d[2:], c.Minor)
		copy(d[6:], []byte{0xde, 0xad, 0xbe, 0xef})
		return sw(0x9000, d)
	case 0x34:
		d := make([]byte, 159)
		d[0] = c.state()
		d[1] = c.Flags
		if c.PIN != "" {
			d[1] |= 0x10
		}
		if c.Stellar != nil {
			d[1] |= 0x80
		}
		copy(d[2:18], c.ProgramID[:])
		copy(d[18:22], c.Currency[:])
		copy(d[22:87], c.IssuerPub)
		copy(d[87:159], c.Cert)
		return sw(0x9000, d)
	case 0x1E:
		return sw(0x9000, c.Account[:], c.CardID[:], []byte("Test Holder"))
	case 0x24:
		if c.EC == nil {
			return sw(0x6230)
		}
		return sw(0x9000, c.ECPub())
	case 0x2C:
		if terminated {
			return sw(0x6687)
		}
		if c.has(FlagInitialized) {
			return sw(0x6686)
		}
		_, _ = rand.Read(c.CardID[:])
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return sw(0x6683)
		}
		c.EC = ec
		if !c.NoStellarEngine && (c.Major > 0 || c.Minor >= 3) {
			_, c.Stellar, _ = ed25519.GenerateKey(rand.Reader)
		}
		c.Flags |= FlagInitialized
		return sw(0x9000)
	case 0x39:
		if !v04 {
			return sw(0x6D00)
		}
		policy := byte(0)
		if c.RequirePIN {
			policy |= 0x01
		}
		if c.FixedPIN {
			policy |= 0x02
		}
		if c.PIN != "" {
			policy |= 0x04
		}
		session := byte(0)
		if c.PIN != "" && s.pinVerified {
			session = 1
		}
		return sw(0x9000, []byte{0x01, policy, byte(c.tries), session})
	case 0x37:
		if !v03 || c.Stellar == nil {
			if !v03 {
				return sw(0x6D00)
			}
			return sw(0x623C)
		}
		d := make([]byte, 169)
		d[0] = 0x01
		copy(d[1:33], c.StellarPub())
		// The two slots mean something only once PERSONALIZE committed.
		if c.has(FlagPersonalized) {
			binding := append(append(append([]byte("IMPALA-SKEY:\x01"), c.Account[:]...), c.CardID[:]...), c.StellarPub()...)
			h := sha256.Sum256(binding)
			bsig, _ := ecdsa.SignASN1(rand.Reader, c.EC, h[:])
			copy(d[33:105], bsig)
			proof := append(append(append([]byte("IMPALA-SKEY:\x02"), c.Account[:]...), c.CardID[:]...), c.ECPub()...)
			copy(d[105:169], ed25519.Sign(c.Stellar, proof))
		}
		return sw(0x9000, d)
	case 0x18:
		if terminated {
			return sw(0x6687)
		}
		return sw(c.verifyPIN(s, p2, data))
	case 0x19:
		if terminated {
			return sw(0x6687)
		}
		if !s.masterVerified {
			return sw(0x6985)
		}
		if len(data) != 4 {
			return sw(0x6700)
		}
		if bytes.Equal(data, []byte{0, 0, 0, 0}) {
			return sw(0x6691)
		}
		c.setUserPIN(s, data)
		return sw(0x9000)
	case 0x3A:
		if terminated {
			return sw(0x6687)
		}
		if p2 != 0 || (p1 != 0x00 && p1 != 0x01) {
			return sw(0x6A86)
		}
		if len(data) != 0 {
			return sw(0x6700)
		}
		if v := c.userPinVerified(s); v != 0x9000 {
			return sw(v)
		}
		if p1 == 0x00 && c.FixedPIN {
			return sw(0x6985)
		}
		c.RequirePIN = p1 == 0x01
		return sw(0x9000)
	case 0x3B:
		if terminated {
			return sw(0x6687)
		}
		if p1 != 0 || p2 != 0 {
			return sw(0x6A86)
		}
		if len(data) != 4 {
			return sw(0x6700)
		}
		if v := c.userPinVerified(s); v != 0x9000 {
			return sw(v)
		}
		for _, d := range data {
			if d > 9 {
				return sw(0x6691)
			}
		}
		if bytes.Equal(data, []byte{0, 0, 0, 0}) {
			return sw(0x6691)
		}
		c.setUserPIN(s, data)
		return sw(0x9000)
	case 0x25:
		if terminated {
			return sw(0x6687)
		}
		if c.has(FlagEnforce) && c.PIN == "" {
			return sw(0x6985)
		}
		if !c.has(FlagPersonalized) {
			return sw(0x6234)
		}
		if len(data) < 8 || len(data) > 64 {
			return sw(0x6700)
		}
		tag := "IMPALA-AUTH:"
		if p1 == 0x01 && v04 {
			if c.PIN == "" {
				return sw(0x6985)
			}
			if !s.pinVerified {
				return sw(0x6690)
			}
			tag = "IMPALA-APIN:"
		} else if c.RequirePIN && !s.pinVerified {
			return sw(0x6690)
		}
		msg := append(append([]byte(tag), c.Account[:]...), data...)
		h := sha256.Sum256(msg)
		sig, _ := ecdsa.SignASN1(rand.Reader, c.EC, h[:])
		return sw(0x9000, sig)
	case 0x38:
		c.parts = append(c.parts, len(data))
		if c.Stellar == nil {
			return sw(0x623C)
		}
		if c.has(FlagEnforce) && c.PIN == "" {
			return sw(0x6985) // the provisioning gate: no signing until a user PIN is provisioned
		}
		if !c.has(FlagPersonalized) {
			return sw(0x6234)
		}
		if c.RequirePIN && !s.pinVerified {
			return sw(0x6690)
		}
		if p2 != 0 {
			return sw(0x6A86)
		}
		switch p1 {
		case 0x00:
			if len(data) < 33 {
				return sw(0x6700)
			}
			s.stage = append([]byte(nil), data...)
			return sw(0x9000)
		case 0x01, 0x02:
			if staged == nil {
				return sw(0x6985)
			}
			stage := append(staged, data...)
			if len(stage)-32 > 640 {
				return sw(0x6700)
			}
			if p1 == 0x01 {
				s.stage = stage
				return sw(0x9000)
			}
			nid, tx := stage[:32], stage[32:]
			if v := validateSep10(tx, c.StellarPub()); v != 0x9000 {
				return sw(v)
			}
			hh := sha256.New()
			hh.Write(nid)
			hh.Write([]byte{0, 0, 0, 2})
			hh.Write(tx)
			return sw(0x9000, ed25519.Sign(c.Stellar, hh.Sum(nil)))
		}
		return sw(0x6A86)
	}
	return sw(0x6D00)
}

// ── PINs (processVerifyPIN, OwnerPIN) ─────────────────────────────────

func digitsOf(pin string) []byte {
	out := make([]byte, len(pin))
	for i := range pin {
		out[i] = pin[i] - '0'
	}
	return out
}

func (c *Card) userValue() string {
	if c.PIN != "" {
		return c.PIN
	}
	return c.unprovisioned
}

// userPinVerified is failIfUserPinNotVerified.
func (c *Card) userPinVerified(s *session) uint16 {
	if c.PIN == "" {
		return 0x6985
	}
	if !s.pinVerified {
		return 0x6690
	}
	return 0x9000
}

// setUserPIN is OwnerPIN.update: a new value, the try counter at its limit,
// and the session not verified.
func (c *Card) setUserPIN(s *session, d []byte) {
	pin := make([]byte, len(d))
	for i := range d {
		pin[i] = '0' + d[i]
	}
	if c.PIN != "" {
		c.PIN = string(pin)
	} else {
		c.unprovisioned = string(pin)
	}
	c.tries = 5
	s.pinVerified = false
}

func (c *Card) verifyPIN(s *session, p2 byte, data []byte) uint16 {
	switch p2 {
	case 0x81:
		if c.masterTries == 0 {
			s.masterVerified = false
			return 0x69C0
		}
		if !bytes.Equal(data, digitsOf(c.MasterPIN)) {
			c.masterTries--
			s.masterVerified = false
			return 0x69C0 | uint16(c.masterTries)
		}
		c.masterTries = 10
		s.masterVerified = true
		return 0x9000
	case 0x82:
		if c.tries == 0 {
			s.pinVerified = false
			return 0x69C0
		}
		if !bytes.Equal(data, digitsOf(c.userValue())) {
			c.tries--
			s.pinVerified = false
			return 0x69C0 | uint16(c.tries)
		}
		c.tries = 5
		s.pinVerified = true
		return 0x9000
	}
	return 0x6A86
}

// ── provisioning (processProvisionPIN, processAppletUpdate, processPersonalize) ──

func (c *Card) provisionPIN(data []byte) uint16 {
	if c.has(FlagEnforce) && c.has(FlagDefaultKeys) {
		return 0x6236
	}
	if len(data) < 3 {
		return 0x6700
	}
	typ, n := data[0], int(data[1])
	if 2+n > len(data) {
		return 0x6700
	}
	pin := data[2 : 2+n]
	text := make([]byte, n)
	for i, d := range pin {
		text[i] = '0' + d
	}
	switch typ {
	case 0x81:
		if n != 8 {
			return 0x6700
		}
		c.MasterPIN = string(text)
		c.masterTries = 10
	case 0x82:
		if n != 4 {
			return 0x6700
		}
		if bytes.Equal(pin, []byte{0, 0, 0, 0}) {
			return 0x6691
		}
		c.PIN = string(text)
		c.tries = 5
	default:
		return 0x6A86
	}
	return 0x9000
}

func (c *Card) appletUpdate(data []byte) uint16 {
	if len(data) < 4 {
		return 0x6700
	}
	seq := binary.BigEndian.Uint16(data[0:2])
	n := int(binary.BigEndian.Uint16(data[2:4]))
	if 4+n > len(data) {
		return 0x6700
	}
	if seq == 0x0001 && n == 48 {
		keys := data[4:52]
		for i := 0; i < 3; i++ {
			if bytes.Equal(keys[16*i:16*i+16], GPDefaultKey) {
				return 0x6684
			}
		}
		copy(c.StaticKeys[:], keys)
		c.Flags &^= FlagDefaultKeys
		return 0x9000
	}
	return 0x6A86
}

func (c *Card) personalize(s *session, p1, p2 byte, data []byte) uint16 {
	if s.level&0x02 == 0 {
		return 0x6982
	}
	if !c.has(FlagInitialized) {
		return 0x6230
	}
	if c.has(FlagPersonalized) {
		return 0x6235
	}
	if c.has(FlagDefaultKeys) {
		return 0x6236
	}
	if p2 != 0 {
		return 0x6A86
	}
	v := c.personalizePart(s, p1, data)
	if v != 0x9000 {
		s.stagedA, s.stagedB = false, false // any failure restarts from part A
	}
	return v
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func (c *Card) personalizePart(s *session, p1 byte, data []byte) uint16 {
	bound := c.has(FlagProgramBound)
	switch p1 {
	case 0x01:
		if len(data) != 40 {
			return 0x6700
		}
		if allZero(data[0:16]) || allZero(data[16:20]) || allZero(data[20:36]) || data[36]&0x80 != 0 {
			return 0x6A80
		}
		if bound && !bytes.Equal(data[20:36], c.ProgramID[:]) {
			return 0x623B
		}
		s.identity = append([]byte(nil), data...)
		s.stagedA, s.stagedB = true, false
		return 0x9000
	case 0x02:
		if bound {
			return 0x623B
		}
		if !s.stagedA {
			return 0x6237
		}
		if len(data) != 65 {
			return 0x6700
		}
		if data[0] != 0x04 {
			return 0x6A80
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), data); err != nil {
			return 0x6683
		}
		s.stagedIssue = append([]byte(nil), data...)
		s.stagedB = true
		return 0x9000
	case 0x03:
		if !s.stagedA || (!bound && !s.stagedB) {
			return 0x6237
		}
		if len(data) < 8 || len(data) > 72 {
			return 0x6700
		}
		if data[0] != 0x30 || int(data[1])+2 != len(data) {
			return 0x6A80
		}
		id := s.identity
		msg := append([]byte("IMPALA-CERT:\x01"), id[20:36]...)
		msg = append(msg, id[0:16]...)
		msg = append(msg, id[16:20]...)
		msg = append(msg, c.ECPub()...)
		issuer := c.IssuerPub
		if !bound {
			issuer = s.stagedIssue
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), issuer)
		h := sha256.Sum256(msg)
		if err != nil || !ecdsa.VerifyASN1(key, h[:], data) {
			return 0x6677
		}
		copy(c.Account[:], id[0:16])
		copy(c.Currency[:], id[16:20])
		copy(c.ProgramID[:], id[20:36])
		c.Counter = binary.BigEndian.Uint32(id[36:40])
		if !bound {
			c.IssuerPub = s.stagedIssue
			c.Flags |= FlagProgramBound
		}
		c.Cert = append([]byte(nil), data...)
		c.Flags |= FlagPersonalized
		s.stagedA, s.stagedB = false, false
		return 0x9000
	}
	return 0x6A86
}

// ── SCP03, the card side (SCP03.java) ─────────────────────────────────

// cmac is AES-CMAC written for the card side: CBC-MAC over the message with
// the last block masked by K1 (complete) or padded and masked by K2.
func cmac(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	dbl := func(b []byte) []byte {
		out := make([]byte, 16)
		for i := 0; i < 16; i++ {
			out[i] = b[i] << 1
			if i < 15 {
				out[i] |= b[i+1] >> 7
			}
		}
		if b[0]&0x80 != 0 {
			out[15] ^= 0x87
		}
		return out
	}
	l := make([]byte, 16)
	block.Encrypt(l, l)
	k1 := dbl(l)
	k2 := dbl(k1)
	var m []byte
	if len(msg) > 0 && len(msg)%16 == 0 {
		m = append([]byte(nil), msg...)
		last := m[len(m)-16:]
		for i := range last {
			last[i] ^= k1[i]
		}
	} else {
		m = append(append([]byte(nil), msg...), 0x80)
		for len(m)%16 != 0 {
			m = append(m, 0)
		}
		last := m[len(m)-16:]
		for i := range last {
			last[i] ^= k2[i]
		}
	}
	out := make([]byte, len(m))
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(out, m)
	return out[len(out)-16:]
}

func (s *session) kdf(key []byte, constant byte, bits uint16) []byte {
	dd := make([]byte, 32)
	dd[11] = constant
	binary.BigEndian.PutUint16(dd[13:15], bits)
	dd[15] = 0x01
	copy(dd[16:24], s.hostChal)
	copy(dd[24:32], s.cardChal)
	return cmac(key, dd)
}

func (c *Card) initializeUpdate(s *session, data []byte) []byte {
	if len(data) != 8 {
		return sw(0x6700)
	}
	s.resetChannel()
	s.hostChal = append([]byte(nil), data...)
	s.cardChal = make([]byte, 8)
	_, _ = rand.Read(s.cardChal)
	s.senc = s.kdf(c.StaticKeys[0:16], 0x04, 0x0080)
	s.smac = s.kdf(c.StaticKeys[16:32], 0x06, 0x0080)
	s.srmac = s.kdf(c.StaticKeys[16:32], 0x07, 0x0080)
	crypt := s.kdf(s.smac, 0x00, 0x0040)[:8]
	resp := append(append([]byte(nil), c.CardID[:10]...), 0x02, 0x03, 0x70)
	resp = append(append(resp, s.cardChal...), crypt...)
	s.chState = 1
	return sw(0x9000, resp)
}

func (c *Card) externalAuthenticate(s *session, level byte, data []byte) []byte {
	if s.chState != 1 {
		return sw(0x6985)
	}
	if len(data) != 16 {
		return sw(0x6700)
	}
	if level&0x01 == 0 {
		return sw(0x6985)
	}
	host := s.kdf(s.smac, 0x01, 0x0040)[:8]
	if subtle.ConstantTimeCompare(host, data[:8]) != 1 {
		s.resetChannel()
		return sw(0x6300)
	}
	in := append(append([]byte(nil), s.chain[:]...), 0x84, 0x82, level, 0x00, 0x10)
	mac := cmac(s.smac, append(in, data[:8]...))
	if subtle.ConstantTimeCompare(mac[:8], data[8:16]) != 1 {
		s.resetChannel()
		return sw(0x6300)
	}
	copy(s.chain[:], mac)
	s.level, s.chState = level, 2
	return sw(0x9000)
}

func (s *session) ecb(counter [16]byte, response bool) []byte {
	if response {
		counter[0] = 0x80
	}
	block, _ := aes.NewCipher(s.senc)
	out := make([]byte, 16)
	block.Encrypt(out, counter[:])
	return out
}

// unwrap is unwrapCommand: the counter first, then C-MAC (over the header
// with the wire Lc), then C-DEC.
func (c *Card) unwrap(s *session, header, data []byte) ([]byte, uint16) {
	if s.chState != 2 {
		return nil, 0x6985
	}
	for i := 15; i >= 0; i-- {
		s.counter[i]++
		if s.counter[i] != 0 {
			break
		}
	}
	payload := data
	if s.level&0x01 != 0 {
		if len(data) < 8 {
			return nil, 0x6700
		}
		payload = data[:len(data)-8]
		in := append(append([]byte(nil), s.chain[:]...), header...)
		in = append(append(in, byte(len(data))), payload...)
		mac := cmac(s.smac, in)
		if subtle.ConstantTimeCompare(mac[:8], data[len(data)-8:]) != 1 {
			s.resetChannel()
			return nil, 0x6688
		}
		copy(s.chain[:], mac)
	}
	if s.level&0x02 != 0 && len(payload) > 0 {
		if len(payload)%16 != 0 {
			return nil, 0x6700
		}
		block, _ := aes.NewCipher(s.senc)
		plain := make([]byte, len(payload))
		cipher.NewCBCDecrypter(block, s.ecb(s.counter, false)).CryptBlocks(plain, payload)
		end := len(plain) - 1
		for end >= 0 && plain[end] == 0 {
			end--
		}
		if end < 0 || plain[end] != 0x80 {
			return nil, 0x6700
		}
		payload = plain[:end]
	}
	s.secured = true
	return payload, 0x9000
}

// wrap is wrapResponse for a 9000 answer with data: R-ENC, then R-MAC.
func (c *Card) wrap(s *session, data []byte) []byte {
	out := data
	if s.level&0x20 != 0 && len(data) > 0 {
		padded := append(append([]byte(nil), data...), 0x80)
		for len(padded)%16 != 0 {
			padded = append(padded, 0)
		}
		block, _ := aes.NewCipher(s.senc)
		out = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, s.ecb(s.counter, true)).CryptBlocks(out, padded)
	}
	if s.level&0x10 != 0 {
		in := append(append(append([]byte(nil), s.chain[:]...), out...), 0x90, 0x00)
		mac := cmac(s.srmac, in)
		copy(s.chain[:], mac)
		out = append(out, mac[:8]...)
	}
	return out
}

// validateSep10 is the card's parser (docs/sep10-card-keys.md §3.3).
func validateSep10(tx, cardKey []byte) uint16 {
	r := &reader{b: tx}
	u32 := func() (uint32, bool) { return r.u32() }
	if t, ok := u32(); !ok || t != 0 {
		return 0x6240
	}
	src, ok := r.fixed(32)
	if !ok {
		return 0x6240
	}
	if bytes.Equal(src, cardKey) {
		return 0x6243
	}
	if _, ok := u32(); !ok { // fee
		return 0x6240
	}
	seq, ok := r.fixed(8)
	if !ok {
		return 0x6240
	}
	if !bytes.Equal(seq, make([]byte, 8)) {
		return 0x6241
	}
	cond, ok := u32()
	if !ok {
		return 0x6240
	}
	if cond != 1 {
		return 0x6245
	}
	if _, ok := r.fixed(8); !ok {
		return 0x6240
	}
	maxT, ok := r.fixed(8)
	if !ok {
		return 0x6240
	}
	if bytes.Equal(maxT, make([]byte, 8)) {
		return 0x6245
	}
	if memo, ok := u32(); !ok || memo != 0 {
		return 0x6240
	}
	n, ok := u32()
	if !ok {
		return 0x6240
	}
	if n < 1 || n > 5 {
		return 0x6242
	}
	for i := uint32(0); i < n; i++ {
		if p, ok := u32(); !ok || p != 1 {
			return 0x6240
		}
		if kt, ok := u32(); !ok || kt != 0 {
			return 0x6240
		}
		opSrc, ok := r.fixed(32)
		if !ok {
			return 0x6240
		}
		typ, ok := u32()
		if !ok {
			return 0x6240
		}
		if typ != 10 {
			return 0x6242
		}
		name, ok := r.varOpaque(64)
		if !ok || len(name) < 1 {
			return 0x6240
		}
		has, ok := u32()
		if !ok || has > 1 {
			return 0x6240
		}
		var value []byte
		if has == 1 {
			if value, ok = r.varOpaque(64); !ok {
				return 0x6240
			}
		}
		if i == 0 {
			if !bytes.Equal(opSrc, cardKey) {
				return 0x6243
			}
			if len(name) < 6 || !strings.HasSuffix(string(name), " auth") || has != 1 || len(value) == 0 {
				return 0x6244
			}
		} else if bytes.Equal(opSrc, cardKey) {
			return 0x6243
		}
	}
	if ext, ok := u32(); !ok || ext != 0 {
		return 0x6240
	}
	if r.p != len(r.b) {
		return 0x6240
	}
	return 0x9000
}

type reader struct {
	b []byte
	p int
}

func (r *reader) u32() (uint32, bool) {
	if len(r.b)-r.p < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b[r.p:])
	r.p += 4
	return v, true
}

func (r *reader) fixed(n int) ([]byte, bool) {
	pad := (4 - n%4) % 4
	if n < 0 || len(r.b)-r.p < n+pad {
		return nil, false
	}
	out := r.b[r.p : r.p+n]
	for _, b := range r.b[r.p+n : r.p+n+pad] {
		if b != 0 {
			return nil, false
		}
	}
	r.p += n + pad
	return out, true
}

func (r *reader) varOpaque(max int) ([]byte, bool) {
	n, ok := r.u32()
	if !ok || n > uint32(max) {
		return nil, false
	}
	return r.fixed(int(n))
}
