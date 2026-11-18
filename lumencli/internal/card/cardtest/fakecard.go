// Package cardtest is an in-process fake Impala card for tests: a TCP server
// speaking the impala-card simulator framing (a 2-byte big-endian length,
// then the APDU; the same for data ‖ SW) and the applet commands lumencli
// sends, with real Ed25519 signatures and the card's own acceptance rules and
// status words.
//
// It is written from the applet's contract (impala-card/docs/apdu.md,
// docs/sep10-card-keys.md §3, and the command rules and guard order of
// ImpalaApplet.java in the Impala repository) and shares no code with
// lumencli's internal/card, so a host-side mistake cannot be mirrored here
// and pass. Its SEP-10 validator follows the one impalactl's fake card
// carries. It is not the applet: the real one runs on jcardsim in the
// Impala demo (demo/scripts/simulator.sh). Test support only; nothing in the
// binary imports it.
package cardtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// Persistent GET_PERSONALIZATION flag bits the fake stores in Card.Flags.
// The PIN-provisioned (0x10) and Stellar-key (0x80) bits are derived from
// PIN and Stellar, and the state byte from the flags, as the applet does.
const (
	FlagInitialized  byte = 0x01
	FlagProgramBound byte = 0x02
	FlagPersonalized byte = 0x04
	FlagDefaultKeys  byte = 0x08
	FlagEnforce      byte = 0x20
	FlagTerminated   byte = 0x40
)

// AID is the applet-instance AID the fake answers SELECT for by default.
var AID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02}

// TestPIN is the user PIN New provisions.
const TestPIN = "4821"

// pinTryLimit is the applet's user-PIN try limit.
const pinTryLimit = 5

// Card is the fake card's persistent state. Configure it before Start; the
// card serves on its own goroutines afterwards, so read it only through the
// accessors.
type Card struct {
	AID          []byte
	Major, Minor uint16
	Flags        byte
	Stellar      ed25519.PrivateKey // nil: no Stellar key (a legacy card)
	Engine       byte               // GET_STELLAR_KEY engine id: 0x01 soft, 0x02 native
	PIN          string             // the provisioned user PIN; "" = none provisioned
	RequirePIN   bool               // the sign-in policy requires the user PIN
	FixedPIN     bool               // the policy was fixed at install
	// Force answers a command with a status word: key INS<<8 | P1.
	Force map[uint16]uint16
	// BadSignature makes FINISH answer a signature that does not verify
	// (a broken engine, or another card's key).
	BadSignature bool

	account, cardID [16]byte
	ec              *ecdsa.PrivateKey

	mu    sync.Mutex
	tries int
	log   []string
	parts []int // SIGN_SEP10 data lengths, in order
}

// StellarKey derives a deterministic Ed25519 key from label, so golden files
// can name the card's address. It holds nothing on any network.
func StellarKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("lumencli fake card stellar key: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// New is an issued applet 0.4 card: initialized, program-bound and
// personalized on its own SCP03 keys, with a provisioned user PIN
// (TestPIN), no sign-in PIN policy, and the software Ed25519 engine's
// Stellar key StellarKey("card").
func New() *Card {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	c := &Card{
		AID:     append([]byte(nil), AID...),
		Major:   0,
		Minor:   4,
		Flags:   FlagInitialized | FlagProgramBound | FlagPersonalized,
		Stellar: StellarKey("card"),
		Engine:  0x01,
		PIN:     TestPIN,
		ec:      ec,
		tries:   pinTryLimit,
	}
	copy(c.account[:], bytes.Repeat([]byte{0xA1}, 16))
	copy(c.cardID[:], bytes.Repeat([]byte{0xC1}, 16))
	return c
}

// StellarPub is the card's Stellar public key (nil without one).
func (c *Card) StellarPub() ed25519.PublicKey {
	if c.Stellar == nil {
		return nil
	}
	return c.Stellar.Public().(ed25519.PublicKey)
}

// Start serves the card on 127.0.0.1 and returns its "tcp:HOST:PORT" spec.
func (c *Card) Start(t testing.TB) string {
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

// Log lists every command received, "NAME P1=xx", in order.
func (c *Card) Log() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.log...)
}

// Received reports whether a command named name ("SIGN_SEP10", "VERIFY_PIN",
// ...) was received.
func (c *Card) Received(name string) bool {
	for _, l := range c.Log() {
		if strings.HasPrefix(l, name+" ") {
			return true
		}
	}
	return false
}

// Sep10Parts returns the data length of every SIGN_SEP10 part received.
func (c *Card) Sep10Parts() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.parts...)
}

// TriesLeft is the user PIN's try counter.
func (c *Card) TriesLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tries
}

// SetTries sets the user PIN's try counter (0 blocks the PIN).
func (c *Card) SetTries(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tries = n
}

// session is per connection: the selection, the PIN state and the SEP-10
// stage are transient (CLEAR_ON_DESELECT; the simulator deselects when the
// connection closes).
type session struct {
	selected    bool
	pinVerified bool
	stage       []byte // SIGN_SEP10: networkId ‖ tx so far; nil = nothing staged
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
	0xA4: "SELECT", 0x64: "GET_VERSION", 0x34: "GET_PERSONALIZATION",
	0x37: "GET_STELLAR_KEY", 0x39: "GET_USER_VERIFICATION", 0x18: "VERIFY_PIN",
	0x38: "SIGN_SEP10", 0x1E: "GET_USER_DATA", 0x25: "SIGN_AUTH",
}

func (c *Card) has(f byte) bool { return c.Flags&f != 0 }

func (c *Card) v03() bool { return c.Major > 0 || c.Minor >= 3 }
func (c *Card) v04() bool { return c.Major > 0 || c.Minor >= 4 }

// state is the GET_PERSONALIZATION state byte, as the applet derives it.
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

func (c *Card) flags() byte {
	f := c.Flags
	if c.PIN != "" {
		f |= 0x10
	}
	// PFLAG_STELLAR_KEY arrived with the Stellar key itself, in applet 0.3:
	// an older applet never reports it, whatever the fake holds.
	if c.Stellar != nil && c.v03() {
		f |= 0x80
	}
	return f
}

func (c *Card) process(s *session, apdu []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(apdu) < 4 {
		return sw(0x6700)
	}
	cla, ins, p1, p2 := apdu[0], apdu[1], apdu[2], apdu[3]
	var data []byte
	if len(apdu) > 5 {
		// Case 3 (Lc data) or case 4 (Lc data Le).
		lc := int(apdu[4])
		if lc == 0 || (len(apdu) != 5+lc && len(apdu) != 6+lc) {
			return sw(0x6700)
		}
		data = apdu[5 : 5+lc]
	}
	name := names[ins]
	if name == "" {
		name = fmt.Sprintf("INS_%02X", ins)
	}
	c.log = append(c.log, fmt.Sprintf("%s P1=%02X", name, p1))
	if ins == 0x38 {
		c.parts = append(c.parts, len(data))
	}

	// A staged challenge survives only the next accepted BEGIN/CONTINUE part:
	// the applet takes it out of service at the start of every command.
	staged := s.stage
	s.stage = nil

	if v, ok := c.Force[uint16(ins)<<8|uint16(p1)]; ok {
		return sw(v)
	}
	if cla != 0x00 {
		return sw(0x6E00) // the fake has no secure channel
	}
	if ins == 0xA4 {
		if p1 == 0x04 && bytes.Equal(data, c.AID) {
			*s = session{selected: true}
			return sw(0x9000)
		}
		return sw(0x6A82)
	}
	if !s.selected {
		return sw(0x6D00)
	}
	terminated := c.has(FlagTerminated)
	switch ins {
	case 0x64: // GET_VERSION
		d := make([]byte, 10)
		binary.BigEndian.PutUint16(d[0:], c.Major)
		binary.BigEndian.PutUint16(d[2:], c.Minor)
		copy(d[6:], []byte{0xde, 0xad, 0xbe, 0xef})
		return sw(0x9000, d)
	case 0x34: // GET_PERSONALIZATION
		d := make([]byte, 159)
		d[0] = c.state()
		d[1] = c.flags()
		return sw(0x9000, d)
	case 0x37: // GET_STELLAR_KEY
		if !c.v03() {
			return sw(0x6D00)
		}
		if c.Stellar == nil {
			return sw(0x623C)
		}
		d := make([]byte, 169)
		d[0] = c.Engine
		copy(d[1:33], c.StellarPub())
		// The two cross-signature slots read as zeros until PERSONALIZE has
		// committed (docs/sep10-card-keys.md §3.2).
		if c.has(FlagPersonalized) {
			ecPub, err := c.ec.PublicKey.Bytes() // 04 ‖ X ‖ Y, 65 bytes
			if err != nil {
				return sw(0x6F00)
			}
			skeyA := concat([]byte("IMPALA-SKEY:\x01"), c.account[:], c.cardID[:], c.StellarPub())
			h := sha256.Sum256(skeyA)
			bsig, err := ecdsa.SignASN1(rand.Reader, c.ec, h[:])
			if err != nil {
				return sw(0x6F00)
			}
			copy(d[33:105], bsig)
			skeyB := concat([]byte("IMPALA-SKEY:\x02"), c.account[:], c.cardID[:], ecPub)
			copy(d[105:169], ed25519.Sign(c.Stellar, skeyB))
		}
		return sw(0x9000, d)
	case 0x39: // GET_USER_VERIFICATION
		if !c.v04() {
			return sw(0x6D00)
		}
		var policy, session byte
		if c.RequirePIN {
			policy |= 0x01
		}
		if c.FixedPIN {
			policy |= 0x02
		}
		if c.PIN != "" {
			policy |= 0x04
		}
		if c.PIN != "" && s.pinVerified {
			session = 0x01
		}
		return sw(0x9000, []byte{0x01, policy, byte(c.tries), session})
	case 0x18: // VERIFY_PIN
		if terminated {
			return sw(0x6687)
		}
		return sw(c.verifyPIN(s, p2, data))
	case 0x38: // SIGN_SEP10
		if !c.v03() {
			return sw(0x6D00)
		}
		return c.signSep10(s, p1, p2, data, staged)
	}
	return sw(0x6D00)
}

func (c *Card) verifyPIN(s *session, p2 byte, data []byte) uint16 {
	if p2 != 0x82 {
		return 0x6A86 // the fake knows only the user PIN
	}
	if len(data) != 4 {
		return 0x6700
	}
	if c.PIN == "" {
		return 0x6985
	}
	if c.tries == 0 {
		return 0x69C0
	}
	want := make([]byte, 4)
	for i, r := range c.PIN {
		want[i] = byte(r - '0')
	}
	if !bytes.Equal(data, want) {
		c.tries--
		s.pinVerified = false
		return 0x69C0 | uint16(c.tries)
	}
	c.tries = pinTryLimit
	s.pinVerified = true
	return 0x9000
}

// signSep10 follows the applet's SIGN_SEP10 guards in their order
// (failIfCardIsTerminated, failIfProvisioningRequired,
// failIfNotPersonalized, failIfNoStellarKey, failIfSignInPinMissing), then
// stages, validates and signs.
func (c *Card) signSep10(s *session, p1, p2 byte, data, staged []byte) []byte {
	switch {
	case c.has(FlagTerminated):
		return sw(0x6687)
	case c.has(FlagEnforce) && c.PIN == "":
		return sw(0x6985) // the provisioning gate: no signing until a user PIN is provisioned
	case !c.has(FlagPersonalized):
		return sw(0x6234)
	case c.Stellar == nil:
		return sw(0x623C)
	case c.RequirePIN && !s.pinVerified:
		if c.PIN == "" {
			return sw(0x6985)
		}
		return sw(0x6690)
	}
	if p2 != 0 {
		return sw(0x6A86)
	}
	switch p1 {
	case 0x00: // BEGIN
		if len(data) < 33 {
			return sw(0x6700)
		}
		s.stage = append([]byte(nil), data...)
		return sw(0x9000)
	case 0x01, 0x02: // CONTINUE, FINISH
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
		if v := ValidateSep10(tx, c.StellarPub()); v != 0x9000 {
			return sw(v)
		}
		h := sha256.New()
		h.Write(nid)
		h.Write([]byte{0, 0, 0, 2})
		h.Write(tx)
		sig := ed25519.Sign(c.Stellar, h.Sum(nil))
		if c.BadSignature {
			sig[0] ^= 0x01
		}
		return sw(0x9000, sig)
	}
	return sw(0x6A86)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ValidateSep10 is the card's challenge parser (docs/sep10-card-keys.md
// §3.3): it returns 0x9000 for a transaction the card would sign for
// cardKey, or the status word of the first rule the transaction breaks.
func ValidateSep10(tx, cardKey []byte) uint16 {
	r := &reader{b: tx}
	if t, ok := r.u32(); !ok || t != 0 { // source account: KEY_TYPE_ED25519 only
		return 0x6240
	}
	src, ok := r.fixed(32)
	if !ok {
		return 0x6240
	}
	if bytes.Equal(src, cardKey) {
		return 0x6243
	}
	if _, ok := r.u32(); !ok { // fee
		return 0x6240
	}
	seq, ok := r.fixed(8)
	if !ok {
		return 0x6240
	}
	if !bytes.Equal(seq, make([]byte, 8)) {
		return 0x6241
	}
	cond, ok := r.u32()
	if !ok {
		return 0x6240
	}
	if cond != 1 { // PRECOND_TIME
		return 0x6245
	}
	if _, ok := r.fixed(8); !ok { // minTime
		return 0x6240
	}
	maxT, ok := r.fixed(8)
	if !ok {
		return 0x6240
	}
	if bytes.Equal(maxT, make([]byte, 8)) {
		return 0x6245
	}
	if memo, ok := r.u32(); !ok || memo != 0 { // MEMO_NONE
		return 0x6240
	}
	n, ok := r.u32()
	if !ok {
		return 0x6240
	}
	if n < 1 || n > 5 {
		return 0x6242
	}
	for i := uint32(0); i < n; i++ {
		if p, ok := r.u32(); !ok || p != 1 { // the operation's source account is present
			return 0x6240
		}
		if kt, ok := r.u32(); !ok || kt != 0 { // and a plain ed25519 key
			return 0x6240
		}
		opSrc, ok := r.fixed(32)
		if !ok {
			return 0x6240
		}
		typ, ok := r.u32()
		if !ok {
			return 0x6240
		}
		if typ != 10 { // MANAGE_DATA
			return 0x6242
		}
		name, ok := r.varOpaque(64)
		if !ok || len(name) < 1 {
			return 0x6240
		}
		has, ok := r.u32()
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
	if ext, ok := r.u32(); !ok || ext != 0 {
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
