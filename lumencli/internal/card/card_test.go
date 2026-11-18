package card

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"lumencli/internal/card/cardtest"
)

func TestParseSpecAndLoopback(t *testing.T) {
	for spec, loopback := range map[string]bool{
		"tcp:127.0.0.1:9443":  true,
		"tcp:127.8.9.10:1":    true,
		"tcp:localhost:9443":  true,
		"tcp:LOCALHOST:9443":  true,
		"tcp:[::1]:9443":      true,
		"tcp:10.0.2.2:9443":   false,
		"tcp:192.0.2.7:9443":  false,
		"tcp:card.local:9443": false,
	} {
		if _, _, err := ParseSpec(spec); err != nil {
			t.Errorf("ParseSpec(%q) = %v", spec, err)
		}
		if got := IsLoopback(spec); got != loopback {
			t.Errorf("IsLoopback(%q) = %v, want %v", spec, got, loopback)
		}
	}
	for _, bad := range []string{"", "127.0.0.1:9443", "pcsc:reader", "tcp:127.0.0.1", "tcp::9443", "tcp:127.0.0.1:0", "tcp:127.0.0.1:65536", "tcp:127.0.0.1:x"} {
		if _, _, err := ParseSpec(bad); err == nil {
			t.Errorf("ParseSpec(%q) accepted", bad)
		}
		if IsLoopback(bad) {
			t.Errorf("IsLoopback(%q) = true for a malformed spec", bad)
		}
	}
}

func TestSWName(t *testing.T) {
	cases := map[uint16]string{
		0x69C3: "WRONG_PIN: 3 tries left",
		0x69C0: "PIN_BLOCKED",
		0x6243: "SEP10_WRONG_ACCOUNT",
		0x6690: "PIN_REQUIRED",
		0x1234: "unknown status",
	}
	for sw, want := range cases {
		if got := SWName(sw); !strings.Contains(got, want) {
			t.Errorf("SWName(%04X) = %q, want it to contain %q", sw, got, want)
		}
	}
	err := error(&Error{Step: "sign the SEP-10 challenge", Command: "SIGN_SEP10 FINISH", SW: 0x6241})
	if got := err.Error(); got != "the card refused to sign the SEP-10 challenge (SIGN_SEP10 FINISH): SW 6241 SEP10_SEQUENCE_NOT_ZERO" {
		t.Errorf("Error() = %q", got)
	}
	if SWOf(err) != 0x6241 || SWOf(errors.New("x")) != 0 {
		t.Error("SWOf")
	}
}

// recorder is a Transport that records each APDU and answers from a func.
type recorder struct {
	apdus  [][]byte
	answer func(apdu []byte) []byte
}

func (r *recorder) Transmit(apdu []byte) ([]byte, error) {
	r.apdus = append(r.apdus, append([]byte(nil), apdu...))
	return r.answer(apdu), nil
}
func (r *recorder) Close() error { return nil }

// signerAnswers is a card that accepts every SIGN_SEP10 part and answers
// FINISH with sigLen bytes.
func signerAnswers(sigLen int) func([]byte) []byte {
	return func(apdu []byte) []byte {
		if apdu[1] == insSignSep10 && apdu[2] == p1Sep10Finish {
			return append(make([]byte, sigLen), 0x90, 0x00)
		}
		return []byte{0x90, 0x00}
	}
}

// TestSignSep10Parts pins the card SDK's part split (docs/sep10-card-keys.md
// §4): BEGIN carries the network id and as much of the transaction as fits
// beside it but never the last byte; CONTINUE parts are 255 bytes; FINISH
// carries the rest, at least one byte. Every command is a short case-3 APDU.
func TestSignSep10Parts(t *testing.T) {
	nid := network.ID(network.TestNetworkPassphrase)
	for _, n := range []int{2, 3, 100, 223, 224, 225, 478, 479, 480, 481, 640} {
		tx := make([]byte, n)
		for i := range tx {
			tx[i] = byte(i*7 + 1)
		}
		r := &recorder{answer: signerAnswers(64)}
		sig, err := New(r).SignSep10(nid[:], tx)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(sig) != 64 {
			t.Fatalf("n=%d: %d-byte signature", n, len(sig))
		}
		var got []byte
		for i, apdu := range r.apdus {
			cla, ins, p1, p2, lc := apdu[0], apdu[1], apdu[2], apdu[3], int(apdu[4])
			data := apdu[5:]
			if cla != 0 || ins != 0x38 || p2 != 0 || lc != len(data) || lc == 0 || lc > 255 {
				t.Fatalf("n=%d part %d: header %X, %d data bytes", n, i, apdu[:5], len(data))
			}
			wantP1 := p1Sep10Continue
			switch i {
			case 0:
				wantP1 = p1Sep10Begin
				if !bytes.Equal(data[:32], nid[:]) {
					t.Fatalf("n=%d: BEGIN does not start with the network id", n)
				}
				data = data[32:]
			case len(r.apdus) - 1:
				wantP1 = p1Sep10Finish
			}
			if p1 != wantP1 {
				t.Fatalf("n=%d part %d: P1 %02X, want %02X", n, i, p1, wantP1)
			}
			if i > 0 && i < len(r.apdus)-1 && len(data) != 255 {
				t.Fatalf("n=%d: CONTINUE part %d carries %d bytes, want 255", n, i, len(data))
			}
			got = append(got, data...)
		}
		if !bytes.Equal(got, tx) {
			t.Fatalf("n=%d: the parts do not reassemble the transaction", n)
		}
		first := min(n-1, 223)
		if len(r.apdus[0]) != 5+32+first {
			t.Errorf("n=%d: BEGIN carries %d transaction bytes, want %d", n, len(r.apdus[0])-37, first)
		}
	}
}

func TestSignSep10RefusesBeforeSending(t *testing.T) {
	nid := network.ID(network.TestNetworkPassphrase)
	for name, call := range map[string]func(*Card) error{
		"1 byte":         func(c *Card) error { _, err := c.SignSep10(nid[:], []byte{1}); return err },
		"641 bytes":      func(c *Card) error { _, err := c.SignSep10(nid[:], make([]byte, 641)); return err },
		"31-byte net id": func(c *Card) error { _, err := c.SignSep10(nid[:31], make([]byte, 100)); return err },
	} {
		r := &recorder{answer: signerAnswers(64)}
		if err := call(New(r)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(r.apdus) != 0 {
			t.Errorf("%s: %d commands sent", name, len(r.apdus))
		}
	}
	r := &recorder{answer: signerAnswers(63)}
	var pe *ProtocolError
	if _, err := New(r).SignSep10(nid[:], make([]byte, 100)); !errors.As(err, &pe) {
		t.Errorf("a 63-byte signature: %v, want a ProtocolError", err)
	}
}

func dialFake(t *testing.T, fc *cardtest.Card) *Card {
	t.Helper()
	tr, err := DialTCP(fc.Start(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := New(tr)
	t.Cleanup(func() { c.Close() })
	if err := c.Select(DefaultAID); err != nil {
		t.Fatal(err)
	}
	return c
}

// sdkChallenge builds a challenge for account the way Go SEP-10 servers do
// and returns its Transaction bytes (the tx of the v1 envelope).
func sdkChallenge(t *testing.T, account string) []byte {
	t.Helper()
	server, err := keypair.Random()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := txnbuild.BuildChallengeTx(server.Seed(), account, "example.com", "example.com", network.TestNetworkPassphrase, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	b64, err := tx.Base64()
	if err != nil {
		t.Fatal(err)
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(b64, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := env.V1.Tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCardCommandsAgainstTheFake(t *testing.T) {
	fc := cardtest.New()
	c := dialFake(t, fc)

	v, err := c.GetVersion()
	if err != nil || v.String() != "0.4" || v.Hash != "deadbeef" || !v.AtLeast(0, 3) || v.AtLeast(0, 5) {
		t.Fatalf("GetVersion = %+v, %v", v, err)
	}
	p, err := c.GetPersonalization()
	if err != nil || !p.Personalized() || p.Terminated() || !p.PinProvisioned() || !p.AdvertisesStellarKey() {
		t.Fatalf("GetPersonalization = %+v, %v", p, err)
	}
	k, err := c.GetStellarKey()
	if err != nil || k == nil {
		t.Fatalf("GetStellarKey = %v, %v", k, err)
	}
	wantAddr, _ := strkey.Encode(strkey.VersionByteAccountID, fc.StellarPub())
	if k.Address() != wantAddr || k.EngineName() != "soft" || !k.Bound {
		t.Errorf("Stellar key = %s %s bound=%v, want %s soft bound", k.Address(), k.EngineName(), k.Bound, wantAddr)
	}
	uv, err := c.GetUserVerification()
	if err != nil || uv == nil || uv.SignInPinRequired || !uv.PinProvisioned || uv.TriesLeft != 5 {
		t.Fatalf("GetUserVerification = %+v, %v", uv, err)
	}

	err = c.VerifyUserPIN("0000")
	if SWOf(err) != 0x69C4 || !strings.Contains(err.Error(), "WRONG_PIN: 4 tries left") {
		t.Errorf("wrong PIN: %v", err)
	}
	if err := c.VerifyUserPIN(cardtest.TestPIN); err != nil {
		t.Errorf("right PIN: %v", err)
	}
	if err := c.VerifyUserPIN("12a4"); err == nil {
		t.Error("a non-digit PIN was sent")
	}

	tx := sdkChallenge(t, k.Address())
	nid := network.ID(network.TestNetworkPassphrase)
	sig, err := c.SignSep10(nid[:], tx)
	if err != nil {
		t.Fatalf("SignSep10: %v", err)
	}
	h := sha256.New()
	h.Write(nid[:])
	h.Write([]byte{0, 0, 0, 2})
	h.Write(tx)
	if !ed25519.Verify(fc.StellarPub(), h.Sum(nil), sig) {
		t.Error("the card's signature does not verify over the transaction hash")
	}

	// A challenge for another account: the card's own parser refuses it.
	other, _ := keypair.Random()
	_, err = c.SignSep10(nid[:], sdkChallenge(t, other.Address()))
	if SWOf(err) != 0x6243 {
		t.Errorf("a challenge for another account: %v, want SW 6243", err)
	}
}

func TestCardWithoutStellarKeyOrNewCommands(t *testing.T) {
	legacy := cardtest.New()
	legacy.Stellar = nil
	if k, err := dialFake(t, legacy).GetStellarKey(); k != nil || err != nil {
		t.Errorf("a card without a Stellar key: %v, %v; want nil, nil", k, err)
	}
	old := cardtest.New()
	old.Minor = 2
	c := dialFake(t, old)
	if k, err := c.GetStellarKey(); k != nil || err != nil {
		t.Errorf("applet 0.2 (no GET_STELLAR_KEY): %v, %v; want nil, nil", k, err)
	}
	if uv, err := c.GetUserVerification(); uv != nil || err != nil {
		t.Errorf("applet 0.2 (no GET_USER_VERIFICATION): %v, %v; want nil, nil", uv, err)
	}
}

func TestSelectAnotherAID(t *testing.T) {
	fc := cardtest.New()
	tr, err := DialTCP(fc.Start(t), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := New(tr)
	defer c.Close()
	err = c.Select("A000000003000000")
	if SWOf(err) != 0x6A82 || !strings.Contains(err.Error(), "APPLET_NOT_FOUND") {
		t.Errorf("Select(another AID) = %v", err)
	}
	if err := c.Select("0102"); err == nil {
		t.Error("a 2-byte AID was sent")
	}
}

// TestTCPTransportFraming: a frame without a status word, and a card that
// hangs up, are transport failures, never answers.
func TestTCPTransportFraming(t *testing.T) {
	serve := func(t *testing.T, answer []byte) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			var hdr [2]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(hdr[:]))); err != nil {
				return
			}
			_, _ = conn.Write(answer)
		}()
		return "tcp:" + ln.Addr().String()
	}
	for name, answer := range map[string][]byte{
		"no status word": {0x00, 0x01, 0x90},
		"hang-up":        nil,
	} {
		tr, err := DialTCP(serve(t, answer), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var te *TransportError
		if _, err := New(tr).GetVersion(); !errors.As(err, &te) {
			t.Errorf("%s: %v, want a TransportError", name, err)
		}
		tr.Close()
	}
	if _, err := DialTCP("tcp:127.0.0.1:1", time.Second); err == nil {
		t.Error("dialing a closed port succeeded")
	}
}
