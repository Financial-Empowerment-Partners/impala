package card

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// The host side of the applet's SCP03 secure channel (GlobalPlatform 2.3
// Amendment D with a counter ICV, key version 0x02), a port of the card SDK's
// SCP03Channel (impala-card/sdk scp03/SCP03Channel.kt) checked against the
// applet's SCP03.java. The setup commands of an issuance (PROVISION_PIN,
// APPLET_UPDATE, PERSONALIZE) travel only through it.

const (
	claGP      byte = 0x80
	claSecured byte = 0x84

	insInitializeUpdate     byte = 0x50
	insExternalAuthenticate byte = 0x82

	// scp03KeyVersion is keyInfo[0] of INITIALIZE UPDATE: 0x02 is the
	// counter-ICV wire format this host speaks (SCP03.java KEY_INFO).
	scp03KeyVersion byte = 0x02

	// SecurityLevel is C-MAC | C-DEC | R-MAC | R-ENC, the only level an
	// issuance opens (PERSONALIZE needs C-DEC).
	SecurityLevel byte = 0x33

	secCDEC byte = 0x02
	secRMAC byte = 0x10
	secRENC byte = 0x20

	derivSENC      byte = 0x04
	derivSMAC      byte = 0x06
	derivSRMAC     byte = 0x07
	derivCardCrypt byte = 0x00
	derivHostCrypt byte = 0x01
)

// DefaultSCP03Key is the GlobalPlatform test key 40 41 .. 4F: a stock card's
// ENC, MAC and DEK, and a value the card refuses as a rotation target.
var DefaultSCP03Key = [16]byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}

// SCP03Keys is a static key set.
type SCP03Keys struct {
	ENC, MAC, DEK [16]byte
}

// DefaultSCP03Keys is the GP default key for all three.
func DefaultSCP03Keys() SCP03Keys {
	return SCP03Keys{ENC: DefaultSCP03Key, MAC: DefaultSCP03Key, DEK: DefaultSCP03Key}
}

// ParseSCP03Keys reads 48 bytes ENC ‖ MAC ‖ DEK.
func ParseSCP03Keys(b []byte) (SCP03Keys, error) {
	var k SCP03Keys
	if len(b) != 48 {
		return k, errors.New("an SCP03 key set is 48 bytes (ENC ‖ MAC ‖ DEK)")
	}
	copy(k.ENC[:], b[0:16])
	copy(k.MAC[:], b[16:32])
	copy(k.DEK[:], b[32:48])
	return k, nil
}

// Wipe zeroes the keys.
func (k *SCP03Keys) Wipe() {
	*k = SCP03Keys{}
}

// CardKeys derives a card's own SCP03 keys from the key master key
// (impala-card tools/issue CardKeys.kt): K = AES-CMAC(KMK, cardId ‖
// "IMPALA-SCP03-" ‖ label) for label ENC, MAC and DEK. A derived key equal to
// the GP default key is refused (the card would refuse it too).
func CardKeys(kmk, cardID []byte) (SCP03Keys, error) {
	var k SCP03Keys
	if len(kmk) != 16 {
		return k, errors.New("the key master key is 16 bytes")
	}
	if len(cardID) != 16 {
		return k, errors.New("a card id is 16 bytes")
	}
	for _, d := range []struct {
		label string
		out   *[16]byte
	}{{"ENC", &k.ENC}, {"MAC", &k.MAC}, {"DEK", &k.DEK}} {
		msg := append(append(append([]byte(nil), cardID...), "IMPALA-SCP03-"...), d.label...)
		*d.out = AESCMAC(kmk, msg)
		if *d.out == DefaultSCP03Key {
			k.Wipe()
			return k, errors.New("a derived per-card key equals the GP default key")
		}
	}
	return k, nil
}

// CryptogramError is a card cryptogram that does not verify under the keys
// tried: the card holds other static keys. Nothing is sent after the
// INITIALIZE UPDATE that produced it, so trying a key set this way is
// harmless (the card's counters are untouched).
type CryptogramError struct{}

func (*CryptogramError) Error() string {
	return "the card's SCP03 cryptogram does not verify under these keys (the card holds other static keys)"
}

// SecureChannel is an open SCP03 session at SecurityLevel.
type SecureChannel struct {
	c                *Card
	senc, smac, srmc [16]byte
	chain            [16]byte
	counter          [16]byte
	level            byte
	open             bool
}

// OpenSecureChannel runs INITIALIZE UPDATE with an 8-byte host challenge
// read from rnd, verifies the card cryptogram (constant time) and only then
// sends EXTERNAL AUTHENTICATE. A cryptogram that does not verify is a
// *CryptogramError and EXTERNAL AUTHENTICATE is never sent.
func (c *Card) OpenSecureChannel(keys *SCP03Keys, rnd io.Reader) (*SecureChannel, error) {
	const step = "open the SCP03 secure channel"
	host := make([]byte, 8)
	if _, err := io.ReadFull(rnd, host); err != nil {
		return nil, fmt.Errorf("draw the SCP03 host challenge: %w", err)
	}
	d, err := c.exchange(step, "INITIALIZE UPDATE", claGP, insInitializeUpdate, 0, 0, host)
	if err != nil {
		return nil, err
	}
	if len(d) != 29 {
		return nil, &ProtocolError{step, fmt.Sprintf("INITIALIZE UPDATE answered %d bytes, expected 29", len(d))}
	}
	if d[10] != scp03KeyVersion {
		return nil, &ProtocolError{step, fmt.Sprintf("the card reports SCP03 key version 0x%02X; this client "+
			"speaks 0x%02X (the counter-ICV format of applet 0.2 and newer)", d[10], scp03KeyVersion)}
	}
	cardCh, cardCrypt := d[13:21], d[21:29]

	s := &SecureChannel{c: c, level: SecurityLevel}
	s.senc = derive(keys.ENC[:], derivSENC, 0x0080, host, cardCh)
	s.smac = derive(keys.MAC[:], derivSMAC, 0x0080, host, cardCh)
	s.srmc = derive(keys.MAC[:], derivSRMAC, 0x0080, host, cardCh)
	want := derive(s.smac[:], derivCardCrypt, 0x0040, host, cardCh)
	if subtle.ConstantTimeCompare(want[:8], cardCrypt) != 1 {
		s.Close()
		return nil, &CryptogramError{}
	}
	hostCrypt := derive(s.smac[:], derivHostCrypt, 0x0040, host, cardCh)

	macIn := make([]byte, 0, 16+5+8)
	macIn = append(macIn, s.chain[:]...)
	macIn = append(macIn, claSecured, insExternalAuthenticate, s.level, 0x00, 0x10)
	macIn = append(macIn, hostCrypt[:8]...)
	s.chain = AESCMAC(s.smac[:], macIn)
	data := append(append([]byte(nil), hostCrypt[:8]...), s.chain[:8]...)
	if _, err := c.exchange(step, "EXTERNAL AUTHENTICATE", claSecured, insExternalAuthenticate, s.level, 0, data); err != nil {
		s.Close()
		return nil, err
	}
	s.open = true
	return s, nil
}

// derive is the SCP03 KDF: AES-CMAC(key, 11 zero bytes ‖ constant ‖ 0x00 ‖
// L (bits, 2 bytes) ‖ 0x01 ‖ hostChallenge ‖ cardChallenge).
func derive(key []byte, constant byte, bits uint16, host, cardCh []byte) [16]byte {
	dd := make([]byte, 32)
	dd[11] = constant
	dd[13] = byte(bits >> 8)
	dd[14] = byte(bits)
	dd[15] = 0x01
	copy(dd[16:24], host)
	copy(dd[24:32], cardCh)
	return AESCMAC(key, dd)
}

// Close ends the session and zeroes its keys.
func (s *SecureChannel) Close() {
	s.open = false
	s.senc, s.smac, s.srmc, s.chain, s.counter = [16]byte{}, [16]byte{}, [16]byte{}, [16]byte{}, [16]byte{}
}

// Transmit wraps CLA 0x80 INS P1 P2 [data] for the session (C-DEC, C-MAC),
// sends it with CLA 0x84 and unwraps the answer. The encryption counter
// advances once per command whether or not it carries data. A response
// carries an R-MAC only when its data is at least 8 bytes (the setup commands
// answer a bare 9000, as the applet sends them); R-ENC is undone on what
// remains. Returns the plaintext data of a 9000 answer.
func (s *SecureChannel) Transmit(step, command string, ins, p1, p2 byte, data []byte) ([]byte, error) {
	if !s.open {
		return nil, &ProtocolError{step, "the secure channel is not open"}
	}
	incrementCounter(&s.counter)
	payload := data
	if len(data) > 0 && s.level&secCDEC != 0 {
		padded := pad(data)
		icv := s.ecb(s.counter)
		payload = make([]byte, len(padded))
		block, _ := aes.NewCipher(s.senc[:])
		cipher.NewCBCEncrypter(block, icv[:]).CryptBlocks(payload, padded)
		clear(padded)
	}
	lc := len(payload) + 8
	if lc > maxShortAPDUData {
		return nil, &ProtocolError{step, "the wrapped command is longer than a short APDU"}
	}
	macIn := make([]byte, 0, 16+5+len(payload))
	macIn = append(macIn, s.chain[:]...)
	macIn = append(macIn, claSecured, ins, p1, p2, byte(lc))
	macIn = append(macIn, payload...)
	s.chain = AESCMAC(s.smac[:], macIn)
	clear(macIn)

	apdu := make([]byte, 0, 5+lc)
	apdu = append(apdu, claSecured, ins, p1, p2, byte(lc))
	apdu = append(apdu, payload...)
	apdu = append(apdu, s.chain[:8]...)
	resp, sw, err := s.c.transmit(step, command, apdu)
	if err != nil {
		return nil, err
	}
	if s.level&secRMAC != 0 && len(resp) >= 8 {
		body, got := resp[:len(resp)-8], resp[len(resp)-8:]
		rmacIn := make([]byte, 0, 16+len(body)+2)
		rmacIn = append(rmacIn, s.chain[:]...)
		rmacIn = append(rmacIn, body...)
		rmacIn = append(rmacIn, byte(sw>>8), byte(sw))
		want := AESCMAC(s.srmc[:], rmacIn)
		if subtle.ConstantTimeCompare(want[:8], got) != 1 {
			return nil, &ProtocolError{step, command + ": the response MAC does not verify"}
		}
		s.chain = want
		resp = body
	}
	if s.level&secRENC != 0 && len(resp) > 0 {
		if len(resp)%16 != 0 {
			return nil, &ProtocolError{step, command + ": the encrypted response is not whole blocks"}
		}
		rc := s.counter
		rc[0] = 0x80
		icv := s.ecb(rc)
		plain := make([]byte, len(resp))
		block, _ := aes.NewCipher(s.senc[:])
		cipher.NewCBCDecrypter(block, icv[:]).CryptBlocks(plain, resp)
		if resp, err = unpad(plain); err != nil {
			return nil, &ProtocolError{step, command + ": " + err.Error()}
		}
	}
	if sw != SWOK {
		return nil, &Error{Step: step, Command: command, SW: sw}
	}
	return resp, nil
}

func (s *SecureChannel) ecb(in [16]byte) [16]byte {
	block, _ := aes.NewCipher(s.senc[:])
	var out [16]byte
	block.Encrypt(out[:], in[:])
	return out
}

func incrementCounter(c *[16]byte) {
	for i := 15; i >= 0; i-- {
		c[i]++
		if c[i] != 0 {
			return
		}
	}
}

// pad is ISO 9797-1 method 2: 0x80, then zeros to a multiple of 16 (always
// at least one byte).
func pad(b []byte) []byte {
	out := make([]byte, (len(b)/16+1)*16)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

func unpad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0x80:
			return b[:i], nil
		case 0x00:
		default:
			return nil, errors.New("bad ISO 9797-1 padding")
		}
	}
	return nil, errors.New("no ISO 9797-1 padding marker")
}
