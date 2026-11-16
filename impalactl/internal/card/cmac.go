package card

import (
	"crypto/aes"
	"crypto/subtle"
)

// AESCMAC is AES-CMAC (RFC 4493, NIST SP 800-38B) with a 16-byte key: the
// MAC of the SCP03 secure channel, its key derivation, and the per-card key
// derivation (CardKeys). It is the SDK's AESCMAC.sign on crypto/aes.
func AESCMAC(key, msg []byte) [16]byte {
	var out [16]byte
	block, err := aes.NewCipher(key)
	if err != nil {
		// Only a key of the wrong length gets here, which is a programming
		// error: every caller passes a 16-byte key.
		panic("card: AES-CMAC key must be 16 bytes")
	}
	var l, k1, k2 [16]byte
	block.Encrypt(l[:], l[:])
	subkey(&k1, &l)
	subkey(&k2, &k1)

	n := (len(msg) + 15) / 16
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last [16]byte
	tail := msg[(n-1)*16:]
	if complete {
		for i := range last {
			last[i] = tail[i] ^ k1[i]
		}
	} else {
		copy(last[:], tail)
		last[len(tail)] = 0x80
		for i := range last {
			last[i] ^= k2[i]
		}
	}
	var x [16]byte
	for i := 0; i < n-1; i++ {
		for j := range x {
			x[j] ^= msg[i*16+j]
		}
		block.Encrypt(x[:], x[:])
	}
	for j := range x {
		x[j] ^= last[j]
	}
	block.Encrypt(out[:], x[:])
	return out
}

// subkey is the RFC 4493 doubling: out = in << 1, xor 0x87 when the top bit
// was set.
func subkey(out, in *[16]byte) {
	carry := in[0] >> 7
	for i := 0; i < 15; i++ {
		out[i] = in[i]<<1 | in[i+1]>>7
	}
	out[15] = in[15] << 1
	out[15] ^= byte(subtle.ConstantTimeSelect(int(carry), 0x87, 0))
}
