// Package sep10 is the client side of SEP-10 (Stellar Web Authentication) as
// the Impala card sign-in uses it: the strict stellar.toml reader, the
// challenge verifier and the signed-envelope framing, ported from the card SDK
// (impala-card/sdk .../stellar/Sep10.kt, Xdr.kt, StrKey.kt) and impala-lib
// (.../stellar/Sep10Client.kt, StellarToml.kt, Sep10Transport.kt). It uses the
// standard library only.
package sep10

import (
	"encoding/base32"
	"errors"
	"fmt"
)

const (
	versionAccountID byte = 6 << 3 // 'G'
	strKeyLength          = 56
)

var strKeyEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// crc16XModem is the StrKey checksum (CRC-16/XMODEM), appended little-endian.
func crc16XModem(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// EncodeAccountID encodes a 32-byte Ed25519 public key as a G… account id.
func EncodeAccountID(key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("an account key is 32 bytes, got %d", len(key))
	}
	payload := append([]byte{versionAccountID}, key...)
	crc := crc16XModem(payload)
	payload = append(payload, byte(crc), byte(crc>>8))
	return strKeyEncoding.EncodeToString(payload), nil
}

// DecodeAccountID decodes a G… account id, checking length, alphabet,
// version byte, checksum and canonical form.
func DecodeAccountID(id string) ([]byte, error) {
	if len(id) != strKeyLength {
		return nil, fmt.Errorf("a Stellar account id is %d characters, got %d", strKeyLength, len(id))
	}
	raw, err := strKeyEncoding.DecodeString(id)
	if err != nil || len(raw) != 35 {
		return nil, errors.New("a Stellar account id must be base32 (A-Z, 2-7)")
	}
	if raw[0] != versionAccountID {
		return nil, errors.New("not a Stellar account id (G…)")
	}
	want := crc16XModem(raw[:33])
	if raw[33] != byte(want) || raw[34] != byte(want>>8) {
		return nil, errors.New("the Stellar account id's checksum does not match")
	}
	if again, _ := EncodeAccountID(raw[1:33]); again != id {
		return nil, errors.New("the Stellar account id is not canonical")
	}
	return raw[1:33], nil
}

// IsValidAccountID reports whether id is a well-formed G… account id.
func IsValidAccountID(id string) bool {
	_, err := DecodeAccountID(id)
	return err == nil
}
