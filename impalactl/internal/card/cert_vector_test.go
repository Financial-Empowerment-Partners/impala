package card

import (
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

// The repo's shared CERT golden vector (impala-card/sdk TransferProtocolGoldenTest.kt,
// impala-bridge src/handlers/card_auth.rs; scripts/check-shared-vectors.sh
// requires these literals here too): programId a0..af, account
// 00112233-4455-6677-8899-aabbccddeeff, USDC, the card key = the P-256
// generator.
const (
	goldenCertMessageHex = "494d50414c412d434552543a01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf00112233445566778899aabbccddeeff55534443046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	goldenCertIDHex      = "82cb580b058873f2554b100cfee07bc7ef7fa5def3ddc477e333f2f60258b77b"
)

func TestCertMessageMatchesTheSharedGoldenVector(t *testing.T) {
	program := unhex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	account := unhex(t, "00112233445566778899aabbccddeeff")
	currency, ok := CurrencyTag("USDC")
	if !ok {
		t.Fatal("USDC tag")
	}
	p := elliptic.P256().Params()
	pub := append([]byte{0x04}, p.Gx.FillBytes(make([]byte, 32))...)
	pub = append(pub, p.Gy.FillBytes(make([]byte, 32))...)
	msg, err := CertMessage(program, account, currency, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg); got != goldenCertMessageHex {
		t.Errorf("CERT message\n got %s\nwant %s", got, goldenCertMessageHex)
	}
	id, err := CertID(program, account, currency, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(id); got != goldenCertIDHex {
		t.Errorf("cert id %s, want %s", got, goldenCertIDHex)
	}
}
