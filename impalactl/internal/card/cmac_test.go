package card

import (
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 4493 §4, the four examples.
func TestAESCMACMatchesRFC4493(t *testing.T) {
	key := unhex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	msg := unhex(t, "6bc1bee22e409f96e93d7e117393172a"+"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+"f69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		got := AESCMAC(key, msg[:tc.n])
		if hex.EncodeToString(got[:]) != tc.want {
			t.Errorf("len %d: %x, want %s", tc.n, got, tc.want)
		}
	}
}

// The per-card keys of the recorded issuance vectors: the card's second
// INITIALIZE UPDATE answer there verifies only under these.
func TestCardKeysDeriveAndRefuseTheDefault(t *testing.T) {
	k, err := CardKeys(unhex(t, "000102030405060708090a0b0c0d0e0f"), unhex(t, "5758412d0816dea4c6a6be6deda95136"))
	if err != nil {
		t.Fatal(err)
	}
	if k.ENC == k.MAC || k.MAC == k.DEK || k.ENC == DefaultSCP03Key {
		t.Errorf("keys %x %x %x", k.ENC, k.MAC, k.DEK)
	}
	if _, err := CardKeys(make([]byte, 15), make([]byte, 16)); err == nil {
		t.Error("a 15-byte KMK was accepted")
	}
}

func TestPadding(t *testing.T) {
	for n, want := range map[int]int{0: 16, 1: 16, 15: 16, 16: 32, 40: 48} {
		p := pad(make([]byte, n))
		if len(p) != want || p[n] != 0x80 {
			t.Errorf("pad(%d) = %d bytes", n, len(p))
		}
		u, err := unpad(p)
		if err != nil || len(u) != n {
			t.Errorf("unpad(pad(%d)) = %d, %v", n, len(u), err)
		}
	}
	if _, err := unpad([]byte{1, 0, 0}); err == nil {
		t.Error("bad padding accepted")
	}
}
