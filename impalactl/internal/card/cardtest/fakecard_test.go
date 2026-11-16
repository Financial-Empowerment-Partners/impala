package cardtest

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// The bridge-issued challenge of the shared vector
// (impala-bridge/src/sep10/card_vectors.rs ISSUED) passes the fake card's
// §3.3 parser for the vector card's key, and fails it for another key.
func TestTheFakeCardAcceptsTheSharedVector(t *testing.T) {
	const issued = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAMgAAAAAAAAAAAAAAAEAAAAAa0nSAAAAAABrSdMsAAAAAAAAAAIAAAABAAAAANcvi2UlBeDOTuymwV66i2L4S7EavAkLq6ISVbdVU/2ZAAAACgAAABxhcGktdGVzdG5ldC5leGFtcGxlLmNvbSBhdXRoAAAAAQAAAEBXbHBhV2xwYVdscGFXbHBhV2xwYVdoRWdFNlM1UHdNeE51NnhxUS8yeXRyWWsyVkhZZjFhWDczZ0djUWVqeXZkAAAAAQAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAAoAAAAPd2ViX2F1dGhfZG9tYWluAAAAAAEAAAAXYXBpLXRlc3RuZXQuZXhhbXBsZS5jb20AAAAAAAAAAAH3B1EaAAAAQEaF82VZmJjfApz9tqEpS/sDsigAZIyf8SHztaUn5LdRCxw14B77qpqeKEGtGbPqepGKw3ZGe4aYXQ5PaJ64VwA="
	env, _ := base64.StdEncoding.DecodeString(issued)
	tx := env[4 : len(env)-4-4-4-64]
	cardKey, _ := hex.DecodeString("d72f8b652505e0ce4eeca6c15eba8b62f84bb11abc090baba21255b75553fd99")
	if sw := validateSep10(tx, cardKey); sw != 0x9000 {
		t.Fatalf("vector refused: SW %04X", sw)
	}
	other := make([]byte, 32)
	if sw := validateSep10(tx, other); sw != 0x6243 {
		t.Fatalf("another key: SW %04X, want 6243", sw)
	}
	server, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if sw := validateSep10(tx, server); sw != 0x6243 {
		t.Fatalf("the server key as the card: SW %04X, want 6243", sw)
	}
	bad := append([]byte(nil), tx...)
	bad[44+3] = 1 // seqNum low byte
	if sw := validateSep10(bad, cardKey); sw != 0x6241 {
		t.Fatalf("sequence: SW %04X, want 6241", sw)
	}
}

// The card side's AES-CMAC (its own, not the host's) on the RFC 4493 examples.
func TestTheFakeCardsCMACMatchesRFC4493(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	msg, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for n, want := range map[int]string{
		0: "bb1d6929e95937287fa37d129b756746", 16: "070a16b46b4d4144f79bdd9dd04a287c",
		40: "dfa66747de9ae63030ca32611497c827", 64: "51f0bebf7e3b9d92fc49741779363cfe",
	} {
		if got := hex.EncodeToString(cmac(key, msg[:n])); got != want {
			t.Errorf("len %d: %s, want %s", n, got, want)
		}
	}
}
