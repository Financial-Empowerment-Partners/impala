package sep10

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Pinned in impala-bridge/src/sep10/card_vectors.rs.
func TestStrKeyMatchesTheSharedVectors(t *testing.T) {
	for addr, pub := range map[string]string{
		"GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF": "d72f8b652505e0ce4eeca6c15eba8b62f84bb11abc090baba21255b75553fd99",
		"GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
	} {
		raw, err := DecodeAccountID(addr)
		if err != nil || hex.EncodeToString(raw) != pub {
			t.Errorf("decode %s = %x, %v", addr, raw, err)
		}
		b, _ := hex.DecodeString(pub)
		if got, _ := EncodeAccountID(b); got != addr {
			t.Errorf("encode %s = %s", pub, got)
		}
	}
}

func TestStrKeyRefusals(t *testing.T) {
	good := "GDLS7C3FEUC6BTSO5STMCXV2RNRPQS5RDK6ASC5LUIJFLN2VKP6ZTXHF"
	for name, id := range map[string]string{
		"checksum": good[:55] + "G",
		"short":    good[:55],
		"seed":     "S" + good[1:],
		"alphabet": strings.ToLower(good),
	} {
		if IsValidAccountID(id) {
			t.Errorf("%s: %s accepted", name, id)
		}
	}
}

func TestTomlReadsTheRootTableStrictly(t *testing.T) {
	text := "# comment\r\nVERSION = \"2.0.0\"\nDOCS = \"\"\"\nSIGNING_KEY = \"GFAKE\"\n\"\"\"\n" +
		"NETWORK_PASSPHRASE = \"Test SDF Network ; September 2015\" # testnet\n" +
		"SIGNING_KEY=\"GABC\"\nWEB_AUTH_ENDPOINT = \"https://x/auth\"\n[[CURRENCIES]]\nSIGNING_KEY = \"GLATER\"\n"
	tm, err := ParseToml(text)
	if err != nil {
		t.Fatal(err)
	}
	if tm.SigningKey != "GABC" || tm.WebAuthEndpoint != "https://x/auth" || tm.NetworkPassphrase != "Test SDF Network ; September 2015" {
		t.Errorf("toml = %+v", tm)
	}
	for name, bad := range map[string]string{
		"duplicate": "SIGNING_KEY = \"A\"\nSIGNING_KEY = \"B\"\n",
		"escape":    "SIGNING_KEY = \"A\\u0041\"\n",
		"literal":   "SIGNING_KEY = 'A'\n",
		"too large": strings.Repeat("#", MaxTomlLength+1),
	} {
		if _, err := ParseToml(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	tm, err = ParseToml("WEB_AUTH_ENDPOINT = \"https://x\"\n")
	if err != nil || tm.SigningKey != "" {
		t.Errorf("missing key: %+v %v", tm, err)
	}
}

func TestWebAuthEndpointRules(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.example.com/auth/sep10": "api.example.com",
		"http://10.0.2.2:8084/auth/sep10":    "10.0.2.2:8084",
	} {
		_, d, err := CheckWebAuthEndpoint(in)
		if err != nil || d != want {
			t.Errorf("%s -> %q, %v", in, d, err)
		}
	}
	for _, bad := range []string{"ftp://x/a", "https:///a", "https://u:p@x/a", "https://x/a?q=1", "https://x/a#f", "auth"} {
		if _, _, err := CheckWebAuthEndpoint(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if !IsValidHomeDomain("10.0.2.2:8084") || IsValidHomeDomain("Upper.example") || IsValidHomeDomain("x:0") {
		t.Error("home domain pattern")
	}
}
