package sep10

import (
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestParseTOMLRecorded reads the stellar.toml recorded from SDF's reference
// anchor (testanchor.stellar.org, 2026-11-15): a real file, with arrays,
// [[CURRENCIES]] tables and a [DOCUMENTATION] table, so the reader is tested
// against what servers actually publish rather than a hand-written sample.
func TestParseTOMLRecorded(t *testing.T) {
	raw, err := os.ReadFile("testdata/testanchor_stellar.toml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTOML(raw)
	if err != nil {
		t.Fatalf("ParseTOML: %v", err)
	}
	want := TOML{
		WebAuthEndpoint:   "https://testanchor.stellar.org/auth",
		SigningKey:        "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR",
		NetworkPassphrase: "Test SDF Network ; September 2015",
	}
	if got != want {
		t.Errorf("ParseTOML = %+v, want %+v", got, want)
	}
}

func TestParseTOMLSyntax(t *testing.T) {
	const key = "GCHLHDBOKG2JWMJQBTLSL5XG6NO7ESXI2TAQKZXCXWXB5WI2X6W233PR"
	cases := []struct {
		name string
		doc  string
		want TOML
	}{
		{"literal strings and comments", "# hi\nSIGNING_KEY = '" + key + "' # trailing\r\nWEB_AUTH_ENDPOINT='https://a.example/auth'\n",
			TOML{SigningKey: key, WebAuthEndpoint: "https://a.example/auth"}},
		{"escapes", `NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"` + "\n",
			TOML{NetworkPassphrase: "Test SDF Network ; September 2015"}},
		{"quoted key", `"SIGNING_KEY" = "` + key + `"`, TOML{SigningKey: key}},
		{"multi-line string hides a look-alike key",
			"DESC = \"\"\"\nSIGNING_KEY = \"GXXX\"\n\"\"\"\nSIGNING_KEY = \"" + key + "\"\n", TOML{SigningKey: key}},
		{"multi-line literal", "DESC = '''\nWEB_AUTH_ENDPOINT = \"x\"\n'''\n", TOML{}},
		{"multi-line array with brackets in strings",
			"ACCOUNTS = [\n  \"]\", # comment ]\n  \"G2\",\n]\nSIGNING_KEY = \"" + key + "\"\n", TOML{SigningKey: key}},
		{"inline table", "X = { a = \"}\", b = [1, 2] }\nSIGNING_KEY = \"" + key + "\"\n", TOML{SigningKey: key}},
		{"dotted key is not ours", "a.SIGNING_KEY = \"x\"\n", TOML{}},
		{"keys after a table header are not root keys", "[DOCUMENTATION]\nSIGNING_KEY = \"" + key + "\"\n", TOML{}},
		{"bare scalars", "VERSION = 2\nOK = true\nAT = 1979-05-27 07:32:00Z\nSIGNING_KEY = \"" + key + "\"", TOML{SigningKey: key}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTOML([]byte(tc.doc))
			if err != nil {
				t.Fatalf("ParseTOML: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseTOMLFailsClosed(t *testing.T) {
	cases := map[string]string{
		"duplicate key":        "SIGNING_KEY = \"a\"\nSIGNING_KEY = \"b\"\n",
		"non-string value":     "WEB_AUTH_ENDPOINT = 42\n",
		"multi-line value":     "SIGNING_KEY = \"\"\"\nG\n\"\"\"\n",
		"unterminated string":  "SIGNING_KEY = \"GABC\n",
		"unterminated array":   "A = [1, 2\n",
		"missing equals":       "SIGNING_KEY \"x\"\n",
		"text after value":     "SIGNING_KEY = \"x\" y\n",
		"bad escape":           `SIGNING_KEY = "\q"`,
		"invalid utf-8":        "SIGNING_KEY = \"\xff\"\n",
		"unterminated literal": "DESC = '''\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseTOML([]byte(doc)); err == nil {
				t.Errorf("ParseTOML accepted %q: %+v", doc, got)
			}
		})
	}
}

func TestValidateHomeDomain(t *testing.T) {
	for _, ok := range []string{"testanchor.stellar.org", "localhost:8000", "127.0.0.1:8080", "10.0.2.2:8084", "[::1]:8000"} {
		if err := ValidateHomeDomain(ok); err != nil {
			t.Errorf("ValidateHomeDomain(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "https://testanchor.stellar.org", "a.example/auth", "user@a.example", "a.example?x", "a b", strings.Repeat("a", 60)} {
		if err := ValidateHomeDomain(bad); err == nil {
			t.Errorf("ValidateHomeDomain(%q) = nil, want an error", bad)
		}
	}
}

func TestTransportPolicy(t *testing.T) {
	if got := TOMLURL("testanchor.stellar.org"); got != "https://testanchor.stellar.org/.well-known/stellar.toml" {
		t.Errorf("TOMLURL = %q", got)
	}
	if got := TOMLURL("10.0.2.2:8084"); !strings.HasPrefix(got, "https://") {
		t.Errorf("a non-loopback home domain must be fetched over https, got %q", got)
	}
	for _, d := range []string{"localhost:8000", "127.0.0.1:8080", "[::1]:9"} {
		if got := TOMLURL(d); !strings.HasPrefix(got, "http://") {
			t.Errorf("TOMLURL(%q) = %q, want plain http for loopback", d, got)
		}
	}
	accept := []string{"https://a.example/auth", "http://localhost:8000/auth", "http://127.0.0.2/auth", "http://[::1]:8000/auth"}
	refuse := []string{"http://a.example/auth", "http://10.0.2.2:8084/auth/sep10", "ftp://a.example/auth", "http://localhost.evil.example/auth"}
	for _, raw := range accept {
		u, _ := url.Parse(raw)
		if err := checkTransport(u); err != nil {
			t.Errorf("checkTransport(%s) = %v, want nil", raw, err)
		}
	}
	for _, raw := range refuse {
		u, _ := url.Parse(raw)
		if err := checkTransport(u); err == nil {
			t.Errorf("checkTransport(%s) = nil, want a refusal", raw)
		}
	}
}

func TestWebAuthDomain(t *testing.T) {
	cases := map[string]string{
		"https://testanchor.stellar.org/auth":     "testanchor.stellar.org",
		"https://a.example:443/auth":              "a.example",
		"https://a.example:8443/auth":             "a.example:8443",
		"http://127.0.0.1:8084/auth/sep10":        "127.0.0.1:8084",
		"http://localhost:80/auth":                "localhost",
		"https://[2001:db8::1]/auth":              "[2001:db8::1]",
		"https://[2001:db8::1]:8443/auth?x=1#top": "[2001:db8::1]:8443",
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := webAuthDomain(u); got != want {
			t.Errorf("webAuthDomain(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseClaims(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	tok := enc(`{"alg":"HS256"}`) + "." + enc(`{"iss":"https://a.example/auth","sub":"GABC","iat":1700000000,"exp":1700000300.5,"jti":"x"}`) + ".sig"
	c, ok := ParseClaims(tok)
	if !ok {
		t.Fatal("ParseClaims rejected a JWT")
	}
	if c.Issuer != "https://a.example/auth" || c.Subject != "GABC" || c.IssuedAt == nil || *c.IssuedAt != 1700000000 || c.Expires == nil || *c.Expires != 1700000300 {
		t.Errorf("claims = %+v", c)
	}
	// Wrongly typed claims are left empty, not guessed.
	c, ok = ParseClaims(enc(`{}`) + "." + enc(`{"iss":7,"sub":["G"],"exp":"soon"}`) + ".s")
	if !ok || c.Issuer != "" || c.Subject != "" || c.Expires != nil {
		t.Errorf("mistyped claims = %+v, %v", c, ok)
	}
	for _, notJWT := range []string{"opaque-token", "a.b", "a.!!!.c", "a." + enc("[1]") + ".c"} {
		if _, ok := ParseClaims(notJWT); ok {
			t.Errorf("ParseClaims(%q) ok, want not a JWT", notJWT)
		}
	}
}

func TestCheckTokenShape(t *testing.T) {
	if err := checkTokenShape("eyJ.abc-_.x"); err != nil {
		t.Errorf("checkTokenShape(jwt) = %v", err)
	}
	for _, bad := range []string{"tok3n secret", "tok3n\nsecret", "tok3n\x1b[2Jsecret", "tok3né", strings.Repeat("a", maxTokenBytes+1)} {
		err := checkTokenShape(bad)
		if err == nil {
			t.Errorf("checkTokenShape(%q) = nil, want a refusal", bad)
			continue
		}
		if strings.Contains(err.Error(), "tok3n") {
			t.Errorf("the refusal echoes the token: %v", err)
		}
	}
}

func TestPrintable(t *testing.T) {
	if got := Printable("ok\x1b[31m‮"); got != "ok?[31m?" {
		t.Errorf("Printable = %q", got)
	}
}
