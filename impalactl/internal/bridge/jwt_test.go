package bridge

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeToken builds an unsigned JWT-shaped string. The CLI never verifies the
// signature, so a placeholder is enough to exercise claim parsing.
func makeToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestParseClaims(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := makeToken(t, map[string]any{
		"sub": "alice", "role": "admin", "token_type": "temporal",
		"exp": exp, "iat": time.Now().Unix(), "jti": "j1", "fid": "f1",
		"iss": "impala-bridge", "aud": "impala",
	})

	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if claims.Subject != "alice" || claims.Role != "admin" || claims.TokenType != "temporal" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.ExpiresAt != exp {
		t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt, exp)
	}
	if claims.FamilyID != "f1" || claims.TokenID != "j1" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestParseClaimsRejectsMalformed(t *testing.T) {
	for name, token := range map[string]string{
		"empty":           "",
		"not a jwt":       "abcdef",
		"two segments":    "a.b",
		"bad base64":      "a.!!!!.c",
		"payload no json": "a." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c",
	} {
		if _, err := ParseClaims(token); err == nil {
			t.Errorf("ParseClaims(%s) = nil error, want an error", name)
		}
	}
}

func TestClaimsExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	valid := Claims{ExpiresAt: now.Add(10 * time.Minute).Unix()}
	if valid.ExpiresWithin(now, time.Minute) {
		t.Error("a token valid for 10m was reported as expiring within 1m")
	}
	if got, want := valid.Expiry(), now.Add(10*time.Minute).UTC(); !got.Equal(want) {
		t.Errorf("Expiry() = %v, want %v", got, want)
	}

	soon := Claims{ExpiresAt: now.Add(30 * time.Second).Unix()}
	if !soon.ExpiresWithin(now, time.Minute) {
		t.Error("a token expiring in 30s was not reported as expiring within 1m")
	}

	past := Claims{ExpiresAt: now.Add(-time.Second).Unix()}
	if !past.ExpiresWithin(now, 0) {
		t.Error("an expired token was not reported as expired")
	}

	// No exp claim: treat as expired rather than sending a token the bridge
	// will reject.
	none := Claims{}
	if !none.ExpiresWithin(now, 0) {
		t.Error("a token without exp was not treated as expired")
	}
	if !none.Expiry().IsZero() {
		t.Errorf("Expiry() = %v, want the zero time", none.Expiry())
	}
}
