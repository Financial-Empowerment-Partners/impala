package sep10

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Claims are the standard claims of a SEP-10 JWT, read for display only.
//
// They are NOT verified: the token is signed with the server's secret (or a
// key the client has no reason to know), so a client cannot check it and
// must treat the token as opaque. These are the server's own statements
// about the token it issued, useful to a person reading them and nothing
// more. A field the token lacks, or holds with an unexpected type, is left
// empty rather than guessed.
type Claims struct {
	Issuer   string
	Subject  string
	IssuedAt *int64
	Expires  *int64
}

// ParseClaims decodes the payload of a JWT-shaped token. ok is false when the
// token is not three base64url segments with a JSON object in the middle —
// SEP-10 only requires a JWT, and a server may issue something else.
func ParseClaims(token string) (Claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, false
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return Claims{}, false
	}
	var c Claims
	c.Issuer = stringClaim(m["iss"])
	c.Subject = stringClaim(m["sub"])
	c.IssuedAt = intClaim(m["iat"])
	c.Expires = intClaim(m["exp"])
	return c, true
}

func stringClaim(raw json.RawMessage) string {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func intClaim(raw json.RawMessage) *int64 {
	if raw == nil {
		return nil
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&n) != nil {
		return nil
	}
	v, err := n.Int64()
	if err != nil {
		// NumericDate may be fractional; keep whole seconds.
		f, ferr := n.Float64()
		if ferr != nil || f < 0 || f > 1<<53 {
			return nil
		}
		v = int64(f)
	}
	return &v
}
