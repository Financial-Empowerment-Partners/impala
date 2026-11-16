package bridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims are the JWT claims the CLI reads locally.
//
// They are decoded WITHOUT verifying the signature: the CLI has no access to
// JWT_SECRET, and it doesn't need one. These values drive display (whoami) and
// the "should I refresh before sending this?" decision only. The bridge
// remains the sole authority on whether a token is valid — never make an
// access-control decision from these fields.
type Claims struct {
	Subject   string `json:"sub"`
	TokenType string `json:"token_type"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	TokenID   string `json:"jti"`
	FamilyID  string `json:"fid"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	// Amr is the session's verified authentication methods, sorted, with the
	// derived "mfa" present when they span two factor kinds
	// (docs/mfa-card-pin-biometrics.md §2). Absent in tokens minted before
	// MFA support: an empty list, never multi-factor.
	Amr []string `json:"amr"`
	// AuthTime is the Unix time of the session's most recent factor
	// verification. A step-up refreshes it; a refresh rotation carries it.
	AuthTime int64 `json:"auth_time"`
	// MFARequired ("mfr") says the account must be multi-factor to use the
	// API, stamped at issuance from the account flag or MFA_REQUIRED_ROLES.
	MFARequired bool `json:"mfr"`
}

// AMRMultiFactor is the derived amr value the bridge adds when a session's
// factors span two factor kinds. It is never an input.
const AMRMultiFactor = "mfa"

// HasMFA reports whether the token's amr carries the multi-factor marker.
// The bridge additionally requires auth_time to be within MFA_MAX_AGE_SECS
// (default 12 h), which the client does not know; GET /mfa/status is the
// authoritative answer.
func (c Claims) HasMFA() bool {
	for _, m := range c.Amr {
		if m == AMRMultiFactor {
			return true
		}
	}
	return false
}

// AuthTimeAt returns auth_time as a time, or the zero time when absent.
func (c Claims) AuthTimeAt() time.Time {
	if c.AuthTime <= 0 {
		return time.Time{}
	}
	return time.Unix(c.AuthTime, 0).UTC()
}

// ParseClaims decodes the payload of a JWT without verifying it.
func ParseClaims(token string) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a JWT (expected three dot-separated segments)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("parse JWT payload: %w", err)
	}
	return claims, nil
}

// Expiry returns the token's expiry as a time, or the zero time when the token
// carries no exp claim.
func (c Claims) Expiry() time.Time {
	if c.ExpiresAt == 0 {
		return time.Time{}
	}
	return time.Unix(c.ExpiresAt, 0).UTC()
}

// ExpiresWithin reports whether the token is already expired or will expire
// within skew of now. A token with no exp claim is treated as expired: better
// to refresh needlessly than to send a token the bridge will reject.
func (c Claims) ExpiresWithin(now time.Time, skew time.Duration) bool {
	if c.ExpiresAt == 0 {
		return true
	}
	return !c.Expiry().After(now.Add(skew))
}
