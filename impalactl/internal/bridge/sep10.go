package bridge

import (
	"context"
	"net/url"
	"strconv"
)

// SEP-10 operator surface (docs/sep10-api-and-admin-ui.md §4; shapes from
// impala-bridge/src/handlers/admin_sep10.rs and models.rs). The server
// signing key is generate-only: no request or response here carries key
// material, only public addresses and fingerprints.

// Sep10Status returns the status object (GET /admin/sep10/signing-keys,
// ReadKeys: admin, key-custodian, auditor). It describes the instance that
// answered.
func (c *Client) Sep10Status(ctx context.Context) (*Sep10Status, []byte, error) {
	var out Sep10Status
	raw, err := c.get(ctx, "/admin/sep10/signing-keys", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GenerateSep10Key creates a pending signing key version
// (POST /admin/sep10/signing-keys/generate, ManageKeys; 201).
func (c *Client) GenerateSep10Key(ctx context.Context) (*Sep10KeyAction, []byte, error) {
	var out Sep10KeyAction
	raw, err := c.post(ctx, "/admin/sep10/signing-keys/generate", struct{}{}, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ActivateSep10Key schedules a pending version to take over
// (POST /admin/sep10/signing-keys/{version}/activate).
func (c *Client) ActivateSep10Key(ctx context.Context, version int, req ActivateSep10KeyRequest) (*Sep10KeyAction, []byte, error) {
	var out Sep10KeyAction
	raw, err := c.post(ctx, "/admin/sep10/signing-keys/"+strconv.Itoa(version)+"/activate", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// RevokeSep10Key revokes a version at once
// (POST /admin/sep10/signing-keys/{version}/revoke).
func (c *Client) RevokeSep10Key(ctx context.Context, version int, req RevokeSep10KeyRequest) (*Sep10KeyAction, []byte, error) {
	var out Sep10KeyAction
	raw, err := c.post(ctx, "/admin/sep10/signing-keys/"+strconv.Itoa(version)+"/revoke", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// AccountCards lists an account's cards with their Stellar addresses
// (GET /admin/accounts/{account_id}/cards, ReadAccounts).
func (c *Client) AccountCards(ctx context.Context, accountID string) (*AdminCardList, []byte, error) {
	var out AdminCardList
	raw, err := c.get(ctx, "/admin/accounts/"+url.PathEscape(accountID)+"/cards", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// StellarToml fetches GET /.well-known/stellar.toml from the endpoint (public;
// mounted only while SEP10_ENABLED). A non-2xx answer is an APIError whose
// Status the caller reads (404 or 503: SEP-10 is not offered).
func (c *Client) StellarToml(ctx context.Context) ([]byte, error) {
	return c.get(ctx, "/.well-known/stellar.toml", nil, nil)
}

// ── Wire types ─────────────────────────────────────────────────────────

// Sep10Status is GET /admin/sep10/signing-keys.
type Sep10Status struct {
	Enabled            bool           `json:"enabled"`
	HomeDomain         *string        `json:"home_domain"`
	WebAuthEndpoint    *string        `json:"web_auth_endpoint"`
	Network            string         `json:"network"`
	NetworkPassphrase  string         `json:"network_passphrase"`
	ChallengeTTLSecs   int64          `json:"challenge_ttl_secs"`
	RegisteredCardKeys int64          `json:"registered_card_keys"`
	KeyRingLive        *bool          `json:"key_ring_live"`
	Keys               []Sep10KeyView `json:"keys"`
}

// Find returns the key with the given version, or nil.
func (s *Sep10Status) Find(version int) *Sep10KeyView {
	for i := range s.Keys {
		if s.Keys[i].Version == version {
			return &s.Keys[i]
		}
	}
	return nil
}

// Active returns every key in state "active" (exactly one in a healthy
// deployment).
func (s *Sep10Status) Active() []*Sep10KeyView {
	var out []*Sep10KeyView
	for i := range s.Keys {
		if s.Keys[i].State == "active" {
			out = append(out, &s.Keys[i])
		}
	}
	return out
}

// Sep10KeyView is one signing key version.
type Sep10KeyView struct {
	Version       int     `json:"version"`
	State         string  `json:"state"`
	PublicAddress string  `json:"public_address"`
	Fingerprint   string  `json:"fingerprint"`
	GeneratedBy   string  `json:"generated_by"`
	GeneratedAt   string  `json:"generated_at"`
	ActivateAt    *string `json:"activate_at"`
	SupersededAt  *string `json:"superseded_at"`
	RevokedAt     *string `json:"revoked_at"`
	// Opened: whether the answering instance holds this version open; nil
	// when it runs no key ring or the version is revoked.
	Opened *bool `json:"opened"`
}

// Sep10KeyAction is the reply to generate, activate and revoke.
type Sep10KeyAction struct {
	Version       int    `json:"version"`
	State         string `json:"state"`
	PublicAddress string `json:"public_address,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	ActivateAt    string `json:"activate_at,omitempty"`
}

// ActivateSep10KeyRequest is the activation body: ConfirmSupersede is the
// active key's fingerprint (or "none"), ConfirmPhrase
// "activate sep10-signing <network>".
type ActivateSep10KeyRequest struct {
	ConfirmSupersede string `json:"confirm_supersede"`
	ConfirmPhrase    string `json:"confirm_phrase"`
}

// RevokeSep10KeyRequest is the revocation body: ConfirmPhrase
// "revoke sep10-signing <network> v<version>".
type RevokeSep10KeyRequest struct {
	ConfirmPhrase string `json:"confirm_phrase"`
}

// AdminCardList is GET /admin/accounts/{account_id}/cards.
type AdminCardList struct {
	Cards []AdminCard `json:"cards"`
}

// AdminCard is one card: public data only.
type AdminCard struct {
	CardID         string  `json:"card_id"`
	Active         bool    `json:"active"`
	CreatedAt      *string `json:"created_at"`
	DeletedAt      *string `json:"deleted_at"`
	StellarAddress *string `json:"stellar_address"`
}
