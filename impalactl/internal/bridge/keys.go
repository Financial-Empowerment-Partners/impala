package bridge

import (
	"context"
	"fmt"
	"net/url"
)

// Bridge key management (/admin/keys/*, /admin/stellar-seeds/*).
//
// These calls install the credentials the bridge uses to move money. The CLI
// is the preferred surface for them because it can read a secret from a file,
// stdin, or a no-echo prompt — never from argv, and never through a browser.
//
// Note what the API does NOT return: no request or response here carries key
// material in the outbound direction. Fingerprints are one-way digests, and
// RSA keys are fingerprinted through their public half.

// ListKeys returns the credential inventory (GET /admin/keys, admin only):
// what the bridge instance answering the request is actually running, what is
// stored, and whether they differ.
func (c *Client) ListKeys(ctx context.Context) (*KeyListResponse, []byte, error) {
	var out KeyListResponse
	raw, err := c.get(ctx, "/admin/keys", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ImportKey stores a provider credential set (POST /admin/keys/{kind}).
// Adds by default; replacing something already in effect requires Replace,
// ExpectedFingerprint and ConfirmPhrase together.
func (c *Client) ImportKey(ctx context.Context, kind string, req ImportKeyRequest) (*KeyActionResponse, []byte, error) {
	var out KeyActionResponse
	raw, err := c.post(ctx, "/admin/keys/"+url.PathEscape(kind), req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// RevokeKey deactivates a stored credential and scrubs its ciphertext
// (POST /admin/keys/{kind}/revoke). It does NOT revoke the key at the
// provider — do that there first if it is compromised.
func (c *Client) RevokeKey(ctx context.Context, kind string, req RevokeKeyRequest) (*KeyActionResponse, []byte, error) {
	var out KeyActionResponse
	raw, err := c.post(ctx, "/admin/keys/"+url.PathEscape(kind)+"/revoke", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GenerateSeed provisions a custodial seed the bridge creates itself
// (POST /admin/stellar-seeds/generate). The only way to provision the
// conversion-reserve account, whose seed must never pass through a human.
func (c *Client) GenerateSeed(ctx context.Context, req GenerateSeedRequest) (*SeedResponse, []byte, error) {
	var out SeedResponse
	raw, err := c.post(ctx, "/admin/stellar-seeds/generate", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ImportSeed brings an existing secret seed under custody
// (POST /admin/stellar-seeds/import). Refused for the reserve account, and a
// replacement may never change the account's Stellar address.
func (c *Client) ImportSeed(ctx context.Context, req ImportSeedRequest) (*SeedResponse, []byte, error) {
	var out SeedResponse
	raw, err := c.post(ctx, "/admin/stellar-seeds/import", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ── Wire types (mirror impala-bridge/src/models.rs) ────────────────────

// KeyListResponse is GET /admin/keys.
type KeyListResponse struct {
	Enabled           bool      `json:"enabled"`
	ProtectionBackend string    `json:"protection_backend"`
	Degraded          bool      `json:"degraded"`
	Keys              []KeyView `json:"keys"`
}

// Find returns the view for one credential kind.
func (r *KeyListResponse) Find(kind string) (*KeyView, error) {
	for i := range r.Keys {
		if r.Keys[i].Kind == kind {
			return &r.Keys[i], nil
		}
	}
	var names []string
	for i := range r.Keys {
		names = append(names, r.Keys[i].Kind)
	}
	return nil, fmt.Errorf("unknown credential kind %q (known: %v)", kind, names)
}

// KeyView is one credential kind: running, stored, and the gap between them.
type KeyView struct {
	Kind          string   `json:"kind"`
	Parts         []string `json:"parts"`
	RequiredParts []string `json:"required_parts"`
	// EffectiveSource is env | db | unconfigured, for the instance that
	// answered — resolution is fixed at that process's startup.
	EffectiveSource        string            `json:"effective_source"`
	EffectiveFingerprint   string            `json:"effective_fingerprint,omitempty"`
	EffectiveVersion       *int              `json:"effective_version,omitempty"`
	Active                 bool              `json:"active"`
	ResolutionError        string            `json:"resolution_error,omitempty"`
	ShadowedEnvFingerprint string            `json:"shadowed_env_fingerprint,omitempty"`
	EnvVarsSet             []string          `json:"env_vars_set"`
	StoredState            string            `json:"stored_state,omitempty"`
	StoredVersion          *int              `json:"stored_version,omitempty"`
	StoredFingerprint      string            `json:"stored_fingerprint,omitempty"`
	PerPartFingerprints    map[string]string `json:"per_part_fingerprints"`
	ImportedBy             string            `json:"imported_by,omitempty"`
	ImportedAt             string            `json:"imported_at,omitempty"`
	Note                   string            `json:"note,omitempty"`
	// ReplaceTargetFingerprint is the fingerprint a replacement would
	// supersede: the stored credential if there is one, otherwise whatever the
	// instance is running. It is what ExpectedFingerprint must equal — read
	// from here rather than chosen between the other two, because a credential
	// can be stored without yet being the one in use.
	ReplaceTargetFingerprint string `json:"replace_target_fingerprint,omitempty"`
	// ConfirmPhrase is the exact phrase a replacement or revoke must echo,
	// present whenever either is possible. Served by the bridge rather than
	// rebuilt here: a client that composed it itself could drift from the
	// server and hand operators a phrase that is always rejected.
	ConfirmPhrase  string `json:"confirm_phrase,omitempty"`
	PendingRestart bool   `json:"pending_restart"`
	InFlightCount  int64  `json:"in_flight_count"`
}

// IsReplacement reports whether importing into this kind would replace
// something rather than add it. Keyed off the bridge's own replace target, so
// it is true both for a credential the deployment supplies (live, no stored
// row) and for one that is stored but not yet activated (a row, nothing
// running) — the latter being the case a naive "is anything running?" check
// gets wrong.
func (v *KeyView) IsReplacement() bool { return v.ReplaceTargetFingerprint != "" }

// ImportKeyRequest is POST /admin/keys/{kind}.
type ImportKeyRequest struct {
	Parts               map[string]string `json:"parts"`
	Replace             bool              `json:"replace,omitempty"`
	ExpectedFingerprint string            `json:"expected_fingerprint,omitempty"`
	ConfirmPhrase       string            `json:"confirm_phrase,omitempty"`
	StrandInFlight      bool              `json:"strand_in_flight,omitempty"`
	SkipVerify          bool              `json:"skip_verify,omitempty"`
	Note                string            `json:"note,omitempty"`
}

// RevokeKeyRequest is POST /admin/keys/{kind}/revoke.
type RevokeKeyRequest struct {
	ExpectedFingerprint string `json:"expected_fingerprint"`
	ConfirmPhrase       string `json:"confirm_phrase,omitempty"`
	ConfirmNextSource   bool   `json:"confirm_next_source,omitempty"`
	StrandInFlight      bool   `json:"strand_in_flight,omitempty"`
}

// KeyActionResponse is the reply to every mutating key call.
type KeyActionResponse struct {
	Result
	Kind           string `json:"kind"`
	Version        *int   `json:"version,omitempty"`
	SetFingerprint string `json:"set_fingerprint,omitempty"`
	// EffectiveAfter is "rolling_restart" for credential changes: stored
	// credentials are resolved once per process, so nothing changes until
	// every task restarts.
	EffectiveAfter string `json:"effective_after"`
	VerifyNote     string `json:"verify_note,omitempty"`
	EnvShadowNote  string `json:"env_shadow_note,omitempty"`
}

// GenerateSeedRequest is POST /admin/stellar-seeds/generate.
type GenerateSeedRequest struct {
	PayalaAccountID string `json:"payala_account_id"`
	Label           string `json:"label,omitempty"`
}

// ImportSeedRequest is POST /admin/stellar-seeds/import.
type ImportSeedRequest struct {
	PayalaAccountID          string `json:"payala_account_id"`
	SecretSeed               string `json:"secret_seed"`
	Replace                  bool   `json:"replace,omitempty"`
	ExpectedStellarAccountID string `json:"expected_stellar_account_id,omitempty"`
	ConfirmPhrase            string `json:"confirm_phrase,omitempty"`
	SkipVerify               bool   `json:"skip_verify,omitempty"`
}

// SeedProbe is what Horizon says about the account a submitted seed derives.
type SeedProbe struct {
	Exists bool `json:"exists"`
	// MasterKeyWeight of 0 means the key was disabled on chain and can
	// authorize nothing, however valid the strkey looks.
	MasterKeyWeight   *int64 `json:"master_key_weight,omitempty"`
	NativeBalance     string `json:"native_balance,omitempty"`
	NonNativeBalances int64  `json:"non_native_balances"`
}

// SeedResponse is the reply to both custodial-seed calls.
type SeedResponse struct {
	Result
	StellarAccountID string     `json:"stellar_account_id,omitempty"`
	OnChain          *SeedProbe `json:"on_chain,omitempty"`
	EffectiveAfter   string     `json:"effective_after"`
}
