package bridge

import (
	"context"
	"net/url"
)

// Multi-factor sign-in (docs/mfa-card-pin-biometrics.md §5; shapes from
// impala-bridge/src/mfa/handlers.rs and src/handlers/mfa.rs).
//
// The step-up, challenge and status routes are reachable by a session that
// is required to be multi-factor but is not yet; every other route answers
// such a session 403 mfa_required.

// MFAStatus returns the current session's assurance (GET /mfa/status).
func (c *Client) MFAStatus(ctx context.Context) (*MFAStatus, []byte, error) {
	var out MFAStatus
	raw, err := c.get(ctx, "/mfa/status", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// MFAChallenge issues a single-use step-up / enrollment challenge bound to
// the caller's account (POST /mfa/challenge): 32 bytes, 120 s, at most three
// outstanding.
func (c *Client) MFAChallenge(ctx context.Context) (*MFAChallenge, []byte, error) {
	var out MFAChallenge
	raw, err := c.post(ctx, "/mfa/challenge", struct{}{}, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// StepUp adds one factor to the current session (POST /mfa/step-up). For a
// bearer session the bridge revokes the presented token family BEFORE it
// mints the new pair, so a successful answer must be persisted before any
// further request.
func (c *Client) StepUp(ctx context.Context, req StepUpRequest) (*StepUpResponse, []byte, error) {
	var out StepUpResponse
	raw, err := c.post(ctx, "/mfa/step-up", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// EnrollMFA enrolls (or re-enrolls, replacing the secret) an MFA method
// (POST /mfa). For TOTP the reply carries the otpauth provisioning URI,
// which holds the shared secret; the enrollment is active immediately.
func (c *Client) EnrollMFA(ctx context.Context, req EnrollMFARequest) (*MFAResponse, []byte, error) {
	var out MFAResponse
	raw, err := c.post(ctx, "/mfa", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// ListMFA lists an account's enrollments without their secrets
// (GET /mfa?account_id=…, owner only).
func (c *Client) ListMFA(ctx context.Context, accountID string) ([]MFAEnrollment, []byte, error) {
	var out []MFAEnrollment
	raw, err := c.get(ctx, "/mfa", url.Values{"account_id": {accountID}}, &out)
	if err != nil {
		return nil, raw, err
	}
	return out, raw, nil
}

// ListDeviceKeys returns the caller's active device keys (GET /mfa/device-keys).
func (c *Client) ListDeviceKeys(ctx context.Context) ([]DeviceKey, []byte, error) {
	var out []DeviceKey
	raw, err := c.get(ctx, "/mfa/device-keys", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return out, raw, nil
}

// EnrollDeviceKey registers a device key after its proof of possession
// (POST /mfa/device-keys).
func (c *Client) EnrollDeviceKey(ctx context.Context, req EnrollDeviceKeyRequest) (*EnrollDeviceKeyResponse, []byte, error) {
	var out EnrollDeviceKeyResponse
	raw, err := c.post(ctx, "/mfa/device-keys", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// DeleteDeviceKey revokes one of the caller's device keys
// (DELETE /mfa/device-keys/{key_id}).
func (c *Client) DeleteDeviceKey(ctx context.Context, keyID string) (*Result, []byte, error) {
	var out Result
	raw, err := c.del(ctx, "/mfa/device-keys/"+url.PathEscape(keyID), &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// AdminAccountMFA returns an account's factor summary, no secrets
// (GET /admin/accounts/{id}/mfa, accounts-read capability).
func (c *Client) AdminAccountMFA(ctx context.Context, accountID string) (*AdminMFAView, []byte, error) {
	var out AdminMFAView
	raw, err := c.get(ctx, "/admin/accounts/"+url.PathEscape(accountID)+"/mfa", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// AdminSetMFAPolicy mandates (or lifts) MFA for an account
// (PUT /admin/accounts/{id}/mfa-policy, admin). Mandating bumps the
// account's auth epoch: every token and session it holds stops working.
func (c *Client) AdminSetMFAPolicy(ctx context.Context, accountID string, required bool) (*MFAPolicyResponse, []byte, error) {
	var out MFAPolicyResponse
	raw, err := c.put(ctx, "/admin/accounts/"+url.PathEscape(accountID)+"/mfa-policy",
		MFAPolicyRequest{Required: required}, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// AdminDeleteDeviceKey revokes an account's device key: recovery for a lost
// device (DELETE /admin/accounts/{id}/mfa/device-keys/{key_id}, admin).
func (c *Client) AdminDeleteDeviceKey(ctx context.Context, accountID, keyID string) (*Result, []byte, error) {
	var out Result
	raw, err := c.del(ctx, "/admin/accounts/"+url.PathEscape(accountID)+"/mfa/device-keys/"+url.PathEscape(keyID), &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// ── Wire types (mirror impala-bridge/src/mfa/handlers.rs, models.rs) ───

// MFAStatus is GET /mfa/status.
type MFAStatus struct {
	Amr      []string `json:"amr"`
	AuthTime int64    `json:"auth_time"`
	// MFA: multi-factor AND verified within MaxAgeSecs.
	MFA            bool  `json:"mfa"`
	Required       bool  `json:"required"`
	RequiredByRole bool  `json:"required_by_role"`
	Satisfied      bool  `json:"satisfied"`
	MaxAgeSecs     int64 `json:"max_age_secs"`
}

// MFAChallenge is POST /mfa/challenge: 64 hex characters.
type MFAChallenge struct {
	Challenge string `json:"challenge"`
	ExpiresIn int64  `json:"expires_in"`
}

// Step-up types (mfa_type).
const (
	StepUpTOTP   = "totp"
	StepUpDevice = "device"
)

// StepUpRequest is POST /mfa/step-up. TOTP sends Code; a device key sends
// Challenge, KeyID and DeviceSignature (hex DER).
type StepUpRequest struct {
	MFAType         string `json:"mfa_type"`
	Code            string `json:"code,omitempty"`
	Challenge       string `json:"challenge,omitempty"`
	KeyID           string `json:"key_id,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
}

// StepUpResponse is the step-up reply: the new amr and, for a bearer
// session, a token pair in a new family.
type StepUpResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	Amr           []string `json:"amr"`
	RefreshToken  string   `json:"refresh_token"`
	TemporalToken string   `json:"temporal_token"`
}

// EnrollMFARequest is POST /mfa.
type EnrollMFARequest struct {
	AccountID string `json:"account_id"`
	MFAType   string `json:"mfa_type"`
}

// MFAResponse is the reply to POST /mfa.
type MFAResponse struct {
	Result
	ProvisioningURI string `json:"provisioning_uri,omitempty"`
}

// MFAEnrollment is one row of GET /mfa: state, never the factor itself.
type MFAEnrollment struct {
	AccountID  string `json:"account_id"`
	MFAType    string `json:"mfa_type"`
	Enabled    bool   `json:"enabled"`
	Configured bool   `json:"configured"`
}

// DeviceKey is one registered device key (public data only).
type DeviceKey struct {
	KeyID            string  `json:"key_id"`
	Label            *string `json:"label"`
	Platform         *string `json:"platform"`
	UserVerification string  `json:"user_verification"`
	CreatedAtUnix    int64   `json:"created_at_unix"`
}

// EnrollDeviceKeyRequest is POST /mfa/device-keys. PublicKey is the 65-byte
// uncompressed P-256 point as 130 hex; Signature the hex DER ECDSA-SHA256
// over the enroll-purpose device message for Challenge.
type EnrollDeviceKeyRequest struct {
	PublicKey        string `json:"public_key"`
	Label            string `json:"label,omitempty"`
	Platform         string `json:"platform,omitempty"`
	UserVerification string `json:"user_verification"`
	Challenge        string `json:"challenge"`
	Signature        string `json:"signature"`
}

// EnrollDeviceKeyResponse is the enrollment reply.
type EnrollDeviceKeyResponse struct {
	Success bool   `json:"success"`
	KeyID   string `json:"key_id"`
}

// MFAPolicyRequest is the body of the policy routes.
type MFAPolicyRequest struct {
	Required bool `json:"required"`
}

// MFAPolicyResponse is the policy routes' reply.
type MFAPolicyResponse struct {
	Success  bool `json:"success"`
	Required bool `json:"required"`
}

// AdminMFAView is GET /admin/accounts/{id}/mfa.
type AdminMFAView struct {
	AccountID    string      `json:"account_id"`
	MFARequired  bool        `json:"mfa_required"`
	TOTPEnrolled bool        `json:"totp_enrolled"`
	DeviceKeys   []DeviceKey `json:"device_keys"`
	Cards        int64       `json:"cards"`
}
