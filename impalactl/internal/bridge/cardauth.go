package bridge

import "context"

// Legacy card sign-in (POST /auth/card/challenge + POST /auth/card; shapes
// from impala-bridge/src/handlers/card_auth.rs and models.rs). The card
// signs "IMPALA-AUTH:" ‖ accountId(16) ‖ challenge with its P-256 key
// (SIGN_AUTH). Both routes are unauthenticated.

// CardChallenge asks for a single-use 32-byte challenge for a card. It is
// issued whether or not the card is registered.
func (c *Client) CardChallenge(ctx context.Context, cardID string) (*CardChallengeResponse, []byte, error) {
	var out CardChallengeResponse
	raw, err := c.post(ctx, "/auth/card/challenge", CardChallengeRequest{CardID: cardID}, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// CardToken exchanges the card's signature (and the optional MFA extras over
// the same challenge) for a token pair.
func (c *Client) CardToken(ctx context.Context, req CardTokenRequest) (*TokenResponse, []byte, error) {
	var out TokenResponse
	raw, err := c.post(ctx, "/auth/card", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// CardChallengeRequest is POST /auth/card/challenge.
type CardChallengeRequest struct {
	CardID string `json:"card_id"`
}

// CardChallengeResponse carries 32 random bytes as 64 hex characters.
type CardChallengeResponse struct {
	Success   bool   `json:"success"`
	Challenge string `json:"challenge"`
	ExpiresIn int64  `json:"expires_in"`
}

// CardTokenRequest is POST /auth/card: hex DER signatures.
type CardTokenRequest struct {
	CardID          string `json:"card_id"`
	Signature       string `json:"signature"`
	PinProof        string `json:"pin_proof,omitempty"`
	DeviceKeyID     string `json:"device_key_id,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
}
