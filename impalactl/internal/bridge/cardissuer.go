package bridge

import (
	"context"
	"net/url"
)

// The card program and card issuance (shapes from impala-bridge
// src/handlers/card_issuer.rs, admin_card_issuer.rs, card.rs and models.rs;
// docs/runbooks/card-issuer.md). The issuer key is generate-only: no request
// or response here carries key material, only public keys and fingerprints.

// CardIssuer reads the public GET /card-issuer (unauthenticated).
func (c *Client) CardIssuer(ctx context.Context) (*CardIssuerInfo, []byte, error) {
	var out CardIssuerInfo
	raw, err := c.get(ctx, "/card-issuer", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GenerateCardIssuer creates (or, with the compare-and-set and the typed
// phrase, rotates) the program issuer key (POST /admin/card-issuer/generate,
// ManageKeys). It is a custody write: one of the operator's 5 per 60 s.
func (c *Client) GenerateCardIssuer(ctx context.Context, req GenerateCardIssuerRequest) (*GenerateCardIssuerResponse, []byte, error) {
	var out GenerateCardIssuerResponse
	raw, err := c.post(ctx, "/admin/card-issuer/generate", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// RegisterCard is POST /card under the holder's token (the bridge allows
// only the account's owner). A success=false envelope is an error.
func (c *Client) RegisterCard(ctx context.Context, req RegisterCardRequest) ([]byte, error) {
	var out Result
	raw, err := c.post(ctx, "/card", req, &out)
	if err != nil {
		return raw, err
	}
	return raw, out.Err()
}

// CertifyCard is POST /admin/cards/{card_id}/certificate (ManageKeys): the
// bridge signs the card's CERT message with the active issuer key. A card
// already certified answers 409 unless Recertify is set. It is a custody
// write: one of the operator's 5 per 60 s.
func (c *Client) CertifyCard(ctx context.Context, cardID string, req CertifyCardRequest) (*CertifyCardResponse, []byte, error) {
	var out CertifyCardResponse
	raw, err := c.post(ctx, "/admin/cards/"+url.PathEscape(cardID)+"/certificate", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// SetCardStellarKey is PUT /card/stellar-key under the holder's token: the
// card's Stellar key with its two cross-signatures. A repeat of the same key
// succeeds.
func (c *Client) SetCardStellarKey(ctx context.Context, req SetCardStellarKeyRequest) ([]byte, error) {
	var out Result
	raw, err := c.put(ctx, "/card/stellar-key", req, &out)
	if err != nil {
		return raw, err
	}
	return raw, out.Err()
}

// ── Wire types ─────────────────────────────────────────────────────────

// CardIssuerInfo is GET /card-issuer: {configured:false}, or the active key.
type CardIssuerInfo struct {
	Configured     bool   `json:"configured"`
	Version        int    `json:"version"`
	PublicKeyHex   string `json:"public_key_hex"`
	Fingerprint    string `json:"fingerprint"`
	RedemptionUUID string `json:"redemption_uuid"`
	ProgramIDHex   string `json:"program_id_hex"`
}

// GenerateCardIssuerRequest is the generate body: empty for the first key;
// a rotation names the active fingerprint and the phrase
// "replace card-issuer <network>".
type GenerateCardIssuerRequest struct {
	ConfirmSupersede string `json:"confirm_supersede,omitempty"`
	ConfirmPhrase    string `json:"confirm_phrase,omitempty"`
}

// GenerateCardIssuerResponse is the generate reply.
type GenerateCardIssuerResponse struct {
	Version        int    `json:"version"`
	PublicKeyHex   string `json:"public_key_hex"`
	Fingerprint    string `json:"fingerprint"`
	RedemptionUUID string `json:"redemption_uuid"`
	ProgramIDHex   string `json:"program_id_hex"`
	Replaced       bool   `json:"replaced"`
	Note           string `json:"note"`
}

// RegisterCardRequest is POST /card: lowercase hex ids and key.
type RegisterCardRequest struct {
	AccountID string `json:"account_id"`
	CardID    string `json:"card_id"`
	ECPubKey  string `json:"ec_pubkey"`
}

// CertifyCardRequest is the certificate body.
type CertifyCardRequest struct {
	Currency       string `json:"currency"`
	CardMinorScale int    `json:"card_minor_scale"`
	Recertify      bool   `json:"recertify,omitempty"`
}

// CertifyCardResponse is the certificate reply.
type CertifyCardResponse struct {
	CardID             string `json:"card_id"`
	IssuerVersion      int    `json:"issuer_version"`
	IssuerCertHex      string `json:"issuer_cert_hex"`
	CertMessageHex     string `json:"cert_message_hex"`
	CertID             string `json:"cert_id"`
	IssuerPublicKeyHex string `json:"issuer_public_key_hex"`
	ProgramIDHex       string `json:"program_id_hex"`
	Currency           string `json:"currency"`
	CardMinorScale     int    `json:"card_minor_scale"`
	Replaced           bool   `json:"replaced"`
}

// SetCardStellarKeyRequest is PUT /card/stellar-key: the binding signature
// as lowercase hex of the trimmed DER, the proof as 128 lowercase hex.
type SetCardStellarKeyRequest struct {
	CardID            string `json:"card_id"`
	StellarAddress    string `json:"stellar_address"`
	StellarBindingSig string `json:"stellar_binding_sig"`
	StellarProofSig   string `json:"stellar_proof_sig"`
}
