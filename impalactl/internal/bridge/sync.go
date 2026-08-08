package bridge

import (
	"context"
	"net/url"
)

// ForceSync records a sync timestamp for a Stellar account and reconciles the
// configured Soroban RPC's transactions against the local ledger
// (POST /sync). Admin only.
func (c *Client) ForceSync(ctx context.Context, stellarAccountID string) (*SyncResponse, []byte, error) {
	var out SyncResponse
	raw, err := c.post(ctx, "/sync", SyncRequest{AccountID: stellarAccountID}, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// SyncProfile forces a directory re-pull of an account's profile
// (POST /admin/accounts/{id}/sync-profile). Admin only, and only meaningful
// for LDAP-sourced profiles — Okta and local profiles are rejected with a 400.
func (c *Client) SyncProfile(ctx context.Context, payalaAccountID string) (*SyncProfileResponse, []byte, error) {
	var out SyncProfileResponse
	path := "/admin/accounts/" + url.PathEscape(payalaAccountID) + "/sync-profile"
	raw, err := c.post(ctx, path, nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// SetSyncMode switches an account between reserve and mirror sync
// (PUT /admin/accounts/{id}/sync-mode). Admin only. Flips are forward-only:
// existing balances and mirrored rows are left untouched.
func (c *Client) SetSyncMode(ctx context.Context, payalaAccountID, mode string, force bool) (*SetSyncModeResponse, []byte, error) {
	req := SetSyncModeRequest{SyncMode: mode}
	if force {
		req.Force = &force
	}
	var out SetSyncModeResponse
	path := "/admin/accounts/" + url.PathEscape(payalaAccountID) + "/sync-mode"
	raw, err := c.put(ctx, path, req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// SyncPayala ingests a batch of offline Payala transactions (POST /sync/payala).
// Owner-only, atomic, and idempotent per (account, payala_tx_id).
func (c *Client) SyncPayala(ctx context.Context, req PayalaSyncRequest) (*PayalaSyncResponse, []byte, error) {
	var out PayalaSyncResponse
	raw, err := c.post(ctx, "/sync/payala", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// GetReserves reads an account's Payala reserve balances
// (GET /reserves/{account_id}). Owner or admin.
func (c *Client) GetReserves(ctx context.Context, payalaAccountID string) (*ReserveBalancesResponse, []byte, error) {
	var out ReserveBalancesResponse
	raw, err := c.get(ctx, "/reserves/"+url.PathEscape(payalaAccountID), nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}
