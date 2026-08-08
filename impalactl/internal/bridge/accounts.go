package bridge

import (
	"context"
	"net/url"
	"strconv"
)

// CreateAccount links a Stellar account to a Payala account (POST /account).
// Admins may create any account; a regular caller may only create their own.
func (c *Client) CreateAccount(ctx context.Context, req CreateAccountRequest) (*Result, []byte, error) {
	var out Result
	raw, err := c.post(ctx, "/account", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// GetAccount looks up an account by Stellar address (GET /account).
func (c *Client) GetAccount(ctx context.Context, stellarAccountID string) (*Account, []byte, error) {
	var out Account
	q := url.Values{"stellar_account_id": {stellarAccountID}}
	raw, err := c.get(ctx, "/account", q, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GetAccountOnchain fetches live Horizon state for an account
// (GET /account/onchain). Owner or admin.
func (c *Client) GetAccountOnchain(ctx context.Context, stellarAccountID string) (*OnchainAccount, []byte, error) {
	var out OnchainAccount
	q := url.Values{"stellar_account_id": {stellarAccountID}}
	raw, err := c.get(ctx, "/account/onchain", q, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ListAccountsOptions filters GET /accounts (admin only).
type ListAccountsOptions struct {
	Page    uint64
	PerPage uint64
	// Search matches payala id, Stellar id, first name or last name.
	Search string
}

func (o ListAccountsOptions) query() url.Values {
	q := url.Values{}
	if o.Page > 0 {
		q.Set("page", strconv.FormatUint(o.Page, 10))
	}
	if o.PerPage > 0 {
		q.Set("per_page", strconv.FormatUint(o.PerPage, 10))
	}
	if o.Search != "" {
		q.Set("search", o.Search)
	}
	return q
}

// ListAccounts returns a page of accounts (GET /accounts, admin only).
func (c *Client) ListAccounts(ctx context.Context, opts ListAccountsOptions) (*Page[AccountListItem], []byte, error) {
	var out Page[AccountListItem]
	raw, err := c.get(ctx, "/accounts", opts.query(), &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GenerateManagedAccount creates a custodial account whose seed is generated
// and protected server-side (POST /managed-account/generate). Only the public
// G-address is ever returned.
func (c *Client) GenerateManagedAccount(ctx context.Context, req GenerateManagedAccountRequest) (*ManagedAccountResponse, []byte, error) {
	var out ManagedAccountResponse
	raw, err := c.post(ctx, "/managed-account/generate", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// ImportManagedAccount places an existing Stellar seed under custody
// (POST /managed-account/import).
func (c *Client) ImportManagedAccount(ctx context.Context, req ImportManagedAccountRequest) (*ManagedAccountResponse, []byte, error) {
	var out ManagedAccountResponse
	raw, err := c.post(ctx, "/managed-account/import", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}
