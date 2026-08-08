package bridge

import (
	"context"
	"net/url"
	"strconv"
)

// SignAndSubmit signs and submits an XLM payment from a custodial account
// (POST /managed-account/sign). This moves real funds and is irreversible:
// the bridge signs synchronously, submits to the network, and records the
// resulting transaction. Owner-only, and separately rate limited.
func (c *Client) SignAndSubmit(ctx context.Context, req SignSubmitRequest) (*SignSubmitResponse, []byte, error) {
	var out SignSubmitResponse
	raw, err := c.post(ctx, "/managed-account/sign", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// CreateTransaction records a dual-chain transaction (POST /transaction).
// This is bookkeeping only — nothing is submitted on-chain.
func (c *Client) CreateTransaction(ctx context.Context, req CreateTransactionRequest) (*CreateTransactionResponse, []byte, error) {
	var out CreateTransactionResponse
	raw, err := c.post(ctx, "/transaction", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// ListTransactionsOptions filters GET /transactions. Zero-valued fields are
// omitted, so the server's own defaults apply.
type ListTransactionsOptions struct {
	Page    uint64
	PerPage uint64
	// Status is one of unreviewed, cleared, flagged, escalated.
	Status string
	// Flagged filters on the review flag when non-nil.
	Flagged *bool
	// SourceAccount is an exact Stellar G-address.
	SourceAccount string
	// From and To bound created_at (RFC3339); From is inclusive, To exclusive.
	From string
	To   string
	// Query is a free-text search over memo, tx ids, hash and source account.
	Query string
}

func (o ListTransactionsOptions) query() url.Values {
	q := url.Values{}
	if o.Page > 0 {
		q.Set("page", strconv.FormatUint(o.Page, 10))
	}
	if o.PerPage > 0 {
		q.Set("per_page", strconv.FormatUint(o.PerPage, 10))
	}
	if o.Status != "" {
		q.Set("status", o.Status)
	}
	if o.Flagged != nil {
		q.Set("flagged", strconv.FormatBool(*o.Flagged))
	}
	if o.SourceAccount != "" {
		q.Set("source_account", o.SourceAccount)
	}
	if o.From != "" {
		q.Set("from", o.From)
	}
	if o.To != "" {
		q.Set("to", o.To)
	}
	if o.Query != "" {
		q.Set("q", o.Query)
	}
	return q
}

// ListTransactions returns a page of transactions with their review state
// (GET /transactions). Admins see everything; a regular caller sees only
// transactions sourced from accounts they own.
func (c *Client) ListTransactions(ctx context.Context, opts ListTransactionsOptions) (*Page[Transaction], []byte, error) {
	var out Page[Transaction]
	raw, err := c.get(ctx, "/transactions", opts.query(), &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// GetTransaction fetches one transaction by bridge id
// (GET /transaction/{btxid}).
func (c *Client) GetTransaction(ctx context.Context, btxid string) (*Transaction, []byte, error) {
	var out Transaction
	raw, err := c.get(ctx, "/transaction/"+url.PathEscape(btxid), nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// ReviewTransaction sets a transaction's review state
// (PUT /transaction/{btxid}/review). Admin only, and a full replacement:
// fields left unset are reset.
func (c *Client) ReviewTransaction(ctx context.Context, btxid string, req ReviewTransactionRequest) (*ReviewTransactionResponse, []byte, error) {
	var out ReviewTransactionResponse
	raw, err := c.put(ctx, "/transaction/"+url.PathEscape(btxid)+"/review", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// ListEvents reads the admin event feed (GET /admin/events). Since is an
// exclusive id cursor: pass the last id seen to poll for newer events.
func (c *Client) ListEvents(ctx context.Context, since, limit int64) (*EventsResponse, []byte, error) {
	q := url.Values{}
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	if limit > 0 {
		q.Set("limit", strconv.FormatInt(limit, 10))
	}
	var out EventsResponse
	raw, err := c.get(ctx, "/admin/events", q, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}
