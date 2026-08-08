package bridge

import "context"

// Health reports the bridge's dependency status (GET /health).
// Unauthenticated. A degraded bridge answers 503 with the same body, which
// surfaces here as an APIError carrying that body.
func (c *Client) Health(ctx context.Context) (*Health, []byte, error) {
	var out Health
	raw, err := c.get(ctx, "/health", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// Version returns build and schema version info (GET /version).
// Unauthenticated.
func (c *Client) Version(ctx context.Context) (*Version, []byte, error) {
	var out Version
	raw, err := c.get(ctx, "/version", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}

// Network returns the Stellar network the bridge is wired to (GET /network).
// Unauthenticated — the CLI calls it before a transfer so the operator always
// sees whether real funds are at stake.
func (c *Client) Network(ctx context.Context) (*NetworkInfo, []byte, error) {
	var out NetworkInfo
	raw, err := c.get(ctx, "/network", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, nil
}
