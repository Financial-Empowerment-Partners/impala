package bridge

import "context"

// Token exchanges credentials for a refresh/temporal token pair
// (POST /token). It is unauthenticated — the client's bearer token, if any,
// is irrelevant here.
//
// The refresh flow is single-use: the presented refresh token is burned
// server-side before the replacement is minted, and presenting a rotated-out
// token again revokes the entire token family. Callers MUST persist the
// returned refresh token before making any further request.
func (c *Client) Token(ctx context.Context, req TokenRequest) (*TokenResponse, []byte, error) {
	var out TokenResponse
	raw, err := c.post(ctx, "/token", req, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// Logout revokes the presented token (POST /logout).
func (c *Client) Logout(ctx context.Context) (*LogoutResponse, []byte, error) {
	var out LogoutResponse
	raw, err := c.post(ctx, "/logout", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}

// LogoutAll revokes every token and session for the account (POST /logout/all).
func (c *Client) LogoutAll(ctx context.Context) (*LogoutResponse, []byte, error) {
	var out LogoutResponse
	raw, err := c.post(ctx, "/logout/all", nil, &out)
	if err != nil {
		return nil, raw, err
	}
	return &out, raw, out.Err()
}
