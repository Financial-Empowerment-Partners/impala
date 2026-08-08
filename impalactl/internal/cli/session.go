package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

const (
	// refreshSkew refreshes a temporal token slightly before it expires, so a
	// token that is valid when checked is still valid when it arrives.
	refreshSkew = 60 * time.Second
	// lockWait bounds how long we queue behind another impalactl that is
	// rotating the same refresh token.
	lockWait = 5 * time.Second
)

// resolveEndpoint applies the flag → environment → default precedence.
func (a *App) resolveEndpoint(opts options) string {
	if v := strings.TrimSpace(opts.endpoint); v != "" {
		return v
	}
	if v := strings.TrimSpace(a.getenv(config.EnvEndpoint)); v != "" {
		return v
	}
	return bridge.DefaultEndpoint
}

// newClient builds an unauthenticated client for the resolved endpoint. It is
// what /health, /version, /network and /token need.
func (a *App) newClient(opts options) (*bridge.Client, error) {
	timeout := opts.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return bridge.New(a.resolveEndpoint(opts), timeout)
}

// authClient builds a client carrying a bearer token, resolved as
// --token → $IMPALA_TOKEN → stored credentials. A stored temporal token that
// has expired (or is about to) is refreshed first.
func (a *App) authClient(opts options) (*bridge.Client, error) {
	c, err := a.newClient(opts)
	if err != nil {
		return nil, err
	}

	if tok := strings.TrimSpace(opts.token); tok != "" {
		c.SetToken(tok)
		return c, nil
	}
	if tok := strings.TrimSpace(a.getenv(config.EnvToken)); tok != "" {
		c.SetToken(tok)
		return c, nil
	}

	store, err := config.NewStore(a.getenv)
	if err != nil {
		return nil, err
	}
	creds, err := store.Load()
	if err != nil {
		return nil, err
	}
	if creds == nil || creds.TemporalToken == "" {
		return nil, fmt.Errorf("not logged in: run `impalactl login` (or pass --token / set $%s)", config.EnvToken)
	}
	// Credentials are endpoint-scoped: a token minted by one bridge is never
	// presented to another.
	if creds.Endpoint != c.Endpoint() {
		return nil, fmt.Errorf(
			"stored credentials are for %s, not %s: run `impalactl login --endpoint %s` (or pass --token)",
			creds.Endpoint, c.Endpoint(), c.Endpoint())
	}

	creds, err = a.refreshIfNeeded(c, store, creds)
	if err != nil {
		return nil, err
	}
	c.SetToken(creds.TemporalToken)
	return c, nil
}

// refreshIfNeeded rotates an expiring temporal token, holding the store lock
// so two impalactl processes cannot burn the same single-use refresh token
// (which would trip the bridge's reuse detection and revoke the whole family).
func (a *App) refreshIfNeeded(c *bridge.Client, store *config.Store, creds *config.Credentials) (*config.Credentials, error) {
	if !needsRefresh(creds.TemporalToken) {
		return creds, nil
	}
	if creds.RefreshToken == "" {
		return nil, fmt.Errorf("stored token has expired and there is no refresh token: run `impalactl login`")
	}

	release, err := store.Lock(lockWait)
	if err != nil {
		return nil, err
	}
	defer release()

	// Re-read under the lock: a concurrent impalactl may have rotated already,
	// in which case we adopt its tokens instead of burning ours.
	if fresh, err := store.Load(); err == nil && fresh != nil && fresh.Endpoint == creds.Endpoint {
		if !needsRefresh(fresh.TemporalToken) {
			return fresh, nil
		}
		creds = fresh
	}

	// POST /token is unauthenticated; c carries no bearer token yet.
	resp, _, err := c.Token(context.Background(), bridge.TokenRequest{RefreshToken: creds.RefreshToken})
	if err != nil {
		if bridge.IsUnauthorized(err) {
			// Expired, revoked, or a family killed by reuse detection. Drop the
			// dead credentials so the next command says "log in" plainly.
			_ = store.Clear()
			return nil, fmt.Errorf("session expired or revoked (%v): run `impalactl login`", err)
		}
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	updated := *creds
	updated.TemporalToken = resp.TemporalToken
	updated.RefreshToken = resp.RefreshToken
	if claims, err := bridge.ParseClaims(resp.TemporalToken); err == nil {
		updated.AccountID = claims.Subject
		updated.Role = claims.Role
	}

	// Persist before the new token is used anywhere: the presented refresh
	// token is already burned server-side, so a replacement lost here would
	// strand the account on a dead family until the next interactive login.
	if err := store.Save(&updated); err != nil {
		return nil, fmt.Errorf("save rotated credentials: %w", err)
	}
	return &updated, nil
}

// needsRefresh reports whether a temporal token is expired, expiring within
// the skew window, or unparseable (in which case refreshing is the safe move).
func needsRefresh(token string) bool {
	claims, err := bridge.ParseClaims(token)
	if err != nil {
		return true
	}
	return claims.ExpiresWithin(time.Now(), refreshSkew)
}
