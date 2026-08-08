package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

// runLogin exchanges a username and password for a token pair and stores it
// (POST /token).
func (a *App) runLogin(opts options, args []string) int {
	fs := a.newFlagSet("login")
	bindGlobalFlags(fs, &opts)
	username := fs.String("username", "", "Payala account id to log in as")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}

	user := strings.TrimSpace(*username)
	switch {
	case len(rest) > 1:
		return a.usageErr("login takes at most one positional argument (the account id)")
	case user == "" && len(rest) == 1:
		user = strings.TrimSpace(rest[0])
	case user == "":
		return a.usageErr("login requires --username <payala-account-id>")
	}

	password, err := a.readSecret(config.EnvPassword, fmt.Sprintf("Password for %s: ", user))
	if err != nil {
		return a.fail("%v", err)
	}

	c, err := a.newClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	resp, raw, err := c.Token(context.Background(), bridge.TokenRequest{Username: user, Password: password})
	if err != nil {
		return a.fail("login failed: %v", err)
	}
	if resp.TemporalToken == "" || resp.RefreshToken == "" {
		return a.fail("login failed: the bridge returned no token pair")
	}

	creds := &config.Credentials{
		Endpoint:      c.Endpoint(),
		AccountID:     user,
		TemporalToken: resp.TemporalToken,
		RefreshToken:  resp.RefreshToken,
	}
	claims, claimsErr := bridge.ParseClaims(resp.TemporalToken)
	if claimsErr == nil {
		creds.AccountID = claims.Subject
		creds.Role = claims.Role
	}

	store, err := config.NewStore(a.getenv)
	if err != nil {
		return a.fail("%v", err)
	}
	if err := store.Save(creds); err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Logged in as:", creds.AccountID},
			{"Role:", dash(creds.Role)},
			{"Endpoint:", creds.Endpoint},
			{"Token expires:", expiryText(claims, time.Now())},
			{"Credentials:", store.Path()},
		})
	})
}

// runLogout revokes the current token and forgets the stored credentials.
func (a *App) runLogout(opts options, args []string) int {
	fs := a.newFlagSet("logout")
	bindGlobalFlags(fs, &opts)
	all := fs.Bool("all", false, "revoke every token and session for the account, on all devices")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("logout takes no positional arguments")
	}

	// Only the credential store is ours to forget; a token supplied via
	// --token or the environment belongs to the caller.
	var store *config.Store
	if a.usingStoredToken(opts) {
		var err error
		if store, err = config.NewStore(a.getenv); err != nil {
			return a.fail("%v", err)
		}
		creds, err := store.Load()
		if err != nil {
			return a.fail("%v", err)
		}
		if creds == nil {
			fmt.Fprintln(a.out, "Not logged in.")
			return 0
		}
	}

	// forget drops the local copy. `logout` is a request to stop holding the
	// credential, so it runs even when revocation fails — the caller is told
	// when the token is still live server-side.
	forget := func() string {
		if store == nil {
			return ""
		}
		if err := store.Clear(); err != nil {
			fmt.Fprintf(a.err, "warning: %v\n", err)
			return ""
		}
		return store.Path()
	}

	c, err := a.authClient(opts)
	if err != nil {
		if path := forget(); path != "" {
			fmt.Fprintf(a.err, "removed %s\n", path)
		}
		return a.fail("%v", err)
	}

	var raw []byte
	if *all {
		_, raw, err = c.LogoutAll(context.Background())
	} else {
		_, raw, err = c.Logout(context.Background())
	}
	cleared := forget()
	if err != nil {
		if cleared != "" {
			fmt.Fprintf(a.err, "removed %s, but the token was not revoked and stays valid until it expires\n", cleared)
		}
		return a.fail("logout: %v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		if *all {
			fmt.Fprintln(w, "Revoked every token and session for the account.")
		} else {
			fmt.Fprintln(w, "Token revoked.")
		}
		if cleared != "" {
			fmt.Fprintf(w, "Removed %s\n", cleared)
		}
	})
}

// runWhoami reports the stored identity. It is deliberately offline: it
// reads the local token so it works without a reachable bridge, and it never
// refreshes (which would rotate the refresh token as a side effect).
func (a *App) runWhoami(opts options, args []string) int {
	fs := a.newFlagSet("whoami")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("whoami takes no positional arguments")
	}

	token, source := a.explicitToken(opts)
	endpoint := a.resolveEndpoint(opts)
	hasRefresh := false

	if token == "" {
		store, err := config.NewStore(a.getenv)
		if err != nil {
			return a.fail("%v", err)
		}
		creds, err := store.Load()
		if err != nil {
			return a.fail("%v", err)
		}
		if creds == nil || creds.TemporalToken == "" {
			return a.fail("not logged in: run `impalactl login`")
		}
		token = creds.TemporalToken
		source = store.Path()
		endpoint = creds.Endpoint
		hasRefresh = creds.RefreshToken != ""
	}

	claims, err := bridge.ParseClaims(token)
	if err != nil {
		return a.fail("cannot read token: %v", err)
	}

	rows := [][2]string{
		{"Account:", dash(claims.Subject)},
		{"Role:", dash(claims.Role)},
		{"Endpoint:", endpoint},
		{"Token type:", dash(claims.TokenType)},
		{"Expires:", expiryText(claims, time.Now())},
		{"Source:", source},
	}
	if hasRefresh {
		rows = append(rows, [2]string{"Refresh token:", "stored"})
	}
	kv(a.out, rows)
	return 0
}

// explicitToken returns a token supplied by --token or $IMPALA_TOKEN, with a
// label describing where it came from.
func (a *App) explicitToken(opts options) (token, source string) {
	if v := strings.TrimSpace(opts.token); v != "" {
		return v, "--token"
	}
	if v := strings.TrimSpace(a.getenv(config.EnvToken)); v != "" {
		return v, "$" + config.EnvToken
	}
	return "", ""
}

// usingStoredToken reports whether commands will fall back to the credential
// store (rather than an explicitly supplied token).
func (a *App) usingStoredToken(opts options) bool {
	token, _ := a.explicitToken(opts)
	return token == ""
}

// expiryText renders a token expiry with the time remaining.
func expiryText(claims bridge.Claims, now time.Time) string {
	exp := claims.Expiry()
	if exp.IsZero() {
		return "-"
	}
	stamp := exp.Format(time.RFC3339)
	remaining := exp.Sub(now).Round(time.Second)
	if remaining < 0 {
		return fmt.Sprintf("%s (expired %s ago)", stamp, -remaining)
	}
	return fmt.Sprintf("%s (in %s)", stamp, remaining)
}
