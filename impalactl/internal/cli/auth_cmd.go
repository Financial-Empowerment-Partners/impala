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

// runLogin signs in and stores the token pair: with a username and password
// (POST /token), or with a card (`--card`, see card_login.go). `--totp` or
// `--device` adds a second factor in the same command (POST /mfa/step-up).
func (a *App) runLogin(opts options, args []string) int {
	fs := a.newFlagSet("login")
	bindGlobalFlags(fs, &opts)
	username := fs.String("username", "", "Payala account id to log in as")
	useTOTP := fs.Bool("totp", false, "step up with a TOTP code after signing in ($"+config.EnvTOTPCode+", prompt, or stdin)")
	useDevice := fs.Bool("device", false, "add this machine's device key as a second factor")
	var card cardLoginFlags
	card.bind(fs)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if *useTOTP && *useDevice {
		return a.usageErr("--totp and --device are exclusive: a login adds at most one factor")
	}
	if card.card != "" {
		if strings.TrimSpace(*username) != "" || len(rest) > 0 {
			return a.usageErr("--card signs in as the card's account: drop the account id")
		}
		if *useTOTP {
			return a.usageErr("--totp is not part of a card sign-in: sign in with the card (and --pin), then `impalactl mfa step-up --totp`")
		}
		return a.runCardLogin(opts, card, *useDevice)
	}
	if card.used() {
		return a.usageErr("--pin, --aid, --sep10-home-domain and --no-sep10 need --card tcp:HOST:PORT")
	}

	user := strings.TrimSpace(*username)
	switch {
	case len(rest) > 1:
		return a.usageErr("login takes at most one positional argument (the account id)")
	case user == "" && len(rest) == 1:
		user = strings.TrimSpace(rest[0])
	case user == "":
		return a.usageErr("login requires --username <payala-account-id> (or --card tcp:HOST:PORT)")
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
	stepUp := ""
	switch {
	case *useTOTP:
		stepUp = bridge.StepUpTOTP
	case *useDevice:
		stepUp = bridge.StepUpDevice
	}
	return a.finishLogin(opts, c, user, resp.TemporalToken, resp.RefreshToken, raw, stepUp)
}

// finishLogin stores a fresh token pair, adds the requested second factor,
// and reports. Every sign-in path ends here, so the stored shape, the MFA
// notice and the summary are one thing.
func (a *App) finishLogin(opts options, c *bridge.Client, fallbackAccount, temporal, refresh string, raw []byte, stepUp string) int {
	creds := &config.Credentials{
		Endpoint:      c.Endpoint(),
		AccountID:     fallbackAccount,
		TemporalToken: temporal,
		RefreshToken:  refresh,
	}
	claims, claimsErr := bridge.ParseClaims(temporal)
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

	if stepUp != "" {
		c.SetToken(temporal)
		s := &session{c: c, claims: claims, store: store}
		if claimsErr != nil || claims.Subject == "" {
			return a.fail("signed in, but the token names no account, so no factor can be added")
		}
		resp, stepRaw, err := a.stepUp(s, stepUp)
		if err != nil {
			return a.fail("signed in with one factor, but the step-up failed: %v", err)
		}
		raw = stepRaw
		temporal = resp.TemporalToken
		if claims, claimsErr = bridge.ParseClaims(temporal); claimsErr == nil {
			creds.Role = claims.Role
		}
	} else if claimsErr == nil && claims.MFARequired && !claims.HasMFA() {
		fmt.Fprintf(a.err, "notice: %s must be multi-factor, and this session has one factor (%s): "+
			"the bridge refuses it (403 mfa_required) until you run `impalactl mfa step-up --totp` "+
			"or `impalactl mfa step-up --device`\n", creds.AccountID, amrText(claims.Amr))
	}

	return a.render(opts, raw, func(w io.Writer) {
		rows := [][2]string{
			{"Logged in as:", creds.AccountID},
			{"Role:", dash(creds.Role)},
			{"Endpoint:", creds.Endpoint},
		}
		if claimsErr == nil {
			rows = append(rows,
				[2]string{"Factors (amr):", amrText(claims.Amr)},
				[2]string{"Multi-factor:", yesNo(claims.HasMFA())})
		}
		rows = append(rows,
			[2]string{"Token expires:", expiryText(claims, time.Now())},
			[2]string{"Credentials:", store.Path()})
		kv(w, rows)
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
		{"Factors (amr):", amrText(claims.Amr)},
		{"Multi-factor:", whoamiMultiFactor(claims)},
		{"Verified at:", authTimeText(claims.AuthTime, a.clock())},
		{"MFA required:", yesNo(claims.MFARequired)},
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

// whoamiMultiFactor reads the multi-factor marker from the token. The
// bridge also ages it out after MFA_MAX_AGE_SECS (default 12 h), which only
// `impalactl mfa status` can report.
func whoamiMultiFactor(claims bridge.Claims) string {
	if !claims.HasMFA() {
		return "no"
	}
	return "yes (as of auth_time; `impalactl mfa status` checks it is still fresh)"
}
