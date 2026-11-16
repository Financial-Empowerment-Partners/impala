package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
	"impalactl/internal/devicekey"
)

// Multi-factor sessions (docs/mfa-card-pin-biometrics.md).
//
// A session records the factors the bridge verified for it (amr). An account
// the bridge requires to be multi-factor gets 403 mfa_required from every
// route except the step-up ones until the session holds two factor kinds;
// `mfa step-up` adds one. For a bearer session the bridge answers a step-up
// with a token pair in a NEW family and revokes the old one, so the stored
// credentials are replaced under the store lock before anything else runs.

var mfaSubcommands = []string{
	"status                       Show this session's factors and whether they satisfy the account",
	"step-up --totp|--device      Add a factor to this session (new tokens replace the stored ones)",
	"totp enroll [--replace]      Enroll TOTP: prints the otpauth URI (it carries the shared secret)",
	"device enroll [--label L]    Make a key on this machine a second factor (possession, not biometric)",
	"device list                  List the account's device keys",
	"device revoke <key-id>       Revoke a device key (and forget it here if it is this machine's)",
	"admin show <account-id>      An account's factor summary (accounts-read roles)",
	"admin mandate <account-id> on|off",
	"                             Require (or stop requiring) MFA for an account (admin; on signs it out)",
	"admin revoke-device <account-id> <key-id>",
	"                             Recovery: revoke an account's lost device key (admin)",
}

func (a *App) runMFA(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "mfa", mfaSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "mfa", mfaSubcommands)
		return 0
	case "status":
		return a.runMFAStatus(opts, rest)
	case "step-up":
		return a.runMFAStepUp(opts, rest)
	case "totp":
		if len(rest) == 0 || rest[0] != "enroll" {
			return a.usageErr("usage: impalactl mfa totp enroll [--replace]")
		}
		return a.runTOTPEnroll(opts, rest[1:])
	case "device":
		if len(rest) == 0 {
			return a.usageErr("usage: impalactl mfa device enroll|list|revoke")
		}
		switch rest[0] {
		case "enroll":
			return a.runDeviceEnroll(opts, rest[1:])
		case "list":
			return a.runDeviceList(opts, rest[1:])
		case "revoke":
			return a.runDeviceRevoke(opts, rest[1:])
		}
		return a.usageErr("unknown subcommand %q (expected enroll, list or revoke)", rest[0])
	case "admin":
		if len(rest) == 0 {
			return a.usageErr("usage: impalactl mfa admin show|mandate|revoke-device")
		}
		switch rest[0] {
		case "show":
			return a.runMFAAdminShow(opts, rest[1:])
		case "mandate":
			return a.runMFAAdminMandate(opts, rest[1:])
		case "revoke-device":
			return a.runMFAAdminRevokeDevice(opts, rest[1:])
		}
		return a.usageErr("unknown subcommand %q (expected show, mandate or revoke-device)", rest[0])
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "mfa", mfaSubcommands)
		return 2
	}
}

// ── sessions ───────────────────────────────────────────────────────────

// session is an authenticated client, the claims of the token it carries,
// and the credential store when that token is the stored one (nil for a
// token supplied with --token or $IMPALA_TOKEN, which is the caller's).
type session struct {
	c      *bridge.Client
	claims bridge.Claims
	store  *config.Store
}

func (a *App) openSession(opts options) (*session, error) {
	c, err := a.authClient(opts)
	if err != nil {
		return nil, err
	}
	claims, err := c.TokenClaims()
	if err != nil {
		return nil, fmt.Errorf("cannot read the session token: %w", err)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, errors.New("the session token names no account")
	}
	s := &session{c: c, claims: claims}
	if a.usingStoredToken(opts) {
		if s.store, err = config.NewStore(a.getenv); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ── status ─────────────────────────────────────────────────────────────

func (a *App) runMFAStatus(opts options, args []string) int {
	fs := a.newFlagSet("mfa status")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("mfa status takes no positional arguments")
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	st, raw, err := c.MFAStatus(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	code := a.render(opts, raw, func(w io.Writer) {
		required := yesNo(st.Required)
		if st.RequiredByRole {
			required += " (by the account's role)"
		}
		kv(w, [][2]string{
			{"Factors (amr):", amrText(st.Amr)},
			{"Multi-factor:", multiFactorText(st)},
			{"Verified at:", authTimeText(st.AuthTime, a.clock())},
			{"MFA required:", required},
			{"Satisfied:", yesNo(st.Satisfied)},
		})
	})
	if !st.Satisfied {
		fmt.Fprintln(a.err, "notice: this session does not satisfy the account's MFA requirement; "+
			"`impalactl mfa step-up --totp` or `--device` adds a factor")
	}
	return code
}

func multiFactorText(st *bridge.MFAStatus) string {
	if st.MFA {
		return fmt.Sprintf("yes (lasts %s from the last verification)", time.Duration(st.MaxAgeSecs)*time.Second)
	}
	for _, m := range st.Amr {
		if m == bridge.AMRMultiFactor {
			return "no (its multi-factor verification has aged out)"
		}
	}
	return "no"
}

// amrText renders an amr list; an empty one is a single-factor session
// minted before MFA support, or with no recorded method.
func amrText(amr []string) string {
	if len(amr) == 0 {
		return "(none recorded)"
	}
	return strings.Join(amr, " ")
}

func authTimeText(unix int64, now time.Time) string {
	if unix <= 0 {
		return "-"
	}
	t := time.Unix(unix, 0).UTC()
	return fmt.Sprintf("%s (%s ago)", t.Format(time.RFC3339), now.Sub(t).Round(time.Second))
}

// ── step-up ────────────────────────────────────────────────────────────

var totpCode = regexp.MustCompile(`^[0-9]{6}$`)

func (a *App) runMFAStepUp(opts options, args []string) int {
	fs := a.newFlagSet("mfa step-up")
	bindGlobalFlags(fs, &opts)
	useTOTP := fs.Bool("totp", false, "a TOTP code (from $"+config.EnvTOTPCode+", a no-echo prompt, or stdin)")
	useDevice := fs.Bool("device", false, "this machine's device key (see `mfa device enroll`)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("mfa step-up takes no positional arguments")
	}
	method, err := stepUpMethod(*useTOTP, *useDevice)
	if err != nil {
		return a.usageErr("%v", err)
	}
	if !a.usingStoredToken(opts) && !opts.json {
		return a.usageErr("a step-up revokes the presented token's family and returns a new pair; " +
			"with --token / $" + config.EnvToken + " that pair can only be handed back: pass --json to receive it")
	}

	s, err := a.openSession(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	resp, raw, err := a.stepUp(s, method)
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, "Step-up complete: the previous tokens are revoked.")
		rows := [][2]string{
			{"Factors (amr):", amrText(resp.Amr)},
			{"Multi-factor:", yesNo(contains(resp.Amr, bridge.AMRMultiFactor))},
		}
		if s.store != nil {
			rows = append(rows, [2]string{"Credentials:", s.store.Path()})
		}
		kv(w, rows)
	})
}

func stepUpMethod(useTOTP, useDevice bool) (string, error) {
	switch {
	case useTOTP && useDevice:
		return "", errors.New("--totp and --device are exclusive: a step-up adds one factor")
	case useTOTP:
		return bridge.StepUpTOTP, nil
	case useDevice:
		return bridge.StepUpDevice, nil
	}
	return "", errors.New("mfa step-up needs --totp or --device")
}

// stepUp adds one factor to the session. The factor is gathered first (the
// TOTP code is read, the device key loaded) so nothing is held while a person
// types; then, for stored credentials, the store lock is taken for the
// challenge, the step-up and the replacement of the stored pair, so no other
// impalactl can rotate the family the bridge is about to revoke.
func (a *App) stepUp(s *session, method string) (*bridge.StepUpResponse, []byte, error) {
	ctx := context.Background()
	var code string
	var devKey *config.DeviceKey
	switch method {
	case bridge.StepUpTOTP:
		var err error
		if code, err = a.readSecret(config.EnvTOTPCode, "TOTP code: "); err != nil {
			return nil, nil, err
		}
		if !totpCode.MatchString(code) {
			return nil, nil, errors.New("a TOTP code is 6 digits")
		}
	case bridge.StepUpDevice:
		var err error
		if devKey, err = a.deviceKeyFor(s.c.Endpoint(), s.claims.Subject); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unknown step-up method %q", method)
	}

	if s.store != nil {
		release, err := s.store.Lock(lockWait)
		defer release()
		if err != nil {
			return nil, nil, err
		}
		// Another impalactl may have rotated the pair since the session was
		// opened: present the current one, never a rotated-out one.
		fresh, err := s.store.Load()
		if err != nil {
			return nil, nil, err
		}
		if fresh == nil || fresh.Endpoint != s.c.Endpoint() || fresh.TemporalToken == "" {
			return nil, nil, errors.New("the stored credentials changed while stepping up: run the command again")
		}
		if !needsRefresh(fresh.TemporalToken) {
			s.c.SetToken(fresh.TemporalToken)
		}
	}

	req := bridge.StepUpRequest{MFAType: method, Code: code}
	if devKey != nil {
		priv, err := devicekey.ParsePrivate(devKey.PrivateKey, devKey.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		ch, _, err := s.c.MFAChallenge(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("step-up challenge: %w", err)
		}
		challenge, err := decodeChallenge32(ch.Challenge)
		if err != nil {
			return nil, nil, fmt.Errorf("step-up challenge: %w", err)
		}
		sig, err := devicekey.Assert(priv, devicekey.PurposeStepUp, s.claims.Subject, challenge)
		if err != nil {
			return nil, nil, err
		}
		req.Challenge, req.KeyID, req.DeviceSignature = ch.Challenge, devKey.KeyID, sig
	}

	resp, raw, err := s.c.StepUp(ctx, req)
	if err != nil {
		return nil, raw, a.stepUpFailure(s, method, err)
	}
	if !resp.Success {
		return nil, raw, errors.New("step-up refused: the bridge answered success=false")
	}
	if resp.TemporalToken == "" || resp.RefreshToken == "" {
		// A bearer step-up revokes the old family before it mints the new
		// one: an answer without the pair leaves nothing usable behind.
		if s.store != nil {
			_ = s.store.Clear()
		}
		return nil, raw, errors.New("the bridge answered the step-up without a token pair, and the " +
			"previous session is revoked: run `impalactl login`")
	}
	if s.store != nil {
		claims, err := bridge.ParseClaims(resp.TemporalToken)
		if err != nil || claims.Subject != s.claims.Subject {
			_ = s.store.Clear()
			return nil, raw, errors.New("the step-up returned a token for another or no account; the " +
				"previous session is revoked and nothing was stored: run `impalactl login`")
		}
		if err := s.store.Save(&config.Credentials{
			Endpoint:      s.c.Endpoint(),
			AccountID:     claims.Subject,
			Role:          claims.Role,
			TemporalToken: resp.TemporalToken,
			RefreshToken:  resp.RefreshToken,
		}); err != nil {
			return nil, raw, fmt.Errorf("the bridge revoked the previous session, and the new tokens "+
				"could not be saved (%v): run `impalactl login`", err)
		}
	}
	return resp, raw, nil
}

// stepUpFailure explains a failed step-up. A refusal (any 4xx) happens
// before the bridge revokes anything; a lost answer may have rotated the
// family, and the stored pair is then dead.
func (a *App) stepUpFailure(s *session, method string, err error) error {
	if bridge.IsUnauthorized(err) {
		what := "TOTP code (wrong, expired, already used, or TOTP is not enrolled)"
		if method == bridge.StepUpDevice {
			what = "device key (revoked, unknown to the bridge, or a challenge that expired)"
		}
		return fmt.Errorf("step-up refused: the bridge did not accept the %s. Nothing changed: the "+
			"current session is as it was (%v)", what, err)
	}
	var reqErr *bridge.RequestError
	if errors.As(err, &reqErr) && (reqErr.Phase == bridge.PhaseRead || reqErr.Phase == bridge.PhaseDecode) {
		if s.store != nil {
			_ = s.store.Clear()
		}
		return fmt.Errorf("the bridge accepted the step-up but its answer could not be read (%v); the "+
			"previous session is revoked: run `impalactl login`", err)
	}
	if bridge.IsAmbiguousOutcome(err) {
		return fmt.Errorf("the step-up's outcome is unknown (%v): if it went through, the stored "+
			"session was revoked. `impalactl mfa status` tells; `impalactl login` recovers", err)
	}
	return err
}

func decodeChallenge32(h string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != devicekey.ChallengeLength {
		return nil, fmt.Errorf("the bridge's challenge is not %d bytes of hex", devicekey.ChallengeLength)
	}
	return b, nil
}

// deviceKeyFor loads this machine's completed device key for (endpoint,
// account), failing with what to do when there is none.
func (a *App) deviceKeyFor(endpoint, account string) (*config.DeviceKey, error) {
	store, err := config.NewStore(a.getenv)
	if err != nil {
		return nil, err
	}
	key, err := store.LoadDeviceKey(endpoint, account)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("this machine holds no device key for %s at %s: run `impalactl mfa device enroll`",
			account, endpoint)
	}
	if key.KeyID == "" {
		return nil, fmt.Errorf("the device key in %s never finished enrolling: run `impalactl mfa device enroll` again",
			store.DeviceKeyPath(endpoint, account))
	}
	return key, nil
}

// ── totp enroll ────────────────────────────────────────────────────────

func (a *App) runTOTPEnroll(opts options, args []string) int {
	fs := a.newFlagSet("mfa totp enroll")
	bindGlobalFlags(fs, &opts)
	replace := fs.Bool("replace", false, "re-enroll, replacing the current TOTP secret")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("mfa totp enroll takes no positional arguments")
	}
	s, err := a.openSession(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	ctx := context.Background()
	account := s.claims.Subject

	// Enrollment replaces any current secret at once (the bridge upserts), so
	// re-enrolling is opt-in: the authenticator that works today would stop.
	existing, _, err := s.c.ListMFA(ctx, account)
	if err != nil {
		return a.fail("cannot check the current enrollment: %v", err)
	}
	for _, e := range existing {
		if e.MFAType == bridge.StepUpTOTP && e.Enabled && !*replace {
			return a.fail("TOTP is already enrolled for %s; re-enrolling REPLACES its secret at once and "+
				"the current authenticator stops working. Pass --replace to do that", account)
		}
	}

	res, raw, err := s.c.EnrollMFA(ctx, bridge.EnrollMFARequest{AccountID: account, MFAType: bridge.StepUpTOTP})
	if err != nil {
		return a.fail("%v", err)
	}
	if !strings.HasPrefix(res.ProvisioningURI, "otpauth://totp/") {
		return a.fail("the bridge enrolled TOTP but returned no otpauth URI; re-run with --replace to get a new secret")
	}
	fmt.Fprintln(a.err, "The URI below carries the TOTP shared secret and is shown ONCE: load it into "+
		"an authenticator now (for a QR code: qrencode -t ansiutf8). impalactl does not keep it; keep it "+
		"out of logs and shell history.")
	fmt.Fprintln(a.err, "The enrollment is active now; `impalactl mfa step-up --totp` uses it.")
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.ProvisioningURI)
	})
}

// ── device keys ────────────────────────────────────────────────────────

func (a *App) runDeviceEnroll(opts options, args []string) int {
	fs := a.newFlagSet("mfa device enroll")
	bindGlobalFlags(fs, &opts)
	label := fs.String("label", devicekey.Platform, "a name for this key in listings")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("mfa device enroll takes no positional arguments")
	}
	s, err := a.openSession(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	store, err := config.NewStore(a.getenv)
	if err != nil {
		return a.fail("%v", err)
	}
	endpoint, account := s.c.Endpoint(), s.claims.Subject
	path := store.DeviceKeyPath(endpoint, account)

	key, err := store.LoadDeviceKey(endpoint, account)
	if err != nil {
		return a.fail("%v", err)
	}
	fresh := key == nil
	if key != nil && key.KeyID != "" {
		return a.fail("this machine already holds device key %s for %s at %s; revoke it first "+
			"(`impalactl mfa device revoke %s`)", key.KeyID, account, endpoint, key.KeyID)
	}
	if key == nil {
		// The private key is written before the bridge is asked: a key the
		// bridge accepts must never be one this machine failed to keep.
		priv, err := devicekey.Generate()
		if err != nil {
			return a.fail("generate the device key: %v", err)
		}
		pub, err := devicekey.PublicKeyHex(&priv.PublicKey)
		if err != nil {
			return a.fail("%v", err)
		}
		enc, err := devicekey.MarshalPrivate(priv)
		if err != nil {
			return a.fail("%v", err)
		}
		key = &config.DeviceKey{Endpoint: endpoint, AccountID: account, Label: strings.TrimSpace(*label),
			PrivateKey: enc, PublicKey: pub}
		if err := store.SaveDeviceKey(key); err != nil {
			return a.fail("%v", err)
		}
	} else {
		fmt.Fprintf(a.err, "resuming the interrupted enrollment of the key in %s\n", path)
	}
	priv, err := devicekey.ParsePrivate(key.PrivateKey, key.PublicKey)
	if err != nil {
		return a.fail("%v", err)
	}

	ctx := context.Background()
	forget := func() { _ = store.DeleteDeviceKey(endpoint, account) }
	// Before the enrollment request, only a key generated by this run is
	// known to be unregistered; a resumed one is kept for the next attempt.
	forgetFresh := func() {
		if fresh {
			forget()
		}
	}
	ch, _, err := s.c.MFAChallenge(ctx)
	if err != nil {
		forgetFresh()
		return a.fail("enrollment challenge: %v", err)
	}
	challenge, err := decodeChallenge32(ch.Challenge)
	if err != nil {
		forgetFresh()
		return a.fail("%v", err)
	}
	sig, err := devicekey.Assert(priv, devicekey.PurposeEnroll, account, challenge)
	if err != nil {
		forgetFresh()
		return a.fail("%v", err)
	}
	res, raw, err := s.c.EnrollDeviceKey(ctx, bridge.EnrollDeviceKeyRequest{
		PublicKey:        key.PublicKey,
		Label:            key.Label,
		Platform:         devicekey.Platform,
		UserVerification: devicekey.UserVerification,
		Challenge:        ch.Challenge,
		Signature:        sig,
	})
	if err != nil {
		if bridge.IsAmbiguousOutcome(err) {
			return a.fail("%v\nthe bridge may have registered the key: it is kept in %s, and "+
				"`impalactl mfa device enroll` resumes with it", err, path)
		}
		forget()
		if bridge.ErrorCode(err) == "device_key_in_use" {
			return a.fail("%v: an earlier, interrupted enrollment registered this key; find it in "+
				"`impalactl mfa device list` and revoke it, then enroll again", err)
		}
		return a.fail("%v", err)
	}
	if !res.Success || strings.TrimSpace(res.KeyID) == "" {
		return a.fail("the bridge answered without a key id; the key is kept in %s and "+
			"`impalactl mfa device enroll` resumes with it", path)
	}
	key.KeyID = res.KeyID
	if err := store.SaveDeviceKey(key); err != nil {
		return a.fail("the bridge registered device key %s, but %s could not be updated (%v): "+
			"revoke it with `impalactl mfa device revoke %s` and enroll again", res.KeyID, path, err, res.KeyID)
	}
	fmt.Fprintf(a.err, "The private key is in %s (0600). It is a possession factor: anyone who can "+
		"read that file holds it. It is declared to the bridge as user_verification=none, never biometric.\n", path)
	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Device key:", res.KeyID},
			{"Account:", account},
			{"Label:", dash(key.Label)},
			{"Platform:", devicekey.Platform},
			{"User verification:", devicekey.UserVerification},
			{"Key file:", path},
		})
	})
}

func (a *App) runDeviceList(opts options, args []string) int {
	fs := a.newFlagSet("mfa device list")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("mfa device list takes no positional arguments")
	}
	s, err := a.openSession(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	keys, raw, err := s.c.ListDeviceKeys(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	local := a.localKeyID(s.c.Endpoint(), s.claims.Subject)
	return a.render(opts, raw, func(w io.Writer) {
		renderDeviceKeys(w, keys, local)
	})
}

func renderDeviceKeys(w io.Writer, keys []bridge.DeviceKey, local string) {
	if len(keys) == 0 {
		fmt.Fprintln(w, "No device keys.")
		return
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].CreatedAtUnix < keys[j].CreatedAtUnix })
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		id := k.KeyID
		if local != "" && k.KeyID == local {
			id += " (this machine)"
		}
		created := "-"
		if k.CreatedAtUnix > 0 {
			created = time.Unix(k.CreatedAtUnix, 0).UTC().Format(time.RFC3339)
		}
		rows = append(rows, []string{id, str(k.Label), str(k.Platform), dash(k.UserVerification), created})
	}
	table(w, []string{"KEY ID", "LABEL", "PLATFORM", "USER VERIFICATION", "CREATED"}, rows)
}

// localKeyID is this machine's completed device key id for the pair, or "".
func (a *App) localKeyID(endpoint, account string) string {
	store, err := config.NewStore(a.getenv)
	if err != nil {
		return ""
	}
	key, err := store.LoadDeviceKey(endpoint, account)
	if err != nil || key == nil {
		return ""
	}
	return key.KeyID
}

func (a *App) runDeviceRevoke(opts options, args []string) int {
	fs := a.newFlagSet("mfa device revoke")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		return a.usageErr("mfa device revoke requires exactly one key id (see `impalactl mfa device list`)")
	}
	keyID := strings.TrimSpace(rest[0])
	s, err := a.openSession(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	endpoint, account := s.c.Endpoint(), s.claims.Subject
	isLocal := a.localKeyID(endpoint, account) == keyID

	_, raw, err := s.c.DeleteDeviceKey(context.Background(), keyID)
	gone := err == nil || bridge.StatusCode(err) == 404
	if gone && isLocal {
		store, serr := config.NewStore(a.getenv)
		if serr == nil {
			serr = store.DeleteDeviceKey(endpoint, account)
		}
		if serr != nil {
			fmt.Fprintf(a.err, "warning: could not remove this machine's copy of %s: %v\n", keyID, serr)
		} else {
			fmt.Fprintf(a.err, "removed this machine's copy of device key %s\n", keyID)
		}
	}
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintf(w, "Device key %s revoked.\n", keyID)
	})
}

// ── admin ──────────────────────────────────────────────────────────────

func (a *App) runMFAAdminShow(opts options, args []string) int {
	fs := a.newFlagSet("mfa admin show")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		return a.usageErr("mfa admin show requires exactly one account id")
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	v, raw, err := c.AdminAccountMFA(context.Background(), strings.TrimSpace(rest[0]))
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Account:", v.AccountID},
			{"MFA required:", yesNo(v.MFARequired) + " (the account's own flag; MFA_REQUIRED_ROLES can also require it)"},
			{"TOTP enrolled:", yesNo(v.TOTPEnrolled)},
			{"Active cards:", fmt.Sprintf("%d", v.Cards)},
		})
		fmt.Fprintln(w)
		renderDeviceKeys(w, v.DeviceKeys, "")
	})
}

func (a *App) runMFAAdminMandate(opts options, args []string) int {
	fs := a.newFlagSet("mfa admin mandate")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 2 || strings.TrimSpace(rest[0]) == "" {
		return a.usageErr("usage: impalactl mfa admin mandate <account-id> on|off")
	}
	account := strings.TrimSpace(rest[0])
	var required bool
	switch rest[1] {
	case "on":
		required = true
	case "off":
	default:
		return a.usageErr("mandate takes on or off, not %q", rest[1])
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	if required {
		fmt.Fprintf(a.err, "Mandating MFA signs %s out everywhere: every token and session it holds "+
			"stops working now, and its next sign-in must be multi-factor (a password plus a TOTP code "+
			"or a device key, a card with its PIN, ...).\n", account)
	}
	res, raw, err := c.AdminSetMFAPolicy(context.Background(), account, required)
	if err != nil {
		return a.fail("%v", err)
	}
	if !res.Success || res.Required != required {
		return a.fail("the bridge did not confirm the change (success=%v, required=%v)", res.Success, res.Required)
	}
	return a.render(opts, raw, func(w io.Writer) {
		if required {
			fmt.Fprintf(w, "MFA is now required for %s; it has been signed out everywhere.\n", account)
		} else {
			fmt.Fprintf(w, "MFA is no longer required for %s by its own flag "+
				"(MFA_REQUIRED_ROLES may still require it).\n", account)
		}
	})
}

func (a *App) runMFAAdminRevokeDevice(opts options, args []string) int {
	fs := a.newFlagSet("mfa admin revoke-device")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 2 || strings.TrimSpace(rest[0]) == "" || strings.TrimSpace(rest[1]) == "" {
		return a.usageErr("usage: impalactl mfa admin revoke-device <account-id> <key-id>")
	}
	account, keyID := strings.TrimSpace(rest[0]), strings.TrimSpace(rest[1])
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	_, raw, err := c.AdminDeleteDeviceKey(context.Background(), account, keyID)
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintf(w, "Device key %s of %s revoked.\n", keyID, account)
	})
}
