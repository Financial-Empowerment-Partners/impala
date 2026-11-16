package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"impalactl/internal/bridge"
	"impalactl/internal/sep10"
)

// SEP-10 operator surface (docs/sep10-api-and-admin-ui.md §4,
// docs/runbooks/sep10.md). The server signing key is generate-only and its
// lifecycle is explicit: generate (pending) → activate (scheduled, typed
// phrase, compare-and-set on the active fingerprint) → active; revoke at any
// time (typed phrase). The confirmation phrases name the network the BRIDGE
// reports, never one chosen here, and --yes never stands in for them.

var sep10Subcommands = []string{
	"info                    What this endpoint's stellar.toml publishes (public, no login)",
	"status                  Signing keys, home domain and key ring of the answering instance",
	"key generate            Create a pending signing key (generate-only: it is never imported)",
	"key activate <version>  Schedule a pending key to take over (typed phrase)",
	"key revoke <version>    Revoke a key at once (typed phrase)",
	"cards <account-id>      An account's cards with their Stellar addresses",
}

func (a *App) runSep10(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "sep10", sep10Subcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "sep10", sep10Subcommands)
		return 0
	case "info":
		return a.runSep10Info(opts, rest)
	case "status":
		return a.runSep10Status(opts, rest)
	case "cards":
		return a.runSep10Cards(opts, rest)
	case "key":
		if len(rest) == 0 {
			return a.usageErr("usage: impalactl sep10 key generate|activate <version>|revoke <version>")
		}
		switch rest[0] {
		case "generate":
			return a.runSep10Generate(opts, rest[1:])
		case "activate":
			return a.runSep10Activate(opts, rest[1:])
		case "revoke":
			return a.runSep10Revoke(opts, rest[1:])
		}
		return a.usageErr("unknown subcommand %q (expected generate, activate or revoke)", rest[0])
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "sep10", sep10Subcommands)
		return 2
	}
}

// ── info ───────────────────────────────────────────────────────────────

// sep10Info is what `sep10 info --json` prints: there is no server JSON to
// echo (stellar.toml is TOML), so this is the parsed view.
type sep10Info struct {
	Offered           bool   `json:"offered"`
	Status            int    `json:"http_status,omitempty"`
	Reason            string `json:"reason,omitempty"`
	SigningKey        string `json:"signing_key,omitempty"`
	WebAuthEndpoint   string `json:"web_auth_endpoint,omitempty"`
	HomeDomain        string `json:"home_domain,omitempty"`
	NetworkPassphrase string `json:"network_passphrase,omitempty"`
}

func (a *App) runSep10Info(opts options, args []string) int {
	fs := a.newFlagSet("sep10 info")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("sep10 info takes no positional arguments")
	}
	c, err := a.newClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	body, err := c.StellarToml(context.Background())
	if st := bridge.StatusCode(err); st == http.StatusNotFound || st == http.StatusServiceUnavailable {
		reason := "the bridge does not serve SEP-10 (SEP10_ENABLED is off, or it is published under a path)"
		if st == http.StatusServiceUnavailable {
			reason = "SEP-10 is temporarily unavailable (no active signing key, or this instance's key ring is not serving)"
		}
		return a.printInfo(opts, sep10Info{Offered: false, Status: st, Reason: reason}, c.Endpoint())
	}
	if err != nil {
		return a.fail("%v", err)
	}
	toml, err := sep10.ParseToml(string(body))
	if err != nil {
		return a.fail("stellar.toml is not readable: %v", err)
	}
	info := sep10Info{
		SigningKey:        toml.SigningKey,
		WebAuthEndpoint:   toml.WebAuthEndpoint,
		NetworkPassphrase: toml.NetworkPassphrase,
	}
	if toml.SigningKey == "" || toml.WebAuthEndpoint == "" {
		info.Reason = "stellar.toml has no WEB_AUTH_ENDPOINT or no SIGNING_KEY"
		return a.printInfo(opts, info, c.Endpoint())
	}
	if !sep10.IsValidAccountID(toml.SigningKey) {
		return a.fail("stellar.toml SIGNING_KEY %q is not a valid Stellar account id", toml.SigningKey)
	}
	_, domain, err := sep10.CheckWebAuthEndpoint(toml.WebAuthEndpoint)
	if err != nil {
		return a.fail("stellar.toml: %v", err)
	}
	info.Offered = true
	info.HomeDomain = domain
	return a.printInfo(opts, info, c.Endpoint())
}

func (a *App) printInfo(opts options, info sep10Info, endpoint string) int {
	if opts.json {
		b, _ := json.Marshal(info)
		return a.printJSON(b)
	}
	if !info.Offered {
		status := ""
		if info.Status != 0 {
			status = fmt.Sprintf(" (HTTP %d)", info.Status)
		}
		fmt.Fprintf(a.out, "SEP-10 is not offered at %s%s: %s.\n", endpoint, status, info.Reason)
		fmt.Fprintln(a.out, "Cards sign in there with the legacy card challenge.")
		return 0
	}
	rows := [][2]string{
		{"SIGNING_KEY:", info.SigningKey},
		{"WEB_AUTH_ENDPOINT:", info.WebAuthEndpoint},
		{"NETWORK_PASSPHRASE:", dash(info.NetworkPassphrase)},
		{"Home domain:", info.HomeDomain},
	}
	if hd, err := sep10.HomeDomainOf(endpoint); err == nil && hd != info.HomeDomain {
		rows = append(rows, [2]string{"Note:", fmt.Sprintf("the home domain is not %s (the endpoint's host): "+
			"`impalactl login --card … --sep10-home-domain %s`", hd, info.HomeDomain)})
	}
	kv(a.out, rows)
	return 0
}

// ── status ─────────────────────────────────────────────────────────────

func (a *App) runSep10Status(opts options, args []string) int {
	fs := a.newFlagSet("sep10 status")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("sep10 status takes no positional arguments")
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	st, raw, err := c.Sep10Status(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) { renderSep10Status(w, st) })
}

func renderSep10Status(w io.Writer, st *bridge.Sep10Status) {
	enabled := "disabled"
	if st.Enabled {
		enabled = "enabled"
	}
	ring := "none (this instance runs no key ring: SEP-10 is off here)"
	if st.KeyRingLive != nil {
		ring = "live"
		if !*st.KeyRingLive {
			ring = "STALE: this instance has not read the key table for five minutes and answers 503"
		}
	}
	kv(w, [][2]string{
		{"SEP-10:", enabled + " (on the instance that answered)"},
		{"Network:", fmt.Sprintf("%s (%s)", dash(st.Network), dash(st.NetworkPassphrase))},
		{"Home domain:", notConfigured(st.HomeDomain)},
		{"Web-auth endpoint:", notConfigured(st.WebAuthEndpoint)},
		{"Challenge lifetime:", fmt.Sprintf("%d s", st.ChallengeTTLSecs)},
		{"Cards with a Stellar key:", fmt.Sprintf("%d", st.RegisteredCardKeys)},
		{"Key ring:", ring},
	})

	active := st.Active()
	var notices []string
	switch {
	case len(active) > 1:
		notices = append(notices, fmt.Sprintf("the bridge reports %d active keys: this should never happen; "+
			"investigate before any key action", len(active)))
	case len(active) == 0 && st.Enabled:
		notices = append(notices, "SEP-10 is enabled but no signing key is active: sign-in answers 503 "+
			"(generate and activate a key)")
	case len(active) == 1 && active[0].Opened != nil && !*active[0].Opened:
		notices = append(notices, "this instance could not open the active key and answers 503: "+
			"check its seed protector (log lines start `sep10 ring:`)")
	}
	if !st.Enabled {
		notices = append(notices, "SEP-10 is off on this bridge (SEP10_ENABLED): a setting and a restart, "+
			"not a command; generate and activate a key first")
	}
	if st.WebAuthEndpoint == nil {
		notices = append(notices, "the web-auth endpoint is not configured: clients cannot discover SEP-10 "+
			"(SEP10_WEB_AUTH_ENDPOINT)")
	}
	for _, n := range notices {
		fmt.Fprintf(w, "\nNotice: %s\n", n)
	}

	if len(st.Keys) == 0 {
		fmt.Fprintln(w, "\nNo signing keys.")
		return
	}
	for _, k := range st.Keys {
		fmt.Fprintf(w, "\nv%d  %s\n", k.Version, k.State)
		kv(w, [][2]string{
			{"  Address:", k.PublicAddress},
			{"  Fingerprint:", k.Fingerprint},
			{"  Generated:", fmt.Sprintf("%s by %s", dash(k.GeneratedAt), dash(k.GeneratedBy))},
			{"  Activate at:", str(k.ActivateAt)},
			{"  Superseded at:", str(k.SupersededAt)},
			{"  Revoked at:", str(k.RevokedAt)},
			{"  Opened here:", openedText(k.Opened)},
		})
	}
}

func notConfigured(p *string) string {
	if p == nil || *p == "" {
		return "not configured"
	}
	return *p
}

func openedText(p *bool) string {
	switch {
	case p == nil:
		return "- (no key ring here, or revoked)"
	case *p:
		return "yes"
	}
	return "no"
}

// ── key generate / activate / revoke ───────────────────────────────────

func (a *App) runSep10Generate(opts options, args []string) int {
	fs := a.newFlagSet("sep10 key generate")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("sep10 key generate takes no positional arguments")
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), a.bridgeNetwork(c))
	res, raw, err := c.GenerateSep10Key(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Next: wait until `impalactl sep10 status` shows v%d opened on the instances "+
		"(one key-ring poll, 30 s), then `impalactl sep10 key activate %d`.\n", res.Version, res.Version)
	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Version:", strconv.Itoa(res.Version)},
			{"State:", dash(res.State)},
			{"Address:", dash(res.PublicAddress)},
			{"Fingerprint:", dash(res.Fingerprint)},
		})
	})
}

var networkWord = regexp.MustCompile(`^[a-z]+$`)

// sep10Phrase builds a confirmation phrase from the network word the bridge
// reported. The bridge does not serve the phrase whole (unlike the key
// listing's confirm_phrase); its format is the documented one
// (docs/sep10-api-and-admin-ui.md §4.3), and a refusal names the exact phrase.
func sep10Phrase(st *bridge.Sep10Status, format string, args ...any) (string, error) {
	if !networkWord.MatchString(st.Network) {
		return "", fmt.Errorf("the bridge did not report a usable network name (%q): the confirmation "+
			"phrase cannot be built, so no key action is offered", st.Network)
	}
	return fmt.Sprintf(format, append([]any{st.Network}, args...)...), nil
}

func (a *App) sep10Version(name string, rest []string) (int, error) {
	if len(rest) != 1 {
		return 0, fmt.Errorf("%s requires exactly one key version (see `impalactl sep10 status`)", name)
	}
	v, err := strconv.Atoi(strings.TrimPrefix(rest[0], "v"))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%q is not a key version", rest[0])
	}
	return v, nil
}

func (a *App) runSep10Activate(opts options, args []string) int {
	fs := a.newFlagSet("sep10 key activate")
	bindGlobalFlags(fs, &opts)
	confirm := fs.String("confirm-phrase", "", "the phrase the activation requires (activate sep10-signing <network>)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	version, err := a.sep10Version("sep10 key activate", rest)
	if err != nil {
		return a.usageErr("%v", err)
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	st, _, err := c.Sep10Status(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	key := st.Find(version)
	switch {
	case key == nil:
		return a.fail("there is no SEP-10 signing key version %d", version)
	case key.State != "pending":
		return a.fail("version %d is %s; only a pending key can be activated", version, key.State)
	case key.ActivateAt != nil:
		return a.fail("version %d is already scheduled to take over at %s", version, *key.ActivateAt)
	case key.Opened != nil && !*key.Opened:
		return a.fail("the bridge instance that answered has not opened version %d yet: its key ring "+
			"reads new keys every 30 s, so retry shortly. If it never opens, the instances cannot unseal "+
			"the key (the seed protector's permissions), and activating it would stop SEP-10 sign-in", version)
	}
	active := st.Active()
	if len(active) > 1 {
		return a.fail("the bridge reports %d active keys; investigate before activating anything", len(active))
	}
	supersede := "none"
	what := "no key is active now"
	if len(active) == 1 {
		supersede = active[0].Fingerprint
		what = fmt.Sprintf("it supersedes v%d (%s, fingerprint %s)", active[0].Version,
			active[0].PublicAddress, active[0].Fingerprint)
	}
	phrase, err := sep10Phrase(st, "activate sep10-signing %s")
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), st.Network)
	fmt.Fprintf(a.err, "Activating v%d (%s, fingerprint %s): %s. It takes over on every instance at once, "+
		"after the activation delay, and becomes the SIGNING_KEY every SEP-10 client pins through stellar.toml.\n",
		version, key.PublicAddress, key.Fingerprint, what)
	typed, err := a.confirmPhrase(phrase, strings.TrimSpace(*confirm), opts.yes)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ActivateSep10Key(context.Background(), version, bridge.ActivateSep10KeyRequest{
		ConfirmSupersede: supersede,
		ConfirmPhrase:    typed,
	})
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintf(w, "Version %d is scheduled to take over at %s (it stays pending until then).\n",
			res.Version, dash(res.ActivateAt))
	})
}

func (a *App) runSep10Revoke(opts options, args []string) int {
	fs := a.newFlagSet("sep10 key revoke")
	bindGlobalFlags(fs, &opts)
	confirm := fs.String("confirm-phrase", "", "the phrase the revocation requires (revoke sep10-signing <network> v<version>)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	version, err := a.sep10Version("sep10 key revoke", rest)
	if err != nil {
		return a.usageErr("%v", err)
	}
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	st, _, err := c.Sep10Status(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	key := st.Find(version)
	if key == nil {
		return a.fail("there is no SEP-10 signing key version %d", version)
	}
	effect := ""
	switch key.State {
	case "revoked":
		return a.fail("version %d is already revoked", version)
	case "active":
		effect = "it is the ACTIVE key: SEP-10 sign-in stops (503) until another key is active, and " +
			"cards sign in with the legacy challenge meanwhile"
	case "pending":
		effect = "it never goes into service"
	case "superseded":
		effect = "the challenges it signed stop being accepted now"
	default:
		effect = fmt.Sprintf("its state is %q, which this client does not know", key.State)
	}
	phrase, err := sep10Phrase(st, "revoke sep10-signing %s v%d", version)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), st.Network)
	fmt.Fprintf(a.err, "Revoking v%d (%s, fingerprint %s) refuses it at once and scrubs its sealed material: %s. "+
		"Sessions already opened are not ended.\n", version, key.PublicAddress, key.Fingerprint, effect)
	typed, err := a.confirmPhrase(phrase, strings.TrimSpace(*confirm), opts.yes)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.RevokeSep10Key(context.Background(), version, bridge.RevokeSep10KeyRequest{ConfirmPhrase: typed})
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintf(w, "Version %d is %s.\n", res.Version, dash(res.State))
	})
}

// ── cards ──────────────────────────────────────────────────────────────

// sep10RefusedRoles are the roles that hold a capability, which the bridge
// refuses at POST /auth/sep10 (auth::role_is_privileged). Display only: the
// bridge decides. Pinned against impala-ui/tests/fixtures/role-capabilities.json.
var sep10RefusedRoles = map[string]bool{"admin": true, "treasurer": true, "key-custodian": true, "auditor": true}

func (a *App) runSep10Cards(opts options, args []string) int {
	fs := a.newFlagSet("sep10 cards")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		return a.usageErr("sep10 cards requires exactly one account id")
	}
	account := strings.TrimSpace(rest[0])
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	list, raw, err := c.AccountCards(context.Background(), account)
	if err != nil {
		return a.fail("%v", err)
	}
	hasKey := false
	for _, card := range list.Cards {
		if card.Active && card.StellarAddress != nil && *card.StellarAddress != "" {
			hasKey = true
		}
	}
	note := ""
	if hasKey {
		refused, err := a.sep10Refused(c, account)
		switch {
		case err != nil:
			fmt.Fprintf(a.err, "warning: could not read %s's role (%v): whether the bridge refuses SEP-10 "+
				"for it is not shown\n", account, err)
		case refused:
			note = "This account holds a privileged role, so the bridge refuses SEP-10 sign-in for it. " +
				"Its cards sign in with the legacy card challenge."
		}
	}
	if opts.json {
		code := a.printJSON(raw)
		if note != "" {
			fmt.Fprintln(a.err, "note: "+note)
		}
		return code
	}
	if len(list.Cards) == 0 {
		fmt.Fprintf(a.out, "No cards for %s.\n", account)
		return 0
	}
	rows := make([][]string, 0, len(list.Cards))
	for _, card := range list.Cards {
		state := "active"
		if !card.Active {
			state = "deleted " + str(card.DeletedAt)
		}
		addr := str(card.StellarAddress)
		if card.Active && card.StellarAddress != nil && *card.StellarAddress != "" {
			addr += " (SEP-10)"
		}
		rows = append(rows, []string{card.CardID, state, addr, str(card.CreatedAt)})
	}
	table(a.out, []string{"CARD ID", "STATE", "STELLAR ADDRESS", "CREATED"}, rows)
	fmt.Fprintln(a.out, "\nA card's Stellar address is a sign-in key only: never fund it.")
	if note != "" {
		fmt.Fprintln(a.out, note)
	}
	return 0
}

// sep10Refused looks the account up (GET /accounts?search=…, exact match)
// and reports whether its role or the allowlist makes it privileged.
func (a *App) sep10Refused(c *bridge.Client, account string) (bool, error) {
	page, _, err := c.ListAccounts(context.Background(), bridge.ListAccountsOptions{Search: account, PerPage: 100})
	if err != nil {
		return false, err
	}
	for _, item := range page.Data {
		if item.PayalaAccountID == account {
			return item.Allowlisted || sep10RefusedRoles[item.Role], nil
		}
	}
	return false, errors.New("the account is not in the accounts list")
}
