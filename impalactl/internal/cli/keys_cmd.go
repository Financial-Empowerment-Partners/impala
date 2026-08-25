package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

// Bridge key management.
//
// This is the preferred surface for installing credentials: a secret can come
// from a file, stdin, or a no-echo prompt, and never touches argv (visible to
// every process on the box) or a browser (visible to extensions, autofill and
// session restore).
//
// Two behaviours are load-bearing and must not be "simplified" away:
//
//   - The part names, the current fingerprint, and the confirmation phrase are
//     all READ FROM THE BRIDGE (`GET /admin/keys`) rather than composed here. A
//     client that built them itself would drift from the server the moment
//     either side changed, and hand operators a phrase that is always rejected.
//   - Before anything is sent, the endpoint and network are printed. The
//     commonest operator mistake with credentials is the right key in the wrong
//     environment, and this is where it gets caught.

var keysSubcommands = []string{
	"list                Show provider credentials: running, stored, and the gap",
	"import <kind>       Import or replace a provider credential set",
	"revoke <kind>       Revoke a stored credential and scrub its ciphertext",
}

var seedSubcommands = []string{
	"generate            Provision a custodial seed the bridge generates itself",
	"import              Bring an existing Stellar secret seed under custody",
}

func (a *App) runKeys(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "keys", keysSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "keys", keysSubcommands)
		return 0
	case "list":
		return a.runKeysList(opts, rest)
	case "import":
		return a.runKeysImport(opts, rest)
	case "revoke":
		return a.runKeysRevoke(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "keys", keysSubcommands)
		return 2
	}
}

func (a *App) runStellarSeed(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "stellar-seed", seedSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "stellar-seed", seedSubcommands)
		return 0
	case "generate":
		return a.runSeedGenerate(opts, rest)
	case "import":
		return a.runSeedImport(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "stellar-seed", seedSubcommands)
		return 2
	}
}

// ── keys list ──────────────────────────────────────────────────────────

func (a *App) runKeysList(opts options, args []string) int {
	fs := a.newFlagSet("keys list")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("keys list takes no positional arguments")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ListKeys(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		if !res.Enabled {
			fmt.Fprintln(w, "Key import is OFF on this bridge (KEY_IMPORT_ENABLED=false).")
			fmt.Fprintln(w, "Credentials come from the deployment configuration; anything")
			fmt.Fprintln(w, "stored below is NOT in use.")
			fmt.Fprintln(w)
		}
		if res.Degraded {
			fmt.Fprintln(w, "WARNING: a stored credential could not be used at startup, so")
			fmt.Fprintln(w, "that provider is disabled on the instance that answered. It did")
			fmt.Fprintln(w, "not fall back to the environment — that would silently")
			fmt.Fprintln(w, "re-activate a replaced credential.")
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "Protection backend: %s\n\n", dash(res.ProtectionBackend))

		for i := range res.Keys {
			v := &res.Keys[i]
			fmt.Fprintf(w, "%s\n", v.Kind)
			rows := [][2]string{
				{"  Running here:", fmt.Sprintf("%s %s", v.EffectiveSource,
					dash(v.EffectiveFingerprint))},
				{"  Stored:", storedSummary(v)},
				{"  Parts:", strings.Join(v.Parts, ", ")},
			}
			if len(v.EnvVarsSet) > 0 {
				label := strings.Join(v.EnvVarsSet, " ")
				if v.ShadowedEnvFingerprint != "" {
					label += "  (shadowed by the stored credential — remove them to finish the rotation)"
				}
				rows = append(rows, [2]string{"  Environment:", label})
			}
			if v.InFlightCount > 0 {
				rows = append(rows, [2]string{"  In flight:",
					fmt.Sprintf("%d order(s)/cycle(s)", v.InFlightCount)})
			}
			if v.ResolutionError != "" {
				rows = append(rows, [2]string{"  Error:", v.ResolutionError})
			}
			if v.PendingRestart {
				rows = append(rows, [2]string{"  Pending:",
					"what is stored differs from what is running here — roll the deployment"})
			}
			kv(w, rows)
			fmt.Fprintln(w)
		}
	})
}

func storedSummary(v *bridge.KeyView) string {
	if v.StoredFingerprint == "" {
		return "-"
	}
	version := 0
	if v.StoredVersion != nil {
		version = *v.StoredVersion
	}
	return fmt.Sprintf("%s (v%d, %s)", v.StoredFingerprint, version, v.StoredState)
}

// ── keys import ────────────────────────────────────────────────────────

// partFiles collects repeated --part-file name=path flags.
type partFiles map[string]string

func (p partFiles) String() string {
	if len(p) == 0 {
		return ""
	}
	names := make([]string, 0, len(p))
	for k := range p {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func (p partFiles) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	name, path = strings.TrimSpace(name), strings.TrimSpace(path)
	if !ok || name == "" || path == "" {
		return fmt.Errorf("expected name=path, got %q", v)
	}
	p[name] = path
	return nil
}

func (a *App) runKeysImport(opts options, args []string) int {
	fs := a.newFlagSet("keys import")
	bindGlobalFlags(fs, &opts)
	files := partFiles{}
	fs.Var(files, "part-file", "read a part from a file: name=path (repeatable; required for PEM keys)")
	replace := fs.Bool("replace", false, "replace the credential currently in effect")
	confirmPhrase := fs.String("confirm-phrase", "", "the phrase the bridge requires for a replacement")
	note := fs.String("note", "", "operator note (stored in plaintext, shown in listings)")
	strand := fs.Bool("strand-in-flight", false, "accept stranding in-flight orders if the new credential is for a different provider account")
	skipVerify := fs.Bool("skip-verify", false, "store without proving the credential against the provider")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("keys import requires exactly one credential kind (see `impalactl keys list`)")
	}
	kind := rest[0]

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}

	// Ask the bridge what this kind needs, and what it is running. Everything
	// below — part names, whether this is a replacement, the exact phrase —
	// comes from that answer rather than from assumptions baked in here.
	listing, _, err := c.ListKeys(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	if !listing.Enabled {
		return a.fail("key import is disabled on this bridge (KEY_IMPORT_ENABLED=false)")
	}
	view, err := listing.Find(kind)
	if err != nil {
		return a.fail("%v", err)
	}

	for name := range files {
		if !contains(view.Parts, name) {
			return a.usageErr("unknown part %q for %s (expected: %s)",
				name, kind, strings.Join(view.Parts, ", "))
		}
	}

	parts, err := a.collectParts(view, files)
	if err != nil {
		return a.fail("%v", err)
	}

	network := a.bridgeNetwork(c)
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)

	req := bridge.ImportKeyRequest{
		Parts:          parts,
		Note:           strings.TrimSpace(*note),
		StrandInFlight: *strand,
		SkipVerify:     *skipVerify,
	}

	if view.IsReplacement() {
		if !*replace {
			return a.fail("a credential for %s already exists (running: %s %s; would replace: %s); "+
				"imports only add by default — pass --replace to replace it",
				kind, view.EffectiveSource, dash(view.EffectiveFingerprint),
				view.ReplaceTargetFingerprint)
		}
		if view.InFlightCount > 0 && !*strand {
			return a.fail("%d order(s)/cycle(s) are still running against %s; if the new "+
				"credential is for a different provider account their references become "+
				"unreachable and anything already sent is stranded. Settle them first, or "+
				"pass --strand-in-flight if the account is the same",
				view.InFlightCount, kind)
		}
		phrase, err := a.confirmPhrase(view.ConfirmPhrase, *confirmPhrase, opts.yes)
		if err != nil {
			return a.fail("%v", err)
		}
		req.Replace = true
		req.ExpectedFingerprint = view.ReplaceTargetFingerprint
		req.ConfirmPhrase = phrase
	}

	// The network gate on top of the phrase: on a live network this refuses
	// outright when non-interactive unless --yes was passed.
	action := fmt.Sprintf("import the %s credential", kind)
	if req.Replace {
		action = fmt.Sprintf("REPLACE the %s credential (%s)", kind, view.ReplaceTargetFingerprint)
	}
	if err := a.confirm(network, action, opts.yes); err != nil {
		return a.fail("%v", err)
	}

	res, raw, err := c.ImportKey(context.Background(), kind, req)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		rows := [][2]string{
			{"Kind:", res.Kind},
			{"Version:", versionOrDash(res.Version)},
			{"Fingerprint:", dash(res.SetFingerprint)},
			{"Effective:", dash(res.EffectiveAfter)},
		}
		kv(w, rows)
		if res.VerifyNote != "" {
			fmt.Fprintf(w, "\nNote: %s\n", res.VerifyNote)
		}
		if res.EnvShadowNote != "" {
			fmt.Fprintf(w, "\nNote: %s\n", res.EnvShadowNote)
		}
	})
}

// collectParts sources every part of a credential set without ever reading one
// from argv. In order: --part-file, then $IMPALA_KEY_<PART>, then a no-echo
// prompt (or a line of stdin when not a terminal).
//
// Files are the only way to supply a PEM: the prompt and the stdin fallback
// both read a single line.
func (a *App) collectParts(view *bridge.KeyView, files partFiles) (map[string]string, error) {
	parts := make(map[string]string, len(view.Parts))
	for _, name := range view.Parts {
		required := contains(view.RequiredParts, name)
		envName := partEnvName(view.Kind, name)

		if path, ok := files[name]; ok {
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read %s from %s: %w", name, path, err)
			}
			value := strings.TrimSpace(string(b))
			if value == "" {
				return nil, fmt.Errorf("%s is empty in %s", name, path)
			}
			parts[name] = value
			continue
		}

		if v := strings.TrimSpace(a.getenv(envName)); v != "" {
			parts[name] = v
			continue
		}

		if !required {
			// Do not prompt for optional parts that were not offered: an
			// omitted webhook secret means "not configured", which is valid,
			// and an empty string would be rejected by the bridge.
			fmt.Fprintf(a.err, "skipping optional part %q (set $%s or --part-file %s=<path> to include it)\n",
				name, envName, name)
			continue
		}

		value, err := a.readSecret(envName, fmt.Sprintf("%s: ", name))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		parts[name] = value
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("no parts supplied")
	}
	return parts, nil
}

// partEnvName is the environment variable one part of one credential kind is
// read from.
//
// The kind is part of the name on purpose. A bare IMPALA_KEY_API_KEY would
// mean the same thing for every provider, so an operator with one exported for
// Changelly who then ran an OwlPay import would submit the Changelly key to
// OwlPay without being asked — a credential mix-up that neither the CLI nor
// the bridge could detect, because both values are well-formed opaque strings.
func partEnvName(kind, part string) string {
	upper := func(s string) string {
		return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
	}
	return "IMPALA_KEY_" + upper(kind) + "_" + upper(part)
}

// confirmPhrase obtains the exact phrase the bridge requires for a
// replacement: from --confirm-phrase, or by prompting.
//
// The phrase is NOT a secret — it is displayed so it can be typed — and it is
// deliberately not the fingerprint, which is on screen and copyable. Naming the
// network in it is what catches the right key in the wrong environment.
func (a *App) confirmPhrase(required, supplied string, assumeYes bool) (string, error) {
	if required == "" {
		return "", fmt.Errorf("the bridge did not supply a confirmation phrase; " +
			"re-run `impalactl keys list` and retry")
	}
	if supplied != "" {
		if supplied != required {
			return "", fmt.Errorf("--confirm-phrase must be exactly %q", required)
		}
		return supplied, nil
	}
	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(a.err, "Type %q to confirm: ", required)
		line, err := bufio.NewReader(a.in).ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("read confirmation: %w", err)
		}
		if strings.TrimSpace(line) != required {
			return "", fmt.Errorf("aborted: confirmation not given")
		}
		return required, nil
	}
	// --yes is deliberately NOT enough on its own: it waives the interactive
	// prompt, not the operator's statement of what they are replacing.
	return "", fmt.Errorf("refusing to replace non-interactively without --confirm-phrase %q", required)
}

// ── keys revoke ────────────────────────────────────────────────────────

func (a *App) runKeysRevoke(opts options, args []string) int {
	fs := a.newFlagSet("keys revoke")
	bindGlobalFlags(fs, &opts)
	confirmPhrase := fs.String("confirm-phrase", "", "the phrase the bridge requires")
	strand := fs.Bool("strand-in-flight", false, "accept that in-flight orders will have nothing able to reconcile them")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("keys revoke requires exactly one credential kind")
	}
	kind := rest[0]

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	listing, _, err := c.ListKeys(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	view, err := listing.Find(kind)
	if err != nil {
		return a.fail("%v", err)
	}
	if view.StoredFingerprint == "" {
		return a.fail("%s has no stored credential to revoke (it is running from %s)",
			kind, view.EffectiveSource)
	}

	// Spell out what happens next BEFORE asking for confirmation. Revocation
	// quietly handing the provider back to an older environment key is the
	// surprise worth naming.
	fallback := "the provider will be UNCONFIGURED and its endpoints will stop working"
	if len(view.EnvVarsSet) > 0 {
		fallback = fmt.Sprintf("it falls back to the environment (%s) — a DIFFERENT key takes over",
			strings.Join(view.EnvVarsSet, ", "))
	}
	network := a.bridgeNetwork(c)
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)
	fmt.Fprintf(a.err, "After the next restart, %s.\n", fallback)
	fmt.Fprintln(a.err, "Revoking here does NOT revoke the key at the provider.")

	phrase, err := a.confirmPhrase(view.ConfirmPhrase, *confirmPhrase, opts.yes)
	if err != nil {
		return a.fail("%v", err)
	}
	if err := a.confirm(network, fmt.Sprintf("revoke the %s credential", kind), opts.yes); err != nil {
		return a.fail("%v", err)
	}

	if view.InFlightCount > 0 && !*strand {
		return a.fail("%d order(s)/cycle(s) are still running against %s; after the next "+
			"restart nothing will be able to reconcile them. Settle them first, or pass "+
			"--strand-in-flight to accept that", view.InFlightCount, kind)
	}

	res, raw, err := c.RevokeKey(context.Background(), kind, bridge.RevokeKeyRequest{
		ExpectedFingerprint: view.StoredFingerprint,
		ConfirmPhrase:       phrase,
		ConfirmNextSource:   true,
		StrandInFlight:      *strand,
	})
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
	})
}

// ── stellar-seed generate / import ─────────────────────────────────────

func (a *App) runSeedGenerate(opts options, args []string) int {
	fs := a.newFlagSet("stellar-seed generate")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "Payala account id to provision (required)")
	label := fs.String("label", "", "display name for the account record")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("stellar-seed generate takes no positional arguments")
	}
	id := strings.TrimSpace(*account)
	if id == "" {
		return a.usageErr("stellar-seed generate requires --account")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	network := a.bridgeNetwork(c)
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)
	if err := a.confirm(network, fmt.Sprintf("generate a custodial seed for %s", id), opts.yes); err != nil {
		return a.fail("%v", err)
	}

	res, raw, err := c.GenerateSeed(context.Background(), bridge.GenerateSeedRequest{
		PayalaAccountID: id,
		Label:           strings.TrimSpace(*label),
	})
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Account:", id},
			{"Stellar address:", dash(res.StellarAccountID)},
			{"Effective:", dash(res.EffectiveAfter)},
		})
	})
}

func (a *App) runSeedImport(opts options, args []string) int {
	fs := a.newFlagSet("stellar-seed import")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "Payala account id (required)")
	replace := fs.Bool("replace", false, "replace the stored seed (must derive the same address)")
	expected := fs.String("expected-address", "", "the address the stored seed currently derives")
	confirmPhraseFlag := fs.String("confirm-phrase", "", "the phrase required for a replacement")
	skipVerify := fs.Bool("skip-verify", false, "store even when the on-chain probe says the key cannot authorize")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("stellar-seed import takes no positional arguments")
	}
	id := strings.TrimSpace(*account)
	if id == "" {
		return a.usageErr("stellar-seed import requires --account")
	}

	// The seed comes from the environment, a no-echo prompt, or stdin — never
	// from argv, which every process on the machine can read.
	seed, err := a.readSecret(config.EnvSecretSeed, "Stellar secret seed (S...): ")
	if err != nil {
		return a.fail("%v", err)
	}
	if err := validateStellarSecretSeed(seed); err != nil {
		return a.fail("%v", err)
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	network := a.bridgeNetwork(c)
	fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)

	req := bridge.ImportSeedRequest{
		PayalaAccountID: id,
		SecretSeed:      seed,
		SkipVerify:      *skipVerify,
	}
	if *replace {
		addr := strings.TrimSpace(*expected)
		if addr == "" {
			return a.usageErr("--replace requires --expected-address (the address the stored seed derives)")
		}
		if len(addr) < 6 {
			return a.usageErr("--expected-address is not a Stellar address")
		}
		required := "replace seed " + addr[len(addr)-6:]
		phrase, err := a.confirmPhrase(required, *confirmPhraseFlag, opts.yes)
		if err != nil {
			return a.fail("%v", err)
		}
		req.Replace = true
		req.ExpectedStellarAccountID = addr
		req.ConfirmPhrase = phrase
	}

	if err := a.confirm(network, fmt.Sprintf("place a seed for %s under custody", id), opts.yes); err != nil {
		return a.fail("%v", err)
	}

	res, raw, err := c.ImportSeed(context.Background(), req)
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		rows := [][2]string{
			{"Account:", id},
			{"Stellar address:", dash(res.StellarAccountID)},
		}
		if res.OnChain != nil {
			exists := "no (unfunded)"
			if res.OnChain.Exists {
				exists = "yes"
			}
			rows = append(rows, [2]string{"On chain:", exists})
			if res.OnChain.MasterKeyWeight != nil {
				rows = append(rows, [2]string{"Master key weight:",
					fmt.Sprintf("%d", *res.OnChain.MasterKeyWeight)})
			}
		}
		kv(w, rows)
	})
}

// ── helpers ────────────────────────────────────────────────────────────

// bridgeNetwork reads the bridge's Stellar network, treating an unreadable
// answer as live so a failed lookup cannot downgrade a confirmation.
func (a *App) bridgeNetwork(c *bridge.Client) string {
	if info, _, err := c.Network(context.Background()); err == nil {
		return info.StellarNetwork
	}
	fmt.Fprintln(a.err, "warning: could not read the bridge's network; treating it as live")
	return "unknown"
}

func versionOrDash(v *int) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *v)
}
