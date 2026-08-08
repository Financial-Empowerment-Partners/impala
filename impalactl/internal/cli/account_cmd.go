package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"impalactl/internal/bridge"
	"impalactl/internal/config"
)

var accountSubcommands = []string{
	"create              Link a Stellar account to a Payala account",
	"generate            Create a custodial account (seed generated server-side)",
	"import              Place an existing Stellar seed under custody",
	"show <G...>         Show an account's bridge record",
	"onchain <G...>      Show live on-chain balances and signers",
	"reserves <id>       Show Payala reserve balances",
	"list                List accounts (admin)",
}

func (a *App) runAccount(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "account", accountSubcommands)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		a.subUsage(a.out, "account", accountSubcommands)
		return 0
	case "create":
		return a.runAccountCreate(opts, rest)
	case "generate":
		return a.runAccountGenerate(opts, rest)
	case "import":
		return a.runAccountImport(opts, rest)
	case "show":
		return a.runAccountShow(opts, rest)
	case "onchain":
		return a.runAccountOnchain(opts, rest)
	case "reserves":
		return a.runAccountReserves(opts, rest)
	case "list":
		return a.runAccountList(opts, rest)
	default:
		fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", sub)
		a.subUsage(a.err, "account", accountSubcommands)
		return 2
	}
}

// profileFlags are the name fields shared by the account-creating commands.
type profileFlags struct {
	first       string
	middle      string
	last        string
	nickname    string
	affiliation string
	gender      string
}

func bindProfileFlags(fs *flag.FlagSet, p *profileFlags) {
	fs.StringVar(&p.first, "first-name", "", "given name (required)")
	fs.StringVar(&p.middle, "middle-name", "", "middle name")
	fs.StringVar(&p.last, "last-name", "", "family name (required)")
	fs.StringVar(&p.nickname, "nickname", "", "preferred name")
	fs.StringVar(&p.affiliation, "affiliation", "", "organization")
	fs.StringVar(&p.gender, "gender", "", "gender")
}

func (p profileFlags) validate() error {
	if strings.TrimSpace(p.first) == "" || strings.TrimSpace(p.last) == "" {
		return fmt.Errorf("--first-name and --last-name are required")
	}
	return nil
}

// runAccountCreate links an existing Stellar address to a Payala account.
func (a *App) runAccountCreate(opts options, args []string) int {
	fs := a.newFlagSet("account create")
	bindGlobalFlags(fs, &opts)
	stellar := fs.String("stellar", "", "Stellar account id (G..., required)")
	account := fs.String("account", "", "Payala account id (required)")
	var profile profileFlags
	bindProfileFlags(fs, &profile)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("account create takes no positional arguments")
	}

	stellarID := strings.TrimSpace(*stellar)
	payalaID := strings.TrimSpace(*account)
	if stellarID == "" || payalaID == "" {
		return a.usageErr("account create requires --stellar and --account")
	}
	if err := validateStellarAccountID(stellarID); err != nil {
		return a.fail("%v", err)
	}
	if err := profile.validate(); err != nil {
		return a.usageErr("%v", err)
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.CreateAccount(context.Background(), bridge.CreateAccountRequest{
		StellarAccountID: stellarID,
		PayalaAccountID:  payalaID,
		FirstName:        profile.first,
		MiddleName:       profile.middle,
		LastName:         profile.last,
		Nickname:         profile.nickname,
		Affiliation:      profile.affiliation,
		Gender:           profile.gender,
	})
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Payala account:", payalaID},
			{"Stellar account:", stellarID},
		})
	})
}

// runAccountGenerate creates a custodial account: the bridge generates the
// seed, protects it with the configured backend, and returns only the address.
func (a *App) runAccountGenerate(opts options, args []string) int {
	fs := a.newFlagSet("account generate")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "Payala account id (defaults to the logged-in account)")
	var profile profileFlags
	bindProfileFlags(fs, &profile)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("account generate takes no positional arguments")
	}
	if err := profile.validate(); err != nil {
		return a.usageErr("%v", err)
	}

	payalaID := a.resolveOwnerAccount(opts, *account)
	if payalaID == "" {
		return a.usageErr("account generate requires --account (the owning Payala account id)")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.GenerateManagedAccount(context.Background(), bridge.GenerateManagedAccountRequest{
		PayalaAccountID: payalaID,
		FirstName:       profile.first,
		MiddleName:      profile.middle,
		LastName:        profile.last,
		Nickname:        profile.nickname,
		Affiliation:     profile.affiliation,
		Gender:          profile.gender,
	})
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Payala account:", payalaID},
			{"Stellar account:", dash(res.StellarAccountID)},
		})
		fmt.Fprintln(w, "\nThe seed is held by the bridge; fund this address before transferring from it.")
	})
}

// runAccountImport places an existing seed under custody. The seed is read
// from the environment, a no-echo prompt, or stdin — never from argv.
func (a *App) runAccountImport(opts options, args []string) int {
	fs := a.newFlagSet("account import")
	bindGlobalFlags(fs, &opts)
	account := fs.String("account", "", "Payala account id (defaults to the logged-in account)")
	var profile profileFlags
	bindProfileFlags(fs, &profile)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("account import takes no positional arguments (the seed is never passed on the command line)")
	}
	if err := profile.validate(); err != nil {
		return a.usageErr("%v", err)
	}

	payalaID := a.resolveOwnerAccount(opts, *account)
	if payalaID == "" {
		return a.usageErr("account import requires --account (the owning Payala account id)")
	}

	seed, err := a.readSecret(config.EnvSecretSeed, "Enter Stellar secret seed (S...): ")
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
	res, raw, err := c.ImportManagedAccount(context.Background(), bridge.ImportManagedAccountRequest{
		PayalaAccountID: payalaID,
		SecretSeed:      seed,
		FirstName:       profile.first,
		MiddleName:      profile.middle,
		LastName:        profile.last,
		Nickname:        profile.nickname,
		Affiliation:     profile.affiliation,
		Gender:          profile.gender,
	})
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		fmt.Fprintln(w, res.Message)
		kv(w, [][2]string{
			{"Payala account:", payalaID},
			{"Stellar account:", dash(res.StellarAccountID)},
		})
	})
}

// runAccountShow prints the bridge's record for a Stellar account.
func (a *App) runAccountShow(opts options, args []string) int {
	fs := a.newFlagSet("account show")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("account show requires one Stellar account id (G...)")
	}
	if err := validateStellarAccountID(rest[0]); err != nil {
		return a.fail("%v", err)
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	acct, raw, err := c.GetAccount(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Payala account:", acct.PayalaAccountID},
			{"Stellar account:", acct.StellarAccountID},
			{"Name:", fullName(acct.FirstName, acct.MiddleName, acct.LastName)},
			{"Nickname:", str(acct.Nickname)},
			{"Affiliation:", str(acct.Affiliation)},
			{"Gender:", str(acct.Gender)},
			{"Role:", acct.Role},
			{"Sync mode:", acct.SyncMode},
			{"Profile source:", acct.ProfileSource},
			{"Profile synced:", str(acct.ProfileSyncedAt)},
			{"Created:", str(acct.CreatedAt)},
		})
	})
}

// runAccountOnchain prints live Horizon state for a Stellar account.
func (a *App) runAccountOnchain(opts options, args []string) int {
	fs := a.newFlagSet("account onchain")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) != 1 {
		return a.usageErr("account onchain requires one Stellar account id (G...)")
	}
	if err := validateStellarAccountID(rest[0]); err != nil {
		return a.fail("%v", err)
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	acct, raw, err := c.GetAccountOnchain(context.Background(), rest[0])
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Stellar account:", acct.StellarAccountID},
			{"Exists on ledger:", yesNo(acct.Exists)},
			{"Sequence:", str(acct.Sequence)},
			{"Native balance:", str(acct.NativeBalance)},
			{"Subentries:", num(acct.SubentryCount)},
		})
		if !acct.Exists {
			fmt.Fprintln(w, "\nThe account is not funded on this network yet.")
			return
		}
		if len(acct.Balances) > 0 {
			fmt.Fprintln(w, "\nBalances:")
			rows := make([][]string, 0, len(acct.Balances))
			for _, b := range acct.Balances {
				code := str(b.AssetCode)
				if b.AssetType == "native" {
					code = "XLM"
				}
				rows = append(rows, []string{code, b.AssetType, shortAddr(b.AssetIssuer), b.Balance})
			}
			table(w, []string{"ASSET", "TYPE", "ISSUER", "BALANCE"}, rows)
		}
		if len(acct.Signers) > 0 {
			fmt.Fprintln(w, "\nSigners:")
			rows := make([][]string, 0, len(acct.Signers))
			for _, s := range acct.Signers {
				key := s.Key
				rows = append(rows, []string{shortAddr(&key), fmt.Sprint(s.Weight), s.Type})
			}
			table(w, []string{"KEY", "WEIGHT", "TYPE"}, rows)
		}
	})
}

// runAccountReserves prints the account's Payala reserve balances.
func (a *App) runAccountReserves(opts options, args []string) int {
	fs := a.newFlagSet("account reserves")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	accountID := ""
	switch len(rest) {
	case 0:
		accountID = a.resolveOwnerAccount(opts, "")
	case 1:
		accountID = rest[0]
	default:
		return a.usageErr("account reserves takes at most one Payala account id")
	}
	if accountID == "" {
		return a.usageErr("account reserves requires a Payala account id")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.GetReserves(context.Background(), accountID)
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Account:", res.AccountID},
			{"Sync mode:", res.SyncMode},
		})
		if len(res.Reserves) == 0 {
			fmt.Fprintln(w, "\nNo reserve balances.")
			return
		}
		fmt.Fprintln(w, "\nReserves (minor units):")
		rows := make([][]string, 0, len(res.Reserves))
		for _, r := range res.Reserves {
			rows = append(rows, []string{r.Currency, fmt.Sprint(r.Balance), str(r.UpdatedAt)})
		}
		table(w, []string{"CURRENCY", "BALANCE", "UPDATED"}, rows)
	})
}

// runAccountList prints a page of accounts (admin only).
func (a *App) runAccountList(opts options, args []string) int {
	fs := a.newFlagSet("account list")
	bindGlobalFlags(fs, &opts)
	page := fs.Uint64("page", 0, "page number (default 1)")
	perPage := fs.Uint64("per-page", 0, "rows per page, 1-100 (default 20)")
	search := fs.String("search", "", "match Payala id, Stellar id, first or last name")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("account list takes no positional arguments")
	}

	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	res, raw, err := c.ListAccounts(context.Background(), bridge.ListAccountsOptions{
		Page:    *page,
		PerPage: *perPage,
		Search:  *search,
	})
	if err != nil {
		return a.fail("%v", err)
	}

	return a.render(opts, raw, func(w io.Writer) {
		if len(res.Data) == 0 {
			fmt.Fprintln(w, "No accounts found.")
			return
		}
		rows := make([][]string, 0, len(res.Data))
		for _, acct := range res.Data {
			stellar := acct.StellarAccountID
			rows = append(rows, []string{
				acct.PayalaAccountID,
				shortAddr(&stellar),
				fullName(acct.FirstName, acct.MiddleName, acct.LastName),
				acct.Role,
				acct.SyncMode,
				acct.ProfileSource,
				str(acct.CreatedAt),
			})
		}
		table(w, []string{"PAYALA ID", "STELLAR", "NAME", "ROLE", "SYNC", "SOURCE", "CREATED"}, rows)
		pageFooter(w, len(res.Data), res.Page, res.PerPage, res.Total, "account", "accounts")
	})
}

// resolveOwnerAccount returns the explicit account id, falling back to the
// account in the bearer token the CLI would use. Owner-scoped endpoints
// require the two to match, so this saves repeating it on every command.
func (a *App) resolveOwnerAccount(opts options, explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	return a.currentAccountID(opts)
}

// currentAccountID reads the account id out of the token the CLI would send,
// without contacting the bridge. It returns "" when no token is available.
func (a *App) currentAccountID(opts options) string {
	token, _ := a.explicitToken(opts)
	if token == "" {
		store, err := config.NewStore(a.getenv)
		if err != nil {
			return ""
		}
		creds, err := store.Load()
		if err != nil || creds == nil {
			return ""
		}
		// Stored credentials only describe the bridge that issued them, so
		// they say nothing about the account on a different endpoint.
		c, err := a.newClient(opts)
		if err != nil || creds.Endpoint != c.Endpoint() {
			return ""
		}
		if creds.AccountID != "" {
			return creds.AccountID
		}
		token = creds.TemporalToken
	}
	claims, err := bridge.ParseClaims(token)
	if err != nil {
		return ""
	}
	return claims.Subject
}

// fullName joins the name parts, skipping absent ones.
func fullName(first string, middle *string, last string) string {
	parts := []string{first}
	if middle != nil && *middle != "" {
		parts = append(parts, *middle)
	}
	parts = append(parts, last)
	return strings.Join(parts, " ")
}

// pageFooter summarizes a paginated response.
func pageFooter(w io.Writer, shown int, page, perPage, total uint64, singular, pluralWord string) {
	if perPage == 0 {
		perPage = 1
	}
	pages := (total + perPage - 1) / perPage
	if pages == 0 {
		pages = 1
	}
	fmt.Fprintf(w, "\nShowing %d of %s (page %d of %d)\n",
		shown, plural(total, singular, pluralWord), page, pages)
}
