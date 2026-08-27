package cli

import (
	"fmt"
	"strings"

	"lumencli/internal/netcfg"
	"lumencli/internal/stellar"
	"lumencli/internal/wallet"
)

func (a *App) runAccount(opts netcfg.Options, args []string) int {
	if len(args) == 0 {
		return a.fail("account requires a subcommand: new | address | create | fund")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "new":
		return a.accountNew(opts, rest)
	case "address":
		return a.accountAddress(opts, rest)
	case "create":
		return a.accountCreate(opts, rest)
	case "fund":
		return a.accountFund(opts, rest)
	default:
		return a.fail("unknown account subcommand %q (want: new | address | create | fund)", sub)
	}
}

// accountNew generates a fresh keypair offline and prints it. With --fund it
// also requests testnet Friendbot funding for the new address.
func (a *App) accountNew(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("account new")
	bindNetworkFlags(fs, &opts)
	fund := fs.Bool("fund", false, "fund the new account via testnet Friendbot (testnet only)")
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}

	kp, err := wallet.Generate()
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.out, "Public key (address): %s\n", kp.Address())
	fmt.Fprintf(a.out, "Secret seed:          %s\n", kp.Seed())
	fmt.Fprintln(a.err, "\nWARNING: store the secret seed securely and never share it.")
	fmt.Fprintln(a.err, "Anyone who has it controls this account's funds.")

	if *fund {
		net, err := a.resolveNetwork(opts)
		if err != nil {
			return a.fail("%v", err)
		}
		a.announce(net)
		if err := stellar.New(net).Fund(kp.Address()); err != nil {
			return a.fail("%v", err)
		}
		fmt.Fprintf(a.out, "\nFunded via Friendbot on %s.\n", net.Name)
	}
	return 0
}

// accountAddress derives and prints the public address for a secret seed. This
// is fully offline; the seed is never sent anywhere. Network flags are accepted
// (and ignored) for consistency with the other commands.
func (a *App) accountAddress(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("account address")
	bindNetworkFlags(fs, &opts)
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}
	secret, err := a.readSecret("Enter secret seed (S...): ")
	if err != nil {
		return a.fail("%v", err)
	}
	addr, err := wallet.AddressFromSecret(secret)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintln(a.out, addr)
	return 0
}

// accountCreate creates and funds a new account on-ledger, paid for by the
// signer's funding account. This spends real XLM on mainnet.
func (a *App) accountCreate(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("account create")
	bindNetworkFlags(fs, &opts)
	dest := fs.String("dest", "", "destination address (G...) of the account to create")
	amount := fs.String("amount", "", "starting XLM balance to fund the new account with")
	memo := bindMemoFlags(fs)
	assumeYes := fs.Bool("yes", false, "skip the mainnet confirmation prompt (for non-interactive use)")
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}

	destination := strings.TrimSpace(*dest)
	amt := strings.TrimSpace(*amount)
	if destination == "" || amt == "" {
		return a.fail("account create requires --dest and --amount")
	}
	if err := wallet.ValidateAddress(destination); err != nil {
		return a.fail("%v", err)
	}
	if err := stellar.ValidateAmount(amt); err != nil {
		return a.fail("%v", err)
	}
	txMemo, err := memo.memo()
	if err != nil {
		return a.fail("%v", err)
	}

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)
	// checkLedger is false: the destination must not exist yet, so it cannot
	// have declared a memo requirement on-ledger. Only the curated list applies.
	if err := a.confirmMissingMemo(net, destination, txMemo, *memo.noMemo, false); err != nil {
		return a.fail("%v", err)
	}
	summary := fmt.Sprintf("create account %s with %s XLM%s", destination, amt, withMemo(txMemo))
	if err := a.confirmSpend(net, summary, *assumeYes); err != nil {
		return a.fail("%v", err)
	}

	secret, err := a.readSecret("Enter funding account secret seed (S...): ")
	if err != nil {
		return a.fail("%v", err)
	}
	source, err := wallet.ParseSecret(secret)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.err, "Signing from: %s\n", source.Address())

	hash, err := stellar.New(net).CreateAccount(source, destination, amt, txMemo)
	if err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.out, "Created account %s with %s XLM%s\nTransaction: %s\n", destination, amt, withMemo(txMemo), hash)
	return 0
}

// accountFund funds an account via testnet Friendbot.
func (a *App) accountFund(opts netcfg.Options, args []string) int {
	fs := a.newFlagSet("account fund")
	bindNetworkFlags(fs, &opts)
	addr := fs.String("address", "", "account address (G...) to fund via Friendbot")
	if _, err := parseArgs(fs, args); err != nil {
		return parseCode(err)
	}
	address := strings.TrimSpace(*addr)
	if address == "" {
		return a.fail("account fund requires --address")
	}

	net, err := a.resolveNetwork(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	a.announce(net)
	if err := stellar.New(net).Fund(address); err != nil {
		return a.fail("%v", err)
	}
	fmt.Fprintf(a.out, "Funded %s via Friendbot on %s.\n", address, net.Name)
	return 0
}
