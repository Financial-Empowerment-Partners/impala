package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"impalactl/internal/bridge"
)

// `card issuer show|generate`: the card program's issuer key
// (docs/runbooks/card-issuer.md). The key is generate-only: it is created
// inside the bridge and sealed there, and nothing here or in any response is
// secret. A rotation invalidates the program key installed on every card, so
// it takes --rotate, the active fingerprint as a compare-and-set and the typed
// phrase "replace card-issuer <network>" (network as the bridge reports it);
// --yes never stands in for the phrase.

const cardIssuerUsage = "usage: impalactl card issuer show | generate [--rotate] [--confirm-phrase PHRASE]"

func (a *App) runCardIssuer(opts options, args []string) int {
	if len(args) == 0 {
		return a.usageErr("%s", cardIssuerUsage)
	}
	switch args[0] {
	case "show":
		return a.runCardIssuerShow(opts, args[1:])
	case "generate":
		return a.runCardIssuerGenerate(opts, args[1:])
	}
	return a.usageErr("unknown subcommand %q (expected show or generate)\n%s", args[0], cardIssuerUsage)
}

func (a *App) runCardIssuerShow(opts options, args []string) int {
	fs := a.newFlagSet("card issuer show")
	bindGlobalFlags(fs, &opts)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("card issuer show takes no positional arguments")
	}
	c, err := a.newClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	info, raw, err := c.CardIssuer(context.Background())
	if err != nil {
		return a.fail("%v", err)
	}
	return a.render(opts, raw, func(w io.Writer) {
		if !info.Configured {
			fmt.Fprintf(w, "The card program is not configured on %s: no issuer key is active.\n"+
				"Create it with `impalactl card issuer generate` (admin or key-custodian).\n", c.Endpoint())
			return
		}
		kv(w, [][2]string{
			{"Configured:", "yes"},
			{"Version:", strconv.Itoa(info.Version)},
			{"Fingerprint:", dash(info.Fingerprint)},
			{"Program id:", dash(info.ProgramIDHex)},
			{"Redemption account:", dash(info.RedemptionUUID)},
			{"Public key:", dash(info.PublicKeyHex)},
		})
	})
}

func (a *App) runCardIssuerGenerate(opts options, args []string) int {
	fs := a.newFlagSet("card issuer generate")
	bindGlobalFlags(fs, &opts)
	rotate := fs.Bool("rotate", false, "replace the active issuer key (re-personalize and re-certify every card afterwards)")
	confirm := fs.String("confirm-phrase", "", "the phrase a rotation requires (replace card-issuer <network>)")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 {
		return a.usageErr("card issuer generate takes no positional arguments")
	}
	ctx := context.Background()
	c, err := a.authClient(opts)
	if err != nil {
		return a.fail("%v", err)
	}
	info, _, err := c.CardIssuer(ctx)
	if err != nil {
		return a.fail("read the card program (GET /card-issuer): %v", err)
	}
	var req bridge.GenerateCardIssuerRequest
	if info.Configured {
		if !*rotate {
			return a.fail("a card issuer key is active (v%d, fingerprint %s). Rotating it invalidates the program "+
				"key installed on every card until they are re-personalized and re-certified; pass --rotate (and "+
				"the confirmation phrase) only if that is the intent", info.Version, dash(info.Fingerprint))
		}
		net, _, err := c.Network(ctx)
		if err != nil {
			return a.fail("read the bridge's network (GET /network): %v; the confirmation phrase names it, so no "+
				"rotation is offered", err)
		}
		if !networkWord.MatchString(net.StellarNetwork) {
			return a.fail("the bridge did not report a usable network name (%q): the confirmation phrase cannot "+
				"be built, so no rotation is offered", net.StellarNetwork)
		}
		phrase := "replace card-issuer " + net.StellarNetwork
		fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), net.StellarNetwork)
		fmt.Fprintf(a.err, "Rotating the card issuer key supersedes v%d (fingerprint %s). Every card holds the "+
			"current program key: none of them verifies a transfer certified under the new key until it is "+
			"re-personalized and re-certified. Certificates the old key signed keep verifying.\n",
			info.Version, dash(info.Fingerprint))
		typed, err := a.confirmPhrase(phrase, *confirm, opts.yes)
		if err != nil {
			return a.fail("%v", err)
		}
		req = bridge.GenerateCardIssuerRequest{ConfirmSupersede: info.Fingerprint, ConfirmPhrase: typed}
	} else {
		network := a.bridgeNetwork(c)
		fmt.Fprintf(a.err, "Bridge:  %s\nNetwork: %s\n", c.Endpoint(), network)
		fmt.Fprintln(a.err, "Generating the card program issuer key: it is created and sealed inside the bridge, "+
			"never exported, and it certifies every card of the program.")
		if err := a.confirmStake(network, "generate the card program issuer key",
			"it creates the card program's issuer key, which certifies every card", opts.yes); err != nil {
			return a.fail("%v", err)
		}
	}
	res, raw, err := c.GenerateCardIssuer(ctx, req)
	if err != nil {
		code := a.fail("%v", err)
		if hint := custodyHint(err); hint != "" {
			fmt.Fprintln(a.err, hint)
		}
		return code
	}
	return a.render(opts, raw, func(w io.Writer) {
		kv(w, [][2]string{
			{"Version:", strconv.Itoa(res.Version)},
			{"Fingerprint:", dash(res.Fingerprint)},
			{"Program id:", dash(res.ProgramIDHex)},
			{"Redemption account:", dash(res.RedemptionUUID)},
			{"Public key:", dash(res.PublicKeyHex)},
			{"Replaced:", yesNo(res.Replaced)},
		})
		if res.Note != "" {
			fmt.Fprintf(w, "\nNote: %s\n", res.Note)
		}
	})
}
