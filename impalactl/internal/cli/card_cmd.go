package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"impalactl/internal/card"
	"impalactl/internal/sep10"
)

var cardSubcommands = []string{
	"info --card tcp:HOST:PORT [--aid HEX]   Read-only: applet, ids, state, Stellar key, PIN policy",
	"setup --card tcp:HOST:PORT --account UUID [--currency XLM|USDC|USDT0] [--card-minor-scale 0..7]",
	"      [--initial-counter N] [--cap FILE] [--aid HEX]",
	"                                        Issue a card (operator: admin or key-custodian; plus the holder's token)",
	"pin change --card SPEC [--aid HEX]      The holder: verify the PIN, set a new one (applet 0.4)",
	"pin policy on|off --card SPEC           The holder: require / stop requiring the PIN to sign in",
	"pin reset --card SPEC [--aid HEX]       With the 8-digit master PIN: set a new user PIN (unblocks it)",
	"issuer show                             Is the card program configured (public)",
	"issuer generate [--rotate] [--confirm-phrase P]",
	"                                        Create (or rotate) the program issuer key (generate-only)",
}

func (a *App) runCard(opts options, args []string) int {
	if len(args) == 0 {
		a.subUsage(a.err, "card", cardSubcommands)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		a.subUsage(a.out, "card", cardSubcommands)
		return 0
	case "info":
		return a.runCardInfo(opts, args[1:])
	case "setup":
		return a.runCardSetup(opts, args[1:])
	case "pin":
		return a.runCardPin(opts, args[1:])
	case "issuer":
		return a.runCardIssuer(opts, args[1:])
	}
	fmt.Fprintf(a.err, "error: unknown subcommand %q\n\n", args[0])
	a.subUsage(a.err, "card", cardSubcommands)
	return 2
}

// cardInfo is `card info --json`: the card's public facts. Never the
// cardholder name, never a signature.
type cardInfo struct {
	Applet           string           `json:"applet"`
	AppletHash       string           `json:"applet_hash"`
	CardID           string           `json:"card_id"`
	Account          string           `json:"account_id"`
	State            string           `json:"state"`
	Flags            []string         `json:"flags"`
	ProgramID        string           `json:"program_id"`
	Certified        bool             `json:"issuer_certificate"`
	ECPubKey         string           `json:"ec_pubkey,omitempty"`
	StellarKey       *cardInfoStellar `json:"stellar_key"`
	UserVerification *cardInfoUV      `json:"user_verification"`
	SignsIn          string           `json:"signs_in_with"`
	Notes            []string         `json:"notes,omitempty"`
}

type cardInfoStellar struct {
	Engine  string `json:"engine"`
	Address string `json:"address"`
	Bound   bool   `json:"bound"`
}

type cardInfoUV struct {
	SignInPinRequired bool `json:"sign_in_pin_required"`
	SignInPinFixed    bool `json:"sign_in_pin_fixed"`
	PinProvisioned    bool `json:"pin_provisioned"`
	PinVerified       bool `json:"pin_verified"`
	TriesLeft         int  `json:"tries_left"`
}

func (a *App) runCardInfo(opts options, args []string) int {
	fs := a.newFlagSet("card info")
	bindGlobalFlags(fs, &opts)
	spec := fs.String("card", "", "the card: tcp:HOST:PORT (the impala-card simulator transport)")
	aid := fs.String("aid", "", "applet AID to SELECT (hex; default "+card.DefaultAID+")")
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseCode(err)
	}
	if len(rest) > 0 || *spec == "" {
		return a.usageErr("usage: impalactl card info --card tcp:HOST:PORT [--aid HEX]")
	}
	cd, id, err := a.openCard(opts, *spec, *aid)
	if err != nil {
		return a.fail("%v", err)
	}
	defer cd.Close()

	info := cardInfo{
		Applet:     id.Version.String(),
		AppletHash: id.Version.Hash,
		CardID:     id.WireCardID(),
		Account:    id.AccountUUID(),
		State:      card.StateName(id.Personalization.State),
		Flags:      card.FlagNames(id.Personalization.Flags),
		ProgramID:  hex.EncodeToString(id.Personalization.ProgramID),
		Certified:  id.Personalization.Certificate,
		SignsIn:    "legacy card challenge (SIGN_AUTH)",
	}
	if info.Flags == nil {
		info.Flags = []string{}
	}
	if id.ECPubKey != nil {
		info.ECPubKey = hex.EncodeToString(id.ECPubKey)
	}
	key, err := cd.GetStellarKey()
	if err != nil {
		return a.fail("%v", err)
	}
	if key != nil {
		addr, err := sep10.EncodeAccountID(key.PublicKey)
		if err != nil {
			return a.fail("%v", err)
		}
		info.StellarKey = &cardInfoStellar{Engine: key.EngineName(), Address: addr, Bound: key.Bound}
		info.SignsIn = "SEP-10 (SIGN_SEP10), legacy challenge where SEP-10 is not offered"
	} else if id.HasStellarKey() {
		info.Notes = append(info.Notes, "the card advertises a Stellar key but GET_STELLAR_KEY has none")
	}
	uv, err := cd.GetUserVerification()
	if err != nil {
		return a.fail("%v", err)
	}
	if uv != nil {
		info.UserVerification = &cardInfoUV{uv.SignInPinRequired, uv.SignInPinFixed, uv.PinProvisioned, uv.PinVerified, uv.TriesLeft}
	}
	if err := id.RequireSigner(); err != nil {
		info.SignsIn = "nothing: " + err.Error()
	}

	if opts.json {
		b, _ := json.Marshal(info)
		return a.printJSON(b)
	}
	rows := [][2]string{
		{"Applet:", fmt.Sprintf("%s (build %s)", info.Applet, info.AppletHash)},
		{"Card id:", info.CardID},
		{"Account:", info.Account},
		{"State:", fmt.Sprintf("%s (flags: %s)", info.State, dash(strings.Join(info.Flags, ", ")))},
		{"Program:", info.ProgramID},
		{"Issuer certificate:", yesNo(info.Certified)},
	}
	if info.StellarKey != nil {
		bound := "bound to the card key"
		if !info.StellarKey.Bound {
			bound = "not yet bound (personalize the card)"
		}
		rows = append(rows, [2]string{"Stellar key:", fmt.Sprintf("%s (%s engine, %s)",
			info.StellarKey.Address, info.StellarKey.Engine, bound)})
	} else {
		rows = append(rows, [2]string{"Stellar key:", "none"})
	}
	if uv != nil {
		rows = append(rows, [2]string{"User PIN:", uvText(uv)})
	} else {
		rows = append(rows, [2]string{"User PIN:", "not reported (applet older than 0.4: no PIN policy, no PIN proof)"})
	}
	rows = append(rows, [2]string{"Signs in with:", info.SignsIn})
	kv(a.out, rows)
	for _, n := range info.Notes {
		fmt.Fprintf(a.out, "Note: %s\n", n)
	}
	return 0
}
