package cli

import (
	"encoding/json"
	"fmt"

	"impalactl/internal/card"
	"impalactl/internal/config"
)

// `card pin change|policy|reset`: the cardholder-PIN commands of applet 0.4
// (docs/mfa-card-pin-biometrics.md §4). PINs are read before the card is
// touched; a wrong or blocked PIN is an error naming the card's status word.

const cardPinUsage = "usage: impalactl card pin change|reset --card tcp:HOST:PORT [--aid HEX]\n" +
	"       impalactl card pin policy on|off --card tcp:HOST:PORT [--aid HEX]"

// cardPinResult is `card pin … --json`.
type cardPinResult struct {
	CardID           string      `json:"card_id"`
	Action           string      `json:"action"`
	Changed          bool        `json:"changed"`
	UserVerification *cardInfoUV `json:"user_verification"`
}

func (a *App) runCardPin(opts options, args []string) int {
	if len(args) == 0 {
		return a.usageErr("%s", cardPinUsage)
	}
	action := args[0]
	fs := a.newFlagSet("card pin " + action)
	bindGlobalFlags(fs, &opts)
	spec := fs.String("card", "", "the card: tcp:HOST:PORT (the impala-card simulator transport)")
	aid := fs.String("aid", "", "applet AID to SELECT (hex; default "+card.DefaultAID+")")
	rest, err := parseArgs(fs, args[1:])
	if err != nil {
		return parseCode(err)
	}
	switch action {
	case "change", "reset":
		if len(rest) != 0 || *spec == "" {
			return a.usageErr("%s", cardPinUsage)
		}
	case "policy":
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") || *spec == "" {
			return a.usageErr("%s", cardPinUsage)
		}
	default:
		return a.usageErr("unknown subcommand %q (expected change, policy or reset)\n%s", action, cardPinUsage)
	}
	if _, _, err := card.ParseSpec(*spec); err != nil {
		return a.usageErr("%v", err)
	}
	switch action {
	case "change":
		return a.runCardPinChange(opts, *spec, *aid)
	case "reset":
		return a.runCardPinReset(opts, *spec, *aid)
	}
	return a.runCardPinPolicy(opts, *spec, *aid, rest[0] == "on")
}

// openPinCard opens the card and reads its PIN state: applet 0.4 and a
// provisioned user PIN are needed.
func (a *App) openPinCard(opts options, spec, aid string) (*card.Card, *card.Identity, *card.UserVerification, int) {
	cd, id, err := a.openCard(opts, spec, aid)
	if err != nil {
		return nil, nil, nil, a.fail("%v", err)
	}
	uv, err := cd.GetUserVerification()
	if err != nil {
		cd.Close()
		return nil, nil, nil, a.fail("%v", err)
	}
	if uv == nil {
		cd.Close()
		return nil, nil, nil, a.fail("card %s runs applet %s, which has no cardholder PIN commands (0.4 or newer is needed)",
			id.WireCardID(), id.Version)
	}
	if !uv.PinProvisioned {
		cd.Close()
		return nil, nil, nil, a.fail("card %s has no provisioned user PIN: issue it with `impalactl card setup` first",
			id.WireCardID())
	}
	return cd, id, uv, 0
}

// pinFail reports a PIN command's refusal, with a hint for a blocked PIN.
func (a *App) pinFail(err error) int {
	code := a.fail("%v", err)
	if card.SWOf(err) == card.SWPinBlocked {
		fmt.Fprintln(a.err, "hint: a blocked user PIN is set anew with the master PIN: `impalactl card pin reset`")
	}
	return code
}

func (a *App) runCardPinChange(opts options, spec, aid string) int {
	current, err := a.readSecret(config.EnvCardPIN, "Current card PIN: ")
	if err != nil {
		return a.usageErr("%v", err)
	}
	if len(current) != 4 || !isDigits(current) {
		return a.usageErr("$%s (the current PIN) must be 4 digits", config.EnvCardPIN)
	}
	next, err := a.readNewSecret(config.EnvCardNewPIN, "New card PIN: ", "Repeat the new card PIN: ")
	if err != nil {
		return a.usageErr("%v", err)
	}
	if !card.ValidUserPIN(next) {
		return a.usageErr("$%s (the new PIN) must be 4 digits, not all zeros", config.EnvCardNewPIN)
	}
	cd, id, _, code := a.openPinCard(opts, spec, aid)
	if code != 0 {
		return code
	}
	defer cd.Close()
	if err := cd.VerifyUserPIN(current); err != nil {
		return a.pinFail(err)
	}
	if err := cd.ChangeUserPIN(next); err != nil {
		return a.pinFail(err)
	}
	if err := cd.VerifyUserPIN(next); err != nil {
		return a.fail("the card took CHANGE_USER_PIN but the new PIN does not verify: %v", err)
	}
	return a.printPinResult(opts, cd, id, "pin-change", true, "the user PIN is changed (and verified once with the new PIN)")
}

func (a *App) runCardPinReset(opts options, spec, aid string) int {
	master, err := a.readSecret(config.EnvCardMasterPIN, "Card master PIN: ")
	if err != nil {
		return a.usageErr("%v", err)
	}
	if !card.ValidMasterPIN(master) {
		return a.usageErr("$%s must be 8 digits", config.EnvCardMasterPIN)
	}
	next, err := a.readNewSecret(config.EnvCardNewPIN, "New card PIN: ", "Repeat the new card PIN: ")
	if err != nil {
		return a.usageErr("%v", err)
	}
	if !card.ValidUserPIN(next) {
		return a.usageErr("$%s (the new PIN) must be 4 digits, not all zeros", config.EnvCardNewPIN)
	}
	cd, id, _, code := a.openPinCard(opts, spec, aid)
	if code != 0 {
		return code
	}
	defer cd.Close()
	fmt.Fprintln(a.err, "The master PIN has 10 tries and no recovery: once it is blocked, nothing can reset the user PIN.")
	if err := cd.VerifyMasterPIN(master); err != nil {
		return a.fail("%v", err)
	}
	if err := cd.UpdateUserPIN(next); err != nil {
		return a.fail("%v", err)
	}
	if err := cd.VerifyUserPIN(next); err != nil {
		return a.fail("the card took UPDATE_USER_PIN but the new PIN does not verify: %v", err)
	}
	return a.printPinResult(opts, cd, id, "pin-reset", true, "the user PIN is set anew (its try counter is reset)")
}

func (a *App) runCardPinPolicy(opts options, spec, aid string, on bool) int {
	pin, err := a.readSecret(config.EnvCardPIN, "Card PIN: ")
	if err != nil {
		return a.usageErr("%v", err)
	}
	if len(pin) != 4 || !isDigits(pin) {
		return a.usageErr("$%s must be 4 digits", config.EnvCardPIN)
	}
	action := "policy-off"
	if on {
		action = "policy-on"
	}
	cd, id, uv, code := a.openPinCard(opts, spec, aid)
	if code != 0 {
		return code
	}
	defer cd.Close()
	if uv.SignInPinRequired == on {
		fmt.Fprintf(a.err, "card %s already %s; nothing was sent\n", id.WireCardID(), policyText(on))
		return a.printPinResult(opts, cd, id, action, false, "unchanged")
	}
	if err := cd.VerifyUserPIN(pin); err != nil {
		return a.pinFail(err)
	}
	if err := cd.SetSignInPolicy(on); err != nil {
		if card.SWOf(err) == card.SWConditions && !on {
			if now, rerr := cd.GetUserVerification(); rerr == nil && now != nil && now.SignInPinFixed {
				return a.fail("card %s's sign-in PIN requirement was fixed at install: it can never be turned off",
					id.WireCardID())
			}
		}
		return a.fail("%v", err)
	}
	return a.printPinResult(opts, cd, id, action, true, "the card now "+policyText(on))
}

func policyText(on bool) string {
	if on {
		return "requires its user PIN to sign in"
	}
	return "signs in without its user PIN"
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// printPinResult reads GET_USER_VERIFICATION back and reports it.
func (a *App) printPinResult(opts options, cd *card.Card, id *card.Identity, action string, changed bool, what string) int {
	uv, err := cd.GetUserVerification()
	if err != nil || uv == nil {
		return a.fail("read the PIN state back: %v", err)
	}
	res := cardPinResult{CardID: id.WireCardID(), Action: action, Changed: changed,
		UserVerification: &cardInfoUV{uv.SignInPinRequired, uv.SignInPinFixed, uv.PinProvisioned, uv.PinVerified, uv.TriesLeft}}
	if opts.json {
		b, _ := json.Marshal(res)
		return a.printJSON(b)
	}
	kv(a.out, [][2]string{
		{"Card id:", res.CardID},
		{"Result:", what},
		{"User PIN:", uvText(uv)},
	})
	return 0
}

// uvText renders a card's PIN state (card info, card pin).
func uvText(uv *card.UserVerification) string {
	policy := "not required to sign in"
	if uv.SignInPinRequired {
		policy = "REQUIRED to sign in"
		if uv.SignInPinFixed {
			policy += " (fixed at install)"
		}
	}
	prov := "no user PIN provisioned (no PIN proof possible)"
	if uv.PinProvisioned {
		prov = fmt.Sprintf("user PIN provisioned, %d tries left", uv.TriesLeft)
	}
	return policy + "; " + prov
}
