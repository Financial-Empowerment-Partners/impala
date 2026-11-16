package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"impalactl/internal/card/cardtest"
	"impalactl/internal/config"
)

func pinHarness(t *testing.T, c *cardtest.Card, env map[string]string) (*harness, string) {
	t.Helper()
	h := newHarness(t, "", nil)
	for k, v := range env {
		h.env[k] = v
	}
	return h, c.Start(t)
}

func userPIN(c *cardtest.Card) (pin string, required bool) {
	c.With(func(c *cardtest.Card) { pin, required = c.PIN, c.RequirePIN })
	return
}

func TestCardPinChange(t *testing.T) {
	c := cardtest.New(t)
	h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234", config.EnvCardNewPIN: "5678"})
	if code := h.run("card", "pin", "change", "--card", spec, "--json"); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, h.stderr())
	}
	if pin, _ := userPIN(c); pin != "5678" {
		t.Errorf("pin = %q", pin)
	}
	if got := commands(c); !strings.HasSuffix(got, "VERIFY_PIN CHANGE_USER_PIN VERIFY_PIN GET_USER_VERIFICATION") {
		t.Errorf("commands: %s", got)
	}
	var res cardPinResult
	if err := json.Unmarshal(h.out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.CardID != "ea94fa5b0f6b2abc1626bc50c0bd5e17" || res.Action != "pin-change" || !res.Changed ||
		res.UserVerification == nil || !res.UserVerification.PinVerified || res.UserVerification.TriesLeft != 5 {
		t.Errorf("result %+v %+v", res, res.UserVerification)
	}
	noSecretsIn(t, h, "1234", "5678")
}

func TestCardPinChangeRefusals(t *testing.T) {
	t.Run("a wrong current PIN", func(t *testing.T) {
		c := cardtest.New(t)
		h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "9999", config.EnvCardNewPIN: "5678"})
		if code := h.run("card", "pin", "change", "--card", spec); code != 1 {
			t.Fatalf("exit = %d", code)
		}
		if !strings.Contains(h.stderr(), "SW 69C4 WRONG_PIN: 4 tries left") || c.Received("CHANGE_USER_PIN") {
			t.Errorf("stderr:\n%s", h.stderr())
		}
		noSecretsIn(t, h, "9999", "5678")
	})
	t.Run("applet 0.3", func(t *testing.T) {
		c := cardtest.New(t)
		c.Minor = 3
		h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234", config.EnvCardNewPIN: "5678"})
		if code := h.run("card", "pin", "change", "--card", spec); code != 1 || !strings.Contains(h.stderr(), "0.4 or newer") {
			t.Errorf("exit = %d:\n%s", code, h.stderr())
		}
		if c.Received("VERIFY_PIN") {
			t.Error("a PIN was sent to a 0.3 card")
		}
	})
	t.Run("no provisioned PIN", func(t *testing.T) {
		c := cardtest.New(t)
		c.PIN = ""
		h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234", config.EnvCardNewPIN: "5678"})
		if code := h.run("card", "pin", "change", "--card", spec); code != 1 || !strings.Contains(h.stderr(), "no provisioned user PIN") {
			t.Errorf("exit = %d:\n%s", code, h.stderr())
		}
	})
	t.Run("a new PIN of all zeros", func(t *testing.T) {
		c := cardtest.New(t)
		h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234", config.EnvCardNewPIN: "0000"})
		if code := h.run("card", "pin", "change", "--card", spec); code != 2 || len(c.Log()) != 0 {
			t.Errorf("exit = %d, card %v", code, c.Log())
		}
	})
}

func TestABlockedPinIsResetWithTheMasterPin(t *testing.T) {
	c := cardtest.New(t)
	c.MasterPIN = "31415926"
	c.SetTries(0)
	h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234", config.EnvCardNewPIN: "5678"})
	if code := h.run("card", "pin", "change", "--card", spec); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "PIN_BLOCKED") || !strings.Contains(h.stderr(), "card pin reset") {
		t.Errorf("stderr:\n%s", h.stderr())
	}

	// A wrong master PIN reports its tries.
	h, _ = pinHarness(t, c, map[string]string{config.EnvCardMasterPIN: "11111111", config.EnvCardNewPIN: "5678"})
	if code := h.run("card", "pin", "reset", "--card", spec); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "WRONG_PIN: 9 tries left") || !strings.Contains(h.stderr(), "10 tries and no recovery") ||
		c.Received("UPDATE_USER_PIN") {
		t.Errorf("stderr:\n%s", h.stderr())
	}

	h, _ = pinHarness(t, c, map[string]string{config.EnvCardMasterPIN: "31415926", config.EnvCardNewPIN: "5678", config.EnvCardPIN: "5678"})
	if code := h.run("card", "pin", "reset", "--card", spec, "--json"); code != 0 {
		t.Fatalf("reset exit = %d:\n%s", code, h.stderr())
	}
	if pin, _ := userPIN(c); pin != "5678" || c.TriesLeft() != 5 || c.MasterTriesLeft() != 10 {
		t.Errorf("pin %q tries %d master %d", pin, c.TriesLeft(), c.MasterTriesLeft())
	}
	if got := commands(c); !strings.HasSuffix(got, "VERIFY_PIN UPDATE_USER_PIN VERIFY_PIN GET_USER_VERIFICATION") {
		t.Errorf("commands: %s", got)
	}
	if !strings.Contains(h.stdout(), `"action": "pin-reset"`) {
		t.Errorf("stdout %s", h.stdout())
	}
	noSecretsIn(t, h, "31415926", "5678")
}

func TestCardPinPolicy(t *testing.T) {
	c := cardtest.New(t)
	h, spec := pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234"})
	if code := h.run("card", "pin", "policy", "on", "--card", spec); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, h.stderr())
	}
	if _, req := userPIN(c); !req || !strings.Contains(h.stdout(), "REQUIRED to sign in") {
		t.Errorf("required %v:\n%s", req, h.stdout())
	}

	// Already on: nothing is sent, not even the PIN.
	before := c.Count("VERIFY_PIN")
	h, _ = pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234"})
	if code := h.run("card", "pin", "policy", "on", "--card", spec, "--json"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if c.Count("VERIFY_PIN") != before || !strings.Contains(h.stderr(), "already requires") || !strings.Contains(h.stdout(), `"changed": false`) {
		t.Errorf("stderr %s stdout %s", h.stderr(), h.stdout())
	}

	h, _ = pinHarness(t, c, map[string]string{config.EnvCardPIN: "1234"})
	if code := h.run("card", "pin", "policy", "off", "--card", spec); code != 0 {
		t.Fatalf("off exit = %d:\n%s", code, h.stderr())
	}
	if _, req := userPIN(c); req {
		t.Error("still required")
	}

	// A requirement fixed at install never turns off.
	f := cardtest.New(t)
	f.RequirePIN, f.FixedPIN = true, true
	h, fspec := pinHarness(t, f, map[string]string{config.EnvCardPIN: "1234"})
	if code := h.run("card", "pin", "policy", "off", "--card", fspec); code != 1 {
		t.Fatalf("fixed exit = %d", code)
	}
	if !strings.Contains(h.stderr(), "fixed at install: it can never be turned off") {
		t.Errorf("stderr:\n%s", h.stderr())
	}
	if _, req := userPIN(f); !req {
		t.Error("a fixed requirement was turned off")
	}

	h, _ = pinHarness(t, c, map[string]string{config.EnvCardPIN: "4321"})
	if code := h.run("card", "pin", "policy", "on", "--card", spec); code != 1 || !strings.Contains(h.stderr(), "tries left") {
		t.Errorf("wrong PIN: exit = %d:\n%s", code, h.stderr())
	}
	noSecretsIn(t, h, "4321")

	h, _ = pinHarness(t, c, nil)
	if code := h.run("card", "pin", "policy", "maybe", "--card", spec); code != 2 {
		t.Errorf("usage exit = %d", code)
	}
}

// ── card issuer ────────────────────────────────────────────────────────

func issuerHarness(t *testing.T, setup func(*issueBridge)) (*harness, *issueBridge) {
	t.Helper()
	b := newIssueBridge(t)
	if setup != nil {
		setup(b)
	}
	h := newHarness(t, "", b.handler())
	h.env[config.EnvToken] = b.operator
	return h, b
}

func TestCardIssuerShow(t *testing.T) {
	h, b := issuerHarness(t, nil)
	delete(h.env, config.EnvToken) // public
	if code := h.run("card", "issuer", "show"); code != 0 {
		t.Fatalf("exit = %d:\n%s", code, h.stderr())
	}
	for _, want := range []string{"Configured:", b.fingerprint, b.issuerHex, "9e1f0000-0000-4000-8000-00000000abcd"} {
		if !strings.Contains(h.stdout(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, h.stdout())
		}
	}
	h, _ = issuerHarness(t, func(b *issueBridge) { b.configured = false })
	if code := h.run("card", "issuer", "show"); code != 0 || !strings.Contains(h.stdout(), "not configured") {
		t.Errorf("exit = %d:\n%s", code, h.stdout())
	}
	h, _ = issuerHarness(t, func(b *issueBridge) { b.configured = false })
	if code := h.run("card", "issuer", "show", "--json"); code != 0 || !strings.Contains(h.stdout(), `"configured": false`) {
		t.Errorf("json exit = %d:\n%s", code, h.stdout())
	}
}

func TestCardIssuerGenerate(t *testing.T) {
	t.Run("the first key", func(t *testing.T) {
		h, b := issuerHarness(t, func(b *issueBridge) { b.configured = false })
		if code := h.run("card", "issuer", "generate"); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, h.stderr())
		}
		if len(b.generate) != 1 || b.generate[0] != "{}" || !strings.Contains(h.stdout(), b.fingerprint) {
			t.Errorf("bodies %v:\n%s", b.generate, h.stdout())
		}
	})
	t.Run("an active key without --rotate", func(t *testing.T) {
		h, b := issuerHarness(t, nil)
		if code := h.run("card", "issuer", "generate", "--yes"); code != 1 {
			t.Fatalf("exit = %d", code)
		}
		if len(b.generate) != 0 || !strings.Contains(h.stderr(), "re-personalized and re-certified") {
			t.Errorf("bodies %v:\n%s", b.generate, h.stderr())
		}
	})
	t.Run("a rotation with the phrase", func(t *testing.T) {
		h, b := issuerHarness(t, nil)
		old := b.fingerprint
		if code := h.run("card", "issuer", "generate", "--rotate", "--confirm-phrase", "replace card-issuer testnet", "--json"); code != 0 {
			t.Fatalf("exit = %d:\n%s", code, h.stderr())
		}
		want := `{"confirm_phrase":"replace card-issuer testnet","confirm_supersede":"` + old + `"}`
		if len(b.generate) != 1 || b.generate[0] != want || !strings.Contains(h.stdout(), `"replaced": true`) {
			t.Errorf("bodies %v:\n%s", b.generate, h.stdout())
		}
	})
	t.Run("a wrong phrase, and --yes without one", func(t *testing.T) {
		h, b := issuerHarness(t, nil)
		if code := h.run("card", "issuer", "generate", "--rotate", "--confirm-phrase", "replace card-issuer pubnet"); code != 1 {
			t.Fatalf("exit = %d", code)
		}
		h2, _ := issuerHarness(t, nil)
		h2.srv, h2.env[config.EnvEndpoint] = h.srv, h.env[config.EnvEndpoint]
		if code := h2.run("card", "issuer", "generate", "--rotate", "--yes"); code != 1 ||
			!strings.Contains(h2.stderr(), `--confirm-phrase "replace card-issuer testnet"`) {
			t.Errorf("--yes exit = %d:\n%s", code, h2.stderr())
		}
		if len(b.generate) != 0 {
			t.Errorf("a rotation was sent: %v", b.generate)
		}
	})
	t.Run("a 429", func(t *testing.T) {
		h, _ := issuerHarness(t, func(b *issueBridge) { b.configured = false; b.generateStatus = 429 })
		if code := h.run("card", "issuer", "generate"); code != 1 || !strings.Contains(h.stderr(), "5 per 60 s") {
			t.Errorf("exit = %d:\n%s", code, h.stderr())
		}
	})
	t.Run("a live network needs confirmation", func(t *testing.T) {
		h, b := issuerHarness(t, func(b *issueBridge) { b.configured = false; b.network = "pubnet" })
		if code := h.run("card", "issuer", "generate"); code != 1 || len(b.generate) != 0 ||
			!strings.Contains(h.stderr(), "refusing to generate the card program issuer key on PUBNET without confirmation") ||
			strings.Contains(h.stderr(), "FUNDS") {
			t.Errorf("exit = %d:\n%s", code, h.stderr())
		}
	})
}

// The transfer prompt keeps its words byte for byte; the card commands name
// their own stake.
func TestConfirmPromptNamesTheStake(t *testing.T) {
	if got := confirmPrompt("send 1 XLM", "PUBNET", stakeFunds); got != "About to send 1 XLM on PUBNET — REAL FUNDS.\nType \"yes\" to proceed: " {
		t.Errorf("transfer prompt %q", got)
	}
	if got := confirmPrompt("issue this card", "PUBNET", "it writes a certificate on the bridge and personalizes the card"); strings.Contains(got, "FUNDS") {
		t.Errorf("card prompt %q", got)
	}
}
