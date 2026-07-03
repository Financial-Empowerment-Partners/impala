package cli

import (
	"bytes"
	"strings"
	"testing"

	"lumencli/internal/netcfg"
	"lumencli/internal/wallet"
)

// newTestApp builds an App wired to in-memory streams and a fake environment.
func newTestApp(stdin string, env map[string]string) (*App, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	app := &App{
		in:     strings.NewReader(stdin),
		out:    &out,
		err:    &errb,
		getenv: func(k string) string { return env[k] },
	}
	return app, &out, &errb
}

func TestVersion(t *testing.T) {
	app, out, _ := newTestApp("", nil)
	if code := app.run([]string{"version"}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), version) {
		t.Errorf("version output %q does not contain %q", out.String(), version)
	}
}

func TestHelp(t *testing.T) {
	app, out, _ := newTestApp("", nil)
	if code := app.run([]string{"help"}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("help output missing usage banner")
	}
}

func TestNoArgsShowsUsage(t *testing.T) {
	app, _, _ := newTestApp("", nil)
	if code := app.run(nil); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestUnknownCommand(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"frobnicate"}); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("stderr %q missing 'unknown command'", errb.String())
	}
}

func TestAccountNewOffline(t *testing.T) {
	app, out, _ := newTestApp("", nil)
	if code := app.run([]string{"account", "new"}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	s := out.String()
	if !strings.Contains(s, "Public key") || !strings.Contains(s, "Secret seed") {
		t.Fatalf("output missing key fields:\n%s", s)
	}
	// The printed address must be a valid G-strkey.
	var addr string
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, "Public key") {
			fields := strings.Fields(ln)
			addr = fields[len(fields)-1]
		}
	}
	if err := wallet.ValidateAddress(addr); err != nil {
		t.Errorf("printed address %q invalid: %v", addr, err)
	}
}

func TestAccountAddressFromEnvSecret(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, out, _ := newTestApp("", map[string]string{EnvSecret: kp.Seed()})
	if code := app.run([]string{"account", "address"}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != kp.Address() {
		t.Errorf("address = %q, want %q", got, kp.Address())
	}
}

func TestAccountAddressFromStdin(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, out, _ := newTestApp(kp.Seed()+"\n", nil)
	if code := app.run([]string{"account", "address"}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != kp.Address() {
		t.Errorf("address = %q, want %q", got, kp.Address())
	}
}

func TestBalanceRequiresOneAddress(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"balance"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "usage") {
		t.Errorf("stderr %q missing usage hint", errb.String())
	}
}

// TestBalanceParsesSubcommandNetworkFlag confirms that --network placed after
// the subcommand is parsed (not treated as a positional). A bogus value must
// surface as an "unknown network" error during resolution, before any network
// call.
func TestBalanceParsesSubcommandNetworkFlag(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"balance", "--network", "bogus", kp.Address()})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "unknown network") {
		t.Errorf("stderr %q missing 'unknown network' (flag not parsed?)", errb.String())
	}
}

func TestSendRequiresToAndAmount(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"send", "--to", ""}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "requires --to and --amount") {
		t.Errorf("stderr %q missing requirement hint", errb.String())
	}
}

func TestSendRejectsBadDestination(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"send", "--to", "not-an-address", "--amount", "10"})
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "invalid account address") {
		t.Errorf("stderr %q missing address validation error", errb.String())
	}
}

func TestReceiveWithAddress(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, out, _ := newTestApp("", nil)
	if code := app.run([]string{"receive", "--address", kp.Address()}); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), kp.Address()) {
		t.Errorf("output %q missing address", out.String())
	}
}

func TestReceiveRejectsBadAddress(t *testing.T) {
	app, _, errb := newTestApp("", nil)
	if code := app.run([]string{"receive", "--address", "nope"}); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "invalid account address") {
		t.Errorf("stderr %q missing address validation error", errb.String())
	}
}

// TestSendRefusesMainnetWithoutConfirmation locks in the headline safety gate:
// on the default (mainnet) network, a non-interactive send must refuse rather
// than silently spend real funds. It must fail BEFORE asking for the secret.
func TestSendRefusesMainnetWithoutConfirmation(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"send", "--to", kp.Address(), "--amount", "10"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	es := errb.String()
	if !strings.Contains(es, "refusing") || !strings.Contains(es, "--yes") {
		t.Errorf("stderr %q missing mainnet confirmation refusal", es)
	}
	if strings.Contains(es, "secret seed") {
		t.Errorf("send prompted for the secret before confirming the network: %q", es)
	}
}

func TestSendRejectsZeroAmount(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"send", "--to", kp.Address(), "--amount", "0", "--network", "testnet"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "greater than 0") {
		t.Errorf("stderr %q missing zero-amount rejection", errb.String())
	}
}

func TestSendRejectsNonNumericAmount(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"send", "--to", kp.Address(), "--amount", "abc", "--network", "testnet"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "invalid amount") {
		t.Errorf("stderr %q missing invalid-amount rejection", errb.String())
	}
}

// TestBalanceFlagAfterPositional proves the GNU-style arg permutation: a flag
// placed after the positional address is parsed (not silently dropped).
func TestBalanceFlagAfterPositional(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"balance", kp.Address(), "--network", "bogus"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "unknown network") {
		t.Errorf("stderr %q: trailing --network was not parsed", errb.String())
	}
}

func TestAccountCreateRefusesMainnetWithoutConfirmation(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	app, _, errb := newTestApp("", nil)
	code := app.run([]string{"account", "create", "--dest", kp.Address(), "--amount", "10"})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "refusing") {
		t.Errorf("stderr %q missing mainnet confirmation refusal", errb.String())
	}
}

// TestOfflineCommandsAcceptNetworkFlag confirms account address / receive accept
// the global --network flag after the command (offline; value ignored).
func TestOfflineCommandsAcceptNetworkFlag(t *testing.T) {
	kp, err := wallet.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	app, out, _ := newTestApp("", map[string]string{EnvSecret: kp.Seed()})
	if code := app.run([]string{"account", "address", "--network", "testnet"}); code != 0 {
		t.Fatalf("account address --network testnet: exit %d, want 0", code)
	}
	if got := strings.TrimSpace(out.String()); got != kp.Address() {
		t.Errorf("address = %q, want %q", got, kp.Address())
	}

	app2, out2, _ := newTestApp("", nil)
	if code := app2.run([]string{"receive", "--address", kp.Address(), "--network", "testnet"}); code != 0 {
		t.Fatalf("receive --network testnet: exit %d, want 0", code)
	}
	if !strings.Contains(out2.String(), kp.Address()) {
		t.Errorf("receive output %q missing address", out2.String())
	}
}

func TestConfirmSpend(t *testing.T) {
	testnet := netcfg.Network{Name: "testnet", IsTestnet: true}
	mainnet := netcfg.Network{Name: "mainnet"}

	app, _, _ := newTestApp("", nil)
	if err := app.confirmSpend(testnet, "send 1 XLM", false); err != nil {
		t.Errorf("testnet should not require confirmation: %v", err)
	}
	if err := app.confirmSpend(mainnet, "send 1 XLM", true); err != nil {
		t.Errorf("--yes should bypass confirmation: %v", err)
	}
	if err := app.confirmSpend(mainnet, "send 1 XLM", false); err == nil {
		t.Error("mainnet non-interactive without --yes must refuse")
	}
}
