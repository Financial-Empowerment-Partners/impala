package netcfg

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
)

// envFunc builds a Getenv from a map.
func envFunc(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestResolveDefaultsToMainnet(t *testing.T) {
	net, err := Resolve(Options{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != NameMainnet {
		t.Errorf("Name = %q, want %q", net.Name, NameMainnet)
	}
	if net.HorizonURL != MainnetHorizonURL {
		t.Errorf("HorizonURL = %q, want %q", net.HorizonURL, MainnetHorizonURL)
	}
	if net.Passphrase != network.PublicNetworkPassphrase {
		t.Errorf("Passphrase = %q, want public passphrase", net.Passphrase)
	}
	if net.IsTestnet {
		t.Error("IsTestnet = true, want false for mainnet")
	}
}

func TestResolveFlagSelectsTestnet(t *testing.T) {
	net, err := Resolve(Options{Network: "testnet"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != NameTestnet || !net.IsTestnet {
		t.Errorf("got %+v, want testnet with IsTestnet=true", net)
	}
	if net.Passphrase != network.TestNetworkPassphrase {
		t.Errorf("Passphrase = %q, want test passphrase", net.Passphrase)
	}
}

func TestResolveAliases(t *testing.T) {
	cases := map[string]string{
		"main":    NameMainnet,
		"MAINNET": NameMainnet,
		"pubnet":  NameMainnet,
		"public":  NameMainnet,
		" test ":  NameTestnet,
		"TestNet": NameTestnet,
	}
	for in, want := range cases {
		net, err := Resolve(Options{Network: in}, nil)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", in, err)
			continue
		}
		if net.Name != want {
			t.Errorf("Resolve(%q).Name = %q, want %q", in, net.Name, want)
		}
	}
}

func TestResolveEnvUsedWhenFlagEmpty(t *testing.T) {
	net, err := Resolve(Options{}, envFunc(map[string]string{EnvNetwork: "testnet"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != NameTestnet {
		t.Errorf("Name = %q, want testnet (from env)", net.Name)
	}
}

func TestResolveFlagBeatsEnv(t *testing.T) {
	net, err := Resolve(
		Options{Network: "mainnet"},
		envFunc(map[string]string{EnvNetwork: "testnet"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != NameMainnet {
		t.Errorf("Name = %q, want mainnet (flag overrides env)", net.Name)
	}
}

func TestResolveUnknownNetworkErrors(t *testing.T) {
	if _, err := Resolve(Options{Network: "futurenet"}, nil); err == nil {
		t.Error("expected error for unknown network without overrides")
	}
}

func TestResolveCustomNetworkViaOverrides(t *testing.T) {
	net, err := Resolve(Options{
		Network:    "futurenet",
		HorizonURL: "https://horizon-futurenet.example.org",
		Passphrase: "Test SDF Future Network ; October 2022",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.Name != NameCustom {
		t.Errorf("Name = %q, want custom", net.Name)
	}
	if net.HorizonURL != "https://horizon-futurenet.example.org" {
		t.Errorf("HorizonURL = %q", net.HorizonURL)
	}
	if net.IsTestnet {
		t.Error("custom network must not be treated as built-in testnet")
	}
}

func TestResolveHorizonOverrideKeepsKnownNetwork(t *testing.T) {
	net, err := Resolve(Options{
		Network:    "testnet",
		HorizonURL: "http://localhost:8000",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.HorizonURL != "http://localhost:8000" {
		t.Errorf("HorizonURL = %q, want override", net.HorizonURL)
	}
	if net.Passphrase != network.TestNetworkPassphrase {
		t.Error("expected testnet passphrase to remain after Horizon-only override")
	}
	if !net.IsTestnet {
		t.Error("IsTestnet should remain true for overridden testnet")
	}
}

func TestResolveOptionOverridesEnvForHorizon(t *testing.T) {
	net, err := Resolve(
		Options{Network: "testnet", HorizonURL: "http://flag-url:8000"},
		envFunc(map[string]string{EnvHorizonURL: "http://env-url:8000"}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if net.HorizonURL != "http://flag-url:8000" {
		t.Errorf("HorizonURL = %q, want flag value", net.HorizonURL)
	}
}

func TestResolveRejectsBadHorizonURL(t *testing.T) {
	_, err := Resolve(Options{Network: "testnet", HorizonURL: "localhost:8000"}, nil)
	if err == nil {
		t.Error("expected error for Horizon URL without http(s) scheme")
	}
}
