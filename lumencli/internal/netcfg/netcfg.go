// Package netcfg resolves which Stellar network the CLI talks to.
//
// A Network bundles a Horizon endpoint with the network passphrase used when
// signing transactions; the two must agree or the network rejects the signed
// transaction. Selection precedence, highest first:
//
//  1. explicit flags (Options)
//  2. environment variables (LUMEN_NETWORK, LUMEN_HORIZON_URL, LUMEN_NETWORK_PASSPHRASE)
//  3. the built-in default (mainnet)
package netcfg

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/network"
)

// Canonical network names.
const (
	NameMainnet = "mainnet"
	NameTestnet = "testnet"
	NameCustom  = "custom"
)

// Built-in Horizon endpoints operated by the Stellar Development Foundation.
const (
	MainnetHorizonURL = "https://horizon.stellar.org"
	TestnetHorizonURL = "https://horizon-testnet.stellar.org"
)

// Environment variables consulted when the corresponding flag is empty.
const (
	EnvNetwork    = "LUMEN_NETWORK"
	EnvHorizonURL = "LUMEN_HORIZON_URL"
	EnvPassphrase = "LUMEN_NETWORK_PASSPHRASE"
)

// DefaultName is the network used when neither a flag nor an env var selects one.
//
// It defaults to mainnet to match this project's stated purpose. Every command
// that moves funds echoes the active network so the choice is never silent.
const DefaultName = NameMainnet

// Network is a fully-resolved network the CLI can connect to.
type Network struct {
	Name       string // "mainnet", "testnet", or "custom"
	HorizonURL string
	Passphrase string
	IsTestnet  bool // true only for the built-in testnet (gates Friendbot)
}

// String renders the network for display, e.g. "testnet (https://...)".
func (n Network) String() string {
	return fmt.Sprintf("%s (%s)", n.Name, n.HorizonURL)
}

// Options holds raw, possibly-empty configuration, typically taken from flags.
type Options struct {
	Network    string // network name or alias
	HorizonURL string // override Horizon endpoint
	Passphrase string // override network passphrase
}

// Getenv matches os.Getenv and is injected to keep Resolve testable.
type Getenv func(string) string

// Resolve combines flag options, environment, and defaults into a Network.
//
// A custom network (an unrecognized name) is allowed only when both a Horizon
// URL and a passphrase are supplied, since neither can be inferred.
func Resolve(opts Options, getenv Getenv) (Network, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	rawName := firstNonEmpty(opts.Network, getenv(EnvNetwork), DefaultName)
	horizonOverride := firstNonEmpty(opts.HorizonURL, getenv(EnvHorizonURL))
	passphraseOverride := firstNonEmpty(opts.Passphrase, getenv(EnvPassphrase))

	var net Network
	switch canonical, ok := canonicalName(rawName); {
	case ok:
		net = baseNetwork(canonical)
	case horizonOverride != "" && passphraseOverride != "":
		net = Network{Name: NameCustom}
	default:
		return Network{}, fmt.Errorf(
			"unknown network %q (use %q, %q, or supply both --horizon-url and --network-passphrase)",
			rawName, NameMainnet, NameTestnet)
	}

	if horizonOverride != "" {
		net.HorizonURL = horizonOverride
	}
	if passphraseOverride != "" {
		net.Passphrase = passphraseOverride
	}

	if err := net.validate(); err != nil {
		return Network{}, err
	}
	return net, nil
}

func baseNetwork(canonical string) Network {
	if canonical == NameTestnet {
		return Network{
			Name:       NameTestnet,
			HorizonURL: TestnetHorizonURL,
			Passphrase: network.TestNetworkPassphrase,
			IsTestnet:  true,
		}
	}
	return Network{
		Name:       NameMainnet,
		HorizonURL: MainnetHorizonURL,
		Passphrase: network.PublicNetworkPassphrase,
		IsTestnet:  false,
	}
}

// canonicalName maps user-facing aliases to a canonical network name.
func canonicalName(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "main", "mainnet", "public", "pubnet", "publicnet":
		return NameMainnet, true
	case "test", "testnet":
		return NameTestnet, true
	default:
		return "", false
	}
}

func (n Network) validate() error {
	if n.HorizonURL == "" {
		return fmt.Errorf("network %q has no Horizon URL configured", n.Name)
	}
	if !strings.HasPrefix(n.HorizonURL, "http://") && !strings.HasPrefix(n.HorizonURL, "https://") {
		return fmt.Errorf("invalid Horizon URL %q: must start with http:// or https://", n.HorizonURL)
	}
	if n.Passphrase == "" {
		return fmt.Errorf("network %q has no passphrase configured", n.Name)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
