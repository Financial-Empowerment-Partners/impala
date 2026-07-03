// Package wallet handles Stellar key material.
//
// Every operation here is offline cryptography — none of it touches the
// network. A Stellar account is an ed25519 keypair: the public key is the
// account address (a "G..." strkey) and the secret seed (an "S..." strkey)
// authorizes spending. Guard the seed accordingly.
package wallet

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/keypair"
)

// Generate creates a new random Stellar keypair.
func Generate() (*keypair.Full, error) {
	kp, err := keypair.Random()
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return kp, nil
}

// ParseSecret validates a secret seed (S...) and returns the full keypair,
// which can sign transactions.
func ParseSecret(secret string) (*keypair.Full, error) {
	kp, err := keypair.ParseFull(strings.TrimSpace(secret))
	if err != nil {
		return nil, fmt.Errorf("invalid secret seed (expected an S... seed): %w", err)
	}
	return kp, nil
}

// AddressFromSecret derives the public address (G...) from a secret seed.
func AddressFromSecret(secret string) (string, error) {
	kp, err := ParseSecret(secret)
	if err != nil {
		return "", err
	}
	return kp.Address(), nil
}

// ValidateAddress reports whether addr is a well-formed public address (G...).
func ValidateAddress(addr string) error {
	if _, err := keypair.ParseAddress(strings.TrimSpace(addr)); err != nil {
		return fmt.Errorf("invalid account address (expected a G... address): %w", err)
	}
	return nil
}
