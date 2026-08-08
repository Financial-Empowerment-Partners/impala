package cli

import (
	"fmt"
	"strings"
)

// These mirror impala-bridge/src/validate.rs so an obvious mistake fails
// before a round trip (and before a password prompt). The bridge re-validates
// everything server-side; this is convenience, never a security boundary.

const strKeyLength = 56

// validateStellarAccountID checks the shape of a `G...` public address.
func validateStellarAccountID(id string) error {
	return validateStrKey(id, 'G', "Stellar account id")
}

// validateStellarSecretSeed checks the shape of an `S...` secret seed. The
// checksum is verified by the bridge when it decodes the keypair.
func validateStellarSecretSeed(seed string) error {
	return validateStrKey(seed, 'S', "Stellar secret seed")
}

func validateStrKey(value string, prefix byte, label string) error {
	if len(value) != strKeyLength {
		return fmt.Errorf("%s must be %d characters (got %d)", label, strKeyLength, len(value))
	}
	if value[0] != prefix {
		return fmt.Errorf("%s must start with %q", label, string(prefix))
	}
	for _, r := range value {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '7') {
			return fmt.Errorf("%s must contain only base32 characters (A-Z, 2-7)", label)
		}
	}
	return nil
}

// validateAmount checks a Stellar amount string: a positive decimal with at
// most 7 fractional digits, the precision the network stores.
func validateAmount(amount string) error {
	if amount == "" {
		return fmt.Errorf("amount must not be empty")
	}
	intPart, fracPart, hasFrac := strings.Cut(amount, ".")
	if intPart == "" && !hasFrac {
		return fmt.Errorf("invalid amount %q", amount)
	}
	digits := func(s string) bool {
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if !digits(intPart) || (hasFrac && !digits(fracPart)) {
		return fmt.Errorf("invalid amount %q: expected a positive decimal like 12.5", amount)
	}
	if hasFrac {
		if fracPart == "" {
			return fmt.Errorf("invalid amount %q: no digits after the decimal point", amount)
		}
		if len(fracPart) > 7 {
			return fmt.Errorf("invalid amount %q: Stellar supports at most 7 decimal places", amount)
		}
	}
	if strings.Trim(intPart+fracPart, "0") == "" {
		return fmt.Errorf("amount must be greater than zero")
	}
	return nil
}
