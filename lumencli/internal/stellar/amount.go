package stellar

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/amount"
)

// ValidateAmount checks that s is a well-formed, strictly positive XLM amount.
//
// It mirrors the parsing the SDK applies when building an operation, but runs
// up front so the CLI can reject bad input (whitespace, non-numeric, zero, or
// negative) with a clear message instead of a deep txnbuild error after a
// network round-trip. The amount is expected to already be trimmed.
func ValidateAmount(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("amount is required")
	}
	v, err := amount.ParseInt64(s)
	if err != nil {
		return fmt.Errorf("invalid amount %q: %v", s, err)
	}
	if v <= 0 {
		return fmt.Errorf("amount must be greater than 0 (got %q)", s)
	}
	return nil
}
