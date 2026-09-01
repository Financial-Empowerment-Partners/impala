package stellar

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"
)

// txHashPattern is the shape of a transaction hash: 64 hex digits (32 bytes).
// Explorers render hashes in either case, so both are accepted.
var txHashPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// NormalizeTxHash validates a transaction hash and returns its canonical
// (lowercase) form. It runs before any network call so a malformed paste
// fails with a clear message rather than a Horizon 400.
func NormalizeTxHash(s string) (string, error) {
	h := strings.TrimSpace(s)
	if !txHashPattern.MatchString(h) {
		return "", fmt.Errorf("invalid transaction hash %q: want 64 hex digits", s)
	}
	return strings.ToLower(h), nil
}

// TransactionInfo fetches one transaction and its operations.
//
// IncludeFailed is set on the operations request so a failed transaction's
// operations are returned too: what a failed transaction tried to do is
// exactly what someone looking it up wants to know.
func (c *Client) TransactionInfo(hash string) (hProtocol.Transaction, []operations.Operation, error) {
	h, err := NormalizeTxHash(hash)
	if err != nil {
		return hProtocol.Transaction{}, nil, err
	}
	tx, err := c.horizon.TransactionDetail(h)
	if err != nil {
		if horizonclient.IsNotFoundError(err) {
			return hProtocol.Transaction{}, nil, fmt.Errorf("transaction %s not found on %s", h, c.net.Name)
		}
		return hProtocol.Transaction{}, nil, wrapHorizonError("fetch transaction", err)
	}
	page, err := c.horizon.Operations(horizonclient.OperationRequest{
		ForTransaction: h,
		IncludeFailed:  true,
		Limit:          historyPageLimit,
	})
	if err != nil {
		return hProtocol.Transaction{}, nil, wrapHorizonError("fetch transaction operations", err)
	}
	return tx, page.Embedded.Records, nil
}
