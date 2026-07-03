package stellar

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
)

// wrapHorizonError turns an opaque Horizon error into a readable message.
//
// Horizon reports failures as RFC 7807 "problem" documents; for rejected
// transactions the useful detail lives in the result codes (e.g.
// "tx_insufficient_balance", "op_no_destination"). This surfaces those so the
// user learns *why* a transfer failed rather than just "horizon error".
func wrapHorizonError(context string, err error) error {
	herr := horizonclient.GetError(err)
	if herr == nil {
		return fmt.Errorf("%s: %w", context, err)
	}

	title := herr.Problem.Title
	if title == "" {
		title = "horizon error"
	}

	if codes, e := herr.ResultCodes(); e == nil && codes != nil {
		if len(codes.OperationCodes) > 0 {
			return fmt.Errorf("%s: %s (tx=%s, ops=%v)", context, title, codes.TransactionCode, codes.OperationCodes)
		}
		if codes.TransactionCode != "" {
			return fmt.Errorf("%s: %s (tx=%s)", context, title, codes.TransactionCode)
		}
	}
	if detail := herr.Problem.Detail; detail != "" {
		return fmt.Errorf("%s: %s — %s", context, title, detail)
	}
	return fmt.Errorf("%s: %s", context, title)
}
