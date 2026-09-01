package stellar

import (
	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/protocols/horizon/operations"

	"lumencli/internal/wallet"
)

// historyPageLimit is how many records each Horizon page request asks for.
// 200 is Horizon's maximum; asking for less would only mean more round-trips
// to fetch the same history.
const historyPageLimit = 200

// HistoryOpts selects what a history walk covers.
type HistoryOpts struct {
	// IncludeFailed additionally reports operations from failed transactions,
	// which moved no funds; Horizon omits them by default.
	IncludeFailed bool
	// AllOps walks the /operations endpoint (every operation type) instead of
	// /payments (only the fund-moving kinds: payments, path payments, account
	// creations, and merges).
	AllOps bool
}

// EachOperation walks accountID's history newest-first, calling visit for
// every operation until the history is exhausted or visit returns false. It
// follows Horizon's paging, so a long history spans several requests.
//
// By default it walks the payments endpoint — the operations that move funds.
// Note that endpoint's limits: claimable-balance operations and Soroban
// (invoke_host_function) transfers do not appear in it. opts.AllOps walks the
// full operations endpoint instead.
//
// Each operation carries its parent transaction (join=transactions), so
// callers can show the memo — the part of a payment that identifies an
// exchange deposit.
func (c *Client) EachOperation(accountID string, opts HistoryOpts, visit func(operations.Operation) bool) error {
	if err := wallet.ValidateAddress(accountID); err != nil {
		return err
	}
	req := horizonclient.OperationRequest{
		ForAccount:    accountID,
		Order:         horizonclient.OrderDesc,
		Limit:         historyPageLimit,
		IncludeFailed: opts.IncludeFailed,
		Join:          "transactions",
	}
	var page operations.OperationsPage
	var err error
	if opts.AllOps {
		page, err = c.horizon.Operations(req)
	} else {
		page, err = c.horizon.Payments(req)
	}
	for {
		if err != nil {
			if horizonclient.IsNotFoundError(err) {
				return c.accountNotFound(accountID)
			}
			return wrapHorizonError("fetch history", err)
		}
		for _, op := range page.Embedded.Records {
			if !visit(op) {
				return nil
			}
		}
		// A short (or empty) page is the end of the history; only a full one
		// can have more records behind it.
		if len(page.Embedded.Records) < historyPageLimit {
			return nil
		}
		page, err = c.horizon.NextOperationsPage(page)
	}
}
