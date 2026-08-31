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

// EachPayment walks accountID's payment history newest-first, calling visit
// for every fund-moving operation — payments, path payments, account
// creations, and merges — until the history is exhausted or visit returns
// false. It follows Horizon's paging, so a long history spans several
// requests.
//
// Each operation carries its parent transaction (join=transactions), so
// callers can show the memo — the part of a payment that identifies an
// exchange deposit. includeFailed additionally reports operations from failed
// transactions, which moved no funds; Horizon omits them by default.
func (c *Client) EachPayment(accountID string, includeFailed bool, visit func(operations.Operation) bool) error {
	if err := wallet.ValidateAddress(accountID); err != nil {
		return err
	}
	page, err := c.horizon.Payments(horizonclient.OperationRequest{
		ForAccount:    accountID,
		Order:         horizonclient.OrderDesc,
		Limit:         historyPageLimit,
		IncludeFailed: includeFailed,
		Join:          "transactions",
	})
	for {
		if err != nil {
			if horizonclient.IsNotFoundError(err) {
				return c.accountNotFound(accountID)
			}
			return wrapHorizonError("fetch payment history", err)
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
		page, err = c.horizon.NextPaymentsPage(page)
	}
}
