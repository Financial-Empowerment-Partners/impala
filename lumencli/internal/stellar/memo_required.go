package stellar

import (
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"

	"lumencli/internal/wallet"
)

// SEP-0029 lets an account declare that payments to it must carry a memo, by
// writing this account data entry. The value is the single character "1".
const (
	memoRequiredKey   = "config.memo_required"
	memoRequiredValue = "1"
)

// knownMemoRequired maps a destination address to the service that operates it,
// for accounts that credit deposits by memo — exchanges and other pooled
// accounts, where one address serves every customer and the memo is the only
// thing saying which customer a payment belongs to. A memo-less deposit to such
// an account arrives, but is credited to nobody.
//
// This is a hand-curated safety net for accounts that have NOT declared the
// requirement on-ledger. MemoRequiredOnLedger covers the ones that have, and
// needs no maintenance; prefer it. The map is mainnet-only: addresses do not
// carry across networks.
//
// To add an entry:
//
//  1. Take the address from the exchange's own deposit page, while logged in —
//     never from a third-party list, a search result, or this file.
//  2. Sanity-check it on-ledger: `lumencli balance <address>` should show an
//     account whose size and activity match a busy deposit account.
//  3. Add it below, labelled with the service name.
//
// Two warnings, both load-bearing:
//
//   - Entries here are for RECOGNITION ONLY. Never copy an address out of this
//     file to send funds to. A stale entry sends them somewhere unrecoverable.
//   - The list is necessarily incomplete, so the absence of a warning means
//     nothing. It can only ever catch the addresses someone has already put in
//     it; it is not a guarantee that a destination needs no memo.
//
// It ships empty: an unverified address here would be worse than no entry at
// all, since a wrong one either misfires on a legitimate counterparty or lends
// false authority to a wrong address.
var knownMemoRequired = map[string]string{}

// KnownMemoRequired reports whether address is on the curated list of accounts
// that credit deposits by memo, returning the operator's name. It is offline:
// no network call, no dependency on the destination existing yet.
func KnownMemoRequired(address string) (string, bool) {
	label, ok := knownMemoRequired[strings.TrimSpace(address)]
	return label, ok
}

// MemoRequiredOnLedger reports whether the destination account itself declares,
// via its SEP-0029 data entry, that payments to it must carry a memo. This is
// the authoritative answer when it is available: it comes from the account
// holder rather than from a list that can go stale.
//
// A destination that does not exist reports false rather than an error: it
// cannot have declared anything, and a payment to it fails on its own terms.
func (c *Client) MemoRequiredOnLedger(address string) (bool, error) {
	if err := wallet.ValidateAddress(address); err != nil {
		return false, err
	}
	acct, err := c.horizon.AccountDetail(horizonclient.AccountRequest{AccountID: address})
	if err != nil {
		if horizonclient.IsNotFoundError(err) {
			return false, nil
		}
		return false, wrapHorizonError("check whether the destination requires a memo", err)
	}
	value, err := acct.GetData(memoRequiredKey)
	if err != nil {
		return false, fmt.Errorf("read %s on %s: %w", memoRequiredKey, address, err)
	}
	return string(value) == memoRequiredValue, nil
}
