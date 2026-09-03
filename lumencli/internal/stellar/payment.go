package stellar

import (
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"lumencli/internal/wallet"
)

// txTimeoutSeconds bounds how long a built transaction stays valid for
// submission. Transactions require a time bound; without one Horizon may hold a
// pending transaction indefinitely if it can't be applied promptly.
//
// It is also the window of doubt after an ambiguous submission: a transaction
// that Horizon did not confirm or reject can still land any time before this
// bound passes (see AmbiguousSubmitError), which is why it is much longer
// than the HTTP timeout and why the two must never be confused.
const txTimeoutSeconds = 300

// SendPayment sends a native XLM payment from source to destination and returns
// the resulting transaction hash. memo is optional — a nil memo attaches none;
// build one with ParseMemo.
func (c *Client) SendPayment(source *keypair.Full, destination, amount string, memo Memo) (string, error) {
	if err := wallet.ValidateAddress(destination); err != nil {
		return "", err
	}
	op := &txnbuild.Payment{
		Destination: destination,
		Amount:      amount,
		Asset:       txnbuild.NativeAsset{},
	}
	return c.buildSignSubmit(source, op, memo)
}

// CreateAccount creates and funds a brand-new account on-ledger, paid for by
// source, seeding it with startingBalance XLM. memo is optional, as for
// SendPayment. Returns the transaction hash.
func (c *Client) CreateAccount(source *keypair.Full, destination, startingBalance string, memo Memo) (string, error) {
	if err := wallet.ValidateAddress(destination); err != nil {
		return "", err
	}
	op := &txnbuild.CreateAccount{
		Destination: destination,
		Amount:      startingBalance,
	}
	return c.buildSignSubmit(source, op, memo)
}

// buildSignSubmit loads the source account (for its sequence number), builds a
// single-operation transaction, signs it with the source key for this network's
// passphrase, and submits it to Horizon.
//
// Failures before the submit (loading the account, building, signing) are
// plain errors: nothing reached the network and a retry is safe. A failure
// OF the submit is classified — a proven rejection is a plain error, anything
// that leaves the outcome open is returned as an *AmbiguousSubmitError
// carrying the hash and time bound, because the transaction may still land.
func (c *Client) buildSignSubmit(source *keypair.Full, op txnbuild.Operation, memo Memo) (string, error) {
	srcAccount, err := c.horizon.AccountDetail(horizonclient.AccountRequest{AccountID: source.Address()})
	if err != nil {
		if horizonclient.IsNotFoundError(err) {
			return "", fmt.Errorf(
				"source account %s does not exist on %s (it has not been created/funded yet)", source.Address(), c.net.Name)
		}
		return "", wrapHorizonError("load source account", err)
	}

	params := txnbuild.TransactionParams{
		SourceAccount:        &srcAccount, // *horizon.Account satisfies txnbuild.Account
		IncrementSequenceNum: true,
		BaseFee:              txnbuild.MinBaseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(txTimeoutSeconds)},
		Operations:           []txnbuild.Operation{op},
		Memo:                 memo,
	}

	tx, err := txnbuild.NewTransaction(params)
	if err != nil {
		return "", fmt.Errorf("build transaction: %w", err)
	}
	tx, err = tx.Sign(c.net.Passphrase, source)
	if err != nil {
		return "", fmt.Errorf("sign transaction: %w", err)
	}

	// The hash is fixed by the signed envelope, so compute it BEFORE asking
	// Horizon: if the answer never comes back it is the one thing the user
	// needs in order to find out what happened.
	hash, err := tx.HashHex(c.net.Passphrase)
	if err != nil {
		return "", fmt.Errorf("hash transaction: %w", err)
	}
	maxTime := time.Unix(tx.Timebounds().MaxTime, 0).UTC()

	// SkipMemoRequiredCheck: left on, the SDK would GET the destination's
	// SEP-0029 data entry between signing and posting. lumencli has already
	// run that check itself, before the secret was even read (see
	// cli.confirmMissingMemo), with the prompt and the --no-memo override the
	// SDK's copy lacks. Keeping the SDK's copy would (a) re-refuse a transfer
	// the user explicitly overrode and (b) let a failed GET surface as a
	// failed — and, worse, as an ambiguous — submission that never happened.
	resp, err := c.horizon.SubmitTransactionWithOptions(tx, horizonclient.SubmitTxOpts{SkipMemoRequiredCheck: true})
	if err != nil {
		wrapped := wrapHorizonError("submit transaction", err)
		if submitOutcomeUnknown(err) {
			return "", &AmbiguousSubmitError{Hash: hash, MaxTime: maxTime, Cause: wrapped}
		}
		return "", wrapped
	}
	if resp.Hash != hash {
		// Horizon acknowledged something other than what was sent (a proxy
		// replaying a cached answer, say). That is not a confirmation of this
		// transaction, and it is not a rejection either: refuse to guess.
		return "", &AmbiguousSubmitError{
			Hash:    hash,
			MaxTime: maxTime,
			Cause: fmt.Errorf("submit transaction: horizon acknowledged transaction %q, not the submitted %s",
				resp.Hash, hash),
		}
	}
	return hash, nil
}
