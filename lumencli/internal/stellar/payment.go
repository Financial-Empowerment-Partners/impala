package stellar

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"lumencli/internal/wallet"
)

// txTimeoutSeconds bounds how long a built transaction stays valid for
// submission. Transactions require a time bound; without one Horizon may hold a
// pending transaction indefinitely if it can't be applied promptly.
const txTimeoutSeconds = 300

// SendPayment sends a native XLM payment from source to destination and returns
// the resulting transaction hash. memoText is optional (max 28 bytes).
func (c *Client) SendPayment(source *keypair.Full, destination, amount, memoText string) (string, error) {
	if err := wallet.ValidateAddress(destination); err != nil {
		return "", err
	}
	if len(memoText) > txnbuild.MemoTextMaxLength {
		return "", fmt.Errorf("memo too long: %d bytes (max %d)", len(memoText), txnbuild.MemoTextMaxLength)
	}
	op := &txnbuild.Payment{
		Destination: destination,
		Amount:      amount,
		Asset:       txnbuild.NativeAsset{},
	}
	return c.buildSignSubmit(source, op, memoText)
}

// CreateAccount creates and funds a brand-new account on-ledger, paid for by
// source, seeding it with startingBalance XLM. Returns the transaction hash.
func (c *Client) CreateAccount(source *keypair.Full, destination, startingBalance string) (string, error) {
	if err := wallet.ValidateAddress(destination); err != nil {
		return "", err
	}
	op := &txnbuild.CreateAccount{
		Destination: destination,
		Amount:      startingBalance,
	}
	return c.buildSignSubmit(source, op, "")
}

// buildSignSubmit loads the source account (for its sequence number), builds a
// single-operation transaction, signs it with the source key for this network's
// passphrase, and submits it to Horizon.
func (c *Client) buildSignSubmit(source *keypair.Full, op txnbuild.Operation, memoText string) (string, error) {
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
	}
	if memoText != "" {
		params.Memo = txnbuild.MemoText(memoText)
	}

	tx, err := txnbuild.NewTransaction(params)
	if err != nil {
		return "", fmt.Errorf("build transaction: %w", err)
	}
	tx, err = tx.Sign(c.net.Passphrase, source)
	if err != nil {
		return "", fmt.Errorf("sign transaction: %w", err)
	}
	resp, err := c.horizon.SubmitTransaction(tx)
	if err != nil {
		return "", wrapHorizonError("submit transaction", err)
	}
	return resp.Hash, nil
}
