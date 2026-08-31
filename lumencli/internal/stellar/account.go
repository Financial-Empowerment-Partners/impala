package stellar

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"

	"lumencli/internal/wallet"
)

// AccountInfo fetches full account details, including balances, for accountID.
func (c *Client) AccountInfo(accountID string) (hProtocol.Account, error) {
	if err := wallet.ValidateAddress(accountID); err != nil {
		return hProtocol.Account{}, err
	}
	acct, err := c.horizon.AccountDetail(horizonclient.AccountRequest{AccountID: accountID})
	if err != nil {
		if horizonclient.IsNotFoundError(err) {
			return hProtocol.Account{}, c.accountNotFound(accountID)
		}
		return hProtocol.Account{}, wrapHorizonError("fetch account", err)
	}
	return acct, nil
}

// accountNotFound is the message for a Horizon 404 on an account: on Stellar
// an address whose account was never created/funded simply does not exist yet.
func (c *Client) accountNotFound(accountID string) error {
	return fmt.Errorf(
		"account %s does not exist on %s (it has not been created/funded yet)", accountID, c.net.Name)
}

// NativeBalance returns the account's XLM (native) balance.
func (c *Client) NativeBalance(accountID string) (string, error) {
	acct, err := c.AccountInfo(accountID)
	if err != nil {
		return "", err
	}
	bal, err := acct.GetNativeBalance()
	if err != nil {
		return "", fmt.Errorf("read native balance: %w", err)
	}
	return bal, nil
}

// Fund requests Friendbot funding for accountID.
//
// Friendbot exists only on testnet; on any other network this returns an error
// rather than silently doing nothing.
func (c *Client) Fund(accountID string) error {
	if err := wallet.ValidateAddress(accountID); err != nil {
		return err
	}
	if !c.net.IsTestnet {
		return fmt.Errorf("friendbot funding is only available on testnet (current network: %s)", c.net.Name)
	}
	if _, err := c.horizon.Fund(accountID); err != nil {
		return wrapHorizonError("fund via friendbot", err)
	}
	return nil
}
