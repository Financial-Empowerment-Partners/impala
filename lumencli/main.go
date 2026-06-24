// Command lumencli is a command-line wallet for Stellar Lumens (XLM).
//
// It can generate keypairs, show an account's public address, view balances,
// and send and receive lumens on either mainnet or testnet. See the CLI help
// (`lumencli help`) for the list of commands.
package main

import (
	"os"

	"lumencli/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
