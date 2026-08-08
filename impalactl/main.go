// Command impalactl is a command-line client for the Impala bridge REST API.
//
// It force-syncs accounts, creates accounts (including custodial ones), makes
// transfers, and shows account status and activity. See the CLI help
// (`impalactl help`) for the list of commands.
package main

import (
	"os"

	"impalactl/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
