// Package stellar performs network operations against a Horizon server:
// reading account state and building, signing, and submitting transactions.
//
// There is no local Stellar node; all reads and submissions go through Horizon,
// the REST API for the network selected via netcfg.
package stellar

import (
	"net/http"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/horizonclient"

	"lumencli/internal/netcfg"
)

// httpTimeout bounds every Horizon request so the CLI cannot hang indefinitely.
const httpTimeout = 30 * time.Second

// appVersion is reported to Horizon via the client headers (X-App-Version),
// by both the paging and the streaming client. A var so release builds stamp
// it alongside the CLI's own version:
//
//	go build -ldflags "-X lumencli/internal/stellar.appVersion=..."
var appVersion = "0.2.0"

// Client is a Horizon-backed client bound to a single network.
type Client struct {
	horizon *horizonclient.Client
	net     netcfg.Network
}

// New builds a Client for the given network.
func New(net netcfg.Network) *Client {
	return &Client{
		horizon: &horizonclient.Client{
			HorizonURL: net.HorizonURL,
			HTTP:       &http.Client{Timeout: httpTimeout},
			AppName:    "lumencli",
			AppVersion: appVersion,
		},
		net: net,
	}
}

// Network returns the network this client is bound to.
func (c *Client) Network() netcfg.Network { return c.net }
