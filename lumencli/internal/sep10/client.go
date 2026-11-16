// Package sep10 is the client side of SEP-10, Stellar Web Authentication
// (https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md):
// discovering a server through its stellar.toml, fetching a challenge
// transaction, checking it, signing it with the wallet's key, and exchanging
// the signed challenge for the server's token.
//
// A SEP-10 challenge is a real Stellar transaction signed by the wallet's
// key; it is built so that it can never be applied to the ledger (sequence
// number 0 on the server's account), and the client checks exist so that the
// wallet never signs something else. Every check here fails closed: a
// challenge that fails any one of them is refused and nothing is signed.
//
// This package talks to the SEP-10 server only. It never contacts Horizon
// and never sends the secret seed anywhere; the only thing that leaves the
// process is the signed challenge, POSTed to the server that issued it.
package sep10

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/stellar/go-stellar-sdk/strkey"
)

// Response size bounds. SEP-1 caps a stellar.toml at 100 KB; the JSON
// documents of the auth endpoint are a few hundred bytes in practice.
const (
	maxTOMLBytes = 100 * 1024
	maxJSONBytes = 64 * 1024
	maxRedirects = 3
)

// DefaultTimeout bounds every request to a SEP-10 server.
const DefaultTimeout = 30 * time.Second

// Client talks to SEP-10 servers.
type Client struct {
	// HTTP is the underlying client; nil selects one with DefaultTimeout.
	// Whatever is supplied, its redirect policy is replaced by the scheme
	// policy below so that no redirect can downgrade a request to plain HTTP.
	HTTP *http.Client
	// UserAgent is sent with every request.
	UserAgent string
}

func (c *Client) httpClient() *http.Client {
	base := c.HTTP
	if base == nil {
		base = &http.Client{Timeout: DefaultTimeout}
	}
	hc := *base
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if err := checkTransport(req.URL); err != nil {
			return fmt.Errorf("refusing redirect to %s: %v", req.URL.Redacted(), err)
		}
		return nil
	}
	return &hc
}

// ValidateHomeDomain checks that d is a bare host or host:port — what SEP-10
// calls a home domain, the value the challenge's first operation is named
// after — and short enough for that name ("<home domain> auth") to fit the
// 64-byte manage-data key.
func ValidateHomeDomain(d string) error {
	if d == "" {
		return fmt.Errorf("home domain is empty")
	}
	if strings.Contains(d, "://") {
		return fmt.Errorf("invalid home domain %q: give the bare domain (e.g. testanchor.stellar.org), not a URL", d)
	}
	if len(d)+len(" auth") > 64 {
		return fmt.Errorf("invalid home domain %q: longer than 59 bytes, so no SEP-10 challenge can name it", d)
	}
	u, err := url.Parse("https://" + d)
	if err != nil || u.Host != d || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid home domain %q: want a host name, optionally with :port", d)
	}
	for _, r := range d {
		if r <= ' ' || r > '~' {
			return fmt.Errorf("invalid home domain %q: only printable ASCII is allowed", d)
		}
	}
	return nil
}

// IsLoopbackHost reports whether host (no port) names the local machine.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TOMLURL is where the stellar.toml of homeDomain lives. It is https, except
// for a loopback home domain (a local development server), which is fetched
// over plain http — the same exception checkTransport makes for the
// endpoints it names.
func TOMLURL(homeDomain string) string {
	scheme := "https"
	if u, err := url.Parse("https://" + homeDomain); err == nil && IsLoopbackHost(u.Hostname()) {
		scheme = "http"
	}
	return scheme + "://" + homeDomain + "/.well-known/stellar.toml"
}

// checkTransport is the scheme policy for every URL this package requests:
// https, or plain http to a loopback host only. A SEP-10 exchange carries a
// bearer token back over the wire and is only as trustworthy as the
// stellar.toml that names the server's key, so neither may cross a network
// in the clear.
func checkTransport(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("plain http is accepted only for a loopback host (localhost, 127.0.0.0/8, ::1); use https")
	default:
		return fmt.Errorf("unsupported scheme %q (want https)", u.Scheme)
	}
}

// Server is a SEP-10 server as its stellar.toml describes it, validated.
type Server struct {
	HomeDomain string
	TOMLURL    string
	TOML       TOML
	// Endpoint is WEB_AUTH_ENDPOINT, parsed and policy-checked.
	Endpoint *url.URL
	// WebAuthDomain is the host (with any non-default port) of Endpoint: the
	// value a challenge's web_auth_domain operation must carry.
	WebAuthDomain string
}

// Discover fetches and validates homeDomain's stellar.toml: WEB_AUTH_ENDPOINT
// and SIGNING_KEY must be present, the key a valid G... account id, and the
// endpoint an https URL (plain http only on loopback). It does not compare
// NETWORK_PASSPHRASE with the selected network; CheckNetwork does.
func (c *Client) Discover(ctx context.Context, homeDomain string) (*Server, error) {
	if err := ValidateHomeDomain(homeDomain); err != nil {
		return nil, err
	}
	tomlURL := TOMLURL(homeDomain)
	body, err := c.get(ctx, tomlURL, maxTOMLBytes, "text/plain, application/toml, */*")
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", tomlURL, err)
	}
	doc, err := ParseTOML(body)
	if err != nil {
		return nil, err
	}
	if doc.WebAuthEndpoint == "" {
		return nil, fmt.Errorf("%s declares no WEB_AUTH_ENDPOINT: %s does not offer SEP-10 web authentication", tomlURL, homeDomain)
	}
	if doc.SigningKey == "" {
		return nil, fmt.Errorf("%s declares no SIGNING_KEY: without it no challenge from %s can be checked", tomlURL, homeDomain)
	}
	if !strkey.IsValidEd25519PublicKey(doc.SigningKey) {
		return nil, fmt.Errorf("%s SIGNING_KEY %q is not a valid G... account id", tomlURL, Printable(doc.SigningKey))
	}
	ep, err := url.Parse(doc.WebAuthEndpoint)
	if err != nil || ep.Host == "" {
		return nil, fmt.Errorf("%s WEB_AUTH_ENDPOINT %q is not an absolute URL", tomlURL, Printable(doc.WebAuthEndpoint))
	}
	if ep.User != nil {
		return nil, fmt.Errorf("%s WEB_AUTH_ENDPOINT carries credentials in the URL; refusing it", tomlURL)
	}
	if err := checkTransport(ep); err != nil {
		return nil, fmt.Errorf("%s WEB_AUTH_ENDPOINT %q: %v", tomlURL, Printable(doc.WebAuthEndpoint), err)
	}
	return &Server{
		HomeDomain:    homeDomain,
		TOMLURL:       tomlURL,
		TOML:          doc,
		Endpoint:      ep,
		WebAuthDomain: webAuthDomain(ep),
	}, nil
}

// webAuthDomain is the domain of the endpoint as SEP-10 means it: the host,
// keeping a port only when it is not the scheme's default.
func webAuthDomain(u *url.URL) string {
	host, port := u.Hostname(), u.Port()
	if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return u.Host
}

// CheckNetwork refuses a server whose stellar.toml declares a different
// network than the one the wallet is on: a testnet wallet must never sign a
// pubnet challenge, nor the reverse. An undeclared NETWORK_PASSPHRASE is not
// an error (SEP-1 makes it optional); the challenge's signature, verified
// under the selected passphrase, still binds it to that network.
func (s *Server) CheckNetwork(passphrase string) error {
	if s.TOML.NetworkPassphrase != "" && s.TOML.NetworkPassphrase != passphrase {
		return fmt.Errorf("%s is for the network %q, not the selected one (%q); select the matching --network",
			s.HomeDomain, Printable(s.TOML.NetworkPassphrase), passphrase)
	}
	return nil
}

// ChallengeResponse is the server's answer to the challenge request.
type ChallengeResponse struct {
	Transaction       string `json:"transaction"`
	NetworkPassphrase string `json:"network_passphrase,omitempty"`
}

// Challenge requests a challenge for account from the server.
func (c *Client) Challenge(ctx context.Context, s *Server, account string) (ChallengeResponse, error) {
	u := *s.Endpoint
	q := u.Query()
	q.Set("account", account)
	q.Set("home_domain", s.HomeDomain)
	u.RawQuery = q.Encode()
	body, err := c.get(ctx, u.String(), maxJSONBytes, "application/json")
	if err != nil {
		return ChallengeResponse{}, fmt.Errorf("request a challenge from %s: %w", s.Endpoint.Redacted(), err)
	}
	var resp ChallengeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChallengeResponse{}, fmt.Errorf("challenge response from %s is not the expected JSON: %v", s.Endpoint.Redacted(), err)
	}
	if resp.Transaction == "" {
		return ChallengeResponse{}, fmt.Errorf("challenge response from %s carries no transaction", s.Endpoint.Redacted())
	}
	return resp, nil
}

// Token POSTs the signed challenge and returns the server's token. The token
// is opaque here: it is checked only to be a single printable line, so that
// it can be written to stdout alone, and its signature is not (cannot be)
// verified by a client.
func (c *Client) Token(ctx context.Context, s *Server, signedXDR string) (string, error) {
	payload, err := json.Marshal(map[string]string{"transaction": signedXDR})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	body, err := c.do(req, maxJSONBytes, "application/json")
	if err != nil {
		return "", fmt.Errorf("exchange the signed challenge at %s: %w", s.Endpoint.Redacted(), err)
	}
	var resp struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("token response from %s is not the expected JSON", s.Endpoint.Redacted())
	}
	if resp.Token == nil || *resp.Token == "" {
		return "", fmt.Errorf("%s accepted the request but answered without a token", s.Endpoint.Redacted())
	}
	if err := checkTokenShape(*resp.Token); err != nil {
		return "", fmt.Errorf("token from %s: %v", s.Endpoint.Redacted(), err)
	}
	return *resp.Token, nil
}

// maxTokenBytes bounds the token; SEP-10 JWTs are a few hundred bytes.
const maxTokenBytes = 16 * 1024

// checkTokenShape requires the token to be visible ASCII on one line. The
// message never includes the token itself.
func checkTokenShape(tok string) error {
	if len(tok) > maxTokenBytes {
		return fmt.Errorf("longer than %d bytes; refusing it", maxTokenBytes)
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 0x21 || tok[i] > 0x7e {
			return fmt.Errorf("contains a byte outside visible ASCII at offset %d; refusing it", i)
		}
	}
	return nil
}

func (c *Client) get(ctx context.Context, rawURL string, limit int64, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req, limit, accept)
}

// StatusError is a non-2xx answer from a SEP-10 server.
type StatusError struct {
	Status  int
	Message string // the server's "error" field, sanitized; may be empty
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("HTTP %d %s", e.Status, http.StatusText(e.Status))
}

func (c *Client) do(req *http.Request, limit int64, accept string) ([]byte, error) {
	if err := checkTransport(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return nil, uerr.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes; refusing it", limit)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return nil, &StatusError{Status: resp.StatusCode, Message: Printable(truncate(e.Error, 200))}
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Printable replaces control and other non-printing characters in a string
// that came from a server, so it cannot drive the terminal it is shown on.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}
