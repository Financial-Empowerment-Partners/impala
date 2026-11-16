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
)

// HTTPError is a non-2xx answer (redirects included: they are never
// followed). Excerpt is at most 200 printable characters of the body.
type HTTPError struct {
	Status  int
	Method  string
	URL     string
	Excerpt string
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.URL, e.Status)
	if e.Excerpt != "" {
		msg += ": " + e.Excerpt
	}
	return msg
}

// ClientErrorKind separates "no SEP-10 here" from a broken or hostile server.
type ClientErrorKind string

const (
	// NotOffered: stellar.toml has no WEB_AUTH_ENDPOINT or no SIGNING_KEY.
	NotOffered ClientErrorKind = "NOT_OFFERED"
	// TomlInvalid: stellar.toml is malformed or its SIGNING_KEY is not an
	// account id.
	TomlInvalid ClientErrorKind = "TOML_INVALID"
	// InsecureEndpoint: WEB_AUTH_ENDPOINT is not a plain http(s) URL, or uses
	// another scheme than the bridge endpoint.
	InsecureEndpoint ClientErrorKind = "INSECURE_ENDPOINT"
	// HostMismatch: WEB_AUTH_ENDPOINT is not on the home domain. A signed
	// challenge is only ever sent to the home domain.
	HostMismatch ClientErrorKind = "HOST_MISMATCH"
	// ResponseInvalid: the challenge or token response is not the JSON
	// object it must be.
	ResponseInvalid ClientErrorKind = "RESPONSE_INVALID"
)

// ClientError is a SEP-10 client failure that is not a challenge rule.
type ClientError struct {
	Kind    ClientErrorKind
	Message string
}

func (e *ClientError) Error() string { return fmt.Sprintf("SEP-10 (%s): %s", e.Kind, e.Message) }

func clientErr(kind ClientErrorKind, format string, args ...any) error {
	return &ClientError{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

const (
	maxJSONLength = 16 * 1024
	excerptLength = 200
)

// Client runs the network half of a SEP-10 sign-in for one home domain.
//
// The home domain is a NAME: the host[:port] the challenge must be for and
// every URL is built on. Every connection goes to the bridge endpoint's own
// address, whatever the name resolves to (the way a hosts-file entry or
// `curl --connect-to` would): the dialer refuses any other address, so a
// stellar.toml cannot send a signed challenge anywhere else.
type Client struct {
	homeDomain string
	scheme     string
	passphrase string
	http       *http.Client
	now        func() int64
	toml       *Toml
}

// NewClient builds a client. endpoint is the bridge's base URL (already
// vetted by the bridge client's plain-HTTP rule); homeDomain the name;
// passphrase the network the bridge reports.
func NewClient(endpoint, homeDomain, passphrase string, timeout time.Duration, now func() int64) (*Client, error) {
	if !IsValidHomeDomain(homeDomain) {
		return nil, fmt.Errorf("invalid SEP-10 home domain %q (a lowercase host[:port])", homeDomain)
	}
	if passphrase == "" {
		return nil, errors.New("the network passphrase is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q", endpoint)
	}
	scheme := strings.ToLower(u.Scheme)
	dialAddr := withDefaultPort(u.Host, scheme)
	nameAddr := withDefaultPort(homeDomain, scheme)
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil, // a proxy would connect to the name, not to the bridge
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != nameAddr {
				return nil, fmt.Errorf("refusing to connect to %s: SEP-10 requests go only to the bridge at %s", addr, endpoint)
			}
			return dialer.DialContext(ctx, network, dialAddr)
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &Client{
		homeDomain: homeDomain,
		scheme:     scheme,
		passphrase: passphrase,
		http: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: now,
	}, nil
}

func withDefaultPort(hostport, scheme string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(hostport)
	}
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(strings.ToLower(hostport), port)
}

// Prepared is a verified challenge and where the signed envelope goes.
type Prepared struct {
	Challenge       *Challenge
	WebAuthEndpoint string
}

// Prepare fetches stellar.toml, a challenge for the 32-byte clientKey, and
// verifies it. When the challenge fails a server-identity rule (its source
// is not SIGNING_KEY, or the server signature does not verify) stellar.toml
// is refetched once and a fresh challenge tried, which follows a signing-key
// rotation (impala-lib Sep10Client.prepare).
func (c *Client) Prepare(ctx context.Context, clientKey []byte) (*Prepared, error) {
	if len(clientKey) != 32 {
		return nil, errors.New("client key must be 32 bytes")
	}
	t, err := c.loadToml(ctx, false)
	if err != nil {
		return nil, err
	}
	p, err := c.attempt(ctx, t, clientKey)
	var ce *ChallengeError
	if err == nil || !errors.As(err, &ce) || (ce.Reason != ReasonServerKey && ce.Reason != ReasonServerSignature) {
		return p, err
	}
	if t, err = c.loadToml(ctx, true); err != nil {
		return nil, err
	}
	return c.attempt(ctx, t, clientKey)
}

func (c *Client) loadToml(ctx context.Context, bypassCache bool) (*Toml, error) {
	if c.toml != nil && !bypassCache {
		return c.toml, nil
	}
	body, err := c.exchange(ctx, http.MethodGet, c.scheme+"://"+c.homeDomain+"/.well-known/stellar.toml", nil, MaxTomlLength)
	if err != nil {
		return nil, err
	}
	t, err := ParseToml(string(body))
	if err != nil {
		return nil, clientErr(TomlInvalid, "%v", err)
	}
	if t.WebAuthEndpoint == "" || t.SigningKey == "" {
		return nil, clientErr(NotOffered, "stellar.toml offers no SEP-10 (WEB_AUTH_ENDPOINT or SIGNING_KEY missing)")
	}
	if !IsValidAccountID(t.SigningKey) {
		return nil, clientErr(TomlInvalid, "stellar.toml SIGNING_KEY is not a valid account id")
	}
	c.toml = t
	return t, nil
}

// checkEndpoint applies the rules a WEB_AUTH_ENDPOINT must pass before any
// request is sent to it, and returns its web_auth_domain.
func (c *Client) checkEndpoint(endpoint string) (string, error) {
	u, domain, err := CheckWebAuthEndpoint(endpoint)
	if err != nil {
		return "", clientErr(InsecureEndpoint, "%v", err)
	}
	if strings.ToLower(u.Scheme) != c.scheme {
		return "", clientErr(InsecureEndpoint, "WEB_AUTH_ENDPOINT uses %s, the bridge endpoint %s", u.Scheme, c.scheme)
	}
	if domain != c.homeDomain {
		return "", clientErr(HostMismatch, "WEB_AUTH_ENDPOINT %s is on %s, not on the home domain %s; a signed "+
			"challenge is only ever sent to the home domain (if %s is this bridge's SEP-10 name, pass "+
			"--sep10-home-domain %s)", endpoint, domain, c.homeDomain, domain, domain)
	}
	return domain, nil
}

func (c *Client) attempt(ctx context.Context, t *Toml, clientKey []byte) (*Prepared, error) {
	serverKey, err := DecodeAccountID(t.SigningKey)
	if err != nil {
		return nil, clientErr(TomlInvalid, "stellar.toml SIGNING_KEY: %v", err)
	}
	if t.NetworkPassphrase != c.passphrase {
		return nil, reject(ReasonNetwork, "stellar.toml NETWORK_PASSPHRASE is not the bridge's network")
	}
	webAuthDomain, err := c.checkEndpoint(t.WebAuthEndpoint)
	if err != nil {
		return nil, err
	}
	account, _ := EncodeAccountID(clientKey)
	target := t.WebAuthEndpoint + "?account=" + url.QueryEscape(account) + "&home_domain=" + url.QueryEscape(c.homeDomain)
	body, err := c.exchange(ctx, http.MethodGet, target, nil, maxJSONLength)
	if err != nil {
		return nil, err
	}
	fields, err := stringFields(body, "challenge response")
	if err != nil {
		return nil, err
	}
	tx, ok := fields["transaction"]
	if !ok {
		return nil, clientErr(ResponseInvalid, "challenge response has no transaction")
	}
	if fields["network_passphrase"] != c.passphrase {
		return nil, reject(ReasonNetwork, "challenge network_passphrase is absent or not the bridge's network")
	}
	if bytes.Equal(serverKey, clientKey) {
		return nil, reject(ReasonServerKey, "the client key is the server signing key")
	}
	ch, err := Verify(tx, Expectation{
		ServerKey:         serverKey,
		NetworkPassphrase: c.passphrase,
		HomeDomain:        c.homeDomain,
		WebAuthDomain:     webAuthDomain,
		ClientKey:         clientKey,
	}, c.now())
	if err != nil {
		return nil, err
	}
	return &Prepared{Challenge: ch, WebAuthEndpoint: t.WebAuthEndpoint}, nil
}

// Extras are the optional MFA fields that ride the signed challenge
// (docs/mfa-card-pin-biometrics.md §5.1). All hex; empty means absent.
type Extras struct {
	PinProof        string `json:"pin_proof,omitempty"`
	DeviceKeyID     string `json:"device_key_id,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
}

// TokenResponse is the POST /auth/sep10 answer: the bridge's token pair plus
// the SEP-10 `token` (byte-identical to temporal_token).
type TokenResponse struct {
	Token         string `json:"token"`
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	RefreshToken  string `json:"refresh_token"`
	TemporalToken string `json:"temporal_token"`
}

// Submit posts the signed envelope to the web-auth endpoint and returns the
// raw body and its token fields, after checking it is a JSON object with a
// non-empty string token.
func (c *Client) Submit(ctx context.Context, webAuthEndpoint, envelope string, extras Extras) ([]byte, *TokenResponse, error) {
	if _, err := c.checkEndpoint(webAuthEndpoint); err != nil {
		return nil, nil, err
	}
	payload := struct {
		Transaction string `json:"transaction"`
		Extras
	}{envelope, extras}
	in, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	body, err := c.exchange(ctx, http.MethodPost, webAuthEndpoint, in, maxJSONLength)
	if err != nil {
		return nil, nil, err
	}
	fields, err := stringFields(body, "token response")
	if err != nil {
		return nil, nil, err
	}
	if fields["token"] == "" {
		return nil, nil, clientErr(ResponseInvalid, "token response has no token")
	}
	var out TokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, nil, clientErr(ResponseInvalid, "token response: %v", err)
	}
	return body, &out, nil
}

// stringFields decodes a JSON object and returns its string-valued members.
func stringFields(body []byte, what string) (map[string]string, error) {
	if len(body) > maxJSONLength {
		return nil, clientErr(ResponseInvalid, "%s too large", what)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return nil, clientErr(ResponseInvalid, "%s is not a JSON object", what)
	}
	out := map[string]string{}
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			out[k] = s
		}
	}
	return out, nil
}

func (c *Client) exchange(ctx context.Context, method, target string, body []byte, limit int64) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "impalactl")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, &HTTPError{Status: resp.StatusCode, Method: method, URL: redactQuery(target), Excerpt: excerpt(b)}
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%s %s: response of %d bytes exceeds the %d-byte cap", method, redactQuery(target), resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s %s: response exceeds the %d-byte cap", method, redactQuery(target), limit)
	}
	return b, nil
}

func excerpt(b []byte) string {
	r := []rune(string(b))
	if len(r) > excerptLength {
		r = r[:excerptLength]
	}
	for i, c := range r {
		if c < ' ' || c == 0x7f {
			r[i] = ' '
		}
	}
	return strings.TrimSpace(string(r))
}

// redactQuery drops the query (the account address) from a URL shown in an
// error; the address is public, but the error needs only the route.
func redactQuery(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i]
	}
	return target
}
