// Package bridge is a typed client for the impala-bridge REST API.
//
// It speaks the contract in impala-bridge/openapi.yaml: JSON request and
// response bodies, a bearer *temporal* JWT in the Authorization header, and an
// {"error": {"code", "message"}} envelope on 4xx/5xx.
//
// Every call returns the decoded value *and* the raw response body, so the CLI
// can print the server's JSON verbatim under --json without re-serializing
// (and therefore without silently dropping fields this client doesn't model).
package bridge

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
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is where a locally-run bridge listens (SERVICE_ADDRESS).
const DefaultEndpoint = "http://localhost:8080"

// maxResponseBytes caps what we buffer from a response. The bridge's own
// request-body limit is 1 MB and its largest reply (a 100-row page) is far
// below this; the cap only exists so a misdirected endpoint cannot stream
// unbounded data into memory.
const maxResponseBytes = 8 << 20

// Client is a bridge API client. Use New to construct one.
type Client struct {
	endpoint string
	http     *http.Client
	token    string
	agent    string
}

// New returns a client for the bridge at endpoint. The endpoint must be an
// absolute http(s) URL; any trailing slash is trimmed so paths concatenate
// cleanly.
//
// Plain http:// is refused for non-loopback hosts unless allowInsecure is set.
// Everything this client sends is a bearer credential — the login password, a
// single-use refresh token on every rotation, the temporal JWT on every call,
// and (on import) a Stellar secret seed — so an unnoticed http:// endpoint
// hands all of it to anyone on the network path. The loopback carve-out keeps
// the http://localhost:8080 development default working.
func New(endpoint string, timeout time.Duration, allowInsecure bool) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if trimmed == "" {
		return nil, errors.New("endpoint must not be empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid endpoint %q: must be an http:// or https:// URL", endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q: missing host", endpoint)
	}
	if u.Scheme == "http" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf(
			"refusing to send credentials to %s over plain HTTP: use https://, "+
				"or pass --insecure-http (or set %s=1) if this endpoint is genuinely trusted",
			u.Host, EnvAllowHTTP)
	}
	return &Client{
		endpoint: u.String(),
		http:     &http.Client{Timeout: timeout},
		agent:    "impalactl",
	}, nil
}

// EnvAllowHTTP opts in to plain-HTTP endpoints on non-loopback hosts.
const EnvAllowHTTP = "IMPALA_ALLOW_HTTP"

// isLoopbackHost reports whether host is a literal loopback address or the
// name "localhost".
//
// Deliberately literal: resolving the name would add a DNS lookup to client
// construction and could be pointed at a non-loopback address, which is the
// gap this check exists to close.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Endpoint returns the normalized base URL this client talks to.
func (c *Client) Endpoint() string { return c.endpoint }

// SetToken sets the bearer temporal JWT sent with each request. An empty token
// means the request is sent unauthenticated (valid for /health, /version,
// /network and /token).
func (c *Client) SetToken(token string) { c.token = strings.TrimSpace(token) }

// SetUserAgent overrides the User-Agent header (used by tests).
func (c *Client) SetUserAgent(agent string) { c.agent = agent }

// APIError is a non-2xx response from the bridge.
type APIError struct {
	Status int
	// Code is the bridge's stable error code (unauthorized, forbidden,
	// not_found, bad_request, conflict, rate_limited, internal_error).
	Code    string
	Message string
	// RetryAfter is the Retry-After header in seconds, set on 429.
	RetryAfter int
	// Body is the raw payload, kept for responses that don't use the error
	// envelope (a proxy's HTML 502, say).
	Body string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = strings.TrimSpace(e.Body)
	}
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	code := e.Code
	if code == "" {
		code = "http_error"
	}
	if e.Status == http.StatusTooManyRequests && e.RetryAfter > 0 {
		return fmt.Sprintf("[%d %s] %s (retry after %ds)", e.Status, code, msg, e.RetryAfter)
	}
	return fmt.Sprintf("[%d %s] %s", e.Status, code, msg)
}

// StatusCode reports the HTTP status of err, or 0 if err is not an APIError.
func StatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsUnauthorized reports whether err is a 401 — the signal that a token was
// rejected (expired, revoked, or from a token family the bridge killed).
func IsUnauthorized(err error) bool { return StatusCode(err) == http.StatusUnauthorized }

// RequestPhase is how far a request got before it failed. It is what decides
// whether the bridge may have acted on the request: nothing sent means
// nothing happened; anything after that is open.
type RequestPhase int

const (
	// PhaseBuild — the request was never sent: the body could not be
	// encoded or the request could not be constructed.
	PhaseBuild RequestPhase = iota
	// PhaseSend — the round trip failed: a dial failure, a TLS failure, a
	// timeout waiting for the response, or a connection dropped mid-flight.
	PhaseSend
	// PhaseRead — the status line and headers arrived but the body could
	// not be read in full.
	PhaseRead
	// PhaseDecode — a 2xx body that is not the JSON this client expected.
	// The bridge answered success; we simply could not read what it said.
	PhaseDecode
)

// RequestError is a failure that is not a bridge verdict: the request could
// not be built or delivered, or its response could not be read or decoded.
// A bridge verdict (any status the bridge chose to send) is an APIError.
type RequestError struct {
	Method string
	URL    string
	Phase  RequestPhase
	Err    error
}

func (e *RequestError) Error() string {
	switch e.Phase {
	case PhaseSend:
		return fmt.Sprintf("%s %s: %v", e.Method, e.URL, e.Err)
	case PhaseRead:
		return fmt.Sprintf("read response: %v", e.Err)
	case PhaseDecode:
		return fmt.Sprintf("decode response from %s %s: %v", e.Method, e.URL, e.Err)
	default:
		return e.Err.Error()
	}
}

// Unwrap exposes the cause so errors.Is/As keep working through the wrapper.
func (e *RequestError) Unwrap() error { return e.Err }

// IsAmbiguousOutcome reports whether err leaves open the possibility that
// the bridge acted on the request before the failure. It exists for the
// money-moving calls: a caller that reads an ambiguous failure as "nothing
// happened" and retries makes a second payment.
//
// Ambiguous:
//
//   - 408: the bridge's own request deadline fired while the handler was
//     still running — for a payment, possibly inside the Horizon submit,
//     which then completes on its own. The bridge sends this with an empty
//     body, so it arrives without the error envelope.
//   - 500 internal_error: the bridge maps every ambiguous Horizon submission
//     (its 504 timeout, any other 5xx, an undecodable 2xx) to this.
//   - 502, 504 and any other 5xx: something in front of the bridge gave up
//     on a request it had already forwarded.
//   - a send that failed after the connection was established: a timeout
//     waiting for the response, a reset, an EOF.
//   - a response whose body could not be read, or a 2xx whose body could
//     not be decoded — a success we cannot see.
//
// Not ambiguous:
//
//   - 503 service_unavailable: the bridge's Retryable, reserved for failures
//     that provably happened before anything was signed or submitted. A
//     proxy's 503 likewise means the request was never forwarded.
//   - every other 4xx: validation, authentication, authorization, rate
//     limiting, not found — the bridge refused before doing anything.
//   - a request that could not be built, or whose connection was never
//     established (refused, no such host, unreachable, dial timeout): not
//     one byte of it left this machine.
func IsAmbiguousOutcome(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusRequestTimeout:
			return true
		case http.StatusServiceUnavailable:
			return false
		}
		return apiErr.Status >= 500
	}
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		switch reqErr.Phase {
		case PhaseBuild:
			return false
		case PhaseSend:
			return !neverConnected(reqErr.Err)
		default:
			return true
		}
	}
	return false
}

// neverConnected reports whether a send failed before a connection existed:
// a dial error (connection refused, no such host, network unreachable, dial
// timeout). Anything later may have happened with the request delivered.
func neverConnected(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// Result is the {success, message} envelope shared by the bridge's mutating
// endpoints. Several of them report a *failed* operation as HTTP 200 with
// success=false (duplicate account, no fields to update, bad credentials), so
// callers must check Err rather than trusting the status code alone.
type Result struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Err converts a success=false envelope into an error.
func (r Result) Err() error {
	if r.Success {
		return nil
	}
	if r.Message == "" {
		return errors.New("request failed")
	}
	return errors.New(r.Message)
}

// get issues a GET and decodes the response into out.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) ([]byte, error) {
	return c.call(ctx, http.MethodGet, path, query, nil, out)
}

// post issues a POST with a JSON body and decodes the response into out.
func (c *Client) post(ctx context.Context, path string, in, out any) ([]byte, error) {
	return c.call(ctx, http.MethodPost, path, nil, in, out)
}

// put issues a PUT with a JSON body and decodes the response into out.
func (c *Client) put(ctx context.Context, path string, in, out any) ([]byte, error) {
	return c.call(ctx, http.MethodPut, path, nil, in, out)
}

// call performs one request/response round trip. It returns the raw response
// body; when out is non-nil the body is also JSON-decoded into it.
//
// A non-2xx status is an *APIError; every other failure is a *RequestError
// whose Phase says how far the exchange got, so a money-moving caller can
// tell "never sent" from "sent, answer lost" (see IsAmbiguousOutcome).
func (c *Client) call(ctx context.Context, method, path string, query url.Values, in, out any) ([]byte, error) {
	target := c.endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	fail := func(phase RequestPhase, err error) *RequestError {
		return &RequestError{Method: method, URL: target, Phase: phase, Err: err}
	}

	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return nil, fail(PhaseBuild, fmt.Errorf("encode request: %w", err))
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fail(PhaseBuild, fmt.Errorf("build request: %w", err))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail(PhaseSend, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fail(PhaseRead, err)
	}

	if resp.StatusCode >= 300 {
		return raw, newAPIError(resp, raw)
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fail(PhaseDecode, err)
		}
	}
	return raw, nil
}

// newAPIError builds an APIError from a non-2xx response, preferring the
// bridge's error envelope and falling back to the raw body.
func newAPIError(resp *http.Response, raw []byte) *APIError {
	apiErr := &APIError{Status: resp.StatusCode, Body: string(raw)}

	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil {
		apiErr.Code = envelope.Error.Code
		apiErr.Message = envelope.Error.Message
	}

	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			apiErr.RetryAfter = secs
		}
	}
	return apiErr
}
