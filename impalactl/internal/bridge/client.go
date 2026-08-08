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
func New(endpoint string, timeout time.Duration) (*Client, error) {
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
	return &Client{
		endpoint: u.String(),
		http:     &http.Client{Timeout: timeout},
		agent:    "impalactl",
	}, nil
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
func (c *Client) call(ctx context.Context, method, path string, query url.Values, in, out any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	target := c.endpoint + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
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
		return nil, fmt.Errorf("%s %s: %w", method, target, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return raw, newAPIError(resp, raw)
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("decode response from %s %s: %w", method, path, err)
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
