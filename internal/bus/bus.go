// Package bus is nanoauth's client for the platform bus.
//
// The bus owns every collection now — accounts, the audit log, the shared
// configuration, the directory links and the refresh tickets — so this service
// has no database connection at all: it asks. The transport carries the internal
// token, the same one every other component presents.
package bus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrNotFound reports a 404 from the bus, so callers can tell "there is no such
// row" from "the call failed" — the store used to get that from sql.ErrNoRows.
var ErrNotFound = errors.New("not found")

// StatusError is a non-2xx answer that is not a 404. Callers match on the code:
// a 409 from the create endpoint means the address is taken, which the sign-in
// flow recovers from by linking instead of creating.
type StatusError struct {
	// Name is the service that answered (bus or admin).
	Name   string
	Method string
	Path   string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("bus %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsStatus reports whether err is a StatusError with this code.
func IsStatus(err error, code int) bool {
	var statusErr *StatusError
	return errors.As(err, &statusErr) && statusErr.Status == code
}

// Client talks to one of the platform's internal REST surfaces.
//
// It serves the bus (accounts, tokens, tickets) and the admin module
// (configuration) — both answer with the same JSON conventions and the same
// internal token, so one small client covers them; `name` only makes errors say
// which service refused.
type Client struct {
	name string
	base string
	http *http.Client
}

// New builds a client for the bus.
func New(baseURL, token string) *Client { return NewFor("bus", baseURL, token) }

// NewFor builds a client for any internal service. An empty token is allowed (a
// local service without the middleware), but the deployment always sets one.
func NewFor(name, baseURL, token string) *Client {
	return &Client{
		name: name,
		base: baseURL,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &tokenTransport{token: token, base: http.DefaultTransport},
		},
	}
}

// Do runs one request and decodes the JSON answer into out (which may be nil).
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("bus %s %s: encode body: %w", method, path, err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("bus %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("bus %s %s: read body: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Name: c.name, Method: method, Path: path, Status: resp.StatusCode, Body: trim(raw)}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("bus %s %s: decode body: %w", method, path, err)
	}
	return nil
}

// tokenTransport presents the internal token on every request.
type tokenTransport struct {
	token string
	base  http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(req)
}

func trim(raw []byte) string {
	const limit = 200
	if len(raw) > limit {
		return string(raw[:limit]) + "…"
	}
	return string(raw)
}
