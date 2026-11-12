package bustest

// Package bustest is the fake the auth service's tests seed.
//
// It is two things in one: the state a test writes (accounts, directory links,
// refresh tickets) and the two HTTP surfaces a service still asks over the wire
// (configuration, which the admin module serves, and the audit trail, which this
// fake records). The identity collections are reached through the stores now, so
// the fake no longer answers them over HTTP — internal/fakestore adapts this
// state to those stores. It is a package rather than a _test file so the store,
// handler and integration tests can share it, the way the bus's own storetest is
// shared.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

type Bus struct {
	mu               sync.Mutex
	accounts         map[string]map[string]any
	links            map[string]map[string]string // userID → provider|providerID → providerID
	tokens           map[string]map[string]string // hash → {user_id, expires_at}
	config           map[string]map[string]string // component → key → value
	audit            []map[string]any
	failRead         bool
	failAccountRead  bool
	requests         []string
	bootstrapClaimed bool
	// newAccountRole is the role the fake gives an account it seeds. A test whose
	// subject is the role of a fresh sign-up sets it explicitly.
	newAccountRole string
}

func New() *Bus {
	return &Bus{
		accounts: map[string]map[string]any{},
		links:    map[string]map[string]string{},
		tokens:   map[string]map[string]string{},
		config:   map[string]map[string]string{},
	}
}

// SetNewAccountRole sets the role the fake assigns to accounts it creates.
func (b *Bus) SetNewAccountRole(role string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.newAccountRole = role
}

// AccountIDs returns the ids the fake holds, for a failure message.
func (b *Bus) AccountIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.accounts))
	for id := range b.accounts {
		out = append(out, id)
	}
	return out
}

// SetLinks replaces a user's links. Keys are "provider|provider_id".
func (b *Bus) SetLinks(userID string, links map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.links[userID] = links
}

// Links returns a user's links (nil when there are none).
func (b *Bus) Links(userID string) map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.links[userID]
}

// SetConfig seeds a component's configuration.
func (b *Bus) SetConfig(component string, values map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config[component] = values
}

// Config returns a component's configuration.
func (b *Bus) Config(component string) map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.config[component]
}

// Tokens returns the stored refresh tickets, keyed by hash.
func (b *Bus) Tokens() map[string]map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]map[string]string, len(b.tokens))
	for hash, token := range b.tokens {
		out[hash] = token
	}
	return out
}

// Token returns one stored ticket and whether it is there.
func (b *Bus) Token(hash string) (map[string]string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ticket, ok := b.tokens[hash]
	return ticket, ok
}

// DeleteToken removes a ticket — what rotation and logout do.
func (b *Bus) DeleteToken(hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.tokens, hash)
}

// StoreToken seeds a refresh ticket directly (hash → owner, expiry).
func (b *Bus) StoreToken(hash, userID string, expires time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens[hash] = map[string]string{
		"user_id": userID, "expires_at": expires.UTC().Format(time.RFC3339),
	}
}

// SetAccountField changes one field of a seeded account.
func (b *Bus) SetAccountField(id, field string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if account, ok := b.accounts[id]; ok {
		account[field] = value
	}
}

// FailReads makes every GET answer 500, which is how "the bus is having a moment"
// paths are exercised.
func (b *Bus) FailReads(fail bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failRead = fail
}

// FailAccountReads makes reads of one account fail while the address lookup and
// the writes keep working — the state a registration is in when the account was
// created but cannot be read back.
func (b *Bus) FailAccountReads(fail bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failAccountRead = fail
}

// AccountReadsFailing reports that switch, for a store adapter that has to fail
// the same reads the fake's HTTP surface fails.
func (b *Bus) AccountReadsFailing() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failAccountRead
}

// Requests returns the calls the fake has served, in order.
func (b *Bus) Requests() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.requests...)
}

// Client returns a bus client pointed at the fake.
func (b *Bus) Client(t *testing.T) *bus.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(b.handle))
	t.Cleanup(srv.Close)
	return bus.New(srv.URL, "test-token")
}

func (b *Bus) AddAccount(id, email, displayName, passwordHash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	role := b.newAccountRole
	if role == "" {
		role = "user"
	}
	b.accounts[id] = map[string]any{
		"user_id": id, "email": email, "display_name": displayName,
		"password_hash": passwordHash, "role": role, "tier": "free",
		"status": "active", "must_change_password": false,
	}
}

// AddLink attaches one provider identity, keeping the others.
func (b *Bus) AddLink(userID, provider, providerID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.links[userID] == nil {
		b.links[userID] = map[string]string{}
	}
	b.links[userID][provider+"|"+providerID] = providerID
}

func (b *Bus) Account(id string) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accounts[id]
}

func (b *Bus) Entries() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]map[string]any{}, b.audit...)
}

func (b *Bus) handle(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	b.requests = append(b.requests, r.Method+" "+r.URL.Path)
	fail := b.failRead && r.Method == http.MethodGet
	b.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	// The admin module owns the trail; the bus only forwards there. One fake
	// serves both shapes so a test can point either client at it.
	case r.Method == http.MethodPost && (path == "/audit" || path == "/internal/audit"):
		b.recordAudit(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/config/"):
		b.readConfig(w, strings.TrimPrefix(path, "/config/"))
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/config/"):
		b.writeConfig(w, r, strings.TrimPrefix(path, "/config/"))
	default:
		http.NotFound(w, r)
	}
}

func writeJSONTo(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (b *Bus) recordAudit(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	b.audit = append(b.audit, body)
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"status": "recorded"})
}

func (b *Bus) readConfig(w http.ResponseWriter, component string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	items := []map[string]string{}
	for key, value := range b.config[component] {
		items = append(items, map[string]string{"key": key, "value": value})
	}
	writeJSONTo(w, map[string]any{"component_type": component, "items": items})
}

func (b *Bus) writeConfig(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	if b.config[parts[0]] == nil {
		b.config[parts[0]] = map[string]string{}
	}
	b.config[parts[0]][parts[1]] = body["value"]
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"status": "set"})
}
