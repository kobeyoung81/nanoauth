package bustest

// Package bustest is a fake bus for nanoauth's tests.
//
// nanoauth's stores are clients now, so what has to be pinned is *what they ask
// for and how they read the answer* — a database mock would pin SQL text that no
// longer exists. The fake keeps just enough state for that: accounts, directory
// links, refresh tickets, configuration and the audit log. It is a package (not a
// _test file) so the store, handler and integration tests can share one fake,
// the same way the bus's own storetest is shared.

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
	// newAccountRole is the role the fake gives an account created through its
	// POST /users. The real bus decides this (the first sign-up becomes an
	// administrator); a test that cares sets it explicitly.
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
	fail := (b.failRead && r.Method == http.MethodGet) ||
		(b.failAccountRead && r.Method == http.MethodGet &&
			strings.HasPrefix(r.URL.Path, "/api/v1/user-accounts/"))
	b.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == http.MethodGet && path == "/user-accounts":
		b.listAccounts(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/user-accounts/") && strings.HasSuffix(path, "/password-hash"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/user-accounts/"), "/password-hash")
		b.writeAccountField(w, id, "password_hash")
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/user-accounts/"):
		b.writeAccount(w, strings.TrimPrefix(path, "/user-accounts/"))
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/user-accounts/"):
		b.patchAccount(w, r, strings.TrimPrefix(path, "/user-accounts/"))
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/user-accounts/"):
		b.putPassword(w, r, strings.TrimPrefix(strings.TrimSuffix(path, "/password"), "/user-accounts/"))
	case r.Method == http.MethodPost && path == "/users":
		b.createAccount(w, r)
	// The bare /oauth-links is the identity lookup; the /users/<id>/ one is the
	// account's links. Order matters: the lookup would otherwise be swallowed.
	case r.Method == http.MethodGet && path == "/oauth-links":
		b.lookupLink(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/oauth-links"):
		b.listLinks(w, strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/oauth-links"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/oauth-links"):
		b.link(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/oauth-links"))
	// The admin module owns the trail; the bus only forwards there. One fake
	// serves both shapes so a test can point either client at it.
	case r.Method == http.MethodPost && (path == "/audit" || path == "/internal/audit"):
		b.recordAudit(w, r)
	case r.Method == http.MethodPost && path == "/auth/refresh-tokens":
		b.storeToken(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/auth/refresh-tokens/"):
		b.readToken(w, strings.TrimPrefix(path, "/auth/refresh-tokens/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/auth/refresh-tokens/"):
		b.deleteToken(w, strings.TrimPrefix(path, "/auth/refresh-tokens/"))
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

func (b *Bus) listAccounts(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	b.mu.Lock()
	defer b.mu.Unlock()
	users := []map[string]any{}
	for _, account := range b.accounts {
		if email == "" || account["email"] == email {
			users = append(users, publicAccount(account))
		}
	}
	writeJSONTo(w, map[string]any{"users": users})
}

func (b *Bus) writeAccount(w http.ResponseWriter, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	account, ok := b.accounts[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSONTo(w, publicAccount(account))
}

func (b *Bus) writeAccountField(w http.ResponseWriter, id, field string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	account, ok := b.accounts[id]
	if !ok || account[field] == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSONTo(w, map[string]any{"user_id": id, field: account[field]})
}

func (b *Bus) patchAccount(w http.ResponseWriter, r *http.Request, id string) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	defer b.mu.Unlock()
	account, ok := b.accounts[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	for key, value := range body {
		account[key] = value
	}
	writeJSONTo(w, map[string]any{"status": "updated"})
}

func (b *Bus) putPassword(w http.ResponseWriter, r *http.Request, id string) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	defer b.mu.Unlock()
	account, ok := b.accounts[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	account["password_hash"] = body["password_hash"]
	// Only a request that names the flag changes it — the bus's own rule.
	if value, ok := body["must_change_password"]; ok {
		account["must_change_password"] = value
	}
	writeJSONTo(w, map[string]any{"status": "updated"})
}

func (b *Bus) createAccount(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	id, _ := body["id"].(string)
	email, _ := body["email"].(string)

	b.mu.Lock()
	defer b.mu.Unlock()
	if email != "" {
		for _, account := range b.accounts {
			if account["email"] == email {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
	}
	role := b.newAccountRole
	if role == "" {
		role = "user"
	}
	account := map[string]any{
		"user_id": id, "email": email, "role": role, "tier": "free",
		"status": "active", "must_change_password": false,
	}
	if name, ok := body["display_name"]; ok {
		account["display_name"] = name
	}
	if hash, ok := body["password_hash"]; ok {
		account["password_hash"] = hash
	}
	b.accounts[id] = account
	writeJSONTo(w, map[string]any{"id": id, "status": "created"})
}

func (b *Bus) listLinks(w http.ResponseWriter, userID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	links := []map[string]any{}
	for pair, providerID := range b.links[userID] {
		provider := strings.SplitN(pair, "|", 2)[0]
		links = append(links, map[string]any{"user_id": userID, "provider": provider, "provider_id": providerID})
	}
	writeJSONTo(w, map[string]any{"links": links})
}

func (b *Bus) link(w http.ResponseWriter, r *http.Request, userID string) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.links[userID] == nil {
		b.links[userID] = map[string]string{}
	}
	b.links[userID][body["provider"]+"|"+body["provider_id"]] = body["provider_id"]
	writeJSONTo(w, map[string]any{"status": "linked"})
}

func (b *Bus) lookupLink(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	providerID := r.URL.Query().Get("provider_id")
	ids := []string{}
	b.mu.Lock()
	for userID, links := range b.links {
		if _, ok := links[provider+"|"+providerID]; ok {
			ids = append(ids, userID)
		}
	}
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"user_ids": ids})
}

func (b *Bus) recordAudit(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	b.audit = append(b.audit, body)
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"status": "recorded"})
}

func (b *Bus) storeToken(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	b.mu.Lock()
	b.tokens[body["token_hash"]] = map[string]string{
		"user_id": body["user_id"], "expires_at": body["expires_at"],
	}
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"status": "saved"})
}

func (b *Bus) readToken(w http.ResponseWriter, hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	token, ok := b.tokens[hash]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSONTo(w, map[string]any{"user_id": token["user_id"], "expires_at": token["expires_at"]})
}

func (b *Bus) deleteToken(w http.ResponseWriter, hash string) {
	b.mu.Lock()
	delete(b.tokens, hash)
	b.mu.Unlock()
	writeJSONTo(w, map[string]any{"status": "revoked"})
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

// publicAccount drops the credential: the bus's account shape never carries it.
func publicAccount(account map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range account {
		if key == "password_hash" {
			continue
		}
		out[key] = value
	}
	return out
}
