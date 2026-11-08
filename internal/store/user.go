package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

// ErrEmailTaken reports that a user with the same email already exists. The
// login flow retries such a race as a link rather than a new account.
var ErrEmailTaken = errors.New("email already taken")

// UserStore reads and writes accounts through the bus.
//
// It used to open `users`, `oauth_providers` and `audit_log` itself. Those tables
// belong to the bus now, which is the only service with a database connection, so
// this store is a client: the method set is unchanged — the handlers never knew
// where the rows lived — and the SQL is gone with the connection.
type UserStore struct {
	bus *bus.Client
}

func NewUserStore(client *bus.Client) *UserStore {
	return &UserStore{bus: client}
}

type UserRecord struct {
	ID                 string
	Email              string
	PasswordHash       string
	DisplayName        string
	Role               string
	Status             string
	Tier               string
	MustChangePassword bool
}

// accountPayload is one account as the bus sends it.
type accountPayload struct {
	UserID             string `json:"user_id"`
	Email              string `json:"email"`
	DisplayName        string `json:"display_name"`
	Role               string `json:"role"`
	Tier               string `json:"tier"`
	Status             string `json:"status"`
	MustChangePassword bool   `json:"must_change_password"`
}

func (p accountPayload) record() UserRecord {
	role := p.Role
	if role == "" {
		role = "user"
	}
	tier := p.Tier
	if tier == "" {
		tier = "free"
	}
	status := p.Status
	if status == "" {
		status = "active"
	}
	return UserRecord{
		ID: p.UserID, Email: p.Email, DisplayName: p.DisplayName,
		Role: role, Tier: tier, Status: status,
		MustChangePassword: p.MustChangePassword,
	}
}

// GetByEmail returns the account with this address, or nil when there is none.
//
// Two calls: the account itself, then its credential. The bus keeps the hash
// behind its own endpoint on purpose (only a caller with the internal token can
// read it), and the sign-in path is not hot enough to argue about one more
// round trip inside the same host.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*UserRecord, error) {
	var payload struct {
		Users []accountPayload `json:"users"`
	}
	path := "/api/v1/user-accounts?email=" + url.QueryEscape(email)
	if err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, fmt.Errorf("query user by email: %w", err)
	}
	if len(payload.Users) == 0 {
		return nil, nil
	}
	record := payload.Users[0].record()
	hash, err := s.passwordHash(ctx, record.ID)
	if err != nil {
		return nil, err
	}
	record.PasswordHash = hash
	return &record, nil
}

func (s *UserStore) GetByID(ctx context.Context, id string) (*UserRecord, error) {
	var payload accountPayload
	path := "/api/v1/user-accounts/" + url.PathEscape(id)
	if err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		if errors.Is(err, bus.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("query user by id: %w", err)
	}
	record := payload.record()
	hash, err := s.passwordHash(ctx, record.ID)
	if err != nil {
		return nil, err
	}
	record.PasswordHash = hash
	return &record, nil
}

// passwordHash reads the stored credential. The bus answers 404 for an account
// that holds none.
func (s *UserStore) passwordHash(ctx context.Context, userID string) (string, error) {
	var payload struct {
		PasswordHash string `json:"password_hash"`
	}
	path := "/api/v1/user-accounts/" + url.PathEscape(userID) + "/password-hash"
	if err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		if errors.Is(err, bus.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("read password hash: %w", err)
	}
	return payload.PasswordHash, nil
}

// GetAuthProviderID returns the directory unique id an account is linked to, or
// "" when the account signs in with a local password.
func (s *UserStore) GetAuthProviderID(ctx context.Context, userID string) (string, error) {
	links, err := s.links(ctx, userID)
	if err != nil {
		return "", err
	}
	for _, link := range links {
		if link.Provider == "ldap" {
			return link.ProviderID, nil
		}
	}
	return "", nil
}

type linkPayload struct {
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
}

func (s *UserStore) links(ctx context.Context, userID string) ([]linkPayload, error) {
	var payload struct {
		Links []linkPayload `json:"links"`
	}
	path := "/api/v1/users/" + url.PathEscape(userID) + "/oauth-links"
	if err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, fmt.Errorf("query ldap link: %w", err)
	}
	return payload.Links, nil
}

// CreateWithLDAP creates a directory-managed account and links it to the
// directory unique id.
//
// The SQL version did both inside one transaction. Across an API boundary there
// is none, so this is two calls: the account, then the link. A failure between
// them leaves a passwordless account with no link, and the caller's own recovery
// path already covers exactly that — a retry answers ErrEmailTaken and the flow
// links the identity to the account that is already there.
func (s *UserStore) CreateWithLDAP(ctx context.Context, uniqueID, email, displayName string) (string, error) {
	id := generateID()
	body := map[string]any{
		"id": id, "email": email, "display_name": displayName,
	}
	if err := s.bus.Do(ctx, http.MethodPost, "/api/v1/users", body, nil); err != nil {
		if isConflict(err) {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("create ldap user: %w", err)
	}
	if err := s.LinkOAuth(ctx, id, "ldap", uniqueID); err != nil {
		return "", fmt.Errorf("link ldap identity: %w", err)
	}
	return id, nil
}

// RecordAuthAudit appends an identity-binding event to the shared audit log.
// Failures are returned for the caller to log; they must not fail a login.
func (s *UserStore) RecordAuthAudit(ctx context.Context, action, userID, role, ip string, detail map[string]any) error {
	body := map[string]any{
		"actor_id": userID, "actor_role": role, "action": action,
		"resource_type": "user", "resource_id": userID, "ip": ip,
	}
	if detail != nil {
		body["detail"] = detail
	}
	if err := s.bus.Do(ctx, http.MethodPost, "/api/v1/audit", body, nil); err != nil {
		return fmt.Errorf("record auth audit: %w", err)
	}
	return nil
}

func (s *UserStore) Create(ctx context.Context, email, passwordHash, displayName string) (string, error) {
	id := generateID()
	body := map[string]any{
		"id": id, "email": email, "display_name": displayName,
		"password_hash": passwordHash,
	}
	if err := s.bus.Do(ctx, http.MethodPost, "/api/v1/users", body, nil); err != nil {
		if isConflict(err) {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// UpdatePasswordHash replaces the credential without touching the forced-change
// flag: the directory path blanks a local password, which says nothing about
// whether the next one is forced.
func (s *UserStore) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	body := map[string]string{"password_hash": passwordHash}
	return s.bus.Do(ctx, http.MethodPut, passwordPath(userID), body, nil)
}

// SetPassword sets the credential and clears the forced-change flag.
func (s *UserStore) SetPassword(ctx context.Context, userID, passwordHash string) error {
	body := map[string]any{"password_hash": passwordHash, "must_change_password": false}
	return s.bus.Do(ctx, http.MethodPut, passwordPath(userID), body, nil)
}

func passwordPath(userID string) string {
	return "/api/v1/user-accounts/" + url.PathEscape(userID) + "/password"
}

// SetStatus moves an account between lifecycle states (active, suspended,
// pending, deleted). The directory login uses it to suspend an account whose
// entry has disappeared from the directory.
func (s *UserStore) SetStatus(ctx context.Context, userID, status string) error {
	return s.patch(ctx, userID, map[string]string{"status": status})
}

// UpdateDisplayName refreshes an account's display name, which is what the next
// issued token carries.
func (s *UserStore) UpdateDisplayName(ctx context.Context, userID, displayName string) error {
	return s.patch(ctx, userID, map[string]string{"display_name": displayName})
}

func (s *UserStore) patch(ctx context.Context, userID string, fields map[string]string) error {
	path := "/api/v1/user-accounts/" + url.PathEscape(userID)
	return s.bus.Do(ctx, http.MethodPatch, path, fields, nil)
}

// GetByOAuthProvider returns the user linked to an OAuth provider identity
// (e.g. a WeChat openid), or nil if none exists.
func (s *UserStore) GetByOAuthProvider(ctx context.Context, provider, providerID string) (*UserRecord, error) {
	query := url.Values{}
	query.Set("provider", provider)
	query.Set("provider_id", providerID)
	var payload struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := s.bus.Do(ctx, http.MethodGet, "/api/v1/oauth-links?"+query.Encode(), nil, &payload); err != nil {
		return nil, fmt.Errorf("query user by oauth provider: %w", err)
	}
	if len(payload.UserIDs) == 0 {
		return nil, nil
	}
	return s.GetByID(ctx, payload.UserIDs[0])
}

// CreateWithOAuth creates an account for an OAuth identity and links it. Like the
// directory variant this is two calls rather than one transaction; the identity is
// the account's address here, so a retry answers ErrEmailTaken and the caller
// links instead.
func (s *UserStore) CreateWithOAuth(ctx context.Context, provider, providerID, displayName string) (string, error) {
	id := generateID()
	body := map[string]any{
		"id": id, "email": provider + ":" + providerID, "display_name": displayName,
	}
	if err := s.bus.Do(ctx, http.MethodPost, "/api/v1/users", body, nil); err != nil {
		if isConflict(err) {
			return "", ErrEmailTaken
		}
		return "", fmt.Errorf("create oauth user: %w", err)
	}
	if err := s.LinkOAuth(ctx, id, provider, providerID); err != nil {
		return "", fmt.Errorf("link oauth provider: %w", err)
	}
	return id, nil
}

// LinkOAuth associates an OAuth provider identity with an existing user. The bus
// upserts on (provider, provider_id), which is what the SQL's ON DUPLICATE KEY
// meant: one identity, one account.
func (s *UserStore) LinkOAuth(ctx context.Context, userID, provider, providerID string) error {
	body := map[string]string{"provider": provider, "provider_id": providerID}
	path := "/api/v1/users/" + url.PathEscape(userID) + "/oauth-links"
	if err := s.bus.Do(ctx, http.MethodPost, path, body, nil); err != nil {
		return fmt.Errorf("link oauth provider: %w", err)
	}
	return nil
}

// isConflict reports the bus's 409, which is how a taken address comes back.
func isConflict(err error) bool { return bus.IsStatus(err, http.StatusConflict) }

func generateID() string {
	// Random UUID v4 without external dependency.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate user id: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
