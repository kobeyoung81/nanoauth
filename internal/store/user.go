package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

// ErrEmailTaken reports that a user with the same email already exists. The
// login flow retries such a race as a link rather than a new account.
var ErrEmailTaken = errors.New("email already taken")

// ErrStoreNotConfigured reports a deployment without a database URI. It is
// deliberately an error rather than an empty answer: an account that cannot be
// written must not look like one that was.
var ErrStoreNotConfigured = errors.New("the account store is not configured")

// AccountStore is the identity database as the handlers reach it.
//
// It is an interface for the same reason the bus's account backend is one: the
// handler tests exercise flows without a database, while the semantics live in
// the store's own tests against a real one.
type AccountStore interface {
	RegisterUser(userID, displayName string) error
	SetUserEmail(userID, email string) error
	SetUserPassword(userID, passwordHash string, mustChange bool) error
	SetUserPasswordKeepingFlag(userID, passwordHash string) error
	UpdateUserStatus(userID, status string) error
	SetUserDisplayName(userID, displayName string) error
	SetUserRole(userID, role string) error
	LinkOAuth(userID, provider, providerID string) error
	OAuthLinks(userID string) ([]OAuthLink, error)
	AccountByID(userID string) (*UserRecord, error)
	AccountByEmail(email string) (*UserRecord, error)
	AccountByOAuthLink(provider, providerID string) (*UserRecord, error)
	PasswordHash(userID string) (string, error)
	CountActiveAdmins() (int, error)
	ClaimBootstrapAdmin(userID string) (bool, error)
	ReleaseBootstrapAdmin(userID string) error
	GetUserPreferredLanguage(userID string) (string, error)
	SetUserPreferredLanguage(userID, language string) error
}

// UserStore is the account store the handlers use.
//
// The documents are identity's and live in the platform database, which this
// service holds: the reads (accounts.go) and the writes (users.go) both go
// straight there. There is no second owner to ask — the bus used to front these
// calls, which made a sign-up depend on the messaging service being up so it
// could be forwarded straight back here.
type UserStore struct {
	accounts AccountStore
	// admin is the admin module: the installation configuration (which decides
	// whether the first account becomes an administrator) and the audit trail.
	admin *bus.Client
}

// NewUserStore builds the store over the identity database.
func NewUserStore(accounts AccountStore) *UserStore {
	return &UserStore{accounts: accounts}
}

// WithAdmin attaches the admin module. Without it the installation switches fall
// back to their defaults and the audit trail reports that it is not configured.
func (s *UserStore) WithAdmin(client *bus.Client) *UserStore {
	s.admin = client
	return s
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
	PreferredLanguage  string
	UpdatedAt          time.Time
}

// GetByEmail returns the account with this address, or nil when there is none.
// The credential comes from its own read so callers that only need the profile
// do not carry the hash around.
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*UserRecord, error) {
	if s.accounts == nil {
		return nil, ErrStoreNotConfigured
	}
	record, err := s.accounts.AccountByEmail(email)
	if err != nil || record == nil {
		return record, err
	}
	return s.withCredential(record)
}

func (s *UserStore) GetByID(ctx context.Context, id string) (*UserRecord, error) {
	if s.accounts == nil {
		return nil, ErrStoreNotConfigured
	}
	record, err := s.accounts.AccountByID(id)
	if err != nil || record == nil {
		return record, err
	}
	return s.withCredential(record)
}

// withCredential fills in the hash the profile read leaves out.
func (s *UserStore) withCredential(record *UserRecord) (*UserRecord, error) {
	hash, err := s.accounts.PasswordHash(record.ID)
	if err != nil {
		return nil, err
	}
	record.PasswordHash = hash
	return record, nil
}

// GetAuthProviderID returns the directory unique id an account is linked to, or
// "" when the account signs in with a local password.
func (s *UserStore) GetAuthProviderID(ctx context.Context, userID string) (string, error) {
	if s.accounts == nil {
		return "", ErrStoreNotConfigured
	}
	links, err := s.accounts.OAuthLinks(userID)
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

// CreateWithLDAP creates a directory-managed account and links it to the
// directory unique id.
//
// A failure between the two writes leaves a passwordless account with no link,
// and the caller's own recovery path covers exactly that: a retry answers
// ErrEmailTaken and the flow links the identity to the account that is there.
func (s *UserStore) CreateWithLDAP(ctx context.Context, uniqueID, email, displayName string) (string, error) {
	id, err := s.createAccount(email, displayName, "")
	if err != nil {
		return "", err
	}
	s.maybeBootstrapAdmin(ctx, id)
	if err := s.LinkOAuth(ctx, id, "ldap", uniqueID); err != nil {
		return "", fmt.Errorf("link ldap identity: %w", err)
	}
	return id, nil
}

// createAccount writes the account document itself: the row, then the address
// (which carries the uniqueness rule), then the credential when there is one.
//
// The address is set after the row because the sparse unique index rejects a
// second account with the same one, and that answer has to reach the caller as
// ErrEmailTaken rather than as a broken insert.
func (s *UserStore) createAccount(email, displayName, passwordHash string) (string, error) {
	if s.accounts == nil {
		return "", ErrStoreNotConfigured
	}
	id := generateID()
	if err := s.accounts.RegisterUser(id, displayName); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	if email != "" {
		if err := s.accounts.SetUserEmail(id, email); err != nil {
			if errors.Is(err, ErrEmailTaken) {
				return "", ErrEmailTaken
			}
			return "", fmt.Errorf("create user: %w", err)
		}
	}
	if passwordHash != "" {
		if err := s.accounts.SetUserPassword(id, passwordHash, false); err != nil {
			return "", fmt.Errorf("create user: %w", err)
		}
	}
	return id, nil
}

// RecordAuthAudit appends an identity event to the platform trail. The admin
// module owns that collection; a deployment without it reports the failure and
// the caller logs it. It must never fail a login.
func (s *UserStore) RecordAuthAudit(ctx context.Context, action, userID, role, ip string, detail map[string]any) error {
	if s.admin == nil {
		return errors.New("the audit trail is not configured")
	}
	body := map[string]any{
		"actor_id": userID, "actor_role": role, "action": action,
		"resource_type": "user", "resource_id": userID, "ip": ip,
	}
	if detail != nil {
		body["detail"] = detail
	}
	if err := s.admin.Do(ctx, http.MethodPost, "/api/v1/internal/audit", body, nil); err != nil {
		return fmt.Errorf("record auth audit: %w", err)
	}
	return nil
}

// Create registers a local account: the address, the credential hash the caller
// produced and, on a fresh installation, the administrator role.
func (s *UserStore) Create(ctx context.Context, email, passwordHash, displayName string) (string, error) {
	id, err := s.createAccount(email, displayName, passwordHash)
	if err != nil {
		return "", err
	}
	s.maybeBootstrapAdmin(ctx, id)
	return id, nil
}

// UpdatePasswordHash replaces the credential without touching the forced-change
// flag: the directory path blanks a local password, which says nothing about
// whether the next one is forced.
func (s *UserStore) UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error {
	if s.accounts == nil {
		return ErrStoreNotConfigured
	}
	return s.accounts.SetUserPasswordKeepingFlag(userID, passwordHash)
}

// SetStatus moves an account between lifecycle states (active, suspended,
// pending, deleted). The directory login uses it to suspend an account whose
// entry has disappeared from the directory.
func (s *UserStore) SetStatus(ctx context.Context, userID, status string) error {
	if s.accounts == nil {
		return ErrStoreNotConfigured
	}
	return s.accounts.UpdateUserStatus(userID, status)
}

// UpdateDisplayName refreshes an account's display name, which is what the next
// issued token carries.
func (s *UserStore) UpdateDisplayName(ctx context.Context, userID, displayName string) error {
	if s.accounts == nil {
		return ErrStoreNotConfigured
	}
	return s.accounts.SetUserDisplayName(userID, displayName)
}

// GetByOAuthProvider returns the user linked to an OAuth provider identity
// (e.g. a WeChat openid), or nil if none exists.
func (s *UserStore) GetByOAuthProvider(ctx context.Context, provider, providerID string) (*UserRecord, error) {
	if s.accounts == nil {
		return nil, ErrStoreNotConfigured
	}
	record, err := s.accounts.AccountByOAuthLink(provider, providerID)
	if err != nil || record == nil {
		return record, err
	}
	return s.withCredential(record)
}

// CreateWithOAuth creates an account for an OAuth identity and links it. The
// identity is the account's address here, so a retry answers ErrEmailTaken and
// the caller links instead.
func (s *UserStore) CreateWithOAuth(ctx context.Context, provider, providerID, displayName string) (string, error) {
	id, err := s.createAccount(provider+":"+providerID, displayName, "")
	if err != nil {
		return "", err
	}
	s.maybeBootstrapAdmin(ctx, id)
	if err := s.LinkOAuth(ctx, id, provider, providerID); err != nil {
		return "", fmt.Errorf("link oauth provider: %w", err)
	}
	return id, nil
}

// LinkOAuth associates an OAuth provider identity with an existing user. The
// store upserts on (provider, provider_id): one identity, one account.
func (s *UserStore) LinkOAuth(ctx context.Context, userID, provider, providerID string) error {
	if s.accounts == nil {
		return ErrStoreNotConfigured
	}
	return s.accounts.LinkOAuth(userID, provider, providerID)
}

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
