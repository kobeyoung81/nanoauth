package accounttest

// An in-memory account store for the HTTP tests.
//
// The user store holds the identity database directly, so a handler test needs
// something that answers the store's account calls without a database. This
// wraps the fake bus's account state — the maps the fake already keeps for its
// REST handlers — and speaks the store's AccountStore to it, so a test seeds an
// account the way it always did (`stub.AddAccount`, `stub.SetLinks`) and both
// the handler's store and the fake's HTTP paths see it.
//
// It is a test double, not a second implementation: the semantics that matter —
// the unique address, the one-shot administrator claim, the column defaults —
// are pinned against the real store in internal/store's own tests.

import (
	"errors"
	"strings"

	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// Accounts adapts a fake bus's account state to store.AccountStore.
type Accounts struct {
	bus *bustest.Bus
	// claimed mirrors the installation flag: the first claim wins, and a
	// registration that could not take the role hands it back.
	claimed bool
}

// New wraps a fake bus.
func New(bus *bustest.Bus) *Accounts { return &Accounts{bus: bus} }

func (a *Accounts) RegisterUser(userID, displayName string) error {
	if a.bus.Account(userID) == nil {
		a.bus.AddAccount(userID, "", displayName, "")
		return nil
	}
	a.bus.SetAccountField(userID, "display_name", displayName)
	return nil
}

func (a *Accounts) SetUserEmail(userID, email string) error {
	if a.bus.Account(userID) == nil {
		return store.ErrUserNotFound
	}
	for _, id := range a.bus.AccountIDs() {
		if id != userID && email != "" && a.bus.Account(id)["email"] == email {
			return store.ErrEmailTaken
		}
	}
	a.bus.SetAccountField(userID, "email", email)
	return nil
}

func (a *Accounts) SetUserPassword(userID, passwordHash string, mustChange bool) error {
	if a.bus.Account(userID) == nil {
		return store.ErrUserNotFound
	}
	a.bus.SetAccountField(userID, "password_hash", passwordHash)
	a.bus.SetAccountField(userID, "must_change_password", mustChange)
	return nil
}

func (a *Accounts) SetUserPasswordKeepingFlag(userID, passwordHash string) error {
	if a.bus.Account(userID) == nil {
		return store.ErrUserNotFound
	}
	a.bus.SetAccountField(userID, "password_hash", passwordHash)
	return nil
}

func (a *Accounts) UpdateUserStatus(userID, status string) error {
	return a.setField(userID, "status", status)
}

func (a *Accounts) SetUserDisplayName(userID, displayName string) error {
	return a.setField(userID, "display_name", displayName)
}

func (a *Accounts) SetUserRole(userID, role string) error {
	return a.setField(userID, "role", role)
}

func (a *Accounts) setField(userID, field string, value any) error {
	if a.bus.Account(userID) == nil {
		return store.ErrUserNotFound
	}
	a.bus.SetAccountField(userID, field, value)
	return nil
}

func (a *Accounts) LinkOAuth(userID, provider, providerID string) error {
	a.bus.AddLink(userID, provider, providerID)
	return nil
}

func (a *Accounts) OAuthLinks(userID string) ([]store.OAuthLink, error) {
	links := make([]store.OAuthLink, 0)
	for pair, providerID := range a.bus.Links(userID) {
		provider := strings.SplitN(pair, "|", 2)[0]
		links = append(links, store.OAuthLink{UserID: userID, Provider: provider, ProviderID: providerID})
	}
	return links, nil
}

func (a *Accounts) AccountByID(userID string) (*store.UserRecord, error) {
	// The fake can be told that a single account cannot be read back, which is the
	// state a registration is in when the row was written but not yet readable.
	if a.bus.AccountReadsFailing() {
		return nil, errors.New("the account cannot be read")
	}
	return record(a.bus.Account(userID)), nil
}

func (a *Accounts) AccountByEmail(email string) (*store.UserRecord, error) {
	for _, id := range a.bus.AccountIDs() {
		if account := a.bus.Account(id); account != nil && email != "" && account["email"] == email {
			return record(account), nil
		}
	}
	return nil, nil
}

func (a *Accounts) AccountByOAuthLink(provider, providerID string) (*store.UserRecord, error) {
	for _, id := range a.bus.AccountIDs() {
		if _, ok := a.bus.Links(id)[provider+"|"+providerID]; ok {
			return record(a.bus.Account(id)), nil
		}
	}
	return nil, nil
}

func (a *Accounts) PasswordHash(userID string) (string, error) {
	account := a.bus.Account(userID)
	if account == nil {
		return "", store.ErrUserNotFound
	}
	hash, _ := account["password_hash"].(string)
	return hash, nil
}

func (a *Accounts) CountActiveAdmins() (int, error) {
	count := 0
	for _, id := range a.bus.AccountIDs() {
		account := a.bus.Account(id)
		if account != nil && account["role"] == "admin" && account["status"] != "deleted" {
			count++
		}
	}
	return count, nil
}

func (a *Accounts) ClaimBootstrapAdmin(string) (bool, error) {
	if a.claimed {
		return false, nil
	}
	a.claimed = true
	return true, nil
}

func (a *Accounts) ReleaseBootstrapAdmin(string) error {
	a.claimed = false
	return nil
}

// record projects the fake's map into the shape the store hands its callers,
// filling the column defaults the real read fills.
func record(account map[string]any) *store.UserRecord {
	if account == nil {
		return nil
	}
	text := func(key, fallback string) string {
		if value, ok := account[key].(string); ok && value != "" {
			return value
		}
		return fallback
	}
	out := &store.UserRecord{
		ID:                text("user_id", ""),
		Email:             text("email", ""),
		DisplayName:       text("display_name", ""),
		Role:              text("role", "user"),
		Tier:              text("tier", "free"),
		Status:            text("status", "active"),
		PreferredLanguage: text("preferred_language", ""),
	}
	if value, ok := account["must_change_password"].(bool); ok {
		out.MustChangePassword = value
	}
	return out
}
