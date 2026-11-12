package store

// Bootstrap administrator
//
// A fresh installation has no administrator, and the console hides every
// administrative surface from an ordinary account, so someone has to be the
// first one. The rule is that the account created by the first sign-up takes the
// role. It is one-shot and atomic across concurrent registrations (see
// ClaimBootstrapAdmin) and it can be switched off, because a deployment that
// opens registration to the internet must not hand its administrator role to
// whoever finds it first.
//
// The rule used to run in the bus, which wrote the accounts. The accounts are
// this service's now, so the rule came with them: a sign-up no longer depends on
// another module being reachable to learn what it is allowed to be.

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

const (
	// configComponent is the configuration component this service owns.
	configComponent = "auth"
	// firstUserIsAdminKey is the installation switch. A deployment seeded before
	// the switch existed has no row for it, and the bootstrap rule is the
	// behaviour it is meant to have.
	firstUserIsAdminKey = "firstUserIsAdmin"
)

// firstUserIsAdmin reports the installation switch, defaulting to on. A config
// read that fails is also on: refusing to promote anyone would leave a fresh
// installation with no administrator because one request timed out.
func (s *UserStore) firstUserIsAdmin(ctx context.Context) bool {
	if s.admin == nil {
		return true
	}
	var payload struct {
		Items []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"items"`
	}
	path := "/api/v1/config/" + configComponent
	if err := s.admin.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		slog.Warn("bootstrap administrator: read the installation switch", "error", err)
		return true
	}
	for _, item := range payload.Items {
		if item.Key == firstUserIsAdminKey {
			return strings.EqualFold(strings.TrimSpace(item.Value), "true")
		}
	}
	return true
}

// maybeBootstrapAdmin promotes the account a sign-up has just created while the
// installation still has no administrator. Failures are logged and swallowed: a
// registration must not fail because the optional role hand-over did not work.
func (s *UserStore) maybeBootstrapAdmin(ctx context.Context, userID string) {
	if s.accounts == nil || userID == "" || !s.firstUserIsAdmin(ctx) {
		return
	}
	admins, err := s.accounts.CountActiveAdmins()
	if err != nil {
		slog.Warn("bootstrap administrator: count administrators", "error", err)
		return
	}
	if admins > 0 {
		return
	}
	claimed, err := s.accounts.ClaimBootstrapAdmin(userID)
	if err != nil {
		slog.Error("bootstrap administrator: claim", "user_id", userID, "error", err)
		return
	}
	if !claimed {
		return
	}
	if err := s.accounts.SetUserRole(userID, "admin"); err != nil {
		// Give the claim back: this account is not an administrator, so the next
		// registration has to be able to take the role.
		if releaseErr := s.accounts.ReleaseBootstrapAdmin(userID); releaseErr != nil {
			slog.Error("bootstrap administrator: release", "user_id", userID, "error", releaseErr)
		}
		slog.Error("bootstrap administrator: set role", "user_id", userID, "error", err)
		return
	}
	slog.Info("bootstrap administrator", "user_id", userID,
		"hint", "the first account of this installation inherited the administrator role")
	if err := s.RecordAuthAudit(ctx, "user.bootstrap.admin", userID, "admin", "", nil); err != nil {
		slog.Warn("bootstrap administrator: audit", "user_id", userID, "error", err)
	}
}
