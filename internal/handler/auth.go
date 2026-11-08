package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
	"golang.org/x/crypto/bcrypt"
)

const (
	// roleUser is the only role a directory login may end up on.
	roleUser = "user"
	// ldapProvider is the oauth_providers.provider value for directory links.
	ldapProvider = "ldap"
	// statusSuspended is the lifecycle state a departed employee's account is
	// moved to, the same state the portal's freeze action sets.
	statusSuspended = "suspended"

	// Stable error codes for the outcomes the portal renders with its own
	// wording; the English message stays for logs and non-portal clients.
	codeDirectoryUnavailable  = "directory_unavailable"
	codeAccountNotProvisioned = "account_not_provisioned"
	codeAccountConflict       = "account_conflict"
	codeAccountDisabled       = "account_disabled"
)

type AuthHandler struct {
	tokenSvc     *token.TokenService
	userStore    *store.UserStore
	tokenStore   *store.TokenStore
	dir          directory.Directory
	configSource directory.ConfigSource
}

func NewAuthHandler(tokenSvc *token.TokenService, userStore *store.UserStore, tokenStore *store.TokenStore) *AuthHandler {
	return &AuthHandler{tokenSvc: tokenSvc, userStore: userStore, tokenStore: tokenStore}
}

// WithDirectory enables directory login. Both arguments must be non-nil; the
// handler keeps its password-only behaviour until this is called.
func (h *AuthHandler) WithDirectory(dir directory.Directory, source directory.ConfigSource) *AuthHandler {
	h.dir = dir
	h.configSource = source
	return h
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type tokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	TokenType          string `json:"token_type"`
	ExpiresIn          int    `json:"expires_in"`
	UserID             string `json:"user_id"`
	DisplayName        string `json:"display_name"`
	Role               string `json:"role"`
	Tier               string `json:"tier"`
	MustChangePassword bool   `json:"must_change_password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	existing, err := h.userStore.GetByEmail(r.Context(), req.Email)
	if err != nil {
		slog.Error("check existing user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if existing != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("hash password", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	userID, err := h.userStore.Create(r.Context(), req.Email, string(hash), req.DisplayName)
	if err != nil {
		slog.Error("create user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	slog.Info("user registered", "user_id", userID, "email", req.Email)

	// The bus decides the account's role, not this handler: a fresh
	// installation hands the administrator role to its first sign-up. Reading
	// the account back (one call, on the registration path only) is what makes
	// that role reach the token and the response, instead of a hard-coded
	// "user" that would only be corrected on the next refresh.
	user, readErr := h.userStore.GetByID(r.Context(), userID)
	if readErr != nil || user == nil {
		slog.Warn("read the new account; issuing the session as a plain user",
			"user_id", userID, "error", readErr)
		user = &store.UserRecord{
			ID: userID, Email: req.Email, DisplayName: req.DisplayName,
			Role: roleUser, Tier: "free", Status: "active",
		}
	}
	h.issueSessionWith(r.Context(), w, http.StatusCreated, user)
}

func (h *AuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// The identifier is the account email. A directory search uses the same
	// value, so it is normalised once for every lookup and for the account
	// created on a first directory login.
	identifier := strings.ToLower(strings.TrimSpace(req.Email))
	if identifier == "" || req.Password == "" {
		// An empty password must never reach a directory: LDAP answers a simple
		// bind carrying no password as an anonymous bind, which succeeds.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	user, err := h.userStore.GetByEmail(r.Context(), identifier)
	if err != nil {
		slog.Error("lookup user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if h.dir != nil && h.configSource != nil {
		cfg, err := h.configSource.Load(r.Context())
		if err != nil {
			slog.Error("load directory config", "error", err)
			writeErrorCode(w, http.StatusServiceUnavailable, "directory unavailable", codeDirectoryUnavailable)
			return
		}
		if cfg != nil && cfg.Enabled {
			resolved, fallThrough := h.loginViaDirectory(w, r, cfg, identifier, req.Password, user)
			switch {
			case resolved != nil:
				// The directory vouched for the account; its local password is
				// deliberately not consulted.
				h.issueSession(r.Context(), w, resolved)
				return
			case !fallThrough:
				return
			}
		}
	}

	if user == nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if user.Status != "active" {
		writeError(w, http.StatusForbidden, "account is not active")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	h.issueSession(r.Context(), w, user)
}

// issueSession writes the token response for an authenticated account. It is
// shared by the local password path and the directory path so both always
// return the same shape.
func (h *AuthHandler) issueSession(ctx context.Context, w http.ResponseWriter, user *store.UserRecord) {
	h.issueSessionWith(ctx, w, http.StatusOK, user)
}

// issueSessionWith is issueSession with a caller-chosen status: registration
// answers 201 while a sign-in answers 200, and both carry the same body.
func (h *AuthHandler) issueSessionWith(ctx context.Context, w http.ResponseWriter, status int, user *store.UserRecord) {
	accessToken, expiresAt, err := h.tokenSvc.GenerateAccessToken(user.ID, user.DisplayName, user.Role, user.Tier)
	if err != nil {
		slog.Error("generate token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := h.tokenStore.StoreRefreshToken(ctx, user.ID, h.tokenStore.TTL())
	if err != nil {
		slog.Error("store refresh token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, status, tokenResponse{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		TokenType:          "Bearer",
		ExpiresIn:          int(time.Until(expiresAt).Seconds()),
		UserID:             user.ID,
		DisplayName:        user.DisplayName,
		Role:               user.Role,
		Tier:               user.Tier,
		MustChangePassword: user.MustChangePassword,
	})
}

// loginViaDirectory applies the directory login rules to a decoded request. It
// returns (user, false) when the caller should issue a session for user,
// (nil, false) when a response has already been written, and (nil, true) when
// the caller should continue with the local password path instead.
func (h *AuthHandler) loginViaDirectory(w http.ResponseWriter, r *http.Request, cfg *directory.Config, email, password string, local *store.UserRecord) (*store.UserRecord, bool) {
	linkedID := ""
	if local != nil {
		providerID, err := h.userStore.GetAuthProviderID(r.Context(), local.ID)
		if err != nil {
			slog.Error("lookup directory link", "user_id", local.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return nil, false
		}
		linkedID = providerID
	}

	// A privileged account never signs in with a directory password: a change
	// in the directory must not become a way into the admin console. It keeps
	// its local password, and it is never linked to a directory identity.
	if local != nil && linkedID == "" && local.Role != roleUser {
		slog.Warn("directory login skipped for a privileged account", "email", email, "role", local.Role)
		return nil, true
	}

	entry, err := h.dir.Authenticate(r.Context(), cfg, email, password)
	if err != nil {
		return h.reportDirectoryError(w, r, cfg, email, local, linkedID, err)
	}

	switch {
	case linkedID != "":
		// Already directory-managed: the id must match, otherwise the entry
		// behind this email has changed owner and the link no longer holds.
		if entry.UniqueID != linkedID {
			slog.Warn("directory unique id mismatch", "email", email, "user_id", local.ID)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return nil, false
		}
		if local.Status != "active" {
			writeError(w, http.StatusForbidden, "account is not active")
			return nil, false
		}
		h.syncDisplayNameFromDirectory(r.Context(), cfg, local, entry)
		return local, false

	case local != nil:
		// First directory login for an existing account. By default the
		// directory identity is bound to it instead of a second account being
		// created for the same email; linkPolicy=refuse leaves the account
		// alone, so merging is always a deliberate act.
		if cfg.LinkPolicy == directory.LinkPolicyRefuse {
			slog.Warn("directory login refused by link policy", "email", email, "user_id", local.ID)
			if err := h.userStore.RecordAuthAudit(r.Context(), "user.ldap.link_refused", local.ID, local.Role, clientIP(r),
				map[string]any{"email": email, "directory_unique_id": entry.UniqueID, "entry_dn": entry.DN}); err != nil {
				slog.Error("record auth audit", "action", "user.ldap.link_refused", "user_id", local.ID, "error", err)
			}
			writeErrorCode(w, http.StatusConflict, "account conflict", codeAccountConflict)
			return nil, false
		}
		if err := h.userStore.LinkOAuth(r.Context(), local.ID, ldapProvider, entry.UniqueID); err != nil {
			slog.Error("link directory identity", "user_id", local.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return nil, false
		}
		// From here on the account only ever signs in through the directory, so
		// the local password is erased rather than left behind as a credential
		// nothing checks any more.
		if err := h.userStore.UpdatePasswordHash(r.Context(), local.ID, ""); err != nil {
			slog.Error("clear the linked account's local password", "user_id", local.ID, "error", err)
		}
		h.recordAuthAudit(r, "user.ldap.link", local, entry, true)
		if local.Status != "active" {
			writeError(w, http.StatusForbidden, "account is not active")
			return nil, false
		}
		h.syncDisplayNameFromDirectory(r.Context(), cfg, local, entry)
		return local, false
	}

	// No account for this email yet.
	if !cfg.AutoProvision {
		writeErrorCode(w, http.StatusForbidden, "account not provisioned", codeAccountNotProvisioned)
		return nil, false
	}
	created, err := h.provisionDirectoryAccount(r, email, entry)
	if err != nil {
		if errors.Is(err, store.ErrEmailTaken) {
			// Someone registered the same email between the lookup and the
			// insert: retry once as a link rather than a creation.
			existing, lookupErr := h.userStore.GetByEmail(r.Context(), email)
			if lookupErr == nil && existing != nil && existing.Role == roleUser {
				if linkErr := h.userStore.LinkOAuth(r.Context(), existing.ID, ldapProvider, entry.UniqueID); linkErr == nil {
					h.recordAuthAudit(r, "user.ldap.link", existing, entry, true)
					return existing, false
				}
			}
			writeErrorCode(w, http.StatusConflict, "account conflict", codeAccountConflict)
			return nil, false
		}
		slog.Error("provision directory account", "email", email, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	h.syncDisplayNameFromDirectory(r.Context(), cfg, created, entry)
	return created, false
}

// syncDisplayNameFromDirectory refreshes the platform display name from the
// directory entry when the setting asks for it. The in-memory record is updated
// too, because that is the name the issued token carries.
func (h *AuthHandler) syncDisplayNameFromDirectory(ctx context.Context, cfg *directory.Config, user *store.UserRecord, entry *directory.Entry) {
	if cfg == nil || !cfg.SyncDisplayName || user == nil || entry == nil {
		return
	}
	name := entry.DisplayName
	if name == "" || name == user.DisplayName {
		return
	}
	if err := h.userStore.UpdateDisplayName(ctx, user.ID, name); err != nil {
		slog.Error("sync display name from the directory", "user_id", user.ID, "error", err)
		return
	}
	user.DisplayName = name
}

// reportDirectoryError maps a failed directory attempt to a response. It is
// also where a local account is allowed to fall back to its own password, and
// where a departed employee's account is suspended.
func (h *AuthHandler) reportDirectoryError(w http.ResponseWriter, r *http.Request, cfg *directory.Config, email string, local *store.UserRecord, linkedID string, err error) (*store.UserRecord, bool) {
	switch {
	case errors.Is(err, directory.ErrUnavailable):
		slog.Warn("directory unavailable", "email", email, "error", err)
		if local == nil || linkedID != "" {
			// Nothing to fall back to: a directory-managed account has no local
			// password by design, and an unknown email cannot be checked.
			writeErrorCode(w, http.StatusServiceUnavailable, "directory unavailable", codeDirectoryUnavailable)
			return nil, false
		}
		// A local account keeps working while the directory is down.
		return nil, true

	case errors.Is(err, directory.ErrEntryNotFound):
		if local != nil && linkedID == "" {
			// The email is simply not a directory account: use the local password.
			return nil, true
		}
		if local != nil && cfg != nil && cfg.DisableOnMissing {
			// The entry behind a directory-managed account is gone: treat it as
			// a departed employee and suspend the platform account, rather than
			// leaving it active with nobody able to sign in.
			if err := h.userStore.SetStatus(r.Context(), local.ID, statusSuspended); err != nil {
				slog.Error("suspend the account of a missing directory entry", "user_id", local.ID, "error", err)
			} else if err := h.userStore.RecordAuthAudit(r.Context(), "user.ldap.missing", local.ID, local.Role, clientIP(r),
				map[string]any{"email": email, "directory_unique_id": linkedID}); err != nil {
				slog.Error("record auth audit", "action", "user.ldap.missing", "user_id", local.ID, "error", err)
			}
			writeErrorCode(w, http.StatusForbidden, "account disabled", codeAccountDisabled)
			return nil, false
		}
		slog.Warn("directory login refused: no entry for the email", "email", email)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return nil, false

	case errors.Is(err, directory.ErrMultipleEntries):
		slog.Warn("directory login refused: the email matches several entries", "email", email)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return nil, false

	default:
		// Wrong password (or a local account whose entry exists in the
		// directory): the identity is directory-managed, so the local password
		// is not tried.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return nil, false
	}
}

// provisionDirectoryAccount creates the platform account for a directory user
// and records the binding in the audit log.
func (h *AuthHandler) provisionDirectoryAccount(r *http.Request, email string, entry *directory.Entry) (*store.UserRecord, error) {
	displayName := entry.DisplayName
	if displayName == "" {
		displayName = entry.Username
	}
	if displayName == "" {
		displayName = email
	}

	userID, err := h.userStore.CreateWithLDAP(r.Context(), entry.UniqueID, email, displayName)
	if err != nil {
		return nil, err
	}

	// The bus may have handed this first account the administrator role; read
	// it back instead of assuming a plain user (see HandleRegister).
	user, readErr := h.userStore.GetByID(r.Context(), userID)
	if readErr != nil || user == nil {
		slog.Warn("read the provisioned account; continuing as a plain user",
			"user_id", userID, "error", readErr)
		user = &store.UserRecord{
			ID:          userID,
			Email:       email,
			DisplayName: displayName,
			Role:        roleUser,
			Tier:        "free",
			Status:      "active",
		}
	}
	h.recordAuthAudit(r, "user.ldap.provision", user, entry, false)
	return user, nil
}

// recordAuthAudit logs an identity-binding event. A failure to record is
// reported but never fails the login it describes.
func (h *AuthHandler) recordAuthAudit(r *http.Request, action string, user *store.UserRecord, entry *directory.Entry, merged bool) {
	detail := map[string]any{
		"email":     user.Email,
		"unique_id": entry.UniqueID,
		"entry_dn":  entry.DN,
		"merged":    merged,
	}
	if err := h.userStore.RecordAuthAudit(r.Context(), action, user.ID, user.Role, clientIP(r), detail); err != nil {
		slog.Error("record auth audit", "action", action, "user_id", user.ID, "error", err)
	}
}

// clientIP prefers the forwarded client address the portal sets; nanoauth sits
// behind the bus proxy, so RemoteAddr alone is the proxy.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first, _, found := strings.Cut(forwarded, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(forwarded)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userID, newToken, err := h.tokenStore.ValidateAndConsume(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	user, err := h.userStore.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		slog.Error("lookup user for refresh", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	accessToken, expiresAt, err := h.tokenSvc.GenerateAccessToken(user.ID, user.DisplayName, user.Role, user.Tier)
	if err != nil {
		slog.Error("generate token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// ValidateAndConsume rotates the refresh token; the replacement must be
	// returned or the client is left holding a token that no longer exists.
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:        accessToken,
		RefreshToken:       newToken,
		TokenType:          "Bearer",
		ExpiresIn:          int(time.Until(expiresAt).Seconds()),
		UserID:             user.ID,
		DisplayName:        user.DisplayName,
		Role:               user.Role,
		Tier:               user.Tier,
		MustChangePassword: user.MustChangePassword,
	})
}

// HandleLogout revokes the presented refresh token. It is intentionally
// idempotent and does not require a valid access token.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.tokenStore.Revoke(r.Context(), req.RefreshToken); err != nil {
		slog.Error("revoke refresh token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *AuthHandler) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.tokenSvc.VerifyToken(tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	user, err := h.userStore.GetByID(r.Context(), claims.Subject)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":          user.ID,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"role":         user.Role,
		"tier":         user.Tier,
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeErrorCode is writeError plus a stable machine-readable code, so the
// portal can answer with localised wording instead of the English message.
func writeErrorCode(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}
