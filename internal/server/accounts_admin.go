package server

// The internal account surface: the operations the platform's account entry points
// need. The bus still fronts the console's and the runtime's endpoints; what it
// fronts, it forwards here.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// accountJSON is one account as this surface reports it.
func accountJSON(record store.UserRecord) map[string]any {
	return map[string]any{
		"user_id":              record.ID,
		"display_name":         record.DisplayName,
		"email":                record.Email,
		"role":                 record.Role,
		"status":               record.Status,
		"tier":                 record.Tier,
		"must_change_password": record.MustChangePassword,
		"preferred_language":   record.PreferredLanguage,
		"updated_at":           record.UpdatedAt,
	}
}

func summaryJSON(sum store.UserSummary) map[string]any {
	return map[string]any{
		"user_id":              sum.ID,
		"display_name":         sum.DisplayName,
		"email":                sum.Email,
		"role":                 sum.Role,
		"status":               sum.Status,
		"tier":                 sum.Tier,
		"must_change_password": sum.MustChangePassword,
		"preferred_language":   sum.PreferredLanguage,
		"updated_at":           sum.UpdatedAt,
	}
}

// internalResolveAccount is onboarding: whose account is this platform identity, and
// create one if nobody's. A disabled channel is a 409 so the caller can tell the
// sender their channel was switched off rather than that something broke.
func (s *Server) internalResolveAccount(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		Channel  string `json:"channel"`
		SenderID string `json:"sender_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Channel == "" || body.SenderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "channel and sender_id are required"})
		return
	}
	resolved, err := s.accounts.ResolveUserBinding(body.Channel, body.SenderID)
	if errors.Is(err, store.ErrChannelDisabled) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "channel disabled"})
		return
	}
	if err != nil {
		slog.Error("resolve account", "channel", body.Channel, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":    resolved.UserID,
		"binding_id": resolved.BindingID,
		"is_new":     resolved.IsNew,
	})
}

// internalRegisterAccount creates an account (or refreshes its display name).
func (s *Server) internalRegisterAccount(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		UserID      string `json:"user_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}
	if err := s.accounts.RegisterUser(body.UserID, body.DisplayName); err != nil {
		slog.Error("register account", "user_id", body.UserID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "registered"})
}

// internalGetAccount answers one account, by id or (with ?email=) by address.
func (s *Server) internalGetAccount(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}
	record, err := s.accounts.AccountByID(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if record == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, accountJSON(*record))
}

// internalListAccounts serves both the console's page (limit / include_deleted)
// and its search box (q).
func (s *Server) internalListAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	includeDeleted := r.URL.Query().Get("include_deleted") == "1" || r.URL.Query().Get("include_deleted") == "true"

	if r.URL.Query().Get("ids_only") == "1" {
		ids, err := s.accounts.ListUsers()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user_ids": ids})
		return
	}
	if email := r.URL.Query().Get("email"); email != "" {
		record, err := s.accounts.AccountByEmail(email)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if record == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusOK, accountJSON(*record))
		return
	}
	if q := r.URL.Query().Get("q"); q != "" {
		sums, err := s.accounts.SearchUserSummaries(q, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accounts": summariesJSON(sums)})
		return
	}
	sums, err := s.accounts.ListUserSummaries(includeDeleted, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": summariesJSON(sums)})
}

func summariesJSON(sums []store.UserSummary) []map[string]any {
	out := make([]map[string]any, 0, len(sums))
	for _, sum := range sums {
		out = append(out, summaryJSON(sum))
	}
	return out
}

// internalPatchAccount applies the fields the request mentions: the console's forms
// each send one, and a zero value would otherwise erase a field nobody touched.
func (s *Server) internalPatchAccount(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	var body struct {
		Status            *string `json:"status"`
		Role              *string `json:"role"`
		Tier              *string `json:"tier"`
		DisplayName       *string `json:"display_name"`
		Email             *string `json:"email"`
		PreferredLanguage *string `json:"preferred_language"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	apply := func(err error) bool {
		if err == nil {
			return true
		}
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return false
		}
		slog.Error("patch account", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return false
	}
	if body.Status != nil {
		if !apply(s.accounts.UpdateUserStatus(userID, *body.Status)) {
			return
		}
	}
	if body.Role != nil {
		if !apply(s.accounts.SetUserRole(userID, *body.Role)) {
			return
		}
	}
	if body.Tier != nil {
		if !apply(s.accounts.SetUserTier(userID, *body.Tier)) {
			return
		}
	}
	if body.DisplayName != nil {
		if !apply(s.accounts.SetUserDisplayName(userID, *body.DisplayName)) {
			return
		}
	}
	if body.Email != nil {
		if !apply(s.accounts.SetUserEmail(userID, *body.Email)) {
			return
		}
	}
	if body.PreferredLanguage != nil {
		if !apply(s.accounts.SetUserPreferredLanguage(userID, *body.PreferredLanguage)) {
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "status": "updated"})
}

// internalPassword serves the credential: read for the sign-in flow's comparison,
// write for a password change.
func (s *Server) internalGetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	hash, err := s.accounts.UserPasswordHash(r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"password_hash": hash})
}

func (s *Server) internalSetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		PasswordHash string `json:"password_hash"`
		MustChange   bool   `json:"must_change_password"`
		KeepFlag     bool   `json:"keep_flag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	userID := r.PathValue("userID")
	var err error
	if body.KeepFlag {
		err = s.accounts.SetUserPasswordKeepingFlag(userID, body.PasswordHash)
	} else {
		err = s.accounts.SetUserPassword(userID, body.PasswordHash, body.MustChange)
	}
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		slog.Error("set password", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// internalBootstrapAdmin serves the one-shot claim (POST) and the roll-back a
// failed claim needs (DELETE).
func (s *Server) internalBootstrapAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	switch r.Method {
	case http.MethodPost:
		claimed, err := s.accounts.ClaimBootstrapAdmin(userID)
		if err != nil {
			slog.Error("claim bootstrap admin", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"claimed": claimed})
	case http.MethodDelete:
		if err := s.accounts.ReleaseBootstrapAdmin(userID); err != nil {
			slog.Error("release bootstrap admin", "user_id", userID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "released"})
	}
}

// internalChannels serves an account's channel names (GET) and one channel's
// enabled flag (PATCH).
func (s *Server) internalChannels(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	channels, err := s.accounts.UserChannels(userID)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

func (s *Server) internalSetChannel(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled is required"})
		return
	}
	userID := r.PathValue("userID")
	channel := r.PathValue("channel")
	var err error
	if *body.Enabled {
		err = s.accounts.EnableChannel(userID, channel)
	} else {
		err = s.accounts.DisableChannel(userID, channel)
	}
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		slog.Error("set channel", "user_id", userID, "channel", channel, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// internalAccountInfo is the runtime's question: is this account active, and which
// tier is it on.
func (s *Server) internalAccountInfo(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	status, level, err := s.accounts.GetUserInfo(r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "tier": level})
}

// internalAccountCounts is the console's overview: how many accounts, how many
// administrators, and how they split by tier.
func (s *Server) internalAccountCounts(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	active, err := s.accounts.CountActiveUsers()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	admins, err := s.accounts.CountActiveAdmins()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	tiers, err := s.accounts.CountUsersByTier()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "admins": admins, "tiers": tiers})
}

// internalUserExists answers the one question onboarding asks before it generates
// an id of its own.
func (s *Server) internalUserExists(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	exists, err := s.accounts.UserExists(r.PathValue("userID"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exists": exists})
}

// internalBindingOwner answers "whose binding id is this" for the provisioning path.
func (s *Server) internalBindingOwner(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	bindingID, err := strconv.ParseInt(r.PathValue("bindingID"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "binding id must be a number"})
		return
	}
	userID, err := s.accounts.UserIDForBinding(bindingID)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID})
}

// internalLinkChannel links one platform identity to an account. It is the console's
// "connect this person to a channel" action; onboarding creates its own link inside
// resolve.
func (s *Server) internalLinkChannel(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		Channel  string `json:"channel"`
		SenderID string `json:"sender_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Channel == "" || body.SenderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "channel and sender_id are required"})
		return
	}
	if err := s.accounts.LinkChannel(r.PathValue("userID"), body.Channel, body.SenderID); err != nil {
		slog.Error("link channel", "user_id", r.PathValue("userID"), "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "linked"})
}
