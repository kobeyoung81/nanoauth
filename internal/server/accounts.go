package server

// The internal account surface.
//
// Accounts are this service's, and the bus still fronts the endpoints the console
// and the runtime call. What it fronts, it forwards here; the shared token is the
// whole authentication — the module trust domain is the platform's, not a user's.

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// internalGuard requires the platform's shared token. An unconfigured token
// refuses every request rather than serving the surface unauthenticated.
func (s *Server) internalGuard(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.BusToken == "" {
			slog.Error("nanoauth: internal endpoints have no token configured and are refusing requests",
				"hint", "set NANOSEC_BUS_INTERNAL_TOKEN")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication is not configured"})
			return
		}
		token := r.Header.Get("Authorization")
		const prefix = "bearer "
		if len(token) < len(prefix) || !strings.EqualFold(token[:len(prefix)], prefix) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token[len(prefix):])), []byte(s.cfg.BusToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	})
}

// accountsReady reports whether the account store is usable. A deployment without
// a database URI is reported as unavailable rather than as an empty answer.
func (s *Server) accountsReady(w http.ResponseWriter) bool {
	if s.accounts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the account store is not configured"})
		return false
	}
	return true
}

// gitShortcutJSON is one starred path, in the shape the console reads.
func gitShortcutJSON(shortcut store.GitShortcut) map[string]any {
	return map[string]any{
		"id":       shortcut.ID,
		"user_id":  shortcut.UserID,
		"agent_id": shortcut.AgentID,
		"path":     shortcut.Path,
		"label":    shortcut.Label,
	}
}

func (s *Server) internalListGitShortcuts(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	shortcuts, err := s.accounts.GitShortcuts(userID, r.URL.Query().Get("agent_id"))
	if err != nil {
		slog.Error("list git shortcuts", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	out := make([]map[string]any, 0, len(shortcuts))
	for _, shortcut := range shortcuts {
		out = append(out, gitShortcutJSON(shortcut))
	}
	writeJSON(w, http.StatusOK, map[string]any{"shortcuts": out})
}

func (s *Server) internalSaveGitShortcut(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	var body struct {
		AgentID string `json:"agent_id"`
		Path    string `json:"path"`
		Label   string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	shortcut, err := s.accounts.SaveGitShortcut(userID, body.AgentID, body.Path, body.Label)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, gitShortcutJSON(shortcut))
}

func (s *Server) internalDeleteGitShortcut(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a number"})
		return
	}
	if err := s.accounts.DeleteGitShortcut(userID, id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ======== per-user capability secrets ========

// internalListSecrets answers with the values themselves: masking is the console's
// job, and this face is only reachable with the platform token.
func (s *Server) internalListSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	secrets, err := s.accounts.ListUserSecrets(r.PathValue("userID"), r.PathValue("kind"), r.PathValue("ref"))
	if err != nil {
		slog.Error("list user secrets", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
}

func (s *Server) internalSetSecret(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Key == "" || body.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key and value are required"})
		return
	}
	if err := s.accounts.UpsertUserSecret(r.PathValue("userID"), r.PathValue("kind"), r.PathValue("ref"), body.Key, body.Value); err != nil {
		slog.Error("set user secret", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) internalDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key is required"})
		return
	}
	if err := s.accounts.DeleteUserSecret(r.PathValue("userID"), r.PathValue("kind"), r.PathValue("ref"), key); err != nil {
		slog.Error("delete user secret", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ======== identity links ========

func (s *Server) internalListOAuthLinks(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	links, err := s.accounts.OAuthLinks(r.PathValue("userID"))
	if err != nil {
		slog.Error("list oauth links", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": linkPayloads(links)})
}

func (s *Server) internalListOAuthLinksByProvider(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	links, err := s.accounts.OAuthProviderLinks(r.URL.Query().Get("provider"))
	if err != nil {
		slog.Error("list oauth links by provider", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": linkPayloads(links)})
}

func (s *Server) internalLinkOAuth(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.ProviderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider_id is required"})
		return
	}
	if err := s.accounts.LinkOAuth(r.PathValue("userID"), r.PathValue("provider"), body.ProviderID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "linked"})
}

func (s *Server) internalUnlinkOAuth(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	if err := s.accounts.UnlinkOAuth(r.PathValue("userID"), r.PathValue("provider")); err != nil {
		slog.Error("unlink oauth", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "unlinked"})
}

func linkPayloads(links []store.OAuthLink) []map[string]string {
	out := make([]map[string]string, 0, len(links))
	for _, link := range links {
		out = append(out, map[string]string{
			"user_id": link.UserID, "provider": link.Provider, "provider_id": link.ProviderID,
		})
	}
	return out
}
