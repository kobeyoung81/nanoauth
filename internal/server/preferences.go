package server

// The account's language, over the internal surface.
//
// Two levels, one answer: the account may set a language, otherwise it inherits
// the platform default the admin module seeds. The console used to ask the bus for
// this composition — the bus read the account through its own client and the
// default through its admin client, which made a two-hop for one string. Both
// halves are reachable here: the row is this service's and the default comes from
// this service's admin client.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// internalGetPreferences returns the effective language and where it came from.
func (s *Server) internalGetPreferences(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	prefs, err := s.users.Preferences(r.Context(), userID)
	if errors.Is(err, store.ErrUserNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err != nil {
		slog.Error("get preferences", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}

// internalSetPreferences stores the account's choice; an empty value clears it so
// the account inherits the platform default again. The answer is the effective
// value, which is what the console shows right after a save.
func (s *Server) internalSetPreferences(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReady(w) {
		return
	}
	userID := r.PathValue("userID")
	var body struct {
		Language string `json:"language"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	prefs, err := s.users.SetPreferences(r.Context(), userID, body.Language)
	if errors.Is(err, store.ErrUnsupportedLanguage) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported language"})
		return
	}
	if errors.Is(err, store.ErrUserNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err != nil {
		slog.Error("set preferences", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, prefs)
}
