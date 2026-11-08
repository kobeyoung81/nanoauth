package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"gitee.com/kobeyoung81/nanoauth/internal/middleware"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// Stable codes for the console's outcomes; the portal renders its own wording.
const (
	codeDirectoryNotConfigured = "directory_not_configured"
	codeInvalidRequest         = "invalid_request"
)

// DirectoryHandler serves the portal's directory login console: the settings in
// force, their validation, and four read-only diagnostics (connection probe,
// tree browse, attribute analysis, login dry run).
//
// It never writes. The settings themselves are edited through the bus config
// API (service_config_items, component auth), which the portal already proxies;
// keeping the write path single is what keeps the console and the config center
// in step. Nothing here creates an account, links an identity or writes to the
// directory.
type DirectoryHandler struct {
	console directory.Console
	source  directory.ConfigSource
	users   *store.UserStore
}

func NewDirectoryHandler(console directory.Console, source directory.ConfigSource, users *store.UserStore) *DirectoryHandler {
	return &DirectoryHandler{console: console, source: source, users: users}
}

// cacheStamper is implemented by the settings loader; the console shows when the
// running configuration was read so an edit's effect is observable.
type cacheStamper interface {
	CachedAt() (time.Time, bool)
}

// directorySettingsPayload mirrors the ldap.* keys with typed fields.
type directorySettingsPayload struct {
	Enabled           bool   `json:"enabled"`
	URL               string `json:"url"`
	StartTLS          bool   `json:"start_tls"`
	TLSSkipVerify     bool   `json:"tls_insecure_skip_verify"`
	CACertPEM         string `json:"ca_cert_pem"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	BaseDN            string `json:"base_dn"`
	UserFilter        string `json:"user_filter"`
	RequiredGroupDN   string `json:"required_group_dn"`
	GroupMatchInChain bool   `json:"group_match_in_chain"`
	BindDN            string `json:"bind_dn"`
	BindPassword      string `json:"bind_password"`
	AttrUniqueID      string `json:"attr_unique_id"`
	AttrUsername      string `json:"attr_username"`
	AttrDisplayName   string `json:"attr_display_name"`
	AutoProvision     bool   `json:"auto_provision"`
	LinkPolicy        string `json:"link_policy"`
	DisableOnMissing  bool   `json:"disable_on_missing"`
	SyncDisplayName   bool   `json:"sync_display_name"`
	BindPasswordIsSet bool   `json:"bind_password_set"`
}

// directoryOpRequest is the body of every diagnostic call: a draft
// configuration plus the parameters of the one operation being asked for.
type directoryOpRequest struct {
	Settings         *directorySettingsPayload `json:"settings"`
	UseSavedPassword bool                      `json:"use_saved_password"`
	BaseDN           string                    `json:"base_dn"`
	Filter           string                    `json:"filter"`
	Limit            int                       `json:"limit"`
	SampleCap        int                       `json:"sample_cap"`
	Email            string                    `json:"email"`
	Password         string                    `json:"password"`
}

// DirectoryCheckResponse is the login dry run plus the verdict the portal shows.
type DirectoryCheckResponse struct {
	Check           *directory.CheckResult `json:"check"`
	Outcome         string                 `json:"outcome"`
	Filter          string                 `json:"filter"`
	ExistingAccount *existingAccount       `json:"existing_account,omitempty"`
	AccountNotLocal bool                   `json:"account_not_local"`
}

type existingAccount struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	Linked      bool   `json:"linked"`
}

// HandleEffective reports the settings currently in force (never the bind
// password) and when they were read.
func (h *DirectoryHandler) HandleEffective(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.source.Load(r.Context())
	if err != nil {
		slog.Error("load directory config", "error", err)
		writeErrorCode(w, http.StatusServiceUnavailable, "directory unavailable", codeDirectoryUnavailable)
		return
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}

	response := map[string]any{
		"configured": true,
		"settings":   payloadFrom(cfg),
	}
	if stamper, ok := h.source.(cacheStamper); ok {
		if at, warm := stamper.CachedAt(); warm {
			response["loaded_at"] = at.UTC().Format(time.RFC3339)
		}
	}
	writeJSON(w, http.StatusOK, response)
}

// HandleValidate answers with the field-level problems of a draft, which is
// what lets the console refuse a setting that would silently break logins.
func (h *DirectoryHandler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	problems := directory.Validate(cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":  len(problems) == 0,
		"errors": problems,
	})
}

// HandleTest runs the five-step connection probe.
func (h *DirectoryHandler) HandleTest(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	result := h.console.Probe(r.Context(), cfg)
	h.recordAudit(r, "directory.test", map[string]any{"url": cfg.URL, "base_dn": cfg.BaseDN, "ok": result.OK})
	writeJSON(w, http.StatusOK, result)
}

// HandleBrowse lists one level of the directory tree.
func (h *DirectoryHandler) HandleBrowse(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	result, err := h.console.Browse(r.Context(), cfg, req.BaseDN, req.Limit)
	if err != nil {
		writeDirectoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// HandleAnalyze samples a search base and reports the settings it suggests.
func (h *DirectoryHandler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	result, err := h.console.Analyze(r.Context(), cfg, req.BaseDN, req.SampleCap)
	if err != nil {
		writeDirectoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// HandleSearch runs an operator-supplied filter under a base. The group picker
// uses it to find the group sign-ins should be restricted to, and it doubles as
// a "show me these entries" tool while a directory is being set up.
func (h *DirectoryHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	result, err := h.console.Search(r.Context(), cfg, req.BaseDN, req.Filter, req.Limit)
	if err != nil {
		writeDirectoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// HandleCheck dry-runs one login and reports what the real login would do. It
// reads users and oauth_providers to answer that; it writes nothing.
func (h *DirectoryHandler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	var req directoryOpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid request body", codeInvalidRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		writeErrorCode(w, http.StatusBadRequest, "email is required", codeInvalidRequest)
		return
	}
	cfg, err := h.resolve(r, &req)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeDirectoryNotConfigured)
		return
	}

	result, dirErr := h.console.CheckEntry(r.Context(), cfg, email, req.Password)
	if result == nil {
		result = &directory.CheckResult{}
	}

	local, err := h.users.GetByEmail(r.Context(), email)
	if err != nil {
		slog.Error("lookup user for the directory check", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	linkedID := ""
	if local != nil {
		linkedID, err = h.users.GetAuthProviderID(r.Context(), local.ID)
		if err != nil {
			slog.Error("lookup directory link for the check", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	response := &DirectoryCheckResponse{
		Check:           result,
		Filter:          result.Filter,
		Outcome:         checkOutcome(cfg, local, linkedID, result, dirErr),
		AccountNotLocal: local == nil,
	}
	if local != nil {
		response.ExistingAccount = &existingAccount{
			UserID:      local.ID,
			Email:       local.Email,
			DisplayName: local.DisplayName,
			Role:        local.Role,
			Status:      local.Status,
			Linked:      linkedID != "",
		}
	}

	h.recordAudit(r, "directory.check", map[string]any{"email": email, "outcome": response.Outcome})
	writeJSON(w, http.StatusOK, response)
}

// checkOutcome mirrors the branches of loginViaDirectory, so the console tells
// the operator exactly what the login path would decide.
func checkOutcome(cfg *directory.Config, local *store.UserRecord, linkedID string, result *directory.CheckResult, err error) string {
	if errors.Is(err, directory.ErrUnavailable) {
		return "directory_unavailable"
	}
	if local != nil && local.Role != roleUser && linkedID == "" {
		// A privileged account is never offered to the directory.
		return "refuse_privileged"
	}
	switch {
	case errors.Is(err, directory.ErrEntryNotFound):
		if local != nil && linkedID == "" {
			return "local_password"
		}
		return "no_directory_entry"
	case errors.Is(err, directory.ErrMultipleEntries):
		return "refuse_ambiguous"
	case errors.Is(err, directory.ErrInvalidCredentials):
		if local == nil || linkedID != "" {
			return "wrong_password"
		}
		return "wrong_password_local_fallback"
	}

	switch {
	case linkedID != "":
		if result.UniqueID != linkedID {
			return "refuse_id_mismatch"
		}
		if local.Status != "active" {
			return "refuse_status"
		}
		return "sign_in"
	case local != nil:
		if cfg != nil && cfg.LinkPolicy == directory.LinkPolicyRefuse {
			return "refuse_policy"
		}
		return "link"
	}
	if cfg != nil && !cfg.AutoProvision {
		return "refuse_not_provisioned"
	}
	return "provision"
}

// resolve answers which configuration an operation should run against: the
// draft in the request when there is one (so settings can be tested before they
// are saved), otherwise the settings in force.
func (h *DirectoryHandler) resolve(r *http.Request, req *directoryOpRequest) (*directory.Config, error) {
	if req.Settings != nil {
		cfg := req.Settings.toConfig()
		if cfg.BindPassword == "" && req.UseSavedPassword {
			saved, err := h.source.Load(r.Context())
			if err != nil {
				return nil, err
			}
			if saved != nil {
				cfg.BindPassword = saved.BindPassword
			}
		}
		return cfg, nil
	}

	cfg, err := h.source.Load(r.Context())
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, errors.New("directory login is not configured yet")
	}
	return cfg, nil
}

// recordAudit writes the console's calls to the shared audit log. A failure to
// record must never fail the operation it describes.
func (h *DirectoryHandler) recordAudit(r *http.Request, action string, detail map[string]any) {
	if h.users == nil {
		return
	}
	actorID, actorRole := "", ""
	if claims := middleware.GetClaims(r.Context()); claims != nil {
		actorID, actorRole = claims.Subject, claims.Role
	}
	if err := h.users.RecordAuthAudit(r.Context(), action, actorID, actorRole, clientIP(r), detail); err != nil {
		slog.Error("record directory audit", "action", action, "error", err)
	}
}

// writeDirectoryError maps the directory sentinels onto responses.
func writeDirectoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, directory.ErrUnavailable):
		writeErrorCode(w, http.StatusServiceUnavailable, "directory unavailable", codeDirectoryUnavailable)
	case errors.Is(err, directory.ErrEntryNotFound):
		writeErrorCode(w, http.StatusNotFound, "no directory entry matched", "directory_entry_not_found")
	case errors.Is(err, directory.ErrMultipleEntries):
		writeErrorCode(w, http.StatusConflict, "the search matched several entries", "directory_multiple_entries")
	case errors.Is(err, directory.ErrInvalidFilter):
		writeErrorCode(w, http.StatusBadRequest, "the search filter could not be parsed", "directory_invalid_filter")
	default:
		writeErrorCode(w, http.StatusBadRequest, err.Error(), codeInvalidRequest)
	}
}

func (p *directorySettingsPayload) toConfig() *directory.Config {
	return &directory.Config{
		Enabled:            p.Enabled,
		URL:                strings.TrimSpace(p.URL),
		StartTLS:           p.StartTLS,
		InsecureSkipVerify: p.TLSSkipVerify,
		CACertPEM:          p.CACertPEM,
		Timeout:            time.Duration(positiveOr(p.TimeoutSeconds, 10)) * time.Second,
		BaseDN:             strings.TrimSpace(p.BaseDN),
		UserFilter:         strings.TrimSpace(p.UserFilter),
		RequiredGroupDN:    strings.TrimSpace(p.RequiredGroupDN),
		GroupMatchInChain:  p.GroupMatchInChain,
		BindDN:             strings.TrimSpace(p.BindDN),
		BindPassword:       p.BindPassword,
		AttrUniqueID:       strings.TrimSpace(p.AttrUniqueID),
		AttrUsername:       strings.TrimSpace(p.AttrUsername),
		AttrDisplayName:    strings.TrimSpace(p.AttrDisplayName),
		AutoProvision:      p.AutoProvision,
		LinkPolicy:         linkPolicyOr(p.LinkPolicy, directory.LinkPolicyAuto),
		DisableOnMissing:   p.DisableOnMissing,
		SyncDisplayName:    p.SyncDisplayName,
	}
}

// payloadFrom renders the settings in force for the console. The bind password
// is never returned: the console reads that one value from the config API it
// already has read access to, and reports only whether a value is stored.
func payloadFrom(cfg *directory.Config) directorySettingsPayload {
	payload := directorySettingsPayload{
		Enabled:           cfg.Enabled,
		URL:               cfg.URL,
		StartTLS:          cfg.StartTLS,
		TLSSkipVerify:     cfg.InsecureSkipVerify,
		CACertPEM:         cfg.CACertPEM,
		TimeoutSeconds:    int(cfg.Timeout.Seconds()),
		BaseDN:            cfg.BaseDN,
		UserFilter:        cfg.UserFilter,
		RequiredGroupDN:   cfg.RequiredGroupDN,
		GroupMatchInChain: cfg.GroupMatchInChain,
		BindDN:            cfg.BindDN,
		AttrUniqueID:      cfg.AttrUniqueID,
		AttrUsername:      cfg.AttrUsername,
		AttrDisplayName:   cfg.AttrDisplayName,
		AutoProvision:     cfg.AutoProvision,
		LinkPolicy:        cfg.LinkPolicy,
		DisableOnMissing:  cfg.DisableOnMissing,
		SyncDisplayName:   cfg.SyncDisplayName,
		BindPasswordIsSet: cfg.BindPassword != "",
	}
	return payload
}

func positiveOr(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func linkPolicyOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
