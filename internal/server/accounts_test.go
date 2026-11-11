package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/config"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/migrations"
)

// testAccounts builds a server over a throwaway database. Without a URI the test
// skips rather than pretend to pass.
func testAccounts(t *testing.T, token string) *Server {
	t.Helper()
	uri := os.Getenv("NANOAUTH_TEST_URI")
	if uri == "" {
		uri = os.Getenv("NANOSEC_ADMIN_TEST_URI")
	}
	if uri == "" {
		t.Skip("NANOAUTH_TEST_URI / NANOSEC_ADMIN_TEST_URI not set")
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	u.Path = "/nanoauth_test_" + hex.EncodeToString(b[:])

	st, err := store.Open(u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.DB().Drop(t.Context())
		_ = st.Close()
	})
	manifests, err := migrations.Load()
	if err != nil {
		t.Fatalf("load manifests: %v", err)
	}
	if _, err := st.Migrate(manifests); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	s := &Server{cfg: config.AuthConfig{BusToken: token}, accounts: st}
	return s
}

// callInternal runs one guarded call through a mux, so the path values the
// handlers read are the ones a router would set.
func callInternal(t *testing.T, s *Server, method, target, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /internal/v1/users/{userID}/git-shortcuts", s.internalGuard(s.internalListGitShortcuts))
	mux.Handle("POST /internal/v1/users/{userID}/git-shortcuts", s.internalGuard(s.internalSaveGitShortcut))
	mux.Handle("DELETE /internal/v1/users/{userID}/git-shortcuts/{id}", s.internalGuard(s.internalDeleteGitShortcut))
	mux.Handle("GET /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalListSecrets))
	mux.Handle("PUT /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalSetSecret))
	mux.Handle("DELETE /internal/v1/users/{userID}/secrets/{kind}/{ref}", s.internalGuard(s.internalDeleteSecret))
	mux.Handle("GET /internal/v1/users/{userID}/oauth-links", s.internalGuard(s.internalListOAuthLinks))
	mux.Handle("POST /internal/v1/users/{userID}/oauth-links/{provider}", s.internalGuard(s.internalLinkOAuth))
	mux.Handle("DELETE /internal/v1/users/{userID}/oauth-links/{provider}", s.internalGuard(s.internalUnlinkOAuth))
	mux.Handle("GET /internal/v1/oauth-links", s.internalGuard(s.internalListOAuthLinksByProvider))
	mux.Handle("POST /internal/v1/accounts/resolve", s.internalGuard(s.internalResolveAccount))
	mux.Handle("POST /internal/v1/accounts", s.internalGuard(s.internalRegisterAccount))
	mux.Handle("GET /internal/v1/accounts", s.internalGuard(s.internalListAccounts))
	mux.Handle("GET /internal/v1/accounts/counts", s.internalGuard(s.internalAccountCounts))
	mux.Handle("GET /internal/v1/accounts/{userID}", s.internalGuard(s.internalGetAccount))
	mux.Handle("PATCH /internal/v1/accounts/{userID}", s.internalGuard(s.internalPatchAccount))
	mux.Handle("GET /internal/v1/accounts/{userID}/password", s.internalGuard(s.internalGetPassword))
	mux.Handle("PUT /internal/v1/accounts/{userID}/password", s.internalGuard(s.internalSetPassword))
	mux.Handle("POST /internal/v1/accounts/{userID}/bootstrap-admin", s.internalGuard(s.internalBootstrapAdmin))
	mux.Handle("DELETE /internal/v1/accounts/{userID}/bootstrap-admin", s.internalGuard(s.internalBootstrapAdmin))
	mux.Handle("GET /internal/v1/accounts/{userID}/channels", s.internalGuard(s.internalChannels))
	mux.Handle("PATCH /internal/v1/accounts/{userID}/channels/{channel}", s.internalGuard(s.internalSetChannel))
	mux.Handle("GET /internal/v1/accounts/{userID}/info", s.internalGuard(s.internalAccountInfo))
	mux.Handle("GET /internal/v1/accounts/{userID}/exists", s.internalGuard(s.internalUserExists))
	mux.Handle("GET /internal/v1/bindings/{bindingID}/account", s.internalGuard(s.internalBindingOwner))

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestInternalEndpointsRequireTheSharedToken: the surface is the platform's, so a
// caller without the token hears nothing; an unconfigured token refuses rather
// than serving it open.
func TestInternalEndpointsRequireTheSharedToken(t *testing.T) {
	s := testAccounts(t, "s3cret")

	if rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/git-shortcuts", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a token", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/git-shortcuts", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a wrong token", rec.Code)
	}

	// No token configured is a deployment mistake: refuse, do not serve.
	unconfigured := &Server{cfg: config.AuthConfig{}, accounts: s.accounts}
	if rec := callInternal(t, unconfigured, http.MethodGet, "/internal/v1/users/u-1/git-shortcuts", "anything", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 without a configured token", rec.Code)
	}
}

// TestInternalGitShortcutsRoundTrip is the console's path end to end: star a
// path, see it, re-label it in place, delete it.
func TestInternalGitShortcutsRoundTrip(t *testing.T) {
	s := testAccounts(t, "s3cret")

	rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/git-shortcuts", "s3cret",
		`{"agent_id":"agent-1","path":"src/main.go","label":"main"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("star: %d %s", rec.Code, rec.Body.String())
	}
	var first struct {
		ID    int64  `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.ID == 0 || first.Label != "main" {
		t.Fatalf("unexpected star: %+v", first)
	}

	// Re-starring relabels the same row: one entry, same id.
	rec = callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/git-shortcuts", "s3cret",
		`{"agent_id":"agent-1","path":"src/main.go","label":"entry"}`)
	var second struct {
		ID    int64  `json:"id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if second.ID != first.ID || second.Label != "entry" {
		t.Fatalf("re-starring did not relabel in place: %+v", second)
	}

	rec = callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/git-shortcuts?agent_id=agent-1", "s3cret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Shortcuts []struct {
			ID    int64  `json:"id"`
			Path  string `json:"path"`
			Label string `json:"label"`
		} `json:"shortcuts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Shortcuts) != 1 || listed.Shortcuts[0].Label != "entry" {
		t.Fatalf("unexpected list: %+v", listed.Shortcuts)
	}

	rec = callInternal(t, s, http.MethodDelete, "/internal/v1/users/u-1/git-shortcuts/"+itoa(first.ID), "s3cret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	// Deleting it again is a 404, which keeps the console's message honest.
	if rec = callInternal(t, s, http.MethodDelete, "/internal/v1/users/u-1/git-shortcuts/"+itoa(first.ID), "s3cret", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d, want 404", rec.Code)
	}
}

// TestInternalGitShortcutRejectsABadCall: the fields are required, and a path id
// that is not a number is the caller's mistake.
func TestInternalGitShortcutRejectsABadCall(t *testing.T) {
	s := testAccounts(t, "s3cret")

	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/git-shortcuts", "s3cret", `{"agent_id":"a","path":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing path", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/git-shortcuts", "s3cret", `not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a malformed body", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodDelete, "/internal/v1/users/u-1/git-shortcuts/abc", "s3cret", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-numeric id", rec.Code)
	}
}

// TestInternalEndpointsReportAnUnconfiguredStore: no database is "unavailable",
// not "empty" — the console must not show an empty list as if it were the truth.
func TestInternalEndpointsReportAnUnconfiguredStore(t *testing.T) {
	s := &Server{cfg: config.AuthConfig{BusToken: "s3cret"}}
	if rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/git-shortcuts", "s3cret", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// TestInternalSecretsRoundTrip is the console's path end to end: store a value,
// read it back, replace it in place, remove it. The values come back unmasked
// because masking is the console's own step.
func TestInternalSecretsRoundTrip(t *testing.T) {
	s := testAccounts(t, "s3cret")
	base := "/internal/v1/users/u-1/secrets/mcp/mcp:github"

	if rec := callInternal(t, s, http.MethodPut, base, "s3cret", `{"key":"TOKEN","value":"sk-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("store: %d %s", rec.Code, rec.Body.String())
	}
	if rec := callInternal(t, s, http.MethodPut, base, "s3cret", `{"key":"TOKEN","value":"sk-2"}`); rec.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body.String())
	}

	rec := callInternal(t, s, http.MethodGet, base, "s3cret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Secrets) != 1 || listed.Secrets["TOKEN"] != "sk-2" {
		t.Fatalf("the value was not replaced in place: %+v", listed.Secrets)
	}

	// Another user, and another capability, see nothing.
	if rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-2/secrets/mcp/mcp:github", "s3cret", ""); rec.Code != http.StatusOK {
		t.Fatalf("other user: %d", rec.Code)
	} else {
		var other struct {
			Secrets map[string]string `json:"secrets"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &other)
		if len(other.Secrets) != 0 {
			t.Fatalf("another user saw secrets: %+v", other.Secrets)
		}
	}

	if rec := callInternal(t, s, http.MethodDelete, base+"?key=TOKEN", "s3cret", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	rec = callInternal(t, s, http.MethodGet, base, "s3cret", "")
	var after struct {
		Secrets map[string]string `json:"secrets"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	if len(after.Secrets) != 0 {
		t.Fatalf("the secret survived: %+v", after.Secrets)
	}
}

// TestInternalSecretsRejectABadCall: the value is the point, and a delete needs to
// say which key.
func TestInternalSecretsRejectABadCall(t *testing.T) {
	s := testAccounts(t, "s3cret")
	base := "/internal/v1/users/u-1/secrets/mcp/mcp:github"

	if rec := callInternal(t, s, http.MethodPut, base, "s3cret", `{"key":"TOKEN"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing value", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodDelete, base, "s3cret", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing key", rec.Code)
	}
	// The same guard as the rest of the surface.
	if rec := callInternal(t, s, http.MethodGet, base, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a token", rec.Code)
	}
}

// TestInternalOAuthLinksRoundTrip is the console's directory page and the sign-in
// flow's question: link an identity, read it back two ways, unlink it.
func TestInternalOAuthLinksRoundTrip(t *testing.T) {
	s := testAccounts(t, "s3cret")

	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/oauth-links/ldap", "s3cret",
		`{"provider_id":"cn=ada"}`); rec.Code != http.StatusOK {
		t.Fatalf("link: %d %s", rec.Code, rec.Body.String())
	}
	// Re-linking the same identity is idempotent (one identity, one account).
	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/oauth-links/ldap", "s3cret",
		`{"provider_id":"cn=ada"}`); rec.Code != http.StatusOK {
		t.Fatalf("relink: %d %s", rec.Code, rec.Body.String())
	}

	rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/oauth-links", "s3cret", "")
	var byUser struct {
		Links []struct {
			Provider   string `json:"provider"`
			ProviderID string `json:"provider_id"`
		} `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &byUser); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(byUser.Links) != 1 || byUser.Links[0].ProviderID != "cn=ada" {
		t.Fatalf("links by user: %+v", byUser.Links)
	}

	rec = callInternal(t, s, http.MethodGet, "/internal/v1/oauth-links?provider=ldap", "s3cret", "")
	var byProvider struct {
		Links []struct {
			UserID string `json:"user_id"`
		} `json:"links"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &byProvider); err != nil {
		t.Fatalf("decode roster: %v", err)
	}
	if len(byProvider.Links) != 1 || byProvider.Links[0].UserID != "u-1" {
		t.Fatalf("roster: %+v", byProvider.Links)
	}

	if rec := callInternal(t, s, http.MethodDelete, "/internal/v1/users/u-1/oauth-links/ldap", "s3cret", ""); rec.Code != http.StatusOK {
		t.Fatalf("unlink: %d %s", rec.Code, rec.Body.String())
	}
	rec = callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/oauth-links", "s3cret", "")
	_ = json.Unmarshal(rec.Body.Bytes(), &byUser)
	if len(byUser.Links) != 0 {
		t.Fatalf("the link survived: %+v", byUser.Links)
	}

	// A link without a provider identity is the caller's mistake.
	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/users/u-1/oauth-links/ldap", "s3cret", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestInternalAccountSurface is the console's user page end to end: register, read,
// patch the fields each form sends, set and read the credential, count, and the
// onboarding path that creates a pending account from a channel identity.
func TestInternalAccountSurface(t *testing.T) {
	s := testAccounts(t, "s3cret")
	ctx := t.Context()

	// Onboarding: a channel identity nobody owns becomes a pending account.
	rec := callInternal(t, s, http.MethodPost, "/internal/v1/accounts/resolve", "s3cret",
		`{"channel":"web","sender_id":"sender-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
	}
	var resolved struct {
		UserID    string `json:"user_id"`
		BindingID int64  `json:"binding_id"`
		IsNew     bool   `json:"is_new"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resolved); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resolved.IsNew || resolved.UserID == "" || resolved.BindingID == 0 {
		t.Fatalf("unexpected onboarding answer: %+v", resolved)
	}
	// The same identity resolves to the same account, not a second one.
	rec = callInternal(t, s, http.MethodPost, "/internal/v1/accounts/resolve", "s3cret",
		`{"channel":"web","sender_id":"sender-1"}`)
	var again struct {
		UserID string `json:"user_id"`
		IsNew  bool   `json:"is_new"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &again)
	if again.IsNew || again.UserID != resolved.UserID {
		t.Fatalf("the identity was not stable: %+v after %+v", again, resolved)
	}

	// The console's own registration, then the fields its forms send.
	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/accounts", "s3cret",
		`{"user_id":"u-1","display_name":"Ada"}`); rec.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	if rec := callInternal(t, s, http.MethodPatch, "/internal/v1/accounts/u-1", "s3cret",
		`{"role":"admin","tier":"pro","status":"active","preferred_language":"en","email":"ada@example.test"}`); rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	rec = callInternal(t, s, http.MethodGet, "/internal/v1/accounts/u-1", "s3cret", "")
	var account map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &account); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if account["role"] != "admin" || account["tier"] != "pro" || account["display_name"] != "Ada" || account["preferred_language"] != "en" {
		t.Fatalf("the patch did not stick: %+v", account)
	}

	// The credential: written by a reset, read back only for the comparison.
	if rec := callInternal(t, s, http.MethodPut, "/internal/v1/accounts/u-1/password", "s3cret",
		`{"password_hash":"hash-1","must_change_password":true}`); rec.Code != http.StatusOK {
		t.Fatalf("password: %d %s", rec.Code, rec.Body.String())
	}
	rec = callInternal(t, s, http.MethodGet, "/internal/v1/accounts/u-1/password", "s3cret", "")
	var password struct {
		Hash string `json:"password_hash"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &password)
	if password.Hash != "hash-1" {
		t.Fatalf("password hash = %q", password.Hash)
	}

	// Channels, and the "does this account exist" the console asks before creating.
	rec = callInternal(t, s, http.MethodGet, "/internal/v1/accounts/"+resolved.UserID+"/channels", "s3cret", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web") {
		t.Fatalf("channels: %d %s", rec.Code, rec.Body.String())
	}
	if rec := callInternal(t, s, http.MethodPatch, "/internal/v1/accounts/"+resolved.UserID+"/channels/web", "s3cret", `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("disable channel: %d %s", rec.Code, rec.Body.String())
	}
	rec = callInternal(t, s, http.MethodPost, "/internal/v1/accounts/resolve", "s3cret",
		`{"channel":"web","sender_id":"sender-1"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("a disabled channel resolved: %d %s", rec.Code, rec.Body.String())
	}

	rec = callInternal(t, s, http.MethodGet, "/internal/v1/accounts/counts", "s3cret", "")
	var counts struct {
		Active int            `json:"active"`
		Admins int            `json:"admins"`
		Tiers  map[string]int `json:"tiers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &counts)
	if counts.Admins != 1 || counts.Tiers["pro"] != 1 {
		t.Fatalf("counts: %+v", counts)
	}

	_ = ctx
}

// TestInternalAccountSurfaceRejectsBadCalls: the fields are the point, and a
// missing account is a 404 the console can show as such.
func TestInternalAccountSurfaceRejectsBadCalls(t *testing.T) {
	s := testAccounts(t, "s3cret")

	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/accounts", "s3cret", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 without a user id", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodPost, "/internal/v1/accounts/resolve", "s3cret", `{"channel":"web"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 without a sender", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodPatch, "/internal/v1/accounts/ghost", "s3cret", `{"role":"admin"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a missing account", rec.Code)
	}
	if rec := callInternal(t, s, http.MethodGet, "/internal/v1/bindings/abc/account", "s3cret", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-numeric binding id", rec.Code)
	}
}
