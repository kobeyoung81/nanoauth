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
