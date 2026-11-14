package server

// The two-level language setting over the internal surface: the account's own
// choice, and the platform default it inherits. The console reads this instead of
// asking the bus, so the composition (row + admin default) is pinned here.

import (
	"encoding/json"
	"net/http"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
)

// withAdmin attaches a fake admin module to the server, seeded with a platform
// language default ("" seeds nothing, which is what an unconfigured install has).
func withAdmin(t *testing.T, s *Server, platformLanguage string) *bustest.Bus {
	t.Helper()
	fake := bustest.New()
	if platformLanguage != "" {
		fake.SetConfig("agent", map[string]string{"agent.language.default": platformLanguage})
	}
	if s.accounts != nil {
		s.users = store.NewUserStore(s.accounts).WithAdmin(fake.Client(t))
	}
	return fake
}

func decodePreferences(t *testing.T, body []byte) (language, source string) {
	t.Helper()
	var out struct {
		Language string `json:"language"`
		Source   string `json:"source"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode preferences: %v (%s)", err, body)
	}
	return out.Language, out.Source
}

func TestInternalPreferencesInheritThePlatformDefault(t *testing.T) {
	s := testAccounts(t, "s3cret")
	withAdmin(t, s, "en")
	if err := s.accounts.RegisterUser("u-1", "One"); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/preferences", "s3cret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	language, source := decodePreferences(t, rec.Body.Bytes())
	if language != "en" || source != "platform" {
		t.Fatalf("expected the platform default, got %q/%q", language, source)
	}
}

func TestInternalPreferencesRoundTripAndClear(t *testing.T) {
	s := testAccounts(t, "s3cret")
	withAdmin(t, s, "en")
	if err := s.accounts.RegisterUser("u-1", "One"); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// A regional tag is stored as its primary subtag.
	rec := callInternal(t, s, http.MethodPut, "/internal/v1/users/u-1/preferences", "s3cret", `{"language":"ja-JP"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	language, source := decodePreferences(t, rec.Body.Bytes())
	if language != "ja" || source != "user" {
		t.Fatalf("expected ja/user, got %q/%q", language, source)
	}

	rec = callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/preferences", "s3cret", "")
	language, source = decodePreferences(t, rec.Body.Bytes())
	if language != "ja" || source != "user" {
		t.Fatalf("the choice must survive a read, got %q/%q", language, source)
	}

	// Clearing goes back to the platform default, and the answer says so.
	rec = callInternal(t, s, http.MethodPut, "/internal/v1/users/u-1/preferences", "s3cret", `{"language":""}`)
	language, source = decodePreferences(t, rec.Body.Bytes())
	if language != "en" || source != "platform" {
		t.Fatalf("expected the platform default after clearing, got %q/%q", language, source)
	}
}

func TestInternalPreferencesRejectAnUnsupportedLanguage(t *testing.T) {
	s := testAccounts(t, "s3cret")
	withAdmin(t, s, "zh")
	if err := s.accounts.RegisterUser("u-1", "One"); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	rec := callInternal(t, s, http.MethodPut, "/internal/v1/users/u-1/preferences", "s3cret", `{"language":"klingon"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestInternalPreferencesUnknownAccountIs404(t *testing.T) {
	s := testAccounts(t, "s3cret")
	withAdmin(t, s, "zh")

	rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/nobody/preferences", "s3cret", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d %s", rec.Code, rec.Body.String())
	}
}

// Without the admin module attached the default is empty, not an error: the row
// is still readable, which is what matters when the console loads the page.
func TestInternalPreferencesWithoutTheAdminModule(t *testing.T) {
	s := testAccounts(t, "s3cret")
	if err := s.accounts.RegisterUser("u-1", "One"); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/preferences", "s3cret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	language, source := decodePreferences(t, rec.Body.Bytes())
	if language != "" || source != "platform" {
		t.Fatalf("expected an empty platform default, got %q/%q", language, source)
	}
}

// The guard is the whole authentication on this surface.
func TestInternalPreferencesRequireTheToken(t *testing.T) {
	s := testAccounts(t, "s3cret")
	withAdmin(t, s, "zh")
	if err := s.accounts.RegisterUser("u-1", "One"); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	rec := callInternal(t, s, http.MethodGet, "/internal/v1/users/u-1/preferences", "wrong", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
