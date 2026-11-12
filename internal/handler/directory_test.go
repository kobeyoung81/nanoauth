package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/accounttest"
	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"gitee.com/kobeyoung81/nanoauth/internal/middleware"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

// fakeConsole answers every console operation from a canned result, so the
// handler's own behaviour is what the tests observe.
type fakeConsole struct {
	probe    *directory.ProbeResult
	check    *directory.CheckResult
	checkErr error
	browse   *directory.BrowseResult
	analyze  *directory.AnalyzeResult

	calls        []string
	lastEmail    string
	lastPassword string
}

func (f *fakeConsole) Probe(context.Context, *directory.Config) *directory.ProbeResult {
	f.calls = append(f.calls, "probe")
	return f.probe
}

func (f *fakeConsole) Browse(context.Context, *directory.Config, string, int) (*directory.BrowseResult, error) {
	f.calls = append(f.calls, "browse")
	return f.browse, nil
}

func (f *fakeConsole) Analyze(context.Context, *directory.Config, string, int) (*directory.AnalyzeResult, error) {
	f.calls = append(f.calls, "analyze")
	return f.analyze, nil
}

func (f *fakeConsole) Search(context.Context, *directory.Config, string, string, int) (*directory.BrowseResult, error) {
	f.calls = append(f.calls, "search")
	return f.browse, nil
}

func (f *fakeConsole) CheckEntry(_ context.Context, _ *directory.Config, email, password string) (*directory.CheckResult, error) {
	f.calls = append(f.calls, "check")
	f.lastEmail, f.lastPassword = email, password
	return f.check, f.checkErr
}

// assertReadOnly fails the test on any call that would change a user, an
// identity binding or a queue: the dry run may read and record its own audit row,
// and nothing else. The fake bus logs every request, so the check sees the
// methods and paths a real call would use.
func assertReadOnly(t *testing.T, stub *bustest.Bus) {
	t.Helper()
	for _, call := range stub.Requests() {
		if strings.HasPrefix(call, "GET ") {
			continue
		}
		// The trail is a report, not a change; the admin module owns it now.
		if call == "POST /api/v1/audit" || call == "POST /api/v1/internal/audit" {
			continue
		}
		t.Errorf("the console must not write: %s", call)
	}
}

func newDirectoryHandler(t *testing.T, console directory.Console, cfg *directory.Config) (*DirectoryHandler, *bustest.Bus) {
	t.Helper()
	stub := bustest.New()
	handler := NewDirectoryHandler(console, &fakeConfigSource{cfg: cfg},
		store.NewUserStore(accounttest.New(stub)).WithAdmin(stub.Client(t)))
	return handler, stub
}

// postConsole drives a console handler behind the middleware chain, so the
// recorded actor is the one a real call would carry.
func postConsole(t *testing.T, h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken(t))
	rec := httptest.NewRecorder()
	middleware.AuthMiddleware(consoleTokenService(t))(http.HandlerFunc(h)).ServeHTTP(rec, req)
	return rec
}

const consoleActorID = "admin-1"

var consoleTokenOnce struct {
	service *token.TokenService
}

func consoleTokenService(t *testing.T) *token.TokenService {
	t.Helper()
	if consoleTokenOnce.service != nil {
		return consoleTokenOnce.service
	}
	privPEM, pubPEM, err := token.GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := token.NewTokenService("test-kid", "test", 3600, privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	consoleTokenOnce.service = svc
	return svc
}

func adminToken(t *testing.T) string {
	t.Helper()
	value, _, err := consoleTokenService(t).GenerateAccessToken(consoleActorID, "Admin", "admin", "free")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func settingsBody(draft map[string]any, extra map[string]any) map[string]any {
	settings := map[string]any{
		"enabled": true, "url": "ldap://dir.corp.local", "timeout_seconds": 10,
		"base_dn": "dc=corp,dc=local", "user_filter": "(&(objectClass=person)(mail=%s))",
		"attr_unique_id": "entryUUID", "attr_username": "uid", "bind_dn": "cn=admin,dc=corp,dc=local",
		"bind_password": "adminpassword", "link_policy": "auto", "auto_provision": true,
	}
	for key, value := range draft {
		settings[key] = value
	}
	body := map[string]any{"settings": settings}
	for key, value := range extra {
		body[key] = value
	}
	return body
}

// The bind password is the one setting the console never reads back: the page
// gets it from the config API it already has access to, and the service reports
// only whether a value is stored.
func TestHandleEffective_NeverReturnsTheBindPassword(t *testing.T) {
	console := &fakeConsole{}
	cfg := enabledDirectoryConfig()
	cfg.BindPassword = "adminpassword"
	h, _ := newDirectoryHandler(t, console, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/directory/effective", nil)
	rec := httptest.NewRecorder()
	h.HandleEffective(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "adminpassword") {
		t.Fatalf("the response leaks the bind password: %s", rec.Body.String())
	}
	var body struct {
		Configured bool `json:"configured"`
		Settings   struct {
			BindPasswordIsSet bool `json:"bind_password_set"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Configured || !body.Settings.BindPasswordIsSet {
		t.Fatalf("expected a configured directory with a stored password: %s", rec.Body.String())
	}
}

func TestHandleValidate_ReportsFieldErrors(t *testing.T) {
	h, _ := newDirectoryHandler(t, &fakeConsole{}, enabledDirectoryConfig())

	rec := postConsole(t, h.HandleValidate, "/auth/v1/directory/validate",
		settingsBody(map[string]any{"user_filter": "(objectClass=person)"}, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Valid  bool `json:"valid"`
		Errors map[string]struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Valid {
		t.Fatal("a filter without the placeholder must not validate")
	}
	if body.Errors["ldap.userFilter"].Code != "filter_missing_placeholder" {
		t.Fatalf("unexpected errors %+v", body.Errors)
	}
}

// The dry run reads the platform account to say what would happen, and writes
// nothing but its own audit row.
func TestHandleCheck_DryRunReadsOnlyAndSaysWhatWouldHappen(t *testing.T) {
	console := &fakeConsole{check: &directory.CheckResult{
		Filter: "(&(objectClass=person)(mail=alice@corp.local))", MatchCount: 1,
		DN: "uid=alice,dc=corp,dc=local", Username: "alice", DisplayName: "Alice Zhang",
		UniqueID: "9f2c1a", UniqueIDSource: directory.UniqueIDSourceAttribute,
		BindAttempted: true, Bound: true,
	}}
	h, stub := newDirectoryHandler(t, console, enabledDirectoryConfig())

	rec := postConsole(t, h.HandleCheck, "/auth/v1/directory/check",
		settingsBody(nil, map[string]any{"email": "Alice@Corp.Local", "password": "alicepass"}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Outcome         string `json:"outcome"`
		AccountNotLocal bool   `json:"account_not_local"`
		Filter          string `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Outcome != "provision" {
		t.Fatalf("outcome = %q, want provision", body.Outcome)
	}
	if !body.AccountNotLocal {
		t.Fatal("expected the verdict to say there is no platform account yet")
	}
	if console.lastEmail != "alice@corp.local" {
		t.Fatalf("the email must reach the directory lowercased, got %q", console.lastEmail)
	}
	if console.lastPassword != "alicepass" {
		t.Fatalf("the password must reach the directory, got %q", console.lastPassword)
	}
	assertReadOnly(t, stub)
}

func TestCheckOutcome_MirrorsTheLoginBranches(t *testing.T) {
	active := &store.UserRecord{ID: "u1", Role: roleUser, Status: "active"}
	privileged := &store.UserRecord{ID: "u2", Role: "admin", Status: "active"}
	suspended := &store.UserRecord{ID: "u3", Role: roleUser, Status: "suspended"}
	matched := &directory.CheckResult{UniqueID: "9f2c1a"}

	for _, tc := range []struct {
		name     string
		cfg      *directory.Config
		local    *store.UserRecord
		linkedID string
		result   *directory.CheckResult
		err      error
		want     string
	}{
		{"unreachable", enabledDirectoryConfig(), nil, "", matched, directory.ErrUnavailable, "directory_unavailable"},
		{"privileged", enabledDirectoryConfig(), privileged, "", matched, nil, "refuse_privileged"},
		{"no entry, local account", enabledDirectoryConfig(), active, "", matched, directory.ErrEntryNotFound, "local_password"},
		{"no entry, no account", enabledDirectoryConfig(), nil, "", matched, directory.ErrEntryNotFound, "no_directory_entry"},
		{"ambiguous", enabledDirectoryConfig(), nil, "", matched, directory.ErrMultipleEntries, "refuse_ambiguous"},
		{"wrong password", enabledDirectoryConfig(), active, "9f2c1a", matched, directory.ErrInvalidCredentials, "wrong_password"},
		{"linked and active", enabledDirectoryConfig(), active, "9f2c1a", matched, nil, "sign_in"},
		{"linked but suspended", enabledDirectoryConfig(), suspended, "9f2c1a", matched, nil, "refuse_status"},
		{"linked id moved", enabledDirectoryConfig(), active, "other", matched, nil, "refuse_id_mismatch"},
		{"merge", enabledDirectoryConfig(), active, "", matched, nil, "link"},
		{"merge refused", &directory.Config{Enabled: true, AutoProvision: true, LinkPolicy: directory.LinkPolicyRefuse}, active, "", matched, nil, "refuse_policy"},
		{"provision", enabledDirectoryConfig(), nil, "", matched, nil, "provision"},
		{"provision off", &directory.Config{Enabled: true, LinkPolicy: directory.LinkPolicyAuto}, nil, "", matched, nil, "refuse_not_provisioned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkOutcome(tc.cfg, tc.local, tc.linkedID, tc.result, tc.err)
			if got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

// A console call with no stored settings at all answers "not configured" rather
// than failing, which is what a first visit to the page looks like.
func TestHandleEffective_SaysWhenNothingIsConfigured(t *testing.T) {
	h, _ := newDirectoryHandler(t, &fakeConsole{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/directory/effective", nil)
	rec := httptest.NewRecorder()
	h.HandleEffective(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Fatalf("expected an unconfigured answer, got %s", rec.Body.String())
	}
}
