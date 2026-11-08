package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"golang.org/x/crypto/bcrypt"
)

// The directory login: what the handler decides for each answer the directory can
// give, and what it does to the platform account behind the email.
//
// The stores are bus clients now, so each test seeds the fake bus with the account
// it needs and asserts the outcome — the HTTP status and the effect on the
// account — rather than SQL statements.

type fakeDirectory struct {
	entry        *directory.Entry
	err          error
	calls        int
	lastEmail    string
	lastPassword string
}

func (f *fakeDirectory) Authenticate(_ context.Context, _ *directory.Config, email, password string) (*directory.Entry, error) {
	f.calls++
	f.lastEmail, f.lastPassword = email, password
	if f.err != nil {
		return nil, f.err
	}
	return f.entry, nil
}

type fakeConfigSource struct {
	cfg *directory.Config
	err error
}

func (f *fakeConfigSource) Load(context.Context) (*directory.Config, error) { return f.cfg, f.err }

func enabledDirectoryConfig() *directory.Config {
	return &directory.Config{Enabled: true, AutoProvision: true, BaseDN: "dc=corp,dc=local"}
}

// setupDirectoryHandler wires a handler whose directory always answers the same
// way, so each test only spells out the account state it needs.
func setupDirectoryHandler(t *testing.T, cfg *directory.Config, dir directory.Directory) (*AuthHandler, *bustest.Bus) {
	t.Helper()
	h, _, stub := setupHandler(t)
	h.WithDirectory(dir, &fakeConfigSource{cfg: cfg})
	return h, stub
}

func postToken(t *testing.T, h *AuthHandler, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleToken(rec, req)
	return rec
}

func responseCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return ""
	}
	code, _ := body["code"].(string)
	return code
}

// A first directory login provisions the account, links the directory identity
// and records the binding.
func TestHandleToken_DirectoryFirstLoginProvisions(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{
		UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice", DisplayName: "Alice Zhang",
	}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)

	rec := postToken(t, h, "Alice@Corp.Local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	userID, _ := resp["user_id"].(string)
	if userID == "" {
		t.Fatal("expected a user id")
	}
	if resp["role"] != "user" {
		t.Fatalf("expected role user, got %v", resp["role"])
	}
	if dir.lastEmail != "alice@corp.local" || dir.lastPassword != "alicepass" {
		t.Fatalf("directory got %q/%q", dir.lastEmail, dir.lastPassword)
	}
	account := stub.Account(userID)
	if account == nil || account["email"] != "alice@corp.local" {
		t.Fatalf("the account was not provisioned: %v", account)
	}
	if _, ok := stub.Links(userID)["ldap|9f2c1a"]; !ok {
		t.Fatalf("the identity was not linked: %v", stub.Links(userID))
	}
}

// The second login must find the existing link instead of provisioning again.
func TestHandleToken_DirectorySecondLoginReusesTheAccount(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice Zhang", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["user_id"] != "u1" {
		t.Fatalf("expected the existing account, got %v", resp["user_id"])
	}
	if len(stub.AccountIDs()) != 1 {
		t.Fatalf("a second account was created: %v", stub.AccountIDs())
	}
}

// A local account whose email exists in the directory is linked on the first
// directory login.
func TestHandleToken_DirectoryMergesIntoALocalAccount(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", string(localHash))

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := stub.Links("u1")["ldap|9f2c1a"]; !ok {
		t.Fatalf("the identity was not linked: %v", stub.Links("u1"))
	}
	// The local password is dead once the account is directory-managed.
	if hash := stub.Account("u1")["password_hash"]; hash != "" {
		t.Fatalf("the stale local password was kept: %v", hash)
	}
}

// A linked account never falls back to its (stale) local password.
func TestHandleToken_DirectoryAccountIgnoresTheLocalPassword(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{err: directory.ErrInvalidCredentials}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", string(localHash))
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	// The local password would verify if it were consulted; it must not be.
	rec := postToken(t, h, "alice@corp.local", "localpass")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// An unlinked local account keeps working while the directory is down.
func TestHandleToken_LocalAccountSurvivesAnUnreachableDirectory(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{err: directory.ErrUnavailable}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "bob@corp.local", "Bob", string(localHash))

	rec := postToken(t, h, "bob@corp.local", "localpass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// The ordinary case once the directory is on: an account that exists only in the
// platform keeps signing in with its local password.
func TestHandleToken_LocalAccountNotInTheDirectoryUsesItsPassword(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{err: directory.ErrEntryNotFound}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "local@example.com", "Local", string(localHash))

	rec := postToken(t, h, "local@example.com", "localpass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Without an account to fall back to, an unreachable directory is reported as
// such instead of looking like a wrong password.
func TestHandleToken_UnknownAccountWithUnreachableDirectoryIs503(t *testing.T) {
	dir := &fakeDirectory{err: directory.ErrUnavailable}
	h, _ := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)

	rec := postToken(t, h, "nobody@corp.local", "whatever")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToken_DirectorySuspendedAccountIsForbidden(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", "")
	stub.SetAccountField("u1", "status", "suspended")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToken_DirectoryEntryNotFoundForAnUnknownEmail(t *testing.T) {
	dir := &fakeDirectory{err: directory.ErrEntryNotFound}
	h, _ := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)

	rec := postToken(t, h, "nobody@corp.local", "whatever")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A changed unique id means the entry behind the email has a new owner: the link
// is not silently moved.
func TestHandleToken_DirectoryUniqueIDMismatchIsRefused(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "new-id", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a mismatched identity must be refused, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := stub.Links("u1")["ldap|new-id"]; ok {
		t.Fatal("the link was moved to a different identity")
	}
}

func TestHandleToken_DirectoryAmbiguousEmailIsRefused(t *testing.T) {
	dir := &fakeDirectory{err: directory.ErrMultipleEntries}
	h, _ := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusConflict && rec.Code != http.StatusUnauthorized {
		t.Fatalf("an ambiguous entry must not log anybody in: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToken_DirectoryProvisioningDisabled(t *testing.T) {
	cfg := enabledDirectoryConfig()
	cfg.AutoProvision = false

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, cfg, dir)

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(stub.AccountIDs()) != 0 {
		t.Fatalf("an account was provisioned anyway: %v", stub.AccountIDs())
	}
}

// A privileged account keeps its local password: the directory must not be able
// to reach the admin console, so no bind is even attempted.
func TestHandleToken_PrivilegedAccountSkipsTheDirectory(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Admin,DC=corp,DC=local", Username: "admin"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "admin@corp.local", "Admin", string(localHash))
	stub.SetAccountField("u1", "role", "admin")

	rec := postToken(t, h, "admin@corp.local", "localpass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if dir.calls != 0 {
		t.Fatalf("the directory was consulted for a privileged account (%d calls)", dir.calls)
	}
}

// A privileged account whose local password is wrong is simply refused, and it is
// never linked to the directory identity.
func TestHandleToken_PrivilegedAccountIsNeverLinked(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Admin,DC=corp,DC=local", Username: "admin"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "admin@corp.local", "Admin", string(localHash))
	stub.SetAccountField("u1", "role", "admin")

	rec := postToken(t, h, "admin@corp.local", "wrongpass")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(stub.Links("u1")) != 0 {
		t.Fatalf("a privileged account was linked: %v", stub.Links("u1"))
	}
}

// An empty password must not reach the directory: LDAP treats an empty-password
// bind as an anonymous bind, which succeeds.
func TestHandleToken_EmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, _ := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)

	rec := postToken(t, h, "alice@corp.local", "")
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected a refusal, got %d: %s", rec.Code, rec.Body.String())
	}
	if dir.calls != 0 {
		t.Fatalf("an empty password reached the directory (%d calls)", dir.calls)
	}
}

// A registration racing the provisioning insert is retried as a link.
func TestHandleToken_DirectoryProvisionRaceLinksInstead(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	// The account is already there under the same email: the provision attempt
	// answers 409 and the flow links instead of failing.
	stub.AddAccount("u1", "alice@corp.local", "Alice", "")

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := stub.Links("u1")["ldap|9f2c1a"]; !ok {
		t.Fatalf("the identity was not linked to the existing account: %v", stub.Links("u1"))
	}
}

// With the feature switched off the handler behaves exactly as before.
func TestHandleToken_DirectoryDisabledKeepsThePasswordPath(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{err: directory.ErrUnavailable}
	h, stub := setupDirectoryHandler(t, &directory.Config{Enabled: false}, dir)
	stub.AddAccount("u1", "bob@corp.local", "Bob", string(localHash))

	rec := postToken(t, h, "bob@corp.local", "localpass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if dir.calls != 0 {
		t.Fatalf("the directory was consulted while disabled (%d calls)", dir.calls)
	}
}

// A failing configuration read is reported instead of silently refusing.
func TestHandleToken_DirectoryConfigFailureIs503(t *testing.T) {
	h, _, _ := setupHandler(t)
	h.WithDirectory(&fakeDirectory{}, &fakeConfigSource{err: directory.ErrUnavailable})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}
