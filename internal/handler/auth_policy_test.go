package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/directory"
	"golang.org/x/crypto/bcrypt"
)

// The account-relationship policies the directory console exposes. Each test
// pins one decision the login path makes about a platform account, because
// getting one wrong is how a directory change reaches an account it must not.
//
// The stores are bus clients, so the account state a test needs arrives through
// the fake bus and the *effect* is asserted on it afterwards — which is what these
// tests are really about: did the login erase the dead password, suspend the
// departed account, follow the rename.

// Merging a directory identity into an existing account used to leave the old
// password hash in place. It is dead from that moment (a linked account only
// signs in through the directory), so it is erased rather than kept as a
// credential nothing checks.
func TestHandleToken_MergingErasesTheLocalPassword(t *testing.T) {
	localHash, _ := bcrypt.GenerateFromPassword([]byte("localpass"), bcrypt.DefaultCost)

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", string(localHash))

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if hash := stub.Account("u1")["password_hash"]; hash != "" {
		t.Fatalf("the dead local password was kept: %v", hash)
	}
	if _, ok := stub.Links("u1")["ldap|9f2c1a"]; !ok {
		t.Fatalf("the identity was not linked: %v", stub.Links("u1"))
	}
}

// linkPolicy=refuse leaves the account exactly as it was: no link, no password
// change, and an audit row saying the login was refused on purpose.
func TestHandleToken_LinkPolicyRefuseKeepsTheAccountsApart(t *testing.T) {
	cfg := enabledDirectoryConfig()
	cfg.LinkPolicy = directory.LinkPolicyRefuse

	dir := &fakeDirectory{entry: &directory.Entry{UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice"}}
	h, stub := setupDirectoryHandler(t, cfg, dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", "localhash")

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := responseCode(t, rec); got != "account_conflict" {
		t.Fatalf("code = %q, want account_conflict", got)
	}
	if len(stub.Links("u1")) != 0 {
		t.Fatalf("the identity was linked anyway: %v", stub.Links("u1"))
	}
	if hash := stub.Account("u1")["password_hash"]; hash != "localhash" {
		t.Fatalf("the account was touched: %v", hash)
	}
	// The refusal is recorded rather than silent.
	actions := []any{}
	for _, entry := range stub.Entries() {
		actions = append(actions, entry["action"])
	}
	if !containsAny(actions, "user.ldap.link_refused") {
		t.Fatalf("the refusal was not audited: %v", actions)
	}
}

// A departed employee: the entry is gone, so the platform account is suspended
// instead of being left active with nobody able to sign in.
func TestHandleToken_MissingEntrySuspendsTheLinkedAccount(t *testing.T) {
	cfg := enabledDirectoryConfig()
	cfg.DisableOnMissing = true

	dir := &fakeDirectory{err: directory.ErrEntryNotFound}
	h, stub := setupDirectoryHandler(t, cfg, dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "whatever")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := responseCode(t, rec); got != "account_disabled" {
		t.Fatalf("code = %q, want account_disabled", got)
	}
	if status := stub.Account("u1")["status"]; status != "suspended" {
		t.Fatalf("the departed account is still %v", status)
	}
}

// With the policy off, a vanished entry is a plain refusal again: no account is
// touched.
func TestHandleToken_MissingEntryWithoutThePolicyIsJustRefused(t *testing.T) {
	dir := &fakeDirectory{err: directory.ErrEntryNotFound}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "whatever")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if status := stub.Account("u1")["status"]; status != "active" {
		t.Fatalf("the account was suspended without the policy: %v", status)
	}
}

// syncDisplayName follows a rename in the directory into the platform name, and
// the issued token carries the new name.
func TestHandleToken_SyncsTheDisplayName(t *testing.T) {
	cfg := enabledDirectoryConfig()
	cfg.SyncDisplayName = true

	dir := &fakeDirectory{entry: &directory.Entry{
		UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice", DisplayName: "Alice Zhang (研发部)",
	}}
	h, stub := setupDirectoryHandler(t, cfg, dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice Zhang", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["display_name"] != "Alice Zhang (研发部)" {
		t.Fatalf("the token must carry the directory name, got %v", resp["display_name"])
	}
	if name := stub.Account("u1")["display_name"]; name != "Alice Zhang (研发部)" {
		t.Fatalf("the platform name was not refreshed: %v", name)
	}
}

// Without the policy the platform keeps its own name: no write, no surprise.
func TestHandleToken_KeepsThePlatformNameByDefault(t *testing.T) {
	dir := &fakeDirectory{entry: &directory.Entry{
		UniqueID: "9f2c1a", DN: "CN=Alice,DC=corp,DC=local", Username: "alice", DisplayName: "Alice Zhang (研发部)",
	}}
	h, stub := setupDirectoryHandler(t, enabledDirectoryConfig(), dir)
	stub.AddAccount("u1", "alice@corp.local", "Alice Zhang", "")
	stub.SetLinks("u1", map[string]string{"ldap|9f2c1a": "9f2c1a"})

	rec := postToken(t, h, "alice@corp.local", "alicepass")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["display_name"] != "Alice Zhang" {
		t.Fatalf("the platform name must be kept, got %v", resp["display_name"])
	}
	if name := stub.Account("u1")["display_name"]; name != "Alice Zhang" {
		t.Fatalf("the account was renamed without the policy: %v", name)
	}
}

func containsAny(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
