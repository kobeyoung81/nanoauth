package store

import (
	"context"
	"errors"
	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"testing"
)

func TestNewUserStore(t *testing.T) {
	stub := bustest.New()
	if NewUserStore(stub.Client(t)) == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestGetByEmail_NotFound(t *testing.T) {
	stub := bustest.New()
	s := NewUserStore(stub.Client(t))

	user, err := s.GetByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestGetByEmail_Found(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "bcrypt-hash")
	s := NewUserStore(stub.Client(t))

	user, err := s.GetByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected a user")
	}
	// The credential comes from its own endpoint, so it has to be there too.
	if user.ID != "u-1" || user.Email != "test@example.com" || user.PasswordHash != "bcrypt-hash" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if user.Role != "user" || user.Status != "active" {
		t.Fatalf("defaults were not filled: %+v", user)
	}
}

func TestGetByID(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "hash")
	s := NewUserStore(stub.Client(t))

	user, err := s.GetByID(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.ID != "u-1" || user.PasswordHash != "hash" {
		t.Fatalf("unexpected user: %+v", user)
	}

	missing, err := s.GetByID(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected nil for an unknown id, got %+v", missing)
	}
}

func TestCreate(t *testing.T) {
	stub := bustest.New()
	s := NewUserStore(stub.Client(t))

	id, err := s.Create(context.Background(), "new@example.com", "hash", "New")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == "" {
		t.Fatal("expected an id")
	}
	account := stub.Account(id)
	if account == nil || account["email"] != "new@example.com" || account["password_hash"] != "hash" {
		t.Fatalf("the account did not arrive: %+v", account)
	}

	// A second account with the same address is the 409 the login flow recovers
	// from by linking instead.
	if _, err := s.Create(context.Background(), "new@example.com", "hash", "Other"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
}

// TestUpdatePasswordHash_KeepsTheFlag: the directory path blanks a local password
// and has no business deciding whether the next one must be changed.
func TestUpdatePasswordHash_KeepsTheFlag(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "old")
	account := stub.Account("u-1")
	account["must_change_password"] = true
	s := NewUserStore(stub.Client(t))

	if err := s.UpdatePasswordHash(context.Background(), "u-1", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	account = stub.Account("u-1")
	if account["password_hash"] != "" {
		t.Fatalf("the password was not blanked: %+v", account)
	}
	if account["must_change_password"] != true {
		t.Fatalf("the forced-change flag was reset: %+v", account)
	}

	// SetPassword, on the other hand, clears it: that is its whole meaning.
	if err := s.SetPassword(context.Background(), "u-1", "fresh"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	account = stub.Account("u-1")
	if account["password_hash"] != "fresh" || account["must_change_password"] != false {
		t.Fatalf("SetPassword did not set hash and clear the flag: %+v", account)
	}
}

func TestGetAuthProviderID(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "")
	stub.SetLinks("u-1", map[string]string{"ldap|cn=kobeyoung,ou=people": "cn=kobeyoung,ou=people"})
	s := NewUserStore(stub.Client(t))

	providerID, err := s.GetAuthProviderID(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if providerID != "cn=kobeyoung,ou=people" {
		t.Fatalf("provider id = %q", providerID)
	}
}

func TestGetAuthProviderID_NotLinked(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "hash")
	s := NewUserStore(stub.Client(t))

	providerID, err := s.GetAuthProviderID(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if providerID != "" {
		t.Fatalf("expected no link, got %q", providerID)
	}
}

func TestCreateWithLDAP(t *testing.T) {
	stub := bustest.New()
	s := NewUserStore(stub.Client(t))

	id, err := s.CreateWithLDAP(context.Background(), "cn=kobeyoung,ou=people", "kobe@corp.example.com", "Kobe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	account := stub.Account(id)
	if account == nil || account["email"] != "kobe@corp.example.com" {
		t.Fatalf("the account did not arrive: %+v", account)
	}
	// A directory account carries no local password.
	if account["password_hash"] != nil {
		t.Fatalf("a directory account got a password: %+v", account)
	}
	if _, ok := stub.Links(id)["ldap|cn=kobeyoung,ou=people"]; !ok {
		t.Fatalf("the identity was not linked: %+v", stub.Links(id))
	}
}

func TestCreateWithLDAP_DuplicateEmail(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "kobe@corp.example.com", "Kobe", "hash")
	s := NewUserStore(stub.Client(t))

	if _, err := s.CreateWithLDAP(context.Background(), "cn=kobeyoung", "kobe@corp.example.com", "Kobe"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
}

func TestGetByOAuthProvider(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "wechat:openid-9", "微信用户", "")
	stub.SetLinks("u-1", map[string]string{"wechat|openid-9": "openid-9"})
	s := NewUserStore(stub.Client(t))

	user, err := s.GetByOAuthProvider(context.Background(), "wechat", "openid-9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.ID != "u-1" {
		t.Fatalf("unexpected user: %+v", user)
	}

	if user, err = s.GetByOAuthProvider(context.Background(), "wechat", "openid-unknown"); err != nil || user != nil {
		t.Fatalf("an unknown identity must not resolve: user=%+v err=%v", user, err)
	}
}

func TestCreateWithOAuth(t *testing.T) {
	stub := bustest.New()
	s := NewUserStore(stub.Client(t))

	id, err := s.CreateWithOAuth(context.Background(), "wechat", "openid-9", "微信用户")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if account := stub.Account(id); account == nil {
		t.Fatalf("the account did not arrive: %+v", stub.AccountIDs())
	}
	if _, ok := stub.Links(id)["wechat|openid-9"]; !ok {
		t.Fatalf("the identity was not linked: %+v", stub.Links(id))
	}
}

func TestRecordAuthAudit(t *testing.T) {
	stub := bustest.New()
	s := NewUserStore(stub.Client(t))

	err := s.RecordAuthAudit(context.Background(), "user.login", "u-1", "user", "10.0.0.1", map[string]any{"method": "password"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entries := stub.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected one audit entry, got %+v", entries)
	}
	if entries[0]["action"] != "user.login" || entries[0]["actor_id"] != "u-1" || entries[0]["ip"] != "10.0.0.1" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}
	if detail, ok := entries[0]["detail"].(map[string]any); !ok || detail["method"] != "password" {
		t.Fatalf("the detail did not survive: %+v", entries[0])
	}
}

func TestLinkOAuth(t *testing.T) {
	stub := bustest.New()
	stub.AddAccount("u-1", "test@example.com", "Kobe", "")
	s := NewUserStore(stub.Client(t))

	if err := s.LinkOAuth(context.Background(), "u-1", "ldap", "cn=one"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Linking the same identity twice is one link, not two.
	if err := s.LinkOAuth(context.Background(), "u-1", "ldap", "cn=one"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stub.Links("u-1")) != 1 {
		t.Fatalf("expected one link, got %+v", stub.Links("u-1"))
	}
}
