package store

// The account reads run against documents another module wrote. What has to hold
// is that this service reads the shape that is there — the identity and
// administration fields, the credential behind its own read, the links in their
// own collection — because the sign-in path now begins here.

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// seedUserDoc writes the shape the bus writes, so the reads are asserted against
// the writer's document rather than against a fixture this side invented.
func seedUserDoc(t *testing.T, s *Store, doc bson.D) {
	t.Helper()
	if _, err := s.DB().Collection("auth_users").InsertOne(t.Context(), doc); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func TestAccountReadsMatchTheDocumentShape(t *testing.T) {
	s := testStore(t)
	seedUserDoc(t, s, bson.D{
		{Key: "_id", Value: "u-1"}, {Key: "display_name", Value: "Ada"},
		{Key: "email", Value: "ada@example.test"}, {Key: "status", Value: "active"},
		{Key: "tier", Value: "pro"}, {Key: "role", Value: "admin"},
		{Key: "password_hash", Value: "bcrypt-hash"}, {Key: "must_change_password", Value: true},
		{Key: "preferred_language", Value: "en"},
	})

	byID, err := s.AccountByID("u-1")
	if err != nil {
		t.Fatalf("AccountByID: %v", err)
	}
	if byID == nil || byID.DisplayName != "Ada" || byID.Email != "ada@example.test" ||
		byID.Role != "admin" || byID.Tier != "pro" || byID.Status != "active" || !byID.MustChangePassword {
		t.Fatalf("unexpected account: %+v", byID)
	}

	byEmail, err := s.AccountByEmail("ada@example.test")
	if err != nil {
		t.Fatalf("AccountByEmail: %v", err)
	}
	if byEmail == nil || byEmail.ID != "u-1" {
		t.Fatalf("email lookup: %+v", byEmail)
	}
	// An address nobody holds is "no such account", not an error: the sign-in
	// flow answers the same way for both.
	if none, err := s.AccountByEmail("nobody@example.test"); err != nil || none != nil {
		t.Fatalf("unknown address: %+v (err %v)", none, err)
	}
	if none, err := s.AccountByID("ghost"); err != nil || none != nil {
		t.Fatalf("unknown id: %+v (err %v)", none, err)
	}

	hash, err := s.PasswordHash("u-1")
	if err != nil || hash != "bcrypt-hash" {
		t.Fatalf("password hash = %q (err %v)", hash, err)
	}
	// An account without a credential reads as empty, which is what the sign-in
	// flow checks before it compares anything.
	seedUserDoc(t, s, bson.D{{Key: "_id", Value: "u-2"}, {Key: "status", Value: "active"}})
	if hash, err := s.PasswordHash("u-2"); err != nil || hash != "" {
		t.Fatalf("passwordless account = %q (err %v)", hash, err)
	}
}

func TestAccountDefaultsAreComputedNotStored(t *testing.T) {
	s := testStore(t)
	// A document that carries no role, tier or status: the SQL had defaults, and
	// the reads have to answer with them.
	seedUserDoc(t, s, bson.D{{Key: "_id", Value: "u-3"}, {Key: "email", Value: "bare@example.test"}})

	record, err := s.AccountByID("u-3")
	if err != nil || record == nil {
		t.Fatalf("AccountByID: %+v (err %v)", record, err)
	}
	if record.Role != "user" || record.Tier != "free" || record.Status != "active" {
		t.Fatalf("defaults = %s/%s/%s, want user/free/active", record.Role, record.Tier, record.Status)
	}
}

func TestAccountByOAuthLink(t *testing.T) {
	s := testStore(t)
	seedUserDoc(t, s, bson.D{{Key: "_id", Value: "u-1"}, {Key: "status", Value: "active"}})
	if _, err := s.DB().Collection("auth_oauth_providers").InsertOne(t.Context(), bson.D{
		{Key: "user_id", Value: "u-1"}, {Key: "provider", Value: "ldap"}, {Key: "provider_id", Value: "cn=ada"},
	}); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	record, err := s.AccountByOAuthLink("ldap", "cn=ada")
	if err != nil {
		t.Fatalf("AccountByOAuthLink: %v", err)
	}
	if record == nil || record.ID != "u-1" {
		t.Fatalf("link lookup: %+v", record)
	}
	// An unlinked identity is "no account", not an error.
	if none, err := s.AccountByOAuthLink("ldap", "cn=bob"); err != nil || none != nil {
		t.Fatalf("unlinked identity: %+v (err %v)", none, err)
	}

	links, err := s.OAuthLinks("u-1")
	if err != nil {
		t.Fatalf("OAuthLinks: %v", err)
	}
	if len(links) != 1 || links[0].Provider != "ldap" || links[0].ProviderID != "cn=ada" {
		t.Fatalf("links: %+v", links)
	}
}

// TestUserStoreReadsFromTheDatabase: the sign-in path reads the identity
// database and nothing else — the bus is not wired into this store at all.
func TestUserStoreReadsFromTheDatabaseWhenItHasOne(t *testing.T) {
	s := testStore(t)
	seedUserDoc(t, s, bson.D{
		{Key: "_id", Value: "u-1"}, {Key: "status", Value: "active"},
		{Key: "email", Value: "ada@example.test"}, {Key: "password_hash", Value: "hash"},
	})
	if _, err := s.DB().Collection("auth_oauth_providers").InsertOne(t.Context(), bson.D{
		{Key: "user_id", Value: "u-1"}, {Key: "provider", Value: "ldap"}, {Key: "provider_id", Value: "cn=ada"},
	}); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	users := NewUserStore(s)
	ctx := t.Context()

	record, err := users.GetByEmail(ctx, "ada@example.test")
	if err != nil || record == nil || record.ID != "u-1" || record.PasswordHash != "hash" {
		t.Fatalf("GetByEmail: %+v (err %v)", record, err)
	}
	if record, err := users.GetByID(ctx, "u-1"); err != nil || record == nil || record.Email != "ada@example.test" {
		t.Fatalf("GetByID: %+v (err %v)", record, err)
	}
	if providerID, err := users.GetAuthProviderID(ctx, "u-1"); err != nil || providerID != "cn=ada" {
		t.Fatalf("GetAuthProviderID = %q (err %v)", providerID, err)
	}
	if record, err := users.GetByOAuthProvider(ctx, "ldap", "cn=ada"); err != nil || record == nil || record.ID != "u-1" {
		t.Fatalf("GetByOAuthProvider: %+v (err %v)", record, err)
	}
}
