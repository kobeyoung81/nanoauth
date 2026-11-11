package store

// The per-user credentials a capability needs: one row per (user, kind, ref, key),
// replaced in place on a second write, scoped so another user or another
// capability never sees them.

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestUserSecrets_RoundTrip(t *testing.T) {
	s := testStore(t)

	for _, kv := range []struct{ key, value string }{
		{"API_KEY", "sk-1"}, {"TOKEN", "t-1"},
	} {
		if err := s.UpsertUserSecret("u-1", "skill", "skill:a", kv.key, kv.value); err != nil {
			t.Fatalf("UpsertUserSecret: %v", err)
		}
	}
	// Replacing a value keeps one row.
	if err := s.UpsertUserSecret("u-1", "skill", "skill:a", "API_KEY", "sk-2"); err != nil {
		t.Fatalf("UpsertUserSecret: %v", err)
	}

	secrets, err := s.ListUserSecrets("u-1", "skill", "skill:a")
	if err != nil {
		t.Fatalf("ListUserSecrets: %v", err)
	}
	if len(secrets) != 2 || secrets["API_KEY"] != "sk-2" || secrets["TOKEN"] != "t-1" {
		t.Fatalf("unexpected secrets: %+v", secrets)
	}
	// Scoped by user, kind and ref.
	if other, err := s.ListUserSecrets("u-2", "skill", "skill:a"); err != nil || len(other) != 0 {
		t.Fatalf("another user's secrets leaked: %+v (err %v)", other, err)
	}
	if other, err := s.ListUserSecrets("u-1", "mcp", "skill:a"); err != nil || len(other) != 0 {
		t.Fatalf("another kind's secrets leaked: %+v (err %v)", other, err)
	}

	if err := s.DeleteUserSecret("u-1", "skill", "skill:a", "API_KEY"); err != nil {
		t.Fatalf("DeleteUserSecret: %v", err)
	}
	if secrets, err = s.ListUserSecrets("u-1", "skill", "skill:a"); err != nil || len(secrets) != 1 {
		t.Fatalf("unexpected secrets after delete: %+v (err %v)", secrets, err)
	}
}

// TestUserSecret_IdentityIsUnique pins the four-field unique index a secret's
// identity rests on: two upserts of the same secret must end as one row.
func TestUserSecret_IdentityIsUnique(t *testing.T) {
	s := testStore(t)

	for i := 0; i < 3; i++ {
		if err := s.UpsertUserSecret("u-1", "mcp", "mcp:a", "TOKEN", "v"); err != nil {
			t.Fatalf("UpsertUserSecret: %v", err)
		}
	}
	n, err := s.DB().Collection("auth_secrets").CountDocuments(context.Background(), bson.D{})
	if err != nil {
		t.Fatalf("count secrets: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected one document, got %d", n)
	}
}
