package store

// nanoauth's collections live in the platform database, which another module's
// connection created. These tests pin the two things that keeps true as the
// owners change: the manifests declare the indexes the collections already have
// (so a fresh installation gets them and an existing one is unchanged), and the
// migration records carry this service's name so they cannot be mistaken for
// another module's.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"gitee.com/kobeyoung81/nanoauth/migrations"
)

// testStore opens a throwaway database and applies this service's manifests, the
// way a deployment does — the indexes are part of what the domain tests rely on
// (a duplicate star collapses because of one).
func testStore(t *testing.T) *Store {
	t.Helper()
	st := rawStore(t)
	if ran := migrateAll(t, st); len(ran) == 0 {
		t.Fatal("the test database was not migrated")
	}
	return st
}

// rawStore opens a throwaway database without applying anything, for the
// migration tests themselves.
func rawStore(t *testing.T) *Store {
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

	st, err := Open(u.String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.DB().Drop(context.Background())
		_ = st.Close()
	})
	return st
}

func migrateAll(t *testing.T, st *Store) []string {
	t.Helper()
	manifests, err := migrations.Load()
	if err != nil {
		t.Fatalf("load manifests: %v", err)
	}
	ran, err := st.Migrate(manifests)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return ran
}

func TestMigrationsAreRecordedUnderThisService(t *testing.T) {
	st := rawStore(t)
	if ran := migrateAll(t, st); len(ran) != 3 {
		t.Fatalf("first run applied %d manifests, want 3: %v", len(ran), ran)
	}

	// Second run converges: nothing is pending.
	if ran := migrateAll(t, st); len(ran) != 0 {
		t.Fatalf("second run applied %v, want nothing", ran)
	}

	var record struct {
		ID      string `bson:"_id"`
		Service string `bson:"service"`
	}
	if err := st.DB().Collection("sys_migrations").FindOne(context.Background(),
		bson.D{{Key: "_id", Value: "auth:0001_users.json"}}).Decode(&record); err != nil {
		t.Fatalf("read migration record: %v", err)
	}
	if record.Service != "auth" {
		t.Fatalf("migration recorded under service %q, want auth", record.Service)
	}
}

// TestMigrations_DeclareAccountIndexes pins the identity constraints: these were
// SQL primary keys and uniques, and they are what makes an account, a channel
// link or an OAuth identity unique.
func TestMigrations_DeclareAccountIndexes(t *testing.T) {
	st := testStore(t)
	db := st.DB()

	// A user's channel identity is its primary key on user_channels, and it is
	// what makes a racing onboarding fail atomically.
	assertIndexKeys(t, db.Collection("auth_users"), "channel_identity_unique", [][2]any{
		{"channels.channel", int32(1)}, {"channels.sender_id", int32(1)},
	})
	// The binding id was UNIQUE on its own table; container requests quote it.
	assertIndexKeys(t, db.Collection("auth_users"), "binding_id_unique", [][2]any{
		{"channels.binding_id", int32(1)},
	})
	assertIndexKeys(t, db.Collection("auth_users"), "email_unique", [][2]any{{"email", int32(1)}})
	// Uniqueness itself, not just the key order: these are the constraints.
	assertIndexUnique(t, db.Collection("auth_users"), "channel_identity_unique")
	assertIndexUnique(t, db.Collection("auth_users"), "binding_id_unique")

	assertIndexUnique(t, db.Collection("auth_oauth_providers"), "provider_identity_unique")
	assertIndexKeys(t, db.Collection("auth_oauth_providers"), "user_provider", [][2]any{
		{"user_id", int32(1)}, {"provider", int32(1)},
	})
	assertIndexUnique(t, db.Collection("auth_git_shortcuts"), "path_unique")
	assertIndexKeys(t, db.Collection("auth_refresh_tokens"), "user_tokens", [][2]any{
		{"user_id", int32(1)},
	})
	assertIndexKeys(t, db.Collection("auth_refresh_tokens"), "expires_at", [][2]any{
		{"expires_at", int32(1)},
	})
	assertIndexUnique(t, db.Collection("auth_secrets"), "identity_unique")
}

// assertIndexKeys checks that one named index exists with exactly the given key
// order. Decoded into a concrete type rather than bson.M: how the driver
// represents a nested document is its business, and asserting on that would make
// this fail for the wrong reason.
func assertIndexKeys(t *testing.T, coll *mongo.Collection, name string, want [][2]any) {
	t.Helper()

	cur, err := coll.Indexes().List(context.Background())
	if err != nil {
		t.Fatalf("list indexes on %s: %v", coll.Name(), err)
	}
	type indexDoc struct {
		Name string `bson:"name"`
		Key  bson.D `bson:"key"`
	}

	for cur.Next(context.Background()) {
		var doc indexDoc
		if err := cur.Decode(&doc); err != nil {
			t.Fatalf("decode index: %v", err)
		}
		if doc.Name != name {
			continue
		}
		if len(doc.Key) != len(want) {
			t.Fatalf("index %s has %d keys, want %d: %+v", name, len(doc.Key), len(want), doc.Key)
		}
		for i, pair := range want {
			if doc.Key[i].Key != pair[0] || doc.Key[i].Value != pair[1] {
				t.Fatalf("index %s key %d = %v %v, want %v %v",
					name, i, doc.Key[i].Key, doc.Key[i].Value, pair[0], pair[1])
			}
		}
		return
	}
	t.Fatalf("index %s is missing from the applied manifests on %s", name, coll.Name())
}

// assertIndexUnique checks that one named index is unique.
func assertIndexUnique(t *testing.T, coll *mongo.Collection, name string) {
	t.Helper()

	cur, err := coll.Indexes().List(context.Background())
	if err != nil {
		t.Fatalf("list indexes on %s: %v", coll.Name(), err)
	}
	type indexDoc struct {
		Name   string `bson:"name"`
		Unique bool   `bson:"unique"`
	}
	for cur.Next(context.Background()) {
		var doc indexDoc
		if err := cur.Decode(&doc); err != nil {
			t.Fatalf("decode index: %v", err)
		}
		if doc.Name != name {
			continue
		}
		if !doc.Unique {
			t.Fatalf("index %s on %s is not unique", name, coll.Name())
		}
		return
	}
	t.Fatalf("index %s is missing from the applied manifests on %s", name, coll.Name())
}
