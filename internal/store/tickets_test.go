package store

// The session tickets: one row per hash, addressed by the hash, consumed exactly
// once, and purged by expiry. The rotation itself is TokenStore's (token_test.go);
// what is pinned here is the storage it rests on.

import (
	"testing"
	"time"
)

func TestRefreshToken_Lifecycle(t *testing.T) {
	s := testStore(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	if err := s.SaveRefreshToken("hash-1", "u-1", expires); err != nil {
		t.Fatalf("save: %v", err)
	}
	userID, got, found, err := s.RefreshToken("hash-1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !found || userID != "u-1" || !got.Equal(expires) {
		t.Fatalf("read gave %q %v found=%v", userID, got, found)
	}

	// Saving the same hash again is the same ticket, not a second one.
	if err := s.SaveRefreshToken("hash-1", "u-1", expires); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if err := s.SaveRefreshToken("hash-2", "u-2", expires); err != nil {
		t.Fatalf("second ticket: %v", err)
	}

	if err := s.DeleteRefreshToken("hash-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, found, err := s.RefreshToken("hash-1"); err != nil || found {
		t.Fatalf("revoked ticket still found: found=%v err=%v", found, err)
	}
	// Logout must be safe to repeat.
	if err := s.DeleteRefreshToken("hash-1"); err != nil {
		t.Fatalf("revoking twice errored: %v", err)
	}

	if err := s.DeleteUserRefreshTokens("u-2"); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if _, _, found, err := s.RefreshToken("hash-2"); err != nil || found {
		t.Fatalf("user revocation missed the ticket: found=%v err=%v", found, err)
	}
}

func TestPurgeExpiredRefreshTokens_KeepsLiveOnes(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()

	if err := s.SaveRefreshToken("expired", "u-1", now.Add(-time.Hour)); err != nil {
		t.Fatalf("save expired: %v", err)
	}
	if err := s.SaveRefreshToken("live", "u-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("save live: %v", err)
	}

	deleted, err := s.PurgeExpiredRefreshTokens(now)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("purged %d, want 1", deleted)
	}
	if _, _, found, err := s.RefreshToken("live"); err != nil || !found {
		t.Fatalf("the live ticket went with the expired one: found=%v err=%v", found, err)
	}
}

// TestTokenStoreRotatesAgainstTheDatabase: the rotation is the auth service's own
// step, and the tickets are its collection — so it must not need the bus. The
// store is built with no bus at all, which makes any fallback a panic.
func TestTokenStoreRotatesAgainstTheDatabase(t *testing.T) {
	s := testStore(t)
	tokens := NewTokenStore(nil).WithAccounts(s)
	ctx := t.Context()

	first, err := tokens.StoreRefreshToken(ctx, "u-1", time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	userID, second, err := tokens.ValidateAndConsume(ctx, first)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if userID != "u-1" || second == "" || second == first {
		t.Fatalf("rotation gave user %q token %q (first %q)", userID, second, first)
	}

	// The presented ticket is spent: consuming it again is invalid, not a second
	// successful rotation.
	if _, _, err := tokens.ValidateAndConsume(ctx, first); err == nil {
		t.Fatal("a consumed ticket was accepted twice")
	}
	// And the successor works.
	if userID, _, err := tokens.ValidateAndConsume(ctx, second); err != nil || userID != "u-1" {
		t.Fatalf("successor: %q (err %v)", userID, err)
	}

	// An expired ticket is refused.
	expired, err := tokens.StoreRefreshToken(ctx, "u-2", -time.Hour)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if _, _, err := tokens.ValidateAndConsume(ctx, expired); err == nil {
		t.Fatal("an expired ticket was accepted")
	}
}
