package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// tickets is the rotation's collection in memory. It lives here rather than in
// the shared fake because this package's tests cannot import that one: it speaks
// the store's interfaces, so importing it from the store's own tests is a cycle.
type tickets struct {
	stored map[string]struct {
		userID    string
		expiresAt time.Time
	}
}

func newTickets() *tickets {
	return &tickets{stored: map[string]struct {
		userID    string
		expiresAt time.Time
	}{}}
}

func (f *tickets) SaveRefreshToken(tokenHash, userID string, expiresAt time.Time) error {
	f.stored[tokenHash] = struct {
		userID    string
		expiresAt time.Time
	}{userID: userID, expiresAt: expiresAt}
	return nil
}

func (f *tickets) RefreshToken(tokenHash string) (string, time.Time, bool, error) {
	ticket, ok := f.stored[tokenHash]
	return ticket.userID, ticket.expiresAt, ok, nil
}

func (f *tickets) DeleteRefreshToken(tokenHash string) error {
	delete(f.stored, tokenHash)
	return nil
}

func (f *tickets) has(token string) bool {
	_, ok := f.stored[hashToken(token)]
	return ok
}

func TestNewTokenStore(t *testing.T) {
	if NewTokenStore(newTickets()) == nil {
		t.Fatal("expected non-nil store")
	}
}

// TestWithoutATicketStoreTheRotationRefuses: a deployment without a database has
// nowhere to keep a ticket, and saying so is the only honest answer.
func TestWithoutATicketStoreTheRotationRefuses(t *testing.T) {
	s := NewTokenStore(nil)
	if _, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := s.ValidateAndConsume(context.Background(), "t"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("consume: %v", err)
	}
	if err := s.Revoke(context.Background(), "t"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("revoke: %v", err)
	}
}

func TestTokenStore_TTL(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	// The default is a week, and a meaningless value is ignored rather than
	// accepted.
	if s.TTL() != 7*24*time.Hour {
		t.Fatalf("default TTL = %v", s.TTL())
	}
	s.SetTTL(2 * time.Hour)
	if s.TTL() != 2*time.Hour {
		t.Fatalf("TTL = %v", s.TTL())
	}
	s.SetTTL(0)
	if s.TTL() != 2*time.Hour {
		t.Fatalf("a zero TTL was accepted: %v", s.TTL())
	}
}

func TestStoreRefreshToken(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	token, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected a token")
	}
	// What the collection holds is the hash: the token itself never leaves this
	// process.
	if !table.has(token) {
		t.Fatalf("the hash was not stored: %+v", table.stored)
	}
	if _, ok := table.stored[token]; ok {
		t.Fatal("the raw token was stored")
	}
}

func TestValidateAndConsume_Valid(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	token, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	userID, newToken, err := s.ValidateAndConsume(context.Background(), token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if userID != "u-1" {
		t.Fatalf("user id = %q", userID)
	}
	if newToken == "" || newToken == token {
		t.Fatalf("rotation did not issue a fresh ticket: %q", newToken)
	}
	// The presented ticket is spent.
	if table.has(token) {
		t.Fatal("the consumed ticket is still stored")
	}
	if !table.has(newToken) {
		t.Fatal("the rotated ticket is not stored")
	}
}

func TestValidateAndConsume_Expired(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	token, err := s.StoreRefreshToken(context.Background(), "u-1", -time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, _, err := s.ValidateAndConsume(context.Background(), token); err == nil {
		t.Fatal("an expired ticket was accepted")
	}
}

func TestValidateAndConsume_Invalid(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	if _, _, err := s.ValidateAndConsume(context.Background(), "not-a-ticket"); err == nil {
		t.Fatal("an unknown ticket was accepted")
	}
}

func TestRevoke(t *testing.T) {
	table := newTickets()
	s := NewTokenStore(table)

	token, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.Revoke(context.Background(), token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if table.has(token) {
		t.Fatal("the ticket survived the revocation")
	}
	// Logout must be safe to repeat, and an empty cookie is not an error either.
	if err := s.Revoke(context.Background(), token); err != nil {
		t.Fatalf("revoking twice errored: %v", err)
	}
	if err := s.Revoke(context.Background(), ""); err != nil {
		t.Fatalf("an empty token errored: %v", err)
	}
}

func TestHashToken(t *testing.T) {
	if hashToken("abc") != hashToken("abc") {
		t.Fatal("the hash is not stable")
	}
	if hashToken("abc") == hashToken("abd") {
		t.Fatal("different tokens hashed the same")
	}
	if len(hashToken("abc")) != 64 {
		t.Fatalf("hash length = %d, want 64 hex characters", len(hashToken("abc")))
	}
}
