package store

import (
	"context"
	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"testing"
	"time"
)

func TestNewTokenStore(t *testing.T) {
	stub := bustest.New()
	if NewTokenStore(stub.Client(t)) == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestTokenStore_TTL(t *testing.T) {
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

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
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

	token, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected a token")
	}
	// What the bus holds is the hash: the token itself never leaves this process.
	if _, ok := stub.Tokens()[hashToken(token)]; !ok {
		t.Fatalf("the hash was not stored: %+v", stub.Tokens())
	}
	if _, ok := stub.Tokens()[token]; ok {
		t.Fatal("the raw token was stored")
	}
}

func TestValidateAndConsume_Valid(t *testing.T) {
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

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
	if _, ok := stub.Tokens()[hashToken(token)]; ok {
		t.Fatal("the consumed ticket is still stored")
	}
	if _, ok := stub.Tokens()[hashToken(newToken)]; !ok {
		t.Fatal("the rotated ticket is not stored")
	}
}

func TestValidateAndConsume_Expired(t *testing.T) {
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

	token, err := s.StoreRefreshToken(context.Background(), "u-1", -time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, _, err := s.ValidateAndConsume(context.Background(), token); err == nil {
		t.Fatal("an expired ticket was accepted")
	}
}

func TestValidateAndConsume_Invalid(t *testing.T) {
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

	if _, _, err := s.ValidateAndConsume(context.Background(), "not-a-ticket"); err == nil {
		t.Fatal("an unknown ticket was accepted")
	}
}

func TestRevoke(t *testing.T) {
	stub := bustest.New()
	s := NewTokenStore(stub.Client(t))

	token, err := s.StoreRefreshToken(context.Background(), "u-1", time.Hour)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := s.Revoke(context.Background(), token); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := stub.Tokens()[hashToken(token)]; ok {
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
