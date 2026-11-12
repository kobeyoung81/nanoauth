package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// TicketStore is the ticket collection as the rotation needs it.
//
// It is an interface for the same reason AccountStore is one: the handler tests
// exercise sign-in and refresh without a database.
type TicketStore interface {
	SaveRefreshToken(tokenHash, userID string, expiresAt time.Time) error
	RefreshToken(tokenHash string) (userID string, expiresAt time.Time, found bool, err error)
	DeleteRefreshToken(tokenHash string) error
}

// TokenStore issues and rotates refresh tickets.
//
// They are `auth_refresh_tokens`, which is this service's collection, so the store
// talks to it directly (tickets.go). Only the hash is stored: the token itself
// never touches the database, exactly as a password never does.
type TokenStore struct {
	tickets TicketStore
	ttl     time.Duration
}

func NewTokenStore(tickets TicketStore) *TokenStore {
	return &TokenStore{tickets: tickets, ttl: 7 * 24 * time.Hour}
}

// SetTTL overrides the refresh-token lifetime used for storage and rotation.
// A non-positive value is ignored so the default is always safe.
func (s *TokenStore) SetTTL(ttl time.Duration) {
	if ttl > 0 {
		s.ttl = ttl
	}
}

// TTL returns the configured refresh-token lifetime.
func (s *TokenStore) TTL() time.Duration {
	if s.ttl <= 0 {
		return 7 * 24 * time.Hour
	}
	return s.ttl
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(raw)

	if s.tickets == nil {
		return "", ErrStoreNotConfigured
	}
	if err := s.tickets.SaveRefreshToken(hashToken(token), userID, time.Now().Add(ttl)); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateAndConsume checks a ticket, revokes it and issues its successor. An
// unknown hash is "invalid" rather than an error, the same answer the SQL's
// ErrNoRows produced.
func (s *TokenStore) ValidateAndConsume(ctx context.Context, token string) (string, string, error) {
	if s.tickets == nil {
		return "", "", ErrStoreNotConfigured
	}
	userID, expiresAt, found, err := s.tickets.RefreshToken(hashToken(token))
	if err != nil {
		return "", "", fmt.Errorf("query refresh token: %w", err)
	}
	if !found {
		return "", "", fmt.Errorf("invalid refresh token")
	}
	if time.Now().After(expiresAt) {
		return "", "", fmt.Errorf("refresh token expired")
	}
	// Rotation: the presented ticket is spent, a fresh one is issued.
	if err := s.tickets.DeleteRefreshToken(hashToken(token)); err != nil {
		return "", "", err
	}
	newToken, err := s.StoreRefreshToken(ctx, userID, s.TTL())
	if err != nil {
		return "", "", err
	}
	return userID, newToken, nil
}

// Revoke deletes the stored refresh token matching the raw value. A missing
// token is not an error so logout is idempotent.
func (s *TokenStore) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if s.tickets == nil {
		return ErrStoreNotConfigured
	}
	return s.tickets.DeleteRefreshToken(hashToken(token))
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}
