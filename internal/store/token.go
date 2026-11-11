package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

// TokenStore issues and rotates refresh tickets.
//
// They are `auth_refresh_tokens`, which is this service's collection, so the store
// talks to it directly (tickets.go). Only the hash is stored: the token itself
// never touches the database, exactly as a password never does.
type TokenStore struct {
	// accounts is the database. It is nil in a deployment without a URI, where the
	// tickets fall back to the bus that used to hold them.
	accounts *Store
	// bus is that fallback.
	bus *bus.Client
	ttl time.Duration
}

func NewTokenStore(client *bus.Client) *TokenStore {
	return &TokenStore{bus: client, ttl: 7 * 24 * time.Hour}
}

// WithAccounts attaches the database.
func (s *TokenStore) WithAccounts(accounts *Store) *TokenStore {
	s.accounts = accounts
	return s
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

	if s.accounts != nil {
		if err := s.accounts.SaveRefreshToken(hashToken(token), userID, time.Now().Add(ttl)); err != nil {
			return "", err
		}
		return token, nil
	}

	body := map[string]string{
		"token_hash": hashToken(token),
		"user_id":    userID,
		"expires_at": time.Now().Add(ttl).UTC().Format(time.RFC3339),
	}
	if err := s.bus.Do(ctx, http.MethodPost, "/api/v1/auth/refresh-tokens", body, nil); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// ValidateAndConsume checks a ticket, revokes it and issues its successor. The
// bus answers 404 for a hash it does not know, which is the same "invalid" the
// SQL's ErrNoRows produced.
func (s *TokenStore) ValidateAndConsume(ctx context.Context, token string) (string, string, error) {
	if s.accounts != nil {
		userID, expiresAt, found, err := s.accounts.RefreshToken(hashToken(token))
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
		if err := s.accounts.DeleteRefreshToken(hashToken(token)); err != nil {
			return "", "", err
		}
		newToken, err := s.StoreRefreshToken(ctx, userID, s.TTL())
		if err != nil {
			return "", "", err
		}
		return userID, newToken, nil
	}

	var payload struct {
		UserID    string `json:"user_id"`
		ExpiresAt string `json:"expires_at"`
	}
	path := "/api/v1/auth/refresh-tokens/" + url.PathEscape(hashToken(token))
	err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload)
	if errors.Is(err, bus.ErrNotFound) {
		return "", "", fmt.Errorf("invalid refresh token")
	}
	if err != nil {
		return "", "", fmt.Errorf("query refresh token: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return "", "", fmt.Errorf("refresh token expiry: %w", err)
	}
	if time.Now().After(expiresAt) {
		return "", "", fmt.Errorf("refresh token expired")
	}

	// Rotation: the presented ticket is spent, a fresh one is issued.
	if err := s.Revoke(ctx, token); err != nil {
		return "", "", err
	}
	newToken, err := s.StoreRefreshToken(ctx, payload.UserID, s.TTL())
	if err != nil {
		return "", "", err
	}
	return payload.UserID, newToken, nil
}

// Revoke deletes the stored refresh token matching the raw value. A missing
// token is not an error so logout is idempotent.
func (s *TokenStore) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if s.accounts != nil {
		return s.accounts.DeleteRefreshToken(hashToken(token))
	}
	path := "/api/v1/auth/refresh-tokens/" + url.PathEscape(hashToken(token))
	if err := s.bus.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}
