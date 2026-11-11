package store

// The session tickets.
//
// A refresh ticket is the auth service's own state — issued here, consumed here,
// revoked here — and the collection is identity's. It lived in the bus while the
// bus was the only writer; now the rotation happens against the database directly,
// which is also what makes a consume a single row operation instead of a call out
// and back.

import (
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// refreshTokensCollection holds the tickets, keyed by their hash.
const refreshTokensCollection = "auth_refresh_tokens"

// storedRefreshToken is the document shape: the token hash is the identity, as it
// was the source table's primary key, so it is the `_id` — one lookup, no second
// index, and a duplicate hash cannot exist.
type storedRefreshToken struct {
	TokenHash string    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

// SaveRefreshToken stores a ticket for a user, replacing one with the same hash
// (which can only be a retry).
func (s *Store) SaveRefreshToken(tokenHash, userID string, expiresAt time.Time) error {
	ctx, cancel := opCtx()
	defer cancel()

	if tokenHash == "" || userID == "" {
		return fmt.Errorf("save refresh token: token_hash and user_id are required")
	}
	if _, err := s.db.Collection(refreshTokensCollection).UpdateOne(ctx,
		bson.D{{Key: "_id", Value: tokenHash}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "user_id", Value: userID},
			{Key: "expires_at", Value: expiresAt.UTC()},
		}}, {Key: "$setOnInsert", Value: bson.D{
			{Key: "created_at", Value: time.Now().UTC()},
		}}},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

// RefreshToken reads one ticket. found=false is "no such ticket", which the
// rotation path answers as an invalid token rather than an error.
func (s *Store) RefreshToken(tokenHash string) (userID string, expiresAt time.Time, found bool, err error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc storedRefreshToken
	err = s.db.Collection(refreshTokensCollection).FindOne(ctx,
		bson.D{{Key: "_id", Value: tokenHash}}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("read refresh token: %w", err)
	}
	return doc.UserID, doc.ExpiresAt, true, nil
}

// DeleteRefreshToken revokes one ticket. Deleting a missing one is not an error:
// logout is idempotent.
func (s *Store) DeleteRefreshToken(tokenHash string) error {
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := s.db.Collection(refreshTokensCollection).DeleteOne(ctx,
		bson.D{{Key: "_id", Value: tokenHash}}); err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}
	return nil
}

// DeleteUserRefreshTokens drops every ticket a user holds — a password change or a
// forced sign-out.
func (s *Store) DeleteUserRefreshTokens(userID string) error {
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := s.db.Collection(refreshTokensCollection).DeleteMany(ctx,
		bson.D{{Key: "user_id", Value: userID}}); err != nil {
		return fmt.Errorf("delete refresh tokens for %s: %w", userID, err)
	}
	return nil
}

// PurgeExpiredRefreshTokens removes tickets whose lifetime has run out.
func (s *Store) PurgeExpiredRefreshTokens(now time.Time) (int64, error) {
	ctx, cancel := opCtx()
	defer cancel()

	res, err := s.db.Collection(refreshTokensCollection).DeleteMany(ctx,
		bson.D{{Key: "expires_at", Value: bson.D{{Key: "$lt", Value: now.UTC()}}}})
	if err != nil {
		return 0, fmt.Errorf("purge refresh tokens: %w", err)
	}
	return res.DeletedCount, nil
}
