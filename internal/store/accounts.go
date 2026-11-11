package store

// The account reads.
//
// The documents were written by the bus while it held the only connection; the
// shape is the same either way, and this file is the mirror of it: a projection of
// the identity and administration fields, never a column list invented here. The
// writes stay on the bus until they move, which is why every method here is a
// read.

import (
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	usersCollection          = "auth_users"
	oauthProvidersCollection = "auth_oauth_providers"
)

// ErrAccountNotFound reports that no account (or link) matches.
var ErrAccountNotFound = errors.New("account not found")

// storedUser is the user document, as far as this service reads it.
type storedUser struct {
	ID                string              `bson:"_id"`
	DisplayName       string              `bson:"display_name,omitempty"`
	Status            string              `bson:"status"`
	Tier              string              `bson:"tier"`
	Role              string              `bson:"role,omitempty"`
	Email             string              `bson:"email,omitempty"`
	PasswordHash      string              `bson:"password_hash,omitempty"`
	MustChangePass    bool                `bson:"must_change_password,omitempty"`
	PreferredLanguage string              `bson:"preferred_language,omitempty"`
	PasswordChanged   *time.Time          `bson:"password_changed_at,omitempty"`
	Channels          []storedUserChannel `bson:"channels,omitempty"`
	CreatedAt         time.Time           `bson:"created_at"`
	UpdatedAt         time.Time           `bson:"updated_at"`
}

// accountProjection is the fields a sign-in answer needs. The credential is read
// separately, by passwordHash, so a caller that only needs identity never loads
// it.
var accountProjection = bson.D{
	{Key: "display_name", Value: 1}, {Key: "status", Value: 1},
	{Key: "tier", Value: 1}, {Key: "role", Value: 1}, {Key: "email", Value: 1},
	{Key: "must_change_password", Value: 1}, {Key: "preferred_language", Value: 1},
	{Key: "updated_at", Value: 1},
}

// normalizeAccount fills the defaults the platform computes rather than stores.
func normalizeAccount(doc storedUser, email string) UserRecord {
	role := doc.Role
	if role == "" {
		role = "user"
	}
	tier := doc.Tier
	if tier == "" {
		tier = "free"
	}
	status := doc.Status
	if status == "" {
		status = "active"
	}
	if doc.Email == "" {
		doc.Email = email
	}
	return UserRecord{
		ID: doc.ID, Email: doc.Email, DisplayName: doc.DisplayName,
		Role: role, Tier: tier, Status: status,
		MustChangePassword: doc.MustChangePass,
		PreferredLanguage:  doc.PreferredLanguage,
		UpdatedAt:          doc.UpdatedAt,
	}
}

// AccountByID returns the account with this id, or nil when there is none.
func (s *Store) AccountByID(userID string) (*UserRecord, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc storedUser
	err := s.db.Collection(usersCollection).FindOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(accountProjection),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read account %s: %w", userID, err)
	}
	record := normalizeAccount(doc, "")
	return &record, nil
}

// AccountByEmail returns the account with this address, or nil when there is none.
// The address is matched exactly: it is stored lower-cased by the writer, and a
// case-folding match here would have to guess what the writer did.
func (s *Store) AccountByEmail(email string) (*UserRecord, error) {
	ctx, cancel := opCtx()
	defer cancel()

	if email == "" {
		return nil, nil
	}
	var doc storedUser
	err := s.db.Collection(usersCollection).FindOne(ctx,
		bson.D{{Key: "email", Value: email}},
		options.FindOne().SetProjection(accountProjection),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read account by email: %w", err)
	}
	record := normalizeAccount(doc, email)
	return &record, nil
}

// PasswordHash returns the stored credential for an account. An account without a
// password (a directory or OAuth one) reads as an empty hash, which is what the
// sign-in flow checks.
func (s *Store) PasswordHash(userID string) (string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc struct {
		PasswordHash string `bson:"password_hash"`
	}
	err := s.db.Collection(usersCollection).FindOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(bson.D{{Key: "password_hash", Value: 1}}),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read password hash: %w", err)
	}
	return doc.PasswordHash, nil
}

// OAuthLinks returns the identities linked to one account.
func (s *Store) OAuthLinks(userID string) ([]OAuthLink, error) {
	ctx, cancel := opCtx()
	defer cancel()

	cur, err := s.db.Collection(oauthProvidersCollection).Find(ctx,
		bson.D{{Key: "user_id", Value: userID}},
		options.Find().SetSort(bson.D{{Key: "provider", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("list oauth links: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	out := []OAuthLink{}
	for cur.Next(ctx) {
		var doc struct {
			UserID     string `bson:"user_id"`
			Provider   string `bson:"provider"`
			ProviderID string `bson:"provider_id"`
		}
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode oauth link: %w", err)
		}
		out = append(out, OAuthLink{UserID: doc.UserID, Provider: doc.Provider, ProviderID: doc.ProviderID})
	}
	return out, cur.Err()
}

// AccountByOAuthLink answers the sign-in question: which account is this directory
// or OAuth identity? It returns nil when the identity is not linked.
func (s *Store) AccountByOAuthLink(provider, providerID string) (*UserRecord, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var link struct {
		UserID string `bson:"user_id"`
	}
	err := s.db.Collection(oauthProvidersCollection).FindOne(ctx,
		bson.D{{Key: "provider", Value: provider}, {Key: "provider_id", Value: providerID}},
		options.FindOne().SetProjection(bson.D{{Key: "user_id", Value: 1}}),
	).Decode(&link)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read oauth link %s/%s: %w", provider, providerID, err)
	}
	return s.AccountByID(link.UserID)
}

// OAuthLink is one identity link.
type OAuthLink struct {
	UserID     string
	Provider   string
	ProviderID string
}
