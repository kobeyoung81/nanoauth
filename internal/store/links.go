package store

// The identity links: which provider identity signs in as which account. The
// collection is `auth_oauth_providers`, and it is identity's — the login flow
// writes a link when it links a directory or OAuth identity, and the console reads
// the roster that answer produces.

import (
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// LinkOAuth links a provider identity to an account, or moves an existing link.
// The (provider, provider_id) pair is unique: one identity, one account.
func (s *Store) LinkOAuth(userID, provider, providerID string) error {
	ctx, cancel := opCtx()
	defer cancel()

	if userID == "" || provider == "" || providerID == "" {
		return fmt.Errorf("link oauth: user_id, provider and provider_id are required")
	}
	if _, err := s.db.Collection(oauthProvidersCollection).UpdateOne(ctx,
		bson.D{{Key: "provider", Value: provider}, {Key: "provider_id", Value: providerID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "user_id", Value: userID},
			{Key: "provider", Value: provider},
			{Key: "provider_id", Value: providerID},
		}}},
		options.UpdateOne().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("link oauth %s/%s: %w", provider, providerID, err)
	}
	return nil
}

// UnlinkOAuth removes an account's link for one provider. Unlinking one that is
// not there is not an error: the caller asked for it to be gone.
func (s *Store) UnlinkOAuth(userID, provider string) error {
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := s.db.Collection(oauthProvidersCollection).DeleteMany(ctx,
		bson.D{{Key: "user_id", Value: userID}, {Key: "provider", Value: provider}},
	); err != nil {
		return fmt.Errorf("unlink oauth %s: %w", provider, err)
	}
	return nil
}

// OAuthProviderLinks is the roster one provider signs in with: every identity
// linked through it, ordered by account. The console's directory page reads it.
func (s *Store) OAuthProviderLinks(provider string) ([]OAuthLink, error) {
	ctx, cancel := opCtx()
	defer cancel()

	cur, err := s.db.Collection(oauthProvidersCollection).Find(ctx,
		bson.D{{Key: "provider", Value: provider}},
		options.Find().SetSort(bson.D{{Key: "user_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("list oauth links for %s: %w", provider, err)
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
