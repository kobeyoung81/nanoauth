package store

// The account writes.
//
// The documents are identity's, so the writes are here: an account is registered,
// a platform identity is linked to it (or moved to another account, keeping its
// binding id — container requests and the "binding-N" names quote that id), its
// fields are set, and the first account to register can claim the administrator
// role once.
//
// What is deliberately NOT here: asking for a container. Onboarding creates the
// account and reports isNew; the provisioning request belongs to the provisioner's
// queue, and the caller that owns that step makes it.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrUserNotFound is returned when a user cannot be resolved.
var ErrUserNotFound = errors.New("user not found")

// ErrChannelDisabled reports a platform identity whose channel has been switched
// off by an administrator; the inbound path answers the sender with that.
var ErrChannelDisabled = errors.New("channel disabled")

// ResolvedBinding is what onboarding answers: whose account this identity is, and
// which binding id it holds.
type ResolvedBinding struct {
	UserID    string
	BindingID int64
	IsNew     bool
}

// bindingIDSequence names the counter that stands in for the AUTO_INCREMENT that
// the source table's binding id was. The value is not internal: container requests,
// the queued messages and the "binding-N" agent names all quote it, so it has to
// stay an increasing integer rather than become an ObjectID.
const bindingIDSequence = "user_channels_binding_id"

// systemFlagsCollection holds one-shot per-installation flags. They are not a
// module's private state: "this installation has given away its administrator role"
// is a fact about the installation, and whoever boots first must be able to read it.
const systemFlagsCollection = "sys_flags"

// bootstrapAdminFlag is the flag that says the first-administrator role has been
// handed out. It is claimed once and never released by the system: an installation
// whose only administrator is deleted does not silently promote the next account.
const bootstrapAdminFlag = "bootstrap_admin"

// storedUserChannel is one platform identity linked to a user.
//
// It is embedded in the user document rather than kept in a collection of its own:
// the identity's uniqueness — the (channel, sender_id) primary key — becomes a
// multikey unique index, so a racing onboarding fails the whole insert instead of
// needing a rollback.
type storedUserChannel struct {
	BindingID     int64     `bson:"binding_id"`
	Channel       string    `bson:"channel"`
	SenderID      string    `bson:"sender_id"`
	Provider      string    `bson:"provider,omitempty"`
	Enabled       bool      `bson:"enabled"`
	BindingStatus string    `bson:"binding_status"`
	CreatedAt     time.Time `bson:"created_at"`
}

// UserSummary is one row of the console's user list: identity and administration
// fields, never the credential.
type UserSummary struct {
	ID                 string
	DisplayName        string
	Email              string
	Role               string
	Status             string
	Tier               string
	MustChangePassword bool
	PreferredLanguage  string
	UpdatedAt          time.Time
}

func (s *Store) users() *mongo.Collection { return s.db.Collection(usersCollection) }

// channelIdentity is the element that names one platform identity, the pair the
// SQL's primary key covered.
func channelIdentity(channel, senderID string) bson.D {
	return bson.D{
		{Key: "channel", Value: channel},
		{Key: "sender_id", Value: senderID},
	}
}

// channelPath is the filter that finds the document holding an identity.
//
// Dotted paths rather than $elemMatch: an equality on channels.channel is what lets
// the unique index serve the lookup. It can match a document whose channel and
// sender live in different elements, which is why every caller reads the array and
// checks the pair before trusting it.
func channelPath(channel, senderID string) bson.D {
	return bson.D{
		{Key: "channels.channel", Value: channel},
		{Key: "channels.sender_id", Value: senderID},
	}
}

// RegisterUser creates a new user in the registry. An empty displayName is
// stored as NULL and, on an existing user, never overwrites a stored name.
func (s *Store) RegisterUser(userID, displayName string) error {
	ctx, cancel := opCtx()
	defer cancel()

	now := time.Now().UTC()
	set := bson.D{{Key: "updated_at", Value: now}}
	if displayName != "" {
		// COALESCE(VALUES(display_name), display_name): a stored name survives a
		// registration that carries none.
		set = append(set, bson.E{Key: "display_name", Value: displayName})
	}
	update := bson.D{
		{Key: "$set", Value: set},
		{Key: "$setOnInsert", Value: bson.D{
			// The column defaults.
			{Key: "status", Value: "active"},
			{Key: "tier", Value: "free"},
			{Key: "created_at", Value: now},
		}},
	}
	err := retryOnDuplicateUpsert(func() error {
		_, err := s.users().UpdateOne(ctx, bson.D{{Key: "_id", Value: userID}}, update,
			options.UpdateOne().SetUpsert(true))
		return err
	})
	if err != nil {
		return fmt.Errorf("register user %q: %w", userID, err)
	}
	return nil
}

// LinkChannel associates a platform identity with a user.
func (s *Store) LinkChannel(userID, channel, senderID string) error {
	ctx, cancel := opCtx()
	defer cancel()

	// The SQL was one INSERT ... ON DUPLICATE KEY UPDATE user_id = VALUES(user_id):
	// linking an identity that is already linked re-parents it, keeping its
	// binding id — container requests and the "binding-N" names quote that id, so
	// it cannot be reissued.
	owner, existing, err := s.channelOwner(ctx, channel, senderID)
	if err != nil {
		return fmt.Errorf("link channel %s/%s: %w", channel, senderID, err)
	}
	if owner == userID {
		return nil
	}

	element := storedUserChannel{
		Channel: channel, SenderID: senderID,
		Enabled: true, BindingStatus: "active", CreatedAt: time.Now().UTC(),
	}
	if existing != nil {
		element = *existing
	} else {
		element.BindingID, err = s.nextSequence(ctx, bindingIDSequence)
		if err != nil {
			return fmt.Errorf("link channel %s/%s: %w", channel, senderID, err)
		}
	}

	// A re-parented identity has to leave one document before it can join
	// another, and no transaction spans the two. So the order is: take it away,
	// then add it. Losing the process in between leaves the identity unlinked —
	// recoverable by linking again — rather than linked to two users, which the
	// unique index would then refuse to repair.
	if owner != "" {
		if _, err := s.users().UpdateOne(ctx,
			bson.D{
				{Key: "_id", Value: owner},
				{Key: "channels.channel", Value: channel},
				{Key: "channels.sender_id", Value: senderID},
			},
			bson.D{{Key: "$pull", Value: bson.D{{Key: "channels", Value: channelIdentity(channel, senderID)}}}},
		); err != nil {
			return fmt.Errorf("unlink channel %s/%s from user %q: %w", channel, senderID, owner, err)
		}
	}

	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$push", Value: bson.D{{Key: "channels", Value: element}}}},
	)
	if err != nil {
		return fmt.Errorf("link channel %s/%s to user %q: %w", channel, senderID, userID, err)
	}
	if res.MatchedCount == 0 {
		// The SQL's foreign key refused this too: a channel belongs to a user
		// that exists.
		return fmt.Errorf("link channel %s/%s: user %q not found", channel, senderID, userID)
	}
	return nil
}

// channelOwner finds the user that holds a platform identity, and the element
// that holds it (nil when nobody does).
func (s *Store) channelOwner(ctx context.Context, channel, senderID string) (string, *storedUserChannel, error) {
	var doc storedUser
	err := s.users().FindOne(ctx, channelPath(channel, senderID),
		options.FindOne().SetProjection(bson.D{{Key: "channels", Value: 1}}),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("find channel owner: %w", err)
	}
	for i := range doc.Channels {
		if doc.Channels[i].Channel == channel && doc.Channels[i].SenderID == senderID {
			return doc.ID, &doc.Channels[i], nil
		}
	}
	return "", nil, nil
}

// ResolveUserBinding looks up or creates the binding for a platform identity.
func (s *Store) ResolveUserBinding(channel, senderID string) (ResolvedBinding, error) {
	userID, bindingID, enabled, err := s.lookupBinding(channel, senderID)
	if err == nil {
		if !enabled {
			return ResolvedBinding{}, ErrChannelDisabled
		}
		return ResolvedBinding{UserID: userID, BindingID: bindingID, IsNew: false}, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return ResolvedBinding{}, fmt.Errorf("resolve user %s/%s: %w", channel, senderID, err)
	}

	ctx, cancel := opCtx()
	defer cancel()

	newID := uuid.New().String()
	bindingID, err = s.nextSequence(ctx, bindingIDSequence)
	if err != nil {
		return ResolvedBinding{}, fmt.Errorf("allocate binding id: %w", err)
	}

	now := time.Now().UTC()
	doc := storedUser{
		ID: newID, Status: "pending", Tier: "free",
		Channels: []storedUserChannel{{
			BindingID: bindingID, Channel: channel, SenderID: senderID,
			Enabled: true, BindingStatus: "active", CreatedAt: now,
		}},
		CreatedAt: now, UpdatedAt: now,
	}

	// One insert. The uniqueness of the identity is a constraint on the embedded
	// array, so a racing onboarding fails the whole document: the SQL needed a
	// transaction to roll back the user row it had already written, this does not
	// — there is nothing to roll back.
	if _, err := s.users().InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			userID, bindingID, enabled, err2 := s.lookupBinding(channel, senderID)
			if err2 != nil {
				return ResolvedBinding{}, fmt.Errorf("retry resolve after race: %w", err2)
			}
			if !enabled {
				return ResolvedBinding{}, ErrChannelDisabled
			}
			return ResolvedBinding{UserID: userID, BindingID: bindingID, IsNew: false}, nil
		}
		return ResolvedBinding{}, fmt.Errorf("insert user: %w", err)
	}

	return ResolvedBinding{UserID: newID, BindingID: bindingID, IsNew: true}, nil
}

// ResolveUser looks up the user ID for a given platform identity. If no user
// exists it creates one with status=pending, links the channel and reports isNew —
// asking for a container is the caller's step, because provisioning is not
// identity's domain.
func (s *Store) ResolveUser(channel, senderID string) (userID string, isNew bool, err error) {
	resolved, err := s.ResolveUserBinding(channel, senderID)
	if err != nil {
		return "", false, err
	}
	return resolved.UserID, resolved.IsNew, nil
}

// ListUsers returns all registered user IDs.
func (s *Store) ListUsers() ([]string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	cur, err := s.users().Find(ctx, bson.D{},
		options.Find().SetProjection(bson.D{{Key: "_id", Value: 1}}).
			SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	users := []string{}
	for cur.Next(ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode user: %w", err)
		}
		users = append(users, doc.ID)
	}
	return users, cur.Err()
}

// UpdateUserStatus updates a user's status. It is idempotent: setting a user
// to a status they already hold is a no-op, not an error.
func (s *Store) UpdateUserStatus(userID, status string) error {
	ctx, cancel := opCtx()
	defer cancel()

	// One statement rather than the SQL's COUNT followed by an UPDATE: the count
	// existed only to tell "no such user" from "already in that status", and an
	// update that matched nothing says the same thing without the race between
	// the two.
	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "status", Value: status},
			{Key: "updated_at", Value: time.Now().UTC()},
		}}},
	)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetUserPreferredLanguage stores the language this person wants replies in.
// An empty value clears it, which puts the account back on the platform default.
func (s *Store) SetUserPreferredLanguage(userID, language string) error {
	ctx, cancel := opCtx()
	defer cancel()

	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "preferred_language", Value: language},
		{Key: "updated_at", Value: time.Now().UTC()},
	}}}
	res, err := s.users().UpdateOne(ctx, bson.D{{Key: "_id", Value: userID}}, update)
	if err != nil {
		return fmt.Errorf("set preferred language: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetUserPreferredLanguage reads just the account's language choice. Empty
// means "inherit the platform default".
func (s *Store) GetUserPreferredLanguage(userID string) (string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc struct {
		Language string `bson:"preferred_language"`
	}
	err := s.users().FindOne(ctx, bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(bson.D{{Key: "preferred_language", Value: 1}}),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get preferred language: %w", err)
	}
	return doc.Language, nil
}

// GetUserInfo returns the status and level for a user.
func (s *Store) GetUserInfo(userID string) (status, level string, err error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc struct {
		Status string `bson:"status"`
		Tier   string `bson:"tier"`
	}
	err = s.users().FindOne(ctx, bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(bson.D{
			{Key: "status", Value: 1}, {Key: "tier", Value: 1},
		})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", "", ErrUserNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("get user info: %w", err)
	}
	return doc.Status, doc.Tier, nil
}

// setUserField writes one administration field, reporting an unknown user the
// way the SQL UPDATE did (nothing matched).
func (s *Store) setUserField(userID, field, value string) error {
	ctx, cancel := opCtx()
	defer cancel()

	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: field, Value: value},
			{Key: "updated_at", Value: time.Now().UTC()},
		}}},
	)
	if err != nil {
		return fmt.Errorf("update user %s: %w", field, err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ClaimBootstrapAdmin records that this installation has handed the
// administrator role to the account created by the first sign-up.
//
// The claim has to be atomic. Two registrations arriving together both see
// "no administrator yet", so counting is not enough to pick a winner; the flag
// document's _id is. Exactly one upsert creates it, and that caller is told it
// won. Every later registration finds the document already there and loses.
//
// The claim is one-shot per installation: it is never released automatically
// when an administrator is deleted or demoted. Recovery from that is a
// deliberate act by someone with shell access, not an invitation for the next
// stranger who registers.
func (s *Store) ClaimBootstrapAdmin(userID string) (bool, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var res *mongo.UpdateResult
	err := retryOnDuplicateUpsert(func() error {
		r, err := s.db.Collection(systemFlagsCollection).UpdateOne(ctx,
			bson.D{{Key: "_id", Value: bootstrapAdminFlag}},
			bson.D{{Key: "$setOnInsert", Value: bson.D{
				{Key: "user_id", Value: userID},
				{Key: "claimed_at", Value: time.Now().UTC()},
			}}},
			options.UpdateOne().SetUpsert(true),
		)
		res = r
		return err
	})
	if err != nil {
		return false, fmt.Errorf("claim bootstrap administrator: %w", err)
	}
	return res != nil && res.UpsertedCount == 1, nil
}

// ReleaseBootstrapAdmin hands the claim back after the role could not be
// written, so the next registration gets the same chance this one did. It only
// removes the flag the same account created.
func (s *Store) ReleaseBootstrapAdmin(userID string) error {
	ctx, cancel := opCtx()
	defer cancel()

	if _, err := s.db.Collection(systemFlagsCollection).DeleteOne(ctx,
		bson.D{{Key: "_id", Value: bootstrapAdminFlag}, {Key: "user_id", Value: userID}},
	); err != nil {
		return fmt.Errorf("release bootstrap administrator: %w", err)
	}
	return nil
}

// SetUserPasswordKeepingFlag replaces the hash and leaves the forced-change flag
// alone.
//
// The directory path wipes a local password when an account becomes
// directory-managed; the flag belongs to whatever password was there before and
// says nothing about a blank one. Stamping it either way would be inventing a
// decision the caller did not make.
func (s *Store) SetUserPasswordKeepingFlag(userID, passwordHash string) error {
	ctx, cancel := opCtx()
	defer cancel()

	now := time.Now().UTC()
	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "password_hash", Value: passwordHash},
			{Key: "password_changed_at", Value: now},
			{Key: "updated_at", Value: now},
		}}},
	)
	if err != nil {
		return fmt.Errorf("set user password: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetUserPassword stores a password hash produced by the caller.
//
// The hash never leaves this process except back to the caller that owns the
// login flow (UserPasswordHash), and the bus never sees a password: verification
// stays where the browser-facing form is.
func (s *Store) SetUserPassword(userID, passwordHash string, mustChange bool) error {
	ctx, cancel := opCtx()
	defer cancel()

	now := time.Now().UTC()
	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "password_hash", Value: passwordHash},
			{Key: "must_change_password", Value: mustChange},
			// Stamped here rather than by the caller, so "when did this password
			// last change" cannot be forgotten on one of the two call paths.
			{Key: "password_changed_at", Value: now},
			{Key: "updated_at", Value: now},
		}}},
	)
	if err != nil {
		return fmt.Errorf("set user password: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UserExists reports whether the account is there, whatever its status.
func (s *Store) UserExists(userID string) (bool, error) {
	ctx, cancel := opCtx()
	defer cancel()

	count, err := s.users().CountDocuments(ctx, bson.D{{Key: "_id", Value: userID}})
	if err != nil {
		return false, fmt.Errorf("check user: %w", err)
	}
	return count > 0, nil
}

// CountActiveAdmins counts accounts that may administer the platform: role admin
// and not deleted. The portal asks before demoting or deleting one, so the last
// admin cannot lock everybody out.
func (s *Store) CountActiveAdmins() (int, error) {
	ctx, cancel := opCtx()
	defer cancel()

	count, err := s.users().CountDocuments(ctx, bson.D{
		{Key: "role", Value: "admin"},
		{Key: "status", Value: bson.D{{Key: "$ne", Value: "deleted"}}},
	})
	if err != nil {
		return 0, fmt.Errorf("count active admins: %w", err)
	}
	return int(count), nil
}

// CountActiveUsers counts the accounts the console calls active. It is the
// overview's headline number, and it is a count rather than a list because that
// number has to stay cheap as the table grows.
func (s *Store) CountActiveUsers() (int, error) {
	ctx, cancel := opCtx()
	defer cancel()

	count, err := s.users().CountDocuments(ctx, bson.D{{Key: "status", Value: "active"}})
	if err != nil {
		return 0, fmt.Errorf("count active users: %w", err)
	}
	return int(count), nil
}

// CountUsersByTier counts the accounts per resource tier.
//
// The three tiers are always present in the result, zero included, because the
// console draws a fixed set of columns and an absent key would read as "not
// counted" rather than "none".
func (s *Store) CountUsersByTier() (map[string]int, error) {
	ctx, cancel := opCtx()
	defer cancel()

	cur, err := s.users().Aggregate(ctx, bson.A{
		bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$tier"},
			{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
		}}},
	})
	if err != nil {
		return nil, fmt.Errorf("count users by tier: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	out := map[string]int{"free": 0, "pro": 0, "ultra": 0}
	for cur.Next(ctx) {
		var doc struct {
			Tier  string `bson:"_id"`
			Count int    `bson:"count"`
		}
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode tier count: %w", err)
		}
		out[doc.Tier] = doc.Count
	}
	return out, cur.Err()
}

// SetUserDisplayName renames an account.
func (s *Store) SetUserDisplayName(userID, displayName string) error {
	return s.setUserField(userID, "display_name", displayName)
}

// SetUserEmail links an address to an account.
//
// The sign-in path looks accounts up by address, so two accounts cannot share
// one: the sparse unique index enforces it and this maps the duplicate-key error
// to something a caller can answer 409 with.
func (s *Store) SetUserEmail(userID, email string) error {
	ctx, cancel := opCtx()
	defer cancel()

	res, err := s.users().UpdateOne(ctx,
		bson.D{{Key: "_id", Value: userID}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "email", Value: email},
			{Key: "updated_at", Value: time.Now().UTC()},
		}}},
	)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrEmailTaken
		}
		return fmt.Errorf("set user email: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UserChannels returns the platform identities linked to a user, by channel name.
func (s *Store) UserChannels(userID string) ([]string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc storedUser
	err := s.users().FindOne(ctx, bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(bson.D{{Key: "channels", Value: 1}})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user channels: %w", err)
	}
	out := make([]string, 0, len(doc.Channels))
	for _, c := range doc.Channels {
		out = append(out, c.Channel)
	}
	return out, nil
}

// ListUserSummaries returns the admin console's user list, newest first.
func (s *Store) ListUserSummaries(includeDeleted bool, limit int) ([]UserSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	ctx, cancel := opCtx()
	defer cancel()

	filter := bson.D{}
	if !includeDeleted {
		filter = bson.D{{Key: "status", Value: bson.D{{Key: "$ne", Value: "deleted"}}}}
	}
	cur, err := s.users().Find(ctx, filter,
		options.Find().
			// Only the columns the list shows: the credential and the channels are
			// not among them.
			SetProjection(bson.D{
				{Key: "display_name", Value: 1}, {Key: "status", Value: 1},
				{Key: "tier", Value: 1}, {Key: "role", Value: 1}, {Key: "updated_at", Value: 1},
				{Key: "email", Value: 1},
			}).
			SetSort(bson.D{{Key: "updated_at", Value: -1}, {Key: "_id", Value: 1}}).
			SetLimit(int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	out := []UserSummary{}
	for cur.Next(ctx) {
		var doc storedUser
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode user: %w", err)
		}
		role := doc.Role
		if role == "" {
			// The SQL default was 'user', and the console shows a role for every
			// row.
			role = "user"
		}
		out = append(out, UserSummary{
			ID: doc.ID, DisplayName: doc.DisplayName, Email: doc.Email, Role: role,
			Status: doc.Status, Tier: doc.Tier, UpdatedAt: doc.UpdatedAt,
		})
	}
	return out, cur.Err()
}

// SearchUserSummaries finds live accounts by display name or e-mail fragment.
// It is what a member picker searches with: the caller types a couple of
// characters and gets a short list, never the whole table.
//
// The fragment is quoted before it becomes a pattern — a name containing "." or
// "+" must match itself rather than behave as a regular expression.
func (s *Store) SearchUserSummaries(q string, limit int) ([]UserSummary, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return []UserSummary{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	ctx, cancel := opCtx()
	defer cancel()

	pattern := bson.D{
		{Key: "$regex", Value: regexp.QuoteMeta(q)},
		{Key: "$options", Value: "i"},
	}
	filter := bson.D{
		{Key: "status", Value: bson.D{{Key: "$ne", Value: "deleted"}}},
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "display_name", Value: pattern}},
			bson.D{{Key: "email", Value: pattern}},
		}},
	}
	cur, err := s.users().Find(ctx, filter,
		options.Find().
			// Same projection as the list: identity only, never the credential.
			SetProjection(bson.D{
				{Key: "display_name", Value: 1}, {Key: "status", Value: 1},
				{Key: "tier", Value: 1}, {Key: "role", Value: 1}, {Key: "updated_at", Value: 1},
				{Key: "email", Value: 1},
			}).
			SetSort(bson.D{{Key: "display_name", Value: 1}, {Key: "_id", Value: 1}}).
			SetLimit(int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("search users: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	out := []UserSummary{}
	for cur.Next(ctx) {
		var doc storedUser
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode user: %w", err)
		}
		role := doc.Role
		if role == "" {
			role = "user"
		}
		out = append(out, UserSummary{
			ID: doc.ID, DisplayName: doc.DisplayName, Email: doc.Email, Role: role,
			Status: doc.Status, Tier: doc.Tier, UpdatedAt: doc.UpdatedAt,
		})
	}
	return out, cur.Err()
}

// UserIDForBinding returns the user a binding belongs to ("" when unowned).
func (s *Store) UserIDForBinding(bindingID int64) (string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc struct {
		ID string `bson:"_id"`
	}
	err := s.users().FindOne(ctx,
		bson.D{{Key: "channels.binding_id", Value: bindingID}},
		options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}}),
	).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get binding owner: %w", err)
	}
	return doc.ID, nil
}

func (s *Store) lookupBinding(channel, senderID string) (userID string, bindingID int64, enabled bool, err error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc storedUser
	err = s.users().FindOne(ctx, channelPath(channel, senderID),
		options.FindOne().SetProjection(bson.D{{Key: "channels", Value: 1}}),
	).Decode(&doc)
	if err != nil {
		return "", 0, false, err
	}
	for _, c := range doc.Channels {
		if c.Channel == channel && c.SenderID == senderID {
			return doc.ID, c.BindingID, c.Enabled, nil
		}
	}
	// The element the filter matched is gone: the identity was unlinked between
	// the two reads, which is the SQL's ErrNoRows.
	return "", 0, false, mongo.ErrNoDocuments
}

// EnableChannel enables a channel for a user.
func (s *Store) EnableChannel(userID, channel string) error {
	return s.setChannelEnabled(userID, channel, true)
}

// DisableChannel disables a channel for a user.
func (s *Store) DisableChannel(userID, channel string) error {
	return s.setChannelEnabled(userID, channel, false)
}

func (s *Store) setChannelEnabled(userID, channel string, enabled bool) error {
	ctx, cancel := opCtx()
	defer cancel()

	// The positional $ names the element the filter matched, so this stays one
	// update of one document.
	_, err := s.users().UpdateOne(ctx,
		bson.D{
			{Key: "_id", Value: userID},
			{Key: "channels.channel", Value: channel},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "channels.$.enabled", Value: enabled},
			{Key: "updated_at", Value: time.Now().UTC()},
		}}},
	)
	if err != nil {
		return fmt.Errorf("set channel enabled: %w", err)
	}
	return nil
}

func (s *Store) SetUserRole(userID, role string) error { return s.setUserField(userID, "role", role) }

func (s *Store) SetUserTier(userID, tier string) error { return s.setUserField(userID, "tier", tier) }

// UserPasswordHash returns the stored hash, or "" when the user has none.
func (s *Store) UserPasswordHash(userID string) (string, error) {
	ctx, cancel := opCtx()
	defer cancel()

	var doc struct {
		PasswordHash string `bson:"password_hash"`
	}
	err := s.users().FindOne(ctx, bson.D{{Key: "_id", Value: userID}},
		options.FindOne().SetProjection(bson.D{{Key: "password_hash", Value: 1}})).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get user password hash: %w", err)
	}
	return doc.PasswordHash, nil
}
