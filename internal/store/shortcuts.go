package store

import (
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// gitShortcutsCollection holds the paths a user starred in the git browser,
// keyed by (user, agent, path).
const gitShortcutsCollection = "auth_git_shortcuts"

// GitShortcut is a user's starred path inside one agent's container.
type GitShortcut struct {
	ID      int64  `json:"id"`
	UserID  string `json:"user_id"`
	AgentID string `json:"agent_id"`
	Path    string `json:"path"`
	Label   string `json:"label"`
}

// storedGitShortcut is the document shape. created_at is a date rather than the
// SQL column's text: the list sorts on it.
type storedGitShortcut struct {
	ID        int64     `bson:"_id"`
	UserID    string    `bson:"user_id"`
	AgentID   string    `bson:"agent_id"`
	Path      string    `bson:"path"`
	Label     string    `bson:"label"`
	CreatedAt time.Time `bson:"created_at"`
}

func (d storedGitShortcut) shortcut() GitShortcut {
	return GitShortcut{ID: d.ID, UserID: d.UserID, AgentID: d.AgentID, Path: d.Path, Label: d.Label}
}

// GitShortcuts lists a user's starred paths, newest first, optionally narrowed to
// one agent.
func (s *Store) GitShortcuts(userID, agentID string) ([]GitShortcut, error) {
	ctx, cancel := opCtx()
	defer cancel()

	filter := bson.D{{Key: "user_id", Value: userID}}
	if agentID != "" {
		filter = append(filter, bson.E{Key: "agent_id", Value: agentID})
	}
	cur, err := s.db.Collection(gitShortcutsCollection).Find(ctx, filter,
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("list git shortcuts: %w", err)
	}
	defer func() { _ = cur.Close(ctx) }()

	out := []GitShortcut{}
	for cur.Next(ctx) {
		var doc storedGitShortcut
		if err := cur.Decode(&doc); err != nil {
			return nil, fmt.Errorf("decode git shortcut: %w", err)
		}
		out = append(out, doc.shortcut())
	}
	return out, cur.Err()
}

// SaveGitShortcut stars a path, or re-labels it when it is already starred. It
// returns the stored row so the console can show the id it will delete by.
func (s *Store) SaveGitShortcut(userID, agentID, path, label string) (GitShortcut, error) {
	ctx, cancel := opCtx()
	defer cancel()

	if userID == "" || agentID == "" || path == "" {
		return GitShortcut{}, fmt.Errorf("save git shortcut: user_id, agent_id and path are required")
	}
	identity := bson.D{
		{Key: "user_id", Value: userID},
		{Key: "agent_id", Value: agentID},
		{Key: "path", Value: path},
	}

	var existing storedGitShortcut
	err := s.db.Collection(gitShortcutsCollection).FindOne(ctx, identity).Decode(&existing)
	switch {
	case err == nil:
		if _, err := s.db.Collection(gitShortcutsCollection).UpdateOne(ctx, identity,
			bson.D{{Key: "$set", Value: bson.D{{Key: "label", Value: label}}}}); err != nil {
			return GitShortcut{}, fmt.Errorf("relabel git shortcut: %w", err)
		}
		existing.Label = label
		return existing.shortcut(), nil
	case !errors.Is(err, mongo.ErrNoDocuments):
		return GitShortcut{}, fmt.Errorf("find git shortcut: %w", err)
	}

	id, err := s.nextSequence(ctx, gitShortcutsCollection)
	if err != nil {
		return GitShortcut{}, err
	}
	doc := storedGitShortcut{
		ID: id, UserID: userID, AgentID: agentID, Path: path, Label: label,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := s.db.Collection(gitShortcutsCollection).InsertOne(ctx, doc); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// Another star of the same path won the race: it is an update now.
			return s.SaveGitShortcut(userID, agentID, path, label)
		}
		return GitShortcut{}, fmt.Errorf("insert git shortcut: %w", err)
	}
	return doc.shortcut(), nil
}

// DeleteGitShortcut removes one star, scoped to its owner.
func (s *Store) DeleteGitShortcut(userID string, id int64) error {
	ctx, cancel := opCtx()
	defer cancel()

	res, err := s.db.Collection(gitShortcutsCollection).DeleteOne(ctx,
		bson.D{{Key: "_id", Value: id}, {Key: "user_id", Value: userID}})
	if err != nil {
		return fmt.Errorf("delete git shortcut: %w", err)
	}
	if res.DeletedCount == 0 {
		return fmt.Errorf("shortcut %d not found", id)
	}
	return nil
}
