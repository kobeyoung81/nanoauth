package store

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// countersCollection holds the named counters that stand in for MySQL's
// AUTO_INCREMENT. It is the platform's collection (sys_); this module keeps its
// own entries in it, keyed by collection name.
const countersCollection = "sys_counters"

// nextSequence returns the next value of a named counter.
//
// A starred path's id is part of an API (the console deletes one by id), so it
// cannot become an ObjectId. MySQL handed it out from the table's own
// auto-increment sequence; here one document per sequence holds it, bumped by a
// single atomic findOneAndUpdate.
func (s *Store) nextSequence(ctx context.Context, name string) (int64, error) {
	var doc struct {
		Seq int64 `bson:"seq"`
	}
	// Upserting a counter can race another upsert and raise E11000; the
	// documented remedy is one retry, and the retry is safe because the failed
	// attempt did not apply its $inc.
	err := retryOnDuplicateUpsert(func() error {
		return s.db.Collection(countersCollection).FindOneAndUpdate(ctx,
			bson.D{{Key: "_id", Value: name}},
			bson.D{{Key: "$inc", Value: bson.D{{Key: "seq", Value: int64(1)}}}},
			options.FindOneAndUpdate().
				SetUpsert(true).
				SetReturnDocument(options.After),
		).Decode(&doc)
	})
	if err != nil {
		return 0, fmt.Errorf("next %s id: %w", name, err)
	}
	return doc.Seq, nil
}
