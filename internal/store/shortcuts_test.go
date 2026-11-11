package store

// Starred paths are identity's: one row per (user, agent, path) with a stable id,
// ordered newest first, and scoped to their owner. The unique index is what makes
// eight tabs starring the same file converge on one row.

import (
	"sync"
	"testing"
	"time"
)

func TestSaveGitShortcut_StarsThenRelabels(t *testing.T) {
	s := testStore(t)

	first, err := s.SaveGitShortcut("u-1", "agent-1", "src/main.go", "main")
	if err != nil {
		t.Fatalf("first star: %v", err)
	}
	if first.ID == 0 {
		t.Fatal("a new star got no id")
	}

	// Re-starring the same path is the same row with a new label — the console
	// shows one entry, not two.
	second, err := s.SaveGitShortcut("u-1", "agent-1", "src/main.go", "entry point")
	if err != nil {
		t.Fatalf("re-star: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("re-starring created a second row: %d then %d", first.ID, second.ID)
	}
	if second.Label != "entry point" {
		t.Fatalf("label = %q, want the new one", second.Label)
	}

	rows, err := s.GitShortcuts("u-1", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one starred path, got %+v", rows)
	}
	if rows[0].Label != "entry point" {
		t.Fatalf("the list did not see the new label: %+v", rows[0])
	}
}

// TestSaveGitShortcut_ConcurrentStarsCollapse is the guard for the unique index
// on (user_id, agent_id, path): eight tabs starring the same file at once must
// converge on one row, and every caller must come away with the same id — the
// console deletes by that id.
func TestSaveGitShortcut_ConcurrentStarsCollapse(t *testing.T) {
	s := testStore(t)

	var wg sync.WaitGroup
	ids := make([]int64, 8)
	errs := make([]error, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			shortcut, err := s.SaveGitShortcut("u-1", "agent-1", "README.md", "label")
			ids[i], errs[i] = shortcut.ID, err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("star %d: %v", i, err)
		}
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("star %d got id %d, the first got %d", i, id, ids[0])
		}
	}
	rows, err := s.GitShortcuts("u-1", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("eight concurrent stars produced %d rows: %+v", len(rows), rows)
	}
}

func TestGitShortcuts_AreScopedAndOrdered(t *testing.T) {
	s := testStore(t)

	if _, err := s.SaveGitShortcut("u-1", "agent-1", "a.go", ""); err != nil {
		t.Fatalf("star a: %v", err)
	}
	time.Sleep(2 * time.Millisecond) // created_at is the sort key; ids break ties
	if _, err := s.SaveGitShortcut("u-1", "agent-1", "b.go", ""); err != nil {
		t.Fatalf("star b: %v", err)
	}
	if _, err := s.SaveGitShortcut("u-1", "agent-2", "c.go", ""); err != nil {
		t.Fatalf("star c: %v", err)
	}

	all, err := s.GitShortcuts("u-1", "")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected three stars, got %+v", all)
	}
	// c.go was starred last, so it heads the list: newest first.
	if all[0].Path != "c.go" || all[2].Path != "a.go" {
		t.Fatalf("newest first expected, got %+v", all)
	}
	scoped, err := s.GitShortcuts("u-1", "agent-2")
	if err != nil {
		t.Fatalf("list scoped: %v", err)
	}
	if len(scoped) != 1 || scoped[0].Path != "c.go" {
		t.Fatalf("agent filter leaked: %+v", scoped)
	}
	other, err := s.GitShortcuts("u-2", "")
	if err != nil {
		t.Fatalf("list other user: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("another user saw rows: %+v", other)
	}
}

func TestDeleteGitShortcut_UnknownIsAnError(t *testing.T) {
	s := testStore(t)

	shortcut, err := s.SaveGitShortcut("u-1", "agent-1", "a.go", "")
	if err != nil {
		t.Fatalf("star: %v", err)
	}
	if err := s.DeleteGitShortcut("u-1", shortcut.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteGitShortcut("u-1", shortcut.ID); err == nil {
		t.Fatal("deleting it twice must report not-found, as it did in SQL")
	}
	// Another user cannot delete it either.
	again, err := s.SaveGitShortcut("u-1", "agent-1", "a.go", "")
	if err != nil {
		t.Fatalf("restar: %v", err)
	}
	if err := s.DeleteGitShortcut("u-2", again.ID); err == nil {
		t.Fatal("a stranger deleted somebody's star")
	}
}
