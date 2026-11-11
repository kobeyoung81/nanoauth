package store

// The account writes: what onboarding, the console and the sign-in flow do to a
// user document. What has to hold is what the callers relied on — an identity
// linked to exactly one account (and keeping its binding id when it moves), the
// column defaults, the one-shot administrator claim, and a credential that is
// never read back to a browser.

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestRegisterUserKeepsAStoredName(t *testing.T) {
	s := testStore(t)

	if err := s.RegisterUser("u-1", "Ada"); err != nil {
		t.Fatalf("register: %v", err)
	}
	// A registration with no name must not erase the one that is there.
	if err := s.RegisterUser("u-1", ""); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	record, err := s.AccountByID("u-1")
	if err != nil || record == nil {
		t.Fatalf("read back: %+v (err %v)", record, err)
	}
	if record.DisplayName != "Ada" || record.Status != "active" || record.Tier != "free" {
		t.Fatalf("unexpected account: %+v", record)
	}
}

func TestResolveUserBindingCreatesOnceAndKeepsTheBindingID(t *testing.T) {
	s := testStore(t)

	first, err := s.ResolveUserBinding("web", "sender-1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !first.IsNew || first.BindingID == 0 {
		t.Fatalf("expected a new pending account, got %+v", first)
	}
	if record, _ := s.AccountByID(first.UserID); record == nil || record.Status != "pending" {
		t.Fatalf("onboarding must create a pending account: %+v", record)
	}

	// The second call is the same identity: same account, same binding id.
	again, err := s.ResolveUserBinding("web", "sender-1")
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if again.IsNew || again.UserID != first.UserID || again.BindingID != first.BindingID {
		t.Fatalf("the identity was not stable: %+v then %+v", first, again)
	}

	// Linking it to another account moves it — and keeps the id container requests
	// and the "binding-N" names quote.
	if err := s.RegisterUser("u-2", "Bob"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.LinkChannel("u-2", "web", "sender-1"); err != nil {
		t.Fatalf("re-parent: %v", err)
	}
	moved, err := s.ResolveUserBinding("web", "sender-1")
	if err != nil {
		t.Fatalf("resolve after move: %v", err)
	}
	if moved.UserID != "u-2" || moved.BindingID != first.BindingID {
		t.Fatalf("the move lost the binding id: %+v (was %d)", moved, first.BindingID)
	}
}

func TestChannelCanBeDisabledForOneUser(t *testing.T) {
	s := testStore(t)
	if _, err := s.ResolveUserBinding("web", "sender-1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var doc struct {
		ID string `bson:"_id"`
	}
	if err := s.users().FindOne(t.Context(), bson.D{{Key: "channels.sender_id", Value: "sender-1"}}).Decode(&doc); err != nil {
		t.Fatalf("find account: %v", err)
	}

	if err := s.DisableChannel(doc.ID, "web"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := s.ResolveUserBinding("web", "sender-1"); err != ErrChannelDisabled {
		t.Fatalf("a disabled channel resolved anyway: %v", err)
	}
	if err := s.EnableChannel(doc.ID, "web"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := s.ResolveUserBinding("web", "sender-1"); err != nil {
		t.Fatalf("the channel did not come back: %v", err)
	}
}

func TestAccountFieldsAndCredential(t *testing.T) {
	s := testStore(t)
	if err := s.RegisterUser("u-1", "Ada"); err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := s.SetUserRole("u-1", "admin"); err != nil {
		t.Fatalf("role: %v", err)
	}
	if err := s.SetUserTier("u-1", "pro"); err != nil {
		t.Fatalf("tier: %v", err)
	}
	if err := s.UpdateUserStatus("u-1", "suspended"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := s.SetUserPreferredLanguage("u-1", "en"); err != nil {
		t.Fatalf("language: %v", err)
	}
	record, _ := s.AccountByID("u-1")
	if record.Role != "admin" || record.Tier != "pro" || record.Status != "suspended" || record.PreferredLanguage != "en" {
		t.Fatalf("fields did not stick: %+v", record)
	}

	if err := s.SetUserPassword("u-1", "hash-1", true); err != nil {
		t.Fatalf("password: %v", err)
	}
	if hash, _ := s.UserPasswordHash("u-1"); hash != "hash-1" {
		t.Fatalf("hash = %q", hash)
	}
	if record, _ := s.AccountByID("u-1"); !record.MustChangePassword {
		t.Fatalf("the must-change flag was not set: %+v", record)
	}
	// The sign-in flow's own change keeps the flag it was given.
	if err := s.SetUserPasswordKeepingFlag("u-1", "hash-2"); err != nil {
		t.Fatalf("password keep-flag: %v", err)
	}
	if hash, _ := s.UserPasswordHash("u-1"); hash != "hash-2" {
		t.Fatalf("hash = %q", hash)
	}
	if record, _ := s.AccountByID("u-1"); !record.MustChangePassword {
		t.Fatalf("keeping the flag did not keep it: %+v", record)
	}

	// A field write on an account that does not exist is "not found", not a
	// silent no-op.
	if err := s.UpdateUserStatus("ghost", "active"); err != ErrUserNotFound {
		t.Fatalf("status on a missing account = %v, want ErrUserNotFound", err)
	}
}

func TestBootstrapAdminIsClaimedOnce(t *testing.T) {
	s := testStore(t)
	for _, id := range []string{"u-1", "u-2"} {
		if err := s.RegisterUser(id, ""); err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
	}

	// The claim is the flag; the caller sets the role once it has the flag, which
	// is what makes the hand-out atomic against a second registration.
	claimed, err := s.ClaimBootstrapAdmin("u-1")
	if err != nil || !claimed {
		t.Fatalf("first claim = %v (err %v)", claimed, err)
	}
	if err := s.SetUserRole("u-1", "admin"); err != nil {
		t.Fatalf("set role: %v", err)
	}
	if record, _ := s.AccountByID("u-1"); record.Role != "admin" {
		t.Fatalf("the claim did not make an administrator: %+v", record)
	}
	// The second account does not get it: the role is handed out once.
	if claimed, err := s.ClaimBootstrapAdmin("u-2"); err != nil || claimed {
		t.Fatalf("second claim = %v (err %v), want false", claimed, err)
	}
	// Releasing is the roll-back a failed first write needs.
	if err := s.ReleaseBootstrapAdmin("u-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if claimed, err := s.ClaimBootstrapAdmin("u-2"); err != nil || !claimed {
		t.Fatalf("claim after release = %v (err %v), want true", claimed, err)
	}
}

func TestAccountCountsAndSearch(t *testing.T) {
	s := testStore(t)
	ctx := t.Context()
	now := time.Now().UTC()
	docs := []bson.D{
		{{Key: "_id", Value: "u-1"}, {Key: "display_name", Value: "Ada"}, {Key: "email", Value: "ada@example.test"}, {Key: "status", Value: "active"}, {Key: "tier", Value: "pro"}, {Key: "role", Value: "admin"}, {Key: "updated_at", Value: now}},
		{{Key: "_id", Value: "u-2"}, {Key: "display_name", Value: "Bob"}, {Key: "status", Value: "active"}, {Key: "tier", Value: "free"}, {Key: "updated_at", Value: now}},
		{{Key: "_id", Value: "u-3"}, {Key: "display_name", Value: "Cid"}, {Key: "status", Value: "deleted"}, {Key: "tier", Value: "free"}, {Key: "updated_at", Value: now}},
	}
	for _, doc := range docs {
		if _, err := s.DB().Collection("auth_users").InsertOne(ctx, doc); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	if got, err := s.CountActiveUsers(); err != nil || got != 2 {
		t.Fatalf("active = %d (err %v), want 2", got, err)
	}
	if got, err := s.CountActiveAdmins(); err != nil || got != 1 {
		t.Fatalf("admins = %d (err %v), want 1", got, err)
	}
	// The tier counts group every document, deleted ones included: the console's
	// overview answers "how many accounts are on this plan", not "how many are
	// active" (that is the separate number).
	tiers, err := s.CountUsersByTier()
	if err != nil || tiers["pro"] != 1 || tiers["free"] != 2 {
		t.Fatalf("tiers = %+v (err %v)", tiers, err)
	}
	// The console's overview always shows the three tiers, including the empty one.
	if _, ok := tiers["ultra"]; !ok {
		t.Fatalf("the empty tier is missing from the counts: %+v", tiers)
	}
	// The console's page can include deleted accounts; its search box can too.
	if all, err := s.ListUserSummaries(true, 10); err != nil || len(all) != 3 {
		t.Fatalf("list all = %d (err %v)", len(all), err)
	}
	if live, err := s.ListUserSummaries(false, 10); err != nil || len(live) != 2 {
		t.Fatalf("list live = %d (err %v)", len(live), err)
	}
	if found, err := s.SearchUserSummaries("ada", 10); err != nil || len(found) != 1 || found[0].ID != "u-1" {
		t.Fatalf("search = %+v (err %v)", found, err)
	}
}
