package store

// The account writes are local: this service holds the collection, so a sign-up
// must not depend on the bus being reachable to store what it just decided. The
// bus is only the fallback of a deployment started without a database URI, and
// these tests pin the difference — with the store attached the fake bus records
// nothing at all.
//
// The bootstrap rule moved here with the writes, so it is pinned here too: the
// first account of an installation takes the administrator role, once, and the
// switch the admin module publishes can turn that off.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
)

// localStore returns a store over a throwaway database, with a fake admin module
// behind it: the trail is a report, and pointing it at the fake keeps these tests
// about the account writes.
func localStore(t *testing.T) (*UserStore, *Store) {
	t.Helper()
	db := testStore(t)
	return NewUserStore(db).WithAdmin(adminConfig(t, nil).Client(t)), db
}

// adminConfig is a fake admin module: the installation switches, and the trail.
func adminConfig(t *testing.T, values map[string]string) *bustest.Bus {
	t.Helper()
	admin := bustest.New()
	if values != nil {
		admin.SetConfig("auth", values)
	}
	return admin
}

func TestCreateWritesTheAccountWithoutTheBus(t *testing.T) {
	s, db := localStore(t)

	id, err := s.Create(context.Background(), "new@example.com", "hash", "New")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	record, err := db.AccountByID(id)
	if err != nil || record == nil {
		t.Fatalf("read back: %+v (err %v)", record, err)
	}
	if record.Email != "new@example.com" || record.DisplayName != "New" {
		t.Fatalf("unexpected account: %+v", record)
	}
	hash, err := db.PasswordHash(id)
	if err != nil || hash != "hash" {
		t.Fatalf("the credential did not arrive: %q (err %v)", hash, err)
	}
}

func TestCreateReportsATakenAddress(t *testing.T) {
	s, _ := localStore(t)
	ctx := context.Background()

	if _, err := s.Create(ctx, "taken@example.com", "hash", "First"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Create(ctx, "taken@example.com", "hash", "Second"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
}

func TestCreateWithLDAPWritesTheAccountAndTheLinkLocally(t *testing.T) {
	s, db := localStore(t)

	id, err := s.CreateWithLDAP(context.Background(), "cn=kobe,ou=people", "kobe@example.com", "Kobe")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	record, err := db.AccountByID(id)
	if err != nil || record == nil || record.Email != "kobe@example.com" {
		t.Fatalf("the account is not there: %+v (err %v)", record, err)
	}
	links, err := db.OAuthLinks(id)
	if err != nil || len(links) != 1 || links[0].Provider != "ldap" {
		t.Fatalf("the directory link is not there: %+v (err %v)", links, err)
	}
}

func TestCreateWithOAuthWritesTheAccountAndTheLinkLocally(t *testing.T) {
	s, db := localStore(t)

	id, err := s.CreateWithOAuth(context.Background(), "wechat", "openid-1", "微信用户")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	record, err := db.AccountByID(id)
	if err != nil || record == nil || record.Email != "wechat:openid-1" {
		t.Fatalf("the account is not there: %+v (err %v)", record, err)
	}
	links, err := db.OAuthLinks(id)
	if err != nil || len(links) != 1 || links[0].ProviderID != "openid-1" {
		t.Fatalf("the provider link is not there: %+v (err %v)", links, err)
	}
}

// TestAccountFieldWritesAreLocal pins the three single-field writes the directory
// login makes: blanking a password, suspending an account, syncing a name.
func TestAccountFieldWritesAreLocal(t *testing.T) {
	s, db := localStore(t)
	ctx := context.Background()

	id, err := s.Create(ctx, "kobe@example.com", "hash", "Kobe")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.SetUserPassword(id, "hash", true); err != nil {
		t.Fatalf("seed the forced-change flag: %v", err)
	}

	if err := s.UpdatePasswordHash(ctx, id, ""); err != nil {
		t.Fatalf("blank the password: %v", err)
	}
	record, err := db.AccountByID(id)
	if err != nil || record == nil {
		t.Fatalf("read back: %+v (err %v)", record, err)
	}
	if !record.MustChangePassword {
		t.Fatal("blanking the password cleared the forced-change flag")
	}
	if hash, _ := db.PasswordHash(id); hash != "" {
		t.Fatalf("the password was not blanked: %q", hash)
	}

	if err := s.UpdateDisplayName(ctx, id, "Renamed"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if record, _ = db.AccountByID(id); record == nil || record.DisplayName != "Renamed" {
		t.Fatalf("the name did not stick: %+v", record)
	}

	if err := s.SetStatus(ctx, id, "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if record, _ = db.AccountByID(id); record == nil || record.Status != "suspended" {
		t.Fatalf("the status did not stick: %+v", record)
	}

}

// TestCreatePromotesTheFirstAccount: the first sign-up of an installation with no
// administrator becomes one, and the second does not.
func TestCreatePromotesTheFirstAccount(t *testing.T) {
	s, db := localStore(t)
	s.WithAdmin(adminConfig(t, map[string]string{"firstUserIsAdmin": "true"}).Client(t))
	ctx := context.Background()

	first, err := s.Create(ctx, "first@example.com", "hash", "First")
	if err != nil {
		t.Fatalf("create the first account: %v", err)
	}
	record, _ := db.AccountByID(first)
	if record == nil || record.Role != "admin" {
		t.Fatalf("the first account did not become an administrator: %+v", record)
	}

	second, err := s.Create(ctx, "second@example.com", "hash", "Second")
	if err != nil {
		t.Fatalf("create the second account: %v", err)
	}
	if record, _ = db.AccountByID(second); record == nil || record.Role != "user" {
		t.Fatalf("the second account took the role too: %+v", record)
	}
	if admins, err := db.CountActiveAdmins(); err != nil || admins != 1 {
		t.Fatalf("administrators = %d (err %v), want 1", admins, err)
	}
}

// TestTheDirectoryPathAlsoPromotesTheFirstAccount: the bus used to run the rule on
// its create endpoint, which every creation path went through; moving the writes
// here must not leave the directory and OAuth sign-ups as plain users on a fresh
// installation.
func TestTheDirectoryPathAlsoPromotesTheFirstAccount(t *testing.T) {
	s, db := localStore(t)
	s.WithAdmin(adminConfig(t, nil).Client(t))

	id, err := s.CreateWithLDAP(context.Background(), "cn=kobe,ou=people", "kobe@example.com", "Kobe")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record, _ := db.AccountByID(id); record == nil || record.Role != "admin" {
		t.Fatalf("the directory account did not become an administrator: %+v", record)
	}
}

func TestTheInstallationSwitchCanTurnTheRuleOff(t *testing.T) {
	s, db := localStore(t)
	s.WithAdmin(adminConfig(t, map[string]string{"firstUserIsAdmin": "false"}).Client(t))

	id, err := s.Create(context.Background(), "first@example.com", "hash", "First")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record, _ := db.AccountByID(id); record == nil || record.Role != "user" {
		t.Fatalf("the switch was ignored: %+v", record)
	}
}

// TestTheSwitchDefaultsOnWhenItCannotBeRead: a config read that fails must not
// leave a fresh installation with an account nobody can administer.
func TestTheSwitchDefaultsOnWhenItCannotBeRead(t *testing.T) {
	s, db := localStore(t)
	admin := adminConfig(t, nil)
	admin.FailReads(true)
	s.WithAdmin(admin.Client(t))

	id, err := s.Create(context.Background(), "first@example.com", "hash", "First")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record, _ := db.AccountByID(id); record == nil || record.Role != "admin" {
		t.Fatalf("an unreadable switch should read as on: %+v", record)
	}
}

// TestRecordAuthAuditAsksTheAdminModule: the trail belongs to admin, and the bus
// is not the middleman for it when an admin URL is configured.
func TestRecordAuthAuditAsksTheAdminModule(t *testing.T) {
	db := testStore(t)
	admin := adminConfig(t, nil)
	s := NewUserStore(db).WithAdmin(admin.Client(t))

	if err := s.RecordAuthAudit(context.Background(), "user.ldap.missing", "u-1", "admin", "10.0.0.1", nil); err != nil {
		t.Fatalf("record: %v", err)
	}
	if entries := admin.Entries(); len(entries) != 1 || entries[0]["action"] != "user.ldap.missing" {
		t.Fatalf("the entry did not reach admin: %+v", entries)
	}
	// The path matters: /api/v1/audit is the bus's forwarder, and the admin
	// module's own door is the internal one.
	posted := false
	for _, call := range admin.Requests() {
		if call == "POST /api/v1/internal/audit" {
			posted = true
		}
	}
	if !posted {
		t.Fatalf("the trail was not posted to the admin module: %v", admin.Requests())
	}
}

// TestBootstrapAdministrationIsAudited: the role hand-over is an administrative
// act, so it lands in the trail next to the console's own actions.
func TestBootstrapAdministrationIsAudited(t *testing.T) {
	s, _ := localStore(t)
	admin := adminConfig(t, nil)
	s.WithAdmin(admin.Client(t))

	if _, err := s.Create(context.Background(), "first@example.com", "hash", "First"); err != nil {
		t.Fatalf("create: %v", err)
	}
	entries := admin.Entries()
	if len(entries) != 1 || entries[0]["action"] != "user.bootstrap.admin" {
		t.Fatalf("the promotion was not audited: %+v", entries)
	}
}

// TestConcurrentSignUpsPromoteExactlyOneAccount: two browsers can register at the
// same moment, and the role must not depend on who wins a race. The atomic claim
// (the flag document) is what decides, not the count read a moment earlier.
func TestConcurrentSignUpsPromoteExactlyOneAccount(t *testing.T) {
	s, db := localStore(t)
	ctx := context.Background()

	const signUps = 4
	ids := make(chan string, signUps)
	errs := make(chan error, signUps)
	for i := 0; i < signUps; i++ {
		go func(i int) {
			id, err := s.Create(ctx, fmt.Sprintf("racer-%d@example.com", i), "hash", "Racer")
			if err != nil {
				errs <- err
				return
			}
			ids <- id
		}(i)
	}
	admins := 0
	for i := 0; i < signUps; i++ {
		select {
		case err := <-errs:
			t.Fatalf("a concurrent sign-up failed: %v", err)
		case id := <-ids:
			record, err := db.AccountByID(id)
			if err != nil || record == nil {
				t.Fatalf("read back %s: %+v (err %v)", id, record, err)
			}
			if record.Role == "admin" {
				admins++
			}
		}
	}
	if admins != 1 {
		t.Fatalf("%d of %d concurrent sign-ups became administrators, want 1", admins, signUps)
	}
}

// TestWithoutADatabaseTheStoreRefusesInsteadOfPretending: a deployment that was
// started without a URI has nowhere to write, and an error is the only honest
// answer — an empty success would look like an account that exists.
func TestWithoutADatabaseTheStoreRefusesInsteadOfPretending(t *testing.T) {
	s := NewUserStore(nil)
	ctx := context.Background()

	if _, err := s.Create(ctx, "a@b.c", "hash", "A"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.GetByEmail(ctx, "a@b.c"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("read: %v", err)
	}
	if err := s.UpdateDisplayName(ctx, "u-1", "A"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("write: %v", err)
	}
}

// TestAnAccountWithoutADirectoryLinkReportsNone guards the sign-in flow's fork:
// a local password must not be mistaken for a directory-managed account.
func TestAnAccountWithoutADirectoryLinkReportsNone(t *testing.T) {
	s, db := localStore(t)
	ctx := context.Background()

	id, err := s.Create(ctx, "local@example.com", "hash", "Local")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.LinkOAuth(id, "wechat", "openid-1"); err != nil {
		t.Fatalf("link another provider: %v", err)
	}
	if providerID, err := s.GetAuthProviderID(ctx, id); err != nil || providerID != "" {
		t.Fatalf("GetAuthProviderID = %q (err %v), want an empty answer", providerID, err)
	}
}
