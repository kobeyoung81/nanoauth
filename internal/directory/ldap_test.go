package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestBuildFilter_EscapesTheEmail(t *testing.T) {
	cfg := &Config{UserFilter: "(&(objectClass=user)(mail=%s))"}

	got := BuildFilter(cfg, "a*li(ce)@corp.local")
	want := `(&(objectClass=user)(mail=a\2ali\28ce\29@corp.local))`
	if got != want {
		t.Fatalf("filter injection is not escaped\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildFilter_LowercasesTheEmail(t *testing.T) {
	cfg := &Config{UserFilter: "(mail=%s)"}

	if got, want := BuildFilter(cfg, "Alice@Corp.Local"), "(mail=alice@corp.local)"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilter_RequiredGroupIsConjoined(t *testing.T) {
	cfg := &Config{
		UserFilter:      "(&(objectClass=user)(mail=%s))",
		RequiredGroupDN: "cn=myriadmind-users,dc=corp,dc=local",
	}

	got := BuildFilter(cfg, "alice@corp.local")
	want := "(&(&(objectClass=user)(mail=alice@corp.local))(memberOf=cn=myriadmind-users,dc=corp,dc=local))"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildFilter_RequiredGroupInChain(t *testing.T) {
	cfg := &Config{
		UserFilter:        "(&(objectClass=user)(mail=%s))",
		RequiredGroupDN:   "cn=myriadmind-users,dc=corp,dc=local",
		GroupMatchInChain: true,
	}

	got := BuildFilter(cfg, "alice@corp.local")
	want := "(&(&(objectClass=user)(mail=alice@corp.local))(memberOf:1.2.840.113556.1.4.1941:=cn=myriadmind-users,dc=corp,dc=local))"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The directory refuses to bind without a password, but LDAP itself answers an
// empty-password bind as an anonymous bind that succeeds — so the guard has to
// run before the connection is opened. The bogus URL proves nothing was dialled.
func TestAuthenticate_EmptyPasswordIsRejectedBeforeDialing(t *testing.T) {
	cfg := &Config{
		URL:        "ldap://127.0.0.1:1",
		BaseDN:     "dc=corp,dc=local",
		UserFilter: "(mail=%s)",
		Timeout:    time.Second,
	}

	_, err := NewClient().Authenticate(context.Background(), cfg, "alice@corp.local", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_IncompleteConfigIsUnavailable(t *testing.T) {
	client := NewClient()
	cases := []*Config{
		nil,
		{URL: "ldap://127.0.0.1:1"}, // no base DN
		{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=local"}, // no filter
		{BaseDN: "dc=corp,dc=local", UserFilter: "(mail=%s)"},   // no url
	}

	for i, cfg := range cases {
		if _, err := client.Authenticate(context.Background(), cfg, "alice@corp.local", "pw"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("case %d: expected ErrUnavailable, got %v", i, err)
		}
	}
}

func TestUniqueID_HexEncodesBinaryValues(t *testing.T) {
	// Active Directory returns objectGUID as raw bytes.
	entry := &ldap.Entry{
		DN: "CN=Alice,DC=corp,DC=local",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", Values: []string{"\x01\x00\x02"}, ByteValues: [][]byte{{0x01, 0x00, 0x02}}},
		},
	}
	cfg := &Config{AttrUniqueID: "objectGUID", AttrUsername: "sAMAccountName"}

	if got := uniqueID(entry, cfg); got != "010002" {
		t.Fatalf("got %q, want the hex form 010002", got)
	}
}

func TestUniqueID_KeepsTextValues(t *testing.T) {
	entry := &ldap.Entry{
		DN:         "uid=alice,dc=corp,dc=local",
		Attributes: []*ldap.EntryAttribute{{Name: "entryUUID", Values: []string{"b7ce-4f1a"}, ByteValues: [][]byte{[]byte("b7ce-4f1a")}}},
	}
	cfg := &Config{AttrUniqueID: "entryUUID", AttrUsername: "uid"}

	if got := uniqueID(entry, cfg); got != "b7ce-4f1a" {
		t.Fatalf("got %q, want the text value", got)
	}
}

func TestUniqueID_FallsBackToTheLoginName(t *testing.T) {
	entry := &ldap.Entry{
		DN:         "CN=Alice,DC=corp,DC=local",
		Attributes: []*ldap.EntryAttribute{{Name: "sAMAccountName", Values: []string{"Alice"}}},
	}
	cfg := &Config{AttrUniqueID: "objectGUID", AttrUsername: "sAMAccountName"}

	if got := uniqueID(entry, cfg); got != "alice" {
		t.Fatalf("got %q, want the login name", got)
	}
}

func TestUniqueID_FallsBackToTheDN(t *testing.T) {
	entry := &ldap.Entry{DN: "CN=Bob,DC=corp,DC=local"}
	cfg := &Config{AttrUniqueID: "objectGUID", AttrUsername: "sAMAccountName"}

	if got := uniqueID(entry, cfg); got != "cn=bob,dc=corp,dc=local" {
		t.Fatalf("got %q, want the lowercased DN", got)
	}
}

func TestDisplayName_FallsBackToTheLoginName(t *testing.T) {
	cfg := &Config{AttrDisplayName: "displayName", AttrUsername: "sAMAccountName"}

	withDisplayName := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "displayName", Values: []string{"Alice Zhang"}}}}
	if got := displayName(withDisplayName, cfg); got != "Alice Zhang" {
		t.Fatalf("got %q", got)
	}

	withoutDisplayName := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{Name: "sAMAccountName", Values: []string{"alice"}}}}
	if got := displayName(withoutDisplayName, cfg); got != "alice" {
		t.Fatalf("got %q", got)
	}
}

func TestTLSConfig_SkippedForPlainConnections(t *testing.T) {
	cfg := &Config{URL: "ldap://dir.corp.local:389"}

	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg != nil {
		t.Fatal("a plain ldap:// connection must not carry a TLS config")
	}
}

func TestTLSConfig_AppliedForLDAPS(t *testing.T) {
	cfg := &Config{URL: "ldaps://dir.corp.local:636"}

	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected a TLS config")
	}
	if tlsCfg.ServerName != "dir.corp.local" {
		t.Fatalf("unexpected server name %q", tlsCfg.ServerName)
	}
}

func TestTLSConfig_RejectsAnUnusableCA(t *testing.T) {
	cfg := &Config{URL: "ldaps://dir.corp.local:636", CACertPEM: "not a certificate"}

	if _, err := tlsConfig(cfg); err == nil {
		t.Fatal("expected an error for a CA that holds no certificate")
	}
}
