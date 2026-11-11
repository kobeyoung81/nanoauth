package store

// The identity links: one row per provider identity (so re-linking moves it rather
// than adding an owner), the roster one provider signs in with, and the reverse
// question the sign-in flow asks — which account is this directory subject.

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// TestLinkOAuth_IdentityBelongsToOneAccount pins the source table's composite
// primary key: an identity is one row, and re-linking it moves it rather than
// adding a second owner.
func TestLinkOAuth_IdentityBelongsToOneAccount(t *testing.T) {
	s := testStore(t)

	if err := s.LinkOAuth("u-1", "ldap", "cn=kobeyoung,ou=people"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if err := s.LinkOAuth("u-1", "ldap", "cn=kobeyoung,ou=people"); err != nil {
		t.Fatalf("re-link: %v", err)
	}

	links, err := s.OAuthLinks("u-1")
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("re-linking produced %d rows: %+v", len(links), links)
	}
	if links[0].Provider != "ldap" || links[0].ProviderID != "cn=kobeyoung,ou=people" {
		t.Fatalf("unexpected link: %+v", links[0])
	}

	if err := s.LinkOAuth("u-2", "ldap", "cn=kobeyoung,ou=people"); err != nil {
		t.Fatalf("relink to another account: %v", err)
	}
	u1, err := s.OAuthLinks("u-1")
	if err != nil {
		t.Fatalf("links u-1: %v", err)
	}
	u2, err := s.OAuthLinks("u-2")
	if err != nil {
		t.Fatalf("links u-2: %v", err)
	}
	if len(u1) != 0 || len(u2) != 1 {
		t.Fatalf("the identity did not move: u-1=%+v u-2=%+v", u1, u2)
	}
}

// TestOAuthProviderLinks_IsTheDirectoryRoster is what the console's user list
// reads instead of its own DISTINCT query.
func TestOAuthProviderLinks_IsTheDirectoryRoster(t *testing.T) {
	s := testStore(t)

	if err := s.LinkOAuth("u-1", "ldap", "cn=one"); err != nil {
		t.Fatalf("link one: %v", err)
	}
	if err := s.LinkOAuth("u-2", "ldap", "cn=two"); err != nil {
		t.Fatalf("link two: %v", err)
	}
	if err := s.LinkOAuth("u-3", "github", "gh-3"); err != nil {
		t.Fatalf("link github: %v", err)
	}

	links, err := s.OAuthProviderLinks("ldap")
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("expected two directory accounts, got %+v", links)
	}
	for _, link := range links {
		if link.Provider != "ldap" {
			t.Fatalf("the roster leaked another provider: %+v", link)
		}
	}

	if err := s.UnlinkOAuth("u-1", "ldap"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if links, err = s.OAuthProviderLinks("ldap"); err != nil {
		t.Fatalf("roster after unlink: %v", err)
	} else if len(links) != 1 {
		t.Fatalf("unlink did not take effect: %+v", links)
	}
}

// TestOAuthLinkOwner_AnswersTheSignInQuestion: given a directory/OAuth identity,
// which account is it? The pair is unique, so this is one lookup.
func TestOAuthLinkOwner_AnswersTheSignInQuestion(t *testing.T) {
	s := testStore(t)

	seedUserDoc(t, s, bson.D{{Key: "_id", Value: "u-1"}, {Key: "status", Value: "active"}})
	if err := s.LinkOAuth("u-1", "wechat", "openid-9"); err != nil {
		t.Fatalf("link: %v", err)
	}
	account, err := s.AccountByOAuthLink("wechat", "openid-9")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if account == nil || account.ID != "u-1" {
		t.Fatalf("lookup gave %+v", account)
	}
	if none, err := s.AccountByOAuthLink("wechat", "openid-unknown"); err != nil || none != nil {
		t.Fatalf("an unknown identity must not resolve: %+v err=%v", none, err)
	}
}
