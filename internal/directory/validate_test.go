package directory

import (
	"testing"
	"time"
)

// TestParseConfig_AccountPolicies pins the three account-relationship settings
// added for the portal's directory console, and their defaults.
func TestParseConfig_AccountPolicies(t *testing.T) {
	stored := parseConfig(map[string]string{
		"ldap.linkPolicy":       "refuse",
		"ldap.disableOnMissing": "true",
		"ldap.syncDisplayName":  "true",
	})
	if stored.LinkPolicy != LinkPolicyRefuse {
		t.Errorf("link policy = %q, want refuse", stored.LinkPolicy)
	}
	if !stored.DisableOnMissing || !stored.SyncDisplayName {
		t.Error("expected both boolean policies to be on")
	}

	defaults := parseConfig(map[string]string{})
	if defaults.LinkPolicy != LinkPolicyAuto {
		t.Errorf("link policy = %q, want auto", defaults.LinkPolicy)
	}
	if defaults.DisableOnMissing || defaults.SyncDisplayName {
		t.Error("both boolean policies must default to off")
	}
}

func TestValidate_AcceptsAUsableConfiguration(t *testing.T) {
	cfg := &Config{
		Enabled:         true,
		URL:             "ldaps://dir.corp.local:636",
		Timeout:         10 * time.Second,
		BaseDN:          "dc=corp,dc=local",
		UserFilter:      "(&(objectClass=user)(mail=%s))",
		AttrUniqueID:    "objectGUID",
		AttrUsername:    "sAMAccountName",
		AttrDisplayName: "displayName",
		LinkPolicy:      LinkPolicyAuto,
	}
	if problems := Validate(cfg); len(problems) != 0 {
		t.Fatalf("expected no problems, got %+v", problems)
	}
}

// A filter without the email placeholder stops matching per user: every login
// would search for the same entry, which is a silent outage rather than a
// security hole — and the console must refuse it before it is saved.
func TestValidate_RequiresTheFilterPlaceholder(t *testing.T) {
	cfg := &Config{Enabled: true, URL: "ldap://dir", Timeout: time.Second, BaseDN: "dc=corp",
		UserFilter: "(objectClass=user)", AttrUniqueID: "objectGUID", AttrUsername: "sAMAccountName"}
	problems := Validate(cfg)
	if problems["ldap.userFilter"].Code != "filter_missing_placeholder" {
		t.Fatalf("expected the placeholder rule to fire, got %+v", problems["ldap.userFilter"])
	}
}

func TestValidate_RejectsABrokenFilter(t *testing.T) {
	cfg := &Config{URL: "ldap://dir", Timeout: time.Second, UserFilter: "(&(objectClass=user)(mail=%s)"}
	if problems := Validate(cfg); problems["ldap.userFilter"].Code != "filter_invalid" {
		t.Fatalf("expected a filter syntax error, got %+v", problems["ldap.userFilter"])
	}
}

func TestValidate_ChecksTheAddressAndTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		code string
	}{
		{"scheme", "http://dir.corp.local", "url_scheme"},
		{"host", "ldap://", "url_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{URL: tc.url, Timeout: time.Second, LinkPolicy: LinkPolicyAuto}
			if got := Validate(cfg)["ldap.url"].Code; got != tc.code {
				t.Fatalf("code = %q, want %q", got, tc.code)
			}
		})
	}

	cfg := &Config{URL: "ldap://dir", Timeout: 5 * time.Minute, LinkPolicy: LinkPolicyAuto}
	if got := Validate(cfg)["ldap.timeoutSeconds"].Code; got != "timeout_range" {
		t.Fatalf("code = %q, want timeout_range", got)
	}
}

func TestValidate_EnabledNeedsASearchBaseAndIdentityAttributes(t *testing.T) {
	cfg := &Config{Enabled: true, URL: "ldap://dir", Timeout: time.Second, UserFilter: "(mail=%s)"}
	problems := Validate(cfg)
	for _, key := range []string{"ldap.baseDN", "ldap.attrUniqueId", "ldap.attrUsername"} {
		if _, ok := problems[key]; !ok {
			t.Errorf("expected a problem for %s, got %+v", key, problems)
		}
	}
}

func TestValidate_RejectsAnUnknownLinkPolicyAndABareAttribute(t *testing.T) {
	cfg := &Config{URL: "ldap://dir", Timeout: time.Second, LinkPolicy: "merge", AttrUsername: "sAM Account"}
	problems := Validate(cfg)
	if problems["ldap.linkPolicy"].Code != "link_policy_invalid" {
		t.Errorf("expected a link policy error, got %+v", problems["ldap.linkPolicy"])
	}
	if problems["ldap.attrUsername"].Code != "attr_invalid" {
		t.Errorf("expected an attribute error, got %+v", problems["ldap.attrUsername"])
	}
}

func TestValidate_RejectsAGroupThatIsNotADN(t *testing.T) {
	cfg := &Config{URL: "ldap://dir", Timeout: time.Second, LinkPolicy: LinkPolicyAuto, RequiredGroupDN: "myriadmind-users"}
	if got := Validate(cfg)["ldap.requiredGroupDN"].Code; got != "group_dn_invalid" {
		t.Fatalf("code = %q, want group_dn_invalid", got)
	}
}
