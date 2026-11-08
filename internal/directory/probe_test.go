package directory

import "testing"

// The console's verdicts are pure functions over what the directory answered, so
// the rules that drive its suggestions are pinned here rather than against a
// live server.

func TestDescribeServer_RecognisesTheFlavour(t *testing.T) {
	ad, adPreset := DescribeServer(map[string][]string{
		"vendorName":           {"Microsoft Windows Active Directory"},
		"defaultNamingContext": {"DC=corp,DC=local"},
		"supportedLDAPVersion": {"3"},
		"namingContexts":       {"DC=corp,DC=local"},
		"supportedControl":     {"1.2.840.113556.1.4.319"},
	})
	if ad != KindAD {
		t.Fatalf("kind = %q, want ad", ad)
	}
	if adPreset.AttrUniqueID != "objectGUID" || adPreset.AttrUsername != "sAMAccountName" || adPreset.AttrDisplayName != "displayName" {
		t.Fatalf("unexpected AD preset %+v", adPreset)
	}
	if adPreset.UserFilter != "(&(objectClass=user)(mail=%s))" {
		t.Fatalf("unexpected AD filter %q", adPreset.UserFilter)
	}

	openldap, openPreset := DescribeServer(map[string][]string{
		"vendorName":           {"OpenLDAP"},
		"namingContexts":       {"dc=corp,dc=local"},
		"supportedLDAPVersion": {"3"},
	})
	if openldap != KindOpenLDAP {
		t.Fatalf("kind = %q, want openldap", openldap)
	}
	if openPreset.AttrUniqueID != "entryUUID" || openPreset.AttrUsername != "uid" || openPreset.AttrDisplayName != "cn" {
		t.Fatalf("unexpected OpenLDAP preset %+v", openPreset)
	}

	unknown, unknownPreset := DescribeServer(map[string][]string{"supportedLDAPVersion": {"3"}})
	if unknown != KindUnknown {
		t.Fatalf("kind = %q, want unknown", unknown)
	}
	if unknownPreset.UserFilter != "" {
		t.Fatalf("an unknown directory must not suggest a preset, got %+v", unknownPreset)
	}
}

func TestLabelFor_PrefersTheDescriptionAndNamesTheType(t *testing.T) {
	label, kind := LabelFor("ou=研发部,dc=corp,dc=local", map[string][]string{
		"ou":          {"研发部"},
		"description": {"研发部门（含平台组与测试组）"},
		"objectClass": {"top", "organizationalUnit"},
	})
	if label != "研发部门（含平台组与测试组）" {
		t.Fatalf("label = %q, want the description", label)
	}
	if kind != "organizational_unit" {
		t.Fatalf("kind = %q, want organizational_unit", kind)
	}

	label, kind = LabelFor("uid=alice,dc=corp,dc=local", map[string][]string{
		"cn":          {"Alice Zhang"},
		"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
	})
	if label != "Alice Zhang" || kind != "user" {
		t.Fatalf("got %q/%q, want Alice Zhang/user", label, kind)
	}

	label, kind = LabelFor("cn=myriadmind-users,dc=corp,dc=local", map[string][]string{
		"cn":          {"myriadmind-users"},
		"objectClass": {"top", "groupOfNames"},
	})
	if label != "myriadmind-users" || kind != "group" {
		t.Fatalf("got %q/%q, want myriadmind-users/group", label, kind)
	}
}

func TestLabelFor_RendersANamingContextAsADomain(t *testing.T) {
	label, _ := LabelFor("dc=corp,dc=local", nil)
	if label != "corp.local" {
		t.Fatalf("label = %q, want corp.local", label)
	}
}

func TestAnalyzeEntries_CountsPresenceDuplicatesAndMasksExamples(t *testing.T) {
	samples := []sampleEntry{
		{DN: "uid=a", Values: map[string][]string{"mail": {"a@corp.local"}, "entryuuid": {"1"}}},
		{DN: "uid=b", Values: map[string][]string{"mail": {"shared@corp.local"}, "entryuuid": {"2"}}},
		{DN: "uid=c", Values: map[string][]string{"mail": {"shared@corp.local"}, "entryuuid": {"3"}}},
		{DN: "uid=d", Values: map[string][]string{"entryuuid": {"4"}}},
	}

	stats := AnalyzeEntries(samples, []string{"mail", "entryuuid", "sAMAccountName"})
	byName := map[string]AttributeStat{}
	for _, stat := range stats {
		byName[stat.Attribute] = stat
	}

	if byName["mail"].Present != 3 || byName["mail"].Samples != 4 {
		t.Fatalf("mail presence = %d/%d, want 3/4", byName["mail"].Present, byName["mail"].Samples)
	}
	if byName["mail"].Distinct != 2 || byName["mail"].Duplicates != 1 {
		t.Fatalf("mail distinct/duplicates = %d/%d, want 2/1", byName["mail"].Distinct, byName["mail"].Duplicates)
	}
	if len(byName["mail"].Examples) != 1 || byName["mail"].Examples[0] == "shared@corp.local" {
		t.Fatalf("a duplicate example must be masked, got %v", byName["mail"].Examples)
	}
	if byName["entryuuid"].Duplicates != 0 {
		t.Fatalf("entryUUID must look unique, got %+v", byName["entryuuid"])
	}
	if byName["sAMAccountName"].Present != 0 {
		t.Fatalf("an absent attribute must be reported as absent, got %+v", byName["sAMAccountName"])
	}
}

func TestRecommend_MatchesOnTheUniqueEmail(t *testing.T) {
	samples := []sampleEntry{
		{Values: map[string][]string{"objectclass": {"person", "inetOrgPerson"}, "mail": {"a@corp"}, "entryuuid": {"1"}, "uid": {"a"}, "cn": {"A"}}},
		{Values: map[string][]string{"objectclass": {"person", "inetOrgPerson"}, "mail": {"b@corp"}, "entryuuid": {"2"}, "uid": {"b"}, "cn": {"B"}}},
	}
	stats := AnalyzeEntries(samples, candidateAttributes)
	recs := recommendationsByKey(Recommend(samples, stats))

	if got := recs["ldap.userFilter"].Value; got != "(&(objectClass=inetOrgPerson)(mail=%s))" {
		t.Fatalf("user filter = %q", got)
	}
	if recs["ldap.userFilter"].Reason != "mail_unique" {
		t.Fatalf("reason = %q, want mail_unique", recs["ldap.userFilter"].Reason)
	}
	if recs["ldap.attrUniqueId"].Value != "entryUUID" {
		t.Fatalf("unique id = %q, want entryUUID", recs["ldap.attrUniqueId"].Value)
	}
	if recs["ldap.attrUsername"].Value != "uid" || recs["ldap.attrDisplayName"].Value != "cn" {
		t.Fatalf("unexpected username/display name %+v", recs)
	}
}

// A duplicate mail is the case that produces "I configured mail and nobody can
// sign in": the console must point at another attribute instead of congratulating
// the operator on a filter that cannot work.
func TestRecommend_SwitchesAwayFromADuplicateMail(t *testing.T) {
	samples := []sampleEntry{
		{Values: map[string][]string{"objectclass": {"user", "person"}, "mail": {"shared@corp"}, "userprincipalname": {"a@corp"}, "objectguid": {"1"}}},
		{Values: map[string][]string{"objectclass": {"user", "person"}, "mail": {"shared@corp"}, "userprincipalname": {"b@corp"}, "objectguid": {"2"}}},
	}
	stats := AnalyzeEntries(samples, candidateAttributes)
	recs := recommendationsByKey(Recommend(samples, stats))

	if recs["ldap.userFilter"].Reason != "mail_duplicated" {
		t.Fatalf("reason = %q, want mail_duplicated", recs["ldap.userFilter"].Reason)
	}
	if got := recs["ldap.userFilter"].Value; got != "(&(objectClass=user)(userPrincipalName=%s))" {
		t.Fatalf("user filter = %q", got)
	}
	if recs["ldap.attrUniqueId"].Value != "objectGUID" {
		t.Fatalf("unique id = %q, want objectGUID", recs["ldap.attrUniqueId"].Value)
	}
}

func TestRecommend_WarnsWhenNoStableKeyExists(t *testing.T) {
	samples := []sampleEntry{
		{Values: map[string][]string{"objectclass": {"person", "inetOrgPerson"}, "mail": {"a@corp"}, "uid": {"a"}}},
	}
	stats := AnalyzeEntries(samples, candidateAttributes)
	recs := recommendationsByKey(Recommend(samples, stats))

	key, ok := recs["ldap.attrUniqueId"]
	if !ok {
		t.Fatal("expected a recommendation for the unique id")
	}
	if key.Level != "warning" || key.Value != "" {
		t.Fatalf("expected a warning without a value, got %+v", key)
	}
	if key.Reason != "no_unique_identifier" {
		t.Fatalf("reason = %q", key.Reason)
	}
}

func TestMemberCount_CountsEveryGroupFlavour(t *testing.T) {
	if got := memberCount(map[string][]string{"member": {"a", "b"}}); got != 2 {
		t.Fatalf("members = %d, want 2", got)
	}
	if got := memberCount(map[string][]string{"memberUid": {"a"}}); got != 1 {
		t.Fatalf("memberUid = %d, want 1", got)
	}
	if got := memberCount(map[string][]string{"cn": {"not-a-group"}}); got != 0 {
		t.Fatalf("members = %d, want 0", got)
	}
}

func TestIsContainerKind(t *testing.T) {
	for kind, want := range map[string]bool{
		"organizational_unit": true,
		"container":           true,
		"naming_context":      true,
		"user":                false,
		"group":               false,
	} {
		if got := IsContainerKind(kind); got != want {
			t.Errorf("IsContainerKind(%q) = %v, want %v", kind, got, want)
		}
	}
}

func recommendationsByKey(recs []Recommendation) map[string]Recommendation {
	byKey := map[string]Recommendation{}
	for _, rec := range recs {
		byKey[rec.Key] = rec
	}
	return byKey
}
