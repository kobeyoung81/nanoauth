package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

// stubConfigBus serves the one endpoint the loader reads, with the items (or the
// failure) a test asks for.
func stubConfigBus(t *testing.T, items map[string]string, fail bool, calls *int) *bus.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			*calls++
		}
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		payload := map[string]any{"component_type": "auth"}
		list := []map[string]string{}
		for key, value := range items {
			list = append(list, map[string]string{"key": key, "value": value})
		}
		payload["items"] = list
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(srv.Close)
	return bus.New(srv.URL, "test-token")
}

func TestParseConfig_Defaults(t *testing.T) {
	cfg := parseConfig(map[string]string{})

	if cfg.Enabled {
		t.Error("an empty configuration must leave the directory login off")
	}
	if cfg.URL != "ldap://127.0.0.1:389" {
		t.Errorf("unexpected url %q", cfg.URL)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("unexpected timeout %v", cfg.Timeout)
	}
	if cfg.UserFilter != "(&(objectClass=user)(mail=%s))" {
		t.Errorf("unexpected user filter %q", cfg.UserFilter)
	}
	if cfg.AttrUniqueID != "objectGUID" || cfg.AttrUsername != "sAMAccountName" || cfg.AttrDisplayName != "displayName" {
		t.Errorf("unexpected attributes %q/%q/%q", cfg.AttrUniqueID, cfg.AttrUsername, cfg.AttrDisplayName)
	}
	if !cfg.AutoProvision {
		t.Error("provisioning must default to on")
	}
}

func TestParseConfig_StoredValues(t *testing.T) {
	cfg := parseConfig(map[string]string{
		"ldap.enabled":               "true",
		"ldap.url":                   "ldaps://dir.corp.local:636",
		"ldap.startTLS":              "true",
		"ldap.tlsInsecureSkipVerify": "yes",
		"ldap.caCertPEM":             "-----BEGIN CERTIFICATE-----",
		"ldap.timeoutSeconds":        "25",
		"ldap.baseDN":                "dc=corp,dc=local",
		"ldap.userFilter":            "(&(objectClass=inetOrgPerson)(mail=%s))",
		"ldap.requiredGroupDN":       "cn=myriadmind-users,dc=corp,dc=local",
		"ldap.groupMatchInChain":     "true",
		"ldap.bindDN":                "cn=admin,dc=corp,dc=local",
		"ldap.bindPassword":          "adminpassword",
		"ldap.attrUniqueId":          "entryUUID",
		"ldap.attrUsername":          "uid",
		"ldap.attrDisplayName":       "cn",
		"ldap.autoProvision":         "false",
	})

	if !cfg.Enabled {
		t.Error("expected enabled")
	}
	if cfg.URL != "ldaps://dir.corp.local:636" {
		t.Errorf("unexpected url %q", cfg.URL)
	}
	if !cfg.StartTLS || !cfg.InsecureSkipVerify || !cfg.GroupMatchInChain {
		t.Error("expected the boolean settings to be on")
	}
	if cfg.Timeout != 25*time.Second {
		t.Errorf("unexpected timeout %v", cfg.Timeout)
	}
	if cfg.BaseDN != "dc=corp,dc=local" || cfg.BindDN != "cn=admin,dc=corp,dc=local" || cfg.BindPassword != "adminpassword" {
		t.Error("unexpected bind settings")
	}
	if cfg.RequiredGroupDN != "cn=myriadmind-users,dc=corp,dc=local" {
		t.Errorf("unexpected group %q", cfg.RequiredGroupDN)
	}
	if cfg.AttrUniqueID != "entryUUID" || cfg.AttrUsername != "uid" || cfg.AttrDisplayName != "cn" {
		t.Error("unexpected attributes")
	}
	if cfg.AutoProvision {
		t.Error("expected provisioning to be off")
	}
}

func TestLoader_NoRowsMeansNotConfigured(t *testing.T) {
	client := stubConfigBus(t, map[string]string{"paths.skillsDir": "x"}, false, nil)

	cfg, err := NewLoader(client).Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected a nil config when no ldap.* row exists")
	}
}

func TestLoader_CachesWithinTTL(t *testing.T) {
	calls := 0
	client := stubConfigBus(t, map[string]string{"ldap.enabled": "true", "ldap.baseDN": "dc=corp,dc=local"}, false, &calls)

	loader := NewLoader(client)
	for i := 0; i < 3; i++ {
		cfg, err := loader.Load(context.Background())
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		if cfg == nil || !cfg.Enabled {
			t.Fatalf("load %d: unexpected config %+v", i, cfg)
		}
	}
	// Three loads, one read: the cache is the point of the loader.
	if calls != 1 {
		t.Fatalf("the loader called the bus %d times, want 1", calls)
	}
}

func TestLoader_ReadFailureKeepsTheLastConfiguration(t *testing.T) {
	calls := 0
	client := stubConfigBus(t, map[string]string{"ldap.enabled": "true"}, false, &calls)
	loader := NewLoader(client)

	if _, err := loader.Load(context.Background()); err != nil {
		t.Fatalf("first load: %v", err)
	}

	// Now the bus answers 500: a failing read must fall back to what is cached,
	// because a config blip must not lock every user out.
	loader.bus = stubConfigBus(t, nil, true, nil)
	loader.ttl = 0 // force a re-read
	cfg, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("a failing read must fall back to the cache: %v", err)
	}
	if cfg == nil || !cfg.Enabled {
		t.Fatalf("expected the cached configuration, got %+v", cfg)
	}
}

func TestLoader_ReadFailureWithoutCacheIsReported(t *testing.T) {
	client := stubConfigBus(t, nil, true, nil)

	cfg, err := NewLoader(client).Load(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if cfg != nil {
		t.Fatalf("expected no configuration, got %+v", cfg)
	}
}
