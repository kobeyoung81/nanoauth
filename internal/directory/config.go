package directory

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
)

// Config holds the directory settings. They live in service_config_items under
// component 'auth' with the 'ldap.' prefix so the portal's config center can
// edit them; nanoauth/README.md documents every key.
type Config struct {
	Enabled            bool
	URL                string
	StartTLS           bool
	InsecureSkipVerify bool
	CACertPEM          string
	Timeout            time.Duration
	BaseDN             string
	UserFilter         string
	RequiredGroupDN    string
	GroupMatchInChain  bool
	BindDN             string
	BindPassword       string
	AttrUniqueID       string
	AttrUsername       string
	AttrDisplayName    string
	AutoProvision      bool
	// LinkPolicy decides what happens when the directory vouches for an email
	// that already has a local account: "auto" links the two, "refuse" leaves
	// the account alone and rejects the login.
	LinkPolicy string
	// DisableOnMissing suspends a directory-linked account whose entry has
	// disappeared from the directory (a departed employee).
	DisableOnMissing bool
	// SyncDisplayName refreshes the platform display name from the directory on
	// every successful login.
	SyncDisplayName bool
}

// Link policies for Config.LinkPolicy.
const (
	LinkPolicyAuto   = "auto"
	LinkPolicyRefuse = "refuse"
)

// ConfigSource returns the directory settings currently in force. A nil Config
// and a nil error together mean the directory login is not configured at all.
type ConfigSource interface {
	Load(ctx context.Context) (*Config, error)
}

// DefaultTTL bounds how long an edited setting may take to be picked up.
const DefaultTTL = 30 * time.Second

// Loader reads the settings from the shared config store and caches them for
// DefaultTTL, so an edit made in the portal takes effect without restarting
// nanoauth.
//
// The configuration lives in the admin module: this service reads its own
// component back over HTTP, from the same store the console edits.
type Loader struct {
	bus *bus.Client
	ttl time.Duration

	mu        sync.Mutex
	cached    *Config
	cachedAt  time.Time
	haveCache bool
}

func NewLoader(client *bus.Client) *Loader {
	return &Loader{bus: client, ttl: DefaultTTL}
}

// Load returns the settings in force. A stale copy is preferred over an error:
// a failing config read must not lock every user out, and an unusable
// configuration is reported by Authenticate as ErrUnavailable instead.
func (l *Loader) Load(ctx context.Context) (*Config, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.haveCache && time.Since(l.cachedAt) < l.ttl {
		return l.cached, nil
	}

	cfg, err := l.read(ctx)
	if err != nil {
		if l.haveCache {
			return l.cached, nil
		}
		return nil, err
	}
	l.cached, l.cachedAt, l.haveCache = cfg, time.Now(), true
	return cfg, nil
}

// CachedAt reports when the settings in force were read, so the portal can show
// whether a saved edit has been picked up yet.
func (l *Loader) CachedAt() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cachedAt, l.haveCache
}

// read returns nil when no ldap.* row exists, which means the feature is off.
func (l *Loader) read(ctx context.Context) (*Config, error) {
	var payload struct {
		Items []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"items"`
	}
	path := "/api/v1/config/" + url.PathEscape(component)
	if err := l.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return nil, fmt.Errorf("query ldap config: %w", err)
	}

	values := map[string]string{}
	for _, item := range payload.Items {
		if strings.HasPrefix(item.Key, "ldap.") {
			values[item.Key] = item.Value
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	return parseConfig(values), nil
}

// component is the configuration component nanoauth owns.
const component = "auth"

// parseConfig fills the gaps a missing or blank row would leave with the
// defaults seeded by `nanobus config seed` (Active Directory values).
func parseConfig(values map[string]string) *Config {
	return &Config{
		Enabled:            boolValue(values["ldap.enabled"], false),
		URL:                stringValue(values["ldap.url"], "ldap://127.0.0.1:389"),
		StartTLS:           boolValue(values["ldap.startTLS"], false),
		InsecureSkipVerify: boolValue(values["ldap.tlsInsecureSkipVerify"], false),
		CACertPEM:          values["ldap.caCertPEM"],
		Timeout:            time.Duration(intValue(values["ldap.timeoutSeconds"], 10)) * time.Second,
		BaseDN:             strings.TrimSpace(values["ldap.baseDN"]),
		UserFilter:         strings.TrimSpace(stringValue(values["ldap.userFilter"], "(&(objectClass=user)(mail=%s))")),
		RequiredGroupDN:    strings.TrimSpace(values["ldap.requiredGroupDN"]),
		GroupMatchInChain:  boolValue(values["ldap.groupMatchInChain"], false),
		BindDN:             strings.TrimSpace(values["ldap.bindDN"]),
		BindPassword:       values["ldap.bindPassword"],
		AttrUniqueID:       stringValue(values["ldap.attrUniqueId"], "objectGUID"),
		AttrUsername:       stringValue(values["ldap.attrUsername"], "sAMAccountName"),
		AttrDisplayName:    stringValue(values["ldap.attrDisplayName"], "displayName"),
		AutoProvision:      boolValue(values["ldap.autoProvision"], true),
		LinkPolicy:         stringValue(values["ldap.linkPolicy"], LinkPolicyAuto),
		DisableOnMissing:   boolValue(values["ldap.disableOnMissing"], false),
		SyncDisplayName:    boolValue(values["ldap.syncDisplayName"], false),
	}
}

func stringValue(raw, fallback string) string {
	if trimmed := strings.TrimSpace(raw); trimmed != "" {
		return trimmed
	}
	return fallback
}

func boolValue(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return fallback
}

func intValue(raw string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
		return n
	}
	return fallback
}
