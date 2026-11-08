package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// adInChainMatchingRule is how Active Directory resolves nested group
// membership, which the plain memberOf attribute does not cover.
const adInChainMatchingRule = "1.2.840.113556.1.4.1941"

// Client verifies passwords against a directory.
//
// Every attempt opens its own connection: logins are rare, and a pooled
// connection would need its own liveness handling for little gain.
type Client struct{}

func NewClient() *Client { return &Client{} }

// Authenticate searches for the entry matching email, binds with the entry's
// own DN and the supplied password, and returns the record the platform needs.
func (c *Client) Authenticate(_ context.Context, cfg *Config, email, password string) (*Entry, error) {
	if email == "" || password == "" {
		// An empty password must never reach a directory: LDAP answers a simple
		// bind carrying no password as an anonymous bind, which succeeds.
		return nil, ErrInvalidCredentials
	}
	if cfg == nil || cfg.URL == "" || cfg.BaseDN == "" || cfg.UserFilter == "" {
		return nil, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}

	conn, err := dial(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()

	// Searching may need a service account; an empty bind DN means the search
	// runs anonymously.
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("%w: search bind failed: %v", ErrUnavailable, err)
		}
	}

	result, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     cfg.BaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     BuildFilter(cfg, email),
		Attributes: searchAttributes(cfg),
		SizeLimit:  2,
	})
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrMultipleEntries
		}
		return nil, fmt.Errorf("%w: search failed: %v", ErrUnavailable, err)
	}
	switch len(result.Entries) {
	case 0:
		return nil, ErrEntryNotFound
	case 1:
	default:
		// An ambiguous match is refused rather than resolved by picking one.
		return nil, ErrMultipleEntries
	}

	found := result.Entries[0]
	if err := conn.Bind(found.DN, password); err != nil {
		// The server answered, so the entry exists and only the password can be
		// wrong. A transport failure is reported as unavailable instead.
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: bind failed: %v", ErrUnavailable, err)
	}

	return &Entry{
		UniqueID:    uniqueID(found, cfg),
		DN:          found.DN,
		Username:    found.GetAttributeValue(cfg.AttrUsername),
		DisplayName: displayName(found, cfg),
	}, nil
}

// BuildFilter renders the configured search filter for an email. The value is
// escaped (RFC 4515) so a literal '*' cannot turn into a match-anything
// wildcard, and the group requirement is appended as a conjunction.
func BuildFilter(cfg *Config, email string) string {
	filter := strings.Replace(cfg.UserFilter, "%s", ldap.EscapeFilter(strings.ToLower(email)), 1)
	if cfg.RequiredGroupDN == "" {
		return filter
	}
	attribute := "memberOf"
	if cfg.GroupMatchInChain {
		attribute = "memberOf:" + adInChainMatchingRule + ":"
	}
	// The configured filter is itself a complete expression, so the group
	// requirement is simply conjoined with it.
	return "(&" + filter + "(" + attribute + "=" + ldap.EscapeFilter(cfg.RequiredGroupDN) + "))"
}

func searchAttributes(cfg *Config) []string {
	attrs := make([]string, 0, 3)
	for _, attr := range []string{cfg.AttrUniqueID, cfg.AttrUsername, cfg.AttrDisplayName} {
		if attr != "" {
			attrs = append(attrs, attr)
		}
	}
	return attrs
}

// uniqueID returns the stable key for the account. Binary values such as Active
// Directory's objectGUID are hex encoded. Entries without the configured
// attribute fall back to the login name, which survives an OU move, and only
// then to the DN, which does not.
func uniqueID(entry *ldap.Entry, cfg *Config) string {
	value, _ := resolveUniqueID(entry, cfg)
	return value
}

// resolveUniqueID is uniqueID plus the provenance, so the directory console can
// show which attribute actually carried the key.
func resolveUniqueID(entry *ldap.Entry, cfg *Config) (value, source string) {
	if value := rawAttribute(entry, cfg.AttrUniqueID); value != "" {
		return value, UniqueIDSourceAttribute
	}
	if value := entry.GetAttributeValue(cfg.AttrUsername); value != "" {
		slog.Warn("ldap: unique id attribute missing, falling back to the login name",
			"attribute", cfg.AttrUniqueID, "dn", entry.DN)
		return strings.ToLower(value), UniqueIDSourceUsername
	}
	slog.Warn("ldap: no unique id and no login name on entry, falling back to the DN", "dn", entry.DN)
	return strings.ToLower(entry.DN), UniqueIDSourceDN
}

// rawAttribute reads an attribute's raw bytes so binary values survive; text
// values are returned unchanged.
func rawAttribute(entry *ldap.Entry, attribute string) string {
	if attribute == "" {
		return ""
	}
	for _, raw := range entry.GetRawAttributeValues(attribute) {
		if len(raw) == 0 {
			continue
		}
		return stringify(raw)
	}
	return ""
}

// stringify renders raw attribute bytes: text stays text, binary identifiers
// (AD objectGUID) become hex. Both the login path and the directory console use
// it, so a value shown in the console is the value the login would store.
func stringify(raw []byte) string {
	if printable(raw) {
		return string(raw)
	}
	return hex.EncodeToString(raw)
}

// printable reports whether a value is text rather than a binary identifier.
// objectGUID values contain control bytes in practice; a value that is valid
// UTF-8 with no control characters is treated as text.
func printable(value []byte) bool {
	for _, b := range value {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return utf8.Valid(value)
}

func displayName(entry *ldap.Entry, cfg *Config) string {
	if value := entry.GetAttributeValue(cfg.AttrDisplayName); value != "" {
		return value
	}
	return entry.GetAttributeValue(cfg.AttrUsername)
}

// dial opens the connection and applies the TLS settings. The TLS config is
// only consulted for ldaps:// URLs and for an explicit StartTLS upgrade.
func dial(cfg *Config) (*ldap.Conn, error) {
	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}

	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: cfg.Timeout})}
	if tlsCfg != nil {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}

	conn, err := ldap.DialURL(cfg.URL, opts...)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(cfg.Timeout)

	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func tlsConfig(cfg *Config) (*tls.Config, error) {
	if !cfg.StartTLS && !cfg.InsecureSkipVerify && cfg.CACertPEM == "" && !strings.HasPrefix(cfg.URL, "ldaps://") {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // opt-in for self-signed intranet directories
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, errors.New("ldap.caCertPEM holds no usable certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if host := serverName(cfg.URL); host != "" {
		tlsCfg.ServerName = host
	}
	return tlsCfg, nil
}

// serverName extracts the host of the directory URL for certificate checking.
func serverName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
