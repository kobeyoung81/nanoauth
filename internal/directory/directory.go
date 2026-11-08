// Package directory authenticates platform users against an external LDAP
// directory (Active Directory or OpenLDAP).
//
// A successful bind is the only identity proof the platform asks for: the local
// password of a directory-managed account is never consulted, and the platform
// never writes to the directory. The directory unique id — kept in
// oauth_providers as provider_id with provider='ldap' — links the two sides, so
// an entry that moves to another OU keeps its platform account.
package directory

import (
	"context"
	"errors"
)

// The failures are deliberately distinct: "the entry is not there", "the
// password is wrong" and "the directory cannot be reached" lead to different
// login outcomes (fall back to the local password, refuse, or answer 503).
var (
	// ErrEntryNotFound reports that no entry matched the email.
	ErrEntryNotFound = errors.New("directory entry not found")
	// ErrInvalidCredentials reports that the entry exists but the bind failed.
	ErrInvalidCredentials = errors.New("directory invalid credentials")
	// ErrMultipleEntries reports that the email matched more than one entry.
	ErrMultipleEntries = errors.New("directory multiple entries")
	// ErrUnavailable reports a configuration, connection, TLS or protocol error.
	ErrUnavailable = errors.New("directory unavailable")
	// ErrInvalidFilter reports a search filter the directory could not parse.
	ErrInvalidFilter = errors.New("directory invalid filter")
)

// Entry is the directory record needed to create or link a platform account.
type Entry struct {
	UniqueID    string
	DN          string
	Username    string
	DisplayName string
}

// Directory verifies an email/password pair against a configured directory.
type Directory interface {
	Authenticate(ctx context.Context, cfg *Config, email, password string) (*Entry, error)
}

// Console is the read-only diagnostic surface of the portal's directory login
// console: probe the connection, walk the tree, sample a search base, and dry
// run one login. None of it writes to the directory, to the platform's tables
// or to the audit log — the console exists to explain a configuration, not to
// change one.
type Console interface {
	Probe(ctx context.Context, cfg *Config) *ProbeResult
	Browse(ctx context.Context, cfg *Config, baseDN string, limit int) (*BrowseResult, error)
	Analyze(ctx context.Context, cfg *Config, baseDN string, sampleCap int) (*AnalyzeResult, error)
	CheckEntry(ctx context.Context, cfg *Config, email, password string) (*CheckResult, error)
	Search(ctx context.Context, cfg *Config, baseDN, filter string, limit int) (*BrowseResult, error)
}
