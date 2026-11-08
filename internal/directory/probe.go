package directory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// The console probes the directory with bounded work: a tree level and a
// statistical sample must never turn into a full-directory read.
const (
	DefaultBrowseLimit = 200
	MaxBrowseLimit     = 500
	DefaultSampleCap   = 500
)

// candidateAttributes is the fixed, ordered set the console reports statistics
// for. The order is part of the API (the table renders in this order).
var candidateAttributes = []string{
	"mail", "userPrincipalName", "sAMAccountName", "uid", "cn", "displayName",
	"givenName", "sn", "objectGUID", "entryUUID", "memberOf",
}

// fieldPages are the attributes the console resolves for diagnostics.
var entryAttributes = []string{"mail", "userPrincipalName", "sAMAccountName", "uid", "cn", "displayName", "sn", "memberOf"}

// Unique id sources reported by CheckEntry.
const (
	UniqueIDSourceAttribute = "attribute"
	UniqueIDSourceUsername  = "username"
	UniqueIDSourceDN        = "dn"
)

// Step names of a connection probe.
const (
	StepDNS     = "dns"
	StepTCP     = "tcp"
	StepTLS     = "tls"
	StepBind    = "bind"
	StepRootDSE = "root_dse"
)

// Step statuses.
const (
	StepOK      = "ok"
	StepSkipped = "skipped"
	StepFailed  = "failed"
)

// Directory kinds.
const (
	KindAD       = "ad"
	KindOpenLDAP = "openldap"
	KindUnknown  = "unknown"
)

// Preset is the set of settings a detected directory kind suggests.
type Preset struct {
	Kind            string `json:"kind"`
	UserFilter      string `json:"user_filter"`
	AttrUniqueID    string `json:"attr_unique_id"`
	AttrUsername    string `json:"attr_username"`
	AttrDisplayName string `json:"attr_display_name"`
}

// StepResult is one line of the connection probe.
type StepResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

// ProbeResult is the outcome of the connection probe.
type ProbeResult struct {
	OK                bool         `json:"ok"`
	Kind              string       `json:"kind"`
	Vendor            string       `json:"vendor,omitempty"`
	VendorVersion     string       `json:"vendor_version,omitempty"`
	AuthDN            string       `json:"auth_dn,omitempty"`
	Anonymous         bool         `json:"anonymous"`
	NamingContexts    []string     `json:"naming_contexts,omitempty"`
	SupportedVersions []string     `json:"supported_ldap_versions,omitempty"`
	PagedResults      bool         `json:"paged_results"`
	Preset            Preset       `json:"preset"`
	Steps             []StepResult `json:"steps"`
}

// BrowseNode is one row of the directory tree.
type BrowseNode struct {
	DN           string `json:"dn"`
	Label        string `json:"label"`
	Kind         string `json:"kind"`
	Description  string `json:"description,omitempty"`
	HasChildren  bool   `json:"has_children"`
	Subordinates int    `json:"subordinates,omitempty"`
	Members      int    `json:"members,omitempty"`
}

// BrowseResult is one tree level.
type BrowseResult struct {
	BaseDN         string       `json:"base_dn"`
	Kind           string       `json:"kind"`
	NamingContexts []string     `json:"naming_contexts,omitempty"`
	Nodes          []BrowseNode `json:"nodes"`
	Truncated      bool         `json:"truncated"`
}

// AttributeStat describes one candidate attribute across the sample.
type AttributeStat struct {
	Attribute  string   `json:"attribute"`
	Present    int      `json:"present"`
	Samples    int      `json:"samples"`
	Distinct   int      `json:"distinct"`
	Duplicates int      `json:"duplicates"`
	Examples   []string `json:"examples,omitempty"`
}

// Recommendation is one suggested setting. An empty Value marks a warning the
// console shows without an apply action.
type Recommendation struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
	Level  string `json:"level"`
}

// AnalyzeResult is the statistical view of a search base.
type AnalyzeResult struct {
	BaseDN          string           `json:"base_dn"`
	Kind            string           `json:"kind"`
	Samples         int              `json:"samples"`
	Truncated       bool             `json:"truncated"`
	ClassCounts     map[string]int   `json:"class_counts"`
	Attributes      []AttributeStat  `json:"attributes"`
	Recommendations []Recommendation `json:"recommendations"`
}

// CheckResult is a dry run of a directory login: everything the real login
// would learn, with nothing written anywhere.
type CheckResult struct {
	Filter         string            `json:"filter"`
	MatchCount     int               `json:"match_count"`
	DN             string            `json:"dn,omitempty"`
	Username       string            `json:"username,omitempty"`
	DisplayName    string            `json:"display_name,omitempty"`
	UniqueID       string            `json:"unique_id,omitempty"`
	UniqueIDSource string            `json:"unique_id_source,omitempty"`
	GroupRequired  string            `json:"group_required,omitempty"`
	GroupOK        bool              `json:"group_ok"`
	BindAttempted  bool              `json:"bind_attempted"`
	Bound          bool              `json:"bound"`
	BindError      string            `json:"bind_error,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// sampleEntry is one directory entry reduced to the values the console needs.
type sampleEntry struct {
	DN     string
	Values map[string][]string
}

// values reads an attribute's values regardless of how the caller spelled it:
// the candidate list uses directory casing (userPrincipalName) while the
// analysis stores keys lowercased.
func (s sampleEntry) values(attribute string) []string {
	if values, ok := s.Values[attribute]; ok {
		return values
	}
	for key, values := range s.Values {
		if strings.EqualFold(key, attribute) {
			return values
		}
	}
	return nil
}

// ======== pure helpers ========

// DescribeServer decides which directory software answers, from its root DSE.
func DescribeServer(dse map[string][]string) (string, Preset) {
	first := func(name string) string {
		if values := dse[name]; len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
		return ""
	}

	vendor := first("vendorName")
	switch {
	case strings.Contains(strings.ToLower(vendor), "microsoft") || first("defaultNamingContext") != "":
		return KindAD, Preset{
			Kind:            KindAD,
			UserFilter:      "(&(objectClass=user)(mail=%s))",
			AttrUniqueID:    "objectGUID",
			AttrUsername:    "sAMAccountName",
			AttrDisplayName: "displayName",
		}
	case strings.Contains(strings.ToLower(vendor), "openldap") || first("namingContexts") != "":
		return KindOpenLDAP, Preset{
			Kind:            KindOpenLDAP,
			UserFilter:      "(&(objectClass=inetOrgPerson)(mail=%s))",
			AttrUniqueID:    "entryUUID",
			AttrUsername:    "uid",
			AttrDisplayName: "cn",
		}
	}
	return KindUnknown, Preset{Kind: KindUnknown}
}

// LabelFor turns a DN plus its attributes into a human readable row: the
// description when the directory carries one, otherwise the naming attribute.
func LabelFor(dn string, attrs map[string][]string) (label, kind string) {
	read := func(name string) string {
		for key, values := range attrs {
			if strings.EqualFold(key, name) && len(values) > 0 {
				return strings.TrimSpace(values[0])
			}
		}
		return ""
	}

	kind = classify(attrs)
	for _, candidate := range []string{"description", "cn", "ou", "o"} {
		if value := read(candidate); value != "" {
			label = value
			break
		}
	}
	if label == "" {
		label = domainLabel(dn)
	}
	if label == "" {
		label = dn
	}
	return label, kind
}

// domainLabel renders a DN built only from dc components as a domain name, so a
// naming context reads as "corp.local" rather than its first component.
func domainLabel(dn string) string {
	parts := strings.Split(dn, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || !strings.EqualFold(key, "dc") {
			return ""
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ".")
}

// classify maps an entry's objectClass values to the console's vocabulary.
func classify(attrs map[string][]string) string {
	classes := map[string]bool{}
	for _, raw := range attrs["objectClass"] {
		classes[strings.ToLower(strings.TrimSpace(raw))] = true
	}
	switch {
	case classes["organizationalunit"]:
		return "organizational_unit"
	case classes["container"]:
		return "container"
	case classes["group"] || classes["groupofnames"] || classes["groupofuniquenames"] || classes["posixgroup"]:
		return "group"
	case classes["user"] || classes["person"] || classes["inetorgperson"] || classes["organizationalperson"] || classes["posixaccount"]:
		return "user"
	case classes["domaindns"] || classes["domain"] || classes["dcobject"]:
		return "domain"
	case classes["organization"]:
		return "organization"
	}
	return "other"
}

// IsContainerKind reports whether a node may have children, used when the
// directory does not answer the hasSubordinates operational attribute.
func IsContainerKind(kind string) bool {
	switch kind {
	case "organizational_unit", "container", "domain", "organization", "naming_context":
		return true
	}
	return false
}

// AnalyzeEntries computes per-attribute presence and uniqueness over a sample.
func AnalyzeEntries(samples []sampleEntry, attributes []string) []AttributeStat {
	stats := make([]AttributeStat, 0, len(attributes))
	for _, attribute := range attributes {
		stat := AttributeStat{Attribute: attribute, Samples: len(samples)}
		counts := map[string]int{}
		for _, sample := range samples {
			values := sample.values(attribute)
			if len(values) == 0 {
				continue
			}
			stat.Present++
			for _, value := range values {
				counts[strings.ToLower(strings.TrimSpace(value))]++
			}
		}
		stat.Distinct = len(counts)
		duplicated := make([]string, 0, 4)
		for value, count := range counts {
			if count > 1 {
				stat.Duplicates++
				duplicated = append(duplicated, value)
			}
		}
		sort.Strings(duplicated)
		if len(duplicated) > 3 {
			duplicated = duplicated[:3]
		}
		for _, value := range duplicated {
			stat.Examples = append(stat.Examples, MaskValue(value))
		}
		stats = append(stats, stat)
	}
	return stats
}

// MaskValue keeps just enough of a value to recognise a duplicate without
// printing directory data in full.
func MaskValue(value string) string {
	runes := []rune(value)
	if len(runes) <= 2 {
		return strings.Repeat("•", len(runes))
	}
	return string(runes[:2]) + strings.Repeat("•", 3) + fmt.Sprintf("(%d)", len(runes))
}

// Recommend derives the settings the sample supports. Warnings (an empty Value)
// mark what no candidate attribute can carry.
func Recommend(samples []sampleEntry, stats []AttributeStat) []Recommendation {
	byName := map[string]AttributeStat{}
	for _, stat := range stats {
		byName[strings.ToLower(stat.Attribute)] = stat
	}
	unique := func(attribute string) bool {
		stat, ok := byName[attribute]
		return ok && stat.Samples > 0 && stat.Present == stat.Samples && stat.Duplicates == 0
	}
	present := func(attribute string) bool {
		stat, ok := byName[attribute]
		return ok && stat.Present > 0
	}

	classCounts := map[string]int{}
	for _, sample := range samples {
		for _, class := range sample.values("objectClass") {
			classCounts[strings.ToLower(class)]++
		}
	}

	recommendations := make([]Recommendation, 0, 5)

	objectClass := ""
	for _, candidate := range []string{"user", "inetorgperson", "person"} {
		if classCounts[candidate] > 0 {
			objectClass = candidate
			break
		}
	}
	if objectClass == "" {
		objectClass = "person"
	}
	if canonical, ok := map[string]string{"user": "user", "inetorgperson": "inetOrgPerson", "person": "person"}[objectClass]; ok {
		objectClass = canonical
	}

	// The attribute the login filter matches on. mail first, because the
	// platform identifier is the email.
	matchAttribute := ""
	matchReason := ""
	switch {
	case unique("mail"):
		matchAttribute, matchReason = "mail", "mail_unique"
	case present("mail") && byName["mail"].Duplicates > 0 && unique("userprincipalname"):
		matchAttribute, matchReason = "userPrincipalName", "mail_duplicated"
	case unique("userprincipalname"):
		matchAttribute, matchReason = "userPrincipalName", "user_principal_name_unique"
	case unique("samaccountname"):
		matchAttribute, matchReason = "sAMAccountName", "login_name_unique"
	case unique("uid"):
		matchAttribute, matchReason = "uid", "login_name_unique"
	}

	if matchAttribute == "" {
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.userFilter", Reason: "no_unique_match_attribute", Level: "warning",
		})
	} else {
		recommendations = append(recommendations, Recommendation{
			Key:    "ldap.userFilter",
			Value:  "(&(objectClass=" + objectClass + ")(" + matchAttribute + "=%s))",
			Reason: matchReason,
			Level:  "suggestion",
		})
	}

	// The stable account key.
	switch {
	case unique("objectguid"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUniqueId", Value: "objectGUID", Reason: "unique_id_present", Level: "suggestion",
		})
	case unique("entryuuid"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUniqueId", Value: "entryUUID", Reason: "unique_id_present", Level: "suggestion",
		})
	case present("objectguid") || present("entryuuid"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUniqueId", Value: "objectGUID", Reason: "unique_id_not_unique", Level: "warning",
		})
	default:
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUniqueId", Reason: "no_unique_identifier", Level: "warning",
		})
	}

	// The fallback account key and the display name.
	switch {
	case present("samaccountname"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUsername", Value: "sAMAccountName", Reason: "login_name_present", Level: "suggestion",
		})
	case present("uid"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUsername", Value: "uid", Reason: "login_name_present", Level: "suggestion",
		})
	case matchAttribute != "":
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrUsername", Value: matchAttribute, Reason: "login_name_missing", Level: "warning",
		})
	}

	switch {
	case present("displayname"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrDisplayName", Value: "displayName", Reason: "display_name_present", Level: "suggestion",
		})
	case present("cn"):
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrDisplayName", Value: "cn", Reason: "display_name_present", Level: "suggestion",
		})
	default:
		recommendations = append(recommendations, Recommendation{
			Key: "ldap.attrDisplayName", Reason: "no_display_name", Level: "warning",
		})
	}

	return recommendations
}

// ======== connections ========

// hostPort splits the configured URL into a host and the port a TCP probe uses.
func hostPort(cfg *Config) (string, string) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return "", ""
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	return parsed.Hostname(), port
}

// tlsWanted reports whether the TLS step has anything to check.
func tlsWanted(cfg *Config) bool {
	return cfg.StartTLS || cfg.InsecureSkipVerify || cfg.CACertPEM != "" || strings.HasPrefix(cfg.URL, "ldaps://")
}

// connect opens a connection and applies the service-account bind, which is
// what every read-only console operation needs. It mirrors Client.Authenticate:
// an empty bind DN means an anonymous search.
func connect(_ context.Context, cfg *Config) (*ldap.Conn, error) {
	conn, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("search bind failed: %w", err)
		}
	}
	return conn, nil
}

// rootDSE reads the directory's own entry.
func rootDSE(conn *ldap.Conn) (*ldap.Entry, error) {
	result, err := conn.Search(&ldap.SearchRequest{
		BaseDN: "",
		Scope:  ldap.ScopeBaseObject,
		Filter: "(objectClass=*)",
		Attributes: []string{
			"namingContexts", "vendorName", "vendorVersion", "supportedLDAPVersion",
			"supportedControl", "defaultNamingContext", "rootDomainNamingContext",
		},
	})
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, errors.New("the directory answered the root DSE search with no entry")
	}
	return result.Entries[0], nil
}

// dseMap flattens a root DSE entry into attribute → values.
func dseMap(entry *ldap.Entry) map[string][]string {
	out := map[string][]string{}
	for _, attribute := range entry.Attributes {
		values := make([]string, 0, len(attribute.Values))
		for _, value := range attribute.Values {
			values = append(values, value)
		}
		out[attribute.Name] = values
	}
	return out
}

// lc returns the lowercased value of a dse attribute.
func dseFirst(dse map[string][]string, name string) string {
	for key, values := range dse {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

// sample fetches at most limit entries, using the paged control when the
// directory supports it and falling back to a server-side size limit otherwise.
// truncated reports that the directory holds more entries than were read.
func sample(conn *ldap.Conn, req *ldap.SearchRequest, limit int) (*ldap.SearchResult, bool, error) {
	if limit <= 0 {
		limit = DefaultSampleCap
	}
	paged := *req
	paged.SizeLimit = 0
	paged.Controls = append(append([]ldap.Control{}, req.Controls...), ldap.NewControlPaging(uint32(limit)))

	result, err := conn.Search(&paged)
	if err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailableCriticalExtension) {
			return nil, false, err
		}
		plain := *req
		plain.SizeLimit = limit
		result, plainErr := conn.Search(&plain)
		if ldap.IsErrorWithCode(plainErr, ldap.LDAPResultSizeLimitExceeded) {
			return result, true, nil
		}
		return result, true, plainErr
	}

	truncated := false
	if control := ldap.FindControl(result.Controls, ldap.ControlTypePaging); control != nil {
		if paging, ok := control.(*ldap.ControlPaging); ok && len(paging.Cookie) > 0 {
			truncated = true
		}
	}
	return result, truncated, nil
}

// ======== console operations ========

// Probe runs the five-step connection check.
func (c *Client) Probe(ctx context.Context, cfg *Config) *ProbeResult {
	result := &ProbeResult{Steps: make([]StepResult, 0, 5), Kind: KindUnknown}
	if cfg == nil {
		cfg = &Config{}
	}

	host, port := hostPort(cfg)

	// 1. DNS
	start := time.Now()
	addresses, err := net.LookupHost(host)
	switch {
	case host == "":
		result.Steps = append(result.Steps, StepResult{Name: StepDNS, Status: StepFailed, Detail: "the URL carries no host", DurationMS: elapsed(start)})
	case err != nil:
		result.Steps = append(result.Steps, StepResult{Name: StepDNS, Status: StepFailed, Detail: err.Error(), DurationMS: elapsed(start)})
	default:
		result.Steps = append(result.Steps, StepResult{Name: StepDNS, Status: StepOK, Detail: strings.Join(addresses, ", "), DurationMS: elapsed(start)})
	}

	// 2. TCP
	start = time.Now()
	address := net.JoinHostPort(host, port)
	conn0, dialErr := net.DialTimeout("tcp", address, cfg.Timeout)
	if dialErr != nil {
		result.Steps = append(result.Steps, StepResult{Name: StepTCP, Status: StepFailed, Detail: dialErr.Error(), DurationMS: elapsed(start)})
	} else {
		_ = conn0.Close()
		result.Steps = append(result.Steps, StepResult{Name: StepTCP, Status: StepOK, Detail: address, DurationMS: elapsed(start)})
	}

	// 3. TLS (and the connection the next two steps reuse)
	var conn *ldap.Conn
	if !tlsWanted(cfg) {
		result.Steps = append(result.Steps, StepResult{Name: StepTLS, Status: StepSkipped, Detail: "plain ldap:// without StartTLS"})
	} else {
		start = time.Now()
		var err error
		conn, err = dial(cfg)
		if err != nil {
			result.Steps = append(result.Steps, StepResult{Name: StepTLS, Status: StepFailed, Detail: err.Error(), DurationMS: elapsed(start)})
		} else if state, ok := conn.TLSConnectionState(); ok && len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			detail := "TLS " + tlsVersionName(state.Version) + "; subject " + cert.Subject.String() +
				"; issuer " + cert.Issuer.String() + "; expires " + cert.NotAfter.Format("2006-01-02")
			status := StepOK
			if time.Now().After(cert.NotAfter) {
				status, detail = StepFailed, detail+"; the certificate has expired"
			}
			result.Steps = append(result.Steps, StepResult{Name: StepTLS, Status: status, Detail: detail, DurationMS: elapsed(start)})
		} else {
			result.Steps = append(result.Steps, StepResult{Name: StepTLS, Status: StepFailed, Detail: "the connection carries no TLS session", DurationMS: elapsed(start)})
		}
	}

	// 4. bind
	start = time.Now()
	if conn == nil {
		var err error
		conn, err = dial(cfg)
		if err != nil {
			result.Steps = append(result.Steps, StepResult{Name: StepBind, Status: StepFailed, Detail: "connect failed: " + err.Error(), DurationMS: elapsed(start)})
		}
	}
	if conn != nil {
		if cfg.BindDN == "" {
			result.Anonymous = true
			result.Steps = append(result.Steps, StepResult{Name: StepBind, Status: StepSkipped,
				Detail: "no service account configured: searches run anonymously", DurationMS: elapsed(start)})
		} else if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			result.Steps = append(result.Steps, StepResult{Name: StepBind, Status: StepFailed, Detail: err.Error(), DurationMS: elapsed(start)})
			conn.Close()
			conn = nil
		} else {
			result.AuthDN = cfg.BindDN
			result.Steps = append(result.Steps, StepResult{Name: StepBind, Status: StepOK, Detail: cfg.BindDN, DurationMS: elapsed(start)})
		}
	}

	// 5. root DSE
	if conn == nil {
		result.Steps = append(result.Steps, StepResult{Name: StepRootDSE, Status: StepSkipped, Detail: "no connection to read it with"})
		result.OK = false
		return result
	}
	defer conn.Close()

	start = time.Now()
	entry, err := rootDSE(conn)
	if err != nil {
		result.Steps = append(result.Steps, StepResult{Name: StepRootDSE, Status: StepFailed, Detail: err.Error(), DurationMS: elapsed(start)})
		result.OK = false
		return result
	}
	dse := dseMap(entry)
	kind, preset := DescribeServer(dse)
	result.Kind, result.Preset = kind, preset
	result.Vendor = dseFirst(dse, "vendorName")
	result.VendorVersion = dseFirst(dse, "vendorVersion")
	result.NamingContexts = dse["namingContexts"]
	result.SupportedVersions = dse["supportedLDAPVersion"]
	result.PagedResults = strings.Contains(strings.Join(dse["supportedControl"], " "), ldap.ControlTypePaging)
	result.Steps = append(result.Steps, StepResult{Name: StepRootDSE, Status: StepOK,
		Detail: describeDSE(result, dse), DurationMS: elapsed(start)})
	result.OK = true
	return result
}

// describeDSE renders the root DSE line the console shows.
func describeDSE(result *ProbeResult, dse map[string][]string) string {
	parts := make([]string, 0, 4)
	if result.Vendor != "" {
		parts = append(parts, result.Vendor)
	}
	if result.VendorVersion != "" {
		parts = append(parts, result.VendorVersion)
	}
	if contexts := dse["namingContexts"]; len(contexts) > 0 {
		parts = append(parts, "naming contexts: "+strings.Join(contexts, ", "))
	}
	if len(parts) == 0 {
		return "the directory answered without describing itself"
	}
	return strings.Join(parts, "; ")
}

// Browse lists one level of the directory.
func (c *Client) Browse(ctx context.Context, cfg *Config, baseDN string, limit int) (*BrowseResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}
	if limit <= 0 {
		limit = DefaultBrowseLimit
	}
	if limit > MaxBrowseLimit {
		limit = MaxBrowseLimit
	}

	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()

	result := &BrowseResult{BaseDN: baseDN, Kind: KindUnknown, Nodes: []BrowseNode{}}

	if entry, err := rootDSE(conn); err == nil {
		dse := dseMap(entry)
		result.Kind, _ = DescribeServer(dse)
		result.NamingContexts = dse["namingContexts"]
	}

	if baseDN == "" {
		for _, context := range result.NamingContexts {
			label, _ := LabelFor(context, nil)
			result.Nodes = append(result.Nodes, BrowseNode{
				DN: context, Label: label, Kind: "naming_context", HasChildren: true,
			})
		}
		return result, nil
	}

	found, truncated, err := sample(conn, &ldap.SearchRequest{
		BaseDN:     baseDN,
		Scope:      ldap.ScopeSingleLevel,
		Filter:     "(objectClass=*)",
		Attributes: nodeAttributes(cfg),
	}, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: browse failed: %v", ErrUnavailable, err)
	}
	result.Truncated = truncated
	result.Nodes = nodesFrom(found, limit)
	return result, nil
}

// Search runs an operator-supplied filter under a base. The group picker uses it
// to find the group a sign-in should be restricted to, and it doubles as a
// general "look at these entries" tool while a directory is being set up.
func (c *Client) Search(ctx context.Context, cfg *Config, baseDN, filter string, limit int) (*BrowseResult, error) {
	if cfg == nil || cfg.URL == "" {
		return nil, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}
	if baseDN == "" {
		return nil, fmt.Errorf("%w: a search base is required", ErrUnavailable)
	}
	if strings.TrimSpace(filter) == "" {
		filter = "(objectClass=*)"
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFilter, err)
	}
	if limit <= 0 {
		limit = DefaultBrowseLimit
	}
	if limit > MaxBrowseLimit {
		limit = MaxBrowseLimit
	}

	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()

	result := &BrowseResult{BaseDN: baseDN, Kind: KindUnknown, Nodes: []BrowseNode{}}
	if entry, err := rootDSE(conn); err == nil {
		dse := dseMap(entry)
		result.Kind, _ = DescribeServer(dse)
		result.NamingContexts = dse["namingContexts"]
	}

	found, truncated, err := sample(conn, &ldap.SearchRequest{
		BaseDN:     baseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     filter,
		Attributes: nodeAttributes(cfg),
	}, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: search failed: %v", ErrUnavailable, err)
	}
	result.Truncated = truncated
	result.Nodes = nodesFrom(found, limit)
	return result, nil
}

// nodeAttributes are what a tree row or a search hit is rendered from.
func nodeAttributes(cfg *Config) []string {
	return append([]string{
		"ou", "cn", "o", "dc", "description", "objectClass",
		"hasSubordinates", "numSubordinates", "member", "uniqueMember", "memberUid",
	}, searchAttributes(cfg)...)
}

// nodesFrom renders search hits as console rows, newest-first disabled: the
// order is stable so a refresh does not reshuffle the list under the operator.
func nodesFrom(found *ldap.SearchResult, limit int) []BrowseNode {
	nodes := make([]BrowseNode, 0, len(found.Entries))
	if len(found.Entries) > limit {
		found.Entries = found.Entries[:limit]
	}
	for _, entry := range found.Entries {
		attrs := map[string][]string{}
		for _, attribute := range entry.Attributes {
			attrs[attribute.Name] = attribute.Values
		}
		label, kind := LabelFor(entry.DN, attrs)
		node := BrowseNode{
			DN:          entry.DN,
			Label:       label,
			Kind:        kind,
			Description: firstValue(attrs, "description"),
			HasChildren: hasChildren(attrs, kind),
			Members:     memberCount(attrs),
		}
		if raw := firstValue(attrs, "numSubordinates"); raw != "" {
			if count, err := strconv.Atoi(raw); err == nil {
				node.Subordinates = count
			}
		}
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		return strings.ToLower(nodes[i].Label) < strings.ToLower(nodes[j].Label)
	})
	return nodes
}

// memberCount counts a group's members across the attribute names the common
// directory flavours use.
func memberCount(attrs map[string][]string) int {
	total := 0
	for _, name := range []string{"member", "uniqueMember", "memberUid"} {
		for key, values := range attrs {
			if strings.EqualFold(key, name) {
				total += len(values)
			}
		}
	}
	return total
}

// hasChildren prefers what the directory says and falls back to the node type.
func hasChildren(attrs map[string][]string, kind string) bool {
	if raw := firstValue(attrs, "hasSubordinates"); raw != "" {
		return strings.EqualFold(raw, "TRUE")
	}
	if raw := firstValue(attrs, "numSubordinates"); raw != "" {
		count, err := strconv.Atoi(raw)
		return err == nil && count > 0
	}
	return IsContainerKind(kind)
}

func firstValue(attrs map[string][]string, name string) string {
	for key, values := range attrs {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
	}
	return ""
}

// Analyze samples a search base and reports what the settings could be.
func (c *Client) Analyze(ctx context.Context, cfg *Config, baseDN string, sampleCap int) (*AnalyzeResult, error) {
	if cfg == nil || cfg.URL == "" || baseDN == "" {
		return nil, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}
	if sampleCap <= 0 {
		sampleCap = DefaultSampleCap
	}

	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()

	result := &AnalyzeResult{BaseDN: baseDN, Kind: KindUnknown, ClassCounts: map[string]int{}, Attributes: []AttributeStat{}}
	if entry, err := rootDSE(conn); err == nil {
		result.Kind, _ = DescribeServer(dseMap(entry))
	}

	attributes := append([]string{"objectClass", "hasSubordinates", "numSubordinates"}, candidateAttributes...)
	found, truncated, err := sample(conn, &ldap.SearchRequest{
		BaseDN:     baseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     "(objectClass=person)",
		Attributes: attributes,
	}, sampleCap)
	if err != nil {
		return nil, fmt.Errorf("%w: analysis failed: %v", ErrUnavailable, err)
	}
	result.Truncated = truncated
	result.Samples = len(found.Entries)

	samples := make([]sampleEntry, 0, len(found.Entries))
	for _, entry := range found.Entries {
		sample := sampleEntry{DN: entry.DN, Values: map[string][]string{}}
		for _, attribute := range attributes {
			values := stringValues(entry, attribute)
			if len(values) > 0 {
				sample.Values[strings.ToLower(attribute)] = values
			}
		}
		samples = append(samples, sample)
		for _, class := range sample.Values["objectclass"] {
			result.ClassCounts[strings.ToLower(class)]++
		}
	}

	result.Attributes = AnalyzeEntries(samples, candidateAttributes)
	result.Recommendations = Recommend(samples, result.Attributes)
	return result, nil
}

// CheckEntry dry-runs a directory login. It renders the same filter the login
// path uses, resolves the same identity attributes, and reports the same bind
// outcome — without writing anything anywhere.
func (c *Client) CheckEntry(ctx context.Context, cfg *Config, email, password string) (*CheckResult, error) {
	result := &CheckResult{Attributes: map[string]string{}}
	if cfg == nil || cfg.URL == "" || cfg.BaseDN == "" || cfg.UserFilter == "" {
		return result, fmt.Errorf("%w: incomplete directory configuration", ErrUnavailable)
	}
	if email == "" {
		return result, ErrInvalidCredentials
	}

	result.Filter = BuildFilter(cfg, email)
	result.GroupRequired = cfg.RequiredGroupDN

	conn, err := connect(ctx, cfg)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer conn.Close()

	found, _, err := sample(conn, &ldap.SearchRequest{
		BaseDN:     cfg.BaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     result.Filter,
		Attributes: append(searchAttributes(cfg), entryAttributes...),
	}, 2)
	if err != nil {
		return result, fmt.Errorf("%w: search failed: %v", ErrUnavailable, err)
	}
	switch len(found.Entries) {
	case 0:
		return result, ErrEntryNotFound
	case 1:
	default:
		return result, ErrMultipleEntries
	}

	entry := found.Entries[0]
	result.MatchCount = 1
	result.DN = entry.DN
	result.GroupOK = cfg.RequiredGroupDN != ""
	result.Username = entry.GetAttributeValue(cfg.AttrUsername)
	result.DisplayName = displayName(entry, cfg)
	result.UniqueID, result.UniqueIDSource = resolveUniqueID(entry, cfg)
	for _, attribute := range entryAttributes {
		if value := entry.GetAttributeValue(attribute); value != "" {
			result.Attributes[attribute] = value
		}
	}

	if password == "" {
		// An empty password must never reach a directory: LDAP answers a simple
		// bind carrying no password as an anonymous bind, which succeeds.
		return result, nil
	}

	result.BindAttempted = true
	if err := conn.Bind(entry.DN, password); err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) {
			result.BindError = err.Error()
			return result, ErrInvalidCredentials
		}
		return result, fmt.Errorf("%w: bind failed: %v", ErrUnavailable, err)
	}
	result.Bound = true
	return result, nil
}

// stringValues reads an attribute's values, hex encoding binary identifiers so
// they survive JSON and stay comparable with the login path.
func stringValues(entry *ldap.Entry, attribute string) []string {
	raw := entry.GetRawAttributeValues(attribute)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		if len(value) == 0 {
			continue
		}
		out = append(out, stringify(value))
	}
	return out
}

func elapsed(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func tlsVersionName(version uint16) string {
	switch version {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	}
	return fmt.Sprintf("0x%04x", version)
}
