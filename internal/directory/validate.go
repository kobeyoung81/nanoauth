package directory

import (
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// FieldError is one rejected setting. Code is stable and machine readable (the
// portal renders its own wording per code); Message is the English rendering
// used by logs and non-portal clients.
type FieldError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// FieldErrors maps a config key (e.g. "ldap.userFilter") to its error.
type FieldErrors map[string]FieldError

// Validate checks a candidate configuration and returns every problem keyed by
// the setting that holds it, so the portal can highlight the offending field.
// It is deliberately the same set of rules for the saved configuration and for
// the drafts the directory console tests before saving.
//
// The rules exist because a wrong value here is a silent failure at login time:
// a filter without the email placeholder, for instance, stops matching per user
// and every directory login answers 401.
func Validate(cfg *Config) FieldErrors {
	errs := FieldErrors{}
	if cfg == nil {
		return errs
	}

	if cfg.URL != "" {
		parsed, err := url.Parse(cfg.URL)
		switch {
		case err != nil:
			errs["ldap.url"] = FieldError{"url_invalid", "not a valid URL"}
		case parsed.Scheme != "ldap" && parsed.Scheme != "ldaps":
			errs["ldap.url"] = FieldError{"url_scheme", "must start with ldap:// or ldaps://"}
		case parsed.Hostname() == "":
			errs["ldap.url"] = FieldError{"url_host", "must carry a host"}
		}
	} else if cfg.Enabled {
		errs["ldap.url"] = FieldError{"url_required", "required while directory login is enabled"}
	}

	if cfg.Timeout <= 0 || cfg.Timeout > time.Minute {
		errs["ldap.timeoutSeconds"] = FieldError{"timeout_range", "must be between 1 and 60 seconds"}
	}

	if cfg.UserFilter != "" {
		if !strings.Contains(cfg.UserFilter, "%s") {
			errs["ldap.userFilter"] = FieldError{"filter_missing_placeholder",
				"must contain the %s placeholder, otherwise every login searches for the same entry"}
		} else if _, err := ldap.CompileFilter(cfg.UserFilter); err != nil {
			errs["ldap.userFilter"] = FieldError{"filter_invalid", err.Error()}
		}
	} else if cfg.Enabled {
		errs["ldap.userFilter"] = FieldError{"filter_required", "required while directory login is enabled"}
	}

	if cfg.Enabled {
		if cfg.BaseDN == "" {
			errs["ldap.baseDN"] = FieldError{"base_dn_required", "required while directory login is enabled"}
		}
		if cfg.AttrUniqueID == "" {
			errs["ldap.attrUniqueId"] = FieldError{"attr_unique_id_required", "required while directory login is enabled"}
		}
		if cfg.AttrUsername == "" {
			errs["ldap.attrUsername"] = FieldError{"attr_username_required", "required while directory login is enabled"}
		}
	}

	for key, attr := range map[string]string{
		"ldap.attrUniqueId":    cfg.AttrUniqueID,
		"ldap.attrUsername":    cfg.AttrUsername,
		"ldap.attrDisplayName": cfg.AttrDisplayName,
	} {
		if attr == "" {
			continue
		}
		if strings.ContainsAny(attr, " \t=(),") {
			errs[key] = FieldError{"attr_invalid", "must be a bare attribute name"}
		}
	}

	if cfg.RequiredGroupDN != "" && !strings.Contains(cfg.RequiredGroupDN, "=") {
		errs["ldap.requiredGroupDN"] = FieldError{"group_dn_invalid", "must be a distinguished name, e.g. cn=team,dc=corp,dc=local"}
	}

	if cfg.LinkPolicy != LinkPolicyAuto && cfg.LinkPolicy != LinkPolicyRefuse {
		errs["ldap.linkPolicy"] = FieldError{"link_policy_invalid", "must be auto or refuse"}
	}

	return errs
}
