package store

// The account's language, and the platform default it falls back to.
//
// Two levels, deliberately: the platform ships one default
// (`agent.language.default`, seeded to "zh") and an account may override it. The
// console used to ask the bus for this composition; the field is an account's, so
// the whole answer lives here now — nanoauth holds both the row and the client
// that reads the admin module's default.

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

// agentComponent is the configuration component that holds the language default.
// (configComponent in bootstrap.go is this service's own component.)
const agentComponent = "agent"

// languageDefaultKey is the platform-wide default language.
const languageDefaultKey = "agent.language.default"

// supportedLanguages are the tags the console offers. The stored value is always a
// primary subtag, so "zh-CN" and "zh-Hans" both land on "zh".
var supportedLanguages = map[string]bool{
	"zh": true, "en": true, "ja": true, "ko": true, "ru": true,
	"ar": true, "fr": true, "de": true, "es": true, "pt": true,
}

// normalizeLanguage lowercases a tag and keeps its primary subtag. It returns ""
// for an empty value (the account inherits the platform default).
func normalizeLanguage(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return ""
	}
	if i := strings.IndexAny(tag, "-_"); i > 0 {
		tag = tag[:i]
	}
	return tag
}

// Preferences is the effective language and where it came from.
type Preferences struct {
	Language string `json:"language"`
	// Source says which level the value came from: "user" when the account set it,
	// "platform" when it is inherited.
	Source string `json:"source"`
}

// platformLanguage reads the configured default. A read that fails answers ""
// rather than an error: the default is a convenience, and refusing to say what
// language an account speaks because one request timed out is worse than saying
// "nothing configured".
func (s *UserStore) platformLanguage(ctx context.Context) string {
	if s.admin == nil {
		return ""
	}
	var payload struct {
		Items []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"items"`
	}
	if err := s.admin.Do(ctx, http.MethodGet, "/api/v1/config/"+agentComponent, nil, &payload); err != nil {
		slog.Warn("preferences: read the platform language default", "error", err)
		return ""
	}
	for _, item := range payload.Items {
		if item.Key == languageDefaultKey {
			return normalizeLanguage(item.Value)
		}
	}
	return ""
}

// Preferences returns the language this account effectively speaks.
func (s *UserStore) Preferences(ctx context.Context, userID string) (Preferences, error) {
	own, err := s.accounts.GetUserPreferredLanguage(userID)
	if err != nil {
		return Preferences{}, err
	}
	if own != "" {
		return Preferences{Language: own, Source: "user"}, nil
	}
	return Preferences{Language: s.platformLanguage(ctx), Source: "platform"}, nil
}

// SetPreferences stores the account's choice; an empty value clears it so the
// account inherits the platform default again. The answer is the effective value,
// which is what the console shows right after a save.
func (s *UserStore) SetPreferences(ctx context.Context, userID, language string) (Preferences, error) {
	lang := normalizeLanguage(language)
	if lang != "" && !supportedLanguages[lang] {
		return Preferences{}, ErrUnsupportedLanguage
	}
	if err := s.accounts.SetUserPreferredLanguage(userID, lang); err != nil {
		return Preferences{}, err
	}
	if lang == "" {
		return Preferences{Language: s.platformLanguage(ctx), Source: "platform"}, nil
	}
	return Preferences{Language: lang, Source: "user"}, nil
}
