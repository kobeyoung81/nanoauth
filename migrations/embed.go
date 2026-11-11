// Package migrations holds nanoauth's declarative MongoDB manifests.
//
// A manifest describes the shape a collection must have (its indexes, and
// optionally a validator) rather than the statements to run, so applying one
// twice converges instead of failing.
package migrations

import "embed"

//go:embed *.json
var FS embed.FS

// Load returns all manifests as a name→content map, in no particular order
// (the migrator sorts by name).
func Load() (map[string]string, error) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := FS.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		out[entry.Name()] = string(data)
	}
	return out, nil
}
