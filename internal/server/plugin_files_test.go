package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pluginFiles serves the module's front end: fingerprinted assets may be cached
// hard, while the entry point and the manifest must not be (their names survive a
// release), and a directory request must not turn into a file listing.
func TestPluginFilesServesOnlyFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"plugin.json":       `{"plugin":"auth"}`,
		"remoteEntry.js":    "export {}",
		"assets/index-1.js": "console.log(1)",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	handler := pluginFiles(dir)

	cases := []struct {
		path       string
		status     int
		cacheMatch string
	}{
		{"/plugins/auth/plugin.json", http.StatusOK, "no-cache"},
		{"/plugins/auth/remoteEntry.js", http.StatusOK, "no-cache"},
		{"/plugins/auth/assets/index-1.js", http.StatusOK, "immutable"},
		// No index to serve: a listing would expose the build's layout.
		{"/plugins/auth/", http.StatusNotFound, ""},
		{"/plugins/auth/../secret", http.StatusNotFound, ""},
	}

	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.path, rec.Code, tc.status)
			continue
		}
		if tc.cacheMatch != "" {
			if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, tc.cacheMatch) {
				t.Errorf("%s: Cache-Control = %q, want %q", tc.path, got, tc.cacheMatch)
			}
		}
	}
}
