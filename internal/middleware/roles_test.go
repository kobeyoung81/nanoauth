package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The directory console is not merely hidden from a role that may not use it: a
// caller without the management role is refused even when the portal is bypassed
// and the auth service is called directly.
func TestRequireRoles_AcceptsTheAllowedRolesAndRefusesTheRest(t *testing.T) {
	svc := mustTokenService(t, "k1", 3600)
	guard := AuthMiddleware(svc)(RequireRoles(RoleAdmin, RoleOperator)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	for _, tc := range []struct {
		role string
		want int
	}{
		{RoleAdmin, http.StatusOK},
		{RoleOperator, http.StatusOK},
		{"support", http.StatusForbidden},
		{"auditor", http.StatusForbidden},
		{"user", http.StatusForbidden},
	} {
		t.Run(tc.role, func(t *testing.T) {
			tokenStr, _, _ := svc.GenerateAccessToken("u-"+tc.role, "Test", tc.role, "free")
			req := httptest.NewRequest(http.MethodGet, "/auth/v1/directory/effective", nil)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rec := httptest.NewRecorder()

			guard.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("role %s: status = %d, want %d", tc.role, rec.Code, tc.want)
			}
		})
	}
}

// Without a verified token there are no claims to check, so the request never
// reaches the role rule.
func TestRequireRoles_RefusesAnAnonymousRequest(t *testing.T) {
	svc := mustTokenService(t, "k1", 3600)
	guard := AuthMiddleware(svc)(RequireRoles(RoleAdmin)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/v1/directory/effective", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
