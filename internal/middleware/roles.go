package middleware

import "net/http"

// The platform roles allowed to operate the directory login console. They match
// the portal's management section (admin and the DevOps role).
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// RequireRoles rejects a request whose verified token carries a role outside the
// allowed set. It runs after AuthMiddleware, which is what puts the claims into
// the request context; a missing token is therefore an unauthorized request, not
// a forbidden one.
func RequireRoles(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r.Context())
			if claims == nil || !allowed[claims.Role] {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
