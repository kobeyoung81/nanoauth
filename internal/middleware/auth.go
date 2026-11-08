package middleware

import (
	"context"
	"net/http"
	"strings"

	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

type contextKey string

const ClaimsKey contextKey = "claims"

func AuthMiddleware(tokenSvc *token.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := tokenSvc.VerifyToken(tokenStr)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetClaims(ctx context.Context) *token.Claims {
	claims, _ := ctx.Value(ClaimsKey).(*token.Claims)
	return claims
}
