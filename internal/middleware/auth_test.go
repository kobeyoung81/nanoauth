package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

func mustTokenService(t *testing.T, keyID string, ttl int) *token.TokenService {
	t.Helper()
	privPEM, pubPEM, err := token.GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := token.NewTokenService(keyID, "test", ttl, privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	svc := mustTokenService(t, "k1", 3600)
	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Admin User", "admin", "pro")

	var capturedUser string
	handler := AuthMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			http.Error(w, "no claims", 500)
			return
		}
		capturedUser = claims.Subject
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if capturedUser != "user-1" {
		t.Fatalf("expected user-1, got %s", capturedUser)
	}
}

func TestAuthMiddleware_NoHeader(t *testing.T) {
	svc := mustTokenService(t, "k1", 3600)

	handler := AuthMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	svc := mustTokenService(t, "k1", 1) // 1 second TTL
	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Test User", "user", "free")

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	handler := AuthMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_WrongScheme(t *testing.T) {
	svc := mustTokenService(t, "k1", 3600)
	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Test User", "user", "free")

	handler := AuthMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+tokenStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong scheme, got %d", rec.Code)
	}
}

func TestGetClaims_Nil(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := GetClaims(req.Context())
	if claims != nil {
		t.Fatal("expected nil claims for request without AuthMiddleware")
	}
}
