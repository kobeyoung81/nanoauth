package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

func TestHandleJWKS_ReturnsKeys(t *testing.T) {
	privPEM, pubPEM, err := token.GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := token.NewTokenService("k1", "issuer", 3600, privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	h := NewJWKSHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/.well-known/jwks", nil)
	rec := httptest.NewRecorder()
	h.HandleJWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatal("expected Content-Type application/json")
	}

	var jwks map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatal("expected non-empty keys array in JWKS")
	}
}
