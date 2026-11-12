package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gitee.com/kobeyoung81/nanoauth/internal/accounttest"
	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"gitee.com/kobeyoung81/nanoauth/internal/handler"
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

func setupAuthServer(t *testing.T) (*httptest.Server, *token.TokenService, *bustest.Bus) {
	t.Helper()

	privPEM, pubPEM, err := token.GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := token.NewTokenService("test-kid", "test", 3600, privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	stub := bustest.New()
	client := stub.Client(t)
	us := store.NewUserStore(accounttest.New(stub))
	ts := store.NewTokenStore(client)

	h := handler.NewAuthHandler(svc, us, ts)
	jwksH := handler.NewJWKSHandler(svc)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v1/register", h.HandleRegister)
	mux.HandleFunc("POST /auth/v1/token", h.HandleToken)
	mux.HandleFunc("POST /auth/v1/token/refresh", h.HandleRefresh)
	mux.HandleFunc("GET /auth/v1/userinfo", h.HandleUserinfo)
	mux.HandleFunc("GET /auth/v1/.well-known/jwks", jwksH.HandleJWKS)

	tsrv := httptest.NewServer(mux)
	return tsrv, svc, stub
}

func postJSON(url string, body map[string]string) (*http.Response, error) {
	data, _ := json.Marshal(body)
	return http.Post(url, "application/json", bytes.NewReader(data))
}

func getWithToken(url, token string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return http.DefaultClient.Do(req)
}

func jsonBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func TestAuthFlow_E2E_RegisterTokenUserinfo(t *testing.T) {
	srv, svc, _ := setupAuthServer(t)
	defer srv.Close()

	// Step 1: Register

	resp, err := postJSON(srv.URL+"/auth/v1/register", map[string]string{
		"email":    "e2e@test.com",
		"password": "securepass123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.StatusCode)
	}

	regBody := jsonBody(t, resp)
	accessToken := regBody["access_token"].(string)

	if accessToken == "" {
		t.Fatal("missing access token in register response")
	}

	_, err = svc.VerifyToken(accessToken)
	if err != nil {
		t.Fatalf("register token verification: %v", err)
	}

	// Step 2: Userinfo with access token
	if regBody["user_id"] == nil || regBody["user_id"] == "" {
		t.Fatal("no user id in the register response")
	}

	resp, err = getWithToken(srv.URL+"/auth/v1/userinfo", accessToken)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d", resp.StatusCode)
	}

	ui := jsonBody(t, resp)
	if ui["email"] != "e2e@test.com" {
		t.Fatalf("expected email e2e@test.com, got %v", ui["email"])
	}
}

func TestAuthFlow_E2E_RefreshToken(t *testing.T) {
	srv, svc, stub := setupAuthServer(t)
	defer srv.Close()

	// The ticket and the account it belongs to, as the fake bus holds them.
	raw := "some-refresh-token-xxxxxxxxxxxxxxxxxx"
	stub.StoreToken(hashToken(raw), "u-refresh", time.Now().Add(24*time.Hour))
	stub.AddAccount("u-refresh", "refresh@test.com", "Refresh", "$2a$10$hash")

	resp, err := postJSON(srv.URL+"/auth/v1/token/refresh", map[string]string{
		"refresh_token": raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: expected 200, got %d", resp.StatusCode)
	}

	refreshBody := jsonBody(t, resp)
	newAccessToken := refreshBody["access_token"].(string)
	if newAccessToken == "" {
		t.Fatal("no access token in refresh response")
	}
	// Verify the token is valid
	_, verifyErr := svc.VerifyToken(newAccessToken)
	if verifyErr != nil {
		t.Fatalf("refresh token verification: %v", verifyErr)
	}
}

func TestAuthFlow_E2E_LoginFlow(t *testing.T) {
	srv, _, _ := setupAuthServer(t)
	defer srv.Close()

	resp, err := postJSON(srv.URL+"/auth/v1/token", map[string]string{
		"email":    "login-e2e@test.com",
		"password": "wrongpass",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login for unknown user: expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthFlow_E2E_JWKS(t *testing.T) {
	srv, _, _ := setupAuthServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/auth/v1/.well-known/jwks")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body := jsonBody(t, resp)
	keys, ok := body["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Fatal("expected non-empty keys")
	}

	key := keys[0].(map[string]any)
	if key["alg"] != "RS256" {
		t.Fatalf("expected RS256, got %v", key["alg"])
	}
	if key["kid"] != "test-kid" {
		t.Fatalf("expected test-kid, got %v", key["kid"])
	}
}

func TestAuthFlow_E2E_RegistrationErrors(t *testing.T) {
	srv, _, _ := setupAuthServer(t)
	defer srv.Close()

	resp, err := postJSON(srv.URL+"/auth/v1/register", map[string]string{
		"password": "nopass",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d", resp.StatusCode)
	}

	resp, err = postJSON(srv.URL+"/auth/v1/register", map[string]string{
		"email":    "short@test.com",
		"password": "ab",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", resp.StatusCode)
	}
}

// hashToken is the store's rule for what a ticket is looked up by: the SHA-256
// hex of the value the client holds.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}
