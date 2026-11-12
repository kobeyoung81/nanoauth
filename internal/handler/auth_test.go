package handler

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
	"gitee.com/kobeyoung81/nanoauth/internal/store"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
	"golang.org/x/crypto/bcrypt"
)

// setupHandler builds the auth handler over a fake bus.
//
// The stores are bus clients now, so the flows are exercised against a fake that
// holds accounts and tickets — the same reason the portal's bus clients are tested
// against an httptest server. What these tests are for is the HTTP behaviour:
// which status a bad password gets, what a suspended account is told, whether a
// rotated refresh token comes back.
func setupHandler(t *testing.T) (*AuthHandler, *token.TokenService, *bustest.Bus) {
	t.Helper()

	privPEM, pubPEM, err := token.GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := token.NewTokenService("test-kid", "test-issuer", 3600, privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}

	stub := bustest.New()
	// The accounts are the identity database's: the fake bus keeps their state,
	// and this adapter speaks the store's calls to it. The admin module is behind
	// it for the audit trail, and the installation switch is off so these flows
	// start from an installation that already has its administrator — the
	// bootstrap rule itself is pinned against the real store.
	stub.SetConfig("auth", map[string]string{"firstUserIsAdmin": "false"})
	users := store.NewUserStore(accounttest.New(stub)).WithAdmin(stub.Client(t))
	h := NewAuthHandler(svc, users, store.NewTokenStore(stub.Client(t)))
	return h, svc, stub
}

func TestHandleRegister_Success(t *testing.T) {
	h, svc, stub := setupHandler(t)

	body := map[string]string{"email": "new@test.com", "password": "securepass123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["access_token"] == nil {
		t.Fatal("expected access_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Fatal("expected Bearer token_type")
	}
	if resp["role"] != "user" {
		t.Fatalf("expected role user, got %v", resp["role"])
	}
	if resp["tier"] != "free" {
		t.Fatalf("expected tier free, got %v", resp["tier"])
	}

	tok := resp["access_token"].(string)
	claims, err := svc.VerifyToken(tok)
	if err != nil {
		t.Fatalf("generated token doesn't verify: %v", err)
	}
	if claims.Role != "user" {
		t.Fatalf("expected role user in claims, got %s", claims.Role)
	}

	// The account really was created, and the session's refresh ticket with it.
	if len(stub.AccountIDs()) != 1 {
		t.Fatalf("expected one account, got %v", stub.AccountIDs())
	}
	if len(stub.Tokens()) != 1 {
		t.Fatalf("expected one refresh ticket, got %v", stub.Tokens())
	}
}

func TestHandleRegister_DuplicateEmail(t *testing.T) {
	h, _, stub := setupHandler(t)
	stub.AddAccount("u1", "dup@test.com", "Dup", "$2a$10$hash")

	body := map[string]string{"email": "dup@test.com", "password": "securepass123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRegister(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestHandleRegister_MissingFields(t *testing.T) {
	tests := []map[string]string{
		{"password": "pass"},
		{"email": "test@test.com"},
		{},
	}

	for _, body := range tests {
		h, _, _ := setupHandler(t)
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.HandleRegister(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for body %v, got %d", body, rec.Code)
		}
	}
}

func TestHandleRegister_ShortPassword(t *testing.T) {
	h, _, _ := setupHandler(t)

	body := map[string]string{"email": "short@test.com", "password": "ab"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", rec.Code)
	}
}

func TestHandleToken_Success(t *testing.T) {
	passHash, _ := bcrypt.GenerateFromPassword([]byte("securepass123"), bcrypt.DefaultCost)

	h, svc, stub := setupHandler(t)
	stub.AddAccount("u1", "login@test.com", "Login User", string(passHash))
	stub.SetAccountField("u1", "role", "admin")
	stub.SetAccountField("u1", "tier", "pro")

	body := map[string]string{"email": "login@test.com", "password": "securepass123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	tok := resp["access_token"].(string)
	claims, err := svc.VerifyToken(tok)
	if err != nil {
		t.Fatalf("generated token doesn't verify: %v", err)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected admin from the account, got %s", claims.Role)
	}
	if claims.Tier != "pro" {
		t.Fatalf("expected pro from the account, got %s", claims.Tier)
	}
}

func TestHandleToken_BadPassword(t *testing.T) {
	passHash, _ := bcrypt.GenerateFromPassword([]byte("correctpass"), bcrypt.DefaultCost)

	h, _, stub := setupHandler(t)
	stub.AddAccount("u1", "badpass@test.com", "User", string(passHash))

	body := map[string]string{"email": "badpass@test.com", "password": "wrongpass"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleToken_UserNotFound(t *testing.T) {
	h, _, _ := setupHandler(t)

	body := map[string]string{"email": "nobody@test.com", "password": "pass123456"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleToken(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestHandleToken_SuspendedUser(t *testing.T) {
	passHash, _ := bcrypt.GenerateFromPassword([]byte("securepass"), bcrypt.DefaultCost)

	h, _, stub := setupHandler(t)
	stub.AddAccount("u1", "suspended@test.com", "Suspended", string(passHash))
	stub.SetAccountField("u1", "status", "suspended")

	body := map[string]string{"email": "suspended@test.com", "password": "securepass"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleToken(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestHandleRefresh_Success(t *testing.T) {
	passHash, _ := bcrypt.GenerateFromPassword([]byte("pass123456"), bcrypt.DefaultCost)

	h, svc, stub := setupHandler(t)
	refreshTokenValue := "valid-refresh-token-xxxxxxxxxx"
	stub.StoreToken(hashTokenHelper(refreshTokenValue), "u1", time.Now().Add(24*time.Hour))
	stub.AddAccount("u1", "refresh@test.com", "Login User", string(passHash))
	stub.SetAccountField("u1", "role", "admin")

	body := map[string]string{"refresh_token": refreshTokenValue}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/token/refresh", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRefresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	// The rotated refresh token must be returned, otherwise the client keeps a
	// token the server has already deleted.
	if rotated, _ := resp["refresh_token"].(string); rotated == "" {
		t.Fatal("expected a rotated refresh_token in the response")
	}
	tok := resp["access_token"].(string)
	claims, err := svc.VerifyToken(tok)
	if err != nil {
		t.Fatalf("refresh token doesn't verify: %v", err)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected admin, got %s", claims.Role)
	}
	// The presented ticket is spent: exactly one (the new one) remains.
	if _, ok := stub.Tokens()[hashTokenHelper(refreshTokenValue)]; ok {
		t.Fatal("the consumed ticket is still stored")
	}
	if len(stub.Tokens()) != 1 {
		t.Fatalf("expected only the rotated ticket, got %v", stub.Tokens())
	}
}

func TestHandleLogout_RevokesToken(t *testing.T) {
	h, _, stub := setupHandler(t)
	raw := "logout-refresh-token-xxxxxxxxxxxxxx"
	stub.StoreToken(hashTokenHelper(raw), "u1", time.Now().Add(time.Hour))

	body := map[string]string{"refresh_token": raw}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/logout", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleLogout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := stub.Tokens()[hashTokenHelper(raw)]; ok {
		t.Fatal("logout left the refresh ticket behind")
	}
}

func TestHandleUserinfo_ValidToken(t *testing.T) {
	passHash, _ := bcrypt.GenerateFromPassword([]byte("pass123"), bcrypt.DefaultCost)

	h, svc, stub := setupHandler(t)
	stub.AddAccount("u1", "userinfo@test.com", "Admin Ultra", string(passHash))
	stub.SetAccountField("u1", "role", "admin")
	stub.SetAccountField("u1", "tier", "ultra")

	tokenStr, _, _ := svc.GenerateAccessToken("u1", "Admin Ultra", "admin", "ultra")

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	h.HandleUserinfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var userinfo map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &userinfo)
	if userinfo["email"] != "userinfo@test.com" {
		t.Fatalf("expected email userinfo@test.com, got %v", userinfo["email"])
	}
	if userinfo["role"] != "admin" {
		t.Fatalf("expected admin, got %v", userinfo["role"])
	}
	if userinfo["tier"] != "ultra" {
		t.Fatalf("expected ultra, got %v", userinfo["tier"])
	}
}

func TestHandleUserinfo_MissingHeader(t *testing.T) {
	h, _, _ := setupHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/userinfo", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rec := httptest.NewRecorder()

	h.HandleUserinfo(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("expected Content-Type application/json")
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["hello"] != "world" {
		t.Fatalf("expected hello=world, got %v", result)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusForbidden, "nope")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["error"] != "nope" {
		t.Fatalf("expected error=nope, got %v", result)
	}
}

func hashTokenHelper(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// A fresh installation hands the administrator role to its first sign-up. The
// identity store owns that decision; what the handler must not do is answer with
// a hard-coded "user", which would hide the role until the next token refresh.
func TestHandleRegister_UsesTheAssignedRole(t *testing.T) {
	h, svc, stub := setupHandler(t)
	stub.SetNewAccountRole("admin")

	body := map[string]string{"email": "first@test.com", "password": "securepass123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["role"] != "admin" {
		t.Fatalf("response role = %v; want admin", resp["role"])
	}
	claims, err := svc.VerifyToken(resp["access_token"].(string))
	if err != nil {
		t.Fatalf("generated token doesn't verify: %v", err)
	}
	if claims.Role != "admin" {
		t.Fatalf("token role = %s; want admin", claims.Role)
	}
}

// A failed read-back must not fail the registration: the account exists, and the
// session is issued as a plain user until the role is read again.
func TestHandleRegister_FallsBackWhenTheAccountCannotBeRead(t *testing.T) {
	h, svc, stub := setupHandler(t)
	stub.SetNewAccountRole("admin")
	stub.FailAccountReads(true)

	body := map[string]string{"email": "first@test.com", "password": "securepass123"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleRegister(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["role"] != "user" {
		t.Fatalf("response role = %v; want the user fallback", resp["role"])
	}
	claims, err := svc.VerifyToken(resp["access_token"].(string))
	if err != nil {
		t.Fatalf("generated token doesn't verify: %v", err)
	}
	if claims.Role != "user" {
		t.Fatalf("token role = %s; want the user fallback", claims.Role)
	}
}
