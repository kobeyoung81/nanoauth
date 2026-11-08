package token

import (
	"testing"
	"time"
)

func mustSvc(t *testing.T, keyID string, ttl int) *TokenService {
	t.Helper()
	privPEM, pubPEM, err := GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPairPEM: %v", err)
	}
	svc, err := NewTokenService(keyID, "test", ttl, privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	return svc
}

func TestGenerateRSAKeyPair(t *testing.T) {
	key, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.N.BitLen() < 2048 {
		t.Fatalf("key too small: %d bits", key.N.BitLen())
	}
}

func TestEncodeAndParseKeys(t *testing.T) {
	privPEM, pubPEM, err := GenerateKeyPairPEM(2048)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := ParseRSAPrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.N.BitLen() < 2048 {
		t.Fatal("private key too small after parse")
	}

	loadedPub, err := ParseRSAPublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPub.N.Cmp(loaded.N) != 0 {
		t.Fatal("public key mismatch after parse")
	}
}

func TestNewTokenService(t *testing.T) {
	privPEM, pubPEM, _ := GenerateKeyPairPEM(2048)

	svc, err := NewTokenService("k1", "test-issuer", 3600, privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	if svc.keyID != "k1" {
		t.Fatalf("expected keyID k1, got %s", svc.keyID)
	}
}

func TestNewTokenService_BadPEM(t *testing.T) {
	_, err := NewTokenService("k1", "test", 3600, "not a pem", "also not a pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestGenerateAccessToken(t *testing.T) {
	svc := mustSvc(t, "k1", 3600)

	tokenStr, expiresAt, err := svc.GenerateAccessToken("user-1", "Admin User", "admin", "pro")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
	if time.Until(expiresAt) < 3590*time.Second {
		t.Fatal("token expires too soon")
	}
}

func TestVerifyToken_Valid(t *testing.T) {
	svc := mustSvc(t, "k1", 3600)

	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Admin User", "admin", "pro")

	claims, err := svc.VerifyToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("expected sub user-1, got %s", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Fatalf("expected role admin, got %s", claims.Role)
	}
	if claims.Tier != "pro" {
		t.Fatalf("expected tier pro, got %s", claims.Tier)
	}
	if claims.Issuer != "test" {
		t.Fatalf("expected issuer test, got %s", claims.Issuer)
	}
}

func TestVerifyToken_Expired(t *testing.T) {
	svc := mustSvc(t, "k1", 1) // 1 second TTL

	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Test User", "user", "free")

	time.Sleep(2 * time.Second)

	_, err := svc.VerifyToken(tokenStr)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyToken_WrongKey(t *testing.T) {
	svc1 := mustSvc(t, "k1", 3600)
	svc2 := mustSvc(t, "k1", 3600)

	tokenStr, _, _ := svc1.GenerateAccessToken("user-1", "Test User", "user", "free")

	_, err := svc2.VerifyToken(tokenStr)
	if err == nil {
		t.Fatal("expected error: wrong key should not verify")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestVerifyToken_Tampered(t *testing.T) {
	svc := mustSvc(t, "k1", 3600)

	tokenStr, _, _ := svc.GenerateAccessToken("user-1", "Test User", "user", "free")

	tampered := tokenStr + "x"
	_, err := svc.VerifyToken(tampered)
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestJWKS_ContainsKey(t *testing.T) {
	svc := mustSvc(t, "my-key-id", 3600)

	jwks := svc.JWKS()

	keys, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %v", jwks)
	}
	if keys[0]["kid"] != "my-key-id" {
		t.Fatalf("expected kid my-key-id, got %v", keys[0]["kid"])
	}
	if keys[0]["alg"] != "RS256" {
		t.Fatalf("expected RS256, got %v", keys[0]["alg"])
	}
	if keys[0]["kty"] != "RSA" {
		t.Fatalf("expected RSA, got %v", keys[0]["kty"])
	}
	if keys[0]["n"] == "" {
		t.Fatal("expected non-empty modulus")
	}
	if keys[0]["e"] == "" {
		t.Fatal("expected non-empty exponent")
	}
}

func TestBase64URLEncode(t *testing.T) {
	result := base64URLEncode([]byte{0x01, 0x02, 0x03})
	if result == "" {
		t.Fatal("expected non-empty result")
	}
}
