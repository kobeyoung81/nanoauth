package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	issuer     string
	ttl        time.Duration
	mu         sync.RWMutex
}

// NewTokenService builds a TokenService from an RSA keypair supplied as PEM
// strings. The keypair is stored in the database and loaded at startup.
func NewTokenService(keyID, issuer string, ttlSeconds int, privatePEM, publicPEM string) (*TokenService, error) {
	privateKey, err := ParseRSAPrivateKeyPEM(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	publicKey, err := ParseRSAPublicKeyPEM(publicPEM)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	return &TokenService{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		issuer:     issuer,
		ttl:        time.Duration(ttlSeconds) * time.Second,
	}, nil
}

// GenerateRSAKeyPair generates a new RSA keypair of the given bit size.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateKeyPairPEM generates a new RSA keypair and returns both halves as
// PEM strings. Used to bootstrap the DB-stored keypair and by tests.
func GenerateKeyPairPEM(bits int) (privatePEM, publicPEM string, err error) {
	key, err := GenerateRSAKeyPair(bits)
	if err != nil {
		return "", "", err
	}
	privatePEM, err = EncodeRSAPrivateKeyPEM(key)
	if err != nil {
		return "", "", err
	}
	publicPEM, err = EncodeRSAPublicKeyPEM(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return privatePEM, publicPEM, nil
}

// EncodeRSAPrivateKeyPEM serializes an RSA private key to PKCS#1 PEM text.
func EncodeRSAPrivateKeyPEM(key *rsa.PrivateKey) (string, error) {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})), nil
}

// EncodeRSAPublicKeyPEM serializes an RSA public key to PKIX PEM text.
func EncodeRSAPublicKeyPEM(key *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})), nil
}

// ParseRSAPrivateKeyPEM parses a PKCS#1 RSA private key from PEM text.
func ParseRSAPrivateKeyPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ParseRSAPublicKeyPEM parses a PKIX RSA public key from PEM text.
func ParseRSAPublicKeyPEM(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}

type Claims struct {
	jwt.RegisteredClaims
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Tier        string `json:"tier"`
}

func (s *TokenService) GenerateAccessToken(userID, displayName, role, tier string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.ttl)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		DisplayName: displayName,
		Role:        role,
		Tier:        tier,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

func (s *TokenService) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (s *TokenService) JWKS() map[string]any {
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": s.keyID,
				"n":   base64URLEncode(s.publicKey.N.Bytes()),
				"e":   base64URLEncode(bigEndianBytes(int(s.publicKey.E))),
			},
		},
	}
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func bigEndianBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte(n % 256)}, result...)
		n /= 256
	}
	return result
}
