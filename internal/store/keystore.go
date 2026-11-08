package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"gitee.com/kobeyoung81/nanoauth/internal/bus"
	"gitee.com/kobeyoung81/nanoauth/internal/token"
)

// KeyStore persists the nanoauth RSA JWT keypair in the shared configuration the
// bus owns (component 'auth') as two independent rows: 'jwtPrivateKey'
// (value_type=secret) and 'jwtPublicKey' (value_type=string). Separate rows
// guarantee every replica signs and verifies with the same key.
//
// It used to read and write `service_config_items` directly — the same table the
// bus served to the console. The rows are the bus's now, so this asks it; the keys
// themselves are unchanged, which is why a deployment keeps issuing tokens that
// the running agents still accept.
type KeyStore struct {
	bus *bus.Client
}

func NewKeyStore(client *bus.Client) *KeyStore {
	return &KeyStore{bus: client}
}

const (
	keyComponent = "auth"
	privateKey   = "jwtPrivateKey"
	publicKey    = "jwtPublicKey"
)

// GetOrCreateJWTKey returns the stored RSA keypair as PEM strings, generating and
// persisting a fresh one on first boot.
//
// The SQL version relied on a transaction and a race-safe INSERT IGNORE. There is
// no transaction across the API, so the order does the work instead: the private
// key is written first and the public key only after it, and a replica that loses
// the race re-reads and adopts the winner's pair. Two replicas starting at once
// can therefore each generate a pair, but only one pair becomes the stored one —
// and the loser adopts it on the next read, which is what the original comment
// promised.
func (s *KeyStore) GetOrCreateJWTKey(ctx context.Context, bits int) (privatePEM, publicPEM string, err error) {
	privatePEM, publicPEM, err = s.get(ctx)
	if err == nil {
		return privatePEM, publicPEM, nil
	}
	if !errors.Is(err, errKeyMissing) {
		return "", "", err
	}

	generatedPrivate, generatedPublic, err := token.GenerateKeyPairPEM(bits)
	if err != nil {
		return "", "", fmt.Errorf("generate jwt key: %w", err)
	}
	if err := s.put(ctx, privateKey, generatedPrivate,
		"nanoauth RSA JWT private key (PKCS#1 PEM)"); err != nil {
		return "", "", err
	}
	if err := s.put(ctx, publicKey, generatedPublic,
		"nanoauth RSA JWT public key (PKIX PEM)"); err != nil {
		return "", "", err
	}

	// Re-read rather than returning what we generated: if another replica wrote
	// first, this process has to sign with *its* key, not with ours.
	storedPrivate, storedPublic, err := s.get(ctx)
	if err != nil {
		return "", "", err
	}
	return storedPrivate, storedPublic, nil
}

// errKeyMissing is the private-key row being absent, which means first boot.
var errKeyMissing = errors.New("jwt key not stored")

func (s *KeyStore) get(ctx context.Context) (privatePEM, publicPEM string, err error) {
	var payload struct {
		Items []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"items"`
	}
	path := "/api/v1/config/" + url.PathEscape(keyComponent)
	if err := s.bus.Do(ctx, http.MethodGet, path, nil, &payload); err != nil {
		return "", "", fmt.Errorf("get jwt key: %w", err)
	}
	for _, item := range payload.Items {
		switch item.Key {
		case privateKey:
			privatePEM = item.Value
		case publicKey:
			publicPEM = item.Value
		}
	}
	if privatePEM == "" || publicPEM == "" {
		return "", "", errKeyMissing
	}
	return privatePEM, publicPEM, nil
}

func (s *KeyStore) put(ctx context.Context, key, value, description string) error {
	path := "/api/v1/config/" + url.PathEscape(keyComponent) + "/" + url.PathEscape(key)
	if key == privateKey {
		body := map[string]string{"value": value, "value_type": "secret", "description": description}
		if err := s.bus.Do(ctx, http.MethodPut, path, body, nil); err != nil {
			return fmt.Errorf("store jwt private key: %w", err)
		}
		return nil
	}
	body := map[string]string{"value": value, "value_type": "string", "description": description}
	if err := s.bus.Do(ctx, http.MethodPut, path, body, nil); err != nil {
		return fmt.Errorf("store jwt public key: %w", err)
	}
	return nil
}
