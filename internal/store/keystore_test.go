package store

import (
	"context"
	"gitee.com/kobeyoung81/nanoauth/internal/bustest"
	"testing"
)

// TestGetOrCreateJWTKey_Existing: a deployment that already has a keypair keeps
// it — the tokens it issued stay verifiable.
func TestGetOrCreateJWTKey_Existing(t *testing.T) {
	stub := bustest.New()
	stub.SetConfig("auth", map[string]string{
		"jwtPrivateKey": "-----BEGIN RSA PRIVATE KEY-----\nstored\n-----END RSA PRIVATE KEY-----",
		"jwtPublicKey":  "-----BEGIN PUBLIC KEY-----\nstored\n-----END PUBLIC KEY-----",
	})
	s := NewKeyStore(stub.Client(t))

	privatePEM, publicPEM, err := s.GetOrCreateJWTKey(context.Background(), 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if privatePEM != stub.Config("auth")["jwtPrivateKey"] || publicPEM != stub.Config("auth")["jwtPublicKey"] {
		t.Fatalf("the stored keypair was not used: %q / %q", privatePEM, publicPEM)
	}
}

// TestGetOrCreateJWTKey_GenerateOnFirstBoot: with nothing stored, a pair is
// generated and persisted (the public key as a string, the private key as a
// secret, which is what makes the console mask it).
func TestGetOrCreateJWTKey_GenerateOnFirstBoot(t *testing.T) {
	stub := bustest.New()
	s := NewKeyStore(stub.Client(t))

	privatePEM, publicPEM, err := s.GetOrCreateJWTKey(context.Background(), 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if privatePEM == "" || publicPEM == "" {
		t.Fatal("no keypair was produced")
	}
	if stub.Config("auth")["jwtPrivateKey"] != privatePEM {
		t.Fatalf("the private key was not stored: %+v", stub.Config("auth"))
	}
	if stub.Config("auth")["jwtPublicKey"] != publicPEM {
		t.Fatalf("the public key was not stored: %+v", stub.Config("auth"))
	}
}

// TestGetOrCreateJWTKey_SecondBootReadsTheSamePair: the second call must not
// generate a second keypair — that would invalidate every token in flight.
func TestGetOrCreateJWTKey_SecondBootReadsTheSamePair(t *testing.T) {
	stub := bustest.New()
	client := stub.Client(t)

	firstPrivate, firstPublic, err := NewKeyStore(client).GetOrCreateJWTKey(context.Background(), 2048)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	secondPrivate, secondPublic, err := NewKeyStore(client).GetOrCreateJWTKey(context.Background(), 2048)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if firstPrivate != secondPrivate || firstPublic != secondPublic {
		t.Fatal("a second keypair was generated on the second boot")
	}
}

func TestGetOrCreateJWTKey_ReadError(t *testing.T) {
	stub := bustest.New()
	stub.FailReads(true)
	s := NewKeyStore(stub.Client(t))

	if _, _, err := s.GetOrCreateJWTKey(context.Background(), 2048); err == nil {
		t.Fatal("a failing config read must be reported, not papered over with a new key")
	}
}
