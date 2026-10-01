package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestValidateToken_HS256(t *testing.T) {
	secret := []byte("super-secret-hmac-key-for-testing-only-32bytes")
	validator := NewHMACValidator(secret, "ztna-idp", "ztna-gateway", 5*time.Second)

	claims := &Claims{
		Subject:   "user:alice",
		Issuer:    "ztna-idp",
		Audience:  []string{"ztna-gateway"},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Roles:     []string{"developer", "security-auditor"},
		Email:     "alice@example.com",
	}

	token, err := GenerateHMAC(claims, secret)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// 1. Success case
	parsed, err := validator.ValidateToken(token)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}
	if parsed.Subject != "user:alice" {
		t.Errorf("expected subject user:alice, got %s", parsed.Subject)
	}
	if len(parsed.Roles) != 2 || parsed.Roles[0] != "developer" {
		t.Errorf("unexpected roles: %v", parsed.Roles)
	}

	// 2. Tampered signature test
	tampered := token[:len(token)-4] + "AAAA"
	if _, err := validator.ValidateToken(tampered); err == nil {
		t.Error("expected error on tampered signature, got nil")
	}

	// 3. Expired token test
	expiredClaims := &Claims{
		Subject:   "user:bob",
		Issuer:    "ztna-idp",
		Audience:  []string{"ztna-gateway"},
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	expiredToken, _ := GenerateHMAC(expiredClaims, secret)
	if _, err := validator.ValidateToken(expiredToken); err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}

	// 4. Invalid Issuer test
	badIssuerClaims := &Claims{
		Subject:   "user:mallory",
		Issuer:    "rogue-idp",
		Audience:  []string{"ztna-gateway"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	badIssuerToken, _ := GenerateHMAC(badIssuerClaims, secret)
	if _, err := validator.ValidateToken(badIssuerToken); err == nil || !strings.Contains(err.Error(), "token issuer") {
		t.Errorf("expected invalid issuer error, got %v", err)
	}

	// 5. Invalid Audience test
	badAudClaims := &Claims{
		Subject:   "user:mallory",
		Issuer:    "ztna-idp",
		Audience:  []string{"other-gateway"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	badAudToken, _ := GenerateHMAC(badAudClaims, secret)
	if _, err := validator.ValidateToken(badAudToken); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Errorf("expected invalid audience error, got %v", err)
	}
}

func TestValidateToken_RS256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubKey := &privKey.PublicKey

	validator := NewRSAValidator(pubKey, "ztna-idp", "ztna-gateway", 2*time.Second)

	claims := &Claims{
		Subject:    "user:carol",
		Issuer:     "ztna-idp",
		Audience:   []string{"ztna-gateway"},
		ExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
		Roles:      []string{"admin"},
		TrustLevel: "high",
	}

	token, err := GenerateRSA(claims, privKey)
	if err != nil {
		t.Fatalf("failed to generate RS256 token: %v", err)
	}

	parsed, err := validator.ValidateToken(token)
	if err != nil {
		t.Fatalf("expected valid RS256 token, got: %v", err)
	}
	if parsed.Subject != "user:carol" {
		t.Errorf("expected subject user:carol, got %s", parsed.Subject)
	}
	if parsed.TrustLevel != "high" {
		t.Errorf("expected high trust level, got %s", parsed.TrustLevel)
	}

	// Verify with a different public key fails
	otherPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherValidator := NewRSAValidator(&otherPrivKey.PublicKey, "ztna-idp", "ztna-gateway", 2*time.Second)
	if _, err := otherValidator.ValidateToken(token); err == nil {
		t.Error("expected signature mismatch with different key, got nil")
	}
}
