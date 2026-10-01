package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken       = errors.New("invalid token format")
	ErrUnsupportedAlg     = errors.New("unsupported signing algorithm")
	ErrSignatureMismatch  = errors.New("signature verification failed")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenNotYetValid   = errors.New("token is not valid yet (nbf)")
	ErrInvalidIssuer      = errors.New("token issuer does not match expected issuer")
	ErrInvalidAudience    = errors.New("token audience does not match expected audience")
	ErrMissingSubject     = errors.New("missing sub claim in token")
)

// Header represents the standard JWT header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Claims represents the identity and contextual claims carried inside the JWT.
type Claims struct {
	Subject       string   `json:"sub"`
	Issuer        string   `json:"iss,omitempty"`
	Audience      []string `json:"aud,omitempty"`
	ExpiresAt     int64    `json:"exp,omitempty"`
	NotBefore     int64    `json:"nbf,omitempty"`
	IssuedAt      int64    `json:"iat,omitempty"`
	Email         string   `json:"email,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	DeviceID      string   `json:"device_id,omitempty"`
	TrustLevel    string   `json:"trust_level,omitempty"` // e.g. "low", "medium", "high"
	Custom        map[string]any `json:"custom,omitempty"`
}

// UnmarshalJSON custom unmarshaler to support audience as either string or array of strings.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type Alias Claims
	aux := struct {
		Audience any `json:"aud,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch v := aux.Audience.(type) {
	case string:
		c.Audience = []string{v}
	case []any:
		c.Audience = make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}
	return nil
}

// Validator validates incoming JWT tokens according to RFC 7519.
type Validator struct {
	hmacSecret       []byte
	rsaPublicKey     *rsa.PublicKey
	expectedIssuer   string
	expectedAudience string
	clockSkew        time.Duration
}

// NewHMACValidator creates a validator for HS256 tokens.
func NewHMACValidator(secret []byte, expectedIssuer, expectedAudience string, clockSkew time.Duration) *Validator {
	return &Validator{
		hmacSecret:       secret,
		expectedIssuer:   expectedIssuer,
		expectedAudience: expectedAudience,
		clockSkew:        clockSkew,
	}
}

// NewRSAValidator creates a validator for RS256 tokens.
func NewRSAValidator(pubKey *rsa.PublicKey, expectedIssuer, expectedAudience string, clockSkew time.Duration) *Validator {
	return &Validator{
		rsaPublicKey:     pubKey,
		expectedIssuer:   expectedIssuer,
		expectedAudience: expectedAudience,
		clockSkew:        clockSkew,
	}
}

// ValidateToken parses, verifies the signature, and validates claims for a given JWT string.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header encoding", ErrInvalidToken)
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header json", ErrInvalidToken)
	}

	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidToken)
	}

	// Verify cryptographic signature
	switch header.Alg {
	case "HS256":
		if len(v.hmacSecret) == 0 {
			return nil, ErrUnsupportedAlg
		}
		mac := hmac.New(sha256.New, v.hmacSecret)
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		// Constant-time compare prevents timing side-channel attacks
		if subtle.ConstantTimeCompare(signatureBytes, expectedSig) != 1 {
			return nil, ErrSignatureMismatch
		}

	case "RS256":
		if v.rsaPublicKey == nil {
			return nil, ErrUnsupportedAlg
		}
		hashed := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(v.rsaPublicKey, crypto.SHA256, hashed[:], signatureBytes); err != nil {
			return nil, ErrSignatureMismatch
		}

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, header.Alg)
	}

	// Decode payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidToken)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid payload json", ErrInvalidToken)
	}

	// Validate temporal claims
	now := time.Now().Unix()
	skewSeconds := int64(v.clockSkew.Seconds())

	if claims.ExpiresAt > 0 && now-skewSeconds > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	if claims.NotBefore > 0 && now+skewSeconds < claims.NotBefore {
		return nil, ErrTokenNotYetValid
	}

	if v.expectedIssuer != "" && claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("%w: got %q, expected %q", ErrInvalidIssuer, claims.Issuer, v.expectedIssuer)
	}

	if v.expectedAudience != "" {
		matched := false
		for _, aud := range claims.Audience {
			if aud == v.expectedAudience {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("%w: %q not in %v", ErrInvalidAudience, v.expectedAudience, claims.Audience)
		}
	}

	if claims.Subject == "" {
		return nil, ErrMissingSubject
	}

	return &claims, nil
}

// GenerateHMAC creates a signed HS256 JWT for testing and mock IdP issuance.
func GenerateHMAC(claims *Claims, secret []byte) (string, error) {
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64URLEncode(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64URLEncode(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	signatureB64 := base64URLEncode(mac.Sum(nil))

	return signingInput + "." + signatureB64, nil
}

// GenerateRSA creates a signed RS256 JWT using a private key.
func GenerateRSA(claims *Claims, privKey *rsa.PrivateKey) (string, error) {
	header := Header{
		Alg: "RS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64URLEncode(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64URLEncode(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64URLEncode(sig), nil
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
