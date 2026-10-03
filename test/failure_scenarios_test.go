package test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauman/identity-access-proxy/internal/audit"
	"github.com/nauman/identity-access-proxy/internal/auth"
	"github.com/nauman/identity-access-proxy/internal/config"
	"github.com/nauman/identity-access-proxy/internal/policy"
	"github.com/nauman/identity-access-proxy/internal/proxy"
)

// TestZeroTrustSecurityScenarios tests the proxy against adversarial edge cases.
func TestZeroTrustSecurityScenarios(t *testing.T) {
	var capturedSubject string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSubject = r.Header.Get("X-ZTNA-Subject")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer mockUpstream.Close()

	secret := []byte("production-grade-secret-key-32-bytes")
	validator := auth.NewHMACValidator(secret, "ztna-idp", "ztna-gateway", time.Second)
	auditLogger := audit.NewLogger(new(bytes.Buffer))

	policySet := policy.PolicySet{
		DefaultAction: "deny",
		Rules: []policy.Rule{
			{
				ID:            "admin-rule",
				PathPrefix:    "/admin",
				RequiredRoles: []string{"admin"},
				DeviceRequirements: policy.DeviceRequirement{
					MinTrustLevel:      "high",
					RequireManaged:     true,
					RequireDiskEncrypt: true,
				},
				Action: "allow",
			},
		},
	}
	engine := policy.NewEngine(policySet)

	cfg := &config.Config{
		Routes: []config.UpstreamRoute{
			{PathPrefix: "/admin", TargetURL: mockUpstream.URL},
		},
	}

	server, err := proxy.NewServer(cfg, validator, engine, auditLogger)
	if err != nil {
		t.Fatalf("failed to initialize server: %v", err)
	}

	// Scenario 1: Forged Header Spoofing Attack
	// An attacker attempts to set X-ZTNA-Subject: root in HTTP request headers.
	t.Run("Header_Injection_Sanitization", func(t *testing.T) {
		validAdminClaims := &auth.Claims{
			Subject:   "user:alice",
			Issuer:    "ztna-idp",
			Audience:  []string{"ztna-gateway"},
			Roles:     []string{"admin"},
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		token, _ := auth.GenerateHMAC(validAdminClaims, secret)

		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Device-Posture", `{"is_managed":true,"disk_encrypted":true,"trust_score":90}`)
		// Attacker injects fake header
		req.Header.Set("X-ZTNA-Subject", "attacker-impersonating-root")

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rr.Code)
		}
		if capturedSubject != "user:alice" {
			t.Errorf("SECURITY FAILURE: Upstream received forged subject: %s instead of user:alice", capturedSubject)
		}
	})

	// Scenario 2: Signature Tampering Attack
	// Attacker modifies payload to elevate role to admin without re-signing.
	t.Run("Tampered_Signature_Rejection", func(t *testing.T) {
		userClaims := &auth.Claims{
			Subject:   "user:mallory",
			Issuer:    "ztna-idp",
			Audience:  []string{"ztna-gateway"},
			Roles:     []string{"user"},
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		token, _ := auth.GenerateHMAC(userClaims, secret)
		// Tamper signature
		tamperedToken := token[:len(token)-5] + "XXXXX"

		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+tamperedToken)
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for tampered token, got %d", rr.Code)
		}
	})

	// Scenario 3: BYOD / Unmanaged Device Rejection
	// Valid admin token presented, but from an unmanaged, unencrypted personal laptop.
	t.Run("Untrusted_Device_Posture_Denial", func(t *testing.T) {
		adminClaims := &auth.Claims{
			Subject:   "user:alice",
			Issuer:    "ztna-idp",
			Audience:  []string{"ztna-gateway"},
			Roles:     []string{"admin"},
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		}
		token, _ := auth.GenerateHMAC(adminClaims, secret)

		req := httptest.NewRequest("GET", "/admin/dashboard", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		// Personal device: unmanaged, disk unencrypted
		req.Header.Set("X-Device-Posture", `{"is_managed":false,"disk_encrypted":false,"trust_score":30}`)

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for untrusted device, got %d", rr.Code)
		}
	})
}
