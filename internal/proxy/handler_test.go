package proxy

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
)

func TestProxyServer_EndToEnd(t *testing.T) {
	// 1. Setup mock upstream backend service
	var receivedSubject, receivedForgedHeader string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSubject = r.Header.Get("X-ZTNA-Subject")
		receivedForgedHeader = r.Header.Get("X-Forged-Claim")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"ok"}`))
	}))
	defer mockUpstream.Close()

	// 2. Setup gateway components
	hmacSecret := []byte("proxy-test-secret-32-bytes-minimum")
	validator := auth.NewHMACValidator(hmacSecret, "test-idp", "test-proxy", time.Second)
	auditBuf := new(bytes.Buffer)
	auditLogger := audit.NewLogger(auditBuf)

	policySet := policy.PolicySet{
		DefaultAction: "deny",
		Rules: []RuleAlias{
			{
				ID:            "orders-rule",
				PathPrefix:    "/api/orders",
				RequiredRoles: []string{"buyer"},
				Action:        "allow",
			},
		},
	}
	engine := policy.NewEngine(policySet)

	cfg := &config.Config{
		Routes: []config.UpstreamRoute{
			{
				PathPrefix: "/api/orders",
				TargetURL:  mockUpstream.URL,
			},
		},
	}

	server, err := NewServer(cfg, validator, engine, auditLogger)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 3. Test: Unauthenticated request should be denied (403 or 401)
	req1 := httptest.NewRequest("GET", "/api/orders/list", nil)
	rr1 := httptest.NewRecorder()
	server.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Errorf("expected 403 on unauthenticated request, got %d", rr1.Code)
	}

	// 4. Test: Authenticated request with wrong role ("guest")
	guestClaims := &auth.Claims{
		Subject:   "user:bob",
		Issuer:    "test-idp",
		Audience:  []string{"test-proxy"},
		Roles:     []string{"guest"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	guestToken, _ := auth.GenerateHMAC(guestClaims, hmacSecret)

	req2 := httptest.NewRequest("GET", "/api/orders/list", nil)
	req2.Header.Set("Authorization", "Bearer "+guestToken)
	rr2 := httptest.NewRecorder()
	server.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for guest role, got %d", rr2.Code)
	}

	// 5. Test: Valid authenticated request with role "buyer"
	buyerClaims := &auth.Claims{
		Subject:   "user:alice",
		Email:     "alice@example.com",
		Issuer:    "test-idp",
		Audience:  []string{"test-proxy"},
		Roles:     []string{"buyer"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	buyerToken, _ := auth.GenerateHMAC(buyerClaims, hmacSecret)

	req3 := httptest.NewRequest("GET", "/api/orders/list", nil)
	req3.Header.Set("Authorization", "Bearer "+buyerToken)
	// Inject a forged identity header that the proxy MUST strip
	req3.Header.Set("X-ZTNA-Subject", "forged:hacker")
	rr3 := httptest.NewRecorder()
	server.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rr3.Code)
	}

	// Verify upstream received the authenticated subject and NOT the forged one!
	if receivedSubject != "user:alice" {
		t.Errorf("expected upstream to receive X-ZTNA-Subject: user:alice, got %q", receivedSubject)
	}

	// Verify audit log has entries
	if auditBuf.Len() == 0 {
		t.Error("expected audit log entries, buffer was empty")
	}
}

// RuleAlias helper to avoid circular imports in tests
type RuleAlias = policy.Rule
