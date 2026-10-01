package policy

import (
	"testing"

	"github.com/nauman/identity-access-proxy/internal/auth"
)

func TestPolicyEngine_Evaluation(t *testing.T) {
	policySet := PolicySet{
		DefaultAction: "deny",
		Rules: []Rule{
			{
				ID:            "allow-public-health",
				Description:   "Public health endpoint",
				PathPrefix:    "/health",
				Action:        "allow",
			},
			{
				ID:            "api-general-user",
				Description:   "General API for regular users",
				PathPrefix:    "/api/v1",
				RequiredRoles: []string{"user", "admin"},
				Action:        "allow",
			},
			{
				ID:            "admin-restricted",
				Description:   "Admin area requires admin role and high device trust",
				PathPrefix:    "/api/v1/admin",
				RequiredRoles: []string{"admin"},
				DeviceRequirements: DeviceRequirement{
					MinTrustLevel:      "high",
					RequireManaged:     true,
					RequireDiskEncrypt: true,
				},
				AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"},
				Action:       "allow",
			},
		},
	}

	engine := NewEngine(policySet)

	// 1. Health check should be allowed without any user or device info
	d1 := engine.Evaluate(EvaluationContext{
		Path:   "/health",
		Method: "GET",
	})
	if !d1.Allowed {
		t.Errorf("expected /health to be allowed, got: %s", d1.Reason)
	}

	// 2. Regular user hitting /api/v1/orders
	d2 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/orders",
		Method:   "GET",
		Subject:  "user:bob",
		Roles:    []string{"user"},
		ClientIP: "192.168.1.50",
	})
	if !d2.Allowed {
		t.Errorf("expected /api/v1/orders allowed for user, got: %s", d2.Reason)
	}

	// 3. Regular user attempting to hit /api/v1/admin/users (Missing admin role)
	d3 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/admin/users",
		Method:   "GET",
		Subject:  "user:bob",
		Roles:    []string{"user"},
		ClientIP: "192.168.1.50",
	})
	if d3.Allowed {
		t.Error("expected /api/v1/admin/users denied for regular user, got allowed")
	}

	// 4. Admin hitting /api/v1/admin without device posture
	d4 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/admin/users",
		Method:   "GET",
		Subject:  "user:alice",
		Roles:    []string{"admin"},
		ClientIP: "192.168.1.10",
	})
	if d4.Allowed {
		t.Error("expected admin denied due to missing device posture")
	}

	// 5. Admin hitting with unmanaged device posture
	d5 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/admin/users",
		Method:   "GET",
		Subject:  "user:alice",
		Roles:    []string{"admin"},
		ClientIP: "192.168.1.10",
		DevicePosture: &auth.DevicePosture{
			IsManaged:     false,
			DiskEncrypted: true,
			AssignedLevel: "high",
		},
	})
	if d5.Allowed {
		t.Error("expected admin denied because device is not managed")
	}

	// 6. Admin hitting from unauthorized CIDR
	d6 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/admin/users",
		Method:   "GET",
		Subject:  "user:alice",
		Roles:    []string{"admin"},
		ClientIP: "203.0.113.195", // Public untrusted IP
		DevicePosture: &auth.DevicePosture{
			IsManaged:     true,
			DiskEncrypted: true,
			AssignedLevel: "high",
		},
	})
	if d6.Allowed {
		t.Error("expected admin denied due to external CIDR")
	}

	// 7. Full compliance: Admin, managed, encrypted, high trust, trusted IP
	d7 := engine.Evaluate(EvaluationContext{
		Path:     "/api/v1/admin/users",
		Method:   "GET",
		Subject:  "user:alice",
		Roles:    []string{"admin"},
		ClientIP: "10.1.2.3",
		DevicePosture: &auth.DevicePosture{
			IsManaged:     true,
			DiskEncrypted: true,
			AssignedLevel: "high",
		},
	})
	if !d7.Allowed {
		t.Errorf("expected compliant admin allowed, got: %s", d7.Reason)
	}

	// 8. Zero trust default deny for unknown path
	d8 := engine.Evaluate(EvaluationContext{
		Path:     "/unmapped/secret",
		Method:   "GET",
		Subject:  "user:alice",
		Roles:    []string{"admin"},
		ClientIP: "10.1.2.3",
	})
	if d8.Allowed {
		t.Error("expected unmapped path to be denied by default")
	}
}
