package policy

import (
	"net"
	"strings"
	"time"

	"github.com/nauman/identity-access-proxy/internal/auth"
)

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allowed    bool      `json:"allowed"`
	RuleID     string    `json:"rule_id,omitempty"`
	Reason     string    `json:"reason"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// DeviceRequirement specifies device posture prerequisites for a rule.
type DeviceRequirement struct {
	MinTrustLevel      string `json:"min_trust_level,omitempty"` // "low", "medium", "high"
	RequireManaged     bool   `json:"require_managed,omitempty"`
	RequireDiskEncrypt bool   `json:"require_disk_encrypt,omitempty"`
}

// Rule defines an authorization policy statement.
type Rule struct {
	ID                 string            `json:"id"`
	Description        string            `json:"description,omitempty"`
	PathPrefix         string            `json:"path_prefix"`
	Methods            []string          `json:"methods,omitempty"` // empty matches any
	RequiredRoles      []string          `json:"required_roles,omitempty"`
	RequiredGroups     []string          `json:"required_groups,omitempty"`
	DeviceRequirements DeviceRequirement `json:"device_requirements,omitempty"`
	AllowedCIDRs       []string          `json:"allowed_cidrs,omitempty"`
	Action             string            `json:"action"` // "allow" or "deny"
}

// EvaluationContext contains the full contextual state presented to the PDP.
type EvaluationContext struct {
	Subject       string
	Roles         []string
	Groups        []string
	DevicePosture *auth.DevicePosture
	ClientIP      string
	Method        string
	Path          string
	Headers       map[string]string
}

// PolicySet is a bundle of rules evaluated in sequence or most-specific-first.
type PolicySet struct {
	DefaultAction string `json:"default_action"` // Defaults to "deny" (Zero Trust default)
	Rules         []Rule `json:"rules"`
}

// LevelRank helper to compare trust level strings.
func LevelRank(level string) int {
	switch strings.ToLower(level) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// IsIPInCIDRs checks if client IP falls into any of the configured CIDRs.
func IsIPInCIDRs(clientIP string, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true // No CIDR restriction
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
