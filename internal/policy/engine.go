package policy

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Engine is the Policy Decision Point (PDP) evaluating access decisions.
type Engine struct {
	mu            sync.RWMutex
	policySet     PolicySet
	defaultAction string
}

// NewEngine constructs a new policy evaluation engine.
func NewEngine(policySet PolicySet) *Engine {
	def := strings.ToLower(policySet.DefaultAction)
	if def == "" {
		def = "deny" // Enforce Zero Trust closed-by-default stance
	}
	return &Engine{
		policySet:     policySet,
		defaultAction: def,
	}
}

// UpdatePolicies dynamically reloads policy rules without stopping the proxy.
func (e *Engine) UpdatePolicies(newSet PolicySet) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policySet = newSet
	if newSet.DefaultAction != "" {
		e.defaultAction = strings.ToLower(newSet.DefaultAction)
	}
}

// Evaluate runs the authorization algorithm against the current rules.
func (e *Engine) Evaluate(ctx EvaluationContext) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()

	// Find all matching rules. Longest path prefix matches take precedence.
	var matchedRule *Rule
	for i := range e.policySet.Rules {
		r := &e.policySet.Rules[i]

		// 1. Path prefix check
		if !strings.HasPrefix(ctx.Path, r.PathPrefix) {
			continue
		}

		// 2. Method check
		if len(r.Methods) > 0 {
			methodMatches := false
			for _, m := range r.Methods {
				if strings.EqualFold(m, ctx.Method) {
					methodMatches = true
					break
				}
			}
			if !methodMatches {
				continue
			}
		}

		// Select the rule with the longer (more specific) prefix
		if matchedRule == nil || len(r.PathPrefix) > len(matchedRule.PathPrefix) {
			matchedRule = r
		}
	}

	if matchedRule == nil {
		return Decision{
			Allowed:     e.defaultAction == "allow",
			RuleID:      "default-policy",
			Reason:      fmt.Sprintf("no explicit rule matched path %q; applying default %s", ctx.Path, e.defaultAction),
			EvaluatedAt: now,
		}
	}

	// Rule was matched; now evaluate all conditions on the rule.

	// A. Role check: if required_roles is set, subject must have at least one of them
	if len(matchedRule.RequiredRoles) > 0 {
		roleFound := false
		for _, reqRole := range matchedRule.RequiredRoles {
			for _, userRole := range ctx.Roles {
				if reqRole == userRole {
					roleFound = true
					break
				}
			}
			if roleFound {
				break
			}
		}
		if !roleFound {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      fmt.Sprintf("missing required role: user has %v, requires one of %v", ctx.Roles, matchedRule.RequiredRoles),
				EvaluatedAt: now,
			}
		}
	}

	// B. Group check: if required_groups is set, subject must belong to at least one
	if len(matchedRule.RequiredGroups) > 0 {
		groupFound := false
		for _, reqGroup := range matchedRule.RequiredGroups {
			for _, userGroup := range ctx.Groups {
				if reqGroup == userGroup {
					groupFound = true
					break
				}
			}
			if groupFound {
				break
			}
		}
		if !groupFound {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      fmt.Sprintf("missing required group: user has %v, requires one of %v", ctx.Groups, matchedRule.RequiredGroups),
				EvaluatedAt: now,
			}
		}
	}

	// C. Device Posture & Zero Trust checks
	reqs := matchedRule.DeviceRequirements
	if reqs.MinTrustLevel != "" || reqs.RequireManaged || reqs.RequireDiskEncrypt {
		if ctx.DevicePosture == nil {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      "device posture verification failed: no posture context supplied",
				EvaluatedAt: now,
			}
		}

		if reqs.RequireManaged && !ctx.DevicePosture.IsManaged {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      "device posture failed: endpoint must be an organization-managed device",
				EvaluatedAt: now,
			}
		}

		if reqs.RequireDiskEncrypt && !ctx.DevicePosture.DiskEncrypted {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      "device posture failed: endpoint disk encryption is mandatory",
				EvaluatedAt: now,
			}
		}

		if reqs.MinTrustLevel != "" {
			reqRank := LevelRank(reqs.MinTrustLevel)
			actualRank := LevelRank(ctx.DevicePosture.AssignedLevel)
			if actualRank < reqRank {
				return Decision{
					Allowed:     false,
					RuleID:      matchedRule.ID,
					Reason:      fmt.Sprintf("insufficient device trust level: required %s, got %s", reqs.MinTrustLevel, ctx.DevicePosture.AssignedLevel),
					EvaluatedAt: now,
				}
			}
		}
	}

	// D. CIDR / IP restrictions
	if len(matchedRule.AllowedCIDRs) > 0 {
		if !IsIPInCIDRs(ctx.ClientIP, matchedRule.AllowedCIDRs) {
			return Decision{
				Allowed:     false,
				RuleID:      matchedRule.ID,
				Reason:      fmt.Sprintf("client IP %s is not inside authorized network CIDRs %v", ctx.ClientIP, matchedRule.AllowedCIDRs),
				EvaluatedAt: now,
			}
		}
	}

	// Rule matches and all conditions satisfied!
	isAllowed := strings.EqualFold(matchedRule.Action, "allow")
	reason := "authorized by rule " + matchedRule.ID
	if !isAllowed {
		reason = "explicit deny rule matched: " + matchedRule.ID
	}

	return Decision{
		Allowed:     isAllowed,
		RuleID:      matchedRule.ID,
		Reason:      reason,
		EvaluatedAt: now,
	}
}
