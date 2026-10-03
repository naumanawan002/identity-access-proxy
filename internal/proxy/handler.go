package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nauman/identity-access-proxy/internal/audit"
	"github.com/nauman/identity-access-proxy/internal/auth"
	"github.com/nauman/identity-access-proxy/internal/config"
	"github.com/nauman/identity-access-proxy/internal/policy"
)

// Server is the Identity-Aware Access Proxy HTTP Handler.
type Server struct {
	config    *config.Config
	validator *auth.Validator
	engine    *policy.Engine
	auditLog  *audit.Logger
	routes    map[string]*url.URL
	proxies   map[string]*httputil.ReverseProxy
}

// NewServer builds and initializes the proxy engine.
func NewServer(cfg *config.Config, validator *auth.Validator, engine *policy.Engine, auditLog *audit.Logger) (*Server, error) {
	s := &Server{
		config:    cfg,
		validator: validator,
		engine:    engine,
		auditLog:  auditLog,
		routes:    make(map[string]*url.URL),
		proxies:   make(map[string]*httputil.ReverseProxy),
	}

	transport, err := NewUpstreamTransport(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("transport init error: %w", err)
	}

	// Initialize reverse proxies for each configured route
	for _, r := range cfg.Routes {
		target, err := url.Parse(r.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid route target %q: %w", r.TargetURL, err)
		}
		s.routes[r.PathPrefix] = target

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = transport

		// Custom director for route rewriting & security headers
		originalDirector := proxy.Director
		routePrefix := r.PathPrefix
		stripPath := r.StripPath

		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Host = target.Host

			if stripPath && strings.HasPrefix(req.URL.Path, routePrefix) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, routePrefix)
				if !strings.HasPrefix(req.URL.Path, "/") {
					req.URL.Path = "/" + req.URL.Path
				}
			}
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
			s.respondJSON(w, http.StatusBadGateway, map[string]string{
				"error":   "bad_gateway",
				"message": fmt.Sprintf("upstream %s unavailable: %v", target.Host, err),
			})
		}

		s.proxies[r.PathPrefix] = proxy
	}

	return s, nil
}

// ServeHTTP handles all incoming requests at the edge.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := generateRequestID()
	clientIP := getClientIP(r)

	// Health check endpoint bypasses auth
	if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","uptime":"ok"}`))
		return
	}

	// 1. Match Upstream Route
	matchedPrefix, targetURL, proxy := s.matchRoute(r.URL.Path)
	if proxy == nil {
		s.respondAndAudit(w, http.StatusNotFound, "not_found", "no route configured for path", r, nil, nil, start, requestID)
		return
	}

	// 2. Extract Device Posture
	posture := s.extractDevicePosture(r, clientIP)

	// 3. Authentication Phase
	token := auth.ExtractBearerToken(r)
	var claims *auth.Claims
	var authErr error

	if token != "" {
		claims, authErr = s.validator.ValidateToken(token)
		if authErr != nil {
			s.respondAndAudit(w, http.StatusUnauthorized, "invalid_token", authErr.Error(), r, nil, posture, start, requestID)
			return
		}
	}

	// 4. Policy Decision (PDP) Evaluation
	var subject string
	var roles, groups []string
	if claims != nil {
		subject = claims.Subject
		roles = claims.Roles
		groups = claims.Groups
	}

	evalCtx := policy.EvaluationContext{
		Subject:       subject,
		Roles:         roles,
		Groups:        groups,
		DevicePosture: posture,
		ClientIP:      clientIP,
		Method:        r.Method,
		Path:          r.URL.Path,
	}

	decision := s.engine.Evaluate(evalCtx)
	if !decision.Allowed {
		s.respondAndAudit(w, http.StatusForbidden, "access_denied", decision.Reason, r, claims, posture, start, requestID)
		return
	}

	// 5. Zero Trust Identity Propagation: Cleanse & Inject Verified Headers
	s.sanitizeAndInjectHeaders(r, claims, posture, requestID)

	// 6. Record success audit entry
	defer func() {
		dur := time.Since(start).Microseconds()
		_ = s.auditLog.Log(audit.Event{
			EventID:        requestID,
			Timestamp:      start.UTC(),
			ClientIP:       clientIP,
			Subject:        subject,
			Roles:          roles,
			Method:         r.Method,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			DeviceID:       posture.DeviceID,
			DeviceTrust:    posture.AssignedLevel,
			Allowed:        true,
			RuleID:         decision.RuleID,
			Reason:         decision.Reason,
			StatusCode:     http.StatusOK,
			DurationMicros: dur,
		})
	}()

	// 7. Dispatch via ReverseProxy to Target Upstream
	_ = matchedPrefix
	_ = targetURL
	proxy.ServeHTTP(w, r)
}

func (s *Server) matchRoute(path string) (string, *url.URL, *httputil.ReverseProxy) {
	var bestMatch string
	for prefix := range s.proxies {
		if strings.HasPrefix(path, prefix) {
			if len(prefix) > len(bestMatch) {
				bestMatch = prefix
			}
		}
	}
	if bestMatch != "" {
		return bestMatch, s.routes[bestMatch], s.proxies[bestMatch]
	}
	return "", nil, nil
}

// sanitizeAndInjectHeaders strips untrusted client-supplied identity headers and injects vouched ones.
func (s *Server) sanitizeAndInjectHeaders(r *http.Request, claims *auth.Claims, posture *auth.DevicePosture, reqID string) {
	// Strip any forged inbound headers
	r.Header.Del("X-ZTNA-Subject")
	r.Header.Del("X-ZTNA-Email")
	r.Header.Del("X-ZTNA-Roles")
	r.Header.Del("X-ZTNA-Device-Trust")
	r.Header.Del("X-ZTNA-Request-ID")
	r.Header.Del("X-Forwarded-Identity")

	// Inject cryptographically vouched identity headers
	r.Header.Set("X-ZTNA-Request-ID", reqID)
	if claims != nil {
		r.Header.Set("X-ZTNA-Subject", claims.Subject)
		if claims.Email != "" {
			r.Header.Set("X-ZTNA-Email", claims.Email)
		}
		if len(claims.Roles) > 0 {
			r.Header.Set("X-ZTNA-Roles", strings.Join(claims.Roles, ","))
		}
	}
	if posture != nil {
		r.Header.Set("X-ZTNA-Device-Trust", posture.AssignedLevel)
	}
}

func (s *Server) extractDevicePosture(r *http.Request, clientIP string) *auth.DevicePosture {
	posture := &auth.DevicePosture{
		ClientIP:      clientIP,
		AssignedLevel: "low",
	}

	headerVal := r.Header.Get("X-Device-Posture")
	if headerVal != "" {
		var parsed struct {
			DeviceID      string `json:"device_id"`
			OS            string `json:"os"`
			IsManaged     bool   `json:"is_managed"`
			DiskEncrypted bool   `json:"disk_encrypted"`
			TrustScore    int    `json:"trust_score"`
		}
		if err := json.Unmarshal([]byte(headerVal), &parsed); err == nil {
			posture.DeviceID = parsed.DeviceID
			posture.OS = parsed.OS
			posture.IsManaged = parsed.IsManaged
			posture.DiskEncrypted = parsed.DiskEncrypted
			posture.TrustScore = parsed.TrustScore

			if parsed.IsManaged && parsed.DiskEncrypted && parsed.TrustScore >= 80 {
				posture.AssignedLevel = "high"
			} else if parsed.IsManaged && parsed.TrustScore >= 50 {
				posture.AssignedLevel = "medium"
			}
		}
	}

	return posture
}

func (s *Server) respondAndAudit(w http.ResponseWriter, status int, errCode, reason string, r *http.Request, claims *auth.Claims, posture *auth.DevicePosture, start time.Time, reqID string) {
	dur := time.Since(start).Microseconds()
	var sub string
	var roles []string
	if claims != nil {
		sub = claims.Subject
		roles = claims.Roles
	}
	var deviceID, trust string
	if posture != nil {
		deviceID = posture.DeviceID
		trust = posture.AssignedLevel
	}

	_ = s.auditLog.Log(audit.Event{
		EventID:        reqID,
		Timestamp:      start.UTC(),
		ClientIP:       getClientIP(r),
		Subject:        sub,
		Roles:          roles,
		Method:         r.Method,
		Path:           r.URL.Path,
		UserAgent:      r.UserAgent(),
		DeviceID:       deviceID,
		DeviceTrust:    trust,
		Allowed:        false,
		Reason:         reason,
		StatusCode:     status,
		DurationMicros: dur,
	})

	s.respondJSON(w, status, map[string]any{
		"error":      errCode,
		"reason":     reason,
		"request_id": reqID,
	})
}

func (s *Server) respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
