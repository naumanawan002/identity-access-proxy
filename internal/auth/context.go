package auth

import (
	"context"
	"net/http"
)

type contextKey string

const (
	identityKey contextKey = "ztna.identity"
	postureKey  contextKey = "ztna.posture"
)

// DevicePosture encapsulates client context gathered at the edge.
type DevicePosture struct {
	DeviceID        string `json:"device_id"`
	OS              string `json:"os"`
	IsManaged       bool   `json:"is_managed"`
	DiskEncrypted   bool   `json:"disk_encrypted"`
	ClientIP        string `json:"client_ip"`
	TrustScore      int    `json:"trust_score"`      // 0 to 100
	AssignedLevel   string `json:"assigned_level"`   // "low", "medium", "high"
}

// IdentityContext bundles the validated subject, claims, and device state.
type IdentityContext struct {
	Claims        *Claims
	DevicePosture *DevicePosture
	RawToken      string
}

// WithIdentity stores the IdentityContext in the request context.
func WithIdentity(ctx context.Context, ident *IdentityContext) context.Context {
	return context.WithValue(ctx, identityKey, ident)
}

// GetIdentity retrieves the IdentityContext from the context.
func GetIdentity(ctx context.Context) (*IdentityContext, bool) {
	ident, ok := ctx.Value(identityKey).(*IdentityContext)
	return ident, ok
}

// WithDevicePosture stores device posture in context.
func WithDevicePosture(ctx context.Context, posture *DevicePosture) context.Context {
	return context.WithValue(ctx, postureKey, posture)
}

// GetDevicePosture retrieves the device posture from context.
func GetDevicePosture(ctx context.Context) (*DevicePosture, bool) {
	posture, ok := ctx.Value(postureKey).(*DevicePosture)
	return posture, ok
}

// ExtractBearerToken extracts the token from the Authorization header or cookie.
func ExtractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	// Fallback to session cookie
	if cookie, err := r.Cookie("ztna_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}
