package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nauman/identity-access-proxy/internal/policy"
)

// UpstreamRoute maps an incoming request path prefix to an upstream service.
type UpstreamRoute struct {
	PathPrefix string `json:"path_prefix"`
	TargetURL  string `json:"target_url"`
	StripPath  bool   `json:"strip_path,omitempty"`
}

// TLSConfig defines edge and upstream TLS parameters.
type TLSConfig struct {
	Enabled       bool   `json:"enabled"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
	UpstreamMTLS  bool   `json:"upstream_mtls,omitempty"`
	ClientCert    string `json:"client_cert,omitempty"`
	ClientKey     string `json:"client_key,omitempty"`
	UpstreamCACert string `json:"upstream_ca_cert,omitempty"`
}

// AuthConfig defines JWT verification parameters.
type AuthConfig struct {
	SigningAlgorithm string        `json:"signing_algorithm"` // "HS256" or "RS256"
	HMACSecret       string        `json:"hmac_secret,omitempty"`
	RSAPublicKeyFile string        `json:"rsa_public_key_file,omitempty"`
	ExpectedIssuer   string        `json:"expected_issuer"`
	ExpectedAudience string        `json:"expected_audience"`
	ClockSkewSeconds int           `json:"clock_skew_seconds,omitempty"`
}

// Config represents the complete gateway configuration.
type Config struct {
	ListenAddr string             `json:"listen_addr"`
	TLS        TLSConfig          `json:"tls"`
	Auth       AuthConfig         `json:"auth"`
	Routes     []UpstreamRoute    `json:"routes"`
	Policies   policy.PolicySet   `json:"policies"`
}

// ClockSkew returns time.Duration from configured seconds.
func (a *AuthConfig) ClockSkew() time.Duration {
	if a.ClockSkewSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(a.ClockSkewSeconds) * time.Second
}

// LoadConfig reads and parses a JSON configuration file.
func LoadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse json config: %w", err)
	}

	// Apply environment variable overrides if present
	if envAddr := os.Getenv("ZTNA_LISTEN_ADDR"); envAddr != "" {
		cfg.ListenAddr = envAddr
	}
	if envSecret := os.Getenv("ZTNA_HMAC_SECRET"); envSecret != "" {
		cfg.Auth.HMACSecret = envSecret
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}

	return &cfg, nil
}
