package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/nauman/identity-access-proxy/internal/config"
)

// NewUpstreamTransport creates an http.Transport configured with optional mTLS.
func NewUpstreamTransport(tlsCfg config.TLSConfig) (*http.Transport, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if !tlsCfg.UpstreamMTLS {
		return transport, nil
	}

	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA cert to verify upstream server identity
	if tlsCfg.UpstreamCACert != "" {
		caData, err := os.ReadFile(tlsCfg.UpstreamCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse upstream CA certificate")
		}
		tlsClientConfig.RootCAs = caPool
	}

	// Load client certificate for mutual TLS authentication
	if tlsCfg.ClientCert != "" && tlsCfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.ClientCert, tlsCfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client mTLS keypair: %w", err)
		}
		tlsClientConfig.Certificates = []tls.Certificate{cert}
	}

	transport.TLSClientConfig = tlsClientConfig
	return transport, nil
}
