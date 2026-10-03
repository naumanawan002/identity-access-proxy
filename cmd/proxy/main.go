package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nauman/identity-access-proxy/internal/audit"
	"github.com/nauman/identity-access-proxy/internal/auth"
	"github.com/nauman/identity-access-proxy/internal/config"
	"github.com/nauman/identity-access-proxy/internal/policy"
	"github.com/nauman/identity-access-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "examples/config.json", "Path to gateway JSON configuration file")
	flag.Parse()

	log.Println("[INFO] Starting Zero Trust Identity-Aware Access Proxy...")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Could not load configuration: %v", err)
	}

	// 1. Initialize Validator
	var validator *auth.Validator
	switch cfg.Auth.SigningAlgorithm {
	case "HS256", "":
		secret := []byte(cfg.Auth.HMACSecret)
		if len(secret) == 0 {
			secret = []byte("default-development-secret-change-in-prod-32bytes")
			log.Println("[WARN] Using default development HMAC secret. Set ZTNA_HMAC_SECRET in production!")
		}
		validator = auth.NewHMACValidator(secret, cfg.Auth.ExpectedIssuer, cfg.Auth.ExpectedAudience, cfg.Auth.ClockSkew())

	case "RS256":
		pubKey, err := loadRSAPublicKey(cfg.Auth.RSAPublicKeyFile)
		if err != nil {
			log.Fatalf("[FATAL] Failed to load RSA public key: %v", err)
		}
		validator = auth.NewRSAValidator(pubKey, cfg.Auth.ExpectedIssuer, cfg.Auth.ExpectedAudience, cfg.Auth.ClockSkew())

	default:
		log.Fatalf("[FATAL] Unsupported signing algorithm: %s", cfg.Auth.SigningAlgorithm)
	}

	// 2. Initialize Policy Engine
	engine := policy.NewEngine(cfg.Policies)

	// 3. Initialize Audit Logger
	auditLogger := audit.NewLogger(os.Stdout)

	// 4. Initialize Proxy Server Handler
	serverHandler, err := proxy.NewServer(cfg, validator, engine, auditLogger)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize proxy server: %v", err)
	}

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      serverHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("[INFO] Zero Trust Proxy listening on %s (HTTPS: %v)\n", cfg.ListenAddr, cfg.TLS.Enabled)
		for _, r := range cfg.Routes {
			log.Printf("[INFO]   Route: %s -> %s (strip: %v)\n", r.PathPrefix, r.TargetURL, r.StripPath)
		}

		var srvErr error
		if cfg.TLS.Enabled {
			srvErr = httpServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			srvErr = httpServer.ListenAndServe()
		}

		if srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("[FATAL] Server error: %v", srvErr)
		}
	}()

	<-ctx.Done()
	log.Println("[INFO] Shutting down Zero Trust Proxy gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("[ERROR] Graceful shutdown failed: %v", err)
	}
	log.Println("[INFO] Gateway terminated cleanly.")
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPub, nil
}
