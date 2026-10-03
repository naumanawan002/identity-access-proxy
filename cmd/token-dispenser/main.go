package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nauman/identity-access-proxy/internal/auth"
)

func main() {
	sub := flag.String("sub", "alice", "Subject / user identifier")
	email := flag.String("email", "alice@example.com", "User email address")
	roles := flag.String("roles", "developer,admin", "Comma-separated roles")
	trust := flag.String("trust", "high", "Device trust level (low, medium, high)")
	device := flag.String("device", "dev-macbook-pro-01", "Device ID")
	ttl := flag.Duration("ttl", 15*time.Minute, "Token time-to-live duration")
	secret := flag.String("secret", "default-development-secret-change-in-prod-32bytes", "HMAC signing secret")
	issuer := flag.String("iss", "ztna-idp", "JWT Issuer")
	audience := flag.String("aud", "ztna-gateway", "JWT Audience")
	flag.Parse()

	var roleList []string
	for _, r := range strings.Split(*roles, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			roleList = append(roleList, r)
		}
	}

	claims := &auth.Claims{
		Subject:    *sub,
		Email:      *email,
		Issuer:     *issuer,
		Audience:   []string{*audience},
		Roles:      roleList,
		DeviceID:   *device,
		TrustLevel: *trust,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(*ttl).Unix(),
	}

	token, err := auth.GenerateHMAC(claims, []byte(*secret))
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	fmt.Println("==================================================")
	fmt.Println("  Zero Trust Identity Token Dispenser (HS256)")
	fmt.Println("==================================================")
	fmt.Printf("Subject:     %s\n", *sub)
	fmt.Printf("Email:       %s\n", *email)
	fmt.Printf("Roles:       %v\n", roleList)
	fmt.Printf("Trust Level: %s\n", *trust)
	fmt.Printf("Expires In:  %v\n", *ttl)
	fmt.Println("--------------------------------------------------")
	fmt.Println("JWT Token:")
	fmt.Println(token)
	fmt.Println("--------------------------------------------------")
	fmt.Println("Sample curl invocation:")
	fmt.Printf("curl -i -H 'Authorization: Bearer %s' \\\n", token)
	fmt.Println("     -H 'X-Device-Posture: {\"is_managed\":true,\"disk_encrypted\":true,\"trust_score\":95}' \\")
	fmt.Println("     http://localhost:8080/api/v1/admin/dashboard")
	fmt.Println("==================================================")
}
