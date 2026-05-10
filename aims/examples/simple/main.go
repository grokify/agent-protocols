// Package main demonstrates basic AIMS agent authentication with SPIFFE ID.
//
// This example shows:
//   - Creating a SPIFFE ID for an agent
//   - Creating a Workload Identity Token (WIT)
//   - Creating a WIMSE Proof Token (WPT) for a specific request
//   - Verifying the agent identity
//
// # EXPERIMENTAL
//
// This example implements draft-klrc-aiagent-auth-00 and draft-ietf-wimse-s2s-protocol
// which are subject to change.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aistandardsio/agent-protocols/aims"
)

const (
	trustDomain    = "example.com"
	agentPath      = "/agent/calendar-bot"
	targetAudience = "https://api.example.com"
)

func main() {
	log.Println("=== AIMS Simple Authentication Demo ===")
	log.Println("This demo shows agent authentication using SPIFFE ID and WIMSE tokens.")
	log.Println()

	// Step 1: Create SPIFFE ID for the agent
	log.Println("1. Creating SPIFFE ID for agent...")
	spiffeID, err := aims.NewSPIFFEID(trustDomain, agentPath)
	if err != nil {
		log.Fatalf("Failed to create SPIFFE ID: %v", err)
	}
	log.Printf("   SPIFFE ID: %s", spiffeID.String())
	log.Printf("   Trust Domain: %s", spiffeID.TrustDomain)
	log.Printf("   Path: %s", spiffeID.Path)
	log.Printf("   Is Agent: %v", spiffeID.IsAgent())
	log.Println()

	// Step 2: Generate a key pair for the agent
	log.Println("2. Generating agent key pair...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	keyID := "agent-key-1"
	log.Printf("   Key type: ECDSA P-256")
	log.Printf("   Key ID: %s", keyID)
	log.Println()

	// Step 3: Create a Workload Identity Token (WIT)
	log.Println("3. Creating Workload Identity Token (WIT)...")
	wit := aims.NewWIT(
		spiffeID,
		[]string{targetAudience},
		1*time.Hour,
		aims.WithWITJTI(aims.GenerateJTI()),
		aims.WithWITCNF(&aims.CNF{Kid: keyID}),
	)
	log.Printf("   Issuer: %s", wit.Issuer)
	log.Printf("   Subject: %s", wit.Subject)
	log.Printf("   Audience: %v", wit.Audience)
	log.Printf("   Expires in: %v", wit.TimeToExpiry().Round(time.Second))
	log.Println()

	// Sign the WIT
	signedWIT, err := wit.Sign(privateKey, keyID)
	if err != nil {
		log.Fatalf("Failed to sign WIT: %v", err)
	}
	log.Printf("   Signed WIT (length: %d chars)", len(signedWIT))
	log.Println()

	// Step 4: Create a WIMSE Proof Token (WPT) for a specific request
	log.Println("4. Creating WIMSE Proof Token (WPT) for request...")
	req, _ := http.NewRequest(http.MethodPost, targetAudience+"/api/v1/events", nil)
	wpt := aims.NewWPTForRequest(spiffeID.String(), targetAudience, req)
	log.Printf("   Issuer: %s", wpt.Issuer)
	log.Printf("   Audience: %s", wpt.Audience)
	log.Printf("   HTTP Method (htm): %s", wpt.HTM)
	log.Printf("   HTTP URI (htu): %s", wpt.HTU)
	log.Println()

	// Sign the WPT and bind to request
	if err := wpt.BindToRequest(req, privateKey, keyID); err != nil {
		log.Fatalf("Failed to bind WPT to request: %v", err)
	}
	log.Printf("   WPT added to header: %s", aims.HeaderWPT)
	log.Printf("   Header value length: %d chars", len(req.Header.Get(aims.HeaderWPT)))
	log.Println()

	// Step 5: Create an AgentIdentity combining all components
	log.Println("5. Creating AgentIdentity...")
	jwtSVID := aims.NewJWTSVID(signedWIT, spiffeID, wit.Expiry)
	identity := aims.NewAgentIdentity(
		spiffeID,
		jwtSVID,
		aims.WithMetadata("agent-type", "calendar-bot"),
		aims.WithMetadata("version", "1.0.0"),
	)
	log.Printf("   SPIFFE ID: %s", identity.SPIFFEID.String())
	log.Printf("   Credential Type: %s", identity.Credential.Type())
	log.Printf("   Is Valid: %v", identity.IsValid())
	log.Printf("   Expires At: %s", identity.ExpiresAt().Format(time.RFC3339))
	log.Printf("   Metadata: %v", identity.Metadata)
	log.Println()

	// Demonstrate validation
	log.Println("6. Validating tokens...")
	if err := wit.Validate(); err != nil {
		log.Printf("   WIT validation failed: %v", err)
	} else {
		log.Println("   WIT validation: PASSED")
	}

	if err := wpt.Validate(); err != nil {
		log.Printf("   WPT validation failed: %v", err)
	} else {
		log.Println("   WPT validation: PASSED")
	}

	if wpt.MatchesRequest(req) {
		log.Println("   WPT matches request: YES")
	} else {
		log.Println("   WPT matches request: NO")
	}
	log.Println()

	fmt.Println("Demo completed successfully!")
}
