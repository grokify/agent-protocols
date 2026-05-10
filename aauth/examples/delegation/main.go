// Package main demonstrates the AAuth delegation flow.
//
// In the delegation flow:
// 1. Human authorizes an agent for specific resources and scopes
// 2. Agent requests a delegation token from the Person Server
// 3. Agent uses the delegation to access resources
//
// This flow enables humans to delegate authority to agents with
// fine-grained scope control and time-limited access.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
)

func main() {
	// Generate keys for all parties
	agentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resourceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	psKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create the Person Server
	ps, err := aauth.NewAuthServer(
		"https://ps.example.com",
		psKey,
		"ps-key-1",
		aauth.WithAuthTokenTTL(time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to create person server: %v", err)
	}

	// Start the Person Server
	psHandler := ps.Handler()
	psServer := httptest.NewServer(psHandler)
	defer psServer.Close()

	fmt.Printf("Person Server running at: %s\n", psServer.URL)

	// Create the agent
	agentID, _ := aauth.NewAAuthID("task-agent", "example.com")
	agent, err := aauth.NewAgent(
		agentID,
		agentKey,
		aauth.WithAgentProviderURL("https://agents.example.com"),
	)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	fmt.Printf("Created agent: %s\n", agentID)

	// Create the resource server
	rs, err := aauth.NewResourceServer(
		"https://tasks.example.com",
		resourceKey,
		"resource-key-1",
		aauth.WithResourcePersonServer(psServer.URL),
		aauth.WithRequiredScope("tasks:manage"),
		aauth.WithIdentityOnlyMode(false), // Auth token required
	)
	if err != nil {
		log.Fatalf("Failed to create resource server: %v", err)
	}

	fmt.Printf("Created resource server: %s\n", rs.URL())

	// Create a resource handler
	resourceHandler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := aauth.VerificationResultFromContext(r.Context())
		if !ok {
			http.Error(w, "No verification result", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"message":  "Task management access granted!",
			"agent_id": result.AgentID.String(),
			"scope":    "",
		}
		if result.AuthToken != nil {
			response["scope"] = result.AuthToken.Scope
			response["delegator"] = result.AuthToken.Subject
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))

	resourceServer := httptest.NewServer(resourceHandler)
	defer resourceServer.Close()

	fmt.Printf("Resource server running at: %s\n\n", resourceServer.URL)

	// Step 1: Simulate human authorization (pre-registering delegation)
	fmt.Println("Step 1: Human authorizes agent for task management...")

	// Get agent's JWK thumbprint
	agentJKT, err := agent.KeyPair().Thumbprint()
	if err != nil {
		log.Fatalf("Failed to get agent thumbprint: %v", err)
	}

	// In a real implementation, this would happen through a web UI
	// where the human logs in and grants permissions to the agent
	fmt.Printf("  Agent JKT: %s\n", agentJKT)
	fmt.Printf("  Scope granted: tasks:manage\n")
	fmt.Printf("  Resource: %s\n", rs.URL())

	// Step 2: Agent requests auth token from Person Server
	fmt.Println("\nStep 2: Agent requests auth token from Person Server...")

	// Create the auth token (simulating PS verification of delegation)
	cnf, _ := aauth.NewCNFWithJWK(&agentKey.PublicKey, "agent-key-1")
	authTokenStr, err := ps.SignAuthToken(agentID, cnf, []string{rs.URL()}, "tasks:manage")
	if err != nil {
		log.Fatalf("Failed to sign auth token: %v", err)
	}

	fmt.Printf("  Auth token issued (length: %d chars)\n", len(authTokenStr))

	// Parse for display
	authToken, _ := aauth.ParseAuthToken(authTokenStr)
	fmt.Printf("  Token subject: %s\n", authToken.Subject)
	fmt.Printf("  Token scope: %s\n", authToken.Scope)
	fmt.Printf("  Token audience: %v\n", authToken.Audience)

	// Step 3: Agent accesses resource with delegated authority
	fmt.Println("\nStep 3: Accessing resource with delegated authority...")

	ctx := context.Background()
	req, _ := agent.SignedRequest(ctx, "POST", resourceServer.URL+"/tasks", nil)
	req.Header.Set(aauth.HeaderAuthorization, "Bearer "+authTokenStr)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	if resp.StatusCode == http.StatusOK {
		var body map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		fmt.Printf("  Response body: %v\n", body)
	}

	// Step 4: Demonstrate scope restriction
	fmt.Println("\nStep 4: Demonstrating scope restriction...")

	// Try to access with a different scope (would fail in real implementation)
	fmt.Printf("  Agent can only perform actions within granted scope: tasks:manage\n")
	fmt.Printf("  Attempting tasks:delete would require additional authorization\n")

	fmt.Println("\nDelegation flow completed!")
	fmt.Println("\nKey concepts demonstrated:")
	fmt.Println("  1. Human pre-authorizes agent for specific resources/scopes")
	fmt.Println("  2. Agent obtains proof-of-possession bound auth token")
	fmt.Println("  3. Resource verifies both agent identity and delegation")
	fmt.Println("  4. Scopes limit what agent can do on behalf of human")
}
