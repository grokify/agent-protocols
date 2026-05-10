# Getting Started with AAuth

This guide covers installation and basic usage of the AAuth package.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/aauth
```

## Quick Start

### Creating an Agent

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "log"

    "github.com/aistandardsio/agent-protocols/aauth"
)

func main() {
    // Generate a key pair for the agent
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // Create an AAuth ID
    agentID, err := aauth.NewAAuthID("calendar-bot", "example.com")
    if err != nil {
        log.Fatal(err)
    }

    // Create the agent
    agent, err := aauth.NewAgent(
        agentID,
        privateKey,
        aauth.WithAgentProviderURL("https://agents.example.com"),
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created agent: %s", agentID)
}
```

### Making Signed Requests

```go
import (
    "context"
    "net/http"
)

func makeRequest(agent *aauth.Agent) error {
    ctx := context.Background()

    // Create a signed HTTP request
    req, err := agent.SignedRequest(ctx, "GET", "https://api.example.com/events", nil)
    if err != nil {
        return err
    }

    // Send the request
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    log.Printf("Response: %d", resp.StatusCode)
    return nil
}
```

### Using the Signing Transport

For automatic request signing, use the `SigningTransport`:

```go
import "net/http"

func createSigningClient(agent *aauth.Agent) *http.Client {
    return &http.Client{
        Transport: agent.Transport(nil), // wraps http.DefaultTransport
    }
}

// All requests through this client are automatically signed
client := createSigningClient(agent)
resp, err := client.Get("https://api.example.com/events")
```

### Creating a Resource Server

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/json"
    "net/http"

    "github.com/aistandardsio/agent-protocols/aauth"
)

func main() {
    // Generate resource server key
    resourceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    // Create resource server
    rs, _ := aauth.NewResourceServer(
        "https://api.example.com",
        resourceKey,
        "resource-key-1",
        aauth.WithIdentityOnlyMode(true), // No auth token required
    )

    // Create handler with middleware
    handler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get verified agent info from context
        agentID, ok := aauth.AgentIDFromContext(r.Context())
        if !ok {
            http.Error(w, "No agent ID", http.StatusUnauthorized)
            return
        }

        json.NewEncoder(w).Encode(map[string]string{
            "message": "Hello, " + agentID.String(),
        })
    }))

    http.ListenAndServe(":8080", handler)
}
```

### Requiring Auth Tokens

For resources requiring Person Server authorization:

```go
rs, _ := aauth.NewResourceServer(
    "https://api.example.com",
    resourceKey,
    "resource-key-1",
    aauth.WithResourcePersonServer("https://ps.example.com"),
    aauth.WithRequiredScope("calendar:read"),
    aauth.WithIdentityOnlyMode(false), // Require auth tokens
)

handler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    result, _ := aauth.VerificationResultFromContext(r.Context())

    if result.AuthToken != nil {
        // Access granted with scope: result.AuthToken.Scope
    }
}))
```

### Creating a Person Server

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "net/http"
    "time"

    "github.com/aistandardsio/agent-protocols/aauth"
)

func main() {
    // Generate Person Server key
    psKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    // Create Person Server
    ps, _ := aauth.NewAuthServer(
        "https://ps.example.com",
        psKey,
        "ps-key-1",
        aauth.WithAuthTokenTTL(time.Hour),
    )

    // Get the HTTP handler
    handler := ps.Handler()

    http.ListenAndServe(":8081", handler)
}
```

## Discovery

### Discovering Resource Metadata

```go
import "context"

client := aauth.NewDiscoveryClient()
ctx := context.Background()

// Discover resource metadata
metadata, err := client.DiscoverResource(ctx, "https://api.example.com")
if err != nil {
    log.Fatal(err)
}

log.Printf("Person Server: %s", metadata.PersonServerURI)
log.Printf("JWKS URI: %s", metadata.JWKSURI)
```

### Discovering the Full Flow

```go
// Discover resource and its Person Server
tokenEndpoint, metadata, err := client.DiscoverResourceFlow(ctx, "https://api.example.com")
if err != nil {
    log.Fatal(err)
}

log.Printf("Token Endpoint: %s", tokenEndpoint)
```

## Next Steps

- [Examples](examples.md) - Run the demo applications
- [Diagrams](diagrams.md) - Understand the protocol flows visually
- [API Reference](api-reference.md) - Full Go package documentation
