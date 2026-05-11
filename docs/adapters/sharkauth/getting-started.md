# Getting Started with SharkAuth Adapter

This guide walks you through using the SharkAuth adapter for agent authentication with delegation support.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/adapters/sharkauth
```

## Basic Usage

### Creating a Client

```go
import "github.com/aistandardsio/agent-protocols/adapters/sharkauth"

// Create client with credentials
client, err := sharkauth.NewClient("https://auth.example.com",
    sharkauth.WithClientCredentials("client-id", "client-secret"),
)
if err != nil {
    log.Fatal(err)
}
```

### Token Exchange

Exchange an AAuth agent token for an access token:

```go
import "github.com/aistandardsio/agent-protocols/aauth"

// Create AAuth agent
agent, _ := aauth.NewAgent(
    &aauth.AAuthID{Local: "calendar-bot", Domain: "example.com"},
    privateKey,
)

// Sign agent token
agentToken, _ := agent.SignAgentToken("https://auth.example.com")

// Exchange for access token
resp, err := client.ExchangeAAuthToken(ctx, agentToken,
    sharkauth.WithScope("calendar:read"),
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", resp.AccessToken)
fmt.Printf("Expires In: %d seconds\n", resp.ExpiresIn)
```

### Using DPoP

Add proof-of-possession binding with DPoP:

```go
// Create DPoP proof for the token endpoint
proof, err := sharkauth.CreateDPoPProof(privateKey, "POST", client.TokenURL())
if err != nil {
    log.Fatal(err)
}

// Exchange with DPoP
resp, err := client.ExchangeAAuthToken(ctx, agentToken,
    sharkauth.WithScope("calendar:read"),
    sharkauth.WithDPoP(proof.Token),
)

// Token is now DPoP-bound
fmt.Printf("Token Type: %s\n", resp.TokenType) // "DPoP"
```

### Managing Delegation Grants

Create and manage `may_act_grants`:

```go
// Create a delegation grant
grant, err := client.CreateDelegationGrant(ctx, sharkauth.DelegationGrantRequest{
    ActorSubject: "agent:calendar-bot",
    UserSubject:  "user:alice",
    Scopes:       []string{"calendar:read", "calendar:write"},
    TTL:          24 * time.Hour,
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Grant ID: %s\n", grant.GrantID)

// List grants for a user
grants, _ := client.ListDelegationGrants(ctx,
    sharkauth.WithUserSubject("user:alice"),
    sharkauth.WithActiveOnly(),
)

for _, g := range grants {
    fmt.Printf("Grant: %s -> %s\n", g.UserSubject, g.ActorSubject)
}

// Revoke a grant (cascades to child grants)
err = client.RevokeDelegationGrant(ctx, grant.GrantID)
```

## Running the Example

A complete working example is available:

```bash
go run ./adapters/sharkauth/examples/aauth
```

This demonstrates:

1. Creating delegation grants
2. Creating AAuth agents
3. Signing agent tokens
4. Creating DPoP proofs
5. Exchanging tokens via SharkAuth
6. Listing and revoking grants

## Configuration Options

### Client Options

| Option | Description |
|--------|-------------|
| `WithHTTPClient(client)` | Custom HTTP client |
| `WithClientCredentials(id, secret)` | OAuth client credentials |
| `WithStaticTokenEndpoint(url)` | Override token endpoint URL |

### Exchange Options

| Option | Description |
|--------|-------------|
| `WithScope(scope)` | Requested scope |
| `WithAudience(aud)` | Target audience |
| `WithDPoP(proof)` | DPoP proof token |
| `WithResource(uri)` | Resource indicator |

### DPoP Options

| Option | Description |
|--------|-------------|
| `WithNonce(nonce)` | Server-provided nonce |
| `WithAccessTokenBinding(token)` | Bind to access token (for resource access) |
| `WithJTI(jti)` | Custom JWT ID |

## Next Steps

- [Overview](overview.md) - Architecture and features
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/adapters/sharkauth) - Full API documentation
