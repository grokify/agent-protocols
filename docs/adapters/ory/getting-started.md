# Getting Started with Ory Adapter

This guide walks you through using the Ory adapter for agent authentication with Fosite and Hydra.

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/adapters/ory
```

## Hydra Client Usage

### Creating a Client

```go
import "github.com/aistandardsio/agent-protocols/adapters/ory/hydra"

// Create client for Hydra
client, err := hydra.NewClient("https://hydra.example.com",
    hydra.WithAdminURL("https://hydra-admin.example.com"),
    hydra.WithClientCredentials("client-id", "client-secret"),
)
if err != nil {
    log.Fatal(err)
}
```

### Token Exchange

Exchange an ID-JAG assertion for an access token:

```go
import "github.com/aistandardsio/agent-protocols/idjag"

// Create and sign an ID-JAG assertion
assertion := idjag.NewAssertion(
    "https://issuer.example.com",
    "agent:calendar-bot",
    []string{client.TokenURL()},
    5*time.Minute,
)
signedAssertion, _ := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")

// Exchange for access token
resp, err := client.ExchangeIDJAG(ctx, signedAssertion,
    hydra.WithScope("calendar:read"),
    hydra.WithAudience("https://api.example.com"),
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", resp.AccessToken)
```

### JWT Bearer Grant

Use JWT assertion as a grant:

```go
resp, err := client.JWTBearerGrant(ctx, signedAssertion,
    hydra.WithScope("api:access"),
)
```

### Token Introspection

Validate and inspect tokens:

```go
introspect, err := client.IntrospectToken(ctx, accessToken)
if err != nil {
    log.Fatal(err)
}

if introspect.Active {
    fmt.Printf("Subject: %s\n", introspect.Sub)
    fmt.Printf("Scope: %s\n", introspect.Scope)

    // Check for delegation
    if introspect.Act != nil {
        fmt.Printf("Acting as: %s\n", introspect.Act.Sub)
    }
}
```

### Delegation with Actor Tokens

Exchange with actor token for delegation:

```go
resp, err := client.TokenExchange(ctx, subjectToken, hydra.TokenTypeJWT,
    hydra.WithActorToken(actorToken, hydra.TokenTypeJWT),
    hydra.WithScope("delegated:scope"),
)
```

## Fosite Handler Usage

### Creating Handlers

```go
import (
    "github.com/aistandardsio/agent-protocols/adapters/ory/fosite"
    "github.com/aistandardsio/agent-protocols/idjag"
)

// Create verifier for assertions
verifier := idjag.NewJWKSVerifier(
    "https://issuer.example.com/.well-known/jwks.json",
    idjag.VerifierOptions{
        ExpectedIssuer: "https://issuer.example.com",
    },
)

// Create handler configuration
config := fosite.DefaultHandlerConfig("https://auth.example.com")

// Create token storage
storage := fosite.NewMemoryStorage()

// Create ID-JAG handler
handler := fosite.NewIDJAGHandler(verifier, config, storage)
```

### Processing Token Requests

```go
// Check if handler can process request
req := &fosite.TokenRequest{
    GrantType:        fosite.GrantTypeJWTBearer,
    SubjectToken:     assertion,
    SubjectTokenType: fosite.TokenTypeJWT,
    Scope:           []string{"read", "write"},
}

if handler.CanHandle(req) {
    resp, err := handler.HandleTokenRequest(ctx, req)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Access Token: %s\n", resp.AccessToken)
}
```

### Custom Token Storage

Implement the `TokenStorage` interface for production:

```go
type TokenStorage interface {
    CreateAccessToken(ctx context.Context, data *TokenData) (string, error)
    GetAccessToken(ctx context.Context, token string) (*TokenData, error)
    RevokeAccessToken(ctx context.Context, token string) error
}
```

## Running the Example

A complete working example is available:

```bash
go run ./adapters/ory/examples/idjag
```

This demonstrates:

1. Creating ID-JAG assertions
2. Exchanging assertions via Hydra
3. Creating delegated assertions with actor claims
4. Token introspection
5. JWT Bearer grants

## Configuration Options

### Hydra Client Options

| Option | Description |
|--------|-------------|
| `WithAdminURL(url)` | Hydra admin API URL |
| `WithHTTPClient(client)` | Custom HTTP client |
| `WithClientCredentials(id, secret)` | OAuth client credentials |

### Exchange Options

| Option | Description |
|--------|-------------|
| `WithScope(scope)` | Requested scope |
| `WithAudience(aud)` | Target audience |
| `WithResource(uri)` | Resource indicator |
| `WithActorToken(token, type)` | Actor token for delegation |

### Handler Configuration

| Field | Description | Default |
|-------|-------------|---------|
| `Issuer` | Token issuer URL | Required |
| `AccessTokenLifetime` | Access token validity | 1 hour |
| `RefreshTokenLifetime` | Refresh token validity | 24 hours |
| `ScopeStrategy` | Scope validation strategy | Allow all |
| `AudienceStrategy` | Audience validation strategy | Allow all |

## Next Steps

- [Overview](overview.md) - Architecture and features
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/adapters/ory) - Full API documentation
