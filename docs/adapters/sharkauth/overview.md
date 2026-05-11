# SharkAuth Adapter Overview

The SharkAuth adapter integrates agent-protocols with [SharkAuth](https://github.com/shark-auth/shark), an OAuth 2.0 server purpose-built for agent delegation.

## Why SharkAuth?

SharkAuth is designed specifically for AI agent authentication scenarios:

- **Native RFC 8693 Token Exchange** - First-class support for token exchange flows
- **DPoP Support** - Proof-of-possession binding per RFC 9449
- **`may_act_grants`** - Structured delegation with explicit grant management
- **Cascade Revocation** - Revoking a parent grant automatically revokes child grants
- **Single Binary** - Simple deployment as a single Go binary
- **MIT Licensed** - Open source and free to use

## Features

### Token Exchange

Exchange agent tokens for access tokens with scope downgrading:

```go
client, _ := sharkauth.NewClient("https://auth.example.com",
    sharkauth.WithClientCredentials("client-id", "client-secret"),
)

resp, _ := client.ExchangeAAuthToken(ctx, agentToken,
    sharkauth.WithScope("calendar:read"),
    sharkauth.WithAudience("https://api.example.com"),
)
```

### DPoP Proof-of-Possession

Bind tokens to cryptographic keys with DPoP proofs:

```go
// Create DPoP proof
proof, _ := sharkauth.CreateDPoPProof(privateKey, "POST", tokenURL)

// Exchange with DPoP binding
resp, _ := client.ExchangeAAuthToken(ctx, agentToken,
    sharkauth.WithDPoP(proof.Token),
)
// Returns TokenType: "DPoP" instead of "Bearer"
```

### Delegation Grants

Manage `may_act_grants` for structured delegation:

```go
// Create delegation grant
grant, _ := client.CreateDelegationGrant(ctx, sharkauth.DelegationGrantRequest{
    ActorSubject: "agent:calendar-bot",
    UserSubject:  "user:alice",
    Scopes:       []string{"calendar:read", "calendar:write"},
    TTL:          24 * time.Hour,
})

// List active grants for a user
grants, _ := client.ListDelegationGrants(ctx,
    sharkauth.WithUserSubject("user:alice"),
    sharkauth.WithActiveOnly(),
)

// Revoke grant (cascades to child grants)
_ = client.RevokeDelegationGrant(ctx, grant.GrantID)
```

## Protocol Support

| Protocol | Support Level | Features |
|----------|--------------|----------|
| AAuth | Full | Token exchange, DPoP, delegation grants |
| ID-JAG | Partial | Token exchange (via generic Exchange) |
| AIMS | Not supported | - |

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Agent     │────▶│  SharkAuth  │────▶│  Resource   │
│  (AAuth)    │     │   Server    │     │   Server    │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │
       │ Agent Token       │ Access Token
       │ + DPoP Proof      │ (DPoP-bound)
       │                   │
       ▼                   ▼
   ┌───────────────────────────────┐
   │      may_act_grants           │
   │  (Structured Delegation)      │
   └───────────────────────────────┘
```

## Next Steps

- [Getting Started](getting-started.md) - Installation and basic usage
- [Examples](../../adapters/sharkauth/examples/) - Working code examples
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/adapters/sharkauth) - Full API documentation
