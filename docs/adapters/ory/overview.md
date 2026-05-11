# Ory Adapter Overview

The Ory adapter integrates agent-protocols with the [Ory](https://www.ory.sh/) ecosystem, including Fosite (OAuth 2.0 SDK) and Hydra (OAuth 2.0 server).

## Why Ory?

Ory provides a mature, production-tested OAuth 2.0 infrastructure:

- **Fosite** - Extensible OAuth 2.0 SDK for building custom authorization servers
- **Hydra** - Production-ready OAuth 2.0 and OpenID Connect server
- **Wide Adoption** - Used by thousands of organizations in production
- **Extensible** - Custom grant handlers for agent-specific flows
- **Open Source** - Apache 2.0 licensed

## Components

### Fosite Integration (`adapters/ory/fosite`)

Custom OAuth grant handlers for embedding agent authentication in your own OAuth server:

```go
import "github.com/aistandardsio/agent-protocols/adapters/ory/fosite"

// Create ID-JAG assertion handler
verifier := idjag.NewJWKSVerifier(jwksURL, idjag.VerifierOptions{})
config := fosite.DefaultHandlerConfig("https://auth.example.com")
storage := fosite.NewMemoryStorage()

handler := fosite.NewIDJAGHandler(verifier, config, storage)

// Register with your OAuth provider
provider.RegisterHandler(handler)
```

### Hydra Integration (`adapters/ory/hydra`)

Client library for interacting with Ory Hydra:

```go
import "github.com/aistandardsio/agent-protocols/adapters/ory/hydra"

// Create Hydra client
client, _ := hydra.NewClient("https://hydra.example.com",
    hydra.WithAdminURL("https://hydra-admin.example.com"),
    hydra.WithClientCredentials("client-id", "client-secret"),
)

// Exchange ID-JAG assertion
resp, _ := client.ExchangeIDJAG(ctx, assertion,
    hydra.WithScope("read write"),
)
```

## Features

### Custom Grant Handlers

The Fosite subpackage provides handlers for:

| Grant Type | Handler | Description |
|------------|---------|-------------|
| JWT Bearer | `IDJAGHandler` | RFC 7523 JWT assertion grants |
| Token Exchange | `IDJAGHandler` | RFC 8693 token exchange |
| AAuth Agent | `AAuthHandler` | Custom AAuth agent token grants |

### Hydra Client

The Hydra client supports:

- **Token Exchange** (RFC 8693) - Exchange agent tokens for access tokens
- **JWT Bearer** (RFC 7523) - Use JWT assertions as grants
- **Token Introspection** - Validate and inspect tokens
- **Actor Claims** - Full delegation chain support

## Protocol Support

| Protocol | Fosite | Hydra |
|----------|--------|-------|
| ID-JAG | Full | Full |
| AAuth | Full | Full |
| AIMS | Verification only | Token introspection |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Application                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────┐           ┌─────────────────┐      │
│  │  Fosite-based   │           │  Hydra Client   │      │
│  │  OAuth Server   │           │                 │      │
│  │                 │           │                 │      │
│  │  ┌───────────┐  │           │  ┌───────────┐  │      │
│  │  │ ID-JAG    │  │           │  │ Exchange  │  │      │
│  │  │ Handler   │  │           │  │ ID-JAG    │  │      │
│  │  └───────────┘  │           │  └───────────┘  │      │
│  │  ┌───────────┐  │           │  ┌───────────┐  │      │
│  │  │ AAuth     │  │           │  │ Exchange  │  │      │
│  │  │ Handler   │  │           │  │ AAuth     │  │      │
│  │  └───────────┘  │           │  └───────────┘  │      │
│  └─────────────────┘           └─────────────────┘      │
│           │                             │                │
└───────────┼─────────────────────────────┼────────────────┘
            │                             │
            ▼                             ▼
    ┌───────────────┐             ┌───────────────┐
    │ Token Storage │             │  Ory Hydra    │
    └───────────────┘             └───────────────┘
```

## Next Steps

- [Getting Started](getting-started.md) - Installation and basic usage
- [Examples](../../adapters/ory/examples/) - Working code examples
- [API Reference](https://pkg.go.dev/github.com/aistandardsio/agent-protocols/adapters/ory) - Full API documentation
