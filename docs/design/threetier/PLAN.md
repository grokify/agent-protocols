# Three-Tier Architecture Plan

**Status**: Draft
**Created**: 2026-05-10

## Overview

This plan describes the three-tier architecture for agent-protocols across all three protocols (ID-JAG, AIMS, AAuth):

1. **Tier 1: Go Packages/Libraries** - Core protocol implementations
2. **Tier 2: Adapters** - Integration with Go identity ecosystems
3. **Tier 3: End-to-End Demos** - Working demonstrations

---

## Tier 1: Go Packages/Libraries (Core)

### Current State

| Package | Status | Description |
|---------|--------|-------------|
| `idjag/` | Complete | ID-JAG: OAuth token exchange with JWT assertions |
| `aims/` | Complete | AIMS: SPIFFE-based workload identity (WIT/WPT) |
| `aauth/` | Complete | AAuth: HTTP signatures, agent tokens, delegation |

### Protocol Comparison

| Aspect | ID-JAG | AIMS | AAuth |
|--------|--------|------|-------|
| **Focus** | Token exchange | Workload identity | Agent delegation |
| **Identity Model** | OAuth JWT assertions | SPIFFE IDs | Agent URIs (`aauth:local@domain`) |
| **Credential** | Signed JWT | X.509/JWT SVID, WIT | Signed HTTP requests + JWTs |
| **Key Binding** | `cnf` claim optional | `cnf` in WIT | `cnf.jwk` mandatory |
| **Delegation** | `act` claim | SPIFFE path | `act` chain + `may_act` |
| **Request Signing** | None | WPT | HTTP Message Signatures (RFC 9421) |
| **Standards** | RFC 8693, RFC 7523 | SPIFFE, WIMSE | RFC 9421, RFC 8693 |
| **Best For** | OAuth environments | Kubernetes/mTLS | Agent-to-agent |

### Structure After AAuth

```
agent-protocols/
├── idjag/           # ID-JAG protocol
│   ├── assertion.go
│   ├── token_exchange.go
│   ├── verifier.go
│   ├── server.go
│   └── examples/
│       ├── simple/
│       └── delegation/
│
├── aims/            # AIMS protocol
│   ├── spiffe.go
│   ├── wit.go
│   ├── wpt.go
│   ├── credential.go
│   └── examples/
│       ├── simple/
│       └── mtls/
│
├── aauth/           # AAuth protocol
│   ├── uri.go
│   ├── agent_token.go
│   ├── auth_token.go
│   ├── resource_token.go
│   ├── httpsig/
│   ├── agent.go
│   ├── resource.go
│   ├── authserver.go
│   └── examples/
│       ├── simple/
│       ├── resource-managed/
│       └── delegation/
│
├── adapters/        # Tier 2: Ecosystem adapters
├── demos/           # Tier 3: Cross-protocol & production demos
└── docs/
```

**Note:** Protocol-specific examples live within each protocol's `examples/` directory (e.g., `aauth/examples/simple/`). This provides better namespacing as protocols can vary widely. The top-level `demos/` directory is reserved for cross-protocol demos and production infrastructure.

---

## Tier 2: Adapters for Go Ecosystems

### Priority Order

1. **Zitadel** (first priority)
2. **SharkAuth** (second priority)
3. **Ory** (third priority)

### Zitadel Adapter (`adapters/zitadel/`)

**Why Zitadel:**
- Written in Go (75%)
- Native RFC 8693 Token Exchange support
- JWT Profile (RFC 7523) support
- OpenID Foundation certified
- Production-ready with [zitadel/oidc](https://github.com/zitadel/oidc) library (1.8k stars)
- Multi-tenant architecture fits agent scenarios

**Structure:**

```
adapters/zitadel/
├── doc.go
├── provider.go          # Agent as OIDC/AAuth provider
├── provider_test.go
├── client.go            # Agent as OIDC client
├── client_test.go
├── token_exchange.go    # RFC 8693 integration
├── token_exchange_test.go
├── jwt_profile.go       # RFC 7523 integration
├── jwt_profile_test.go
├── middleware.go        # Zitadel verification middleware
├── middleware_test.go
└── examples/
    ├── idjag/           # ID-JAG with Zitadel
    ├── aims/            # AIMS with Zitadel (WIT as JWT-SVID)
    └── aauth/           # AAuth with Zitadel as PS/AS
```

**Key Features:**
- Map ID-JAG assertions to Zitadel token exchange
- Map AIMS WITs to Zitadel JWT-SVIDs
- Map AAuth agent tokens to Zitadel machine users
- Unified middleware for all three protocols

### SharkAuth Adapter (`adapters/sharkauth/`)

**Why SharkAuth:**
- Purpose-built for agent delegation
- Native RFC 8693 + DPoP support
- `may_act_grants` for structured delegation
- Cascade revocation
- Single Go binary deployment
- MIT licensed

**Note:** SharkAuth is new (v0.1.0, 11 stars) but architecturally aligned with AAuth.

**Structure:**

```
adapters/sharkauth/
├── doc.go
├── delegation.go        # may_act_grants mapping
├── delegation_test.go
├── dpop.go              # DPoP integration
├── dpop_test.go
├── client.go            # SharkAuth client
├── client_test.go
├── server.go            # SharkAuth server integration
├── server_test.go
└── examples/
    ├── aauth/           # AAuth with SharkAuth (primary)
    └── idjag/           # ID-JAG delegation with SharkAuth
```

**Key Features:**
- Map AAuth delegation chains to SharkAuth `may_act_grants`
- DPoP binding for proof-of-possession
- Cascade revocation support
- Grant ID audit trail integration

### Ory Adapter (`adapters/ory/`)

**Why Ory:**
- Mature ecosystem (Hydra, Fosite, Kratos)
- Fosite is extensible Go library
- Community RFC 8693 extensions exist
- Wide production adoption

**Structure:**

```
adapters/ory/
├── doc.go
├── fosite/              # Fosite library integration
│   ├── handler.go       # Custom grant handlers
│   ├── handler_test.go
│   ├── storage.go       # Token storage
│   └── storage_test.go
├── hydra/               # Hydra server integration
│   ├── client.go
│   └── client_test.go
└── examples/
    ├── idjag/           # ID-JAG with Hydra
    └── custom-grant/    # Custom Fosite grant type
```

**Key Features:**
- Custom Fosite handlers for ID-JAG assertions
- Custom Fosite handlers for AAuth tokens
- Hydra admin API integration

---

## Tier 3: Examples and Demos

### Strategy

1. **Protocol Examples** (`<protocol>/examples/`): Single-protocol demos within each package
2. **Cross-Protocol Demos** (`demos/`): Multi-protocol integration demos
3. **Production Demos** (`demos/production/`): Full infrastructure with Docker Compose

### Protocol Examples

Each protocol contains its own examples for better namespacing. This approach scales well as protocols vary widely.

```
idjag/examples/
├── simple/
│   ├── README.md
│   └── main.go          # Basic token exchange
└── delegation/
    ├── README.md
    └── main.go          # Human-to-agent delegation

aims/examples/
├── simple/
│   ├── README.md
│   └── main.go          # WIT issuance + WPT verification
└── mtls/
    ├── README.md
    ├── main.go          # X.509 SVID + mTLS
    └── certs/           # Self-signed test certs

aauth/examples/
├── simple/
│   ├── README.md
│   └── main.go          # Identity-only mode
├── resource-managed/
│   ├── README.md
│   └── main.go          # Challenge-response flow
└── delegation/
    ├── README.md
    └── main.go          # Full delegation chain
```

**Characteristics:**
- Examples namespaced by protocol
- Single `main.go` per example
- No Docker required
- `go run ./<protocol>/examples/<example>`
- Self-contained with embedded servers

### Cross-Protocol Demos (`demos/`)

Reserved for demos that integrate multiple protocols.

```
demos/
├── multi-protocol/
│   ├── README.md
│   └── main.go          # All three protocols interoperating
└── protocol-bridge/
    ├── README.md
    └── main.go          # Bridging between protocols
```

### Production Demos (`demos/production/`)

Full infrastructure with Docker Compose, Zitadel, and observability.

```
demos/production/
├── docker-compose.yaml    # All services
├── .env.example
│
├── zitadel/
│   ├── docker-compose.yaml
│   ├── config/            # Zitadel configuration
│   └── init/              # Initialization scripts
│
├── services/
│   ├── agent-a/           # Example agent A
│   │   ├── Dockerfile
│   │   ├── main.go
│   │   └── config.yaml
│   │
│   ├── agent-b/           # Example agent B
│   │   ├── Dockerfile
│   │   ├── main.go
│   │   └── config.yaml
│   │
│   └── resource-api/      # Protected resource
│       ├── Dockerfile
│       ├── main.go
│       └── config.yaml
│
├── scenarios/
│   ├── idjag-token-exchange/
│   │   ├── README.md
│   │   └── test.sh
│   │
│   ├── aims-k8s-workload/
│   │   ├── README.md
│   │   ├── k8s/           # Kubernetes manifests
│   │   └── test.sh
│   │
│   ├── aauth-multi-agent/
│   │   ├── README.md
│   │   └── test.sh
│   │
│   └── cross-protocol/
│       ├── README.md
│       └── test.sh
│
└── observability/
    ├── jaeger/            # Distributed tracing
    ├── prometheus/        # Metrics
    └── grafana/           # Dashboards
```

**Characteristics:**
- `docker compose up` to start
- Zitadel as identity provider
- Multiple agents demonstrating delegation
- Protected resources with policy enforcement
- Full observability stack
- Kubernetes scenarios for AIMS

---

## Implementation Order

### Phase 1: Complete Core (Current → Week 8)

1. ~~ID-JAG~~ (complete)
2. ~~AIMS~~ (complete)
3. ~~AAuth~~ (complete)

### Phase 2: Protocol Examples (Weeks 9-10)

Protocol-specific examples live within each protocol's `examples/` directory.

| Example | Week | Location |
|---------|------|----------|
| `idjag/examples/simple` | 9 | ID-JAG basic flow |
| `idjag/examples/delegation` | 9 | ID-JAG delegation |
| `aims/examples/simple` | 9 | AIMS WIT/WPT flow |
| `aims/examples/mtls` | 9 | AIMS mTLS with X.509 |
| `aauth/examples/simple` | 10 | AAuth identity-only |
| `aauth/examples/resource-managed` | 10 | AAuth challenge-response |
| `aauth/examples/delegation` | 10 | AAuth delegation |
| `demos/multi-protocol` | 10 | Cross-protocol integration |

### Phase 3: Zitadel Adapter (Weeks 11-13)

| Component | Week |
|-----------|------|
| `adapters/zitadel/client.go` | 11 |
| `adapters/zitadel/token_exchange.go` | 11 |
| `adapters/zitadel/jwt_profile.go` | 12 |
| `adapters/zitadel/middleware.go` | 12 |
| `adapters/zitadel/examples/` | 13 |

### Phase 4: Production Demos (Weeks 14-16)

| Component | Week |
|-----------|------|
| Docker Compose base | 14 |
| Zitadel setup | 14 |
| Agent services | 15 |
| Scenarios | 15 |
| Observability | 16 |
| Documentation | 16 |

### Phase 5: SharkAuth Adapter (Weeks 17-18)

| Component | Week |
|-----------|------|
| `adapters/sharkauth/delegation.go` | 17 |
| `adapters/sharkauth/dpop.go` | 17 |
| `adapters/sharkauth/examples/` | 18 |

### Phase 6: Ory Adapter (Weeks 19-20)

| Component | Week |
|-----------|------|
| `adapters/ory/fosite/handler.go` | 19 |
| `adapters/ory/hydra/client.go` | 19 |
| `adapters/ory/examples/` | 20 |

---

## README.md Updates

After implementation, update the root README.md:

```markdown
## Architecture

This repository provides three levels of capability:

### Level 1: Go Packages (Core)

| Package | Protocol | Use Case | Examples |
|---------|----------|----------|----------|
| [`idjag/`](./idjag/) | ID-JAG | OAuth token exchange with delegation | `idjag/examples/` |
| [`aims/`](./aims/) | AIMS | SPIFFE-based workload identity | `aims/examples/` |
| [`aauth/`](./aauth/) | AAuth | HTTP-signed agent authentication | `aauth/examples/` |

### Level 2: Adapters

| Adapter | Infrastructure | Status |
|---------|----------------|--------|
| [`adapters/zitadel/`](./adapters/zitadel/) | Zitadel | Production |
| [`adapters/sharkauth/`](./adapters/sharkauth/) | SharkAuth | Beta |
| [`adapters/ory/`](./adapters/ory/) | Ory Hydra/Fosite | Beta |

### Level 3: Demos

| Demo | Description |
|------|-------------|
| [`demos/multi-protocol/`](./demos/multi-protocol/) | Cross-protocol integration |
| [`demos/production/`](./demos/production/) | Docker Compose + Zitadel |
```

---

## Dependencies by Tier

### Tier 1: Core Packages

```go
require (
    github.com/golang-jwt/jwt/v5 v5.3.1
)
```

### Tier 2: Adapters

```go
require (
    // Zitadel adapter
    github.com/zitadel/oidc/v3 v3.x.x

    // SharkAuth adapter (when stable)
    github.com/shark-auth/shark v0.x.x

    // Ory adapter
    github.com/ory/fosite v0.x.x
)
```

### Tier 3: Demos

```go
require (
    // Observability
    go.opentelemetry.io/otel v1.x.x
    go.opentelemetry.io/otel/exporters/jaeger v1.x.x
)
```

---

## Testing Strategy

### Unit Tests

Each package has comprehensive `*_test.go` files.

### Integration Tests

```
tests/integration/
├── idjag_zitadel_test.go
├── aims_spire_test.go
├── aauth_sharkauth_test.go
└── cross_protocol_test.go
```

### E2E Tests

```bash
# Minimal demos
go test ./demos/minimal/...

# Production demos (requires Docker)
cd demos/production && docker compose up -d
./scenarios/idjag-token-exchange/test.sh
./scenarios/aauth-multi-agent/test.sh
docker compose down
```

---

## Verification

### After Phase 1 (Core)

```bash
go build ./...
go test -v ./idjag/... ./aims/... ./aauth/...
golangci-lint run
```

### After Phase 2 (Protocol Examples)

```bash
# ID-JAG examples
go run ./idjag/examples/simple
go run ./idjag/examples/delegation

# AIMS examples
go run ./aims/examples/simple
go run ./aims/examples/mtls

# AAuth examples
go run ./aauth/examples/simple
go run ./aauth/examples/resource-managed
go run ./aauth/examples/delegation

# Cross-protocol demo
go run ./demos/multi-protocol
```

### After Phase 4 (Production Demos)

```bash
cd demos/production
docker compose up -d
./scenarios/cross-protocol/test.sh
docker compose down
```

---

## References

### Infrastructure Projects

- [Zitadel](https://github.com/zitadel/zitadel) - Cloud-native IdP
- [zitadel/oidc](https://github.com/zitadel/oidc) - Go OIDC library
- [SharkAuth](https://github.com/shark-auth/shark) - Agent-focused auth
- [Ory Hydra](https://github.com/ory/hydra) - OAuth 2.0 server
- [Ory Fosite](https://github.com/ory/fosite) - OAuth 2.0 SDK

### Protocol Specifications

- [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- [AIMS](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
- [AAuth](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol)
- [RFC 8693 - Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9421 - HTTP Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [SPIFFE](https://spiffe.io/)
- [WIMSE](https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol/)
