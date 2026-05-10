# AAuth Diagrams

This page provides visual diagrams of the AAuth protocol flows.

## Identity-Only Flow

The simplest flow where resources only verify agent identity.

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant AP as Agent Provider

    Note over Agent,AP: Identity-Only (2-Party)

    Agent->>Resource: HTTP Request + Signature + Signature-Key

    opt Key not cached
        Resource->>AP: GET /.well-known/aauth-agent.json
        AP-->>Resource: Agent Provider Metadata
        Resource->>AP: GET /jwks
        AP-->>Resource: JWKS (Agent Public Keys)
    end

    Resource->>Resource: Verify HTTP Signature
    Resource-->>Agent: Protected Resource
```

## Resource-Managed Flow

Resources challenge agents to obtain auth tokens from the Person Server.

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant PS as Person Server

    Note over Agent,PS: Resource-Managed (3-Party)

    Agent->>Resource: HTTP Request + Signature (no auth token)
    Resource->>Resource: Verify identity
    Resource-->>Agent: 401 + WWW-Authenticate: AAuth<br/>realm=... ps=... resource_token=...

    Agent->>PS: POST /token<br/>grant_type=token-exchange<br/>subject_token=resource_token
    PS->>PS: Verify resource token<br/>Check agent authorization
    PS-->>Agent: Auth Token (aa-auth+jwt with cnf)

    Agent->>Resource: HTTP Request + Signature + Authorization: Bearer <auth_token>
    Resource->>Resource: Verify signature + auth token + cnf binding
    Resource-->>Agent: Protected Resource
```

## PS-Asserted Flow

Agent proactively obtains auth tokens before accessing resources.

```mermaid
sequenceDiagram
    participant Agent
    participant Resource
    participant PS as Person Server

    Note over Agent,PS: PS-Asserted (Proactive)

    Agent->>Resource: GET /.well-known/aauth-resource.json
    Resource-->>Agent: Resource Metadata (person_server_uri)

    Agent->>PS: GET /.well-known/aauth-person.json
    PS-->>Agent: Person Server Metadata (token_endpoint)

    Agent->>PS: POST /token (request auth token for resource)
    PS->>PS: Verify agent authorization
    PS-->>Agent: Auth Token

    Agent->>Resource: HTTP Request + Signature + Authorization: Bearer <auth_token>
    Resource->>Resource: Verify signature + auth token
    Resource-->>Agent: Protected Resource
```

## Federated Delegation Flow

Cross-organizational access with human delegation.

```mermaid
sequenceDiagram
    participant Human
    participant Agent
    participant HumanPS as Human's PS
    participant ResourcePS as Resource's PS
    participant Resource

    Note over Human,Resource: Federated Delegation (4-Party)

    Human->>HumanPS: Authorize agent for resources/scopes
    HumanPS->>HumanPS: Store delegation
    HumanPS-->>Human: Delegation confirmed

    Agent->>Resource: GET /.well-known/aauth-resource.json
    Resource-->>Agent: Resource Metadata

    Agent->>HumanPS: Request delegation token
    HumanPS-->>Agent: Delegation Token (signed by human's PS)

    Agent->>ResourcePS: POST /token<br/>subject_token=delegation_token<br/>actor_token=agent_identity
    ResourcePS->>ResourcePS: Validate delegation<br/>Verify agent identity
    ResourcePS-->>Agent: Auth Token (valid for resource org)

    Agent->>Resource: HTTP Request + Signature + Auth Token
    Resource->>Resource: Verify signature + auth token
    Resource-->>Agent: Protected Resource
```

## Component Architecture

```mermaid
flowchart TB
    subgraph Agents["Agent Layer"]
        A1[Calendar Bot]
        A2[Task Agent]
        A3[Assistant]
    end

    subgraph AgentProvider["Agent Provider"]
        AP[Agent Provider]
        APJWKS[(JWKS)]
    end

    subgraph Authorization["Authorization Layer"]
        PS[Person Server]
        PSJWKS[(JWKS)]
    end

    subgraph Resources["Resource Layer"]
        R1[Calendar API]
        R2[Task API]
        R3[Email API]
    end

    A1 & A2 & A3 -->|Identity| AP
    AP --> APJWKS

    A1 & A2 & A3 -->|Auth Request| PS
    PS --> PSJWKS
    PS -->|Delegation| Human[Human Principal]

    A1 -->|Access| R1
    A2 -->|Access| R2
    A3 -->|Access| R3

    R1 & R2 & R3 -->|Verify| PS
    R1 & R2 & R3 -->|Fetch JWKS| AP
```

## Token Types

```mermaid
flowchart LR
    subgraph Identity
        IT[Identity Token<br/>aa-agent+jwt]
    end

    subgraph Authorization
        AT[Auth Token<br/>aa-auth+jwt]
    end

    subgraph Challenge
        RT[Resource Token<br/>aa-resource+jwt]
    end

    Agent -->|Signs| IT
    IT -->|In Signature-Key header| Resource

    Resource -->|Issues| RT
    RT -->|Exchange at PS| PS[Person Server]

    PS -->|Issues| AT
    AT -->|In Authorization header| Resource
```

## JWT Structure

### Identity Token (aa-agent+jwt)

```json
{
  "header": {
    "alg": "ES256",
    "typ": "aa-agent+jwt",
    "kid": "agent-key-1"
  },
  "payload": {
    "iss": "https://agents.example.com",
    "sub": "aauth:calendar-bot@example.com",
    "aud": ["https://resource.example.com"],
    "iat": 1234567890,
    "exp": 1234571490,
    "cnf": {
      "jwk": { "kty": "EC", "crv": "P-256", ... }
    }
  }
}
```

### Auth Token (aa-auth+jwt)

```json
{
  "header": {
    "alg": "ES256",
    "typ": "aa-auth+jwt",
    "kid": "ps-key-1"
  },
  "payload": {
    "iss": "https://ps.example.com",
    "sub": "aauth:calendar-bot@example.com",
    "aud": ["https://resource.example.com"],
    "scope": "calendar:read calendar:write",
    "iat": 1234567890,
    "exp": 1234571490,
    "cnf": {
      "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    }
  }
}
```

### Resource Token (aa-resource+jwt)

```json
{
  "header": {
    "alg": "ES256",
    "typ": "aa-resource+jwt",
    "kid": "resource-key-1"
  },
  "payload": {
    "iss": "https://resource.example.com",
    "sub": "aauth:calendar-bot@example.com",
    "aud": ["https://ps.example.com"],
    "scope": "calendar:read",
    "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    "iat": 1234567890,
    "exp": 1234568190
  }
}
```

## PIDL Protocol Diagrams

Protocol diagrams are also available in PIDL format for generating various output formats:

```bash
# Generate PlantUML
pidl generate aauth/pidl/identity_only.json

# Generate Mermaid
pidl generate -f mermaid aauth/pidl/resource_managed.json

# Generate D2
pidl generate -f d2 aauth/pidl/federated.json
```

Available PIDL files:

- `aauth/pidl/identity_only.json`
- `aauth/pidl/resource_managed.json`
- `aauth/pidl/ps_asserted.json`
- `aauth/pidl/federated.json`
