# Diagram Comparison: Mermaid vs D2

This page compares the same ID-JAG flows rendered with two different diagram tools:

- **Mermaid** - Generated from [PIDL](https://github.com/grokify/pidl) protocol definitions
- **D2** - Hand-crafted diagrams with custom styling

## Simple Flow (Agent-Only)

The agent authenticates as itself without human delegation.

### Mermaid (from PIDL)

```mermaid
sequenceDiagram
    autonumber

    participant agent as AI Agent
    participant issuer as Assertion Issuer
    participant auth_server as Authorization Server
    participant jwks as JWKS Endpoint
    participant resource_server as Resource Server

    rect rgb(240, 240, 240)
    note right of agent: Assertion Creation
    agent->>issuer: Request Identity Assertion
    issuer->>issuer: Create JWT Claims (iss, sub, aud, exp)
    issuer->>issuer: Sign with Private Key (RS256/ES256)
    issuer-->>agent: Signed JWT Assertion
    end

    rect rgb(240, 240, 240)
    note right of agent: Token Exchange
    agent->>auth_server: POST /token (grant_type=token-exchange)
    auth_server->>jwks: GET /.well-known/jwks.json
    jwks-->>auth_server: JWK Set (Public Keys)
    auth_server->>auth_server: Verify Signature + Validate Claims
    auth_server->>auth_server: Issue Access Token
    auth_server-->>agent: 200 OK (access_token, Bearer, expires_in)
    end

    rect rgb(240, 240, 240)
    note right of agent: Resource Access
    agent->>resource_server: GET /api/data (Authorization: Bearer)
    resource_server->>jwks: Verify Access Token Signature
    jwks-->>resource_server: Public Keys
    resource_server->>resource_server: Validate Token + Check Scope
    resource_server-->>agent: 200 OK (Protected Data)
    end
```

### D2 (Hand-crafted)

![Simple Flow - D2](diagrams/simple-flow.svg)

---

## Delegation Flow (Human-to-Agent)

The agent acts on behalf of a human user using the `act` claim.

### Mermaid (from PIDL)

```mermaid
sequenceDiagram
    autonumber

    participant user as Human User
    participant idp as Identity Provider
    participant agent as AI Agent
    participant issuer as Assertion Issuer
    participant auth_server as Authorization Server
    participant jwks as JWKS Endpoint
    participant resource_server as Resource Server

    rect rgb(240, 240, 240)
    note right of user: User Authentication
    user->>idp: Authenticate (OAuth/OIDC/SAML)
    idp-->>user: Identity Verified + Session Established
    end

    rect rgb(240, 240, 240)
    note right of user: Delegation Setup
    user->>agent: Request Agent Action
    agent->>issuer: Request Delegated Assertion
    issuer->>issuer: Create JWT: sub=user, act={sub: agent}
    issuer->>issuer: Sign with Private Key (RS256/ES256)
    issuer-->>agent: Signed Delegated JWT Assertion
    end

    rect rgb(240, 240, 240)
    note right of user: Token Exchange
    agent->>auth_server: POST /token (grant_type=token-exchange)
    auth_server->>jwks: GET /.well-known/jwks.json
    jwks-->>auth_server: JWK Set (Public Keys)
    auth_server->>auth_server: Verify Signature + Check Actor
    auth_server->>auth_server: Apply Delegation Policies
    auth_server->>auth_server: Issue Access Token (preserves act)
    auth_server-->>agent: 200 OK (access_token with sub + act)
    end

    rect rgb(240, 240, 240)
    note right of user: Delegated Resource Access
    agent->>resource_server: GET /api/calendar (Authorization: Bearer)
    resource_server->>resource_server: Extract sub (user) + act (agent)
    resource_server->>resource_server: Authorize: User + Agent allowed
    resource_server-->>agent: 200 OK (User's Protected Data)
    agent-->>user: Task Completed (Result Summary)
    end
```

### D2 (Hand-crafted)

![Delegation Flow - D2](diagrams/delegation-flow.svg)

---

## Token Exchange Sequence (D2 Only)

A detailed view of the token exchange process:

![Token Exchange Sequence - D2](diagrams/token-exchange-sequence.svg)

---

## Comparison Summary

| Aspect | Mermaid (PIDL) | D2 |
|--------|----------------|-----|
| **Source** | Generated from JSON protocol definition | Hand-crafted `.d2` files |
| **Maintainability** | Single source of truth (PIDL JSON) | Manual updates required |
| **Styling** | Limited, theme-based | Full control over colors, shapes |
| **Web Embedding** | Native in MkDocs, GitHub | Requires SVG rendering |
| **Tooling** | `pidl generate -f mermaid` | `d2 file.d2 file.svg` |
| **Best For** | Quick iteration, consistency | Polished documentation |

## Source Files

### PIDL Definitions

- [`idjag_simple.json`](https://github.com/grokify/agent-protocols/blob/main/idjag/pidl/idjag_simple.json)
- [`idjag_delegation.json`](https://github.com/grokify/agent-protocols/blob/main/idjag/pidl/idjag_delegation.json)

### D2 Source Files

- [`simple-flow.d2`](https://github.com/grokify/agent-protocols/blob/main/docs/idjag/diagrams/simple-flow.d2)
- [`delegation-flow.d2`](https://github.com/grokify/agent-protocols/blob/main/docs/idjag/diagrams/delegation-flow.d2)
- [`token-exchange-sequence.d2`](https://github.com/grokify/agent-protocols/blob/main/docs/idjag/diagrams/token-exchange-sequence.d2)
