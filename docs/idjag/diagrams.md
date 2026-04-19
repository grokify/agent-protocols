# Protocol Diagrams

These sequence diagrams are generated from [PIDL](https://github.com/grokify/pidl) protocol definitions.

## Simple Flow (Agent-Only)

The agent authenticates as itself without human delegation.

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

**PIDL Source:** [`idjag_simple.json`](https://github.com/grokify/agent-protocols/blob/main/idjag/pidl/idjag_simple.json)

---

## Delegation Flow (Human-to-Agent)

The agent acts on behalf of a human user using the `act` claim.

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

**PIDL Source:** [`idjag_delegation.json`](https://github.com/grokify/agent-protocols/blob/main/idjag/pidl/idjag_delegation.json)

---

## Token Exchange Sequence (Detailed)

A detailed view of the complete token exchange process including JWT construction, signature verification, and claim validation.

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
    agent->>issuer: Request identity assertion
    issuer->>issuer: Build JWT header (alg: RS256, typ: JWT, kid)
    issuer->>issuer: Build claims (iss, sub, aud, iat, exp, jti)
    issuer->>issuer: Sign with private key (RS256/ES256)
    issuer-->>agent: Signed JWT (header.payload.signature)
    end

    rect rgb(240, 240, 240)
    note right of agent: Token Exchange Request
    agent->>auth_server: POST /token
    auth_server->>auth_server: Parse token exchange parameters
    end

    rect rgb(240, 240, 240)
    note right of agent: Assertion Validation
    auth_server->>auth_server: Decode JWT (extract header + payload)
    auth_server->>auth_server: Extract key ID (kid) from header
    auth_server->>jwks: GET /.well-known/jwks.json
    jwks-->>auth_server: JWK Set (keys array)
    auth_server->>auth_server: Find key by kid in JWK Set
    auth_server->>auth_server: Verify JWT signature with public key
    auth_server->>auth_server: Validate iss claim (trusted issuer)
    auth_server->>auth_server: Validate aud claim (matches this server)
    auth_server->>auth_server: Validate exp claim (not expired)
    auth_server->>auth_server: Validate act claim if present (delegation)
    end

    rect rgb(240, 240, 240)
    note right of agent: Access Token Issuance
    auth_server->>auth_server: Apply authorization policies
    auth_server->>auth_server: Generate access token (preserve sub, act)
    auth_server->>auth_server: Sign access token
    auth_server-->>agent: 200 OK (access_token, token_type, expires_in)
    end

    rect rgb(240, 240, 240)
    note right of agent: Resource Access
    agent->>resource_server: GET /api/resource (Authorization: Bearer)
    resource_server->>jwks: GET /.well-known/jwks.json
    jwks-->>resource_server: JWK Set
    resource_server->>resource_server: Verify access token signature
    resource_server->>resource_server: Check scope claim against required permissions
    resource_server->>resource_server: Extract sub (user) and act (agent) for authz
    resource_server-->>agent: 200 OK (protected resource data)
    end
```

**PIDL Source:** [`idjag_token_exchange.json`](https://github.com/grokify/agent-protocols/blob/main/idjag/pidl/idjag_token_exchange.json)

---

## About PIDL

These diagrams are generated from [PIDL](https://github.com/grokify/pidl) (Protocol Interaction Description Language) definitions. PIDL provides:

- **Single source of truth** - JSON protocol definitions
- **Multiple output formats** - Mermaid, PlantUML, Graphviz DOT, D2
- **Validation** - Schema-based validation of protocol definitions
- **Consistency** - Same structure for all protocols

### Regenerating Diagrams

```bash
# Install PIDL CLI
go install github.com/grokify/pidl/cmd/pidl@latest

# Generate Mermaid diagrams
pidl generate -f mermaid idjag/pidl/idjag_simple.json
pidl generate -f mermaid idjag/pidl/idjag_delegation.json
pidl generate -f mermaid idjag/pidl/idjag_token_exchange.json
```
