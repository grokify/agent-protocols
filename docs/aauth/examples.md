# AAuth Examples

This page describes how to run the AAuth example applications.

## Available Examples

| Example | Description |
|---------|-------------|
| `simple` | Identity-only flow (2-party) |
| `resource-managed` | Resource-managed flow with challenge-response (3-party) |
| `delegation` | Human-to-agent delegation flow |

## Running Examples

### Simple (Identity-Only)

The simple example demonstrates identity-only authentication where agents present their cryptographic identity directly to resources.

```bash
go run ./aauth/examples/simple
```

**What it demonstrates:**

- Creating an agent with cryptographic identity
- Signing HTTP requests with RFC 9421 signatures
- Resource server verifying agent identity

**Expected output:**

```
Created agent: aauth:calendar-bot@example.com
Created resource server: https://calendar.example.com
Resource server running at: http://127.0.0.1:XXXXX

Sending signed request to resource...
  URL: http://127.0.0.1:XXXXX/events
  Signature-Key header present: true
  Signature header present: true

Response status: 200
Response: map[agent_id:aauth:calendar-bot@example.com key_id:... message:Hello from the resource!]

Identity-only flow completed successfully!
```

### Resource-Managed (Challenge-Response)

The resource-managed example demonstrates the full challenge-response flow where resources require auth tokens from the Person Server.

```bash
go run ./aauth/examples/resource-managed
```

**What it demonstrates:**

- Resource challenging agent with WWW-Authenticate header
- Token exchange at Person Server
- Auth token with proof-of-possession (cnf claim)
- Resource verifying both identity and authorization

**Expected output:**

```
Person Server running at: http://127.0.0.1:XXXXX
Created agent: aauth:calendar-bot@example.com
Created resource server: https://calendar.example.com
Resource server running at: http://127.0.0.1:XXXXX

Step 1: Attempting access without auth token...
  Response: 401 Unauthorized
  WWW-Authenticate: AAuth realm="https://calendar.example.com" ...

Step 2: Creating resource token for exchange...
  Resource token issued (length: XXX chars)

Step 3: Exchanging resource token at Person Server...
  Auth token issued (length: XXX chars)
  Auth token subject: aauth:calendar-bot@example.com
  Auth token scope: calendar:read

Step 4: Accessing resource with auth token...
  Response: 200 OK
  Response body: map[agent_id:aauth:calendar-bot@example.com auth_scope:calendar:read ...]

Resource-managed flow completed!
```

### Delegation

The delegation example demonstrates human-to-agent authorization where humans grant specific permissions to agents.

```bash
go run ./aauth/examples/delegation
```

**What it demonstrates:**

- Human authorizing agent for specific scopes
- Agent obtaining delegated auth token
- Resource verifying delegation chain
- Scope restrictions limiting agent actions

**Expected output:**

```
Person Server running at: http://127.0.0.1:XXXXX
Created agent: aauth:task-agent@example.com
Created resource server: https://tasks.example.com
Resource server running at: http://127.0.0.1:XXXXX

Step 1: Human authorizes agent for task management...
  Agent JKT: <thumbprint>
  Scope granted: tasks:manage
  Resource: https://tasks.example.com

Step 2: Agent requests auth token from Person Server...
  Auth token issued (length: XXX chars)
  Token subject: aauth:task-agent@example.com
  Token scope: tasks:manage

Step 3: Accessing resource with delegated authority...
  Response: 200 OK
  Response body: map[agent_id:aauth:task-agent@example.com scope:tasks:manage ...]

Step 4: Demonstrating scope restriction...
  Agent can only perform actions within granted scope: tasks:manage

Delegation flow completed!
```

## Protocol Flow Diagrams

Visual protocol diagrams are available in PIDL format:

```bash
# List available diagrams
ls aauth/pidl/

# Generate PlantUML diagram
pidl generate aauth/pidl/identity_only.json

# Generate Mermaid diagram
pidl generate -f mermaid aauth/pidl/resource_managed.json
```

Available PIDL files:

| File | Description |
|------|-------------|
| `identity_only.json` | Identity-only flow (2-party) |
| `resource_managed.json` | Resource-managed flow with challenge |
| `ps_asserted.json` | PS-asserted flow (proactive) |
| `federated.json` | Federated delegation flow (4-party) |

## Key Concepts in Examples

### HTTP Message Signatures

All examples use RFC 9421 HTTP Message Signatures:

```http
POST /events HTTP/1.1
Host: api.example.com
Signature-Key: eyJ... (aa-agent+jwt)
Signature: sig1=:base64...:
Signature-Input: sig1=("@method" "@target-uri" "host");created=...
```

### Auth Token Binding

Auth tokens are bound to agent keys via the `cnf` claim:

```json
{
  "cnf": {
    "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  }
}
```

Resources verify:

1. Auth token signature (from Person Server)
2. HTTP signature (from agent)
3. `cnf.jkt` matches agent's key thumbprint

### Scope-Based Authorization

Scopes define permitted actions:

| Scope | Permission |
|-------|------------|
| `calendar:read` | Read calendar events |
| `calendar:write` | Create/update events |
| `tasks:manage` | Full task management |

## Building Custom Examples

See the [Getting Started](getting-started.md) guide for code snippets you can use to build your own applications.
