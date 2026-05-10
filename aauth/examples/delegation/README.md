# AAuth Delegation Example: Human-to-Agent Authorization

This example demonstrates the **delegation flow** where humans explicitly authorize agents to act on their behalf with specific scopes and resource access.

## When to Use

Delegation is essential when:

- Agents need to act on behalf of specific humans
- Fine-grained permission control is required
- Audit trails must trace actions back to human principals
- Time-limited access is needed

## How It Works

1. **Human authorization**: Human logs into Person Server and authorizes an agent for specific resources and scopes
2. **Delegation stored**: Person Server stores the delegation (agent JKT, resources, scopes, expiry)
3. **Token request**: Agent requests an auth token from Person Server
4. **Delegation verified**: Person Server verifies agent has valid delegation and issues auth token
5. **Resource access**: Agent accesses resources using the delegated authority

## Key Concepts

### JWK Thumbprint (JKT)

The JKT is a hash of the agent's public key, used to:

- Uniquely identify agents
- Bind auth tokens to specific keys via the `cnf` claim
- Prevent token theft (stolen token unusable without private key)

### Scope-Based Access

Scopes define what actions an agent can perform:

- `tasks:read` - Read task data
- `tasks:manage` - Create and update tasks
- `tasks:delete` - Delete tasks

Humans grant only the scopes the agent needs (principle of least privilege).

### Proof-of-Possession

Auth tokens contain a `cnf` (confirmation) claim with the agent's JKT:

```json
{
  "sub": "aauth:task-agent@example.com",
  "aud": ["https://tasks.example.com"],
  "scope": "tasks:manage",
  "cnf": {
    "jkt": "abc123..."
  }
}
```

Resources verify:

1. The auth token signature (from Person Server)
2. The HTTP signature (from agent)
3. The `cnf.jkt` matches the agent's key

## Running the Example

```bash
go run ./aauth/examples/delegation
```

## Expected Output

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
  Attempting tasks:delete would require additional authorization

Delegation flow completed!

Key concepts demonstrated:
  1. Human pre-authorizes agent for specific resources/scopes
  2. Agent obtains proof-of-possession bound auth token
  3. Resource verifies both agent identity and delegation
  4. Scopes limit what agent can do on behalf of human
```

## Security Considerations

1. **Delegation expiry**: Set appropriate TTLs for delegations
2. **Scope minimization**: Grant only necessary scopes
3. **Resource restrictions**: Limit which resources agents can access
4. **Revocation**: Person Server should support delegation revocation

## Related

- [Simple Example](../simple/README.md) - Identity-only mode
- [Resource-Managed Example](../resource-managed/README.md) - Challenge-response flow
