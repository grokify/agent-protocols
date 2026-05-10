# AAuth API Reference

Full Go package documentation for the `aauth` package.

## Package Import

```go
import "github.com/aistandardsio/agent-protocols/aauth"
```

## Core Types

### AAuthID

Represents an AAuth agent identifier (`aauth:local@domain`).

```go
// Create a new AAuth ID
id, err := aauth.NewAAuthID("calendar-bot", "example.com")
// Result: aauth:calendar-bot@example.com

// Parse an existing ID
id, err := aauth.ParseAAuthID("aauth:calendar-bot@example.com")

// Access components
id.Local()  // "calendar-bot"
id.Domain() // "example.com"
id.String() // "aauth:calendar-bot@example.com"
```

### Agent

Represents an AI agent with cryptographic identity.

```go
type Agent struct {
    // Private fields
}

// Create a new agent
agent, err := aauth.NewAgent(
    agentID,
    privateKey,
    aauth.WithAgentProviderURL("https://agents.example.com"),
    aauth.WithTokenTTL(time.Hour),
    aauth.WithKeyID("key-1"),
)

// Create a signed HTTP request
req, err := agent.SignedRequest(ctx, "GET", "https://api.example.com/events", body)

// Get the signing transport for automatic request signing
transport := agent.Transport(http.DefaultTransport)

// Get the agent's key pair
keyPair := agent.KeyPair()
thumbprint, _ := keyPair.Thumbprint()
```

### Agent Options

```go
// Set the Agent Provider URL (issuer)
aauth.WithAgentProviderURL(url string)

// Set token time-to-live
aauth.WithTokenTTL(ttl time.Duration)

// Set the key ID for signing
aauth.WithKeyID(kid string)
```

### ResourceServer

Server-side component for verifying agent requests.

```go
type ResourceServer struct {
    // Private fields
}

// Create a resource server
rs, err := aauth.NewResourceServer(
    "https://api.example.com",
    privateKey,
    "resource-key-1",
    aauth.WithIdentityOnlyMode(true),
    aauth.WithResourcePersonServer("https://ps.example.com"),
    aauth.WithRequiredScope("read:data"),
)

// Get middleware for HTTP handlers
middleware := rs.Middleware(handler)

// Get the resource URL
url := rs.URL()

// Sign a resource token for challenges
token, err := rs.SignResourceToken(agentID, agentJKT, "scope")
```

### Resource Server Options

```go
// Enable identity-only mode (no auth token required)
aauth.WithIdentityOnlyMode(enabled bool)

// Set the Person Server URL
aauth.WithResourcePersonServer(url string)

// Set required scope(s)
aauth.WithRequiredScope(scope string)
aauth.WithRequiredScopes(scopes []string)
```

### AuthServer (Person Server)

Authorization server issuing auth tokens.

```go
type AuthServer struct {
    // Private fields
}

// Create an auth server
ps, err := aauth.NewAuthServer(
    "https://ps.example.com",
    privateKey,
    "ps-key-1",
    aauth.WithAuthTokenTTL(time.Hour),
)

// Get the HTTP handler
handler := ps.Handler()

// Sign an auth token
token, err := ps.SignAuthToken(agentID, cnf, audiences, scope)
```

### Auth Server Options

```go
// Set auth token time-to-live
aauth.WithAuthTokenTTL(ttl time.Duration)
```

## Token Types

### IdentityToken

Agent identity assertion (`aa-agent+jwt`).

```go
type IdentityToken struct {
    Issuer    string
    Subject   string
    Audience  []string
    IssuedAt  time.Time
    ExpiresAt time.Time
    CNF       *CNF
}

// Parse an identity token
token, err := aauth.ParseIdentityToken(tokenString)
```

### AuthToken

Authorization token from Person Server (`aa-auth+jwt`).

```go
type AuthToken struct {
    Issuer    string
    Subject   string
    Audience  []string
    Scope     string
    IssuedAt  time.Time
    ExpiresAt time.Time
    CNF       *CNF
}

// Parse an auth token
token, err := aauth.ParseAuthToken(tokenString)

// Check if audience is valid
ok := token.HasAudience("https://api.example.com")
```

### ResourceToken

Challenge token from resource servers (`aa-resource+jwt`).

```go
type ResourceToken struct {
    Issuer    string
    Subject   string
    Audience  []string
    Scope     string
    JKT       string
    IssuedAt  time.Time
    ExpiresAt time.Time
}

// Parse a resource token
token, err := aauth.ParseResourceToken(tokenString)
```

### CNF (Confirmation)

Proof-of-possession key binding (RFC 7800).

```go
type CNF struct {
    JWK json.RawMessage `json:"jwk,omitempty"`
    JKT string          `json:"jkt,omitempty"`
    Kid string          `json:"kid,omitempty"`
}

// Create CNF with JWK
cnf, err := aauth.NewCNFWithJWK(publicKey, keyID)

// Create CNF with JKT (thumbprint)
cnf := aauth.NewCNFWithJKT(thumbprint)
```

## HTTP Signatures

### SignedRequest

Creates a signed HTTP request per RFC 9421.

```go
req, err := agent.SignedRequest(ctx, method, url, body)
```

### SigningTransport

Automatically signs all requests.

```go
transport := agent.Transport(http.DefaultTransport)
client := &http.Client{Transport: transport}

// All requests are automatically signed
resp, err := client.Get("https://api.example.com/events")
```

## Verification

### VerificationResult

Result of request verification.

```go
type VerificationResult struct {
    AgentID   *AAuthID
    KeyID     string
    AuthToken *AuthToken
}

// Get from request context
result, ok := aauth.VerificationResultFromContext(r.Context())
```

### Context Helpers

```go
// Get agent ID from context
agentID, ok := aauth.AgentIDFromContext(ctx)

// Get verification result from context
result, ok := aauth.VerificationResultFromContext(ctx)
```

## Discovery

### DiscoveryClient

Fetches and caches AAuth metadata.

```go
// Create client
client := aauth.NewDiscoveryClient(
    aauth.WithDiscoveryHTTPClient(httpClient),
    aauth.WithDiscoveryCacheTTL(10 * time.Minute),
)

// Discover resource metadata
metadata, err := client.DiscoverResource(ctx, "https://api.example.com")

// Discover agent provider metadata
metadata, err := client.DiscoverAgentProvider(ctx, "https://agents.example.com")

// Discover person server metadata
metadata, err := client.DiscoverPersonServer(ctx, "https://ps.example.com")

// Discover full resource flow (resource + PS)
tokenEndpoint, metadata, err := client.DiscoverResourceFlow(ctx, "https://api.example.com")

// Fetch JWKS
jwks, err := client.FetchJWKS(ctx, "https://example.com/.well-known/jwks.json")

// Clear cache
client.ClearCache()
```

### Metadata Types

```go
type ResourceMetadata struct {
    Resource        string `json:"resource"`
    JWKSURI         string `json:"jwks_uri"`
    PersonServerURI string `json:"person_server_uri,omitempty"`
    AccessServerURI string `json:"access_server_uri,omitempty"`
}

type AgentProviderMetadata struct {
    AgentProvider              string   `json:"agent_provider"`
    JWKSURI                    string   `json:"jwks_uri"`
    RegistrationEndpoint       string   `json:"registration_endpoint,omitempty"`
    DelegationEndpoint         string   `json:"delegation_endpoint,omitempty"`
    SigningAlgorithmsSupported []string `json:"signing_algs_supported,omitempty"`
}

type PersonServerMetadata struct {
    Issuer                            string   `json:"issuer"`
    TokenEndpoint                     string   `json:"token_endpoint"`
    JWKSURI                           string   `json:"jwks_uri"`
    GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
    ScopesSupported                   []string `json:"scopes_supported,omitempty"`
    DelegationSupported               bool     `json:"delegation_supported,omitempty"`
}
```

## Token Exchange

### ExchangeClient

Client for OAuth 2.0 token exchange.

```go
client := aauth.NewExchangeClient(tokenEndpoint, httpClient)

// Create exchange request
req := aauth.NewResourceManagedExchangeRequest(
    resourceToken,
    []string{"https://api.example.com"},
    "read:data",
)

// Perform exchange
resp, err := client.Exchange(req)
// resp.AccessToken contains the auth token
```

## Well-Known Paths

```go
const (
    WellKnownResourcePath = "/.well-known/aauth-resource.json"
    WellKnownAgentPath    = "/.well-known/aauth-agent.json"
    WellKnownPersonPath   = "/.well-known/aauth-person.json"
    WellKnownOAuthPath    = "/.well-known/oauth-authorization-server"
)
```

## HTTP Headers

```go
const (
    HeaderAuthorization    = "Authorization"
    HeaderSignature        = "Signature"
    HeaderSignatureInput   = "Signature-Input"
    HeaderSignatureKey     = "Signature-Key"
    HeaderWWWAuthenticate  = "WWW-Authenticate"
)
```

## Error Types

```go
var (
    ErrInvalidToken      = errors.New("invalid token")
    ErrInvalidSignature  = errors.New("invalid signature")
    ErrTokenExpired      = errors.New("token expired")
    ErrInvalidAudience   = errors.New("invalid audience")
    ErrInvalidIssuer     = errors.New("invalid issuer")
    ErrMissingAuthToken  = errors.New("missing auth token")
    ErrInvalidScope      = errors.New("invalid scope")
    ErrDiscoveryFailed   = errors.New("discovery failed")
    ErrInvalidRequest    = errors.New("invalid request")
    ErrInvalidGrant      = errors.New("invalid grant")
)
```

## Challenge Parsing

```go
// Parse WWW-Authenticate challenge
challenge, err := aauth.ParseChallenge(wwwAuthHeader)
// challenge.Realm
// challenge.PersonServerURL
// challenge.ResourceToken
```
