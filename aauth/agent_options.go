package aauth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AgentOption configures an Agent.
type AgentOption func(*agentOptions)

type agentOptions struct {
	// HTTP client for making requests
	httpClient *http.Client

	// Signing method for JWTs
	signingMethod jwt.SigningMethod

	// Token TTL
	tokenTTL time.Duration

	// Agent provider URL (for DWK claim)
	agentProviderURL string

	// Person server URL
	personServerURL string

	// HTTP signature components to cover
	coveredComponents []string

	// Include nonce in HTTP signatures
	includeNonce bool

	// Signature label
	signatureLabel string
}

func defaultAgentOptions() *agentOptions {
	return &agentOptions{
		httpClient:        http.DefaultClient,
		signingMethod:     jwt.SigningMethodES256,
		tokenTTL:          1 * time.Hour,
		coveredComponents: []string{"@method", "@target-uri", "content-digest", "signature-key"},
		includeNonce:      true,
		signatureLabel:    "sig1",
	}
}

// WithHTTPClient sets a custom HTTP client for the agent.
func WithHTTPClient(client *http.Client) AgentOption {
	return func(opts *agentOptions) {
		opts.httpClient = client
	}
}

// WithSigningMethod sets the JWT signing method.
func WithSigningMethod(method jwt.SigningMethod) AgentOption {
	return func(opts *agentOptions) {
		opts.signingMethod = method
	}
}

// WithTokenTTL sets the TTL for generated tokens.
func WithTokenTTL(ttl time.Duration) AgentOption {
	return func(opts *agentOptions) {
		opts.tokenTTL = ttl
	}
}

// WithAgentProviderURL sets the agent provider URL (for DWK claim).
func WithAgentProviderURL(url string) AgentOption {
	return func(opts *agentOptions) {
		opts.agentProviderURL = url
	}
}

// WithPersonServerURL sets the person server URL.
func WithPersonServerURL(url string) AgentOption {
	return func(opts *agentOptions) {
		opts.personServerURL = url
	}
}

// WithCoveredComponents sets the HTTP signature covered components.
func WithCoveredComponents(components []string) AgentOption {
	return func(opts *agentOptions) {
		opts.coveredComponents = components
	}
}

// WithNonce enables or disables nonce in HTTP signatures.
func WithNonce(include bool) AgentOption {
	return func(opts *agentOptions) {
		opts.includeNonce = include
	}
}

// WithSignatureLabel sets the HTTP signature label.
func WithSignatureLabel(label string) AgentOption {
	return func(opts *agentOptions) {
		opts.signatureLabel = label
	}
}
