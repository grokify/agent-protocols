package aauth

import (
	"fmt"
	"net/http"
)

// agentTransport is an http.RoundTripper that automatically signs requests.
type agentTransport struct {
	agent *Agent
}

// RoundTrip implements http.RoundTripper.
func (t *agentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Add agent token if not present
	if reqCopy.Header.Get(HeaderSignatureKey) == "" {
		token, err := t.agent.GetOrCreateAgentToken()
		if err != nil {
			return nil, fmt.Errorf("failed to get agent token: %w", err)
		}
		reqCopy.Header.Set(HeaderSignatureKey, fmt.Sprintf("scheme=%s %s", SignatureKeySchemeJWT, token))
	}

	// Sign the request if not already signed
	if reqCopy.Header.Get(HeaderSignature) == "" {
		if err := t.agent.SignRequest(reqCopy); err != nil {
			return nil, fmt.Errorf("failed to sign request: %w", err)
		}
	}

	// Use the agent's HTTP client transport or default
	var transport http.RoundTripper = http.DefaultTransport
	if t.agent.opts.httpClient != nil && t.agent.opts.httpClient.Transport != nil {
		transport = t.agent.opts.httpClient.Transport
	}

	return transport.RoundTrip(reqCopy)
}

// SigningTransport wraps an existing transport with request signing.
type SigningTransport struct {
	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Agent is the agent used for signing.
	Agent *Agent

	// AddAgentToken controls whether to add the agent token.
	// Default is true.
	AddAgentToken bool
}

// RoundTrip implements http.RoundTripper.
func (t *SigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Add agent token if enabled
	if t.AddAgentToken && reqCopy.Header.Get(HeaderSignatureKey) == "" {
		token, err := t.Agent.GetOrCreateAgentToken()
		if err != nil {
			return nil, fmt.Errorf("failed to get agent token: %w", err)
		}
		reqCopy.Header.Set(HeaderSignatureKey, fmt.Sprintf("scheme=%s %s", SignatureKeySchemeJWT, token))
	}

	// Sign the request
	if err := t.Agent.SignRequest(reqCopy); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Use base transport
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(reqCopy)
}
