package aauth

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth/httpsig"
)

// Agent represents an AAuth agent with identity and signing capability.
type Agent struct {
	id         *AAuthID
	keyPair    *KeyPair
	opts       *agentOptions
	httpSigner httpsig.Signer

	// Cached agent token
	mu          sync.RWMutex
	cachedToken string
	tokenExpiry time.Time
}

// NewAgent creates a new AAuth agent.
func NewAgent(id *AAuthID, privateKey crypto.PrivateKey, opts ...AgentOption) (*Agent, error) {
	if id == nil {
		return nil, fmt.Errorf("agent ID is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Determine key type and create KeyPair
	kp, err := keyPairFromPrivateKey(privateKey, id.Local)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	options := defaultAgentOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Create HTTP signer
	httpSigner, err := httpsig.NewSigner(httpsig.SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             kp.KeyID,
		Algorithm:         kp.HTTPSigAlgorithm(),
		CoveredComponents: options.coveredComponents,
		Label:             options.signatureLabel,
		IncludeNonce:      options.includeNonce,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP signer: %w", err)
	}

	return &Agent{
		id:         id,
		keyPair:    kp,
		opts:       options,
		httpSigner: httpSigner,
	}, nil
}

// ID returns the agent's AAuth ID.
func (a *Agent) ID() *AAuthID {
	return a.id
}

// KeyPair returns the agent's key pair.
func (a *Agent) KeyPair() *KeyPair {
	return a.keyPair
}

// CreateAgentToken creates a new agent token.
func (a *Agent) CreateAgentToken(audience ...string) (*AgentToken, error) {
	cnf, err := a.keyPair.ToCNF()
	if err != nil {
		return nil, fmt.Errorf("failed to create CNF: %w", err)
	}

	// Use agent provider URL as issuer, or construct from domain
	issuer := a.opts.agentProviderURL
	if issuer == "" {
		issuer = fmt.Sprintf("https://%s", a.id.Domain)
	}

	token := NewAgentToken(issuer, a.id.String(), cnf, a.opts.tokenTTL)

	if len(audience) > 0 {
		token.WithAudience(audience...)
	}

	if a.opts.agentProviderURL != "" {
		token.WithDWK(a.opts.agentProviderURL + WellKnownAgentPath)
	}

	if a.opts.personServerURL != "" {
		token.WithPS(a.opts.personServerURL)
	}

	return token, nil
}

// SignAgentToken creates and signs an agent token.
func (a *Agent) SignAgentToken(audience ...string) (string, error) {
	token, err := a.CreateAgentToken(audience...)
	if err != nil {
		return "", err
	}

	return token.Sign(a.opts.signingMethod, a.keyPair.PrivateKey, a.keyPair.KeyID)
}

// GetOrCreateAgentToken returns a cached agent token or creates a new one.
// Tokens are cached until they are within 5 minutes of expiry.
func (a *Agent) GetOrCreateAgentToken(audience ...string) (string, error) {
	a.mu.RLock()
	if a.cachedToken != "" && time.Until(a.tokenExpiry) > 5*time.Minute {
		token := a.cachedToken
		a.mu.RUnlock()
		return token, nil
	}
	a.mu.RUnlock()

	// Create new token
	token, err := a.SignAgentToken(audience...)
	if err != nil {
		return "", err
	}

	// Cache it
	a.mu.Lock()
	a.cachedToken = token
	a.tokenExpiry = time.Now().Add(a.opts.tokenTTL)
	a.mu.Unlock()

	return token, nil
}

// SignRequest signs an HTTP request with HTTP Message Signatures.
// This adds the Signature and Signature-Input headers.
func (a *Agent) SignRequest(req *http.Request) error {
	return a.httpSigner.Sign(req)
}

// SignedRequest creates a new signed HTTP request.
func (a *Agent) SignedRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Add the agent token as Signature-Key header
	token, err := a.GetOrCreateAgentToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get agent token: %w", err)
	}
	req.Header.Set(HeaderSignatureKey, fmt.Sprintf("scheme=%s %s", SignatureKeySchemeJWT, token))

	// Sign the request
	if err := a.SignRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return req, nil
}

// Do sends a signed HTTP request and returns the response.
func (a *Agent) Do(req *http.Request) (*http.Response, error) {
	// Sign the request if not already signed
	if req.Header.Get(HeaderSignature) == "" {
		// Add agent token if not present
		if req.Header.Get(HeaderSignatureKey) == "" {
			token, err := a.GetOrCreateAgentToken()
			if err != nil {
				return nil, fmt.Errorf("failed to get agent token: %w", err)
			}
			req.Header.Set(HeaderSignatureKey, fmt.Sprintf("scheme=%s %s", SignatureKeySchemeJWT, token))
		}

		if err := a.SignRequest(req); err != nil {
			return nil, fmt.Errorf("failed to sign request: %w", err)
		}
	}

	return a.opts.httpClient.Do(req)
}

// Transport returns an http.RoundTripper that automatically signs requests.
func (a *Agent) Transport() http.RoundTripper {
	return &agentTransport{agent: a}
}

// Client returns an http.Client that automatically signs requests.
func (a *Agent) Client() *http.Client {
	return &http.Client{
		Transport: a.Transport(),
	}
}

// keyPairFromPrivateKey creates a KeyPair from a private key.
func keyPairFromPrivateKey(privateKey crypto.PrivateKey, keyID string) (*KeyPair, error) {
	switch k := privateKey.(type) {
	case interface{ Public() crypto.PublicKey }:
		pub := k.Public()
		// Determine algorithm based on key type
		jwk, err := PublicKeyToJWK(pub, keyID)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			PrivateKey: privateKey,
			PublicKey:  pub,
			KeyID:      keyID,
			Algorithm:  jwk.Alg,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}
