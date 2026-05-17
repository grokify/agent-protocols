package idjag

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IdPAuthorizationServer issues ID-JAG assertions via OAuth 2.0 token exchange.
// Per draft-ietf-oauth-identity-assertion-authz-grant, clients request an ID-JAG
// using grant_type=token-exchange with requested_token_type=id-jag.
type IdPAuthorizationServer struct {
	// Issuer is the issuer identifier (iss claim) for created assertions.
	Issuer string

	// SigningMethod is the JWT signing method (e.g., RS256, ES256).
	SigningMethod jwt.SigningMethod

	// SigningKey is the private key for signing assertions.
	SigningKey crypto.PrivateKey

	// KeyID is the key identifier to include in JWT headers.
	KeyID string

	// AssertionTTL is the lifetime for issued assertions.
	// Default is 5 minutes per IETF draft recommendations.
	AssertionTTL time.Duration

	// SubjectTokenVerifier validates the subject_token (e.g., ID token, refresh token).
	// If nil, subject tokens are not validated (not recommended for production).
	SubjectTokenVerifier Verifier

	// DelegationPolicy is called to validate delegation requests.
	// If nil, all delegation requests are allowed.
	DelegationPolicy func(ctx context.Context, req *IDJAGRequest) error
}

// IDJAGRequest represents an OAuth 2.0 token exchange request for an ID-JAG.
// Per IETF draft, the request uses grant_type=token-exchange.
type IDJAGRequest struct {
	// SubjectToken is the security token representing the user's identity.
	// This is typically an ID token, SAML assertion, or refresh token.
	SubjectToken string

	// SubjectTokenType identifies the type of subject token.
	// Common values: TokenTypeIDToken, TokenTypeSAML2, TokenTypeRefreshToken.
	SubjectTokenType string

	// ActorToken optionally identifies the acting party (agent).
	// Per IETF draft, processing of actor_token is not normatively defined.
	ActorToken string

	// ActorTokenType identifies the type of actor token (required if ActorToken set).
	ActorTokenType string

	// Audience is the Resource Authorization Server identifier.
	Audience string

	// ClientID is the OAuth client identifier at the Resource Authorization Server.
	ClientID string

	// Scope is the requested scope (optional).
	Scope string

	// Resource is the resource identifier per RFC 8707 (optional).
	Resource string
}

// IDJAGResponse is the token exchange response containing the ID-JAG.
type IDJAGResponse struct {
	// AccessToken contains the ID-JAG assertion (named per OAuth convention).
	AccessToken string `json:"access_token"`

	// IssuedTokenType is always TokenTypeIDJAG for ID-JAG responses.
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is "N_A" per RFC 8693 for non-access-token responses.
	TokenType string `json:"token_type"`

	// ExpiresIn is the assertion lifetime in seconds.
	ExpiresIn int `json:"expires_in"`

	// Scope is the granted scope.
	Scope string `json:"scope,omitempty"`
}

// NewIdPAuthorizationServer creates a new IdP Authorization Server for issuing ID-JAGs.
func NewIdPAuthorizationServer(issuer string, signingMethod jwt.SigningMethod, signingKey crypto.PrivateKey, keyID string) *IdPAuthorizationServer {
	return &IdPAuthorizationServer{
		Issuer:        issuer,
		SigningMethod: signingMethod,
		SigningKey:    signingKey,
		KeyID:         keyID,
		AssertionTTL:  5 * time.Minute,
	}
}

// ServeHTTP implements http.Handler for the IdP token endpoint.
// Handles token exchange requests with requested_token_type=id-jag.
func (s *IdPAuthorizationServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "invalid request body")
		return
	}

	grantType := r.Form.Get("grant_type")
	if grantType != GrantTypeTokenExchange {
		s.writeError(w, http.StatusBadRequest, ErrorUnsupportedGrantType,
			fmt.Sprintf("expected %s, got %s", GrantTypeTokenExchange, grantType))
		return
	}

	requestedTokenType := r.Form.Get("requested_token_type")
	if requestedTokenType != TokenTypeIDJAG {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest,
			fmt.Sprintf("requested_token_type must be %s", TokenTypeIDJAG))
		return
	}

	req := &IDJAGRequest{
		SubjectToken:     r.Form.Get("subject_token"),
		SubjectTokenType: r.Form.Get("subject_token_type"),
		ActorToken:       r.Form.Get("actor_token"),
		ActorTokenType:   r.Form.Get("actor_token_type"),
		Audience:         r.Form.Get("audience"),
		ClientID:         r.Form.Get("client_id"),
		Scope:            r.Form.Get("scope"),
		Resource:         r.Form.Get("resource"),
	}

	if req.SubjectToken == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "subject_token required")
		return
	}
	if req.SubjectTokenType == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "subject_token_type required")
		return
	}
	if req.Audience == "" {
		s.writeError(w, http.StatusBadRequest, ErrorInvalidRequest, "audience required")
		return
	}

	resp, err := s.IssueIDJAG(r.Context(), req)
	if err != nil {
		s.writeError(w, http.StatusForbidden, ErrorInvalidGrant, err.Error())
		return
	}

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	//nolint:gosec // G117: access_token is OAuth field name, not a secret
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// IssueIDJAG creates an ID-JAG assertion from a token exchange request.
func (s *IdPAuthorizationServer) IssueIDJAG(ctx context.Context, req *IDJAGRequest) (*IDJAGResponse, error) {
	// Validate required fields
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}
	if req.Audience == "" {
		return nil, fmt.Errorf("audience is required")
	}

	// Validate subject token if verifier is configured
	var subjectAssertion *Assertion
	if s.SubjectTokenVerifier != nil {
		var err error
		subjectAssertion, err = s.SubjectTokenVerifier.Verify(ctx, req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject_token: %w", err)
		}
	} else {
		// Parse without verification (for demo/testing only)
		var err error
		subjectAssertion, err = ParseAssertion(req.SubjectToken)
		if err != nil {
			return nil, fmt.Errorf("failed to parse subject_token: %w", err)
		}
	}

	// Apply delegation policy if configured
	if s.DelegationPolicy != nil {
		if err := s.DelegationPolicy(ctx, req); err != nil {
			return nil, fmt.Errorf("delegation not authorized: %w", err)
		}
	}

	// Create the ID-JAG assertion
	assertion := NewAssertion(
		s.Issuer,
		subjectAssertion.Subject, // User identity from subject_token
		[]string{req.Audience},
		s.AssertionTTL,
	)
	assertion.ClientID = req.ClientID

	// Add actor claim if actor_token is provided
	// Note: IETF draft does not normatively define actor_token processing;
	// this implementation follows RFC 8693 delegation semantics.
	if req.ActorToken != "" {
		actorAssertion, err := ParseAssertion(req.ActorToken)
		if err != nil {
			return nil, fmt.Errorf("invalid actor_token: %w", err)
		}
		assertion.Actor = &Actor{Subject: actorAssertion.Subject}
	}

	// Add scope if requested
	if req.Scope != "" {
		assertion.WithClaim(ClaimScope, req.Scope)
	}

	// Sign the ID-JAG
	signedJWT, err := assertion.Sign(s.SigningMethod, s.SigningKey, s.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign ID-JAG: %w", err)
	}

	return &IDJAGResponse{
		AccessToken:     signedJWT,
		IssuedTokenType: TokenTypeIDJAG,
		TokenType:       "N_A", // Per RFC 8693 for non-access-token responses
		ExpiresIn:       int(s.AssertionTTL.Seconds()),
		Scope:           req.Scope,
	}, nil
}

func (s *IdPAuthorizationServer) writeError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(&TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	})
}

// IDJAGClient requests ID-JAG assertions from an IdP via OAuth token exchange.
type IDJAGClient struct {
	// TokenURL is the IdP's token endpoint.
	TokenURL string

	// HTTPClient is the HTTP client to use. If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// ClientID is the OAuth client identifier.
	ClientID string

	// ClientSecret is the OAuth client secret (for confidential clients).
	ClientSecret string
}

// NewIDJAGClient creates a client for requesting ID-JAG assertions.
func NewIDJAGClient(tokenURL string) *IDJAGClient {
	return &IDJAGClient{
		TokenURL:   tokenURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithCredentials sets client credentials for authentication.
func (c *IDJAGClient) WithCredentials(clientID, clientSecret string) *IDJAGClient {
	c.ClientID = clientID
	c.ClientSecret = clientSecret
	return c
}

// RequestIDJAG requests an ID-JAG from the IdP using OAuth token exchange.
// Per IETF draft, this uses grant_type=token-exchange with requested_token_type=id-jag.
func (c *IDJAGClient) RequestIDJAG(ctx context.Context, req *IDJAGRequest) (*IDJAGResponse, error) {
	data := url.Values{}
	data.Set("grant_type", GrantTypeTokenExchange)
	data.Set("requested_token_type", TokenTypeIDJAG)
	data.Set("subject_token", req.SubjectToken)
	data.Set("subject_token_type", req.SubjectTokenType)
	data.Set("audience", req.Audience)

	if req.ActorToken != "" {
		data.Set("actor_token", req.ActorToken)
		data.Set("actor_token_type", req.ActorTokenType)
	}
	if req.ClientID != "" {
		data.Set("client_id", req.ClientID)
	} else if c.ClientID != "" && c.ClientSecret == "" {
		data.Set("client_id", c.ClientID)
	}
	if req.Scope != "" {
		data.Set("scope", req.Scope)
	}
	if req.Resource != "" {
		data.Set("resource", req.Resource)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set(HeaderContentType, ContentTypeFormURLEncoded)

	if c.ClientID != "" && c.ClientSecret != "" {
		httpReq.SetBasicAuth(c.ClientID, c.ClientSecret)
	}

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("IdP error: %s - %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("IdP returned status %d", resp.StatusCode)
	}

	var idjagResp IDJAGResponse
	if err := json.Unmarshal(body, &idjagResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &idjagResp, nil
}

// ============================================================================
// Legacy API (deprecated, kept for backward compatibility)
// ============================================================================

// IssuerService is deprecated. Use IdPAuthorizationServer instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
type IssuerService = IdPAuthorizationServer

// NewIssuerService is deprecated. Use NewIdPAuthorizationServer instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
var NewIssuerService = NewIdPAuthorizationServer

// DelegationRequest is deprecated. Use IDJAGRequest instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
type DelegationRequest struct {
	Subject           string            `json:"subject"`
	AgentID           string            `json:"agent_id"`
	Audience          []string          `json:"audience"`
	RequestedScopes   []string          `json:"requested_scopes,omitempty"`
	DelegationContext map[string]string `json:"delegation_context,omitempty"`
}

// DelegationResponse is deprecated. Use IDJAGResponse instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
type DelegationResponse struct {
	Assertion string `json:"assertion"`
	ExpiresIn int    `json:"expires_in"`
	Subject   string `json:"subject"`
	Actor     string `json:"actor"`
}

// CreateDelegatedAssertion is deprecated. Use IssueIDJAG instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
func (s *IdPAuthorizationServer) CreateDelegatedAssertion(ctx context.Context, req *DelegationRequest) (*DelegationResponse, error) {
	if req.Subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if req.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if len(req.Audience) == 0 {
		return nil, fmt.Errorf("audience is required")
	}

	// Create the assertion with user as subject and agent as actor
	assertion := NewDelegatedAssertion(
		s.Issuer,
		req.Subject,
		req.AgentID,
		req.Audience,
		s.AssertionTTL,
	)

	if len(req.RequestedScopes) > 0 {
		assertion.WithClaim("requested_scope", req.RequestedScopes)
	}

	signedJWT, err := assertion.Sign(s.SigningMethod, s.SigningKey, s.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	return &DelegationResponse{
		Assertion: signedJWT,
		ExpiresIn: int(s.AssertionTTL.Seconds()),
		Subject:   req.Subject,
		Actor:     req.AgentID,
	}, nil
}

// CreateNestedDelegation creates an assertion with a nested delegation chain.
func (s *IdPAuthorizationServer) CreateNestedDelegation(ctx context.Context, subject string, actors []string, audience []string) (*DelegationResponse, error) {
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if len(actors) == 0 {
		return nil, fmt.Errorf("at least one actor is required")
	}
	if len(audience) == 0 {
		return nil, fmt.Errorf("audience is required")
	}

	var actor *Actor
	for i := len(actors) - 1; i >= 0; i-- {
		actor = &Actor{
			Subject: actors[i],
			Actor:   actor,
		}
	}

	assertion := NewAssertion(s.Issuer, subject, audience, s.AssertionTTL)
	assertion.Actor = actor

	signedJWT, err := assertion.Sign(s.SigningMethod, s.SigningKey, s.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	return &DelegationResponse{
		Assertion: signedJWT,
		ExpiresIn: int(s.AssertionTTL.Seconds()),
		Subject:   subject,
		Actor:     actors[0],
	}, nil
}

// IssuerHandler is deprecated. Use IdPAuthorizationServer.ServeHTTP instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
type IssuerHandler struct {
	issuer *IdPAuthorizationServer
}

// NewIssuerHandler is deprecated.
// Deprecated: Use IdPAuthorizationServer directly as an http.Handler.
func NewIssuerHandler(issuer *IdPAuthorizationServer) *IssuerHandler {
	return &IssuerHandler{issuer: issuer}
}

// ServeHTTP handles legacy delegation requests (JSON body, not OAuth).
func (h *IssuerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req DelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeIssuerError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.issuer.CreateDelegatedAssertion(r.Context(), &req)
	if err != nil {
		writeIssuerError(w, http.StatusForbidden, err.Error())
		return
	}

	w.Header().Set(HeaderContentType, ContentTypeJSON)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeIssuerError(w http.ResponseWriter, status int, message string) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// IssuerClient is deprecated. Use IDJAGClient instead.
// Deprecated: This simplified API does not follow the IETF draft OAuth flow.
type IssuerClient struct {
	IssuerURL  string
	HTTPClient *http.Client
}

// NewIssuerClient is deprecated. Use NewIDJAGClient instead.
func NewIssuerClient(issuerURL string) *IssuerClient {
	return &IssuerClient{
		IssuerURL:  issuerURL,
		HTTPClient: http.DefaultClient,
	}
}

// RequestDelegatedAssertion is deprecated.
func (c *IssuerClient) RequestDelegatedAssertion(ctx context.Context, req *DelegationRequest) (*DelegationResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.IssuerURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set(HeaderContentType, ContentTypeJSON)

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("issuer returned status %d: %s", resp.StatusCode, errResp.Error)
	}

	var delegationResp DelegationResponse
	if err := json.NewDecoder(resp.Body).Decode(&delegationResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &delegationResp, nil
}
