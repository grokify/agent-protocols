package aauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AgentProviderMetadata represents the .well-known/aauth-agent-provider.json metadata.
// This metadata is served by Agent Providers to help clients discover agent capabilities.
type AgentProviderMetadata struct {
	// AgentProvider is the Agent Provider URL.
	AgentProvider string `json:"agent_provider"`

	// JWKSURI is the URL to the Agent Provider's JWKS.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// RegistrationEndpoint is the agent registration endpoint.
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// DelegationEndpoint is the delegation endpoint for human-to-agent delegation.
	DelegationEndpoint string `json:"delegation_endpoint,omitempty"`

	// SigningAlgorithmsSupported lists supported signing algorithms.
	SigningAlgorithmsSupported []string `json:"signing_algs_supported,omitempty"`

	// AgentIDFormats lists supported agent ID formats.
	AgentIDFormats []string `json:"agent_id_formats_supported,omitempty"`

	// KeyTypesSupported lists supported key types.
	KeyTypesSupported []string `json:"key_types_supported,omitempty"`
}

// PersonServerMetadata represents the .well-known/aauth-person-server.json metadata.
// This metadata is served by Person Servers (or Access Servers acting as PS).
type PersonServerMetadata struct {
	// Issuer is the Person Server's issuer identifier.
	Issuer string `json:"issuer"`

	// TokenEndpoint is the URL of the token endpoint.
	TokenEndpoint string `json:"token_endpoint"`

	// JWKSURI is the URL of the JSON Web Key Set document.
	JWKSURI string `json:"jwks_uri"`

	// GrantTypesSupported lists the supported grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists the client auth methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// ScopesSupported lists the supported scopes.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// SubjectTokenTypesSupported lists supported subject_token_type values.
	SubjectTokenTypesSupported []string `json:"subject_token_types_supported,omitempty"`

	// ActorTokenTypesSupported lists supported actor_token_type values.
	ActorTokenTypesSupported []string `json:"actor_token_types_supported,omitempty"`

	// DelegationSupported indicates if human-to-agent delegation is supported.
	DelegationSupported bool `json:"delegation_supported,omitempty"`

	// SigningAlgorithmsSupported lists supported signing algorithms.
	SigningAlgorithmsSupported []string `json:"signing_algs_supported,omitempty"`
}

// AccessServerMetadata represents the .well-known/oauth-authorization-server metadata.
// This follows the standard OAuth 2.0 Authorization Server Metadata format.
type AccessServerMetadata = AuthServerMetadata

// Additional well-known paths not defined in claims.go.
const (
	// WellKnownOAuthPath is the path for OAuth authorization server metadata.
	WellKnownOAuthPath = "/.well-known/oauth-authorization-server"

	// WellKnownJWKSPath is the path for JWKS.
	WellKnownJWKSPath = "/.well-known/jwks.json"
)

// BuildWellKnownURL constructs a well-known URL from a base URL and path.
func BuildWellKnownURL(baseURL, wellKnownPath string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return baseURL + wellKnownPath
}

// MetadataHandler returns an http.Handler that serves the given metadata as JSON.
func MetadataHandler(metadata interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")

		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})
}

// JWKSHandler returns an http.Handler that serves the given JWKS.
func JWKSHandler(jwks *JWKS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")

		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})
}

// ParseResourceMetadata parses resource metadata from JSON.
func ParseResourceMetadata(data []byte) (*ResourceMetadata, error) {
	var metadata ResourceMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	return &metadata, nil
}

// ParseAgentProviderMetadata parses agent provider metadata from JSON.
func ParseAgentProviderMetadata(data []byte) (*AgentProviderMetadata, error) {
	var metadata AgentProviderMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	return &metadata, nil
}

// ParsePersonServerMetadata parses person server metadata from JSON.
func ParsePersonServerMetadata(data []byte) (*PersonServerMetadata, error) {
	var metadata PersonServerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	return &metadata, nil
}

// ParseAuthServerMetadata parses auth server metadata from JSON.
func ParseAuthServerMetadata(data []byte) (*AuthServerMetadata, error) {
	var metadata AuthServerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	return &metadata, nil
}
