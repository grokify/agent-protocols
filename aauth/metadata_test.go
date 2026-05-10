package aauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildWellKnownURL(t *testing.T) {
	tests := []struct {
		baseURL       string
		wellKnownPath string
		expected      string
	}{
		{
			baseURL:       "https://example.com",
			wellKnownPath: WellKnownResourcePath,
			expected:      "https://example.com/.well-known/aauth-resource.json",
		},
		{
			baseURL:       "https://example.com/",
			wellKnownPath: WellKnownResourcePath,
			expected:      "https://example.com/.well-known/aauth-resource.json",
		},
		{
			baseURL:       "https://example.com",
			wellKnownPath: WellKnownOAuthPath,
			expected:      "https://example.com/.well-known/oauth-authorization-server",
		},
	}

	for _, tt := range tests {
		got := BuildWellKnownURL(tt.baseURL, tt.wellKnownPath)
		if got != tt.expected {
			t.Errorf("BuildWellKnownURL(%q, %q) = %q, want %q", tt.baseURL, tt.wellKnownPath, got, tt.expected)
		}
	}
}

func TestMetadataHandler(t *testing.T) {
	metadata := &ResourceMetadata{
		Resource:        "https://resource.example.com",
		JWKSURI:         "https://resource.example.com/.well-known/jwks.json",
		PersonServerURI: "https://ps.example.com",
	}

	handler := MetadataHandler(metadata)
	req := httptest.NewRequest("GET", "/metadata", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var gotMetadata ResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&gotMetadata); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if gotMetadata.Resource != metadata.Resource {
		t.Errorf("expected Resource %s, got %s", metadata.Resource, gotMetadata.Resource)
	}
}

func TestMetadataHandler_MethodNotAllowed(t *testing.T) {
	metadata := &ResourceMetadata{}
	handler := MetadataHandler(metadata)

	req := httptest.NewRequest("POST", "/metadata", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestJWKSHandler(t *testing.T) {
	jwks := &JWKS{
		Keys: []JWK{
			{Kid: "key-1", Kty: "EC", Crv: "P-256"},
		},
	}

	handler := JWKSHandler(jwks)
	req := httptest.NewRequest("GET", "/jwks", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var gotJWKS JWKS
	if err := json.NewDecoder(rec.Body).Decode(&gotJWKS); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(gotJWKS.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(gotJWKS.Keys))
	}
	if gotJWKS.Keys[0].Kid != "key-1" {
		t.Errorf("expected kid 'key-1', got %s", gotJWKS.Keys[0].Kid)
	}
}

func TestParseResourceMetadata(t *testing.T) {
	data := []byte(`{
		"resource": "https://resource.example.com",
		"jwks_uri": "https://resource.example.com/.well-known/jwks.json",
		"person_server_uri": "https://ps.example.com"
	}`)

	metadata, err := ParseResourceMetadata(data)
	if err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	if metadata.Resource != "https://resource.example.com" {
		t.Errorf("expected resource https://resource.example.com, got %s", metadata.Resource)
	}
	if metadata.JWKSURI != "https://resource.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKS URI, got %s", metadata.JWKSURI)
	}
	if metadata.PersonServerURI != "https://ps.example.com" {
		t.Errorf("expected person server URI https://ps.example.com, got %s", metadata.PersonServerURI)
	}
}

func TestParseResourceMetadata_Invalid(t *testing.T) {
	data := []byte(`invalid json`)

	_, err := ParseResourceMetadata(data)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseAgentProviderMetadata(t *testing.T) {
	data := []byte(`{
		"agent_provider": "https://ap.example.com",
		"jwks_uri": "https://ap.example.com/.well-known/jwks.json",
		"signing_algs_supported": ["ES256", "ES384"]
	}`)

	metadata, err := ParseAgentProviderMetadata(data)
	if err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	if metadata.AgentProvider != "https://ap.example.com" {
		t.Errorf("expected agent_provider https://ap.example.com, got %s", metadata.AgentProvider)
	}
	if len(metadata.SigningAlgorithmsSupported) != 2 {
		t.Errorf("expected 2 signing algorithms, got %d", len(metadata.SigningAlgorithmsSupported))
	}
}

func TestParsePersonServerMetadata(t *testing.T) {
	data := []byte(`{
		"issuer": "https://ps.example.com",
		"token_endpoint": "https://ps.example.com/token",
		"jwks_uri": "https://ps.example.com/.well-known/jwks.json",
		"delegation_supported": true
	}`)

	metadata, err := ParsePersonServerMetadata(data)
	if err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	if metadata.Issuer != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", metadata.Issuer)
	}
	if metadata.TokenEndpoint != "https://ps.example.com/token" {
		t.Errorf("expected token endpoint, got %s", metadata.TokenEndpoint)
	}
	if !metadata.DelegationSupported {
		t.Error("expected delegation_supported to be true")
	}
}

func TestParseAuthServerMetadata(t *testing.T) {
	data := []byte(`{
		"issuer": "https://as.example.com",
		"token_endpoint": "https://as.example.com/token",
		"jwks_uri": "https://as.example.com/.well-known/jwks.json",
		"grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"]
	}`)

	metadata, err := ParseAuthServerMetadata(data)
	if err != nil {
		t.Fatalf("failed to parse metadata: %v", err)
	}

	if metadata.Issuer != "https://as.example.com" {
		t.Errorf("expected issuer https://as.example.com, got %s", metadata.Issuer)
	}
	if len(metadata.GrantTypesSupported) != 1 {
		t.Errorf("expected 1 grant type, got %d", len(metadata.GrantTypesSupported))
	}
}

func TestAgentProviderMetadata_Fields(t *testing.T) {
	metadata := &AgentProviderMetadata{
		AgentProvider:              "https://ap.example.com",
		JWKSURI:                    "https://ap.example.com/.well-known/jwks.json",
		RegistrationEndpoint:       "https://ap.example.com/register",
		DelegationEndpoint:         "https://ap.example.com/delegate",
		SigningAlgorithmsSupported: []string{"ES256"},
		AgentIDFormats:             []string{"aauth"},
		KeyTypesSupported:          []string{"EC", "RSA"},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var parsed AgentProviderMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	if parsed.RegistrationEndpoint != "https://ap.example.com/register" {
		t.Errorf("expected registration_endpoint, got %s", parsed.RegistrationEndpoint)
	}
}

func TestPersonServerMetadata_Fields(t *testing.T) {
	//nolint:gosec // G101 false positive - TokenEndpoint is a URL field, not credentials
	metadata := &PersonServerMetadata{
		Issuer:                            "https://ps.example.com",
		TokenEndpoint:                     "https://ps.example.com/token",
		JWKSURI:                           "https://ps.example.com/.well-known/jwks.json",
		GrantTypesSupported:               []string{GrantTypeTokenExchange},
		TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
		ScopesSupported:                   []string{"read", "write"},
		SubjectTokenTypesSupported:        []string{TokenTypeURIAgentJWT},
		ActorTokenTypesSupported:          []string{TokenTypeURIAgentJWT},
		DelegationSupported:               true,
		SigningAlgorithmsSupported:        []string{"ES256"},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal metadata: %v", err)
	}

	var parsed PersonServerMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}

	if len(parsed.ScopesSupported) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(parsed.ScopesSupported))
	}
}
