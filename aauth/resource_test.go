package aauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestNewResourceServer(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	if rs.URL() != "https://resource.example.com" {
		t.Errorf("expected URL https://resource.example.com, got %s", rs.URL())
	}
}

func TestNewResourceServer_Errors(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name       string
		url        string
		privateKey interface{}
		keyID      string
		wantErr    bool
	}{
		{
			name:       "valid",
			url:        "https://resource.example.com",
			privateKey: privateKey,
			keyID:      "key-1",
			wantErr:    false,
		},
		{
			name:       "empty URL",
			url:        "",
			privateKey: privateKey,
			keyID:      "key-1",
			wantErr:    true,
		},
		{
			name:       "nil key",
			url:        "https://resource.example.com",
			privateKey: nil,
			keyID:      "key-1",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewResourceServer(tt.url, tt.privateKey, tt.keyID)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestResourceServerOptions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
		WithResourceAccessServer("https://as.example.com"),
		WithRequiredScope("read write"),
		WithResourceTokenTTL(10*time.Minute),
		WithIdentityOnlyMode(true),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	opts := rs.Options()
	if opts.personServerURL != "https://ps.example.com" {
		t.Errorf("expected PS URL https://ps.example.com, got %s", opts.personServerURL)
	}
	if opts.accessServerURL != "https://as.example.com" {
		t.Errorf("expected AS URL https://as.example.com, got %s", opts.accessServerURL)
	}
	if opts.requiredScope != "read write" {
		t.Errorf("expected scope 'read write', got %s", opts.requiredScope)
	}
	if opts.resourceTokenTTL != 10*time.Minute {
		t.Errorf("expected TTL 10m, got %s", opts.resourceTokenTTL)
	}
	if !opts.allowIdentityOnly {
		t.Error("expected allowIdentityOnly to be true")
	}
}

func TestResourceServerChallenge(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
		WithRequiredScope("read"),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	challenge := rs.Challenge()
	if challenge.Realm != "https://resource.example.com" {
		t.Errorf("expected realm https://resource.example.com, got %s", challenge.Realm)
	}
	if challenge.PersonServerURL != "https://ps.example.com" {
		t.Errorf("expected PS URL https://ps.example.com, got %s", challenge.PersonServerURL)
	}
	if challenge.Scope != "read" {
		t.Errorf("expected scope 'read', got %s", challenge.Scope)
	}

	header := rs.ChallengeHeader()
	if header == "" {
		t.Error("expected non-empty challenge header")
	}
}

func TestResourceServerIssueResourceToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")
	token, err := rs.IssueResourceToken(agentID, "test-jkt-thumbprint", "read")
	if err != nil {
		t.Fatalf("failed to issue resource token: %v", err)
	}

	if token.Issuer != "https://resource.example.com" {
		t.Errorf("expected issuer https://resource.example.com, got %s", token.Issuer)
	}
	if token.AgentJKT != "test-jkt-thumbprint" {
		t.Errorf("expected AgentJKT test-jkt-thumbprint, got %s", token.AgentJKT)
	}
	if token.Scope != "read" {
		t.Errorf("expected scope read, got %s", token.Scope)
	}
}

func TestResourceServerIssueResourceToken_Errors(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")

	tests := []struct {
		name     string
		agentID  *AAuthID
		agentJKT string
		wantErr  bool
	}{
		{
			name:     "valid",
			agentID:  agentID,
			agentJKT: "test-jkt",
			wantErr:  false,
		},
		{
			name:     "nil agent ID",
			agentID:  nil,
			agentJKT: "test-jkt",
			wantErr:  true,
		},
		{
			name:     "empty JKT",
			agentID:  agentID,
			agentJKT: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := rs.IssueResourceToken(tt.agentID, tt.agentJKT, "read")
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestResourceServerSignResourceToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	agentID, _ := NewAAuthID("agent", "example.com")
	tokenStr, err := rs.SignResourceToken(agentID, "test-jkt-thumbprint", "read")
	if err != nil {
		t.Fatalf("failed to sign resource token: %v", err)
	}

	if tokenStr == "" {
		t.Error("expected non-empty token string")
	}
}

func TestResourceServerMetadata(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithResourcePersonServer("https://ps.example.com"),
		WithResourceAccessServer("https://as.example.com"),
		WithRequiredScope("read"),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	metadata := rs.Metadata()
	if metadata.Resource != "https://resource.example.com" {
		t.Errorf("expected resource https://resource.example.com, got %s", metadata.Resource)
	}
	if metadata.PersonServerURI != "https://ps.example.com" {
		t.Errorf("expected PS URI https://ps.example.com, got %s", metadata.PersonServerURI)
	}
	if metadata.AccessServerURI != "https://as.example.com" {
		t.Errorf("expected AS URI https://as.example.com, got %s", metadata.AccessServerURI)
	}
	if metadata.JWKSURI != "https://resource.example.com/.well-known/jwks.json" {
		t.Errorf("expected JWKS URI ending with .well-known/jwks.json, got %s", metadata.JWKSURI)
	}
}

func TestResourceServerPublicJWKS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	jwks, err := rs.PublicJWKS()
	if err != nil {
		t.Fatalf("failed to get JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "test-key-1" {
		t.Errorf("expected kid test-key-1, got %s", jwks.Keys[0].Kid)
	}
}

func TestCreateTokenResponse(t *testing.T) {
	resp := CreateTokenResponse("test-token", 5*time.Minute, "read write")

	if resp.AccessToken != "test-token" {
		t.Errorf("expected access_token test-token, got %s", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("expected expires_in 300, got %d", resp.ExpiresIn)
	}
	if resp.Scope != "read write" {
		t.Errorf("expected scope 'read write', got %s", resp.Scope)
	}
	if resp.IssuedTokenType != TokenTypeURIResourceJWT {
		t.Errorf("expected issued_token_type %s, got %s", TokenTypeURIResourceJWT, resp.IssuedTokenType)
	}
}
