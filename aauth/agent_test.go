package aauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewAgent(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, err := NewAgent(id, privateKey)
	if err != nil {
		t.Fatalf("NewAgent() error = %v", err)
	}

	if agent.ID().String() != "aauth:test-agent@example.com" {
		t.Errorf("expected ID aauth:test-agent@example.com, got %s", agent.ID().String())
	}
}

func TestNewAgent_MissingID(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := NewAgent(nil, privateKey)
	if err == nil {
		t.Error("expected error for missing ID")
	}
}

func TestNewAgent_MissingKey(t *testing.T) {
	id, _ := NewAAuthID("test-agent", "example.com")

	_, err := NewAgent(id, nil)
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestAgent_CreateAgentToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	token, err := agent.CreateAgentToken("https://resource.example.com")
	if err != nil {
		t.Fatalf("CreateAgentToken() error = %v", err)
	}

	if token.Subject != "aauth:test-agent@example.com" {
		t.Errorf("expected subject aauth:test-agent@example.com, got %s", token.Subject)
	}
	if len(token.Audience) != 1 || token.Audience[0] != "https://resource.example.com" {
		t.Error("expected audience to be set")
	}
	if token.CNF == nil {
		t.Error("expected CNF to be set")
	}
}

func TestAgent_SignAgentToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	tokenStr, err := agent.SignAgentToken()
	if err != nil {
		t.Fatalf("SignAgentToken() error = %v", err)
	}

	if tokenStr == "" {
		t.Error("expected non-empty token string")
	}

	// Verify it can be parsed
	parsed, err := ParseAgentToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if parsed.Subject != "aauth:test-agent@example.com" {
		t.Errorf("expected subject aauth:test-agent@example.com, got %s", parsed.Subject)
	}
}

func TestAgent_GetOrCreateAgentToken_Caching(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	token1, _ := agent.GetOrCreateAgentToken()
	token2, _ := agent.GetOrCreateAgentToken()

	if token1 != token2 {
		t.Error("expected tokens to be cached")
	}
}

func TestAgent_SignRequest(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	req, _ := http.NewRequest("GET", "https://example.com/api", nil)
	err := agent.SignRequest(req)
	if err != nil {
		t.Fatalf("SignRequest() error = %v", err)
	}

	if req.Header.Get("Signature") == "" {
		t.Error("expected Signature header")
	}
	if req.Header.Get("Signature-Input") == "" {
		t.Error("expected Signature-Input header")
	}
}

func TestAgent_SignedRequest(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	req, err := agent.SignedRequest(context.Background(), "GET", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("SignedRequest() error = %v", err)
	}

	if req.Header.Get("Signature") == "" {
		t.Error("expected Signature header")
	}
	if req.Header.Get("Signature-Key") == "" {
		t.Error("expected Signature-Key header")
	}
}

func TestAgent_Transport(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)
	transport := agent.Transport()

	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestAgent_Client(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)
	client := agent.Client()

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Transport == nil {
		t.Error("expected transport to be set")
	}
}

func TestAgent_Do(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify signature headers are present
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header")
		}
		if r.Header.Get("Signature-Input") == "" {
			t.Error("expected Signature-Input header")
		}
		if r.Header.Get("Signature-Key") == "" {
			t.Error("expected Signature-Key header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)

	req, _ := http.NewRequest("GET", server.URL+"/api", nil)
	resp, err := agent.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAgent_WithOptions(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey,
		WithTokenTTL(30*time.Minute),
		WithAgentProviderURL("https://provider.example.com"),
		WithPersonServerURL("https://ps.example.com"),
		WithCoveredComponents([]string{"@method", "@target-uri"}),
		WithSignatureLabel("custom-sig"),
	)

	token, _ := agent.CreateAgentToken()

	if token.DWK != "https://provider.example.com/.well-known/aauth-agent.json" {
		t.Errorf("expected DWK to be set, got %s", token.DWK)
	}
	if token.PS != "https://ps.example.com" {
		t.Errorf("expected PS to be set, got %s", token.PS)
	}
}

func TestAgent_KeyPair(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)
	kp := agent.KeyPair()

	if kp == nil {
		t.Fatal("expected non-nil key pair")
	}
	if kp.Algorithm != AlgorithmES256 {
		t.Errorf("expected algorithm ES256, got %s", kp.Algorithm)
	}
}

func TestAgentTransport_RoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Signature") == "" {
			t.Error("expected Signature header")
		}
		if !strings.HasPrefix(r.Header.Get("Signature-Key"), "scheme=jwt") {
			t.Error("expected Signature-Key header with jwt scheme")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := NewAAuthID("test-agent", "example.com")

	agent, _ := NewAgent(id, privateKey)
	client := agent.Client()

	resp, err := client.Get(server.URL + "/test")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
