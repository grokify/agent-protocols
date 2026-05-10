package aauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewDiscoveryClient(t *testing.T) {
	client := NewDiscoveryClient()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.httpClient == nil {
		t.Error("expected default HTTP client")
	}
	if client.cache == nil {
		t.Error("expected cache to be initialized")
	}
}

func TestDiscoveryClientOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 30 * time.Second}
	client := NewDiscoveryClient(
		WithDiscoveryHTTPClient(customClient),
		WithDiscoveryCacheTTL(10*time.Minute),
	)

	if client.httpClient != customClient {
		t.Error("expected custom HTTP client")
	}
	if client.cacheTTL != 10*time.Minute {
		t.Errorf("expected TTL 10m, got %s", client.cacheTTL)
	}
}

func TestDiscoveryClient_DiscoverResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownResourcePath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"resource": "https://resource.example.com",
			"jwks_uri": "https://resource.example.com/.well-known/jwks.json",
			"person_server_uri": "https://ps.example.com"
		}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	metadata, err := client.DiscoverResource(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover resource: %v", err)
	}

	if metadata.Resource != "https://resource.example.com" {
		t.Errorf("expected resource https://resource.example.com, got %s", metadata.Resource)
	}
	if metadata.PersonServerURI != "https://ps.example.com" {
		t.Errorf("expected PS URI https://ps.example.com, got %s", metadata.PersonServerURI)
	}
}

func TestDiscoveryClient_DiscoverResource_Cached(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource": "https://resource.example.com"}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	// First call
	_, err := client.DiscoverResource(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover resource: %v", err)
	}

	// Second call should use cache
	_, err = client.DiscoverResource(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover resource: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 server call (cached), got %d", callCount)
	}
}

func TestDiscoveryClient_DiscoverAgentProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownAgentPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"agent_provider": "https://ap.example.com",
			"jwks_uri": "https://ap.example.com/.well-known/jwks.json"
		}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	metadata, err := client.DiscoverAgentProvider(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover agent provider: %v", err)
	}

	if metadata.AgentProvider != "https://ap.example.com" {
		t.Errorf("expected agent_provider https://ap.example.com, got %s", metadata.AgentProvider)
	}
}

func TestDiscoveryClient_DiscoverPersonServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPersonPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer": "https://ps.example.com",
			"token_endpoint": "https://ps.example.com/token",
			"jwks_uri": "https://ps.example.com/.well-known/jwks.json"
		}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	metadata, err := client.DiscoverPersonServer(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover person server: %v", err)
	}

	if metadata.Issuer != "https://ps.example.com" {
		t.Errorf("expected issuer https://ps.example.com, got %s", metadata.Issuer)
	}
	if metadata.TokenEndpoint != "https://ps.example.com/token" {
		t.Errorf("expected token endpoint, got %s", metadata.TokenEndpoint)
	}
}

func TestDiscoveryClient_DiscoverAuthServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownOAuthPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer": "https://as.example.com",
			"token_endpoint": "https://as.example.com/token",
			"jwks_uri": "https://as.example.com/.well-known/jwks.json"
		}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	metadata, err := client.DiscoverAuthServer(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover auth server: %v", err)
	}

	if metadata.Issuer != "https://as.example.com" {
		t.Errorf("expected issuer https://as.example.com, got %s", metadata.Issuer)
	}
}

func TestDiscoveryClient_FetchJWKS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"keys": [
				{"kty": "EC", "crv": "P-256", "kid": "key-1", "x": "test", "y": "test"}
			]
		}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	jwks, err := client.FetchJWKS(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to fetch JWKS: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "key-1" {
		t.Errorf("expected kid 'key-1', got %s", jwks.Keys[0].Kid)
	}
}

func TestDiscoveryClient_ClearCache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource": "https://resource.example.com"}`))
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	// First call
	_, _ = client.DiscoverResource(ctx, server.URL)

	// Clear cache
	client.ClearCache()

	// Second call should hit server again
	_, _ = client.DiscoverResource(ctx, server.URL)

	if callCount != 2 {
		t.Errorf("expected 2 server calls after cache clear, got %d", callCount)
	}
}

func TestDiscoveryClient_DiscoverResource_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	_, err := client.DiscoverResource(ctx, server.URL)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestDiscoveryClient_DiscoverResourceFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(WellKnownResourcePath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G705 false positive - test code writing JSON, not HTML
		_, _ = w.Write([]byte(`{
			"resource": "https://resource.example.com",
			"person_server_uri": "http://` + r.Host + `"
		}`))
	})
	mux.HandleFunc(WellKnownPersonPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer": "https://ps.example.com",
			"token_endpoint": "https://ps.example.com/token",
			"jwks_uri": "https://ps.example.com/.well-known/jwks.json"
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewDiscoveryClient()
	ctx := context.Background()

	tokenEndpoint, metadata, err := client.DiscoverResourceFlow(ctx, server.URL)
	if err != nil {
		t.Fatalf("failed to discover resource flow: %v", err)
	}

	//nolint:gosec // G101 false positive - tokenEndpoint is a URL, not credentials
	if tokenEndpoint != "https://ps.example.com/token" {
		t.Errorf("expected token endpoint https://ps.example.com/token, got %s", tokenEndpoint)
	}
	if metadata.Resource != "https://resource.example.com" {
		t.Errorf("expected resource, got %s", metadata.Resource)
	}
}

func TestDiscoveryClient_CreateJWKSVerifier(t *testing.T) {
	client := NewDiscoveryClient()

	verifier := client.CreateJWKSVerifier("https://example.com/.well-known/jwks.json")
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestDiscoveryCache_Expiration(t *testing.T) {
	cache := newDiscoveryCache()

	metadata := &ResourceMetadata{Resource: "https://resource.example.com"}
	url := "https://resource.example.com/.well-known/aauth-resource.json"

	// Set with very short TTL
	cache.setResource(url, metadata, 1*time.Millisecond)

	// Should be cached initially
	_, ok := cache.getResource(url)
	if !ok {
		t.Error("expected item to be cached initially")
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Should be expired
	_, ok = cache.getResource(url)
	if ok {
		t.Error("expected item to be expired")
	}
}

func TestDiscoveryCache_Clear(t *testing.T) {
	cache := newDiscoveryCache()

	// Set various items
	cache.setResource("url1", &ResourceMetadata{}, time.Hour)
	cache.setAgentProvider("url2", &AgentProviderMetadata{}, time.Hour)
	cache.setPersonServer("url3", &PersonServerMetadata{}, time.Hour)
	cache.setAuthServer("url4", &AuthServerMetadata{}, time.Hour)
	cache.setJWKS("url5", &JWKS{}, time.Hour)

	// Clear
	cache.clear()

	// All should be empty
	if _, ok := cache.getResource("url1"); ok {
		t.Error("expected cache to be cleared")
	}
	if _, ok := cache.getAgentProvider("url2"); ok {
		t.Error("expected cache to be cleared")
	}
	if _, ok := cache.getPersonServer("url3"); ok {
		t.Error("expected cache to be cleared")
	}
	if _, ok := cache.getAuthServer("url4"); ok {
		t.Error("expected cache to be cleared")
	}
	if _, ok := cache.getJWKS("url5"); ok {
		t.Error("expected cache to be cleared")
	}
}
