//nolint:gosec // G117: Test file uses mock tokens with predictable values
package zitadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewTokenExchanger(t *testing.T) {
	// Create a mock OIDC discovery endpoint
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		config := map[string]string{
			"issuer":         r.Host,
			"token_endpoint": "http://" + r.Host + "/oauth/v2/token",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	}))
	defer discoveryServer.Close()

	t.Run("with discovery", func(t *testing.T) {
		exchanger, err := NewTokenExchanger(discoveryServer.URL)
		if err != nil {
			t.Fatalf("NewTokenExchanger failed: %v", err)
		}

		if exchanger.Issuer() != discoveryServer.URL {
			t.Errorf("issuer = %q, want %q", exchanger.Issuer(), discoveryServer.URL)
		}

		expectedTokenURL := discoveryServer.URL + "/oauth/v2/token"
		if exchanger.TokenURL() != expectedTokenURL {
			t.Errorf("tokenURL = %q, want %q", exchanger.TokenURL(), expectedTokenURL)
		}
	})

	t.Run("with static token endpoint", func(t *testing.T) {
		staticURL := "https://example.com/token"
		exchanger, err := NewTokenExchanger(
			"https://issuer.example.com",
			WithStaticTokenEndpoint(staticURL),
		)
		if err != nil {
			t.Fatalf("NewTokenExchanger failed: %v", err)
		}

		if exchanger.TokenURL() != staticURL {
			t.Errorf("tokenURL = %q, want %q", exchanger.TokenURL(), staticURL)
		}
	})

	t.Run("discovery failure", func(t *testing.T) {
		_, err := NewTokenExchanger(
			"http://invalid.localhost:9999",
			WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}),
		)
		if err == nil {
			t.Error("expected error for invalid issuer")
		}
	})
}

func TestTokenExchanger_ExchangeAssertion(t *testing.T) {
	// Create a mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		// Verify grant type
		grantType := r.PostForm.Get("grant_type")
		if grantType != GrantTypeTokenExchange {
			t.Errorf("grant_type = %q, want %q", grantType, GrantTypeTokenExchange)
		}

		// Verify subject token
		subjectToken := r.PostForm.Get("subject_token")
		if subjectToken == "" {
			t.Error("subject_token is empty")
		}

		subjectTokenType := r.PostForm.Get("subject_token_type")
		if subjectTokenType != TokenTypeJWT {
			t.Errorf("subject_token_type = %q, want %q", subjectTokenType, TokenTypeJWT)
		}

		// Return success response
		resp := TokenResponse{
			AccessToken:     "test-access-token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			IssuedTokenType: TokenTypeAccessToken,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	exchanger, err := NewTokenExchanger(
		"https://issuer.example.com",
		WithStaticTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewTokenExchanger failed: %v", err)
	}

	ctx := context.Background()
	resp, err := exchanger.ExchangeAssertion(ctx, "test-assertion")
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}

	if resp.AccessToken != "test-access-token" {
		t.Errorf("access_token = %q, want %q", resp.AccessToken, "test-access-token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", resp.TokenType, "Bearer")
	}
}

func TestTokenExchanger_ExchangeWithActor(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		// Verify actor token is present
		actorToken := r.PostForm.Get("actor_token")
		if actorToken == "" {
			t.Error("actor_token is empty")
		}

		actorTokenType := r.PostForm.Get("actor_token_type")
		if actorTokenType != TokenTypeJWT {
			t.Errorf("actor_token_type = %q, want %q", actorTokenType, TokenTypeJWT)
		}

		resp := TokenResponse{
			AccessToken:     "delegated-access-token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			IssuedTokenType: TokenTypeAccessToken,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	exchanger, err := NewTokenExchanger(
		"https://issuer.example.com",
		WithStaticTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewTokenExchanger failed: %v", err)
	}

	ctx := context.Background()
	resp, err := exchanger.ExchangeWithActor(ctx, "subject-assertion", "actor-assertion")
	if err != nil {
		t.Fatalf("ExchangeWithActor failed: %v", err)
	}

	if resp.AccessToken != "delegated-access-token" {
		t.Errorf("access_token = %q, want %q", resp.AccessToken, "delegated-access-token")
	}
}

func TestTokenExchanger_WithOptions(t *testing.T) {
	var receivedScope, receivedAudience, receivedResource string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		receivedScope = r.PostForm.Get("scope")
		receivedAudience = r.PostForm.Get("audience")
		receivedResource = r.PostForm.Get("resource")

		resp := TokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			Scope:       receivedScope,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	exchanger, err := NewTokenExchanger(
		"https://issuer.example.com",
		WithStaticTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewTokenExchanger failed: %v", err)
	}

	ctx := context.Background()
	resp, err := exchanger.ExchangeAssertion(ctx, "test-assertion",
		WithScope("openid profile"),
		WithAudience("https://api.example.com"),
		WithResource("https://resource.example.com"),
	)
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}

	if receivedScope != "openid profile" {
		t.Errorf("scope = %q, want %q", receivedScope, "openid profile")
	}
	if receivedAudience != "https://api.example.com" {
		t.Errorf("audience = %q, want %q", receivedAudience, "https://api.example.com")
	}
	if receivedResource != "https://resource.example.com" {
		t.Errorf("resource = %q, want %q", receivedResource, "https://resource.example.com")
	}
	if resp.Scope != "openid profile" {
		t.Errorf("response scope = %q, want %q", resp.Scope, "openid profile")
	}
}

func TestTokenExchanger_WithClientCredentials(t *testing.T) {
	var receivedAuth string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")

		resp := TokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	exchanger, err := NewTokenExchanger(
		"https://issuer.example.com",
		WithStaticTokenEndpoint(tokenServer.URL),
		WithClientCredentials("client-id", "client-secret"),
	)
	if err != nil {
		t.Fatalf("NewTokenExchanger failed: %v", err)
	}

	ctx := context.Background()
	_, err = exchanger.ExchangeAssertion(ctx, "test-assertion")
	if err != nil {
		t.Fatalf("ExchangeAssertion failed: %v", err)
	}

	// Should use Basic auth
	if receivedAuth == "" {
		t.Error("expected Authorization header")
	}
	if !hasPrefix(receivedAuth, "Basic ") {
		t.Errorf("Authorization = %q, want Basic auth", receivedAuth)
	}
}

func TestTokenExchanger_ErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenErrorResponse{
			Error:            ErrorInvalidGrant,
			ErrorDescription: "The assertion is invalid",
		})
	}))
	defer tokenServer.Close()

	exchanger, err := NewTokenExchanger(
		"https://issuer.example.com",
		WithStaticTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewTokenExchanger failed: %v", err)
	}

	ctx := context.Background()
	_, err = exchanger.ExchangeAssertion(ctx, "invalid-assertion")
	if err == nil {
		t.Error("expected error for invalid assertion")
	}

	// Error should contain the error code
	if !containsString(err.Error(), ErrorInvalidGrant) {
		t.Errorf("error = %v, want to contain %q", err, ErrorInvalidGrant)
	}
}

// Helper functions for testing
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
