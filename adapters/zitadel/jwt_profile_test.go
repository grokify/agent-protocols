package zitadel

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockAssertionSigner implements AssertionSigner for testing.
type mockAssertionSigner struct {
	assertion string
	err       error
}

func (m *mockAssertionSigner) SignAssertion(audience []string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.assertion, nil
}

func TestNewJWTProfileSource(t *testing.T) {
	// Create a mock discovery endpoint
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
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

	signer := &mockAssertionSigner{assertion: "test-assertion"}

	t.Run("with discovery", func(t *testing.T) {
		source, err := NewJWTProfileSource(discoveryServer.URL, "client-id", signer)
		if err != nil {
			t.Fatalf("NewJWTProfileSource failed: %v", err)
		}

		if source.issuer != discoveryServer.URL {
			t.Errorf("issuer = %q, want %q", source.issuer, discoveryServer.URL)
		}
	})

	t.Run("with static endpoint", func(t *testing.T) {
		staticURL := "https://example.com/token"
		source, err := NewJWTProfileSource(
			"https://issuer.example.com",
			"client-id",
			signer,
			WithJWTProfileTokenEndpoint(staticURL),
		)
		if err != nil {
			t.Fatalf("NewJWTProfileSource failed: %v", err)
		}

		if source.tokenURL != staticURL {
			t.Errorf("tokenURL = %q, want %q", source.tokenURL, staticURL)
		}
	})
}

func TestJWTProfileSource_Token(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}

		// Verify grant type
		grantType := r.PostForm.Get("grant_type")
		if grantType != GrantTypeJWTBearer {
			t.Errorf("grant_type = %q, want %q", grantType, GrantTypeJWTBearer)
		}

		// Verify assertion
		assertion := r.PostForm.Get("assertion")
		if assertion == "" {
			t.Error("assertion is empty")
		}

		// Return success response
		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	signer := &mockAssertionSigner{assertion: "test-assertion"}
	source, err := NewJWTProfileSource(
		"https://issuer.example.com",
		"client-id",
		signer,
		WithJWTProfileTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewJWTProfileSource failed: %v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
}

func TestJWTProfileSource_TokenCaching(t *testing.T) {
	callCount := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	signer := &mockAssertionSigner{assertion: "test-assertion"}
	source, err := NewJWTProfileSource(
		"https://issuer.example.com",
		"client-id",
		signer,
		WithJWTProfileTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewJWTProfileSource failed: %v", err)
	}

	// First call
	_, err = source.Token()
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	// Second call should use cache
	_, err = source.Token()
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	// Should only have made one HTTP call
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}

	// Invalidate cache
	source.Invalidate()

	// Third call should fetch new token
	_, err = source.Token()
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	if callCount != 2 {
		t.Errorf("callCount = %d, want 2", callCount)
	}
}

func TestJWTProfileSource_WithScopes(t *testing.T) {
	var receivedScope string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		receivedScope = r.PostForm.Get("scope")

		resp := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	signer := &mockAssertionSigner{assertion: "test-assertion"}
	source, err := NewJWTProfileSource(
		"https://issuer.example.com",
		"client-id",
		signer,
		WithJWTProfileTokenEndpoint(tokenServer.URL),
		WithJWTProfileScopes("openid", "profile", "email"),
	)
	if err != nil {
		t.Fatalf("NewJWTProfileSource failed: %v", err)
	}

	_, err = source.Token()
	if err != nil {
		t.Fatalf("Token failed: %v", err)
	}

	expected := "openid profile email"
	if receivedScope != expected {
		t.Errorf("scope = %q, want %q", receivedScope, expected)
	}
}

func TestJWTProfileSource_ErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenErrorResponse{
			Error:            ErrorInvalidGrant,
			ErrorDescription: "Invalid assertion",
		})
	}))
	defer tokenServer.Close()

	signer := &mockAssertionSigner{assertion: "invalid-assertion"}
	source, err := NewJWTProfileSource(
		"https://issuer.example.com",
		"client-id",
		signer,
		WithJWTProfileTokenEndpoint(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("NewJWTProfileSource failed: %v", err)
	}

	_, err = source.Token()
	if err == nil {
		t.Error("expected error for invalid assertion")
	}
}

func TestIDJAGAssertionSigner(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer := NewIDJAGAssertionSigner(
		"https://issuer.example.com",
		"test-subject",
		jwt.SigningMethodRS256,
		privateKey,
		"test-key-id",
		WithIDJAGSignerTTL(10*time.Minute),
	)

	assertion, err := signer.SignAssertion([]string{"https://audience.example.com"})
	if err != nil {
		t.Fatalf("SignAssertion failed: %v", err)
	}

	// Parse and verify the assertion
	parser := jwt.NewParser()
	token, err := parser.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to get claims")
	}

	if iss := claims["iss"].(string); iss != "https://issuer.example.com" {
		t.Errorf("iss = %q, want %q", iss, "https://issuer.example.com")
	}
	if sub := claims["sub"].(string); sub != "test-subject" {
		t.Errorf("sub = %q, want %q", sub, "test-subject")
	}
	if kid := token.Header["kid"].(string); kid != "test-key-id" {
		t.Errorf("kid = %q, want %q", kid, "test-key-id")
	}
}
