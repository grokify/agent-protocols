package zitadel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMiddleware_Handler(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{
			TokenType: TokenTypeIDJAG,
		})

		// Create test token
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := createSignedToken(t, claims, privateKey, keyID)

		// Create test request
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Create handler that checks context
		var contextAssertion bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertion, ok := IDJAGAssertionFromContext(r.Context())
			contextAssertion = ok && assertion != nil && assertion.Subject == "user:alice"
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !contextAssertion {
			t.Error("assertion not found in context")
		}
	})

	t.Run("missing token", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{})

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("allow anonymous", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{
			AllowAnonymous: true,
		})

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		rr := httptest.NewRecorder()

		handlerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if !handlerCalled {
			t.Error("handler was not called")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{})

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{})

		// Create expired token
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
		token := createSignedToken(t, claims, privateKey, keyID)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})
}

func TestMiddleware_RequiredAudience(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	t.Run("matching audience", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{
			TokenType:        TokenTypeIDJAG,
			RequiredAudience: "https://api.example.com",
		})

		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": "https://api.example.com",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := createSignedToken(t, claims, privateKey, keyID)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		middleware := NewMiddleware(verifier, MiddlewareOptions{
			TokenType:        TokenTypeIDJAG,
			RequiredAudience: "https://api.example.com",
		})

		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": "https://other.example.com",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := createSignedToken(t, claims, privateKey, keyID)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		})

		middleware.Handler(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})
}

func TestMiddleware_CustomErrorHandler(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	_ = privateKey // suppress unused warning
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	customHandlerCalled := false
	middleware := NewMiddleware(verifier, MiddlewareOptions{
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			customHandlerCalled = true
			w.WriteHeader(http.StatusForbidden)
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	middleware.Handler(handler).ServeHTTP(rr, req)

	if !customHandlerCalled {
		t.Error("custom error handler was not called")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestContextAccessors(t *testing.T) {
	t.Run("IDJAGAssertionFromContext", func(t *testing.T) {
		ctx := context.Background()

		// Without value
		_, ok := IDJAGAssertionFromContext(ctx)
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})

	t.Run("AIMSWITFromContext", func(t *testing.T) {
		ctx := context.Background()

		// Without value
		_, ok := AIMSWITFromContext(ctx)
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})

	t.Run("AAuthTokenFromContext", func(t *testing.T) {
		ctx := context.Background()

		// Without value
		_, ok := AAuthTokenFromContext(ctx)
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})

	t.Run("TokenTypeFromContext", func(t *testing.T) {
		ctx := context.Background()

		// Without value
		_, ok := TokenTypeFromContext(ctx)
		if ok {
			t.Error("expected ok=false for empty context")
		}
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer abc123", "abc123"},
		{"no bearer prefix", "abc123", ""},
		{"empty", "", ""},
		{"lowercase bearer", "bearer abc123", ""},
		{"with extra spaces", "Bearer  abc123", " abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			result := extractBearerToken(req)
			if result != tt.expected {
				t.Errorf("extractBearerToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestRequireMiddlewareFactories(t *testing.T) {
	// Generate test keys for test server
	_, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("RequireIDJAG", func(t *testing.T) {
		// Just verify it returns a middleware with correct token type
		middleware := RequireIDJAG(nil, MiddlewareOptions{})
		if middleware.opts.TokenType != TokenTypeIDJAG {
			t.Errorf("TokenType = %v, want %v", middleware.opts.TokenType, TokenTypeIDJAG)
		}
	})

	t.Run("RequireAIMS", func(t *testing.T) {
		middleware := RequireAIMS(nil, MiddlewareOptions{})
		if middleware.opts.TokenType != TokenTypeAIMS {
			t.Errorf("TokenType = %v, want %v", middleware.opts.TokenType, TokenTypeAIMS)
		}
	})

	t.Run("RequireAAuth", func(t *testing.T) {
		middleware := RequireAAuth(nil, MiddlewareOptions{})
		if middleware.opts.TokenType != TokenTypeAAuth {
			t.Errorf("TokenType = %v, want %v", middleware.opts.TokenType, TokenTypeAAuth)
		}
	})
}
