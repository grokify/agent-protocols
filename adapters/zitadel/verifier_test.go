package zitadel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/golang-jwt/jwt/v5"
)

func TestNewVerifier(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a mock OIDC server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]string{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := createTestJWKS(privateKey, "test-key-id")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	t.Run("with discovery", func(t *testing.T) {
		verifier, err := NewVerifier(server.URL)
		if err != nil {
			t.Fatalf("NewVerifier failed: %v", err)
		}

		if verifier.Issuer() != server.URL {
			t.Errorf("Issuer() = %q, want %q", verifier.Issuer(), server.URL)
		}

		expectedJWKS := server.URL + "/jwks"
		if verifier.JWKSURL() != expectedJWKS {
			t.Errorf("JWKSURL() = %q, want %q", verifier.JWKSURL(), expectedJWKS)
		}
	})

	t.Run("with static JWKS URL", func(t *testing.T) {
		staticJWKS := "https://example.com/jwks"
		verifier, err := NewVerifier(
			"https://issuer.example.com",
			WithStaticJWKSURL(staticJWKS),
		)
		if err != nil {
			t.Fatalf("NewVerifier failed: %v", err)
		}

		if verifier.JWKSURL() != staticJWKS {
			t.Errorf("JWKSURL() = %q, want %q", verifier.JWKSURL(), staticJWKS)
		}
	})
}

func TestVerifier_VerifyIDJAGAssertion(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	// Create test server
	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	t.Run("valid assertion", func(t *testing.T) {
		// Create a valid assertion
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		tokenString := createSignedToken(t, claims, privateKey, keyID)

		ctx := context.Background()
		assertion, err := verifier.VerifyIDJAGAssertion(ctx, tokenString)
		if err != nil {
			t.Fatalf("VerifyIDJAGAssertion failed: %v", err)
		}

		if assertion.Subject != "user:alice" {
			t.Errorf("Subject = %q, want %q", assertion.Subject, "user:alice")
		}
	})

	t.Run("assertion with actor", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"act": map[string]interface{}{
				"sub": "agent:calendar-bot",
			},
		}
		tokenString := createSignedToken(t, claims, privateKey, keyID)

		ctx := context.Background()
		assertion, err := verifier.VerifyIDJAGAssertion(ctx, tokenString)
		if err != nil {
			t.Fatalf("VerifyIDJAGAssertion failed: %v", err)
		}

		if assertion.Actor == nil {
			t.Fatal("expected Actor to be set")
		}
		if assertion.Actor.Subject != "agent:calendar-bot" {
			t.Errorf("Actor.Subject = %q, want %q", assertion.Actor.Subject, "agent:calendar-bot")
		}
	})

	t.Run("expired assertion", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
		tokenString := createSignedToken(t, claims, privateKey, keyID)

		ctx := context.Background()
		_, err := verifier.VerifyIDJAGAssertion(ctx, tokenString)
		if err == nil {
			t.Error("expected error for expired token")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "https://other-issuer.example.com",
			"sub": "user:alice",
			"aud": server.URL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		tokenString := createSignedToken(t, claims, privateKey, keyID)

		ctx := context.Background()
		_, err := verifier.VerifyIDJAGAssertion(ctx, tokenString)
		if err == nil {
			t.Error("expected error for wrong issuer")
		}
	})
}

func TestVerifier_VerifyAIMSWIT(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	t.Run("valid WIT", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "spiffe://example.com/workload/api",
			"aud": []string{"https://api.example.com"},
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		tokenString := createSignedToken(t, claims, privateKey, keyID)

		ctx := context.Background()
		wit, err := verifier.VerifyAIMSWIT(ctx, tokenString)
		if err != nil {
			t.Fatalf("VerifyAIMSWIT failed: %v", err)
		}

		if wit.Subject != "spiffe://example.com/workload/api" {
			t.Errorf("Subject = %q, want %q", wit.Subject, "spiffe://example.com/workload/api")
		}
	})
}

func TestVerifier_VerifyAAuthAgentToken(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	verifier, err := NewVerifier(server.URL)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	t.Run("valid agent token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": server.URL,
			"sub": "aauth:calendar-bot@example.com",
			"aud": "https://api.example.com",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"cnf": map[string]interface{}{
				"jwk": map[string]interface{}{
					"kty": "RSA",
					"n":   "test",
					"e":   "AQAB",
				},
			},
			"dwk": "https://example.com/.well-known/aauth-agent.json",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = keyID
		token.Header["typ"] = aauth.TokenTypeAgentJWT
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}

		ctx := context.Background()
		agentToken, err := verifier.VerifyAAuthAgentToken(ctx, tokenString)
		if err != nil {
			t.Fatalf("VerifyAAuthAgentToken failed: %v", err)
		}

		if agentToken.Subject != "aauth:calendar-bot@example.com" {
			t.Errorf("Subject = %q, want %q", agentToken.Subject, "aauth:calendar-bot@example.com")
		}
		if agentToken.DWK != "https://example.com/.well-known/aauth-agent.json" {
			t.Errorf("DWK = %q, want %q", agentToken.DWK, "https://example.com/.well-known/aauth-agent.json")
		}
		if agentToken.CNF == nil {
			t.Error("expected CNF to be set")
		}
	})
}

func TestVerifier_AllowedAlgorithms(t *testing.T) {
	privateKey, publicKey := generateTestKeys(t)
	keyID := "test-key-id"

	server := createTestServer(publicKey, keyID)
	defer server.Close()

	// Only allow ES256
	verifier, err := NewVerifier(server.URL, WithAllowedAlgorithms("ES256"))
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	// Create RS256 token (not allowed)
	claims := jwt.MapClaims{
		"iss": server.URL,
		"sub": "user:alice",
		"aud": server.URL,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenString := createSignedToken(t, claims, privateKey, keyID)

	ctx := context.Background()
	_, err = verifier.VerifyIDJAGAssertion(ctx, tokenString)
	if err == nil {
		t.Error("expected error for disallowed algorithm")
	}
}

// Helper functions

func generateTestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func createTestServer(publicKey *rsa.PublicKey, keyID string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		config := map[string]string{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := createTestJWKS(publicKey, keyID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
	return httptest.NewServer(mux)
}

func createTestJWKS(key interface{}, keyID string) JWKS {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return createRSAJWKS(&k.PublicKey, keyID)
	case *rsa.PublicKey:
		return createRSAJWKS(k, keyID)
	default:
		return JWKS{}
	}
}

func createRSAJWKS(pubKey *rsa.PublicKey, keyID string) JWKS {
	return JWKS{
		Keys: []JWK{
			{
				KeyType:   "RSA",
				KeyID:     keyID,
				Algorithm: "RS256",
				Use:       "sig",
				N:         base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
				E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
			},
		},
	}
}

func createSignedToken(t *testing.T, claims jwt.MapClaims, privateKey *rsa.PrivateKey, keyID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}
