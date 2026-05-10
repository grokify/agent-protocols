package aauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_MissingSignature(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithIdentityOnlyMode(true),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	handler := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	// Check WWW-Authenticate header
	wwwAuth := rec.Header().Get(HeaderWWWAuthenticate)
	if wwwAuth == "" {
		t.Error("expected WWW-Authenticate header to be set")
	}
}

func TestMiddlewareFunc(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithIdentityOnlyMode(true),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	handler := rs.MiddlewareFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should fail due to missing signature
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestExtractSignatureKeyToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		want    string
		wantErr bool
	}{
		{
			name:   "valid",
			header: "scheme=jwt eyJhbGciOiJFUzI1NiJ9.test.signature",
			want:   "eyJhbGciOiJFUzI1NiJ9.test.signature",
		},
		{
			name:    "invalid format",
			header:  "Bearer token",
			wantErr: true,
		},
		{
			name:    "empty",
			header:  "",
			wantErr: true,
		},
		{
			name:    "missing token",
			header:  "scheme=jwt",
			wantErr: true, // "scheme=jwt" without trailing space and token is invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractSignatureKeyToken(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("extractSignatureKeyToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name      string
		scopeStr  string
		required  string
		wantMatch bool
	}{
		{
			name:      "single match",
			scopeStr:  "read",
			required:  "read",
			wantMatch: true,
		},
		{
			name:      "multiple scopes match",
			scopeStr:  "read write delete",
			required:  "write",
			wantMatch: true,
		},
		{
			name:      "no match",
			scopeStr:  "read write",
			required:  "admin",
			wantMatch: false,
		},
		{
			name:      "partial match not allowed",
			scopeStr:  "readonly",
			required:  "read",
			wantMatch: false,
		},
		{
			name:      "empty scope string",
			scopeStr:  "",
			required:  "read",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasScope(tt.scopeStr, tt.required)
			if got != tt.wantMatch {
				t.Errorf("hasScope(%q, %q) = %v, want %v", tt.scopeStr, tt.required, got, tt.wantMatch)
			}
		})
	}
}

func TestVerifyHandler(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	rs, err := NewResourceServer(
		"https://resource.example.com",
		privateKey,
		"test-key-1",
		WithIdentityOnlyMode(true),
	)
	if err != nil {
		t.Fatalf("failed to create resource server: %v", err)
	}

	handler := VerifyHandler(rs, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should fail due to missing signature
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestResourceServerVerifyCNFMatch(t *testing.T) {
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

	// Create two CNF claims with the same embedded JWK
	cnf1, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("failed to create CNF: %v", err)
	}
	cnf2, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("failed to create CNF: %v", err)
	}

	match, err := rs.verifyCNFMatch(cnf1, cnf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected CNF claims to match")
	}
}

func TestResourceServerVerifyCNFMatch_References(t *testing.T) {
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

	// Create two CNF claims with the same JKU and kid reference
	// (IsReference() requires JKU to be set)
	cnf1 := NewCNFWithJKU("https://keys.example.com/jwks.json", "same-key-id")
	cnf2 := NewCNFWithJKU("https://keys.example.com/jwks.json", "same-key-id")

	match, err := rs.verifyCNFMatch(cnf1, cnf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !match {
		t.Error("expected CNF claims to match")
	}

	// Different kid should not match
	cnf3 := NewCNFWithJKU("https://keys.example.com/jwks.json", "different-key-id")
	match, err = rs.verifyCNFMatch(cnf1, cnf3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected CNF claims to not match")
	}
}

func TestResourceServerVerifyCNFMatch_MixedTypes(t *testing.T) {
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

	// One embedded, one reference - should not match
	cnf1, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("failed to create CNF: %v", err)
	}
	cnf2 := &CNF{Kid: "test-key"}

	match, err := rs.verifyCNFMatch(cnf1, cnf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match {
		t.Error("expected mixed CNF types to not match")
	}
}
