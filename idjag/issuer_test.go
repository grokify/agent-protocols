package idjag_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aistandardsio/agent-protocols/idjag"
)

func TestIdPAuthorizationServer_IssueIDJAG(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	idp := idjag.NewIdPAuthorizationServer("https://idp.example.com", jwt.SigningMethodRS256, privateKey, "key-1")

	// Create a mock subject token (simulating user's ID token)
	subjectToken := createTestIDToken(t, privateKey, "user:alice")

	tests := []struct {
		name    string
		req     *idjag.IDJAGRequest
		wantErr bool
	}{
		{
			name: "valid ID-JAG request",
			req: &idjag.IDJAGRequest{
				SubjectToken:     subjectToken,
				SubjectTokenType: idjag.TokenTypeIDToken,
				Audience:         "https://api.example.com",
				ClientID:         "agent-client-123",
				Scope:            "read write",
			},
			wantErr: false,
		},
		{
			name: "missing subject token",
			req: &idjag.IDJAGRequest{
				SubjectTokenType: idjag.TokenTypeIDToken,
				Audience:         "https://api.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing audience",
			req: &idjag.IDJAGRequest{
				SubjectToken:     subjectToken,
				SubjectTokenType: idjag.TokenTypeIDToken,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := idp.IssueIDJAG(context.Background(), tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssueIDJAG() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if resp.AccessToken == "" {
					t.Error("expected AccessToken to be non-empty")
				}
				if resp.IssuedTokenType != idjag.TokenTypeIDJAG {
					t.Errorf("IssuedTokenType = %s, want %s", resp.IssuedTokenType, idjag.TokenTypeIDJAG)
				}
				if resp.TokenType != "N_A" {
					t.Errorf("TokenType = %s, want N_A", resp.TokenType)
				}

				// Verify the ID-JAG can be parsed and has correct claims
				parsed, err := idjag.ParseAssertion(resp.AccessToken)
				if err != nil {
					t.Errorf("failed to parse ID-JAG: %v", err)
				}
				if parsed.Issuer != "https://idp.example.com" {
					t.Errorf("Issuer = %s, want https://idp.example.com", parsed.Issuer)
				}
				if parsed.ClientID != tt.req.ClientID {
					t.Errorf("ClientID = %s, want %s", parsed.ClientID, tt.req.ClientID)
				}
			}
		})
	}
}

func TestIdPAuthorizationServer_ServeHTTP(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	idp := idjag.NewIdPAuthorizationServer("https://idp.example.com", jwt.SigningMethodRS256, privateKey, "key-1")
	subjectToken := createTestIDToken(t, privateKey, "user:bob")

	tests := []struct {
		name       string
		method     string
		formData   url.Values
		wantStatus int
	}{
		{
			name:   "valid token exchange request",
			method: http.MethodPost,
			formData: url.Values{
				"grant_type":           {idjag.GrantTypeTokenExchange},
				"requested_token_type": {idjag.TokenTypeIDJAG},
				"subject_token":        {subjectToken},
				"subject_token_type":   {idjag.TokenTypeIDToken},
				"audience":             {"https://api.example.com"},
				"client_id":            {"agent-123"},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			formData:   url.Values{},
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:   "wrong grant type",
			method: http.MethodPost,
			formData: url.Values{
				"grant_type": {"client_credentials"},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "wrong requested token type",
			method: http.MethodPost,
			formData: url.Values{
				"grant_type":           {idjag.GrantTypeTokenExchange},
				"requested_token_type": {idjag.TokenTypeAccessToken},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "missing subject token",
			method: http.MethodPost,
			formData: url.Values{
				"grant_type":           {idjag.GrantTypeTokenExchange},
				"requested_token_type": {idjag.TokenTypeIDJAG},
				"subject_token_type":   {idjag.TokenTypeIDToken},
				"audience":             {"https://api.example.com"},
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/token", strings.NewReader(tt.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			idp.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantStatus == http.StatusOK {
				var resp idjag.IDJAGResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Errorf("failed to decode response: %v", err)
				}
				if resp.AccessToken == "" {
					t.Error("expected AccessToken to be non-empty")
				}
				if resp.IssuedTokenType != idjag.TokenTypeIDJAG {
					t.Errorf("IssuedTokenType = %s, want %s", resp.IssuedTokenType, idjag.TokenTypeIDJAG)
				}
			}
		})
	}
}

func TestIdPAuthorizationServer_DelegationPolicy(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	idp := idjag.NewIdPAuthorizationServer("https://idp.example.com", jwt.SigningMethodRS256, privateKey, "key-1")

	// Add policy that denies certain clients
	idp.DelegationPolicy = func(ctx context.Context, req *idjag.IDJAGRequest) error {
		if req.ClientID == "untrusted-client" {
			return jwt.ErrTokenMalformed // Using existing error type
		}
		return nil
	}

	subjectToken := createTestIDToken(t, privateKey, "user:alice")

	tests := []struct {
		name     string
		clientID string
		wantErr  bool
	}{
		{
			name:     "authorized client",
			clientID: "trusted-client",
			wantErr:  false,
		},
		{
			name:     "unauthorized client",
			clientID: "untrusted-client",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &idjag.IDJAGRequest{
				SubjectToken:     subjectToken,
				SubjectTokenType: idjag.TokenTypeIDToken,
				Audience:         "https://api.example.com",
				ClientID:         tt.clientID,
			}
			_, err := idp.IssueIDJAG(context.Background(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssueIDJAG() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIDJAGClient(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	idp := idjag.NewIdPAuthorizationServer("https://idp.example.com", jwt.SigningMethodRS256, privateKey, "key-1")
	server := httptest.NewServer(idp)
	defer server.Close()

	subjectToken := createTestIDToken(t, privateKey, "user:charlie")
	client := idjag.NewIDJAGClient(server.URL)

	t.Run("successful ID-JAG request", func(t *testing.T) {
		resp, err := client.RequestIDJAG(context.Background(), &idjag.IDJAGRequest{
			SubjectToken:     subjectToken,
			SubjectTokenType: idjag.TokenTypeIDToken,
			Audience:         "https://api.example.com",
			ClientID:         "agent-123",
			Scope:            "read",
		})
		if err != nil {
			t.Fatalf("RequestIDJAG() error = %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected AccessToken to be non-empty")
		}
		if resp.IssuedTokenType != idjag.TokenTypeIDJAG {
			t.Errorf("IssuedTokenType = %s, want %s", resp.IssuedTokenType, idjag.TokenTypeIDJAG)
		}
	})

	t.Run("error response", func(t *testing.T) {
		_, err := client.RequestIDJAG(context.Background(), &idjag.IDJAGRequest{
			// Missing required fields
			SubjectTokenType: idjag.TokenTypeIDToken,
		})
		if err == nil {
			t.Error("expected error for invalid request")
		}
	})
}

// Test that ID-JAG has correct typ header
func TestIDJAG_TypHeader(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create an assertion and sign it
	assertion := idjag.NewAssertion("https://idp.example.com", "user:alice", []string{"https://api.example.com"}, 5*time.Minute)
	assertion.ClientID = "agent-123"

	signedJWT, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")
	if err != nil {
		t.Fatalf("failed to sign assertion: %v", err)
	}

	// Parse the JWT to check the header
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	typ, ok := token.Header["typ"]
	if !ok {
		t.Error("missing typ header")
	}
	if typ != idjag.JWTTypeIDJAG {
		t.Errorf("typ = %s, want %s", typ, idjag.JWTTypeIDJAG)
	}
}

// Test that ID-JAG has required claims per IETF draft
func TestIDJAG_RequiredClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	assertion := idjag.NewAssertion("https://idp.example.com", "user:alice", []string{"https://api.example.com"}, 5*time.Minute)
	assertion.ClientID = "agent-123"

	signedJWT, err := assertion.Sign(jwt.SigningMethodRS256, privateKey, "key-1")
	if err != nil {
		t.Fatalf("failed to sign assertion: %v", err)
	}

	parsed, err := idjag.ParseAssertion(signedJWT)
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}

	// Check required claims per IETF draft
	if parsed.Issuer == "" {
		t.Error("missing iss claim")
	}
	if parsed.Subject == "" {
		t.Error("missing sub claim")
	}
	if len(parsed.Audience) == 0 {
		t.Error("missing aud claim")
	}
	if parsed.ClientID == "" {
		t.Error("missing client_id claim")
	}
	if parsed.JWTID == "" {
		t.Error("missing jti claim")
	}
	if parsed.ExpiresAt.IsZero() {
		t.Error("missing exp claim")
	}
	if parsed.IssuedAt.IsZero() {
		t.Error("missing iat claim")
	}
}

// Legacy API backward compatibility tests
func TestLegacyAPI_CreateDelegatedAssertion(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	issuer := idjag.NewIssuerService("https://idp.example.com", jwt.SigningMethodRS256, privateKey, "key-1")

	resp, err := issuer.CreateDelegatedAssertion(context.Background(), &idjag.DelegationRequest{
		Subject:  "user:alice",
		AgentID:  "agent:calendar-bot",
		Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("CreateDelegatedAssertion() error = %v", err)
	}

	if resp.Assertion == "" {
		t.Error("expected Assertion to be non-empty")
	}
	if resp.Subject != "user:alice" {
		t.Errorf("Subject = %s, want user:alice", resp.Subject)
	}
	if resp.Actor != "agent:calendar-bot" {
		t.Errorf("Actor = %s, want agent:calendar-bot", resp.Actor)
	}

	// Verify the assertion has act claim
	parsed, err := idjag.ParseAssertion(resp.Assertion)
	if err != nil {
		t.Fatalf("failed to parse assertion: %v", err)
	}
	if !parsed.IsDelegated() {
		t.Error("expected assertion to be delegated")
	}
	if parsed.Actor.Subject != "agent:calendar-bot" {
		t.Errorf("Actor.Subject = %s, want agent:calendar-bot", parsed.Actor.Subject)
	}
}

// Helper to create a test ID token
func createTestIDToken(t *testing.T, privateKey *rsa.PrivateKey, subject string) string {
	t.Helper()

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://idp.example.com",
		"sub": subject,
		"aud": "https://idp.example.com",
		"exp": jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key-1"
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign test ID token: %v", err)
	}
	return signedToken
}
