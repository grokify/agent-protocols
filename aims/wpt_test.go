package aims

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"
)

func TestNewWPT(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	if wpt.Issuer != "spiffe://example.com/agent/test" {
		t.Errorf("Issuer = %q, want %q", wpt.Issuer, "spiffe://example.com/agent/test")
	}
	if wpt.Audience != "https://api.example.com" {
		t.Errorf("Audience = %q, want %q", wpt.Audience, "https://api.example.com")
	}
	if wpt.HTM != "POST" {
		t.Errorf("HTM = %q, want %q", wpt.HTM, "POST")
	}
	if wpt.HTU != "/api/v1/events" {
		t.Errorf("HTU = %q, want %q", wpt.HTU, "/api/v1/events")
	}
	if wpt.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
	if wpt.JWTID == "" {
		t.Error("JWTID should be auto-generated")
	}
}

func TestNewWPT_WithOptions(t *testing.T) {
	expiry := time.Now().Add(10 * time.Minute)
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"GET",
		"/api/v1/data",
		WithWPTNonce("server-nonce-123"),
		WithWPTJTI("custom-jti"),
		WithWPTExpiry(expiry),
		WithWPTAccessToken("access-token-value"),
	)

	if wpt.Nonce != "server-nonce-123" {
		t.Errorf("Nonce = %q, want %q", wpt.Nonce, "server-nonce-123")
	}
	if wpt.JWTID != "custom-jti" {
		t.Errorf("JWTID = %q, want %q", wpt.JWTID, "custom-jti")
	}
	if !wpt.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", wpt.Expiry, expiry)
	}
	if wpt.ATH == "" {
		t.Error("ATH should be set when access token is bound")
	}
}

func TestNewWPTFromWIT(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	wit := NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)

	wpt := NewWPTFromWIT(wit, "https://api.example.com", "POST", "/api/v1/action")

	if wpt.Issuer != wit.Subject {
		t.Errorf("Issuer = %q, want %q", wpt.Issuer, wit.Subject)
	}
}

func TestNewWPTForRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/api/v1/events?filter=active", nil)

	wpt := NewWPTForRequest("spiffe://example.com/agent/test", "https://api.example.com", req)

	if wpt.HTM != "POST" {
		t.Errorf("HTM = %q, want %q", wpt.HTM, "POST")
	}
	if wpt.HTU != "/api/v1/events?filter=active" {
		t.Errorf("HTU = %q, want %q", wpt.HTU, "/api/v1/events?filter=active")
	}
}

func TestWIMSEProofToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		wpt     *WIMSEProofToken
		wantErr error
	}{
		{
			name: "valid",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
				Expiry:   time.Now().Add(5 * time.Minute),
			},
			wantErr: nil,
		},
		{
			name: "missing_issuer",
			wpt: &WIMSEProofToken{
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
			},
			wantErr: ErrWPTMissingIssuer,
		},
		{
			name: "missing_audience",
			wpt: &WIMSEProofToken{
				Issuer: "spiffe://example.com/agent/test",
				HTM:    "POST",
				HTU:    "/api/v1/events",
			},
			wantErr: ErrWPTMissingAudience,
		},
		{
			name: "missing_htm",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTU:      "/api/v1/events",
			},
			wantErr: ErrWPTMissingHTM,
		},
		{
			name: "missing_htu",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
			},
			wantErr: ErrWPTMissingHTU,
		},
		{
			name: "expired",
			wpt: &WIMSEProofToken{
				Issuer:   "spiffe://example.com/agent/test",
				Audience: "https://api.example.com",
				HTM:      "POST",
				HTU:      "/api/v1/events",
				Expiry:   time.Now().Add(-1 * time.Minute),
			},
			wantErr: ErrWPTExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wpt.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWIMSEProofToken_Sign(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	signed, err := wpt.Sign(privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if signed == "" {
		t.Error("Sign() returned empty string")
	}

	// JWT should have 3 parts
	parts := 0
	for i := range signed {
		if signed[i] == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("Signed JWT should have 3 parts (2 dots), got %d dots", parts)
	}
}

func TestWIMSEProofToken_BindToRequest(t *testing.T) {
	wpt := NewWPT(
		"spiffe://example.com/agent/test",
		"https://api.example.com",
		"POST",
		"/api/v1/events",
	)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/api/v1/events", nil)
	err = wpt.BindToRequest(req, privateKey, "test-key-1")
	if err != nil {
		t.Fatalf("BindToRequest() error = %v", err)
	}

	header := req.Header.Get(HeaderWPT)
	if header == "" {
		t.Errorf("Request should have %s header", HeaderWPT)
	}
}

func TestWIMSEProofToken_MatchesRequest(t *testing.T) {
	tests := []struct {
		name   string
		wpt    *WIMSEProofToken
		method string
		uri    string
		want   bool
	}{
		{
			name: "exact_match",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "POST",
			uri:    "/api/v1/events",
			want:   true,
		},
		{
			name: "method_case_insensitive",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "post",
			uri:    "/api/v1/events",
			want:   true,
		},
		{
			name: "method_mismatch",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "GET",
			uri:    "/api/v1/events",
			want:   false,
		},
		{
			name: "uri_mismatch",
			wpt: &WIMSEProofToken{
				HTM: "POST",
				HTU: "/api/v1/events",
			},
			method: "POST",
			uri:    "/api/v1/other",
			want:   false,
		},
		{
			name: "with_query_string",
			wpt: &WIMSEProofToken{
				HTM: "GET",
				HTU: "/api/v1/data?filter=active",
			},
			method: "GET",
			uri:    "/api/v1/data?filter=active",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "https://api.example.com"+tt.uri, nil)
			if got := tt.wpt.MatchesRequest(req); got != tt.want {
				t.Errorf("MatchesRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWIMSEProofToken_IsExpired(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"future", time.Now().Add(5 * time.Minute), false},
		{"past", time.Now().Add(-1 * time.Minute), true},
		{"zero", time.Time{}, false}, // No expiry set
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wpt := &WIMSEProofToken{Expiry: tt.expiry}
			if got := wpt.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWPTFromHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	req.Header.Set(HeaderWPT, "signed-wpt-value")

	got := WPTFromHeader(req)
	if got != "signed-wpt-value" {
		t.Errorf("WPTFromHeader() = %q, want %q", got, "signed-wpt-value")
	}
}

func Test_hashAccessToken(t *testing.T) {
	hash1 := hashAccessToken("access-token-1")
	hash2 := hashAccessToken("access-token-1")
	hash3 := hashAccessToken("access-token-2")

	if hash1 == "" {
		t.Error("hashAccessToken() returned empty string")
	}
	if hash1 != hash2 {
		t.Error("Same token should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}
}
