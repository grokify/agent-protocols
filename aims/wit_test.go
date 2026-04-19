package aims

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestNewWIT(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	audience := []string{"https://api.example.com"}

	wit := NewWIT(spiffeID, audience, 1*time.Hour)

	if wit.Issuer != "https://example.com" {
		t.Errorf("Issuer = %q, want %q", wit.Issuer, "https://example.com")
	}
	if wit.Subject != spiffeID.String() {
		t.Errorf("Subject = %q, want %q", wit.Subject, spiffeID.String())
	}
	if len(wit.Audience) != 1 || wit.Audience[0] != audience[0] {
		t.Errorf("Audience = %v, want %v", wit.Audience, audience)
	}
	if wit.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
	if wit.Expiry.Before(wit.IssuedAt) {
		t.Error("Expiry should be after IssuedAt")
	}
}

func TestNewWIT_WithOptions(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	audience := []string{"https://api.example.com"}
	nbf := time.Now().Add(-5 * time.Minute)

	wit := NewWIT(
		spiffeID,
		audience,
		1*time.Hour,
		WithWITJTI("custom-jti"),
		WithWITNotBefore(nbf),
		WithWITCNF(&CNF{Kid: "key-1"}),
	)

	if wit.JWTID != "custom-jti" {
		t.Errorf("JWTID = %q, want %q", wit.JWTID, "custom-jti")
	}
	if !wit.NotBefore.Equal(nbf) {
		t.Errorf("NotBefore = %v, want %v", wit.NotBefore, nbf)
	}
	if wit.CNF == nil || wit.CNF.Kid != "key-1" {
		t.Error("CNF should be set with Kid")
	}
}

func TestWorkloadIdentityToken_Validate(t *testing.T) {
	tests := []struct {
		name    string
		wit     *WorkloadIdentityToken
		wantErr error
	}{
		{
			name: "valid",
			wit: &WorkloadIdentityToken{
				Issuer:   "https://example.com",
				Subject:  "spiffe://example.com/agent/test",
				Audience: []string{"https://api.example.com"},
				Expiry:   time.Now().Add(1 * time.Hour),
			},
			wantErr: nil,
		},
		{
			name: "missing_subject",
			wit: &WorkloadIdentityToken{
				Issuer:   "https://example.com",
				Audience: []string{"https://api.example.com"},
				Expiry:   time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrWITMissingSubject,
		},
		{
			name: "missing_issuer",
			wit: &WorkloadIdentityToken{
				Subject:  "spiffe://example.com/agent/test",
				Audience: []string{"https://api.example.com"},
				Expiry:   time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrWITMissingIssuer,
		},
		{
			name: "missing_audience",
			wit: &WorkloadIdentityToken{
				Issuer:  "https://example.com",
				Subject: "spiffe://example.com/agent/test",
				Expiry:  time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrWITMissingAudience,
		},
		{
			name: "expired",
			wit: &WorkloadIdentityToken{
				Issuer:   "https://example.com",
				Subject:  "spiffe://example.com/agent/test",
				Audience: []string{"https://api.example.com"},
				Expiry:   time.Now().Add(-1 * time.Hour),
			},
			wantErr: ErrWITExpired,
		},
		{
			name: "not_yet_valid",
			wit: &WorkloadIdentityToken{
				Issuer:    "https://example.com",
				Subject:   "spiffe://example.com/agent/test",
				Audience:  []string{"https://api.example.com"},
				Expiry:    time.Now().Add(1 * time.Hour),
				NotBefore: time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrWITNotYetValid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wit.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWorkloadIdentityToken_Sign(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	wit := NewWIT(spiffeID, []string{"https://api.example.com"}, 1*time.Hour)

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	signed, err := wit.Sign(privateKey, "test-key-1")
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

func TestWorkloadIdentityToken_IsExpired(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{"future", time.Now().Add(1 * time.Hour), false},
		{"past", time.Now().Add(-1 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wit := &WorkloadIdentityToken{Expiry: tt.expiry}
			if got := wit.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWorkloadIdentityToken_TimeToExpiry(t *testing.T) {
	wit := &WorkloadIdentityToken{Expiry: time.Now().Add(1 * time.Hour)}
	ttl := wit.TimeToExpiry()

	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("TimeToExpiry() = %v, want ~1 hour", ttl)
	}

	expiredWit := &WorkloadIdentityToken{Expiry: time.Now().Add(-1 * time.Hour)}
	if ttl := expiredWit.TimeToExpiry(); ttl != 0 {
		t.Errorf("TimeToExpiry() for expired = %v, want 0", ttl)
	}
}

func TestWorkloadIdentityToken_SPIFFEID(t *testing.T) {
	wit := &WorkloadIdentityToken{Subject: "spiffe://example.com/agent/test"}

	spiffeID, err := wit.SPIFFEID()
	if err != nil {
		t.Fatalf("SPIFFEID() error = %v", err)
	}

	if spiffeID.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", spiffeID.TrustDomain, "example.com")
	}
	if spiffeID.Path != "/agent/test" {
		t.Errorf("Path = %q, want %q", spiffeID.Path, "/agent/test")
	}
}

func TestWorkloadIdentityToken_Type(t *testing.T) {
	wit := &WorkloadIdentityToken{}
	if got := wit.Type(); got != CredentialWIT {
		t.Errorf("Type() = %v, want %v", got, CredentialWIT)
	}
}

func TestGenerateJTI(t *testing.T) {
	jti1 := GenerateJTI()
	jti2 := GenerateJTI()

	if jti1 == "" {
		t.Error("GenerateJTI() returned empty string")
	}
	if jti1 == jti2 {
		t.Error("GenerateJTI() should return unique values")
	}
	if len(jti1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("GenerateJTI() length = %d, want 32", len(jti1))
	}
}
