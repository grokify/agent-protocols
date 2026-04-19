package aims

import (
	"testing"
	"time"
)

func TestCredentialType_String(t *testing.T) {
	tests := []struct {
		ct   CredentialType
		want string
	}{
		{CredentialX509SVID, "x509-svid"},
		{CredentialJWTSVID, "jwt-svid"},
		{CredentialWIT, "wit"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.ct.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewJWTSVID(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	expiry := time.Now().Add(1 * time.Hour)

	svid := NewJWTSVID("token-value", spiffeID, expiry)

	if svid.Token != "token-value" {
		t.Errorf("Token = %q, want %q", svid.Token, "token-value")
	}
	if svid.SPIFFEID() != spiffeID {
		t.Error("SPIFFEID() should return the provided SPIFFE ID")
	}
	if !svid.ExpiresAt().Equal(expiry) {
		t.Errorf("ExpiresAt() = %v, want %v", svid.ExpiresAt(), expiry)
	}
}

func TestJWTSVID_Type(t *testing.T) {
	svid := &JWTSVID{}
	if got := svid.Type(); got != CredentialJWTSVID {
		t.Errorf("Type() = %v, want %v", got, CredentialJWTSVID)
	}
}

func TestJWTSVID_IsExpired(t *testing.T) {
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
			svid := &JWTSVID{expiry: tt.expiry}
			if got := svid.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestX509SVID_Type(t *testing.T) {
	// Create a minimal X509SVID for type check only
	svid := &X509SVID{}
	if got := svid.Type(); got != CredentialX509SVID {
		t.Errorf("Type() = %v, want %v", got, CredentialX509SVID)
	}
}

func TestX509SVID_IsExpired_NoCerts(t *testing.T) {
	svid := &X509SVID{}
	if !svid.IsExpired() {
		t.Error("X509SVID with no certificates should be expired")
	}
}

func TestX509SVID_LeafCertificate_NoCerts(t *testing.T) {
	svid := &X509SVID{}
	if svid.LeafCertificate() != nil {
		t.Error("LeafCertificate() should return nil when no certificates")
	}
}

func TestX509SVID_ExpiresAt_NoCerts(t *testing.T) {
	svid := &X509SVID{}
	if !svid.ExpiresAt().IsZero() {
		t.Error("ExpiresAt() should return zero time when no certificates")
	}
}

func TestX509SVID_SPIFFEID_NoCerts(t *testing.T) {
	svid := &X509SVID{}
	if svid.SPIFFEID() != nil {
		t.Error("SPIFFEID() should return nil when no certificates")
	}
}

func TestCredentialInterface(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")

	// Test that JWTSVID implements Credential interface
	var cred Credential
	cred = NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour))

	if cred.Type() != CredentialJWTSVID {
		t.Error("JWTSVID should return jwt-svid type")
	}
	if cred.SPIFFEID() == nil {
		t.Error("SPIFFEID should not be nil")
	}
	if cred.IsExpired() {
		t.Error("Fresh credential should not be expired")
	}
	if cred.ExpiresAt().IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}
