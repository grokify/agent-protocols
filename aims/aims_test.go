package aims

import (
	"testing"
	"time"
)

func TestLayer_String(t *testing.T) {
	tests := []struct {
		layer Layer
		want  string
	}{
		{LayerIdentifiers, "Identifiers"},
		{LayerCredentials, "Credentials"},
		{LayerAttestation, "Attestation"},
		{LayerProvisioning, "Provisioning"},
		{LayerAuthentication, "Authentication"},
		{LayerAuthorization, "Authorization"},
		{LayerMonitoring, "Monitoring"},
		{LayerPolicy, "Policy"},
		{LayerCompliance, "Compliance"},
		{Layer(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.layer.String(); got != tt.want {
				t.Errorf("Layer.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLayer_Description(t *testing.T) {
	// Just verify descriptions are non-empty for all layers
	for _, l := range AllLayers() {
		desc := l.Description()
		if desc == "" {
			t.Errorf("Layer %v has empty description", l)
		}
		if desc == "Unknown layer" {
			t.Errorf("Layer %v has unknown description", l)
		}
	}
}

func TestAllLayers(t *testing.T) {
	layers := AllLayers()
	if len(layers) != 9 {
		t.Errorf("AllLayers() returned %d layers, want 9", len(layers))
	}

	// Verify order
	expected := []Layer{
		LayerIdentifiers,
		LayerCredentials,
		LayerAttestation,
		LayerProvisioning,
		LayerAuthentication,
		LayerAuthorization,
		LayerMonitoring,
		LayerPolicy,
		LayerCompliance,
	}

	for i, l := range layers {
		if l != expected[i] {
			t.Errorf("AllLayers()[%d] = %v, want %v", i, l, expected[i])
		}
	}
}

func TestNewAgentIdentity(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	cred := NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour))

	identity := NewAgentIdentity(spiffeID, cred)

	if identity.SPIFFEID == nil {
		t.Error("SPIFFEID should not be nil")
	}
	if identity.Credential == nil {
		t.Error("Credential should not be nil")
	}
	if identity.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestNewAgentIdentity_WithOptions(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")
	cred := NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour))
	att := NewAttestation(AttestationKubernetes, []byte("evidence"))

	identity := NewAgentIdentity(
		spiffeID,
		cred,
		WithAttestation(att),
		WithMetadata("key1", "value1"),
		WithMetadata("key2", "value2"),
	)

	if identity.Attestation == nil {
		t.Error("Attestation should be set")
	}
	if identity.Attestation.Type != AttestationKubernetes {
		t.Errorf("Attestation type = %v, want %v", identity.Attestation.Type, AttestationKubernetes)
	}

	if len(identity.Metadata) != 2 {
		t.Errorf("Metadata length = %d, want 2", len(identity.Metadata))
	}
	if identity.Metadata["key1"] != "value1" {
		t.Errorf("Metadata[key1] = %q, want %q", identity.Metadata["key1"], "value1")
	}
}

func TestAgentIdentity_IsValid(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")

	tests := []struct {
		name     string
		identity *AgentIdentity
		want     bool
	}{
		{
			name: "valid",
			identity: &AgentIdentity{
				SPIFFEID:   spiffeID,
				Credential: NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour)),
			},
			want: true,
		},
		{
			name: "nil_spiffe_id",
			identity: &AgentIdentity{
				SPIFFEID:   nil,
				Credential: NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour)),
			},
			want: false,
		},
		{
			name: "nil_credential",
			identity: &AgentIdentity{
				SPIFFEID:   spiffeID,
				Credential: nil,
			},
			want: false,
		},
		{
			name: "expired_credential",
			identity: &AgentIdentity{
				SPIFFEID:   spiffeID,
				Credential: NewJWTSVID("token", spiffeID, time.Now().Add(-1*time.Hour)),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identity.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgentIdentity_TimeToExpiry(t *testing.T) {
	spiffeID, _ := NewSPIFFEID("example.com", "/agent/test")

	// Test with valid credential
	identity := &AgentIdentity{
		SPIFFEID:   spiffeID,
		Credential: NewJWTSVID("token", spiffeID, time.Now().Add(1*time.Hour)),
	}

	ttl := identity.TimeToExpiry()
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("TimeToExpiry() = %v, want ~1 hour", ttl)
	}

	// Test with expired credential
	expiredIdentity := &AgentIdentity{
		SPIFFEID:   spiffeID,
		Credential: NewJWTSVID("token", spiffeID, time.Now().Add(-1*time.Hour)),
	}

	if ttl := expiredIdentity.TimeToExpiry(); ttl != 0 {
		t.Errorf("TimeToExpiry() for expired = %v, want 0", ttl)
	}

	// Test with nil credential
	nilCredIdentity := &AgentIdentity{SPIFFEID: spiffeID}
	if ttl := nilCredIdentity.TimeToExpiry(); ttl != 0 {
		t.Errorf("TimeToExpiry() for nil credential = %v, want 0", ttl)
	}
}
