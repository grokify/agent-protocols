package aims

import (
	"testing"
	"time"
)

func TestAttestationType_String(t *testing.T) {
	tests := []struct {
		at   AttestationType
		want string
	}{
		{AttestationTPM, "tpm"},
		{AttestationSGX, "sgx"},
		{AttestationSEVSNP, "sev-snp"},
		{AttestationKubernetes, "kubernetes"},
		{AttestationAWS, "aws"},
		{AttestationGCP, "gcp"},
		{AttestationAzure, "azure"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.at.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAttestationType_Description(t *testing.T) {
	// Verify all types have non-empty descriptions
	types := []AttestationType{
		AttestationTPM,
		AttestationSGX,
		AttestationSEVSNP,
		AttestationTDX,
		AttestationKubernetes,
		AttestationAWS,
		AttestationGCP,
		AttestationAzure,
		AttestationGitHub,
		AttestationUnix,
		AttestationDocker,
	}

	for _, at := range types {
		desc := at.Description()
		if desc == "" {
			t.Errorf("AttestationType %v has empty description", at)
		}
		if desc == "Unknown attestation type" {
			t.Errorf("AttestationType %v has unknown description", at)
		}
	}
}

func TestAttestationType_IsHardware(t *testing.T) {
	tests := []struct {
		at   AttestationType
		want bool
	}{
		{AttestationTPM, true},
		{AttestationSGX, true},
		{AttestationSEVSNP, true},
		{AttestationTDX, true},
		{AttestationKubernetes, false},
		{AttestationAWS, false},
		{AttestationGCP, false},
		{AttestationAzure, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.at), func(t *testing.T) {
			if got := tt.at.IsHardware(); got != tt.want {
				t.Errorf("IsHardware() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttestationType_IsCloud(t *testing.T) {
	tests := []struct {
		at   AttestationType
		want bool
	}{
		{AttestationAWS, true},
		{AttestationGCP, true},
		{AttestationAzure, true},
		{AttestationTPM, false},
		{AttestationKubernetes, false},
		{AttestationGitHub, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.at), func(t *testing.T) {
			if got := tt.at.IsCloud(); got != tt.want {
				t.Errorf("IsCloud() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAttestation(t *testing.T) {
	evidence := []byte("attestation-evidence")
	att := NewAttestation(AttestationKubernetes, evidence)

	if att.Type != AttestationKubernetes {
		t.Errorf("Type = %v, want %v", att.Type, AttestationKubernetes)
	}
	if string(att.Evidence) != string(evidence) {
		t.Errorf("Evidence = %q, want %q", att.Evidence, evidence)
	}
	if att.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestNewAttestationWithOptions(t *testing.T) {
	customTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	evidence := []byte("evidence")

	att := NewAttestationWithOptions(
		AttestationAWS,
		evidence,
		WithAttestationTimestamp(customTime),
		WithAttribute(AttrInstanceID, "i-12345"),
		WithAttribute(AttrRegion, "us-west-2"),
	)

	if !att.Timestamp.Equal(customTime) {
		t.Errorf("Timestamp = %v, want %v", att.Timestamp, customTime)
	}

	if len(att.Attributes) != 2 {
		t.Errorf("Attributes length = %d, want 2", len(att.Attributes))
	}

	if att.Attributes[AttrInstanceID] != "i-12345" {
		t.Errorf("Attributes[instance-id] = %q, want %q", att.Attributes[AttrInstanceID], "i-12345")
	}
}

func TestAttestation_Age(t *testing.T) {
	att := &Attestation{
		Timestamp: time.Now().Add(-1 * time.Hour),
	}

	age := att.Age()
	if age < 59*time.Minute || age > 61*time.Minute {
		t.Errorf("Age() = %v, want ~1 hour", age)
	}
}

func TestAttestation_IsFresh(t *testing.T) {
	tests := []struct {
		name      string
		timestamp time.Time
		maxAge    time.Duration
		want      bool
	}{
		{
			name:      "fresh",
			timestamp: time.Now().Add(-30 * time.Second),
			maxAge:    1 * time.Minute,
			want:      true,
		},
		{
			name:      "stale",
			timestamp: time.Now().Add(-2 * time.Minute),
			maxAge:    1 * time.Minute,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			att := &Attestation{Timestamp: tt.timestamp}
			if got := att.IsFresh(tt.maxAge); got != tt.want {
				t.Errorf("IsFresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAttestation_GetAttribute(t *testing.T) {
	att := &Attestation{
		Attributes: map[string]string{
			"key1": "value1",
		},
	}

	// Existing key
	val, ok := att.GetAttribute("key1")
	if !ok || val != "value1" {
		t.Errorf("GetAttribute(key1) = (%q, %v), want (%q, true)", val, ok, "value1")
	}

	// Missing key
	val, ok = att.GetAttribute("key2")
	if ok || val != "" {
		t.Errorf("GetAttribute(key2) = (%q, %v), want (\"\", false)", val, ok)
	}

	// Nil attributes
	attNil := &Attestation{}
	val, ok = attNil.GetAttribute("key")
	if ok || val != "" {
		t.Errorf("GetAttribute on nil attrs = (%q, %v), want (\"\", false)", val, ok)
	}
}

func TestAttestationAttributeConstants(t *testing.T) {
	// Just verify constants are defined
	attrs := []string{
		AttrInstanceID,
		AttrRegion,
		AttrAccountID,
		AttrNamespace,
		AttrServiceAccount,
		AttrPodName,
		AttrContainerID,
		AttrImageDigest,
		AttrPCR0,
		AttrMRENCLAVE,
		AttrMRSIGNER,
	}

	for _, attr := range attrs {
		if attr == "" {
			t.Error("Attribute constant should not be empty")
		}
	}
}
