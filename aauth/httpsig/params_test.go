package httpsig

import (
	"testing"
	"time"
)

func TestSignatureParams_Serialize(t *testing.T) {
	created := time.Unix(1618884473, 0)
	expires := time.Unix(1618884773, 0)

	tests := []struct {
		name   string
		params *SignatureParams
		want   string
	}{
		{
			name: "basic",
			params: &SignatureParams{
				Components: []string{"@method", "@target-uri"},
				Created:    created,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
			},
			want: `(@method @target-uri);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
		},
		{
			name: "with header",
			params: &SignatureParams{
				Components: []string{"@method", "content-type"},
				Created:    created,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
			},
			want: `(@method "content-type");created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
		},
		{
			name: "with expires",
			params: &SignatureParams{
				Components: []string{"@method"},
				Created:    created,
				Expires:    &expires,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
			},
			want: `(@method);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256";expires=1618884773`,
		},
		{
			name: "with nonce",
			params: &SignatureParams{
				Components: []string{"@method"},
				Created:    created,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
				Nonce:      "abc123",
			},
			want: `(@method);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256";nonce="abc123"`,
		},
		{
			name: "with tag",
			params: &SignatureParams{
				Components: []string{"@method"},
				Created:    created,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
				Tag:        "replay",
			},
			want: `(@method);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256";tag="replay"`,
		},
		{
			name: "empty components",
			params: &SignatureParams{
				Components: []string{},
				Created:    created,
				KeyID:      "test-key",
				Algorithm:  "ecdsa-p256-sha256",
			},
			want: `();created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.params.Serialize()
			if got != tt.want {
				t.Errorf("Serialize() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSignatureParams(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantComponents []string
		wantKeyID      string
		wantAlgorithm  string
		wantErr        bool
	}{
		{
			name:           "basic",
			input:          `(@method @target-uri);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
			wantComponents: []string{"@method", "@target-uri"},
			wantKeyID:      "test-key",
			wantAlgorithm:  "ecdsa-p256-sha256",
			wantErr:        false,
		},
		{
			name:           "with header",
			input:          `(@method "content-type");created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
			wantComponents: []string{"@method", "content-type"},
			wantKeyID:      "test-key",
			wantAlgorithm:  "ecdsa-p256-sha256",
			wantErr:        false,
		},
		{
			name:           "empty components",
			input:          `();created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`,
			wantComponents: []string{},
			wantKeyID:      "test-key",
			wantAlgorithm:  "ecdsa-p256-sha256",
			wantErr:        false,
		},
		{
			name:    "missing opening paren",
			input:   `@method);created=1618884473`,
			wantErr: true,
		},
		{
			name:    "missing closing paren",
			input:   `(@method;created=1618884473`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureParams(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if len(got.Components) != len(tt.wantComponents) {
				t.Errorf("Components length = %d, want %d", len(got.Components), len(tt.wantComponents))
			} else {
				for i, comp := range got.Components {
					if comp != tt.wantComponents[i] {
						t.Errorf("Component[%d] = %q, want %q", i, comp, tt.wantComponents[i])
					}
				}
			}

			if got.KeyID != tt.wantKeyID {
				t.Errorf("KeyID = %q, want %q", got.KeyID, tt.wantKeyID)
			}
			if got.Algorithm != tt.wantAlgorithm {
				t.Errorf("Algorithm = %q, want %q", got.Algorithm, tt.wantAlgorithm)
			}
		})
	}
}

func TestParseSignatureParams_Timestamps(t *testing.T) {
	input := `(@method);created=1618884473;expires=1618884773;keyid="test"`

	params, err := ParseSignatureParams(input)
	if err != nil {
		t.Fatalf("ParseSignatureParams() error = %v", err)
	}

	expectedCreated := time.Unix(1618884473, 0)
	expectedExpires := time.Unix(1618884773, 0)

	if !params.Created.Equal(expectedCreated) {
		t.Errorf("Created = %v, want %v", params.Created, expectedCreated)
	}

	if params.Expires == nil {
		t.Fatal("Expires should not be nil")
	}
	if !params.Expires.Equal(expectedExpires) {
		t.Errorf("Expires = %v, want %v", *params.Expires, expectedExpires)
	}
}

func TestFormatSignatureInput(t *testing.T) {
	created := time.Unix(1618884473, 0)

	params := &SignatureParams{
		Components: []string{"@method"},
		Created:    created,
		KeyID:      "test-key",
		Algorithm:  "ecdsa-p256-sha256",
	}

	got := FormatSignatureInput("sig1", params)
	want := `sig1=(@method);created=1618884473;keyid="test-key";alg="ecdsa-p256-sha256"`

	if got != want {
		t.Errorf("FormatSignatureInput() = %q, want %q", got, want)
	}
}

func TestParseSignatureInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
	}{
		{
			name:      "single signature",
			input:     `sig1=(@method);created=1618884473;keyid="test"`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "multiple signatures",
			input:     `sig1=(@method);created=1618884473;keyid="k1", sig2=(@path);created=1618884473;keyid="k2"`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:    "missing equals",
			input:   `sig1(@method)`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureInput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if len(got) != tt.wantCount {
				t.Errorf("ParseSignatureInput() returned %d signatures, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestParseSignatureInput_Labels(t *testing.T) {
	input := `sig1=(@method);created=1618884473;keyid="k1", sig2=(@path);created=1618884474;keyid="k2"`

	got, err := ParseSignatureInput(input)
	if err != nil {
		t.Fatalf("ParseSignatureInput() error = %v", err)
	}

	if _, ok := got["sig1"]; !ok {
		t.Error("expected sig1 to be present")
	}
	if _, ok := got["sig2"]; !ok {
		t.Error("expected sig2 to be present")
	}

	if got["sig1"].KeyID != "k1" {
		t.Errorf("sig1 KeyID = %q, want k1", got["sig1"].KeyID)
	}
	if got["sig2"].KeyID != "k2" {
		t.Errorf("sig2 KeyID = %q, want k2", got["sig2"].KeyID)
	}
}

func TestSignatureParams_Roundtrip(t *testing.T) {
	created := time.Unix(1618884473, 0)
	expires := time.Unix(1618884773, 0)

	original := &SignatureParams{
		Components: []string{"@method", "@target-uri", "content-type"},
		Created:    created,
		Expires:    &expires,
		Nonce:      "test-nonce",
		Algorithm:  "ecdsa-p256-sha256",
		KeyID:      "test-key",
		Tag:        "test-tag",
	}

	serialized := original.Serialize()
	parsed, err := ParseSignatureParams(serialized)
	if err != nil {
		t.Fatalf("ParseSignatureParams() error = %v", err)
	}

	// Compare values
	if len(parsed.Components) != len(original.Components) {
		t.Errorf("Components length mismatch")
	}
	if !parsed.Created.Equal(original.Created) {
		t.Errorf("Created mismatch")
	}
	if parsed.Expires == nil || !parsed.Expires.Equal(*original.Expires) {
		t.Errorf("Expires mismatch")
	}
	if parsed.Nonce != original.Nonce {
		t.Errorf("Nonce mismatch")
	}
	if parsed.Algorithm != original.Algorithm {
		t.Errorf("Algorithm mismatch")
	}
	if parsed.KeyID != original.KeyID {
		t.Errorf("KeyID mismatch")
	}
	if parsed.Tag != original.Tag {
		t.Errorf("Tag mismatch")
	}
}

func TestDefaultSignatureParams(t *testing.T) {
	before := time.Now()
	params := DefaultSignatureParams("my-key", "ecdsa-p256-sha256", []string{"@method"})
	after := time.Now()

	if params.KeyID != "my-key" {
		t.Errorf("KeyID = %q, want my-key", params.KeyID)
	}
	if params.Algorithm != "ecdsa-p256-sha256" {
		t.Errorf("Algorithm = %q, want ecdsa-p256-sha256", params.Algorithm)
	}
	if len(params.Components) != 1 || params.Components[0] != "@method" {
		t.Errorf("Components = %v, want [@method]", params.Components)
	}

	// Created should be set to now
	if params.Created.Before(before) || params.Created.After(after) {
		t.Errorf("Created should be set to current time")
	}
}
