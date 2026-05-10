package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
)

func TestNewSigner_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(SignerOptions{
		PrivateKey: privateKey,
		KeyID:      "test-key",
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	if signer == nil {
		t.Fatal("expected signer to be non-nil")
	}
}

func TestNewSigner_MissingKey(t *testing.T) {
	_, err := NewSigner(SignerOptions{
		KeyID: "test-key",
	})
	if err == nil {
		t.Fatal("expected error for missing private key")
	}
}

func TestNewSigner_MissingKeyID(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := NewSigner(SignerOptions{
		PrivateKey: privateKey,
	})
	if err == nil {
		t.Fatal("expected error for missing key ID")
	}
}

func TestSigner_Sign_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		Algorithm:         "ecdsa-p256-sha256",
		CoveredComponents: []string{"@method", "@target-uri"},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	req, err := http.NewRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	err = signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Check that headers were added
	signature := req.Header.Get("Signature")
	signatureInput := req.Header.Get("Signature-Input")

	if signature == "" {
		t.Error("expected Signature header to be set")
	}
	if signatureInput == "" {
		t.Error("expected Signature-Input header to be set")
	}

	// Verify header format
	if !contains(signature, "sig1=:") {
		t.Errorf("unexpected Signature format: %s", signature)
	}
	if !contains(signatureInput, "sig1=") {
		t.Errorf("unexpected Signature-Input format: %s", signatureInput)
	}
}

func TestSigner_Sign_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		Algorithm:         "rsa-pss-sha256",
		CoveredComponents: []string{"@method", "@target-uri"},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	req, err := http.NewRequest("POST", "https://example.com/api", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	err = signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if req.Header.Get("Signature") == "" {
		t.Error("expected Signature header to be set")
	}
}

func TestSigner_Sign_Ed25519(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer, err := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		Algorithm:         "ed25519",
		CoveredComponents: []string{"@method", "@target-uri"},
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	req, err := http.NewRequest("GET", "https://example.com/data", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	err = signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if req.Header.Get("Signature") == "" {
		t.Error("expected Signature header to be set")
	}
}

func TestSigner_Sign_WithNonce(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
		IncludeNonce:      true,
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	err = signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signatureInput := req.Header.Get("Signature-Input")
	if !contains(signatureInput, "nonce=") {
		t.Errorf("expected nonce in Signature-Input: %s", signatureInput)
	}
}

func TestSigner_Sign_CustomLabel(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
		Label:             "custom-sig",
	})
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	err = signer.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signature := req.Header.Get("Signature")
	if !contains(signature, "custom-sig=:") {
		t.Errorf("expected custom-sig label in Signature: %s", signature)
	}
}

func TestSigner_SignAndVerify_Roundtrip(t *testing.T) {
	// Test roundtrip with different key types
	tests := []struct {
		name      string
		keyGen    func() (any, any)
		algorithm string
	}{
		{
			name: "ECDSA P-256",
			keyGen: func() (any, any) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key, &key.PublicKey
			},
			algorithm: "ecdsa-p256-sha256",
		},
		{
			name: "ECDSA P-384",
			keyGen: func() (any, any) {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key, &key.PublicKey
			},
			algorithm: "ecdsa-p384-sha384",
		},
		{
			name: "RSA-PSS",
			keyGen: func() (any, any) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey
			},
			algorithm: "rsa-pss-sha256",
		},
		{
			name: "Ed25519",
			keyGen: func() (any, any) {
				pub, priv, _ := ed25519.GenerateKey(rand.Reader)
				return priv, pub
			},
			algorithm: "ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey := tt.keyGen()

			signer, err := NewSigner(SignerOptions{
				PrivateKey:        privateKey,
				KeyID:             "test-key",
				Algorithm:         tt.algorithm,
				CoveredComponents: []string{"@method", "@target-uri"},
			})
			if err != nil {
				t.Fatalf("NewSigner() error = %v", err)
			}

			req, _ := http.NewRequest("GET", "https://example.com/data", nil)
			err = signer.Sign(req)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			verifier, err := NewVerifier(VerifierOptions{
				PublicKey: publicKey,
				KeyID:     "test-key",
			})
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			result, err := verifier.Verify(req)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}

			if !result.Valid {
				t.Error("expected signature to be valid")
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
