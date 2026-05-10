package httpsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"
)

func TestNewVerifier(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	verifier, err := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	if verifier == nil {
		t.Fatal("expected verifier to be non-nil")
	}
}

func TestNewVerifier_MissingKey(t *testing.T) {
	_, err := NewVerifier(VerifierOptions{})
	if err == nil {
		t.Fatal("expected error for missing public key")
	}
}

func TestVerifier_MissingSignatureHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for missing Signature header")
	}
}

func TestVerifier_MissingSignatureInputHeader(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Header.Set("Signature", "sig1=:abc:")

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for missing Signature-Input header")
	}
}

func TestVerifier_KeyIDMismatch(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "key-1",
		CoveredComponents: []string{"@method"},
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
		KeyID:     "key-2", // Different key ID
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for key ID mismatch")
	}
}

func TestVerifier_AlgorithmNotAllowed(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		Algorithm:         "ecdsa-p256-sha256",
		CoveredComponents: []string{"@method"},
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey:         &privateKey.PublicKey,
		AllowedAlgorithms: []string{"rsa-pss-sha256"}, // Only allow RSA
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for disallowed algorithm")
	}
}

func TestVerifier_RequiredComponentMissing(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"}, // Only sign @method
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey:          &privateKey.PublicKey,
		RequiredComponents: []string{"@target-uri"}, // Require @target-uri
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for missing required component")
	}
}

func TestVerifier_SignatureTooOld(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
		MaxAge:    1 * time.Nanosecond, // Very short max age
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	// Wait a bit to make the signature old
	time.Sleep(10 * time.Millisecond)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for old signature")
	}
}

func TestVerifier_InvalidSignature(t *testing.T) {
	privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey1,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
	})

	// Use a different key for verification
	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey2.PublicKey,
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	result, err := verifier.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Valid {
		t.Error("expected signature to be invalid with wrong key")
	}
}

func TestVerifier_SpecificLabel(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
		Label:             "mysig",
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
		Label:     "mysig",
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	result, err := verifier.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected signature to be valid")
	}
	if result.Label != "mysig" {
		t.Errorf("expected label mysig, got %s", result.Label)
	}
}

func TestVerifier_LabelNotFound(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method"},
		Label:             "sig1",
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
		Label:     "nonexistent",
	})

	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	_ = signer.Sign(req)

	_, err := verifier.Verify(req)
	if err == nil {
		t.Fatal("expected error for nonexistent label")
	}
}

func TestVerifier_WithHeaders(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method", "@target-uri", "content-type"},
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
	})

	req, _ := http.NewRequest("POST", "https://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")
	_ = signer.Sign(req)

	result, err := verifier.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected signature to be valid")
	}
}

func TestVerifier_TamperedRequest(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(SignerOptions{
		PrivateKey:        privateKey,
		KeyID:             "test-key",
		CoveredComponents: []string{"@method", "@target-uri"},
	})

	verifier, _ := NewVerifier(VerifierOptions{
		PublicKey: &privateKey.PublicKey,
	})

	req, _ := http.NewRequest("GET", "https://example.com/original", nil)
	_ = signer.Sign(req)

	// Tamper with the request
	req.URL.Path = "/tampered"

	result, err := verifier.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Valid {
		t.Error("expected signature to be invalid after tampering")
	}
}
