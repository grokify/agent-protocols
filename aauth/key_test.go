package aauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestNewCNFWithJWK_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("NewCNFWithJWK() error = %v", err)
	}

	if cnf.JWK == nil {
		t.Error("expected JWK to be set")
	}

	// Verify it's valid JSON
	var jwk map[string]any
	if err := json.Unmarshal(cnf.JWK, &jwk); err != nil {
		t.Fatalf("JWK is not valid JSON: %v", err)
	}

	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %v", jwk["kty"])
	}
}

func TestNewCNFWithJKU(t *testing.T) {
	cnf := NewCNFWithJKU("https://example.com/.well-known/jwks.json", "key-1")

	if cnf.JKU != "https://example.com/.well-known/jwks.json" {
		t.Errorf("expected JKU to be set")
	}
	if cnf.Kid != "key-1" {
		t.Errorf("expected Kid to be key-1")
	}
	if cnf.JWK != nil {
		t.Error("expected JWK to be nil")
	}
}

func TestCNF_GetJWK(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("NewCNFWithJWK() error = %v", err)
	}

	jwk, err := cnf.GetJWK()
	if err != nil {
		t.Fatalf("GetJWK() error = %v", err)
	}

	if jwk.Kty != "EC" {
		t.Errorf("expected Kty EC, got %s", jwk.Kty)
	}
}

func TestCNF_GetJWK_NoJWK(t *testing.T) {
	cnf := NewCNFWithJKU("https://example.com/jwks", "key-1")

	_, err := cnf.GetJWK()
	if err == nil {
		t.Error("expected error when no JWK is embedded")
	}
}

func TestCNF_GetPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("NewCNFWithJWK() error = %v", err)
	}

	pubKey, err := cnf.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey() error = %v", err)
	}

	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
	}

	if ecPub.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("X coordinates don't match")
	}
}

func TestCNF_GetThumbprint(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf, err := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("NewCNFWithJWK() error = %v", err)
	}

	thumbprint, err := cnf.GetThumbprint()
	if err != nil {
		t.Fatalf("GetThumbprint() error = %v", err)
	}

	if thumbprint == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestCNF_IsEmbedded(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf1, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	cnf2 := NewCNFWithJKU("https://example.com/jwks", "key-1")

	if !cnf1.IsEmbedded() {
		t.Error("expected CNF with JWK to be embedded")
	}
	if cnf2.IsEmbedded() {
		t.Error("expected CNF with JKU to not be embedded")
	}
}

func TestCNF_IsReference(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cnf1, _ := NewCNFWithJWK(&privateKey.PublicKey, "test-key")
	cnf2 := NewCNFWithJKU("https://example.com/jwks", "key-1")

	if cnf1.IsReference() {
		t.Error("expected CNF with JWK to not be a reference")
	}
	if !cnf2.IsReference() {
		t.Error("expected CNF with JKU to be a reference")
	}
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		alg   string
	}{
		{"P-256", elliptic.P256(), AlgorithmES256},
		{"P-384", elliptic.P384(), AlgorithmES384},
		{"P-521", elliptic.P521(), AlgorithmES512},
		{"nil defaults to P-256", nil, AlgorithmES256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateECDSAKeyPair("test-key", tt.curve)
			if err != nil {
				t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
			}

			if kp.Algorithm != tt.alg {
				t.Errorf("expected Algorithm %s, got %s", tt.alg, kp.Algorithm)
			}
			if kp.KeyID != "test-key" {
				t.Errorf("expected KeyID test-key, got %s", kp.KeyID)
			}
			if kp.PrivateKey == nil {
				t.Error("expected PrivateKey to be set")
			}
			if kp.PublicKey == nil {
				t.Error("expected PublicKey to be set")
			}
		})
	}
}

func TestGenerateRSAKeyPair(t *testing.T) {
	kp, err := GenerateRSAKeyPair("test-key", 2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}

	if kp.Algorithm != AlgorithmRS256 {
		t.Errorf("expected Algorithm RS256, got %s", kp.Algorithm)
	}

	rsaKey, ok := kp.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", kp.PrivateKey)
	}

	if rsaKey.N.BitLen() < 2048 {
		t.Error("expected at least 2048 bit key")
	}
}

func TestGenerateRSAKeyPair_MinimumBits(t *testing.T) {
	kp, err := GenerateRSAKeyPair("test-key", 1024) // Should be upgraded to 2048
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() error = %v", err)
	}

	rsaKey := kp.PrivateKey.(*rsa.PrivateKey)
	if rsaKey.N.BitLen() < 2048 {
		t.Error("expected key to be upgraded to at least 2048 bits")
	}
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	kp, err := GenerateEd25519KeyPair("test-key")
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}

	if kp.Algorithm != AlgorithmEdDSA {
		t.Errorf("expected Algorithm EdDSA, got %s", kp.Algorithm)
	}

	_, ok := kp.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", kp.PrivateKey)
	}

	_, ok = kp.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", kp.PublicKey)
	}
}

func TestKeyPair_ToJWK(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	jwk, err := kp.ToJWK()
	if err != nil {
		t.Fatalf("ToJWK() error = %v", err)
	}

	if jwk.Kty != "EC" {
		t.Errorf("expected Kty EC, got %s", jwk.Kty)
	}
	if jwk.Kid != "test-key" {
		t.Errorf("expected Kid test-key, got %s", jwk.Kid)
	}
}

func TestKeyPair_ToCNF(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	cnf, err := kp.ToCNF()
	if err != nil {
		t.Fatalf("ToCNF() error = %v", err)
	}

	if !cnf.IsEmbedded() {
		t.Error("expected CNF to have embedded JWK")
	}
}

func TestKeyPair_Thumbprint(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	thumbprint, err := kp.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint() error = %v", err)
	}

	if thumbprint == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestKeyPair_HTTPSigAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		genFunc  func() (*KeyPair, error)
		expected string
	}{
		{
			name: "ECDSA P-256",
			genFunc: func() (*KeyPair, error) {
				return GenerateECDSAKeyPair("test", elliptic.P256())
			},
			expected: HTTPSigAlgorithmECDSAP256SHA256,
		},
		{
			name: "ECDSA P-384",
			genFunc: func() (*KeyPair, error) {
				return GenerateECDSAKeyPair("test", elliptic.P384())
			},
			expected: HTTPSigAlgorithmECDSAP384SHA384,
		},
		{
			name: "Ed25519",
			genFunc: func() (*KeyPair, error) {
				return GenerateEd25519KeyPair("test")
			},
			expected: HTTPSigAlgorithmEdDSA,
		},
		{
			name: "RSA",
			genFunc: func() (*KeyPair, error) {
				return GenerateRSAKeyPair("test", 2048)
			},
			expected: HTTPSigAlgorithmRSAv15SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := tt.genFunc()
			if err != nil {
				t.Fatalf("key generation error = %v", err)
			}

			if got := kp.HTTPSigAlgorithm(); got != tt.expected {
				t.Errorf("HTTPSigAlgorithm() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestKeyPair_MatchesCNF(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	cnf, err := kp.ToCNF()
	if err != nil {
		t.Fatalf("ToCNF() error = %v", err)
	}

	matches, err := kp.MatchesCNF(cnf)
	if err != nil {
		t.Fatalf("MatchesCNF() error = %v", err)
	}
	if !matches {
		t.Error("expected key pair to match its own CNF")
	}

	// Test with different key
	kp2, _ := GenerateECDSAKeyPair("other-key", elliptic.P256())
	matches, err = kp2.MatchesCNF(cnf)
	if err != nil {
		t.Fatalf("MatchesCNF() error = %v", err)
	}
	if matches {
		t.Error("expected different key pair to not match CNF")
	}

	// Test with nil CNF
	matches, _ = kp.MatchesCNF(nil)
	if matches {
		t.Error("expected no match for nil CNF")
	}
}

func TestKeyPair_MatchesCNF_JKUReference(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("test-key", elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	cnf := NewCNFWithJKU("https://example.com/jwks", "test-key")

	matches, err := kp.MatchesCNF(cnf)
	if err != nil {
		t.Fatalf("MatchesCNF() error = %v", err)
	}
	if !matches {
		t.Error("expected match by kid for JKU reference")
	}

	cnf2 := NewCNFWithJKU("https://example.com/jwks", "other-key")
	matches, _ = kp.MatchesCNF(cnf2)
	if matches {
		t.Error("expected no match for different kid")
	}
}
