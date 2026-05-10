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

func TestPublicKeyToJWK_ECDSA_P256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key-1")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	if jwk.Kty != "EC" {
		t.Errorf("expected Kty EC, got %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("expected Crv P-256, got %s", jwk.Crv)
	}
	if jwk.Kid != "test-key-1" {
		t.Errorf("expected Kid test-key-1, got %s", jwk.Kid)
	}
	if jwk.Alg != AlgorithmES256 {
		t.Errorf("expected Alg ES256, got %s", jwk.Alg)
	}
	if jwk.X == "" {
		t.Error("expected X to be set")
	}
	if jwk.Y == "" {
		t.Error("expected Y to be set")
	}
}

func TestPublicKeyToJWK_ECDSA_P384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key-1")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	if jwk.Crv != "P-384" {
		t.Errorf("expected Crv P-384, got %s", jwk.Crv)
	}
	if jwk.Alg != AlgorithmES384 {
		t.Errorf("expected Alg ES384, got %s", jwk.Alg)
	}
}

func TestPublicKeyToJWK_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key-1")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	if jwk.Kty != "RSA" {
		t.Errorf("expected Kty RSA, got %s", jwk.Kty)
	}
	if jwk.N == "" {
		t.Error("expected N to be set")
	}
	if jwk.E == "" {
		t.Error("expected E to be set")
	}
}

func TestPublicKeyToJWK_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(pub, "test-key-1")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	if jwk.Kty != "OKP" {
		t.Errorf("expected Kty OKP, got %s", jwk.Kty)
	}
	if jwk.Crv != "Ed25519" {
		t.Errorf("expected Crv Ed25519, got %s", jwk.Crv)
	}
	if jwk.X == "" {
		t.Error("expected X to be set")
	}
}

func TestJWKToPublicKey_ECDSA_Roundtrip(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	pubKey, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey() error = %v", err)
	}

	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
	}

	if ecPub.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("X coordinates don't match")
	}
	if ecPub.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Error("Y coordinates don't match")
	}
}

func TestJWKToPublicKey_RSA_Roundtrip(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	pubKey, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey() error = %v", err)
	}

	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pubKey)
	}

	if rsaPub.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("modulus doesn't match")
	}
	if rsaPub.E != privateKey.PublicKey.E {
		t.Error("exponent doesn't match")
	}
}

func TestJWKToPublicKey_Ed25519_Roundtrip(t *testing.T) {
	origPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(origPub, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	pubKey, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey() error = %v", err)
	}

	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", pubKey)
	}

	if !origPub.Equal(edPub) {
		t.Error("keys don't match")
	}
}

func TestJWK_Thumbprint_EC(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint() error = %v", err)
	}

	if thumbprint == "" {
		t.Error("expected non-empty thumbprint")
	}

	// Verify thumbprint is deterministic
	thumbprint2, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint() second call error = %v", err)
	}

	if thumbprint != thumbprint2 {
		t.Error("thumbprint should be deterministic")
	}
}

func TestJWK_Thumbprint_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint() error = %v", err)
	}

	if thumbprint == "" {
		t.Error("expected non-empty thumbprint")
	}
}

func TestJWK_ToJSON(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey, "test-key")
	if err != nil {
		t.Fatalf("PublicKeyToJWK() error = %v", err)
	}

	jsonBytes, err := jwk.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["kty"] != "EC" {
		t.Error("expected kty to be EC in JSON")
	}
}

func TestParseJWK(t *testing.T) {
	jwkJSON := `{
		"kty": "EC",
		"crv": "P-256",
		"x": "WbbgG2sMfQyg9Crm7q8t9w7xOiCJYBz9OlvVJBCm_L4",
		"y": "9wO4Hag9_-5vEBE2H_O8XR8-n1iZPtXR3-vVLHpF_kk",
		"kid": "test-key"
	}`

	jwk, err := ParseJWK([]byte(jwkJSON))
	if err != nil {
		t.Fatalf("ParseJWK() error = %v", err)
	}

	if jwk.Kty != "EC" {
		t.Errorf("expected Kty EC, got %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("expected Crv P-256, got %s", jwk.Crv)
	}
	if jwk.Kid != "test-key" {
		t.Errorf("expected Kid test-key, got %s", jwk.Kid)
	}
}

func TestParseJWKS(t *testing.T) {
	jwksJSON := `{
		"keys": [
			{
				"kty": "EC",
				"crv": "P-256",
				"x": "WbbgG2sMfQyg9Crm7q8t9w7xOiCJYBz9OlvVJBCm_L4",
				"y": "9wO4Hag9_-5vEBE2H_O8XR8-n1iZPtXR3-vVLHpF_kk",
				"kid": "key1"
			},
			{
				"kty": "EC",
				"crv": "P-256",
				"x": "abc",
				"y": "def",
				"kid": "key2"
			}
		]
	}`

	jwks, err := ParseJWKS([]byte(jwksJSON))
	if err != nil {
		t.Fatalf("ParseJWKS() error = %v", err)
	}

	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "key1" {
		t.Errorf("expected first key Kid to be key1, got %s", jwks.Keys[0].Kid)
	}
}

func TestJWKS_FindKey(t *testing.T) {
	jwks := &JWKS{
		Keys: []JWK{
			{Kty: "EC", Kid: "key1"},
			{Kty: "EC", Kid: "key2"},
		},
	}

	key := jwks.FindKey("key1")
	if key == nil {
		t.Fatal("expected to find key1")
	}
	if key.Kid != "key1" {
		t.Errorf("expected Kid key1, got %s", key.Kid)
	}

	key = jwks.FindKey("nonexistent")
	if key != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestJWKToPublicKey_InvalidKeyType(t *testing.T) {
	jwk := &JWK{Kty: "invalid"}

	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

func TestParseJWK_InvalidJSON(t *testing.T) {
	_, err := ParseJWK([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
