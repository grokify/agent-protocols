package aauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
)

// CNF represents the confirmation claim for proof-of-possession (RFC 7800).
// It binds a token to a specific cryptographic key.
type CNF struct {
	// JWK contains the embedded public key (mutually exclusive with JKU/Kid).
	JWK json.RawMessage `json:"jwk,omitempty"`

	// JKU is a URL pointing to a JWK Set containing the key.
	JKU string `json:"jku,omitempty"`

	// Kid is the key ID for key lookup within a JWKS.
	Kid string `json:"kid,omitempty"`
}

// NewCNFWithJWK creates a CNF with an embedded JWK from a public key.
func NewCNFWithJWK(pub crypto.PublicKey, keyID string) (*CNF, error) {
	jwk, err := PublicKeyToJWK(pub, keyID)
	if err != nil {
		return nil, err
	}

	jwkJSON, err := jwk.ToJSON()
	if err != nil {
		return nil, err
	}

	return &CNF{
		JWK: jwkJSON,
	}, nil
}

// NewCNFWithJKU creates a CNF with a JWK Set URL reference.
func NewCNFWithJKU(jku string, kid string) *CNF {
	return &CNF{
		JKU: jku,
		Kid: kid,
	}
}

// GetJWK extracts the JWK from the CNF if present.
func (c *CNF) GetJWK() (*JWK, error) {
	if c.JWK == nil {
		return nil, fmt.Errorf("%w: no embedded JWK in CNF", ErrMissingCNF)
	}

	return ParseJWK(c.JWK)
}

// GetPublicKey extracts the public key from the CNF.
// This only works for embedded JWKs; JKU references require separate resolution.
func (c *CNF) GetPublicKey() (crypto.PublicKey, error) {
	jwk, err := c.GetJWK()
	if err != nil {
		return nil, err
	}

	return JWKToPublicKey(jwk)
}

// GetThumbprint computes the JWK thumbprint from the CNF.
func (c *CNF) GetThumbprint() (string, error) {
	jwk, err := c.GetJWK()
	if err != nil {
		return "", err
	}

	return jwk.Thumbprint()
}

// IsEmbedded returns true if the CNF contains an embedded JWK.
func (c *CNF) IsEmbedded() bool {
	return c.JWK != nil
}

// IsReference returns true if the CNF references an external key (JKU).
func (c *CNF) IsReference() bool {
	return c.JKU != ""
}

// KeyPair holds a private/public key pair for signing.
type KeyPair struct {
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	KeyID      string
	Algorithm  string
}

// GenerateECDSAKeyPair generates a new ECDSA key pair.
// Supported curves: P-256 (default), P-384, P-521.
func GenerateECDSAKeyPair(keyID string, curve elliptic.Curve) (*KeyPair, error) {
	if curve == nil {
		curve = elliptic.P256()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	var alg string
	switch curve {
	case elliptic.P256():
		alg = AlgorithmES256
	case elliptic.P384():
		alg = AlgorithmES384
	case elliptic.P521():
		alg = AlgorithmES512
	default:
		return nil, fmt.Errorf("%w: unsupported curve", ErrUnsupportedAlgorithm)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      keyID,
		Algorithm:  alg,
	}, nil
}

// GenerateRSAKeyPair generates a new RSA key pair.
// Key size should be at least 2048 bits.
func GenerateRSAKeyPair(keyID string, bits int) (*KeyPair, error) {
	if bits < 2048 {
		bits = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      keyID,
		Algorithm:  AlgorithmRS256,
	}, nil
}

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
func GenerateEd25519KeyPair(keyID string) (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      keyID,
		Algorithm:  AlgorithmEdDSA,
	}, nil
}

// ToJWK converts the public key to a JWK.
func (kp *KeyPair) ToJWK() (*JWK, error) {
	return PublicKeyToJWK(kp.PublicKey, kp.KeyID)
}

// ToCNF creates a CNF claim from the key pair.
func (kp *KeyPair) ToCNF() (*CNF, error) {
	return NewCNFWithJWK(kp.PublicKey, kp.KeyID)
}

// Thumbprint returns the JWK thumbprint of the public key.
func (kp *KeyPair) Thumbprint() (string, error) {
	jwk, err := kp.ToJWK()
	if err != nil {
		return "", err
	}
	return jwk.Thumbprint()
}

// HTTPSigAlgorithm returns the HTTP signature algorithm for this key pair.
func (kp *KeyPair) HTTPSigAlgorithm() string {
	switch kp.Algorithm {
	case AlgorithmES256:
		return HTTPSigAlgorithmECDSAP256SHA256
	case AlgorithmES384:
		return HTTPSigAlgorithmECDSAP384SHA384
	case AlgorithmRS256:
		return HTTPSigAlgorithmRSAv15SHA256
	case AlgorithmPS256:
		return HTTPSigAlgorithmRSAPSSSHA256
	case AlgorithmPS384:
		return HTTPSigAlgorithmRSAPSSSHA384
	case AlgorithmPS512:
		return HTTPSigAlgorithmRSAPSSSHA512
	case AlgorithmEdDSA:
		return HTTPSigAlgorithmEdDSA
	default:
		return ""
	}
}

// MatchesCNF checks if this key pair matches the given CNF claim.
func (kp *KeyPair) MatchesCNF(cnf *CNF) (bool, error) {
	if cnf == nil {
		return false, nil
	}

	if !cnf.IsEmbedded() {
		// For JKU references, we can only compare by kid
		return cnf.Kid == kp.KeyID, nil
	}

	// Compare thumbprints
	cnfThumbprint, err := cnf.GetThumbprint()
	if err != nil {
		return false, err
	}

	kpThumbprint, err := kp.Thumbprint()
	if err != nil {
		return false, err
	}

	return cnfThumbprint == kpThumbprint, nil
}
