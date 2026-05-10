package aauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key (RFC 7517).
// This struct supports public keys only; private key fields are not included.
type JWK struct {
	// Key type (e.g., "EC", "RSA", "OKP")
	Kty string `json:"kty"`

	// Key ID
	Kid string `json:"kid,omitempty"`

	// Algorithm
	Alg string `json:"alg,omitempty"`

	// Key use (e.g., "sig", "enc")
	Use string `json:"use,omitempty"`

	// EC and OKP fields
	Crv string `json:"crv,omitempty"` // Curve: P-256, P-384, P-521, Ed25519
	X   string `json:"x,omitempty"`   // X coordinate (base64url)
	Y   string `json:"y,omitempty"`   // Y coordinate (base64url, EC only)

	// RSA fields
	N string `json:"n,omitempty"` // Modulus (base64url)
	E string `json:"e,omitempty"` // Exponent (base64url)
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWK converts a crypto.PublicKey to a JWK.
func PublicKeyToJWK(pub crypto.PublicKey, keyID string) (*JWK, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsaPublicKeyToJWK(k, keyID)
	case *rsa.PublicKey:
		return rsaPublicKeyToJWK(k, keyID)
	case ed25519.PublicKey:
		return ed25519PublicKeyToJWK(k, keyID)
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrInvalidJWK, pub)
	}
}

// JWKToPublicKey converts a JWK to a crypto.PublicKey.
func JWKToPublicKey(jwk *JWK) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "EC":
		return jwkToECDSAPublicKey(jwk)
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "OKP":
		return jwkToOKPPublicKey(jwk)
	default:
		return nil, fmt.Errorf("%w: unsupported key type %q", ErrInvalidJWK, jwk.Kty)
	}
}

// Thumbprint computes the JWK thumbprint per RFC 7638.
// Uses SHA-256 and returns the base64url-encoded result.
func (j *JWK) Thumbprint() (string, error) {
	// Build the canonical JSON representation per RFC 7638
	var canonical map[string]string

	switch j.Kty {
	case "EC":
		canonical = map[string]string{
			"crv": j.Crv,
			"kty": j.Kty,
			"x":   j.X,
			"y":   j.Y,
		}
	case "RSA":
		canonical = map[string]string{
			"e":   j.E,
			"kty": j.Kty,
			"n":   j.N,
		}
	case "OKP":
		canonical = map[string]string{
			"crv": j.Crv,
			"kty": j.Kty,
			"x":   j.X,
		}
	default:
		return "", fmt.Errorf("%w: unsupported key type %q for thumbprint", ErrInvalidJWK, j.Kty)
	}

	// Marshal to JSON (Go's map iteration is sorted for string keys)
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("failed to marshal canonical JWK: %w", err)
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(data)

	// Return base64url-encoded thumbprint
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ToJSON returns the JWK as a JSON-encoded byte slice.
func (j *JWK) ToJSON() ([]byte, error) {
	return json.Marshal(j)
}

// ecdsaPublicKeyToJWK converts an ECDSA public key to a JWK.
func ecdsaPublicKeyToJWK(pub *ecdsa.PublicKey, keyID string) (*JWK, error) {
	var crv string
	var alg string

	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
		alg = AlgorithmES256
	case elliptic.P384():
		crv = "P-384"
		alg = AlgorithmES384
	case elliptic.P521():
		crv = "P-521"
		alg = AlgorithmES512
	default:
		return nil, fmt.Errorf("%w: unsupported ECDSA curve", ErrInvalidJWK)
	}

	// Get the byte size for the curve
	byteSize := (pub.Curve.Params().BitSize + 7) / 8

	// Pad X and Y coordinates to the correct byte size
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPadded := make([]byte, byteSize)
	yPadded := make([]byte, byteSize)
	copy(xPadded[byteSize-len(xBytes):], xBytes)
	copy(yPadded[byteSize-len(yBytes):], yBytes)

	return &JWK{
		Kty: "EC",
		Kid: keyID,
		Alg: alg,
		Use: "sig",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}, nil
}

// rsaPublicKeyToJWK converts an RSA public key to a JWK.
func rsaPublicKeyToJWK(pub *rsa.PublicKey, keyID string) (*JWK, error) {
	// Encode the exponent
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	return &JWK{
		Kty: "RSA",
		Kid: keyID,
		Alg: AlgorithmRS256,
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}, nil
}

// ed25519PublicKeyToJWK converts an Ed25519 public key to a JWK.
func ed25519PublicKeyToJWK(pub ed25519.PublicKey, keyID string) (*JWK, error) {
	return &JWK{
		Kty: "OKP",
		Kid: keyID,
		Alg: AlgorithmEdDSA,
		Use: "sig",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}, nil
}

// jwkToECDSAPublicKey converts a JWK to an ECDSA public key.
func jwkToECDSAPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("%w: expected EC key type, got %q", ErrInvalidJWK, jwk.Kty)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: unsupported curve %q", ErrInvalidJWK, jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid x coordinate: %v", ErrInvalidJWK, err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid y coordinate: %v", ErrInvalidJWK, err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("%w: expected RSA key type, got %q", ErrInvalidJWK, jwk.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid n (modulus): %v", ErrInvalidJWK, err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid e (exponent): %v", ErrInvalidJWK, err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Validate exponent fits in int
	if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
		return nil, fmt.Errorf("%w: exponent too large", ErrInvalidJWK)
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// jwkToOKPPublicKey converts a JWK to an OKP public key (Ed25519).
func jwkToOKPPublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" {
		return nil, fmt.Errorf("%w: expected OKP key type, got %q", ErrInvalidJWK, jwk.Kty)
	}

	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: unsupported OKP curve %q", ErrInvalidJWK, jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid x coordinate: %v", ErrInvalidJWK, err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid Ed25519 public key size", ErrInvalidJWK)
	}

	return ed25519.PublicKey(xBytes), nil
}

// ParseJWK parses a JSON-encoded JWK.
func ParseJWK(data []byte) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWK, err)
	}
	return &jwk, nil
}

// ParseJWKS parses a JSON-encoded JWK Set.
func ParseJWKS(data []byte) (*JWKS, error) {
	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWK, err)
	}
	return &jwks, nil
}

// FindKey finds a key in the JWKS by key ID.
func (jwks *JWKS) FindKey(kid string) *JWK {
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid {
			return &jwks.Keys[i]
		}
	}
	return nil
}
