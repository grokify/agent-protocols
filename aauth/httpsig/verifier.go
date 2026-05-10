package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Verifier verifies HTTP message signatures per RFC 9421.
type Verifier interface {
	// Verify checks the signature on a request.
	Verify(req *http.Request) (*VerificationResult, error)
}

// VerificationResult contains the result of signature verification.
type VerificationResult struct {
	// Valid is true if the signature verified successfully.
	Valid bool

	// Label is the signature label that was verified.
	Label string

	// Params contains the signature parameters.
	Params *SignatureParams

	// KeyID is the key ID from the signature.
	KeyID string
}

// VerifierOptions configures a Verifier.
type VerifierOptions struct {
	// PublicKey is the key used for verification.
	PublicKey crypto.PublicKey

	// KeyID is the expected key ID (optional, used for matching).
	KeyID string

	// AllowedAlgorithms restricts which algorithms are accepted.
	// If empty, all supported algorithms are allowed.
	AllowedAlgorithms []string

	// RequiredComponents specifies components that must be in the signature.
	// If empty, no specific components are required.
	RequiredComponents []string

	// MaxAge is the maximum age of a signature (based on created time).
	// If zero, no age check is performed.
	MaxAge time.Duration

	// Label specifies which signature to verify (defaults to first signature).
	Label string
}

type verifier struct {
	opts VerifierOptions
}

// NewVerifier creates a new HTTP message signature verifier.
func NewVerifier(opts VerifierOptions) (Verifier, error) {
	if opts.PublicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	return &verifier{opts: opts}, nil
}

// Verify checks the signature on a request.
func (v *verifier) Verify(req *http.Request) (*VerificationResult, error) {
	// Get Signature and Signature-Input headers
	signatureHeader := req.Header.Get("Signature")
	signatureInputHeader := req.Header.Get("Signature-Input")

	if signatureHeader == "" {
		return nil, fmt.Errorf("missing Signature header")
	}
	if signatureInputHeader == "" {
		return nil, fmt.Errorf("missing Signature-Input header")
	}

	// Parse signature input
	sigInputs, err := ParseSignatureInput(signatureInputHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input: %w", err)
	}

	// Determine which signature to verify
	label := v.opts.Label
	if label == "" {
		// Use first signature
		for l := range sigInputs {
			label = l
			break
		}
	}

	params, ok := sigInputs[label]
	if !ok {
		return nil, fmt.Errorf("signature label not found: %s", label)
	}

	// Verify key ID if specified
	if v.opts.KeyID != "" && params.KeyID != v.opts.KeyID {
		return nil, fmt.Errorf("key ID mismatch: expected %s, got %s", v.opts.KeyID, params.KeyID)
	}

	// Verify algorithm is allowed
	if len(v.opts.AllowedAlgorithms) > 0 {
		allowed := false
		for _, alg := range v.opts.AllowedAlgorithms {
			if alg == params.Algorithm {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("algorithm not allowed: %s", params.Algorithm)
		}
	}

	// Verify required components
	if len(v.opts.RequiredComponents) > 0 {
		for _, required := range v.opts.RequiredComponents {
			found := false
			for _, comp := range params.Components {
				if comp == required {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("required component not signed: %s", required)
			}
		}
	}

	// Check age if configured
	if v.opts.MaxAge > 0 {
		age := time.Since(params.Created)
		if age > v.opts.MaxAge {
			return nil, fmt.Errorf("signature too old: %v > %v", age, v.opts.MaxAge)
		}
	}

	// Check expiration if present
	if params.Expires != nil && time.Now().After(*params.Expires) {
		return nil, fmt.Errorf("signature expired")
	}

	// Extract signature value
	signature, err := extractSignature(signatureHeader, label)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signature: %w", err)
	}

	// Rebuild signature base
	signatureBase, err := v.buildSignatureBase(req, params)
	if err != nil {
		return nil, fmt.Errorf("failed to build signature base: %w", err)
	}

	// Verify the signature
	valid, err := v.verify([]byte(signatureBase), signature, params.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return &VerificationResult{
		Valid:  valid,
		Label:  label,
		Params: params,
		KeyID:  params.KeyID,
	}, nil
}

// extractSignature extracts the signature bytes for a given label.
func extractSignature(header, label string) ([]byte, error) {
	// Format: sig1=:base64:, sig2=:base64:
	// Split by comma to handle multiple signatures
	parts := splitSignatures(header)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, "=")
		if idx == -1 {
			continue
		}

		sigLabel := part[:idx]
		if sigLabel != label {
			continue
		}

		// Extract the base64 value between : markers
		value := part[idx+1:]
		if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
			return nil, fmt.Errorf("invalid signature format for label %s", label)
		}

		b64 := value[1 : len(value)-1]
		return base64.StdEncoding.DecodeString(b64)
	}

	return nil, fmt.Errorf("signature not found for label: %s", label)
}

// buildSignatureBase recreates the signature base for verification.
func (v *verifier) buildSignatureBase(req *http.Request, params *SignatureParams) (string, error) {
	var lines []string

	for _, component := range params.Components {
		value, err := DeriveComponent(req, component)
		if err != nil {
			return "", fmt.Errorf("failed to derive component %s: %w", component, err)
		}

		line := formatSignatureBaseLine(component, value)
		lines = append(lines, line)
	}

	// Add @signature-params as the last line
	lines = append(lines, "\"@signature-params\": "+params.Serialize())

	return strings.Join(lines, "\n"), nil
}

// verify performs the cryptographic verification.
func (v *verifier) verify(data, signature []byte, algorithm string) (bool, error) {
	switch algorithm {
	case "ecdsa-p256-sha256":
		return v.verifyECDSA(data, signature, sha256.New())
	case "ecdsa-p384-sha384":
		return v.verifyECDSA(data, signature, sha512.New384())
	case "rsa-pss-sha256":
		return v.verifyRSAPSS(data, signature, crypto.SHA256)
	case "rsa-pss-sha384":
		return v.verifyRSAPSS(data, signature, crypto.SHA384)
	case "rsa-pss-sha512":
		return v.verifyRSAPSS(data, signature, crypto.SHA512)
	case "rsa-v1_5-sha256":
		return v.verifyRSAPKCS1(data, signature, crypto.SHA256)
	case "ed25519":
		return v.verifyEd25519(data, signature)
	default:
		return false, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// verifyECDSA verifies an ECDSA signature.
func (v *verifier) verifyECDSA(data, signature []byte, h hash.Hash) (bool, error) {
	key, ok := v.opts.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not ECDSA")
	}

	h.Write(data)
	digest := h.Sum(nil)

	// Parse P1363 format signature
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*byteLen {
		return false, fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:byteLen])
	s := new(big.Int).SetBytes(signature[byteLen:])

	return ecdsa.Verify(key, digest, r, s), nil
}

// verifyRSAPSS verifies an RSA-PSS signature.
func (v *verifier) verifyRSAPSS(data, signature []byte, hashType crypto.Hash) (bool, error) {
	key, ok := v.opts.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not RSA")
	}

	h := hashType.New()
	h.Write(data)
	digest := h.Sum(nil)

	err := rsa.VerifyPSS(key, hashType, digest, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	return err == nil, nil
}

// verifyRSAPKCS1 verifies an RSA PKCS#1 v1.5 signature.
func (v *verifier) verifyRSAPKCS1(data, signature []byte, hashType crypto.Hash) (bool, error) {
	key, ok := v.opts.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not RSA")
	}

	h := hashType.New()
	h.Write(data)
	digest := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(key, hashType, digest, signature)
	return err == nil, nil
}

// verifyEd25519 verifies an Ed25519 signature.
func (v *verifier) verifyEd25519(data, signature []byte) (bool, error) {
	key, ok := v.opts.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not Ed25519")
	}

	return ed25519.Verify(key, data, signature), nil
}

// KeyResolver resolves public keys by key ID.
type KeyResolver interface {
	// ResolveKey returns the public key for a given key ID.
	ResolveKey(keyID string) (crypto.PublicKey, error)
}

// KeyResolverVerifier is a verifier that uses a KeyResolver to find keys.
type KeyResolverVerifier struct {
	Resolver           KeyResolver
	AllowedAlgorithms  []string
	RequiredComponents []string
	MaxAge             time.Duration
}

// Verify verifies a request using the key resolver to find the appropriate key.
func (v *KeyResolverVerifier) Verify(req *http.Request) (*VerificationResult, error) {
	// Parse signature input first to get key ID
	signatureInputHeader := req.Header.Get("Signature-Input")
	if signatureInputHeader == "" {
		return nil, fmt.Errorf("missing Signature-Input header")
	}

	sigInputs, err := ParseSignatureInput(signatureInputHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input: %w", err)
	}

	// Use first signature
	var label string
	var params *SignatureParams
	for l, p := range sigInputs {
		label = l
		params = p
		break
	}

	if params == nil {
		return nil, fmt.Errorf("no signature found")
	}

	// Resolve the public key
	publicKey, err := v.Resolver.ResolveKey(params.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key: %w", err)
	}

	// Create a verifier with the resolved key
	verifierOpts := VerifierOptions{
		PublicKey:          publicKey,
		KeyID:              params.KeyID,
		AllowedAlgorithms:  v.AllowedAlgorithms,
		RequiredComponents: v.RequiredComponents,
		MaxAge:             v.MaxAge,
		Label:              label,
	}

	ver, err := NewVerifier(verifierOpts)
	if err != nil {
		return nil, err
	}

	return ver.Verify(req)
}
