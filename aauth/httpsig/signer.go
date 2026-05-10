package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strings"
)

// Signer signs HTTP requests per RFC 9421.
type Signer interface {
	// Sign adds Signature and Signature-Input headers to the request.
	Sign(req *http.Request) error
}

// SignerOptions configures a Signer.
type SignerOptions struct {
	// PrivateKey is the key used for signing.
	PrivateKey crypto.PrivateKey

	// KeyID is the identifier for the signing key.
	KeyID string

	// Algorithm is the HTTP signature algorithm identifier.
	// Supported: ecdsa-p256-sha256, ecdsa-p384-sha384, rsa-pss-sha256, ed25519
	Algorithm string

	// CoveredComponents is the list of components to include in the signature.
	// Defaults to DefaultCoveredComponents if not specified.
	CoveredComponents []string

	// Label is the signature label (defaults to "sig1").
	Label string

	// IncludeNonce adds a nonce to signatures for replay protection.
	IncludeNonce bool
}

type signer struct {
	opts SignerOptions
}

// NewSigner creates a new HTTP message signer.
func NewSigner(opts SignerOptions) (Signer, error) {
	if opts.PrivateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	if opts.KeyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}

	if opts.Algorithm == "" {
		// Infer algorithm from key type
		switch opts.PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			opts.Algorithm = "ecdsa-p256-sha256"
		case *rsa.PrivateKey:
			opts.Algorithm = "rsa-pss-sha256"
		case ed25519.PrivateKey:
			opts.Algorithm = "ed25519"
		default:
			return nil, fmt.Errorf("cannot infer algorithm for key type %T", opts.PrivateKey)
		}
	}

	if len(opts.CoveredComponents) == 0 {
		opts.CoveredComponents = DefaultCoveredComponents
	}

	if opts.Label == "" {
		opts.Label = "sig1"
	}

	return &signer{opts: opts}, nil
}

// Sign adds the Signature and Signature-Input headers to the request.
func (s *signer) Sign(req *http.Request) error {
	// Create signature parameters
	params := DefaultSignatureParams(s.opts.KeyID, s.opts.Algorithm, s.opts.CoveredComponents)

	if s.opts.IncludeNonce {
		nonce, err := generateNonce()
		if err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}
		params.Nonce = nonce
	}

	// Build the signature base
	signatureBase, err := s.buildSignatureBase(req, params)
	if err != nil {
		return fmt.Errorf("failed to build signature base: %w", err)
	}

	// Sign the base
	signature, err := s.sign([]byte(signatureBase))
	if err != nil {
		return fmt.Errorf("failed to sign: %w", err)
	}

	// Add headers
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	signatureInput := FormatSignatureInput(s.opts.Label, params)

	req.Header.Set("Signature", s.opts.Label+"=:"+signatureB64+":")
	req.Header.Set("Signature-Input", signatureInput)

	return nil
}

// buildSignatureBase creates the signature base string per RFC 9421.
func (s *signer) buildSignatureBase(req *http.Request, params *SignatureParams) (string, error) {
	var lines []string

	for _, component := range params.Components {
		value, err := DeriveComponent(req, component)
		if err != nil {
			return "", fmt.Errorf("failed to derive component %s: %w", component, err)
		}

		// Format: "component-id": value
		line := formatSignatureBaseLine(component, value)
		lines = append(lines, line)
	}

	// Add @signature-params as the last line
	lines = append(lines, "\"@signature-params\": "+params.Serialize())

	return strings.Join(lines, "\n"), nil
}

// formatSignatureBaseLine formats a single line of the signature base.
func formatSignatureBaseLine(component, value string) string {
	// Normalize component name
	if strings.HasPrefix(component, "@") {
		return "\"" + component + "\": " + value
	}
	return "\"" + strings.ToLower(component) + "\": " + value
}

// sign creates the cryptographic signature.
func (s *signer) sign(data []byte) ([]byte, error) {
	switch s.opts.Algorithm {
	case "ecdsa-p256-sha256":
		return s.signECDSA(data, sha256.New())
	case "ecdsa-p384-sha384":
		return s.signECDSA(data, sha512.New384())
	case "rsa-pss-sha256":
		return s.signRSAPSS(data, crypto.SHA256)
	case "rsa-pss-sha384":
		return s.signRSAPSS(data, crypto.SHA384)
	case "rsa-pss-sha512":
		return s.signRSAPSS(data, crypto.SHA512)
	case "rsa-v1_5-sha256":
		return s.signRSAPKCS1(data, crypto.SHA256)
	case "ed25519":
		return s.signEd25519(data)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.opts.Algorithm)
	}
}

// signECDSA creates an ECDSA signature.
func (s *signer) signECDSA(data []byte, h hash.Hash) ([]byte, error) {
	key, ok := s.opts.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}

	h.Write(data)
	digest := h.Sum(nil)

	r, ss, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	// Encode as P1363 format (r || s, both padded to curve size)
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := ss.Bytes()
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)

	return sig, nil
}

// signRSAPSS creates an RSA-PSS signature.
func (s *signer) signRSAPSS(data []byte, hashType crypto.Hash) ([]byte, error) {
	key, ok := s.opts.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	h := hashType.New()
	h.Write(data)
	digest := h.Sum(nil)

	return rsa.SignPSS(rand.Reader, key, hashType, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

// signRSAPKCS1 creates an RSA PKCS#1 v1.5 signature.
func (s *signer) signRSAPKCS1(data []byte, hashType crypto.Hash) ([]byte, error) {
	key, ok := s.opts.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	h := hashType.New()
	h.Write(data)
	digest := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, key, hashType, digest)
}

// signEd25519 creates an Ed25519 signature.
func (s *signer) signEd25519(data []byte) ([]byte, error) {
	key, ok := s.opts.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return ed25519.Sign(key, data), nil
}

// generateNonce generates a random nonce for replay protection.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
