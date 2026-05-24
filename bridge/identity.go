package bridge

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// Protocol represents the source protocol of an identity.
type Protocol string

const (
	// ProtocolIDJAG indicates the identity came from an ID-JAG assertion.
	ProtocolIDJAG Protocol = "id-jag"

	// ProtocolAIMS indicates the identity came from an AIMS WIT.
	ProtocolAIMS Protocol = "aims"

	// ProtocolAAuth indicates the identity came from an AAuth agent token.
	ProtocolAAuth Protocol = "aauth"

	// ProtocolUnknown indicates the protocol could not be determined.
	ProtocolUnknown Protocol = "unknown"
)

// Common errors for bridge operations.
var (
	ErrUnsupportedProtocol  = errors.New("unsupported protocol")
	ErrMissingRequiredField = errors.New("missing required field")
	ErrInvalidIdentity      = errors.New("invalid identity")
)

// Identity represents the canonical identity extracted from any protocol.
// This is the common representation that enables cross-protocol bridging.
type Identity struct {
	// Protocol indicates which protocol this identity was extracted from.
	Protocol Protocol

	// Issuer is the entity that issued the token (iss claim).
	Issuer string

	// Subject is the primary identity being asserted (sub claim).
	Subject string

	// Audience is the intended recipient(s) of the token (aud claim).
	Audience []string

	// IssuedAt is when the token was created (iat claim).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (exp claim).
	ExpiresAt time.Time

	// JWTID is the unique token identifier (jti claim).
	JWTID string

	// KeyBinding contains proof-of-possession key information if present.
	// This is extracted from CNF claims in AIMS and AAuth.
	KeyBinding *KeyBinding

	// Actor contains delegation chain information if present.
	// This is extracted from act claims in ID-JAG and AAuth.
	Actor *Actor

	// OriginalClaims preserves protocol-specific claims for reference.
	OriginalClaims map[string]any
}

// KeyBinding represents proof-of-possession key binding information.
type KeyBinding struct {
	// Kid is the key identifier.
	Kid string

	// JWK is the embedded public key in JWK format.
	JWK []byte

	// JKU is the URL to fetch the JWK Set.
	JKU string

	// X5T is the X.509 certificate SHA-256 thumbprint.
	X5T string
}

// Actor represents an actor in a delegation chain (RFC 8693 act claim).
type Actor struct {
	// Subject is the actor's identity.
	Subject string

	// Issuer is the actor's issuer (optional).
	Issuer string

	// Actor is the nested actor for multi-level delegation.
	Actor *Actor
}

// IsExpired returns true if the identity has expired.
func (i *Identity) IsExpired() bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(i.ExpiresAt)
}

// HasKeyBinding returns true if the identity has proof-of-possession binding.
func (i *Identity) HasKeyBinding() bool {
	return i.KeyBinding != nil && (i.KeyBinding.Kid != "" || len(i.KeyBinding.JWK) > 0)
}

// HasDelegation returns true if the identity has a delegation chain.
func (i *Identity) HasDelegation() bool {
	return i.Actor != nil
}

// FromIDJAG extracts a canonical identity from an ID-JAG assertion.
func FromIDJAG(assertion *idjag.Assertion) (*Identity, error) {
	if assertion == nil {
		return nil, ErrInvalidIdentity
	}

	identity := &Identity{
		Protocol:  ProtocolIDJAG,
		Issuer:    assertion.Issuer,
		Subject:   assertion.Subject,
		Audience:  assertion.Audience,
		IssuedAt:  assertion.IssuedAt,
		ExpiresAt: assertion.ExpiresAt,
		JWTID:     assertion.JWTID,
		OriginalClaims: map[string]any{
			"client_id": assertion.ClientID,
		},
	}

	// Convert actor chain if present
	if assertion.Actor != nil {
		identity.Actor = convertIDJAGActor(assertion.Actor)
	}

	return identity, nil
}

// FromWIT extracts a canonical identity from an AIMS Workload Identity Token.
func FromWIT(wit *aims.WorkloadIdentityToken) (*Identity, error) {
	if wit == nil {
		return nil, ErrInvalidIdentity
	}

	identity := &Identity{
		Protocol:  ProtocolAIMS,
		Issuer:    wit.Issuer,
		Subject:   wit.Subject,
		Audience:  wit.Audience,
		IssuedAt:  wit.IssuedAt,
		ExpiresAt: wit.Expiry,
		JWTID:     wit.JWTID,
	}

	// Convert CNF if present
	if wit.CNF != nil {
		identity.KeyBinding = &KeyBinding{
			Kid: wit.CNF.Kid,
			JWK: wit.CNF.JWK,
			X5T: wit.CNF.X5T,
		}
	}

	return identity, nil
}

// FromAAuth extracts a canonical identity from an AAuth agent token.
func FromAAuth(token *aauth.AgentToken) (*Identity, error) {
	if token == nil {
		return nil, ErrInvalidIdentity
	}

	identity := &Identity{
		Protocol:       ProtocolAAuth,
		Issuer:         token.Issuer,
		Subject:        token.Subject,
		Audience:       token.Audience,
		IssuedAt:       token.IssuedAt,
		ExpiresAt:      token.ExpiresAt,
		JWTID:          token.JWTID,
		OriginalClaims: map[string]any{},
	}

	// Convert CNF if present
	if token.CNF != nil {
		identity.KeyBinding = &KeyBinding{
			Kid: token.CNF.Kid,
			JWK: token.CNF.JWK,
			JKU: token.CNF.JKU,
		}
	}

	// Convert actor chain if present
	if token.Actor != nil {
		identity.Actor = convertAAuthActor(token.Actor)
	}

	// Preserve AAuth-specific claims
	if token.DWK != "" {
		identity.OriginalClaims["dwk"] = token.DWK
	}
	if token.PS != "" {
		identity.OriginalClaims["ps"] = token.PS
	}

	return identity, nil
}

// ToIDJAG converts the canonical identity to an ID-JAG assertion.
// The clientID parameter is required for ID-JAG compliance.
func (i *Identity) ToIDJAG(clientID string) (*idjag.Assertion, error) {
	if clientID == "" {
		return nil, ErrMissingRequiredField
	}

	assertion := &idjag.Assertion{
		Issuer:    i.Issuer,
		Subject:   i.Subject,
		Audience:  i.Audience,
		ClientID:  clientID,
		IssuedAt:  i.IssuedAt,
		ExpiresAt: i.ExpiresAt,
		JWTID:     i.JWTID,
	}

	// Convert actor chain if present
	if i.Actor != nil {
		assertion.Actor = convertToIDJAGActor(i.Actor)
	}

	return assertion, nil
}

// ToWIT converts the canonical identity to an AIMS Workload Identity Token.
// The identity's subject should be a valid SPIFFE ID for full AIMS compliance.
func (i *Identity) ToWIT() (*aims.WorkloadIdentityToken, error) {
	wit := &aims.WorkloadIdentityToken{
		Issuer:   i.Issuer,
		Subject:  i.Subject,
		Audience: i.Audience,
		IssuedAt: i.IssuedAt,
		Expiry:   i.ExpiresAt,
		JWTID:    i.JWTID,
	}

	// Convert key binding if present
	if i.KeyBinding != nil {
		wit.CNF = &aims.CNF{
			Kid: i.KeyBinding.Kid,
			JWK: i.KeyBinding.JWK,
			X5T: i.KeyBinding.X5T,
		}
	}

	return wit, nil
}

// ToAAuth converts the canonical identity to an AAuth agent token.
// The cnf parameter provides the required proof-of-possession binding.
func (i *Identity) ToAAuth(cnf *aauth.CNF) (*aauth.AgentToken, error) {
	if cnf == nil {
		return nil, ErrMissingRequiredField
	}

	token := &aauth.AgentToken{
		Issuer:    i.Issuer,
		Subject:   i.Subject,
		Audience:  i.Audience,
		IssuedAt:  i.IssuedAt,
		ExpiresAt: i.ExpiresAt,
		JWTID:     i.JWTID,
		CNF:       cnf,
	}

	// Convert actor chain if present
	if i.Actor != nil {
		token.Actor = convertToAAuthActor(i.Actor)
	}

	// Restore AAuth-specific claims if present
	if dwk, ok := i.OriginalClaims["dwk"].(string); ok {
		token.DWK = dwk
	}
	if ps, ok := i.OriginalClaims["ps"].(string); ok {
		token.PS = ps
	}

	return token, nil
}

// SignIDJAG converts the identity to an ID-JAG assertion and signs it.
func (i *Identity) SignIDJAG(clientID string, signer crypto.Signer, keyID string) (string, error) {
	assertion, err := i.ToIDJAG(clientID)
	if err != nil {
		return "", err
	}
	method := signingMethodForSigner(signer)
	return assertion.Sign(method, signer, keyID)
}

// SignWIT converts the identity to a WIT and signs it.
func (i *Identity) SignWIT(signer crypto.Signer, keyID string) (string, error) {
	wit, err := i.ToWIT()
	if err != nil {
		return "", err
	}
	return wit.Sign(signer, keyID)
}

// SignAAuth converts the identity to an AAuth agent token and signs it.
func (i *Identity) SignAAuth(cnf *aauth.CNF, signer crypto.Signer, keyID string) (string, error) {
	token, err := i.ToAAuth(cnf)
	if err != nil {
		return "", err
	}
	method := signingMethodForSigner(signer)
	return token.Sign(method, signer, keyID)
}

// Helper functions for actor conversion

func convertIDJAGActor(actor *idjag.Actor) *Actor {
	if actor == nil {
		return nil
	}
	return &Actor{
		Subject: actor.Subject,
		Issuer:  actor.Issuer,
		Actor:   convertIDJAGActor(actor.Actor),
	}
}

func convertAAuthActor(actor *aauth.Actor) *Actor {
	if actor == nil {
		return nil
	}
	return &Actor{
		Subject: actor.Subject,
		Issuer:  actor.Issuer,
		Actor:   convertAAuthActor(actor.Actor),
	}
}

func convertToIDJAGActor(actor *Actor) *idjag.Actor {
	if actor == nil {
		return nil
	}
	return &idjag.Actor{
		Subject: actor.Subject,
		Issuer:  actor.Issuer,
		Actor:   convertToIDJAGActor(actor.Actor),
	}
}

func convertToAAuthActor(actor *Actor) *aauth.Actor {
	if actor == nil {
		return nil
	}
	return &aauth.Actor{
		Subject: actor.Subject,
		Issuer:  actor.Issuer,
		Actor:   convertToAAuthActor(actor.Actor),
	}
}

// signingMethodForSigner determines the appropriate JWT signing method for a signer.
func signingMethodForSigner(signer crypto.Signer) jwt.SigningMethod {
	pub := signer.Public()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return jwt.SigningMethodES256
		case 384:
			return jwt.SigningMethodES384
		case 521:
			return jwt.SigningMethodES512
		default:
			return jwt.SigningMethodES256
		}
	case ed25519.PublicKey:
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodES256
	}
}
