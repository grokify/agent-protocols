package aauth

// Standard JWT claim names per RFC 7519.
const (
	ClaimIssuer         = "iss"
	ClaimSubject        = "sub"
	ClaimAudience       = "aud"
	ClaimExpirationTime = "exp"
	ClaimNotBefore      = "nbf"
	ClaimIssuedAt       = "iat"
	ClaimJWTID          = "jti"
)

// AAuth-specific claim names.
const (
	// ClaimCNF is the confirmation claim for proof-of-possession keys (RFC 7800).
	ClaimCNF = "cnf"

	// ClaimActor is the actor claim for delegation chains (RFC 8693).
	ClaimActor = "act"

	// ClaimDWK is the delegate well-known URL for the agent provider.
	ClaimDWK = "dwk"

	// ClaimAgentJKT is the JWK thumbprint of the agent's key.
	ClaimAgentJKT = "agent_jkt"

	// ClaimAgent is the agent identifier in a resource token.
	ClaimAgent = "agent"

	// ClaimScope is the authorized scope.
	ClaimScope = "scope"

	// ClaimMission contains mission-specific claims.
	ClaimMission = "mission"

	// ClaimPS is the person server URL.
	ClaimPS = "ps"

	// ClaimMayAct indicates the entity may act on behalf of another.
	ClaimMayAct = "may_act"
)

// CNF sub-claims for key confirmation.
const (
	// CNFClaimJWK contains an embedded JWK public key.
	CNFClaimJWK = "jwk"

	// CNFClaimJKU contains a URL to a JWK Set.
	CNFClaimJKU = "jku"

	// CNFClaimKID contains a key ID for key lookup.
	CNFClaimKID = "kid"
)

// Token type identifiers as used in the typ header.
// nolint:gosec // These are token type identifiers, not credentials
const (
	// TokenTypeAgentJWT is the type for agent tokens.
	TokenTypeAgentJWT = "aa-agent+jwt"

	// TokenTypeAuthJWT is the type for authorization tokens.
	TokenTypeAuthJWT = "aa-auth+jwt"

	// TokenTypeResourceJWT is the type for resource tokens.
	TokenTypeResourceJWT = "aa-resource+jwt"
)

// Grant types for token exchange.
// nolint:gosec
const (
	// GrantTypeTokenExchange is the RFC 8693 token exchange grant type.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Token type URIs for token exchange.
// nolint:gosec
const (
	// TokenTypeURIAgentJWT is the URI for agent token type in token exchange.
	TokenTypeURIAgentJWT = "urn:ietf:params:oauth:token-type:aa-agent+jwt"

	// TokenTypeURIAuthJWT is the URI for auth token type in token exchange.
	TokenTypeURIAuthJWT = "urn:ietf:params:oauth:token-type:aa-auth+jwt"

	// TokenTypeURIResourceJWT is the URI for resource token type in token exchange.
	TokenTypeURIResourceJWT = "urn:ietf:params:oauth:token-type:aa-resource+jwt"
)

// Signing algorithms supported by AAuth.
const (
	// AlgorithmES256 is ECDSA using P-256 and SHA-256.
	AlgorithmES256 = "ES256"

	// AlgorithmES384 is ECDSA using P-384 and SHA-384.
	AlgorithmES384 = "ES384"

	// AlgorithmES512 is ECDSA using P-521 and SHA-512.
	AlgorithmES512 = "ES512"

	// AlgorithmRS256 is RSASSA-PKCS1-v1_5 using SHA-256.
	AlgorithmRS256 = "RS256"

	// AlgorithmRS384 is RSASSA-PKCS1-v1_5 using SHA-384.
	AlgorithmRS384 = "RS384"

	// AlgorithmRS512 is RSASSA-PKCS1-v1_5 using SHA-512.
	AlgorithmRS512 = "RS512"

	// AlgorithmPS256 is RSASSA-PSS using SHA-256.
	AlgorithmPS256 = "PS256"

	// AlgorithmPS384 is RSASSA-PSS using SHA-384.
	AlgorithmPS384 = "PS384"

	// AlgorithmPS512 is RSASSA-PSS using SHA-512.
	AlgorithmPS512 = "PS512"

	// AlgorithmEdDSA is Edwards-curve Digital Signature Algorithm.
	AlgorithmEdDSA = "EdDSA"
)

// HTTP signature algorithms per RFC 9421.
const (
	// HTTPSigAlgorithmECDSAP256SHA256 is ECDSA using P-256 and SHA-256.
	HTTPSigAlgorithmECDSAP256SHA256 = "ecdsa-p256-sha256"

	// HTTPSigAlgorithmECDSAP384SHA384 is ECDSA using P-384 and SHA-384.
	HTTPSigAlgorithmECDSAP384SHA384 = "ecdsa-p384-sha384"

	// HTTPSigAlgorithmRSAPSSSHA256 is RSASSA-PSS using SHA-256.
	HTTPSigAlgorithmRSAPSSSHA256 = "rsa-pss-sha256"

	// HTTPSigAlgorithmRSAPSSSHA384 is RSASSA-PSS using SHA-384.
	HTTPSigAlgorithmRSAPSSSHA384 = "rsa-pss-sha384"

	// HTTPSigAlgorithmRSAPSSSHA512 is RSASSA-PSS using SHA-512.
	HTTPSigAlgorithmRSAPSSSHA512 = "rsa-pss-sha512"

	// HTTPSigAlgorithmRSAv15SHA256 is RSASSA-PKCS1-v1_5 using SHA-256.
	HTTPSigAlgorithmRSAv15SHA256 = "rsa-v1_5-sha256"

	// HTTPSigAlgorithmEdDSA is Ed25519.
	HTTPSigAlgorithmEdDSA = "ed25519"
)

// Well-known metadata paths.
const (
	// WellKnownAgentPath is the path for agent provider metadata.
	WellKnownAgentPath = "/.well-known/aauth-agent.json"

	// WellKnownResourcePath is the path for resource metadata.
	WellKnownResourcePath = "/.well-known/aauth-resource.json"

	// WellKnownPersonPath is the path for person server metadata.
	WellKnownPersonPath = "/.well-known/aauth-person.json"

	// WellKnownAccessPath is the path for access server metadata.
	WellKnownAccessPath = "/.well-known/aauth-access.json"
)

// HTTP headers used in AAuth.
const (
	// HeaderAuthorization is the standard Authorization header.
	HeaderAuthorization = "Authorization"

	// HeaderSignature is the HTTP Message Signatures header (RFC 9421).
	HeaderSignature = "Signature"

	// HeaderSignatureInput is the signature parameters header (RFC 9421).
	HeaderSignatureInput = "Signature-Input"

	// HeaderSignatureKey is the AAuth signature key header.
	HeaderSignatureKey = "Signature-Key"

	// HeaderContentDigest is the content digest header (RFC 9530).
	HeaderContentDigest = "Content-Digest"

	// HeaderWWWAuthenticate is the WWW-Authenticate challenge header.
	HeaderWWWAuthenticate = "WWW-Authenticate"
)

// Signature-Key scheme values.
const (
	// SignatureKeySchemeJWT indicates the key is provided as a JWT.
	SignatureKeySchemeJWT = "jwt"
)
