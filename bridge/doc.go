// Package bridge provides cross-protocol bridging for agent-protocols.
//
// The bridge package enables interoperability between the three authentication
// protocols (ID-JAG, AIMS, AAuth) by providing:
//
//   - Canonical identity representation shared across all protocols
//   - Token converters for translating between protocol-specific formats
//   - Multi-protocol middleware for accepting any protocol token
//
// # Canonical Identity
//
// All three protocols share a common set of identity fields that form the
// "canonical identity":
//
//   - Issuer (iss): Entity that issued the token
//   - Subject (sub): Primary identity being asserted
//   - Audience (aud): Intended recipient(s)
//   - IssuedAt (iat): Token creation time
//   - ExpiresAt (exp): Token validity end
//   - JWTID (jti): Unique identifier for replay prevention
//
// The [Identity] type captures these common fields, allowing application code
// to work with a unified identity regardless of which protocol was used.
//
// # Token Conversion
//
// Convert between protocol token types:
//
//	// Extract canonical identity from any token
//	identity, err := bridge.FromIDJAG(assertion)
//	identity, err := bridge.FromWIT(wit)
//	identity, err := bridge.FromAAuth(agentToken)
//
//	// Convert to a different protocol
//	assertion, err := identity.ToIDJAG(clientID)
//	wit, err := identity.ToWIT(spiffeID)
//	agentToken, err := identity.ToAAuth(cnf)
//
// # Multi-Protocol Middleware
//
// Accept any protocol token in HTTP requests:
//
//	handler := bridge.MultiProtocolMiddleware(
//		bridge.WithIDJAGVerifier(idjagVerifier),
//		bridge.WithWITVerifier(witVerifier),
//		bridge.WithAAuthVerifier(aauthorizer),
//	)(protectedHandler)
//
// The middleware detects the protocol from request headers and extracts
// the canonical identity into the request context.
//
// # Protocol Detection
//
// Protocols are detected by examining:
//
//   - JWT typ header: oauth-id-jag+jwt, wimse-id+jwt, aa-agent+jwt
//   - HTTP headers: Authorization Bearer, Workload-Identity-Token, Signature-Key
//
// # Use Cases
//
// Common bridging scenarios:
//
//   - Gateway accepting multiple protocols from different clients
//   - Migration from one protocol to another
//   - Hybrid environments with mixed protocol usage
//   - Protocol translation for legacy system integration
package bridge
