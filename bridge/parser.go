package bridge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
)

// JWT typ header values for protocol detection.
//
//nolint:gosec // G101: These are JWT type headers, not credentials
const (
	TypIDJAG = "oauth-id-jag+jwt"
	TypWIT   = "wimse-id+jwt"
	TypWPT   = "wimse-proof+jwt"
	TypAAuth = "aa-agent+jwt"
)

// Parser errors.
var (
	ErrInvalidJWT      = errors.New("invalid JWT format")
	ErrUnknownProtocol = errors.New("unknown protocol")
	ErrParsingFailed   = errors.New("token parsing failed")
)

// ParseResult contains the result of parsing a token.
type ParseResult struct {
	// Protocol is the detected protocol.
	Protocol Protocol

	// Identity is the canonical identity extracted from the token.
	Identity *Identity

	// IDJAGAssertion is the parsed ID-JAG assertion (if Protocol == ProtocolIDJAG).
	IDJAGAssertion *idjag.Assertion

	// WIT is the parsed AIMS WIT (if Protocol == ProtocolAIMS).
	WIT *aims.WorkloadIdentityToken

	// AAuthToken is the parsed AAuth agent token (if Protocol == ProtocolAAuth).
	AAuthToken *aauth.AgentToken
}

// Parse attempts to parse a JWT token and detect its protocol.
// This parses without verification - use Verify methods for secure validation.
func Parse(tokenString string) (*ParseResult, error) {
	// Detect protocol from JWT header
	protocol, err := DetectProtocol(tokenString)
	if err != nil {
		return nil, err
	}

	result := &ParseResult{
		Protocol: protocol,
	}

	// Parse based on detected protocol
	switch protocol {
	case ProtocolIDJAG:
		assertion, err := idjag.ParseAssertion(tokenString)
		if err != nil {
			return nil, errors.Join(ErrParsingFailed, err)
		}
		result.IDJAGAssertion = assertion
		result.Identity, err = FromIDJAG(assertion)
		if err != nil {
			return nil, err
		}

	case ProtocolAIMS:
		wit, err := aims.ParseWIT(tokenString)
		if err != nil {
			return nil, errors.Join(ErrParsingFailed, err)
		}
		result.WIT = wit
		result.Identity, err = FromWIT(wit)
		if err != nil {
			return nil, err
		}

	case ProtocolAAuth:
		token, err := aauth.ParseAgentToken(tokenString)
		if err != nil {
			return nil, errors.Join(ErrParsingFailed, err)
		}
		result.AAuthToken = token
		result.Identity, err = FromAAuth(token)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnknownProtocol
	}

	return result, nil
}

// DetectProtocol examines a JWT token and returns its protocol.
func DetectProtocol(tokenString string) (Protocol, error) {
	header, err := extractJWTHeader(tokenString)
	if err != nil {
		return ProtocolUnknown, err
	}

	typ, _ := header["typ"].(string)

	switch typ {
	case TypIDJAG:
		return ProtocolIDJAG, nil
	case TypWIT:
		return ProtocolAIMS, nil
	case TypAAuth:
		return ProtocolAAuth, nil
	case "JWT", "":
		// No specific typ - try to detect from claims
		return detectFromClaims(tokenString)
	default:
		return ProtocolUnknown, nil
	}
}

// extractJWTHeader extracts the header from a JWT token.
func extractJWTHeader(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Try standard base64 with padding
		headerBytes, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, ErrInvalidJWT
		}
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidJWT
	}

	return header, nil
}

// extractJWTClaims extracts the claims from a JWT token.
func extractJWTClaims(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 with padding
		claimsBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, ErrInvalidJWT
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidJWT
	}

	return claims, nil
}

// detectFromClaims attempts to detect the protocol from JWT claims.
func detectFromClaims(tokenString string) (Protocol, error) {
	claims, err := extractJWTClaims(tokenString)
	if err != nil {
		return ProtocolUnknown, err
	}

	// Check for protocol-specific claims
	sub, _ := claims["sub"].(string)

	// ID-JAG: has client_id claim (required)
	if _, hasClientID := claims["client_id"]; hasClientID {
		return ProtocolIDJAG, nil
	}

	// AIMS: subject is SPIFFE ID
	if strings.HasPrefix(sub, "spiffe://") {
		return ProtocolAIMS, nil
	}

	// AAuth: has cnf claim and aauth: prefix in subject
	if _, hasCNF := claims["cnf"]; hasCNF {
		if strings.HasPrefix(sub, "aauth:") {
			return ProtocolAAuth, nil
		}
		// Could be AIMS with CNF
		return ProtocolAIMS, nil
	}

	// AAuth: has dwk or ps claims
	if _, hasDWK := claims["dwk"]; hasDWK {
		return ProtocolAAuth, nil
	}
	if _, hasPS := claims["ps"]; hasPS {
		return ProtocolAAuth, nil
	}

	return ProtocolUnknown, nil
}

// MustParse is like Parse but panics on error.
// Use only in tests or when the token is known to be valid.
func MustParse(tokenString string) *ParseResult {
	result, err := Parse(tokenString)
	if err != nil {
		panic(err)
	}
	return result
}

// IsIDJAG returns true if the token is an ID-JAG assertion.
func IsIDJAG(tokenString string) bool {
	protocol, err := DetectProtocol(tokenString)
	return err == nil && protocol == ProtocolIDJAG
}

// IsWIT returns true if the token is an AIMS WIT.
func IsWIT(tokenString string) bool {
	protocol, err := DetectProtocol(tokenString)
	return err == nil && protocol == ProtocolAIMS
}

// IsAAuth returns true if the token is an AAuth agent token.
func IsAAuth(tokenString string) bool {
	protocol, err := DetectProtocol(tokenString)
	return err == nil && protocol == ProtocolAAuth
}
