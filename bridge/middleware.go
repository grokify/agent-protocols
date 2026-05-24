package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/aims"
	"github.com/aistandardsio/agent-protocols/idjag"
)

// Context keys for storing identity information.
type contextKey string

const (
	// IdentityContextKey is the context key for the canonical identity.
	IdentityContextKey contextKey = "bridge.identity"

	// ProtocolContextKey is the context key for the detected protocol.
	ProtocolContextKey contextKey = "bridge.protocol"
)

// Common middleware errors.
var (
	ErrNoToken            = errors.New("no authentication token found")
	ErrVerificationFailed = errors.New("token verification failed")
	ErrNoVerifier         = errors.New("no verifier configured for protocol")
)

// IDJAGVerifier verifies ID-JAG assertions.
type IDJAGVerifier interface {
	Verify(ctx context.Context, tokenString string) (*idjag.Assertion, error)
}

// WITVerifier verifies AIMS Workload Identity Tokens.
type WITVerifier interface {
	Verify(tokenString string) (*aims.WorkloadIdentityToken, error)
}

// AAuthVerifier verifies AAuth agent tokens.
type AAuthVerifier interface {
	VerifyAgentToken(ctx context.Context, tokenString string) (*aauth.AgentToken, error)
}

// MiddlewareConfig holds configuration for multi-protocol middleware.
type MiddlewareConfig struct {
	// IDJAGVerifier verifies ID-JAG assertions.
	IDJAGVerifier IDJAGVerifier

	// WITVerifier verifies AIMS WITs.
	WITVerifier WITVerifier

	// AAuthVerifier verifies AAuth agent tokens.
	AAuthVerifier AAuthVerifier

	// OnError is called when verification fails.
	// If nil, a 401 response is returned.
	OnError func(w http.ResponseWriter, r *http.Request, err error)

	// RequireKeyBinding requires proof-of-possession for all protocols.
	RequireKeyBinding bool

	// AllowedProtocols limits which protocols are accepted.
	// If empty, all configured protocols are allowed.
	AllowedProtocols []Protocol
}

// MiddlewareOption configures the middleware.
type MiddlewareOption func(*MiddlewareConfig)

// WithIDJAGVerifier sets the ID-JAG verifier.
func WithIDJAGVerifier(v IDJAGVerifier) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.IDJAGVerifier = v
	}
}

// WithWITVerifier sets the AIMS WIT verifier.
func WithWITVerifier(v WITVerifier) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.WITVerifier = v
	}
}

// WithAAuthVerifier sets the AAuth verifier.
func WithAAuthVerifier(v AAuthVerifier) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.AAuthVerifier = v
	}
}

// WithErrorHandler sets a custom error handler.
func WithErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error)) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.OnError = handler
	}
}

// WithRequireKeyBinding requires proof-of-possession binding.
func WithRequireKeyBinding() MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.RequireKeyBinding = true
	}
}

// WithAllowedProtocols limits which protocols are accepted.
func WithAllowedProtocols(protocols ...Protocol) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.AllowedProtocols = protocols
	}
}

// MultiProtocolMiddleware creates HTTP middleware that accepts any configured protocol.
//
// The middleware detects the protocol from request headers:
//   - Authorization: Bearer <token> with typ=oauth-id-jag+jwt → ID-JAG
//   - Workload-Identity-Token header → AIMS
//   - Signature-Key header → AAuth
//
// On success, the canonical [Identity] is stored in the request context.
func MultiProtocolMiddleware(opts ...MiddlewareOption) func(http.Handler) http.Handler {
	config := &MiddlewareConfig{}
	for _, opt := range opts {
		opt(config)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, protocol, err := extractAndVerify(r, config)
			if err != nil {
				handleError(w, r, err, config)
				return
			}

			// Check if protocol is allowed
			if len(config.AllowedProtocols) > 0 {
				allowed := false
				for _, p := range config.AllowedProtocols {
					if p == protocol {
						allowed = true
						break
					}
				}
				if !allowed {
					handleError(w, r, ErrUnsupportedProtocol, config)
					return
				}
			}

			// Check key binding requirement
			if config.RequireKeyBinding && !identity.HasKeyBinding() {
				handleError(w, r, errors.New("proof-of-possession required"), config)
				return
			}

			// Store identity in context
			ctx := context.WithValue(r.Context(), IdentityContextKey, identity)
			ctx = context.WithValue(ctx, ProtocolContextKey, protocol)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IdentityFromContext retrieves the canonical identity from context.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(IdentityContextKey).(*Identity)
	return identity, ok
}

// ProtocolFromContext retrieves the detected protocol from context.
func ProtocolFromContext(ctx context.Context) Protocol {
	protocol, ok := ctx.Value(ProtocolContextKey).(Protocol)
	if !ok {
		return ProtocolUnknown
	}
	return protocol
}

// extractAndVerify attempts to extract and verify a token from the request.
func extractAndVerify(r *http.Request, config *MiddlewareConfig) (*Identity, Protocol, error) {
	ctx := r.Context()

	// Try AAuth first (most specific headers - Signature-Key)
	if signatureKey := r.Header.Get(aauth.HeaderSignatureKey); signatureKey != "" {
		if config.AAuthVerifier == nil {
			return nil, ProtocolAAuth, ErrNoVerifier
		}
		token, err := config.AAuthVerifier.VerifyAgentToken(ctx, signatureKey)
		if err != nil {
			return nil, ProtocolAAuth, err
		}
		identity, err := FromAAuth(token)
		if err != nil {
			return nil, ProtocolAAuth, err
		}
		return identity, ProtocolAAuth, nil
	}

	// Try Authorization Bearer header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Detect protocol from JWT typ header or claims
		protocol, _ := DetectProtocol(tokenString)

		switch protocol {
		case ProtocolIDJAG:
			if config.IDJAGVerifier == nil {
				return nil, ProtocolIDJAG, ErrNoVerifier
			}
			assertion, err := config.IDJAGVerifier.Verify(ctx, tokenString)
			if err != nil {
				return nil, ProtocolIDJAG, err
			}
			identity, err := FromIDJAG(assertion)
			if err != nil {
				return nil, ProtocolIDJAG, err
			}
			return identity, ProtocolIDJAG, nil

		case ProtocolAIMS:
			if config.WITVerifier == nil {
				return nil, ProtocolAIMS, ErrNoVerifier
			}
			wit, err := config.WITVerifier.Verify(tokenString)
			if err != nil {
				return nil, ProtocolAIMS, err
			}
			identity, err := FromWIT(wit)
			if err != nil {
				return nil, ProtocolAIMS, err
			}
			return identity, ProtocolAIMS, nil

		case ProtocolAAuth:
			if config.AAuthVerifier == nil {
				return nil, ProtocolAAuth, ErrNoVerifier
			}
			token, err := config.AAuthVerifier.VerifyAgentToken(ctx, tokenString)
			if err != nil {
				return nil, ProtocolAAuth, err
			}
			identity, err := FromAAuth(token)
			if err != nil {
				return nil, ProtocolAAuth, err
			}
			return identity, ProtocolAAuth, nil

		default:
			// Unknown protocol - try each verifier in order
			if config.IDJAGVerifier != nil {
				if assertion, err := config.IDJAGVerifier.Verify(ctx, tokenString); err == nil {
					if identity, err := FromIDJAG(assertion); err == nil {
						return identity, ProtocolIDJAG, nil
					}
				}
			}
			if config.WITVerifier != nil {
				if wit, err := config.WITVerifier.Verify(tokenString); err == nil {
					if identity, err := FromWIT(wit); err == nil {
						return identity, ProtocolAIMS, nil
					}
				}
			}
		}
	}

	return nil, ProtocolUnknown, ErrNoToken
}

// handleError handles authentication errors.
func handleError(w http.ResponseWriter, r *http.Request, err error, config *MiddlewareConfig) {
	if config.OnError != nil {
		config.OnError(w, r, err)
		return
	}

	// Default error handling with proper JSON encoding
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	response := map[string]string{
		"error":   "unauthorized",
		"message": err.Error(),
	}
	//nolint:errcheck // Best effort error response
	json.NewEncoder(w).Encode(response)
}
