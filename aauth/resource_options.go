package aauth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ResourceOption configures a ResourceServer.
type ResourceOption func(*resourceOptions)

type resourceOptions struct {
	// HTTP client for outbound requests
	httpClient *http.Client

	// Signing method for resource tokens
	signingMethod jwt.SigningMethod

	// Resource token TTL
	resourceTokenTTL time.Duration

	// Person server URL
	personServerURL string

	// Access server URL
	accessServerURL string

	// Required scope (optional)
	requiredScope string

	// Allow identity-only mode (no auth token required)
	allowIdentityOnly bool

	// Custom agent token verifier
	agentTokenVerifier TokenVerifier

	// Custom auth token verifier
	authTokenVerifier TokenVerifier

	// JWKS URL for agent token verification
	agentJWKSURL string

	// JWKS URL for auth token verification
	authJWKSURL string

	// Allowed algorithms for verification
	allowedAlgorithms []string

	// Clock skew tolerance
	clockSkew time.Duration
}

func defaultResourceOptions() *resourceOptions {
	return &resourceOptions{
		httpClient:        http.DefaultClient,
		signingMethod:     jwt.SigningMethodES256,
		resourceTokenTTL:  5 * time.Minute,
		allowIdentityOnly: false,
		clockSkew:         1 * time.Minute,
	}
}

// WithResourceHTTPClient sets a custom HTTP client.
func WithResourceHTTPClient(client *http.Client) ResourceOption {
	return func(opts *resourceOptions) {
		opts.httpClient = client
	}
}

// WithResourceSigningMethod sets the signing method for resource tokens.
func WithResourceSigningMethod(method jwt.SigningMethod) ResourceOption {
	return func(opts *resourceOptions) {
		opts.signingMethod = method
	}
}

// WithResourceTokenTTL sets the TTL for resource tokens.
func WithResourceTokenTTL(ttl time.Duration) ResourceOption {
	return func(opts *resourceOptions) {
		opts.resourceTokenTTL = ttl
	}
}

// WithResourcePersonServer sets the person server URL.
func WithResourcePersonServer(url string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.personServerURL = url
	}
}

// WithResourceAccessServer sets the access server URL.
func WithResourceAccessServer(url string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.accessServerURL = url
	}
}

// WithRequiredScope sets the required scope for access.
func WithRequiredScope(scope string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.requiredScope = scope
	}
}

// WithIdentityOnlyMode enables identity-only mode.
func WithIdentityOnlyMode(allow bool) ResourceOption {
	return func(opts *resourceOptions) {
		opts.allowIdentityOnly = allow
	}
}

// WithAgentTokenVerifier sets a custom agent token verifier.
func WithAgentTokenVerifier(verifier TokenVerifier) ResourceOption {
	return func(opts *resourceOptions) {
		opts.agentTokenVerifier = verifier
	}
}

// WithAuthTokenVerifier sets a custom auth token verifier.
func WithAuthTokenVerifier(verifier TokenVerifier) ResourceOption {
	return func(opts *resourceOptions) {
		opts.authTokenVerifier = verifier
	}
}

// WithAgentJWKSURL sets the JWKS URL for agent token verification.
func WithAgentJWKSURL(url string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.agentJWKSURL = url
	}
}

// WithAuthJWKSURL sets the JWKS URL for auth token verification.
func WithAuthJWKSURL(url string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.authJWKSURL = url
	}
}

// WithResourceAllowedAlgorithms sets the allowed verification algorithms.
func WithResourceAllowedAlgorithms(algorithms []string) ResourceOption {
	return func(opts *resourceOptions) {
		opts.allowedAlgorithms = algorithms
	}
}

// WithResourceClockSkew sets the clock skew tolerance.
func WithResourceClockSkew(skew time.Duration) ResourceOption {
	return func(opts *resourceOptions) {
		opts.clockSkew = skew
	}
}
