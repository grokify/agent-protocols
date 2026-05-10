package aauth

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// AAuthScheme is the URI scheme for AAuth identifiers.
	AAuthScheme = "aauth"
)

// localPartRegex validates the local part of an AAuth ID.
// Allowed: lowercase letters, digits, hyphens, underscores, plus signs, periods.
// Maximum length: 255 characters.
var localPartRegex = regexp.MustCompile(`^[a-z0-9\-_+.]{1,255}$`)

// domainRegex validates the domain part of an AAuth ID.
// Simple validation for domain name format.
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+$`)

// AAuthID represents an AAuth agent identifier.
// The format is aauth:local@domain, for example aauth:calendar-bot@example.com.
type AAuthID struct {
	// Local is the local part of the identifier (before @).
	// Must contain only lowercase letters, digits, hyphens, underscores,
	// plus signs, and periods. Maximum 255 characters.
	Local string

	// Domain is the domain part of the identifier (after @).
	// Must be a valid domain name.
	Domain string
}

// ParseAAuthID parses an AAuth identifier string into an AAuthID.
// The expected format is "aauth:local@domain".
func ParseAAuthID(uri string) (*AAuthID, error) {
	// Check for aauth: prefix
	if !strings.HasPrefix(uri, AAuthScheme+":") {
		return nil, fmt.Errorf("%w: missing aauth: scheme", ErrInvalidAAuthID)
	}

	// Extract the identifier part after "aauth:"
	identifier := strings.TrimPrefix(uri, AAuthScheme+":")

	// Split on @ to get local and domain
	atIndex := strings.LastIndex(identifier, "@")
	if atIndex == -1 {
		return nil, fmt.Errorf("%w: missing @ separator", ErrInvalidAAuthID)
	}

	local := identifier[:atIndex]
	domain := identifier[atIndex+1:]

	if local == "" {
		return nil, fmt.Errorf("%w: empty local part", ErrInvalidAAuthID)
	}

	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain part", ErrInvalidAAuthID)
	}

	// Validate local part
	if !localPartRegex.MatchString(local) {
		return nil, fmt.Errorf("%w: invalid local part %q", ErrInvalidAAuthID, local)
	}

	// Validate domain part
	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("%w: invalid domain %q", ErrInvalidAAuthID, domain)
	}

	return &AAuthID{
		Local:  local,
		Domain: domain,
	}, nil
}

// NewAAuthID creates a new AAuthID from local and domain parts.
// Returns an error if either part is invalid.
func NewAAuthID(local, domain string) (*AAuthID, error) {
	if local == "" {
		return nil, fmt.Errorf("%w: empty local part", ErrInvalidAAuthID)
	}

	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain part", ErrInvalidAAuthID)
	}

	if !localPartRegex.MatchString(local) {
		return nil, fmt.Errorf("%w: invalid local part %q", ErrInvalidAAuthID, local)
	}

	if !domainRegex.MatchString(domain) {
		return nil, fmt.Errorf("%w: invalid domain %q", ErrInvalidAAuthID, domain)
	}

	return &AAuthID{
		Local:  local,
		Domain: domain,
	}, nil
}

// String returns the full AAuth URI string (e.g., "aauth:calendar-bot@example.com").
func (id *AAuthID) String() string {
	return fmt.Sprintf("%s:%s@%s", AAuthScheme, id.Local, id.Domain)
}

// AgentProviderURL returns the presumed agent provider URL for this identity.
// The URL is https://{domain}/.well-known/aauth-agent.json.
func (id *AAuthID) AgentProviderURL() string {
	return fmt.Sprintf("https://%s%s", id.Domain, WellKnownAgentPath)
}

// Equals returns true if two AAuthIDs are equal.
func (id *AAuthID) Equals(other *AAuthID) bool {
	if id == nil || other == nil {
		return id == other
	}
	return id.Local == other.Local && id.Domain == other.Domain
}
