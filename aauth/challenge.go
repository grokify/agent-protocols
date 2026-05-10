package aauth

import (
	"fmt"
	"strings"
)

// Challenge represents an AAuth WWW-Authenticate challenge.
type Challenge struct {
	// Scheme is the authentication scheme (always "AAuth").
	Scheme string

	// Realm is the protection realm.
	Realm string

	// Scope is the required scope (optional).
	Scope string

	// PersonServerURL is the person server URL (optional).
	PersonServerURL string

	// AccessServerURL is the access server URL (optional).
	AccessServerURL string

	// Error is an error code if the challenge is due to an error.
	Error string

	// ErrorDescription is a human-readable error description.
	ErrorDescription string
}

// NewChallenge creates a new AAuth challenge.
func NewChallenge(realm string) *Challenge {
	return &Challenge{
		Scheme: "AAuth",
		Realm:  realm,
	}
}

// WithScope sets the required scope.
func (c *Challenge) WithScope(scope string) *Challenge {
	c.Scope = scope
	return c
}

// WithPersonServer sets the person server URL.
func (c *Challenge) WithPersonServer(url string) *Challenge {
	c.PersonServerURL = url
	return c
}

// WithAccessServer sets the access server URL.
func (c *Challenge) WithAccessServer(url string) *Challenge {
	c.AccessServerURL = url
	return c
}

// WithError sets the error details.
func (c *Challenge) WithError(code, description string) *Challenge {
	c.Error = code
	c.ErrorDescription = description
	return c
}

// String returns the challenge as a WWW-Authenticate header value.
func (c *Challenge) String() string {
	var parts []string

	if c.Realm != "" {
		parts = append(parts, fmt.Sprintf(`realm="%s"`, escapeHeaderValue(c.Realm)))
	}

	if c.Scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, escapeHeaderValue(c.Scope)))
	}

	if c.PersonServerURL != "" {
		parts = append(parts, fmt.Sprintf(`ps="%s"`, escapeHeaderValue(c.PersonServerURL)))
	}

	if c.AccessServerURL != "" {
		parts = append(parts, fmt.Sprintf(`as="%s"`, escapeHeaderValue(c.AccessServerURL)))
	}

	if c.Error != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, escapeHeaderValue(c.Error)))
	}

	if c.ErrorDescription != "" {
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, escapeHeaderValue(c.ErrorDescription)))
	}

	if len(parts) == 0 {
		return c.Scheme
	}

	return fmt.Sprintf("%s %s", c.Scheme, strings.Join(parts, ", "))
}

// ParseChallenge parses a WWW-Authenticate challenge header value.
func ParseChallenge(header string) (*Challenge, error) {
	// Extract scheme
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: empty challenge", ErrInvalidChallenge)
	}

	challenge := &Challenge{
		Scheme: parts[0],
	}

	if len(parts) == 1 {
		return challenge, nil
	}

	// Parse parameters
	params := parseHeaderParams(parts[1])

	challenge.Realm = params["realm"]
	challenge.Scope = params["scope"]
	challenge.PersonServerURL = params["ps"]
	challenge.AccessServerURL = params["as"]
	challenge.Error = params["error"]
	challenge.ErrorDescription = params["error_description"]

	return challenge, nil
}

// parseHeaderParams parses header parameters from a string like:
// realm="example", scope="read write"
func parseHeaderParams(s string) map[string]string {
	params := make(map[string]string)

	var key, value strings.Builder
	inKey := true
	inQuotes := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]

		if escaped {
			if inKey {
				key.WriteByte(c)
			} else {
				value.WriteByte(c)
			}
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if c == '"' {
			inQuotes = !inQuotes
			continue
		}

		if !inQuotes {
			if c == '=' && inKey {
				inKey = false
				continue
			}

			if c == ',' || c == ' ' {
				if !inKey && key.Len() > 0 {
					params[strings.TrimSpace(key.String())] = value.String()
					key.Reset()
					value.Reset()
					inKey = true
				}
				continue
			}
		}

		if inKey {
			key.WriteByte(c)
		} else {
			value.WriteByte(c)
		}
	}

	// Don't forget the last parameter
	if key.Len() > 0 {
		params[strings.TrimSpace(key.String())] = value.String()
	}

	return params
}

// escapeHeaderValue escapes a value for use in a header parameter.
func escapeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// InvalidSignatureChallenge creates a challenge for invalid signature errors.
func InvalidSignatureChallenge(realm string) *Challenge {
	return NewChallenge(realm).WithError(ErrorInvalidSignature, "HTTP signature verification failed")
}

// InvalidTokenChallenge creates a challenge for invalid token errors.
func InvalidTokenChallenge(realm string) *Challenge {
	return NewChallenge(realm).WithError(ErrorInvalidGrant, "Invalid or expired token")
}

// InsufficientScopeChallenge creates a challenge for insufficient scope errors.
func InsufficientScopeChallenge(realm, requiredScope string) *Challenge {
	return NewChallenge(realm).
		WithScope(requiredScope).
		WithError(ErrorInvalidScope, "Insufficient scope")
}
