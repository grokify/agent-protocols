package httpsig

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureParams represents the parameters of a signature.
type SignatureParams struct {
	// Components is the ordered list of covered components.
	Components []string

	// Created is the signature creation time.
	Created time.Time

	// Expires is the optional expiration time.
	Expires *time.Time

	// Nonce is an optional nonce value for replay protection.
	Nonce string

	// Algorithm is the signature algorithm identifier.
	Algorithm string

	// KeyID is the identifier for the signing key.
	KeyID string

	// Tag is an optional application-specific tag.
	Tag string
}

// DefaultSignatureParams creates default signature parameters.
func DefaultSignatureParams(keyID, algorithm string, components []string) *SignatureParams {
	return &SignatureParams{
		Components: components,
		Created:    time.Now(),
		Algorithm:  algorithm,
		KeyID:      keyID,
	}
}

// Serialize serializes the signature parameters to the Signature-Input format.
// Format: (component1 component2 ...);created=123;keyid="key";alg="alg"
func (p *SignatureParams) Serialize() string {
	var builder strings.Builder

	// Components list
	builder.WriteString("(")
	for i, comp := range p.Components {
		if i > 0 {
			builder.WriteString(" ")
		}
		// Quote header names, but not derived components
		if strings.HasPrefix(comp, "@") {
			builder.WriteString(comp)
		} else {
			builder.WriteString("\"")
			builder.WriteString(comp)
			builder.WriteString("\"")
		}
	}
	builder.WriteString(")")

	// Required parameters
	builder.WriteString(";created=")
	builder.WriteString(strconv.FormatInt(p.Created.Unix(), 10))

	if p.KeyID != "" {
		builder.WriteString(";keyid=\"")
		builder.WriteString(escapeString(p.KeyID))
		builder.WriteString("\"")
	}

	if p.Algorithm != "" {
		builder.WriteString(";alg=\"")
		builder.WriteString(escapeString(p.Algorithm))
		builder.WriteString("\"")
	}

	// Optional parameters
	if p.Expires != nil {
		builder.WriteString(";expires=")
		builder.WriteString(strconv.FormatInt(p.Expires.Unix(), 10))
	}

	if p.Nonce != "" {
		builder.WriteString(";nonce=\"")
		builder.WriteString(escapeString(p.Nonce))
		builder.WriteString("\"")
	}

	if p.Tag != "" {
		builder.WriteString(";tag=\"")
		builder.WriteString(escapeString(p.Tag))
		builder.WriteString("\"")
	}

	return builder.String()
}

// ParseSignatureParams parses a Signature-Input header value into SignatureParams.
// Format: (component1 component2 ...);created=123;keyid="key";alg="alg"
func ParseSignatureParams(input string) (*SignatureParams, error) {
	params := &SignatureParams{}

	// Find the components list
	if !strings.HasPrefix(input, "(") {
		return nil, fmt.Errorf("invalid signature params: missing opening parenthesis")
	}

	closeIdx := strings.Index(input, ")")
	if closeIdx == -1 {
		return nil, fmt.Errorf("invalid signature params: missing closing parenthesis")
	}

	// Parse components
	componentsStr := input[1:closeIdx]
	if componentsStr != "" {
		params.Components = parseComponentList(componentsStr)
	}

	// Parse parameters after the components list
	paramsStr := input[closeIdx+1:]
	if err := parseParameters(paramsStr, params); err != nil {
		return nil, err
	}

	return params, nil
}

// parseComponentList parses a space-separated list of components.
func parseComponentList(s string) []string {
	var components []string
	var current strings.Builder
	inQuotes := false

	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ' ':
			if !inQuotes {
				if current.Len() > 0 {
					components = append(components, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		components = append(components, current.String())
	}

	return components
}

// parseParameters parses the key-value parameters after the components list.
func parseParameters(s string, params *SignatureParams) error {
	// Remove leading semicolon if present
	s = strings.TrimPrefix(s, ";")

	// Split by semicolon (but be careful with quoted values)
	parts := splitParameters(s)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split on = for key-value pairs
		idx := strings.Index(part, "=")
		if idx == -1 {
			continue // Boolean parameters not supported yet
		}

		key := part[:idx]
		value := part[idx+1:]

		switch key {
		case "created":
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid created timestamp: %w", err)
			}
			params.Created = time.Unix(ts, 0)

		case "expires":
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid expires timestamp: %w", err)
			}
			expires := time.Unix(ts, 0)
			params.Expires = &expires

		case "keyid":
			params.KeyID = unquoteString(value)

		case "alg":
			params.Algorithm = unquoteString(value)

		case "nonce":
			params.Nonce = unquoteString(value)

		case "tag":
			params.Tag = unquoteString(value)
		}
	}

	return nil
}

// splitParameters splits a parameter string by semicolons,
// handling quoted values that may contain semicolons.
func splitParameters(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ';':
			if !inQuotes {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// escapeString escapes special characters in a string value.
func escapeString(s string) string {
	// Escape backslashes and double quotes
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

// unquoteString removes surrounding quotes and unescapes the string.
func unquoteString(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	// Unescape
	s = strings.ReplaceAll(s, "\\\"", "\"")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// FormatSignatureInput formats a signature label and params for the Signature-Input header.
// Example: sig1=(@method @target-uri);created=123;keyid="key"
func FormatSignatureInput(label string, params *SignatureParams) string {
	return label + "=" + params.Serialize()
}

// ParseSignatureInput parses a Signature-Input header value.
// Returns a map of label -> SignatureParams.
func ParseSignatureInput(header string) (map[string]*SignatureParams, error) {
	result := make(map[string]*SignatureParams)

	// Split by comma for multiple signatures
	signatures := splitSignatures(header)

	for _, sig := range signatures {
		sig = strings.TrimSpace(sig)
		if sig == "" {
			continue
		}

		// Split label from params
		idx := strings.Index(sig, "=")
		if idx == -1 {
			return nil, fmt.Errorf("invalid signature input: missing = for label")
		}

		label := sig[:idx]
		paramsStr := sig[idx+1:]

		params, err := ParseSignatureParams(paramsStr)
		if err != nil {
			return nil, fmt.Errorf("invalid signature params for %s: %w", label, err)
		}

		result[label] = params
	}

	return result, nil
}

// splitSignatures splits multiple signatures in a header.
// Handles quoted values and parenthesized lists.
func splitSignatures(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	parenDepth := 0

	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case '(':
			if !inQuotes {
				parenDepth++
			}
			current.WriteRune(r)
		case ')':
			if !inQuotes {
				parenDepth--
			}
			current.WriteRune(r)
		case ',':
			if !inQuotes && parenDepth == 0 {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}
