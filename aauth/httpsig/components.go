package httpsig

import (
	"fmt"
	"net/http"
	"strings"
)

// Derived component identifiers per RFC 9421.
const (
	// ComponentMethod is the HTTP request method.
	ComponentMethod = "@method"

	// ComponentTargetURI is the full target URI of the request.
	ComponentTargetURI = "@target-uri"

	// ComponentAuthority is the host/authority of the request.
	ComponentAuthority = "@authority"

	// ComponentScheme is the scheme of the request URI.
	ComponentScheme = "@scheme"

	// ComponentPath is the absolute path of the request URI.
	ComponentPath = "@path"

	// ComponentQuery is the query string (including the leading ?).
	ComponentQuery = "@query"

	// ComponentQueryParam is a specific query parameter (requires name parameter).
	ComponentQueryParam = "@query-param"

	// ComponentRequestTarget is the HTTP/1.1 request target.
	ComponentRequestTarget = "@request-target"

	// ComponentSignatureParams is the signature parameters (always included last).
	ComponentSignatureParams = "@signature-params"
)

// DefaultCoveredComponents are the default components to include in a signature.
var DefaultCoveredComponents = []string{
	ComponentMethod,
	ComponentTargetURI,
	"content-digest",
	"authorization",
}

// AAuthCoveredComponents are the components recommended for AAuth signatures.
var AAuthCoveredComponents = []string{
	ComponentMethod,
	ComponentTargetURI,
	"content-digest",
	"signature-key",
}

// DeriveComponent derives the value of a component from an HTTP request.
// For derived components (starting with @), it computes the value per RFC 9421.
// For regular headers, it returns the header value.
func DeriveComponent(req *http.Request, component string) (string, error) {
	if strings.HasPrefix(component, "@") {
		return deriveDerivedComponent(req, component)
	}
	return deriveHeaderComponent(req, component)
}

// deriveDerivedComponent handles derived components (@ prefixed).
func deriveDerivedComponent(req *http.Request, component string) (string, error) {
	switch component {
	case ComponentMethod:
		return strings.ToUpper(req.Method), nil

	case ComponentTargetURI:
		return deriveTargetURI(req), nil

	case ComponentAuthority:
		return deriveAuthority(req), nil

	case ComponentScheme:
		return deriveScheme(req), nil

	case ComponentPath:
		return derivePath(req), nil

	case ComponentQuery:
		return deriveQuery(req), nil

	case ComponentRequestTarget:
		return deriveRequestTarget(req), nil

	default:
		// Handle parameterized components like @query-param;name="key"
		if strings.HasPrefix(component, ComponentQueryParam) {
			return deriveQueryParam(req, component)
		}
		return "", fmt.Errorf("unsupported derived component: %s", component)
	}
}

// deriveTargetURI derives the @target-uri value.
func deriveTargetURI(req *http.Request) string {
	// If URL is fully qualified, use it directly
	if req.URL.IsAbs() {
		return req.URL.String()
	}

	// Reconstruct the full URI
	scheme := "https"
	if req.TLS == nil && req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	result := fmt.Sprintf("%s://%s%s", scheme, host, path)
	if req.URL.RawQuery != "" {
		result += "?" + req.URL.RawQuery
	}
	return result
}

// deriveAuthority derives the @authority value.
func deriveAuthority(req *http.Request) string {
	if req.Host != "" {
		return strings.ToLower(req.Host)
	}
	return strings.ToLower(req.URL.Host)
}

// deriveScheme derives the @scheme value.
func deriveScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if req.URL.Scheme != "" {
		return strings.ToLower(req.URL.Scheme)
	}
	return "https" // Default to https
}

// derivePath derives the @path value.
func derivePath(req *http.Request) string {
	path := req.URL.Path
	if path == "" {
		return "/"
	}
	return path
}

// deriveQuery derives the @query value.
// Returns "?" + query string, or "?" if no query string.
func deriveQuery(req *http.Request) string {
	if req.URL.RawQuery != "" {
		return "?" + req.URL.RawQuery
	}
	return "?"
}

// deriveRequestTarget derives the @request-target value (HTTP/1.1 style).
func deriveRequestTarget(req *http.Request) string {
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	if req.URL.RawQuery != "" {
		return path + "?" + req.URL.RawQuery
	}
	return path
}

// deriveQueryParam derives a specific query parameter value.
// The component should be in the form: @query-param;name="key"
func deriveQueryParam(req *http.Request, component string) (string, error) {
	// Parse the parameter name from the component
	// Expected format: @query-param;name="key"
	parts := strings.SplitN(component, ";", 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid @query-param component: missing name parameter")
	}

	params := parts[1]
	if !strings.HasPrefix(params, "name=\"") || !strings.HasSuffix(params, "\"") {
		return "", fmt.Errorf("invalid @query-param component: malformed name parameter")
	}

	name := params[6 : len(params)-1] // Extract the name value

	values := req.URL.Query()[name]
	if len(values) == 0 {
		return "", fmt.Errorf("query parameter not found: %s", name)
	}

	return values[0], nil
}

// deriveHeaderComponent gets a header value for the signature base.
func deriveHeaderComponent(req *http.Request, headerName string) (string, error) {
	// Normalize header name to lowercase for lookup
	canonicalName := strings.ToLower(headerName)

	// Get header values (case-insensitive)
	var values []string
	for name, vals := range req.Header {
		if strings.ToLower(name) == canonicalName {
			values = append(values, vals...)
			break
		}
	}

	if len(values) == 0 {
		// Header not present - this may be acceptable depending on the component
		return "", nil
	}

	// Combine multiple values with ", " per HTTP/1.1
	return strings.Join(values, ", "), nil
}

// NormalizeHeaderName normalizes a header name for signature purposes.
// Header names are lowercased per RFC 9421.
func NormalizeHeaderName(name string) string {
	return strings.ToLower(name)
}

// IsValidComponent checks if a component identifier is valid.
func IsValidComponent(component string) bool {
	if strings.HasPrefix(component, "@") {
		switch component {
		case ComponentMethod, ComponentTargetURI, ComponentAuthority,
			ComponentScheme, ComponentPath, ComponentQuery, ComponentRequestTarget:
			return true
		default:
			// Check for parameterized components
			return strings.HasPrefix(component, ComponentQueryParam+";")
		}
	}
	// Regular header names are valid if they don't contain invalid characters
	return !strings.ContainsAny(component, " \t\r\n")
}
