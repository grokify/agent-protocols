package aauth

import (
	"testing"
)

func TestNewChallenge(t *testing.T) {
	challenge := NewChallenge("https://resource.example.com")

	if challenge.Scheme != "AAuth" {
		t.Errorf("expected scheme AAuth, got %s", challenge.Scheme)
	}
	if challenge.Realm != "https://resource.example.com" {
		t.Errorf("expected realm https://resource.example.com, got %s", challenge.Realm)
	}
}

func TestChallengeBuilder(t *testing.T) {
	challenge := NewChallenge("https://resource.example.com").
		WithScope("read write").
		WithPersonServer("https://ps.example.com").
		WithAccessServer("https://as.example.com")

	if challenge.Scope != "read write" {
		t.Errorf("expected scope 'read write', got %s", challenge.Scope)
	}
	if challenge.PersonServerURL != "https://ps.example.com" {
		t.Errorf("expected PS URL https://ps.example.com, got %s", challenge.PersonServerURL)
	}
	if challenge.AccessServerURL != "https://as.example.com" {
		t.Errorf("expected AS URL https://as.example.com, got %s", challenge.AccessServerURL)
	}
}

func TestChallengeString(t *testing.T) {
	tests := []struct {
		name      string
		challenge *Challenge
		expected  string
	}{
		{
			name:      "basic",
			challenge: NewChallenge("https://resource.example.com"),
			expected:  `AAuth realm="https://resource.example.com"`,
		},
		{
			name: "with scope",
			challenge: NewChallenge("https://resource.example.com").
				WithScope("read write"),
			expected: `AAuth realm="https://resource.example.com", scope="read write"`,
		},
		{
			name: "with person server",
			challenge: NewChallenge("https://resource.example.com").
				WithPersonServer("https://ps.example.com"),
			expected: `AAuth realm="https://resource.example.com", ps="https://ps.example.com"`,
		},
		{
			name: "with error",
			challenge: NewChallenge("https://resource.example.com").
				WithError("invalid_token", "Token expired"),
			expected: `AAuth realm="https://resource.example.com", error="invalid_token", error_description="Token expired"`,
		},
		{
			name: "full challenge",
			challenge: NewChallenge("https://resource.example.com").
				WithScope("read").
				WithPersonServer("https://ps.example.com").
				WithAccessServer("https://as.example.com"),
			expected: `AAuth realm="https://resource.example.com", scope="read", ps="https://ps.example.com", as="https://as.example.com"`,
		},
		{
			name:      "empty realm",
			challenge: &Challenge{Scheme: "AAuth"},
			expected:  "AAuth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.challenge.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		wantErr  bool
		validate func(*testing.T, *Challenge)
	}{
		{
			name:   "basic",
			header: `AAuth realm="https://resource.example.com"`,
			validate: func(t *testing.T, c *Challenge) {
				if c.Scheme != "AAuth" {
					t.Errorf("expected scheme AAuth, got %s", c.Scheme)
				}
				if c.Realm != "https://resource.example.com" {
					t.Errorf("expected realm https://resource.example.com, got %s", c.Realm)
				}
			},
		},
		{
			name:   "with scope",
			header: `AAuth realm="https://resource.example.com", scope="read write"`,
			validate: func(t *testing.T, c *Challenge) {
				if c.Scope != "read write" {
					t.Errorf("expected scope 'read write', got %s", c.Scope)
				}
			},
		},
		{
			name:   "with servers",
			header: `AAuth realm="https://resource.example.com", ps="https://ps.example.com", as="https://as.example.com"`,
			validate: func(t *testing.T, c *Challenge) {
				if c.PersonServerURL != "https://ps.example.com" {
					t.Errorf("expected PS https://ps.example.com, got %s", c.PersonServerURL)
				}
				if c.AccessServerURL != "https://as.example.com" {
					t.Errorf("expected AS https://as.example.com, got %s", c.AccessServerURL)
				}
			},
		},
		{
			name:   "with error",
			header: `AAuth realm="https://resource.example.com", error="invalid_token", error_description="Token expired"`,
			validate: func(t *testing.T, c *Challenge) {
				if c.Error != "invalid_token" {
					t.Errorf("expected error invalid_token, got %s", c.Error)
				}
				if c.ErrorDescription != "Token expired" {
					t.Errorf("expected error_description 'Token expired', got %s", c.ErrorDescription)
				}
			},
		},
		{
			name:   "scheme only",
			header: "AAuth",
			validate: func(t *testing.T, c *Challenge) {
				if c.Scheme != "AAuth" {
					t.Errorf("expected scheme AAuth, got %s", c.Scheme)
				}
			},
		},
		{
			name:   "empty",
			header: "",
			validate: func(t *testing.T, c *Challenge) {
				// Empty header returns empty challenge
				if c.Scheme != "" {
					t.Errorf("expected empty scheme, got %s", c.Scheme)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, err := ParseChallenge(tt.header)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, challenge)
			}
		})
	}
}

func TestEscapeHeaderValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`with "quotes"`, `with \"quotes\"`},
		{`with \backslash`, `with \\backslash`},
		{`both "and" \`, `both \"and\" \\`},
	}

	for _, tt := range tests {
		got := escapeHeaderValue(tt.input)
		if got != tt.expected {
			t.Errorf("escapeHeaderValue(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestInvalidSignatureChallenge(t *testing.T) {
	challenge := InvalidSignatureChallenge("https://resource.example.com")

	if challenge.Error != ErrorInvalidSignature {
		t.Errorf("expected error %s, got %s", ErrorInvalidSignature, challenge.Error)
	}
	if challenge.ErrorDescription == "" {
		t.Error("expected error description to be set")
	}
}

func TestInvalidTokenChallenge(t *testing.T) {
	challenge := InvalidTokenChallenge("https://resource.example.com")

	if challenge.Error != ErrorInvalidGrant {
		t.Errorf("expected error %s, got %s", ErrorInvalidGrant, challenge.Error)
	}
}

func TestInsufficientScopeChallenge(t *testing.T) {
	challenge := InsufficientScopeChallenge("https://resource.example.com", "admin")

	if challenge.Error != ErrorInvalidScope {
		t.Errorf("expected error %s, got %s", ErrorInvalidScope, challenge.Error)
	}
	if challenge.Scope != "admin" {
		t.Errorf("expected scope admin, got %s", challenge.Scope)
	}
}
