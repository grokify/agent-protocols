package httpsig

import (
	"net/http"
	"testing"
)

func TestDeriveComponent_Method(t *testing.T) {
	tests := []struct {
		method string
		want   string
	}{
		{"GET", "GET"},
		{"get", "GET"},
		{"POST", "POST"},
		{"post", "POST"},
		{"DELETE", "DELETE"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "https://example.com/", nil)
			got, err := DeriveComponent(req, ComponentMethod)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_TargetURI(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "simple path",
			url:  "https://example.com/path",
			want: "https://example.com/path",
		},
		{
			name: "with query",
			url:  "https://example.com/path?key=value",
			want: "https://example.com/path?key=value",
		},
		{
			name: "root path",
			url:  "https://example.com/",
			want: "https://example.com/",
		},
		{
			name: "complex path",
			url:  "https://api.example.com/v1/users/123",
			want: "https://api.example.com/v1/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got, err := DeriveComponent(req, ComponentTargetURI)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_Authority(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "simple domain",
			url:  "https://example.com/path",
			want: "example.com",
		},
		{
			name: "with port",
			url:  "https://example.com:8080/path",
			want: "example.com:8080",
		},
		{
			name: "subdomain",
			url:  "https://api.example.com/path",
			want: "api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got, err := DeriveComponent(req, ComponentAuthority)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_Path(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "simple path",
			url:  "https://example.com/path",
			want: "/path",
		},
		{
			name: "root",
			url:  "https://example.com/",
			want: "/",
		},
		{
			name: "nested path",
			url:  "https://example.com/a/b/c",
			want: "/a/b/c",
		},
		{
			name: "with query (only path returned)",
			url:  "https://example.com/path?query=value",
			want: "/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got, err := DeriveComponent(req, ComponentPath)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_Query(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "simple query",
			url:  "https://example.com/path?key=value",
			want: "?key=value",
		},
		{
			name: "no query",
			url:  "https://example.com/path",
			want: "?",
		},
		{
			name: "multiple params",
			url:  "https://example.com/path?a=1&b=2",
			want: "?a=1&b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got, err := DeriveComponent(req, ComponentQuery)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_RequestTarget(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "path only",
			url:  "https://example.com/path",
			want: "/path",
		},
		{
			name: "path with query",
			url:  "https://example.com/path?key=value",
			want: "/path?key=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			got, err := DeriveComponent(req, ComponentRequestTarget)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_Header(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")

	tests := []struct {
		header string
		want   string
	}{
		{"content-type", "application/json"},
		{"Content-Type", "application/json"},
		{"x-custom-header", "custom-value"},
		{"nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got, err := DeriveComponent(req, tt.header)
			if err != nil {
				t.Fatalf("DeriveComponent() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveComponent_UnsupportedDerived(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	_, err := DeriveComponent(req, "@unsupported")
	if err == nil {
		t.Error("expected error for unsupported derived component")
	}
}

func TestIsValidComponent(t *testing.T) {
	tests := []struct {
		component string
		valid     bool
	}{
		{ComponentMethod, true},
		{ComponentTargetURI, true},
		{ComponentAuthority, true},
		{ComponentPath, true},
		{ComponentQuery, true},
		{"content-type", true},
		{"x-custom-header", true},
		{"@invalid", false},
		{"header with space", false},
	}

	for _, tt := range tests {
		t.Run(tt.component, func(t *testing.T) {
			got := IsValidComponent(tt.component)
			if got != tt.valid {
				t.Errorf("IsValidComponent(%q) = %v, want %v", tt.component, got, tt.valid)
			}
		})
	}
}

func TestNormalizeHeaderName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Content-Type", "content-type"},
		{"CONTENT-TYPE", "content-type"},
		{"content-type", "content-type"},
		{"X-Custom-Header", "x-custom-header"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeHeaderName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeHeaderName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
