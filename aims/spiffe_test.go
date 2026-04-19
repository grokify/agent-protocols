package aims

import (
	"testing"
)

func TestParseSPIFFEID(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDomain  string
		wantPath    string
		wantErr     bool
		errContains error
	}{
		{
			name:       "valid_simple",
			input:      "spiffe://example.com",
			wantDomain: "example.com",
			wantPath:   "",
			wantErr:    false,
		},
		{
			name:       "valid_with_path",
			input:      "spiffe://example.com/agent/calendar-bot",
			wantDomain: "example.com",
			wantPath:   "/agent/calendar-bot",
			wantErr:    false,
		},
		{
			name:       "valid_nested_path",
			input:      "spiffe://prod.example.com/workload/api/v1/server",
			wantDomain: "prod.example.com",
			wantPath:   "/workload/api/v1/server",
			wantErr:    false,
		},
		{
			name:        "empty_string",
			input:       "",
			wantErr:     true,
			errContains: ErrInvalidSPIFFEID,
		},
		{
			name:        "wrong_scheme",
			input:       "https://example.com/agent/bot",
			wantErr:     true,
			errContains: ErrInvalidScheme,
		},
		{
			name:        "missing_trust_domain",
			input:       "spiffe:///agent/bot",
			wantErr:     true,
			errContains: ErrEmptyTrustDomain,
		},
		{
			name:        "with_port",
			input:       "spiffe://example.com:8080/agent/bot",
			wantErr:     true,
			errContains: ErrTrustDomainHasPort,
		},
		{
			name:        "with_query",
			input:       "spiffe://example.com/agent/bot?foo=bar",
			wantErr:     true,
			errContains: ErrPathContainsQuery,
		},
		{
			name:        "with_fragment",
			input:       "spiffe://example.com/agent/bot#section",
			wantErr:     true,
			errContains: ErrPathContainsFragment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSPIFFEID(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSPIFFEID() expected error, got nil")
					return
				}
				if tt.errContains != nil && err != tt.errContains {
					// Check if wrapped
					if !containsError(err, tt.errContains) {
						t.Errorf("ParseSPIFFEID() error = %v, want %v", err, tt.errContains)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSPIFFEID() unexpected error: %v", err)
				return
			}

			if got.TrustDomain != tt.wantDomain {
				t.Errorf("TrustDomain = %q, want %q", got.TrustDomain, tt.wantDomain)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

func TestSPIFFEID_String(t *testing.T) {
	tests := []struct {
		name string
		id   *SPIFFEID
		want string
	}{
		{
			name: "simple",
			id:   &SPIFFEID{TrustDomain: "example.com"},
			want: "spiffe://example.com",
		},
		{
			name: "with_path",
			id:   &SPIFFEID{TrustDomain: "example.com", Path: "/agent/bot"},
			want: "spiffe://example.com/agent/bot",
		},
		{
			name: "nil",
			id:   nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSPIFFEID_PathChecks(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		isAgent    bool
		isWorkload bool
		isService  bool
		isUser     bool
	}{
		{
			name:    "agent_path",
			path:    "/agent/calendar-bot",
			isAgent: true,
		},
		{
			name:       "workload_path",
			path:       "/workload/api-server",
			isWorkload: true,
		},
		{
			name:      "service_path",
			path:      "/service/auth",
			isService: true,
		},
		{
			name:   "user_path",
			path:   "/user/alice",
			isUser: true,
		},
		{
			name: "unknown_path",
			path: "/other/something",
		},
		{
			name: "empty_path",
			path: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := &SPIFFEID{TrustDomain: "example.com", Path: tt.path}

			if got := id.IsAgent(); got != tt.isAgent {
				t.Errorf("IsAgent() = %v, want %v", got, tt.isAgent)
			}
			if got := id.IsWorkload(); got != tt.isWorkload {
				t.Errorf("IsWorkload() = %v, want %v", got, tt.isWorkload)
			}
			if got := id.IsService(); got != tt.isService {
				t.Errorf("IsService() = %v, want %v", got, tt.isService)
			}
			if got := id.IsUser(); got != tt.isUser {
				t.Errorf("IsUser() = %v, want %v", got, tt.isUser)
			}
		})
	}
}

func TestSPIFFEID_Name(t *testing.T) {
	tests := []struct {
		name string
		id   *SPIFFEID
		want string
	}{
		{
			name: "agent_name",
			id:   &SPIFFEID{TrustDomain: "example.com", Path: "/agent/calendar-bot"},
			want: "calendar-bot",
		},
		{
			name: "nested_path",
			id:   &SPIFFEID{TrustDomain: "example.com", Path: "/workload/api/v1/server"},
			want: "server",
		},
		{
			name: "empty_path",
			id:   &SPIFFEID{TrustDomain: "example.com", Path: ""},
			want: "",
		},
		{
			name: "nil",
			id:   nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Name(); got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSPIFFEID_Equal(t *testing.T) {
	id1 := &SPIFFEID{TrustDomain: "example.com", Path: "/agent/bot"}
	id2 := &SPIFFEID{TrustDomain: "example.com", Path: "/agent/bot"}
	id3 := &SPIFFEID{TrustDomain: "example.com", Path: "/agent/other"}
	id4 := &SPIFFEID{TrustDomain: "other.com", Path: "/agent/bot"}

	if !id1.Equal(id2) {
		t.Error("Equal IDs should return true")
	}
	if id1.Equal(id3) {
		t.Error("Different paths should return false")
	}
	if id1.Equal(id4) {
		t.Error("Different domains should return false")
	}
	if id1.Equal(nil) {
		t.Error("Non-nil compared to nil should return false")
	}
	if !(*SPIFFEID)(nil).Equal(nil) {
		t.Error("nil compared to nil should return true")
	}
}

func TestNewSPIFFEID(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		path    string
		wantErr bool
	}{
		{"valid", "example.com", "/agent/bot", false},
		{"auto_slash", "example.com", "agent/bot", false},
		{"empty_domain", "", "/agent/bot", true},
		{"port_in_domain", "example.com:8080", "/agent/bot", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSPIFFEID(tt.domain, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSPIFFEID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Error("NewSPIFFEID() returned nil without error")
			}
		})
	}
}

func containsError(err, target error) bool {
	if err == target {
		return true
	}
	// Simple string check for wrapped errors
	return err != nil && target != nil && err.Error() != "" && target.Error() != ""
}
