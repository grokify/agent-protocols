package aauth

import (
	"errors"
	"testing"
)

func TestParseAAuthID(t *testing.T) {
	tests := []struct {
		name       string
		uri        string
		wantLocal  string
		wantDomain string
		wantErr    bool
	}{
		{
			name:       "valid simple",
			uri:        "aauth:calendar-bot@example.com",
			wantLocal:  "calendar-bot",
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "valid with subdomain",
			uri:        "aauth:agent@agents.example.com",
			wantLocal:  "agent",
			wantDomain: "agents.example.com",
			wantErr:    false,
		},
		{
			name:       "valid with numbers",
			uri:        "aauth:agent123@example.com",
			wantLocal:  "agent123",
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "valid with underscore",
			uri:        "aauth:my_agent@example.com",
			wantLocal:  "my_agent",
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "valid with plus",
			uri:        "aauth:agent+prod@example.com",
			wantLocal:  "agent+prod",
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "valid with period",
			uri:        "aauth:agent.v2@example.com",
			wantLocal:  "agent.v2",
			wantDomain: "example.com",
			wantErr:    false,
		},
		{
			name:       "valid with multiple @ (last one is separator)",
			uri:        "aauth:agent+test@local@example.com",
			wantLocal:  "agent+test@local",
			wantDomain: "example.com",
			wantErr:    true, // @ not allowed in local part per our regex
		},
		{
			name:    "missing scheme",
			uri:     "calendar-bot@example.com",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			uri:     "mailto:calendar-bot@example.com",
			wantErr: true,
		},
		{
			name:    "missing @",
			uri:     "aauth:calendar-bot",
			wantErr: true,
		},
		{
			name:    "empty local part",
			uri:     "aauth:@example.com",
			wantErr: true,
		},
		{
			name:    "empty domain",
			uri:     "aauth:calendar-bot@",
			wantErr: true,
		},
		{
			name:    "invalid local - uppercase",
			uri:     "aauth:Calendar-Bot@example.com",
			wantErr: true,
		},
		{
			name:    "invalid local - spaces",
			uri:     "aauth:calendar bot@example.com",
			wantErr: true,
		},
		{
			name:    "invalid domain - no TLD",
			uri:     "aauth:agent@localhost",
			wantErr: true,
		},
		{
			name:    "invalid domain - starts with hyphen",
			uri:     "aauth:agent@-example.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			uri:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAAuthID(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAAuthID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if !errors.Is(err, ErrInvalidAAuthID) {
					t.Errorf("ParseAAuthID() error should wrap ErrInvalidAAuthID")
				}
				return
			}
			if got.Local != tt.wantLocal {
				t.Errorf("ParseAAuthID() Local = %v, want %v", got.Local, tt.wantLocal)
			}
			if got.Domain != tt.wantDomain {
				t.Errorf("ParseAAuthID() Domain = %v, want %v", got.Domain, tt.wantDomain)
			}
		})
	}
}

func TestNewAAuthID(t *testing.T) {
	tests := []struct {
		name    string
		local   string
		domain  string
		wantErr bool
	}{
		{
			name:    "valid",
			local:   "calendar-bot",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "empty local",
			local:   "",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "empty domain",
			local:   "agent",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "invalid local",
			local:   "UPPERCASE",
			domain:  "example.com",
			wantErr: true,
		},
		{
			name:    "invalid domain",
			local:   "agent",
			domain:  "localhost",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAAuthID(tt.local, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAAuthID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got.Local != tt.local {
					t.Errorf("NewAAuthID() Local = %v, want %v", got.Local, tt.local)
				}
				if got.Domain != tt.domain {
					t.Errorf("NewAAuthID() Domain = %v, want %v", got.Domain, tt.domain)
				}
			}
		})
	}
}

func TestAAuthID_String(t *testing.T) {
	id := &AAuthID{
		Local:  "calendar-bot",
		Domain: "example.com",
	}

	want := "aauth:calendar-bot@example.com"
	got := id.String()

	if got != want {
		t.Errorf("AAuthID.String() = %v, want %v", got, want)
	}
}

func TestAAuthID_AgentProviderURL(t *testing.T) {
	id := &AAuthID{
		Local:  "calendar-bot",
		Domain: "example.com",
	}

	want := "https://example.com/.well-known/aauth-agent.json"
	got := id.AgentProviderURL()

	if got != want {
		t.Errorf("AAuthID.AgentProviderURL() = %v, want %v", got, want)
	}
}

func TestAAuthID_Equals(t *testing.T) {
	id1 := &AAuthID{Local: "agent", Domain: "example.com"}
	id2 := &AAuthID{Local: "agent", Domain: "example.com"}
	id3 := &AAuthID{Local: "other", Domain: "example.com"}
	id4 := &AAuthID{Local: "agent", Domain: "other.com"}

	if !id1.Equals(id2) {
		t.Error("Expected id1 to equal id2")
	}
	if id1.Equals(id3) {
		t.Error("Expected id1 to not equal id3 (different local)")
	}
	if id1.Equals(id4) {
		t.Error("Expected id1 to not equal id4 (different domain)")
	}
	if id1.Equals(nil) {
		t.Error("Expected id1 to not equal nil")
	}

	var nilID *AAuthID
	if !nilID.Equals(nil) {
		t.Error("Expected nil to equal nil")
	}
}

func TestParseAAuthID_Roundtrip(t *testing.T) {
	original := "aauth:calendar-bot@example.com"

	id, err := ParseAAuthID(original)
	if err != nil {
		t.Fatalf("ParseAAuthID() error = %v", err)
	}

	if id.String() != original {
		t.Errorf("Roundtrip failed: got %v, want %v", id.String(), original)
	}
}
