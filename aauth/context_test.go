package aauth

import (
	"context"
	"testing"
	"time"
)

func TestContextWithAgentToken(t *testing.T) {
	token := &AgentToken{
		Issuer:    "https://issuer.example.com",
		Subject:   "aauth:agent@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	ctx := ContextWithAgentToken(context.Background(), token)

	retrieved, ok := AgentTokenFromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve agent token from context")
	}
	if retrieved.Subject != token.Subject {
		t.Errorf("expected subject %s, got %s", token.Subject, retrieved.Subject)
	}
}

func TestAgentTokenFromContext_NotSet(t *testing.T) {
	ctx := context.Background()

	_, ok := AgentTokenFromContext(ctx)
	if ok {
		t.Error("expected ok to be false when token not set")
	}
}

func TestContextWithAuthToken(t *testing.T) {
	token := &AuthToken{
		Issuer:    "https://ps.example.com",
		Subject:   "aauth:agent@example.com",
		Audience:  []string{"https://resource.example.com"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	ctx := ContextWithAuthToken(context.Background(), token)

	retrieved, ok := AuthTokenFromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve auth token from context")
	}
	if retrieved.Subject != token.Subject {
		t.Errorf("expected subject %s, got %s", token.Subject, retrieved.Subject)
	}
}

func TestContextWithAgentID(t *testing.T) {
	id, _ := NewAAuthID("test-agent", "example.com")

	ctx := ContextWithAgentID(context.Background(), id)

	retrieved, ok := AgentIDFromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve agent ID from context")
	}
	if !retrieved.Equals(id) {
		t.Errorf("expected ID %s, got %s", id.String(), retrieved.String())
	}
}

func TestContextWithVerificationResult(t *testing.T) {
	result := &RequestVerificationResult{
		AgentID: &AAuthID{Local: "agent", Domain: "example.com"},
		KeyID:   "test-key",
	}

	ctx := ContextWithVerificationResult(context.Background(), result)

	retrieved, ok := VerificationResultFromContext(ctx)
	if !ok {
		t.Fatal("expected to retrieve verification result from context")
	}
	if retrieved.KeyID != result.KeyID {
		t.Errorf("expected KeyID %s, got %s", result.KeyID, retrieved.KeyID)
	}
}

func TestContextChaining(t *testing.T) {
	agentToken := &AgentToken{Subject: "aauth:agent@example.com"}
	authToken := &AuthToken{Subject: "aauth:agent@example.com"}
	id, _ := NewAAuthID("agent", "example.com")

	ctx := context.Background()
	ctx = ContextWithAgentToken(ctx, agentToken)
	ctx = ContextWithAuthToken(ctx, authToken)
	ctx = ContextWithAgentID(ctx, id)

	// All values should be retrievable
	if _, ok := AgentTokenFromContext(ctx); !ok {
		t.Error("expected agent token to be retrievable")
	}
	if _, ok := AuthTokenFromContext(ctx); !ok {
		t.Error("expected auth token to be retrievable")
	}
	if _, ok := AgentIDFromContext(ctx); !ok {
		t.Error("expected agent ID to be retrievable")
	}
}
