package aauth

import "context"

// Context keys for AAuth values.
type contextKey int

const (
	agentTokenKey contextKey = iota
	authTokenKey
	agentIDKey
	verificationResultKey
)

// ContextWithAgentToken returns a new context with the agent token.
func ContextWithAgentToken(ctx context.Context, token *AgentToken) context.Context {
	return context.WithValue(ctx, agentTokenKey, token)
}

// AgentTokenFromContext retrieves the agent token from the context.
func AgentTokenFromContext(ctx context.Context) (*AgentToken, bool) {
	token, ok := ctx.Value(agentTokenKey).(*AgentToken)
	return token, ok
}

// ContextWithAuthToken returns a new context with the auth token.
func ContextWithAuthToken(ctx context.Context, token *AuthToken) context.Context {
	return context.WithValue(ctx, authTokenKey, token)
}

// AuthTokenFromContext retrieves the auth token from the context.
func AuthTokenFromContext(ctx context.Context) (*AuthToken, bool) {
	token, ok := ctx.Value(authTokenKey).(*AuthToken)
	return token, ok
}

// ContextWithAgentID returns a new context with the agent ID.
func ContextWithAgentID(ctx context.Context, id *AAuthID) context.Context {
	return context.WithValue(ctx, agentIDKey, id)
}

// AgentIDFromContext retrieves the agent ID from the context.
func AgentIDFromContext(ctx context.Context) (*AAuthID, bool) {
	id, ok := ctx.Value(agentIDKey).(*AAuthID)
	return id, ok
}

// VerificationResult contains the result of request verification.
type RequestVerificationResult struct {
	// AgentToken is the verified agent token.
	AgentToken *AgentToken

	// AuthToken is the verified auth token (if present).
	AuthToken *AuthToken

	// AgentID is the agent's identifier.
	AgentID *AAuthID

	// KeyID is the key ID used for signing.
	KeyID string
}

// ContextWithVerificationResult returns a new context with the verification result.
func ContextWithVerificationResult(ctx context.Context, result *RequestVerificationResult) context.Context {
	return context.WithValue(ctx, verificationResultKey, result)
}

// VerificationResultFromContext retrieves the verification result from the context.
func VerificationResultFromContext(ctx context.Context) (*RequestVerificationResult, bool) {
	result, ok := ctx.Value(verificationResultKey).(*RequestVerificationResult)
	return result, ok
}
