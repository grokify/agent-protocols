package aauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DiscoveryClient fetches and caches AAuth metadata from well-known endpoints.
type DiscoveryClient struct {
	httpClient *http.Client
	cache      *discoveryCache
	cacheTTL   time.Duration
}

// DiscoveryOption configures a DiscoveryClient.
type DiscoveryOption func(*DiscoveryClient)

// NewDiscoveryClient creates a new discovery client.
func NewDiscoveryClient(opts ...DiscoveryOption) *DiscoveryClient {
	client := &DiscoveryClient{
		httpClient: http.DefaultClient,
		cache:      newDiscoveryCache(),
		cacheTTL:   5 * time.Minute,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// WithDiscoveryHTTPClient sets the HTTP client.
func WithDiscoveryHTTPClient(client *http.Client) DiscoveryOption {
	return func(dc *DiscoveryClient) {
		dc.httpClient = client
	}
}

// WithDiscoveryCacheTTL sets the cache TTL.
func WithDiscoveryCacheTTL(ttl time.Duration) DiscoveryOption {
	return func(dc *DiscoveryClient) {
		dc.cacheTTL = ttl
	}
}

// DiscoverResource fetches resource metadata from a resource URL.
func (dc *DiscoveryClient) DiscoverResource(ctx context.Context, resourceURL string) (*ResourceMetadata, error) {
	url := BuildWellKnownURL(resourceURL, WellKnownResourcePath)

	if cached, ok := dc.cache.getResource(url); ok {
		return cached, nil
	}

	data, err := dc.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch resource metadata: %v", ErrDiscoveryFailed, err)
	}

	metadata, err := ParseResourceMetadata(data)
	if err != nil {
		return nil, err
	}

	dc.cache.setResource(url, metadata, dc.cacheTTL)
	return metadata, nil
}

// DiscoverAgentProvider fetches agent provider metadata.
func (dc *DiscoveryClient) DiscoverAgentProvider(ctx context.Context, providerURL string) (*AgentProviderMetadata, error) {
	url := BuildWellKnownURL(providerURL, WellKnownAgentPath)

	if cached, ok := dc.cache.getAgentProvider(url); ok {
		return cached, nil
	}

	data, err := dc.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch agent provider metadata: %v", ErrDiscoveryFailed, err)
	}

	metadata, err := ParseAgentProviderMetadata(data)
	if err != nil {
		return nil, err
	}

	dc.cache.setAgentProvider(url, metadata, dc.cacheTTL)
	return metadata, nil
}

// DiscoverPersonServer fetches person server metadata.
func (dc *DiscoveryClient) DiscoverPersonServer(ctx context.Context, serverURL string) (*PersonServerMetadata, error) {
	url := BuildWellKnownURL(serverURL, WellKnownPersonPath)

	if cached, ok := dc.cache.getPersonServer(url); ok {
		return cached, nil
	}

	data, err := dc.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch person server metadata: %v", ErrDiscoveryFailed, err)
	}

	metadata, err := ParsePersonServerMetadata(data)
	if err != nil {
		return nil, err
	}

	dc.cache.setPersonServer(url, metadata, dc.cacheTTL)
	return metadata, nil
}

// DiscoverAuthServer fetches authorization server metadata (OAuth 2.0 format).
func (dc *DiscoveryClient) DiscoverAuthServer(ctx context.Context, serverURL string) (*AuthServerMetadata, error) {
	url := BuildWellKnownURL(serverURL, WellKnownOAuthPath)

	if cached, ok := dc.cache.getAuthServer(url); ok {
		return cached, nil
	}

	data, err := dc.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch auth server metadata: %v", ErrDiscoveryFailed, err)
	}

	metadata, err := ParseAuthServerMetadata(data)
	if err != nil {
		return nil, err
	}

	dc.cache.setAuthServer(url, metadata, dc.cacheTTL)
	return metadata, nil
}

// FetchJWKS fetches a JWKS from a URL.
func (dc *DiscoveryClient) FetchJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	if cached, ok := dc.cache.getJWKS(jwksURL); ok {
		return cached, nil
	}

	data, err := dc.fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch JWKS: %v", ErrDiscoveryFailed, err)
	}

	jwks, err := ParseJWKS(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}

	dc.cache.setJWKS(jwksURL, jwks, dc.cacheTTL)
	return jwks, nil
}

// ClearCache clears the discovery cache.
func (dc *DiscoveryClient) ClearCache() {
	dc.cache.clear()
}

// fetch performs an HTTP GET request and returns the response body.
func (dc *DiscoveryClient) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := dc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// discoveryCache caches discovery results.
type discoveryCache struct {
	mu sync.RWMutex

	resources      map[string]*cachedItem[ResourceMetadata]
	agentProviders map[string]*cachedItem[AgentProviderMetadata]
	personServers  map[string]*cachedItem[PersonServerMetadata]
	authServers    map[string]*cachedItem[AuthServerMetadata]
	jwks           map[string]*cachedItem[JWKS]
}

type cachedItem[T any] struct {
	value     *T
	expiresAt time.Time
}

func newDiscoveryCache() *discoveryCache {
	return &discoveryCache{
		resources:      make(map[string]*cachedItem[ResourceMetadata]),
		agentProviders: make(map[string]*cachedItem[AgentProviderMetadata]),
		personServers:  make(map[string]*cachedItem[PersonServerMetadata]),
		authServers:    make(map[string]*cachedItem[AuthServerMetadata]),
		jwks:           make(map[string]*cachedItem[JWKS]),
	}
}

func (c *discoveryCache) getResource(url string) (*ResourceMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.resources[url]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

func (c *discoveryCache) setResource(url string, metadata *ResourceMetadata, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.resources[url] = &cachedItem[ResourceMetadata]{
		value:     metadata,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *discoveryCache) getAgentProvider(url string) (*AgentProviderMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.agentProviders[url]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

func (c *discoveryCache) setAgentProvider(url string, metadata *AgentProviderMetadata, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.agentProviders[url] = &cachedItem[AgentProviderMetadata]{
		value:     metadata,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *discoveryCache) getPersonServer(url string) (*PersonServerMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.personServers[url]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

func (c *discoveryCache) setPersonServer(url string, metadata *PersonServerMetadata, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.personServers[url] = &cachedItem[PersonServerMetadata]{
		value:     metadata,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *discoveryCache) getAuthServer(url string) (*AuthServerMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.authServers[url]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

func (c *discoveryCache) setAuthServer(url string, metadata *AuthServerMetadata, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authServers[url] = &cachedItem[AuthServerMetadata]{
		value:     metadata,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *discoveryCache) getJWKS(url string) (*JWKS, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.jwks[url]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.value, true
}

func (c *discoveryCache) setJWKS(url string, jwks *JWKS, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.jwks[url] = &cachedItem[JWKS]{
		value:     jwks,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *discoveryCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.resources = make(map[string]*cachedItem[ResourceMetadata])
	c.agentProviders = make(map[string]*cachedItem[AgentProviderMetadata])
	c.personServers = make(map[string]*cachedItem[PersonServerMetadata])
	c.authServers = make(map[string]*cachedItem[AuthServerMetadata])
	c.jwks = make(map[string]*cachedItem[JWKS])
}

// CreateJWKSVerifier creates a JWKS verifier for the given URL.
// The verifier will fetch and cache keys from the JWKS endpoint.
func (dc *DiscoveryClient) CreateJWKSVerifier(jwksURL string) *JWKSVerifier {
	return NewJWKSVerifier(jwksURL).WithHTTPClient(dc.httpClient)
}

// DiscoverResourceFlow discovers the token exchange flow for a resource.
// Returns the person server or access server URL and metadata.
func (dc *DiscoveryClient) DiscoverResourceFlow(ctx context.Context, resourceURL string) (tokenEndpoint string, metadata *ResourceMetadata, err error) {
	metadata, err = dc.DiscoverResource(ctx, resourceURL)
	if err != nil {
		return "", nil, err
	}

	// Check for person server first, then access server
	if metadata.PersonServerURI != "" {
		psMetadata, err := dc.DiscoverPersonServer(ctx, metadata.PersonServerURI)
		if err != nil {
			return "", nil, err
		}
		return psMetadata.TokenEndpoint, metadata, nil
	}

	if metadata.AccessServerURI != "" {
		asMetadata, err := dc.DiscoverAuthServer(ctx, metadata.AccessServerURI)
		if err != nil {
			return "", nil, err
		}
		return asMetadata.TokenEndpoint, metadata, nil
	}

	return "", nil, fmt.Errorf("%w: no person server or access server configured", ErrDiscoveryFailed)
}
