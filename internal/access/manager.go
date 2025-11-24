package access

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// AccessInfo holds resolved access information for a request
type AccessInfo struct {
	APIKeyConfig     *config.APIKeyConfig
	ModelReference   *config.ModelReference
	OriginalModel    string        // The original model requested by the client
	ResolvedModel    string        // The actual model name that will be used
	ProviderName     string        // The provider that will handle the request
	ModelGroup       string        // The model group that granted access
	ResolvedBy       string        // How the model was resolved: "alias", "direct", or "provider-fallback"
	CacheKey         string        // Cache key for this resolution
	ResolvedAt       time.Time     // When this resolution was made
}

// Cache entry for resolved model references
type cacheEntry struct {
	accessInfo   *AccessInfo
	expiresAt    time.Time
	mu           sync.RWMutex
}

// AccessManager handles API key validation and model access control
type AccessManager struct {
	config            *config.Config
	cache             map[string]*cacheEntry
	cacheTTL          time.Duration
	mu                sync.RWMutex

	// Rate limiting
	rateLimiters      map[string]*RateLimiter
	rateLimitMu       sync.RWMutex

	// Legacy API key support
	legacyAPIKey      string
	legacyFallback    bool
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens    int
	capacity  int
	lastRefill time.Time
	mu        sync.RWMutex
}

// NewAccessManager creates a new AccessManager
func NewAccessManager(cfg *config.Config) *AccessManager {
	var legacyAPIKey string
	if cfg != nil {
		legacyAPIKey = cfg.APIKEY
	}

	return &AccessManager{
		config:         cfg,
		cache:          make(map[string]*cacheEntry),
		cacheTTL:       5 * time.Minute, // Default cache TTL
		rateLimiters:   make(map[string]*RateLimiter),
		legacyAPIKey:   legacyAPIKey,
		legacyFallback: true, // Enable legacy fallback by default
	}
}

// SetCacheTTL sets the cache TTL for resolved model references
func (am *AccessManager) SetCacheTTL(ttl time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.cacheTTL = ttl
}

// EnableLegacyFallback enables or disables legacy API key fallback
func (am *AccessManager) EnableLegacyFallback(enable bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.legacyFallback = enable
}

// ValidateAPIKey validates an API key against the configuration
func (am *AccessManager) ValidateAPIKey(apiKey string) (*config.APIKeyConfig, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key cannot be empty")
	}

	if am.config == nil {
		return nil, fmt.Errorf("configuration not available")
	}

	// Try client API keys first
	if am.config.ClientAPIKeys != nil {
		keyConfig, err := am.config.ValidateClientAPIKey(apiKey)
		if err == nil {
			return keyConfig, nil
		}
	}

	// Fallback to legacy API key if enabled
	if am.legacyFallback && am.legacyAPIKey != "" && apiKey == am.legacyAPIKey {
		// Create a temporary config for legacy key
		return &config.APIKeyConfig{
			APIKey:      am.legacyAPIKey,
			Description: "Legacy API key",
			ModelGroups: []string{}, // No restrictions
			Enabled:     true,
		}, nil
	}

	return nil, fmt.Errorf("invalid API key")
}

// ResolveModel resolves a model name (or alias) to a model reference
func (am *AccessManager) ResolveModel(ctx context.Context, model string) (*config.ModelReference, string, error) {
	if model == "" {
		return nil, "", fmt.Errorf("model name cannot be empty")
	}

	if am.config == nil {
		return nil, "", fmt.Errorf("configuration not available")
	}

	// First try to find it as an alias
	modelRef, err := am.config.GetModelReferenceByAlias(model)
	if err == nil {
		return modelRef, "alias", nil
	}

	// Try to find it as a direct model name
	provider, err := am.config.GetProviderForModel(model)
	if err == nil {
		return &config.ModelReference{
			Provider: provider.Name,
			Model:    model,
		}, "direct", nil
	}

	// Fallback: if model name contains a provider prefix (e.g., "anthropic:claude-3-sonnet")
	if colonIndex := strings.Index(model, ":"); colonIndex > 0 {
		// This would handle provider:model format in the future
		// For now, return an error
		return nil, "", fmt.Errorf("provider:model format not yet supported: %s", model)
	}

	return nil, "", fmt.Errorf("model not found: %s", model)
}

// CanAccessModel checks if an API key can access a specific model
func (am *AccessManager) CanAccessModel(ctx context.Context, apiKey string, model string) (*AccessInfo, error) {
	// First validate API key (this will be needed for rate limiting anyway)
	keyConfig, err := am.ValidateAPIKey(apiKey)
	if err != nil {
		return nil, fmt.Errorf("API key validation failed: %w", err)
	}

	// Check rate limit first (this should not be cached)
	if err := am.checkRateLimit(apiKey, keyConfig); err != nil {
		return nil, err
	}

	// Create cache key
	cacheKey := am.buildCacheKey(apiKey, model)

	// Check cache first
	am.mu.RLock()
	if entry, exists := am.cache[cacheKey]; exists {
		entry.mu.RLock()
		// For zero TTL, cache entries expire immediately
		if am.cacheTTL > 0 && time.Now().Before(entry.expiresAt) {
			// Cache hit and still valid - create a copy with new timestamp
			cachedInfo := entry.accessInfo
			// Create a new AccessInfo with the current timestamp
			accessInfo := &AccessInfo{
				APIKeyConfig:   cachedInfo.APIKeyConfig,
				ModelReference: cachedInfo.ModelReference,
				OriginalModel:  cachedInfo.OriginalModel,
				ResolvedModel:  cachedInfo.ResolvedModel,
				ProviderName:   cachedInfo.ProviderName,
				ModelGroup:     cachedInfo.ModelGroup,
				ResolvedBy:     cachedInfo.ResolvedBy,
				CacheKey:       cachedInfo.CacheKey,
				ResolvedAt:     time.Now(), // Current time for this request
			}
			entry.mu.RUnlock()
			am.mu.RUnlock()
			return accessInfo, nil
		}
		entry.mu.RUnlock()
		delete(am.cache, cacheKey) // Remove expired entry
	}
	am.mu.RUnlock()

	// Cache miss or expired - perform full resolution (without rate limiting since we already checked)
	accessInfo, err := am.performAccessCheckWithoutRateLimit(ctx, apiKey, model, keyConfig)
	if err != nil {
		return nil, err
	}

	// Cache the result only if TTL > 0
	if am.cacheTTL > 0 {
		am.cacheAccessInfo(cacheKey, accessInfo)
	}

	return accessInfo, nil
}

// performAccessCheck performs the full access check without caching
func (am *AccessManager) performAccessCheck(ctx context.Context, apiKey string, model string) (*AccessInfo, error) {
	// Validate API key
	keyConfig, err := am.ValidateAPIKey(apiKey)
	if err != nil {
		return nil, fmt.Errorf("API key validation failed: %w", err)
	}

	// Resolve model
	modelRef, resolvedBy, err := am.ResolveModel(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("model resolution failed: %w", err)
	}

	// Check if API key can access the model via model groups
	accessGroup, err := am.checkModelGroupAccess(keyConfig, modelRef)
	if err != nil {
		return nil, fmt.Errorf("model group access check failed: %w", err)
	}

	// Check rate limit
	if err := am.checkRateLimit(apiKey, keyConfig); err != nil {
		return nil, err
	}

	return &AccessInfo{
		APIKeyConfig:   keyConfig,
		ModelReference: modelRef,
		OriginalModel:  model,
		ResolvedModel:  modelRef.Model,
		ProviderName:   modelRef.Provider,
		ModelGroup:     accessGroup,
		ResolvedBy:     resolvedBy,
		CacheKey:       am.buildCacheKey(apiKey, model),
		ResolvedAt:     time.Now(),
	}, nil
}

// performAccessCheckWithoutRateLimit performs the full access check without caching or rate limiting
func (am *AccessManager) performAccessCheckWithoutRateLimit(ctx context.Context, apiKey string, model string, keyConfig *config.APIKeyConfig) (*AccessInfo, error) {
	// Resolve model
	modelRef, resolvedBy, err := am.ResolveModel(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("model resolution failed: %w", err)
	}

	// Check if API key can access the model via model groups
	accessGroup, err := am.checkModelGroupAccess(keyConfig, modelRef)
	if err != nil {
		return nil, fmt.Errorf("model group access check failed: %w", err)
	}

	return &AccessInfo{
		APIKeyConfig:   keyConfig,
		ModelReference: modelRef,
		OriginalModel:  model,
		ResolvedModel:  modelRef.Model,
		ProviderName:   modelRef.Provider,
		ModelGroup:     accessGroup,
		ResolvedBy:     resolvedBy,
		CacheKey:       am.buildCacheKey(apiKey, model),
		ResolvedAt:     time.Now(),
	}, nil
}

// checkModelGroupAccess checks if the API key can access the model through any model group
func (am *AccessManager) checkModelGroupAccess(keyConfig *config.APIKeyConfig, modelRef *config.ModelReference) (string, error) {
	// If API key has no model group restrictions, allow access to all models
	if len(keyConfig.ModelGroups) == 0 {
		return "unrestricted", nil
	}

	if am.config == nil {
		return "", fmt.Errorf("configuration not available")
	}

	// Check each allowed model group
	for _, groupName := range keyConfig.ModelGroups {
		group, err := am.config.GetModelGroup(groupName)
		if err != nil {
			continue // Skip invalid groups
		}

		// Check if model is in this group
		for _, groupModelRef := range group.Models {
			if groupModelRef.Provider == modelRef.Provider && groupModelRef.Model == modelRef.Model {
				return groupName, nil
			}
		}
	}

	return "", fmt.Errorf("API key does not have access to model %s:%s", modelRef.Provider, modelRef.Model)
}

// checkRateLimit checks if the API key is within its rate limit
func (am *AccessManager) checkRateLimit(apiKey string, keyConfig *config.APIKeyConfig) error {
	if keyConfig.RateLimit <= 0 {
		return nil // No rate limit configured
	}

	am.rateLimitMu.Lock()
	defer am.rateLimitMu.Unlock()

	limiter, exists := am.rateLimiters[apiKey]
	if !exists {
		limiter = &RateLimiter{
			tokens:   keyConfig.RateLimit,
			capacity: keyConfig.RateLimit,
			lastRefill: time.Now(),
		}
		am.rateLimiters[apiKey] = limiter
	}

	return limiter.Allow()
}

// Allow checks if the rate limiter allows a request and consumes a token
func (rl *RateLimiter) Allow() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Refill tokens based on time elapsed
	timeSinceRefill := now.Sub(rl.lastRefill)
	if timeSinceRefill >= time.Second {
		// Refill tokens (simple implementation: 1 token per second rate)
		tokensToAdd := int(timeSinceRefill.Seconds())
		rl.tokens += tokensToAdd
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
		rl.lastRefill = now
	}

	if rl.tokens <= 0 {
		return fmt.Errorf("rate limit exceeded")
	}

	rl.tokens--
	return nil
}

// buildCacheKey builds a cache key for the given API key and model
func (am *AccessManager) buildCacheKey(apiKey, model string) string {
	// Use more characters from the API key to avoid collisions
	// Use first 16 characters to provide enough uniqueness while still masking the full key
	if len(apiKey) >= 16 {
		return fmt.Sprintf("%.16s:%s", apiKey, model)
	}
	// If API key is shorter than 16 characters, use the full key
	return fmt.Sprintf("%s:%s", apiKey, model)
}

// cacheAccessInfo caches the resolved access information
func (am *AccessManager) cacheAccessInfo(cacheKey string, accessInfo *AccessInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()

	entry := &cacheEntry{
		accessInfo: accessInfo,
		expiresAt:  time.Now().Add(am.cacheTTL),
	}

	am.cache[cacheKey] = entry

	// Clean up expired entries periodically if cache gets too large
	if len(am.cache) > 1000 {
		go am.cleanupCache()
	}
}

// cleanupCache removes expired entries from the cache
func (am *AccessManager) cleanupCache() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for key, entry := range am.cache {
		entry.mu.RLock()
		if now.After(entry.expiresAt) {
			delete(am.cache, key)
		}
		entry.mu.RUnlock()
	}
}

// GetAvailableModels returns all available models for an API key
func (am *AccessManager) GetAvailableModels(apiKey string) ([]string, error) {
	keyConfig, err := am.ValidateAPIKey(apiKey)
	if err != nil {
		return nil, fmt.Errorf("API key validation failed: %w", err)
	}

	var models []string
	modelSet := make(map[string]bool)

	// If API key has no restrictions, return all available models
	if len(keyConfig.ModelGroups) == 0 {
		// Add all aliases from model groups
		if am.config != nil && am.config.ModelGroups != nil {
			for _, group := range *am.config.ModelGroups {
				for _, modelRef := range group.Models {
					if modelRef.Alias != "" && !modelSet[modelRef.Alias] {
						models = append(models, modelRef.Alias)
						modelSet[modelRef.Alias] = true
					}
					if !modelSet[modelRef.Model] {
						models = append(models, modelRef.Model)
						modelSet[modelRef.Model] = true
					}
				}
			}
		}

		// Add all direct models from all providers
		if am.config != nil {
			for _, provider := range am.config.Providers {
				for _, model := range provider.Models {
					if !modelSet[model] {
						models = append(models, model)
						modelSet[model] = true
					}
				}
			}
		}
	} else {
		// Return only models from allowed groups
		for _, groupName := range keyConfig.ModelGroups {
			group, err := am.config.GetModelGroup(groupName)
			if err != nil {
				continue
			}

			for _, modelRef := range group.Models {
				if modelRef.Alias != "" && !modelSet[modelRef.Alias] {
					models = append(models, modelRef.Alias)
					modelSet[modelRef.Alias] = true
				}
				if !modelSet[modelRef.Model] {
					models = append(models, modelRef.Model)
					modelSet[modelRef.Model] = true
				}
			}
		}
	}

	return models, nil
}

// ClearCache clears the model resolution cache
func (am *AccessManager) ClearCache() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.cache = make(map[string]*cacheEntry)
}

// ClearRateLimiters clears all rate limiters (useful for testing)
func (am *AccessManager) ClearRateLimiters() {
	am.rateLimitMu.Lock()
	defer am.rateLimitMu.Unlock()

	am.rateLimiters = make(map[string]*RateLimiter)
}

// GetStats returns cache and rate limiting statistics
func (am *AccessManager) GetStats() map[string]interface{} {
	am.mu.RLock()
	am.rateLimitMu.RLock()
	defer am.mu.RUnlock()
	defer am.rateLimitMu.RUnlock()

	stats := map[string]interface{}{
		"cache_size":        len(am.cache),
		"rate_limiters":     len(am.rateLimiters),
		"cache_ttl_seconds": am.cacheTTL.Seconds(),
		"legacy_fallback":   am.legacyFallback,
	}

	return stats
}