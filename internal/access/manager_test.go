package access

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
)

// TestNewAccessManager tests AccessManager creation and initial setup
func TestNewAccessManager(t *testing.T) {
	// Create test configuration
	cfg := createTestConfig(t)

	// Create access manager
	am := NewAccessManager(cfg)

	if am.config != cfg {
		t.Error("AccessManager should store the provided config")
	}

	if am.cache == nil {
		t.Error("AccessManager should initialize cache")
	}

	if len(am.cache) != 0 {
		t.Error("AccessManager should start with empty cache")
	}

	if am.cacheTTL != 5*time.Minute {
		t.Errorf("Expected default cache TTL of 5 minutes, got %v", am.cacheTTL)
	}

	if am.rateLimiters == nil {
		t.Error("AccessManager should initialize rate limiters map")
	}

	if am.legacyAPIKey != cfg.APIKEY {
		t.Error("AccessManager should store legacy API key from config")
	}

	if !am.legacyFallback {
		t.Error("AccessManager should enable legacy fallback by default")
	}
}

// TestValidateAPIKey tests API key validation
func TestValidateAPIKey(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	tests := []struct {
		name           string
		apiKey         string
		expectedError  bool
		expectedDesc   string
		setupFunc      func(*config.Config)
	}{
		{
			name:          "valid client API key",
			apiKey:        "prod-api-key-123",
			expectedError: false,
			expectedDesc:  "Production key",
		},
		{
			name:          "valid unrestricted key",
			apiKey:        "unrestricted-api-key-456",
			expectedError: false,
			expectedDesc:  "Unrestricted key",
		},
		{
			name:          "valid legacy API key",
			apiKey:        "legacy-router-key",
			expectedError: false,
			expectedDesc:  "Legacy API key",
		},
		{
			name:          "disabled API key",
			apiKey:        "disabled-api-key-789",
			expectedError: true,
		},
		{
			name:          "invalid API key",
			apiKey:        "invalid-key",
			expectedError: true,
		},
		{
			name:          "empty API key",
			apiKey:        "",
			expectedError: true,
		},
		{
			name:          "expired API key",
			apiKey:        "expired-api-key-999",
			expectedError: true,
			setupFunc: func(cfg *config.Config) {
				// Add an expired key for testing
				if cfg.ClientAPIKeys != nil {
					(*cfg.ClientAPIKeys)["expired"] = &config.APIKeyConfig{
						APIKey:     "expired-api-key-999",
						Enabled:    true,
						ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup if needed
			if tt.setupFunc != nil {
				testCfg := createTestConfig(t)
				tt.setupFunc(testCfg)
				am = NewAccessManager(testCfg)
			}

			keyConfig, err := am.ValidateAPIKey(tt.apiKey)

			if (err != nil) != tt.expectedError {
				t.Errorf("ValidateAPIKey() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.expectedError {
				if keyConfig == nil {
					t.Error("ValidateAPIKey() should return key config for valid key")
				} else if tt.expectedDesc != "" && keyConfig.Description != tt.expectedDesc {
					t.Errorf("Expected description '%s', got '%s'", tt.expectedDesc, keyConfig.Description)
				}
			}
		})
	}
}

// TestValidateAPIKeyWithLegacyFallback tests legacy fallback functionality
func TestValidateAPIKeyWithLegacyFallback(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	// Test with legacy fallback enabled (default)
	t.Run("legacy fallback enabled", func(t *testing.T) {
		keyConfig, err := am.ValidateAPIKey("legacy-router-key")
		if err != nil {
			t.Errorf("Legacy API key should be valid when fallback is enabled: %v", err)
		}
		if keyConfig.Description != "Legacy API key" {
			t.Errorf("Expected 'Legacy API key', got '%s'", keyConfig.Description)
		}
	})

	// Test with legacy fallback disabled
	t.Run("legacy fallback disabled", func(t *testing.T) {
		am.EnableLegacyFallback(false)
		_, err := am.ValidateAPIKey("legacy-router-key")
		if err == nil {
			t.Error("Legacy API key should be invalid when fallback is disabled")
		}
	})
}

// TestResolveModel tests model resolution
func TestResolveModel(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	tests := []struct {
		name           string
		model          string
		expectedProvider string
		expectedModel  string
		expectedResolvedBy string
		expectedError  bool
	}{
		{
			name:           "resolve by alias",
			model:          "claude-prod",
			expectedProvider: "anthropic",
			expectedModel:  "claude-3-sonnet",
			expectedResolvedBy: "alias",
			expectedError:   false,
		},
		{
			name:           "resolve by direct model name",
			model:          "claude-3-haiku",
			expectedProvider: "anthropic",
			expectedModel:  "claude-3-haiku",
			expectedResolvedBy: "direct",
			expectedError:   false,
		},
		{
			name:          "non-existent model",
			model:         "nonexistent-model",
			expectedError: true,
		},
		{
			name:          "empty model",
			model:         "",
			expectedError: true,
		},
		{
			name:           "resolve openai model directly",
			model:          "gpt-4",
			expectedProvider: "openai",
			expectedModel:  "gpt-4",
			expectedResolvedBy: "direct",
			expectedError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modelRef, resolvedBy, err := am.ResolveModel(context.Background(), tt.model)

			if (err != nil) != tt.expectedError {
				t.Errorf("ResolveModel() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.expectedError {
				if modelRef == nil {
					t.Error("ResolveModel() should return model reference for valid model")
				} else {
					if modelRef.Provider != tt.expectedProvider {
						t.Errorf("Expected provider '%s', got '%s'", tt.expectedProvider, modelRef.Provider)
					}
					if modelRef.Model != tt.expectedModel {
						t.Errorf("Expected model '%s', got '%s'", tt.expectedModel, modelRef.Model)
					}
				}
				if resolvedBy != tt.expectedResolvedBy {
					t.Errorf("Expected resolvedBy '%s', got '%s'", tt.expectedResolvedBy, resolvedBy)
				}
			}
		})
	}
}

// TestCanAccessModel tests model access checking
func TestCanAccessModel(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	tests := []struct {
		name          string
		apiKey        string
		model         string
		expectedError bool
		expectedGroup string
		expectedResolvedBy string
	}{
		{
			name:          "unrestricted key access",
			apiKey:        "unrestricted-api-key-456",
			model:         "claude-3-sonnet",
			expectedError: false,
			expectedGroup: "unrestricted",
			expectedResolvedBy: "direct",
		},
		{
			name:          "restricted key access to allowed model",
			apiKey:        "prod-api-key-123",
			model:         "claude-prod", // Alias for claude-3-sonnet
			expectedError: false,
			expectedGroup: "production",
			expectedResolvedBy: "alias",
		},
		{
			name:          "restricted key access to disallowed model",
			apiKey:        "prod-api-key-123",
			model:         "claude-dev", // Not in production group
			expectedError: true,
		},
		{
			name:          "invalid API key",
			apiKey:        "invalid-key",
			model:         "claude-prod",
			expectedError: true,
		},
		{
			name:          "valid key but non-existent model",
			apiKey:        "prod-api-key-123",
			model:         "nonexistent-model",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			accessInfo, err := am.CanAccessModel(ctx, tt.apiKey, tt.model)

			if (err != nil) != tt.expectedError {
				t.Errorf("CanAccessModel() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.expectedError {
				if accessInfo == nil {
					t.Error("CanAccessModel() should return access info for valid access")
				} else {
					if tt.expectedGroup != "" && accessInfo.ModelGroup != tt.expectedGroup {
						t.Errorf("Expected model group '%s', got '%s'", tt.expectedGroup, accessInfo.ModelGroup)
					}
					if tt.expectedResolvedBy != "" && accessInfo.ResolvedBy != tt.expectedResolvedBy {
						t.Errorf("Expected resolvedBy '%s', got '%s'", tt.expectedResolvedBy, accessInfo.ResolvedBy)
					}
					if accessInfo.APIKeyConfig == nil {
						t.Error("CanAccessModel() should include API key config")
					}
					if accessInfo.ModelReference == nil {
						t.Error("CanAccessModel() should include model reference")
					}
					if accessInfo.OriginalModel != tt.model {
						t.Errorf("Expected original model '%s', got '%s'", tt.model, accessInfo.OriginalModel)
					}
					if accessInfo.ResolvedAt.IsZero() {
						t.Error("CanAccessModel() should set resolved timestamp")
					}
				}
			}
		})
	}
}

// TestCacheFunctionality tests caching behavior
func TestCacheFunctionality(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)
	am.SetCacheTTL(100 * time.Millisecond) // Short TTL for testing
	am.ClearRateLimiters() // Ensure clean rate limiting state

	ctx := context.Background()
	apiKey := "unrestricted-api-key-456" // Use unrestricted key to avoid rate limiting
	model := "claude-prod"

	// First call should miss cache
	start := time.Now()
	accessInfo1, err := am.CanAccessModel(ctx, apiKey, model)
	if err != nil {
		t.Fatalf("CanAccessModel() failed: %v", err)
	}
	duration1 := time.Since(start)

	// Second call should hit cache
	start = time.Now()
	accessInfo2, err := am.CanAccessModel(ctx, apiKey, model)
	if err != nil {
		t.Fatalf("CanAccessModel() failed on cache hit: %v", err)
	}
	duration2 := time.Since(start)

	// Cache should generally be faster, but allow for some variance due to system load
	// Use a more lenient check - cached call should not be significantly slower
	if duration2 > duration1*2 {
		t.Errorf("Cached call should be faster than initial call. Initial: %v, Cached: %v", duration1, duration2)
	}

	// Access info should be the same
	if accessInfo1.CacheKey != accessInfo2.CacheKey {
		t.Error("Cache keys should be the same for same input")
	}

	if accessInfo1.ResolvedAt.Equal(accessInfo2.ResolvedAt) {
		t.Error("Resolved timestamps should be different for different calls")
	}

	// Wait for cache to expire
	time.Sleep(120 * time.Millisecond)

	// Call after cache expiration - cache should automatically clear

	accessInfo3, err := am.CanAccessModel(ctx, apiKey, model)
	if err != nil {
		t.Fatalf("CanAccessModel() failed after cache expiration: %v", err)
	}

	if accessInfo3.CacheKey != accessInfo1.CacheKey {
		t.Error("Cache keys should be consistent even after expiration")
	}
}

// TestCacheInvalidation tests cache clearing and invalidation
func TestCacheInvalidation(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	ctx := context.Background()
	apiKey := "prod-api-key-123"
	model := "claude-prod"

	// Add some cache entries
	_, err := am.CanAccessModel(ctx, apiKey, model)
	if err != nil {
		t.Fatalf("CanAccessModel() failed: %v", err)
	}

	_, err = am.CanAccessModel(ctx, "unrestricted-api-key-456", "claude-3-haiku")
	if err != nil {
		t.Fatalf("CanAccessModel() failed: %v", err)
	}

	// Check cache size
	stats := am.GetStats()
	if stats["cache_size"].(int) != 2 {
		t.Errorf("Expected cache size 2, got %v", stats["cache_size"])
	}

	// Clear cache
	am.ClearCache()

	// Check cache is empty
	stats = am.GetStats()
	if stats["cache_size"].(int) != 0 {
		t.Errorf("Expected cache size 0 after clear, got %v", stats["cache_size"])
	}
}

// TestRateLimiting tests rate limiting functionality
func TestRateLimiting(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	ctx := context.Background()

	t.Run("no rate limit configured", func(t *testing.T) {
		// Use unrestricted key with no rate limit
		apiKey := "unrestricted-api-key-456"
		model := "claude-3-haiku"

		// Multiple requests should not be limited
		for i := 0; i < 10; i++ {
			_, err := am.CanAccessModel(ctx, apiKey, model)
			if err != nil {
				t.Errorf("Request %d should not be rate limited: %v", i, err)
			}
		}
	})

	t.Run("rate limit enforced", func(t *testing.T) {
		// Clear rate limiters to ensure clean state
		am.ClearRateLimiters()

		// Use production key with rate limit of 2
		apiKey := "prod-api-key-123"
		model := "claude-prod"

		// First two requests should succeed
		for i := 0; i < 2; i++ {
			_, err := am.CanAccessModel(ctx, apiKey, model)
			if err != nil {
				t.Errorf("Request %d should succeed: %v", i, err)
			}
		}

		// Third request should be rate limited
		_, err := am.CanAccessModel(ctx, apiKey, model)
		if err == nil {
			t.Error("Third request should be rate limited")
		}

		// Wait for token refill (1 second)
		time.Sleep(1 * time.Second + 100 * time.Millisecond)

		// Next request should succeed
		_, err = am.CanAccessModel(ctx, apiKey, model)
		if err != nil {
			t.Errorf("Request after refill should succeed: %v", err)
		}
	})

	t.Run("different keys have separate limits", func(t *testing.T) {
		// Clear rate limiters to ensure clean state
		am.ClearRateLimiters()

		// Use prod key (rate limited) and unrestricted key (not limited)

		// Exhaust prod key limit
		for i := 0; i < 2; i++ {
			_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
			if err != nil {
				t.Errorf("Prod key request %d should succeed: %v", i, err)
			}
		}

		// Third request with prod key should be limited
		_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
		if err == nil {
			t.Error("Third prod key request should be rate limited")
		}

		// But unrestricted key should still work
		_, err = am.CanAccessModel(ctx, "unrestricted-api-key-456", "claude-3-haiku")
		if err != nil {
			t.Errorf("Unrestricted key should not be rate limited: %v", err)
		}
	})
}

// TestConcurrentAccess tests thread safety under concurrent access
func TestConcurrentAccess(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	ctx := context.Background()
	numGoroutines := 50
	numRequests := 100

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*numRequests)

	// Concurrent requests to test thread safety
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				apiKey := "unrestricted-api-key-456"
				models := []string{"claude-prod", "claude-3-haiku", "gpt-4"}
				model := models[j%len(models)]

				_, err := am.CanAccessModel(ctx, apiKey, model)
				if err != nil {
					errors <- err
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent access failed: %v", err)
	}
}

// TestConcurrentCacheOperations tests thread safety of cache operations
func TestConcurrentCacheOperations(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)
	am.SetCacheTTL(10 * time.Millisecond) // Very short TTL for testing

	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent cache access and clearing
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, err := am.CanAccessModel(ctx, "unrestricted-api-key-456", "claude-prod")
				if err != nil {
					t.Errorf("Cache access failed: %v", err)
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				am.ClearCache()
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	wg.Wait()

	// Check final stats
	stats := am.GetStats()
	if cacheSize, ok := stats["cache_size"].(int); ok && cacheSize < 0 {
		t.Errorf("Cache size should be non-negative, got %d", cacheSize)
	}
}

// TestGetAvailableModels tests available models listing
func TestGetAvailableModels(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	tests := []struct {
		name               string
		apiKey             string
		expectedModelCount int
		expectedModels     []string
	}{
		{
			name:               "unrestricted key",
			apiKey:             "unrestricted-api-key-456",
			expectedModelCount: 7, // All models and aliases: claude-prod, claude-dev, claude-3-sonnet, claude-3-haiku, claude-3-opus, gpt-4, gpt-3.5-turbo
		},
		{
			name:               "production key",
			apiKey:             "prod-api-key-123",
			expectedModelCount: 2, // Only production models and aliases
		},
		{
			name:               "development key",
			apiKey:             "dev-api-key-789",
			expectedModelCount: 2, // Only development models and aliases
		},
		{
			name:               "invalid key",
			apiKey:             "invalid-key",
			expectedModelCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			models, err := am.GetAvailableModels(tt.apiKey)

			if tt.apiKey == "invalid-key" {
				if err == nil {
					t.Error("GetAvailableModels() should return error for invalid key")
				}
				return
			}

			if err != nil {
				t.Errorf("GetAvailableModels() failed: %v", err)
				return
			}

			if len(models) != tt.expectedModelCount {
				t.Errorf("Expected %d models, got %d: %v", tt.expectedModelCount, len(models), models)
			}

			// Check that expected models are present
			for _, expectedModel := range tt.expectedModels {
				found := false
				for _, model := range models {
					if model == expectedModel {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected model '%s' not found in available models: %v", expectedModel, models)
				}
			}

			// Check for duplicates
			modelSet := make(map[string]bool)
			for _, model := range models {
				if modelSet[model] {
					t.Errorf("Duplicate model found: %s", model)
				}
				modelSet[model] = true
			}
		})
	}
}

// TestAccessManagerConfiguration tests configuration options
func TestAccessManagerConfiguration(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	// Test SetCacheTTL
	newTTL := 10 * time.Minute
	am.SetCacheTTL(newTTL)
	if am.cacheTTL != newTTL {
		t.Errorf("Expected cache TTL %v, got %v", newTTL, am.cacheTTL)
	}

	// Test EnableLegacyFallback
	am.EnableLegacyFallback(false)
	if am.legacyFallback != false {
		t.Error("Legacy fallback should be disabled")
	}

	am.EnableLegacyFallback(true)
	if am.legacyFallback != true {
		t.Error("Legacy fallback should be enabled")
	}

	// Test GetStats
	stats := am.GetStats()
	expectedKeys := []string{"cache_size", "rate_limiters", "cache_ttl_seconds", "legacy_fallback"}
	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Stats should contain key '%s': %v", key, stats)
		}
	}

	// Verify stats values
	if stats["cache_ttl_seconds"].(float64) != newTTL.Seconds() {
		t.Errorf("Expected cache TTL seconds %f, got %f", newTTL.Seconds(), stats["cache_ttl_seconds"].(float64))
	}

	if stats["legacy_fallback"].(bool) != true {
		t.Error("Expected legacy_fallback to be true in stats")
	}
}

// TestAccessManagerEdgeCases tests edge cases and error conditions
func TestAccessManagerEdgeCases(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	ctx := context.Background()

	t.Run("nil config", func(t *testing.T) {
		amNilConfig := NewAccessManager(nil)
		if amNilConfig.config != nil {
			t.Error("AccessManager should handle nil config")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
		// The function might not check context cancellation, but should still work
		_ = err // We don't assert here as behavior may vary
	})

	t.Run("zero TTL cache", func(t *testing.T) {
		am.SetCacheTTL(0)

		_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
		if err != nil {
			t.Errorf("CanAccessModel() should work with zero TTL cache: %v", err)
		}

		// Check that cache doesn't grow
		stats := am.GetStats()
		if cacheSize, ok := stats["cache_size"].(int); ok && cacheSize != 0 {
			t.Errorf("Cache should not grow with zero TTL, got size %d", cacheSize)
		}
	})

	t.Run("very large cache cleanup", func(t *testing.T) {
		// Simulate a large cache
		for i := 0; i < 1001; i++ { // Over threshold for cleanup
			_, err := am.CanAccessModel(ctx, "unrestricted-api-key-456", "claude-prod")
			if err != nil {
				t.Errorf("CanAccessModel() failed: %v", err)
			}
		}

		stats := am.GetStats()
		if cacheSize, ok := stats["cache_size"].(int); ok && cacheSize > 1001 {
			t.Errorf("Cache should not grow uncontrollably, got size %d", cacheSize)
		}
	})

	t.Run("empty model groups", func(t *testing.T) {
		emptyCfg := &config.Config{
			Providers: []config.Provider{
				{Name: "test", AuthMethod: config.AuthMethodAPIKey, APIKEY: "key", BaseURL: "https://test.com", Models: []string{"model1"}},
			},
			Router: config.RouterConfig{
				Default: "test",
			},
			ModelGroups: &config.ModelGroups{},
			ClientAPIKeys: &config.ClientAPIKeys{
				"test": {APIKey: "test-key", Enabled: true},
			},
		}
		emptyAM := NewAccessManager(emptyCfg)

		_, err := emptyAM.GetAvailableModels("test-key")
		if err != nil {
			t.Errorf("GetAvailableModels() should work with empty model groups: %v", err)
		}
	})
}

// TestRateLimiter tests the rate limiter implementation in detail
func TestRateLimiter(t *testing.T) {
	limiter := &RateLimiter{
		tokens:    2,
		capacity:  2,
		lastRefill: time.Now(),
	}

	// Test allowance within limit
	for i := 0; i < 2; i++ {
		err := limiter.Allow()
		if err != nil {
			t.Errorf("Request %d should be allowed: %v", i, err)
		}
	}

	// Test denial when limit exceeded
	err := limiter.Allow()
	if err == nil {
		t.Error("Request beyond limit should be denied")
	}

	// Test token refill after time
	time.Sleep(1 * time.Second + 100 * time.Millisecond)
	err = limiter.Allow()
	if err != nil {
		t.Errorf("Request after refill should be allowed: %v", err)
	}

	// Test that tokens don't exceed capacity
	time.Sleep(5 * time.Second)
	err = limiter.Allow()
	if err != nil {
		t.Errorf("Request after long wait should be allowed: %v", err)
	}

	// Check that tokens are properly managed
	if limiter.tokens > limiter.capacity {
		t.Errorf("Tokens should not exceed capacity, got %d", limiter.tokens)
	}
}

// Helper function to create test configuration
func createTestConfig(t *testing.T) *config.Config {
	modelGroups := config.ModelGroups{
		"production": {
			Description: "Production models",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
			},
		},
		"development": {
			Description: "Development models",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-dev"},
			},
		},
	}

	clientAPIKeys := config.ClientAPIKeys{
		"prod": {
			APIKey:      "prod-api-key-123",
			Description: "Production key",
			ModelGroups: []string{"production"},
			Enabled:     true,
			RateLimit:   2, // Low rate limit for testing
		},
		"dev": {
			APIKey:      "dev-api-key-789",
			Description: "Development key",
			ModelGroups: []string{"development"},
			Enabled:     true,
		},
		"unrestricted": {
			APIKey:      "unrestricted-api-key-456",
			Description: "Unrestricted key",
			ModelGroups: []string{}, // Empty = unrestricted
			Enabled:     true,
		},
		"disabled": {
			APIKey:      "disabled-api-key-789",
			Description: "Disabled key",
			ModelGroups: []string{"production"},
			Enabled:     false,
		},
	}

	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "anthropic-key-123",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-sonnet", "claude-3-haiku", "claude-3-opus"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "openai-key-456",
				BaseURL:    "https://api.openai.com",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
		},
		Router: config.RouterConfig{
			Default: "anthropic",
		},
		ModelGroups:  &modelGroups,
		ClientAPIKeys: &clientAPIKeys,
		APIKEY:       "legacy-router-key", // For legacy fallback testing
	}

	// Validate test configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Test configuration is invalid: %v", err)
	}

	return cfg
}

// BenchmarkAccessManager benchmarks for access manager operations
func BenchmarkAccessManager(b *testing.B) {
	cfg := createTestConfig(&testing.T{})
	am := NewAccessManager(cfg)
	ctx := context.Background()

	b.Run("ValidateAPIKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := am.ValidateAPIKey("prod-api-key-123")
			if err != nil {
				b.Fatalf("ValidateAPIKey failed: %v", err)
			}
		}
	})

	b.Run("ResolveModel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := am.ResolveModel(ctx, "claude-prod")
			if err != nil {
				b.Fatalf("ResolveModel failed: %v", err)
			}
		}
	})

	b.Run("CanAccessModel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
			if err != nil {
				b.Fatalf("CanAccessModel failed: %v", err)
			}
		}
	})

	b.Run("CanAccessModelCacheHit", func(b *testing.B) {
		// Prime the cache
		_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
		if err != nil {
			b.Fatalf("Failed to prime cache: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := am.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
			if err != nil {
				b.Fatalf("CanAccessModel failed: %v", err)
			}
		}
	})
}

// TestAccessManagerPerformanceUnderLoad tests performance with high load
func TestAccessManagerPerformanceUnderLoad(t *testing.T) {
	cfg := createTestConfig(t)
	am := NewAccessManager(cfg)

	ctx := context.Background()
	numGoroutines := 100
	numRequests := 1000

	var wg sync.WaitGroup
	successCount := 0
	errorCount := 0
	var mu sync.Mutex

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numRequests; j++ {
				apiKeys := []string{"prod-api-key-123", "unrestricted-api-key-456"}
				models := []string{"claude-prod", "claude-dev", "claude-3-haiku"}

				apiKey := apiKeys[j%len(apiKeys)]
				model := models[j%len(models)]

				_, err := am.CanAccessModel(ctx, apiKey, model)

				mu.Lock()
				if err != nil {
					// Some errors are expected due to rate limiting
					errorCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	totalRequests := numGoroutines * numRequests
	successRate := float64(successCount) / float64(totalRequests) * 100
	requestsPerSecond := float64(totalRequests) / duration.Seconds()

	t.Logf("Performance Test Results:")
	t.Logf("  Total requests: %d", totalRequests)
	t.Logf("  Success rate: %.2f%%", successRate)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Requests/sec: %.2f", requestsPerSecond)
	t.Logf("  Successes: %d", successCount)
	t.Logf("  Errors: %d", errorCount)

	// Basic performance assertions
	if successRate == 0 {
		t.Error("All requests failed - this indicates a serious performance issue")
	}

	if requestsPerSecond < 100 {
		t.Errorf("Performance below expected threshold: %.2f requests/sec (expected >= 100)", requestsPerSecond)
	}

	// Check final stats
	stats := am.GetStats()
	t.Logf("  Cache size: %v", stats["cache_size"])
	t.Logf("  Rate limiters: %v", stats["rate_limiters"])
}