package models

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// MockModelProvider implements a mock model provider
type MockModelProvider struct {
	name         string
	models       []types.Model
	shouldFail   bool
	responseTime time.Duration
	callCount    int
	mu           sync.Mutex
}

func NewMockModelProvider(name string, models []types.Model) *MockModelProvider {
	return &MockModelProvider{
		name:         name,
		models:       models,
		responseTime: 10 * time.Millisecond,
	}
}

func (m *MockModelProvider) GetModels(ctx context.Context) ([]types.Model, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++

	// Simulate response time
	time.Sleep(m.responseTime)

	if m.shouldFail {
		return nil, errors.New("mock model discovery failure")
	}

	return m.models, nil
}

func (m *MockModelProvider) SetShouldFail(shouldFail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
}

func (m *MockModelProvider) SetResponseTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseTime = duration
}

func (m *MockModelProvider) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *MockModelProvider) GetDefaultModel() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.models) == 0 {
		return ""
	}

	// Return the first model's ID as the default
	return m.models[0].ID
}

func (m *MockModelProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
	m.shouldFail = false
}

// ============================================================================
// Test Data
// ============================================================================

func createTestModels() []types.Model {
	return []types.Model{
		{
			ID:                "gpt-4",
			Name:              "GPT-4",
			MaxTokens:         8192,
			SupportsStreaming: true,
			SupportsToolCalling: true,
			SupportsResponsesAPI: true,
			Capabilities:      []string{"chat", "function-calling", "vision"},
			Pricing: types.Pricing{
				InputTokenPrice:  0.03,
				OutputTokenPrice: 0.06,
				Unit:            "1K tokens",
			},
		},
		{
			ID:                "gpt-3.5-turbo",
			Name:              "GPT-3.5 Turbo",
			MaxTokens:         4096,
			SupportsStreaming: true,
			SupportsToolCalling: false,
			SupportsResponsesAPI: false,
			Capabilities:      []string{"chat"},
			Pricing: types.Pricing{
				InputTokenPrice:  0.001,
				OutputTokenPrice: 0.002,
				Unit:            "1K tokens",
			},
		},
		{
			ID:                "claude-3-opus",
			Name:              "Claude 3 Opus",
			MaxTokens:         200000,
			SupportsStreaming: true,
			SupportsToolCalling: true,
			SupportsResponsesAPI: false,
			Capabilities:      []string{"chat", "function-calling", "vision", "long-context"},
			Pricing: types.Pricing{
				InputTokenPrice:  0.015,
				OutputTokenPrice: 0.075,
				Unit:            "1K tokens",
			},
		},
		{
			ID:                "claude-3-haiku",
			Name:              "Claude 3 Haiku",
			MaxTokens:         200000,
			SupportsStreaming: true,
			SupportsToolCalling: false,
			SupportsResponsesAPI: false,
			Capabilities:      []string{"chat", "fast"},
			Pricing: types.Pricing{
				InputTokenPrice:  0.00025,
				OutputTokenPrice: 0.00125,
				Unit:            "1K tokens",
			},
		},
	}
}

func createTestProviderConfig(name, baseURL string) *config.Provider {
	return &config.Provider{
		Name:    name,
		APIKEY:  "test-key",
		Models:  []string{"test-model"},
		BaseURL: baseURL,
	}
}

// ============================================================================
// Basic Discovery Service Tests
// ============================================================================

func TestDiscoveryServiceCreation(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	if ds == nil {
		t.Fatal("Discovery service should not be nil")
	}

	if !ds.IsEnabled() {
		t.Error("Discovery service should be enabled by default")
	}

	if ds.cacheExpiry != 5*time.Minute {
		t.Errorf("Expected cache expiry 5 minutes, got %v", ds.cacheExpiry)
	}

	// Check that maps are properly initialized
	if ds.providers == nil || ds.providerConfigs == nil || ds.modelCache == nil {
		t.Error("Provider lists and cache should be initialized")
	}
}

func TestAddProvider(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Create mock provider
	mockProvider := NewMockModelProvider("test-provider", createTestModels())
	providerConfig := createTestProviderConfig("test-provider", "https://api.test.com")

	// Add provider
	err := ds.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Try to add the same provider again (should fail)
	err = ds.AddProvider("test-provider", mockProvider, providerConfig)
	if err == nil {
		t.Error("Expected error when adding duplicate provider")
	}

	// Verify cache was invalidated
	if !ds.lastCacheUpdate.IsZero() {
		t.Error("Cache should be invalidated when new provider is added")
	}
}

func TestRemoveProvider(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add provider first
	mockProvider := NewMockModelProvider("test-provider", createTestModels())
	providerConfig := createTestProviderConfig("test-provider", "https://api.test.com")

	err := ds.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Remove provider
	err = ds.RemoveProvider("test-provider")
	if err != nil {
		t.Fatalf("Failed to remove provider: %v", err)
	}

	// Try to remove non-existent provider (should fail)
	err = ds.RemoveProvider("non-existent")
	if err == nil {
		t.Error("Expected error when removing non-existent provider")
	}
}

func TestDiscoverModelsSequential(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add multiple providers
	openaiProvider := NewMockModelProvider("openai", createTestModels())
	openaiConfig := createTestProviderConfig("openai", "https://api.openai.com")

	anthropicProvider := NewMockModelProvider("anthropic", createTestModels())
	anthropicConfig := createTestProviderConfig("anthropic", "https://api.anthropic.com")

	err := ds.AddProvider("openai", openaiProvider, openaiConfig)
	if err != nil {
		t.Fatalf("Failed to add OpenAI provider: %v", err)
	}

	err = ds.AddProvider("anthropic", anthropicProvider, anthropicConfig)
	if err != nil {
		t.Fatalf("Failed to add Anthropic provider: %v", err)
	}

	// Discover models sequentially
	ctx := context.Background()
	opts := ModelDiscoveryOptions{
		CacheResults:      false,
		ParallelDiscovery: false,
		Timeout:           10 * time.Second,
	}

	models, err := ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	// Verify results
	if len(models) != 2 {
		t.Errorf("Expected models from 2 providers, got %d", len(models))
	}

	if _, exists := models["openai"]; !exists {
		t.Error("Expected models from OpenAI provider")
	}

	if _, exists := models["anthropic"]; !exists {
		t.Error("Expected models from Anthropic provider")
	}

	// Verify each provider has the expected number of models
	if len(models["openai"]) != 4 {
		t.Errorf("Expected 4 models from OpenAI, got %d", len(models["openai"]))
	}

	if len(models["anthropic"]) != 4 {
		t.Errorf("Expected 4 models from Anthropic, got %d", len(models["anthropic"]))
	}

	// Verify providers were called
	if openaiProvider.GetCallCount() == 0 {
		t.Error("OpenAI provider should have been called")
	}

	if anthropicProvider.GetCallCount() == 0 {
		t.Error("Anthropic provider should have been called")
	}
}

func TestDiscoverModelsParallel(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add multiple providers with different response times
	openaiProvider := NewMockModelProvider("openai", createTestModels())
	openaiProvider.SetResponseTime(50 * time.Millisecond)

	anthropicProvider := NewMockModelProvider("anthropic", createTestModels())
	anthropicProvider.SetResponseTime(100 * time.Millisecond)

	geminiProvider := NewMockModelProvider("gemini", createTestModels())
	geminiProvider.SetResponseTime(30 * time.Millisecond)

	providers := map[string]*config.Provider{
		"openai":    createTestProviderConfig("openai", "https://api.openai.com"),
		"anthropic": createTestProviderConfig("anthropic", "https://api.anthropic.com"),
		"gemini":    createTestProviderConfig("gemini", "https://api.gemini.com"),
	}

	// Add providers
	for name, config := range providers {
		var provider *MockModelProvider
		switch name {
		case "openai":
			provider = openaiProvider
		case "anthropic":
			provider = anthropicProvider
		case "gemini":
			provider = geminiProvider
		}

		err := ds.AddProvider(name, provider, config)
		if err != nil {
			t.Fatalf("Failed to add %s provider: %v", name, err)
		}
	}

	// Discover models in parallel
	start := time.Now()
	ctx := context.Background()
	opts := ModelDiscoveryOptions{
		CacheResults:      false,
		ParallelDiscovery: true,
		Timeout:           5 * time.Second,
	}

	models, err := ds.DiscoverModels(ctx, opts)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	// Parallel discovery should be faster than sequential
	if duration > 200*time.Millisecond {
		t.Errorf("Parallel discovery took too long: %v (expected ~100ms)", duration)
	}

	// Verify all providers were called
	if openaiProvider.GetCallCount() == 0 || anthropicProvider.GetCallCount() == 0 || geminiProvider.GetCallCount() == 0 {
		t.Error("All providers should have been called")
	}

	// Verify results
	if len(models) != 3 {
		t.Errorf("Expected models from 3 providers, got %d", len(models))
	}
}

func TestDiscoveryCaching(t *testing.T) {
	ds := NewDiscoveryService(100 * time.Millisecond) // Short cache for testing

	// Add provider
	mockProvider := NewMockModelProvider("test-provider", createTestModels())
	providerConfig := createTestProviderConfig("test-provider", "https://api.test.com")

	err := ds.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// First discovery - should call provider
	ctx := context.Background()
	opts := ModelDiscoveryOptions{
		CacheResults:      true,
		ParallelDiscovery: true,
	}

	models, err := ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	firstCallCount := mockProvider.GetCallCount()
	if firstCallCount == 0 {
		t.Error("Provider should have been called on first discovery")
	}

	// Second discovery - should use cache
	models2, err := ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	secondCallCount := mockProvider.GetCallCount()
	if secondCallCount > firstCallCount {
		t.Error("Provider should not have been called on second discovery (cache hit)")
	}

	// Verify cached results are identical
	if len(models) != len(models2) {
		t.Error("Cached results should be identical to original")
	}

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third discovery - cache expired, should call provider again
	_, err = ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	thirdCallCount := mockProvider.GetCallCount()
	if thirdCallCount <= secondCallCount {
		t.Error("Provider should have been called again after cache expiry")
	}
}

func TestDiscoveryWithForceRefresh(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add provider
	mockProvider := NewMockModelProvider("test-provider", createTestModels())
	providerConfig := createTestProviderConfig("test-provider", "https://api.test.com")

	err := ds.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// First discovery
	ctx := context.Background()
	opts := ModelDiscoveryOptions{
		CacheResults:      true,
		ParallelDiscovery: true,
		ForceRefresh:      false,
	}

	_, err = ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	firstCallCount := mockProvider.GetCallCount()

	// Second discovery with force refresh
	opts.ForceRefresh = true
	_, err = ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models with force refresh: %v", err)
	}

	secondCallCount := mockProvider.GetCallCount()

	// Provider should have been called again despite cache
	if secondCallCount <= firstCallCount {
		t.Error("Provider should have been called again with force refresh")
	}
}

func TestDiscoveryWithFailure(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add providers - one will fail
	successProvider := NewMockModelProvider("success-provider", createTestModels())
	successConfig := createTestProviderConfig("success-provider", "https://api.success.com")

	failingProvider := NewMockModelProvider("failing-provider", createTestModels())
	failingProvider.SetShouldFail(true)
	failingConfig := createTestProviderConfig("failing-provider", "https://api.fail.com")

	err := ds.AddProvider("success-provider", successProvider, successConfig)
	if err != nil {
		t.Fatalf("Failed to add success provider: %v", err)
	}

	err = ds.AddProvider("failing-provider", failingProvider, failingConfig)
	if err != nil {
		t.Fatalf("Failed to add failing provider: %v", err)
	}

	// Discovery without including inactive providers
	ctx := context.Background()
	opts := ModelDiscoveryOptions{
		IncludeInactive:  false,
		CacheResults:     false,
		ParallelDiscovery: true,
	}

	models, err := ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models: %v", err)
	}

	// Only successful provider should be in results
	if len(models) != 1 {
		t.Errorf("Expected 1 provider (successful only), got %d", len(models))
	}

	if _, exists := models["success-provider"]; !exists {
		t.Error("Expected success-provider in results")
	}

	if _, exists := models["failing-provider"]; exists {
		t.Error("Should not include failing provider when IncludeInactive=false")
	}

	// Discovery with including inactive providers
	opts.IncludeInactive = true
	models2, err := ds.DiscoverModels(ctx, opts)
	if err != nil {
		t.Fatalf("Failed to discover models with include inactive: %v", err)
	}

	// Both providers should be in results
	if len(models2) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(models2))
	}

	if _, exists := models2["failing-provider"]; !exists {
		t.Error("Expected failing-provider in results when IncludeInactive=true")
	}
}

func TestModelInfoConversion(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Create test model
	testModel := types.Model{
		ID:                "test-gpt-4",
		Name:              "Test GPT-4",
		MaxTokens:         8192,
		SupportsStreaming: true,
		SupportsToolCalling: true,
		SupportsResponsesAPI: false,
		Capabilities:      []string{"chat", "vision"},
		Pricing: types.Pricing{
			InputTokenPrice:  0.03,
			OutputTokenPrice: 0.06,
			Unit:            "1K tokens",
		},
	}

	// Convert to ModelInfo
	providerConfig := createTestProviderConfig("test-provider", "https://api.test.com")
	modelInfo := ds.convertToModelInfo(testModel, "test-provider", providerConfig)

	// Verify conversion
	if modelInfo.ID != "test-gpt-4" {
		t.Errorf("Expected ID 'test-gpt-4', got '%s'", modelInfo.ID)
	}

	if modelInfo.ProviderName != "test-provider" {
		t.Errorf("Expected provider name 'test-provider', got '%s'", modelInfo.ProviderName)
	}

	if !modelInfo.Available {
		t.Error("Model should be marked as available")
	}

	if modelInfo.ContextWindow != 8192 {
		t.Errorf("Expected context window 8192, got %d", modelInfo.ContextWindow)
	}

	if modelInfo.Endpoint != "https://api.test.com" {
		t.Errorf("Expected endpoint 'https://api.test.com', got '%s'", modelInfo.Endpoint)
	}

	// Verify supported features
	if streaming, exists := modelInfo.SupportedFeatures["streaming"]; !exists || !streaming.(bool) {
		t.Error("Streaming should be in supported features")
	}

	if toolCalling, exists := modelInfo.SupportedFeatures["tool_calling"]; !exists || !toolCalling.(bool) {
		t.Error("Tool calling should be in supported features")
	}

	if provider, exists := modelInfo.SupportedFeatures["provider"]; !exists || provider != "test-provider" {
		t.Error("Provider should be in supported features")
	}

	// Verify tags
	hasStreamingTag := false
	for _, tag := range modelInfo.Tags {
		if tag == "streaming" {
			hasStreamingTag = true
			break
		}
	}
	if !hasStreamingTag {
		t.Error("Streaming tag should be present")
	}

	// Verify pricing information
	if pricing, exists := modelInfo.SupportedFeatures["pricing"]; !exists {
		t.Error("Pricing should be in supported features")
	} else {
		pricingMap := pricing.(map[string]interface{})
		if inputPrice := pricingMap["input_price"]; inputPrice != 0.03 {
			t.Errorf("Expected input price 0.03, got %v", inputPrice)
		}
	}
}

func TestModelFamilyGuessing(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	testCases := map[string]string{
		"gpt-4":           "gpt-4",
		"gpt-3.5-turbo":   "gpt-3.5-turbo",
		"gpt-3-text-davinci-003": "gpt-3",
		"claude-3-opus":   "claude-3",
		"claude-2":        "claude-2",
		"gemini-pro":      "gemini",
		"llama-2-70b":     "llama",
		"mistral-7b":      "mistral",
		"unknown-model":   "unknown",
	}

	for modelID, expectedFamily := range testCases {
		family := ds.guessModelFamily(modelID)
		if family != expectedFamily {
			t.Errorf("Expected family '%s' for model '%s', got '%s'", expectedFamily, modelID, family)
		}
	}
}

// ============================================================================
// Model Filtering Tests
// ============================================================================

func TestModelFiltering(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Create test models
	models := []types.Model{
		{
			ID:                "gpt-4",
			Name:              "GPT-4",
			MaxTokens:         8192,
			SupportsStreaming: true,
			SupportsToolCalling: true,
			SupportsResponsesAPI: true,
			Capabilities:      []string{"chat", "function-calling"},
		},
		{
			ID:                "gpt-3.5-turbo",
			Name:              "GPT-3.5 Turbo",
			MaxTokens:         4096,
			SupportsStreaming: true,
			SupportsToolCalling: false,
			SupportsResponsesAPI: false,
			Capabilities:      []string{"chat"},
		},
		{
			ID:                "claude-3-opus",
			Name:              "Claude 3 Opus",
			MaxTokens:         200000,
			SupportsStreaming: false,
			SupportsToolCalling: true,
			SupportsResponsesAPI: false,
			Capabilities:      []string{"chat", "function-calling", "vision"},
		},
	}

	// Convert to ModelInfo
	modelInfos := make([]*ModelInfo, len(models))
	providerConfig := createTestProviderConfig("test", "")

	for i, model := range models {
		modelInfos[i] = ds.convertToModelInfo(model, "test", providerConfig)
	}

	testModels := map[string][]*ModelInfo{
		"test": modelInfos,
		"another": []*ModelInfo{}, // Empty provider
	}

	// Test filtering by streaming support
	filter := ModelFilter{
		SupportsStreaming: &[]bool{true}[0],
	}
	filtered := ds.FilterModels(testModels, filter)

	if len(filtered["test"]) != 2 {
		t.Errorf("Expected 2 streaming models, got %d", len(filtered["test"]))
	}

	// Test filtering by tool support
	filter = ModelFilter{
		SupportsTools: &[]bool{true}[0],
	}
	filtered = ds.FilterModels(testModels, filter)

	if len(filtered["test"]) != 2 {
		t.Errorf("Expected 2 tool-supporting models, got %d", len(filtered["test"]))
	}

	// Test filtering by min tokens
	filter = ModelFilter{
		MinTokens: 10000,
	}
	filtered = ds.FilterModels(testModels, filter)

	if len(filtered["test"]) != 1 {
		t.Errorf("Expected 1 model with >10k tokens, got %d", len(filtered["test"]))
	}

	// Test filtering by features
	filter = ModelFilter{
		Features: []string{"function-calling"},
	}
	filtered = ds.FilterModels(testModels, filter)

	if len(filtered["test"]) != 2 {
		t.Errorf("Expected 2 models with function calling, got %d", len(filtered["test"]))
	}

	// Test filtering by provider
	filter = ModelFilter{
		Provider: "non-existent",
	}
	filtered = ds.FilterModels(testModels, filter)

	if len(filtered) != 0 {
		t.Error("Expected no results when filtering by non-existent provider")
	}
}

func TestModelFilteringWithTags(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Create model with specific tags
	model := types.Model{
		ID:                "test-model",
		Name:              "Test Model",
		MaxTokens:         4096,
		SupportsStreaming: true,
		SupportsToolCalling: true,
		Capabilities:      []string{"chat", "vision"},
	}

	providerConfig := createTestProviderConfig("test", "")
	modelInfo := ds.convertToModelInfo(model, "test", providerConfig)

	// Add custom tag
	modelInfo.Tags = append(modelInfo.Tags, "custom-tag")

	testModels := map[string][]*ModelInfo{
		"test": {modelInfo},
	}

	// Test filtering by existing tags
	filter := ModelFilter{
		Tags: []string{"streaming", "custom-tag"},
	}
	filtered := ds.FilterModels(testModels, filter)

	if len(filtered["test"]) != 1 {
		t.Error("Expected model to match when both required tags are present")
	}

	// Test filtering by missing tag
	filter = ModelFilter{
		Tags: []string{"non-existent-tag"},
	}
	filtered = ds.FilterModels(testModels, filter)

	if len(filtered) != 0 {
		t.Error("Expected no results when filtering by missing tag")
	}
}

// ============================================================================
// Advanced Discovery Methods Tests
// ============================================================================

func TestGetModelsByProvider(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add providers
	openaiProvider := NewMockModelProvider("openai", createTestModels())
	openaiConfig := createTestProviderConfig("openai", "")

	anthropicProvider := NewMockModelProvider("anthropic", createTestModels())
	anthropicConfig := createTestProviderConfig("anthropic", "")

	err := ds.AddProvider("openai", openaiProvider, openaiConfig)
	if err != nil {
		t.Fatalf("Failed to add OpenAI provider: %v", err)
	}

	err = ds.AddProvider("anthropic", anthropicProvider, anthropicConfig)
	if err != nil {
		t.Fatalf("Failed to add Anthropic provider: %v", err)
	}

	// Get models by provider
	ctx := context.Background()
	models, err := ds.GetModelsByProvider(ctx, "openai")
	if err != nil {
		t.Fatalf("Failed to get models by provider: %v", err)
	}

	if len(models) != 4 {
		t.Errorf("Expected 4 models from OpenAI, got %d", len(models))
	}

	// Verify model properties
	for _, model := range models {
		if model.ProviderName != "openai" {
			t.Errorf("Expected provider name 'openai', got '%s'", model.ProviderName)
		}
	}

	// Test with non-existent provider
	_, err = ds.GetModelsByProvider(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error when getting models from non-existent provider")
	}
}

func TestFindModel(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add provider
	openaiProvider := NewMockModelProvider("openai", createTestModels())
	openaiConfig := createTestProviderConfig("openai", "")

	err := ds.AddProvider("openai", openaiProvider, openaiConfig)
	if err != nil {
		t.Fatalf("Failed to add OpenAI provider: %v", err)
	}

	// Find existing model
	ctx := context.Background()
	model, err := ds.FindModel(ctx, "gpt-4")
	if err != nil {
		t.Fatalf("Failed to find model: %v", err)
	}

	if model.ID != "gpt-4" {
		t.Errorf("Expected model ID 'gpt-4', got '%s'", model.ID)
	}

	if model.ProviderName != "openai" {
		t.Errorf("Expected provider name 'openai', got '%s'", model.ProviderName)
	}

	// Find non-existent model
	_, err = ds.FindModel(ctx, "non-existent-model")
	if err == nil {
		t.Error("Expected error when finding non-existent model")
	}
}

func TestFindModelsByName(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add providers with different models
	openaiModels := []types.Model{
		{ID: "gpt-4", Name: "GPT-4"},
		{ID: "gpt-3.5-turbo", Name: "GPT-3.5 Turbo"},
	}

	anthropicModels := []types.Model{
		{ID: "claude-3-opus", Name: "Claude 3 Opus"},
		{ID: "claude-3-haiku", Name: "Claude 3 Haiku"},
	}

	openaiProvider := NewMockModelProvider("openai", openaiModels)
	openaiConfig := createTestProviderConfig("openai", "")

	anthropicProvider := NewMockModelProvider("anthropic", anthropicModels)
	anthropicConfig := createTestProviderConfig("anthropic", "")

	err := ds.AddProvider("openai", openaiProvider, openaiConfig)
	if err != nil {
		t.Fatalf("Failed to add OpenAI provider: %v", err)
	}

	err = ds.AddProvider("anthropic", anthropicProvider, anthropicConfig)
	if err != nil {
		t.Fatalf("Failed to add Anthropic provider: %v", err)
	}

	// Find models by name pattern
	ctx := context.Background()
	models, err := ds.FindModelsByName(ctx, "gpt")
	if err != nil {
		t.Fatalf("Failed to find models by name: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models matching 'gpt', got %d", len(models))
	}

	// Find models by partial name
	models, err = ds.FindModelsByName(ctx, "claude")
	if err != nil {
		t.Fatalf("Failed to find models by name: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models matching 'claude', got %d", len(models))
	}

	// Find models by exact name
	models, err = ds.FindModelsByName(ctx, "GPT-4")
	if err != nil {
		t.Fatalf("Failed to find models by exact name: %v", err)
	}

	if len(models) != 1 {
		t.Errorf("Expected 1 model matching 'GPT-4', got %d", len(models))
	}

	if models[0].ID != "gpt-4" {
		t.Errorf("Expected model ID 'gpt-4', got '%s'", models[0].ID)
	}
}

func TestGetModelsByCapability(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	testModels := []types.Model{
		{ID: "model1", MaxTokens: 4096, SupportsToolCalling: true, Capabilities: []string{"chat"}},
		{ID: "model2", MaxTokens: 8192, SupportsToolCalling: false, Capabilities: []string{"chat", "vision"}},
		{ID: "model3", MaxTokens: 16384, SupportsToolCalling: true, Capabilities: []string{"chat", "vision", "tools"}},
	}

	provider := NewMockModelProvider("test", testModels)
	providerConfig := createTestProviderConfig("test", "")

	err := ds.AddProvider("test", provider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	ctx := context.Background()

	// Get models with tool calling capability
	models, err := ds.GetModelsByCapability(ctx, "tool_calling")
	if err != nil {
		t.Fatalf("Failed to get models by capability: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models with tool calling, got %d", len(models))
	}

	// Get models with vision capability
	models, err = ds.GetModelsByCapability(ctx, "vision")
	if err != nil {
		t.Fatalf("Failed to get models by capability: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models with vision, got %d", len(models))
	}

	// Get models with multiple capabilities
	models, err = ds.GetModelsByCapability(ctx, "chat", "vision")
	if err != nil {
		t.Fatalf("Failed to get models by multiple capabilities: %v", err)
	}

	if len(models) != 2 {
		t.Errorf("Expected 2 models with both chat and vision, got %d", len(models))
	}
}

func TestGetPopularModels(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Create mix of popular and non-popular models
	testModels := []types.Model{
		{ID: "gpt-4", Name: "GPT-4"},
		{ID: "gpt-3.5-turbo", Name: "GPT-3.5 Turbo"},
		{ID: "claude-3-opus", Name: "Claude 3 Opus"},
		{ID: "claude-3-haiku", Name: "Claude 3 Haiku"},
		{ID: "unknown-model", Name: "Unknown Model"},
		{ID: "custom-llama", Name: "Custom Llama"},
	}

	provider := NewMockModelProvider("test", testModels)
	providerConfig := createTestProviderConfig("test", "")

	err := ds.AddProvider("test", provider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	ctx := context.Background()
	popularModels, err := ds.GetPopularModels(ctx)
	if err != nil {
		t.Fatalf("Failed to get popular models: %v", err)
	}

	// Should include popular models but not the unknown one
	if len(popularModels) != 4 {
		t.Errorf("Expected 4 popular models, got %d", len(popularModels))
	}

	// Verify all returned models are actually popular
	popularIDs := make(map[string]bool)
	for _, model := range popularModels {
		popularIDs[model.ID] = true
	}

	expectedPopularIDs := []string{"gpt-4", "gpt-3.5-turbo", "claude-3-opus", "claude-3-haiku"}
	for _, id := range expectedPopularIDs {
		if !popularIDs[id] {
			t.Errorf("Expected popular model %s to be included", id)
		}
	}

	// Should not include non-popular models
	if popularIDs["unknown-model"] {
		t.Error("Should not include unknown-model in popular models")
	}

	if popularIDs["custom-llama"] {
		t.Error("Should not include custom-llama in popular models")
	}
}

// ============================================================================
// Service Management Tests
// ============================================================================

func TestServiceEnableDisable(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Verify initially enabled
	if !ds.IsEnabled() {
		t.Error("Service should be enabled by default")
	}

	// Disable service
	ds.SetEnabled(false)
	if ds.IsEnabled() {
		t.Error("Service should be disabled")
	}

	// Try discovery (should fail)
	ctx := context.Background()
	_, err := ds.DiscoverModels(ctx, ModelDiscoveryOptions{})
	if err == nil {
		t.Error("Expected error when discovery is disabled")
	}

	// Re-enable service
	ds.SetEnabled(true)
	if !ds.IsEnabled() {
		t.Error("Service should be enabled")
	}
}

func TestUpdateCache(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add provider
	provider := NewMockModelProvider("test", createTestModels())
	providerConfig := createTestProviderConfig("test", "")

	err := ds.AddProvider("test", provider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Update cache
	ctx := context.Background()
	err = ds.UpdateCache(ctx)
	if err != nil {
		t.Fatalf("Failed to update cache: %v", err)
	}

	// Verify cache is valid
	if !ds.isCacheValid() {
		t.Error("Cache should be valid after update")
	}

	// Verify provider was called
	if provider.GetCallCount() == 0 {
		t.Error("Provider should have been called during cache update")
	}
}

func TestGetDiscoveryStats(t *testing.T) {
	ds := NewDiscoveryService(5 * time.Minute)

	// Add multiple providers with different models
	openaiModels := []types.Model{
		{ID: "gpt-4", MaxTokens: 8192, SupportsStreaming: true, SupportsToolCalling: true},
		{ID: "gpt-3.5-turbo", MaxTokens: 4096, SupportsStreaming: true, SupportsToolCalling: false},
	}

	anthropicModels := []types.Model{
		{ID: "claude-3-opus", MaxTokens: 200000, SupportsStreaming: false, SupportsToolCalling: true},
	}

	openaiProvider := NewMockModelProvider("openai", openaiModels)
	openaiConfig := createTestProviderConfig("openai", "")

	anthropicProvider := NewMockModelProvider("anthropic", anthropicModels)
	anthropicConfig := createTestProviderConfig("anthropic", "")

	err := ds.AddProvider("openai", openaiProvider, openaiConfig)
	if err != nil {
		t.Fatalf("Failed to add OpenAI provider: %v", err)
	}

	err = ds.AddProvider("anthropic", anthropicProvider, anthropicConfig)
	if err != nil {
		t.Fatalf("Failed to add Anthropic provider: %v", err)
	}

	// Get stats
	ctx := context.Background()
	stats, err := ds.GetDiscoveryStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get discovery stats: %v", err)
	}

	// Verify stats structure
	totalModels := stats["total_models"].(int)
	if totalModels != 3 {
		t.Errorf("Expected 3 total models, got %d", totalModels)
	}

	totalProviders := stats["total_providers"].(int)
	if totalProviders != 2 {
		t.Errorf("Expected 2 total providers, got %d", totalProviders)
	}

	streamingModels := stats["streaming_models"].(int)
	if streamingModels != 2 {
		t.Errorf("Expected 2 streaming models, got %d", streamingModels)
	}

	toolModels := stats["tool_supporting_models"].(int)
	if toolModels != 2 {
		t.Errorf("Expected 2 tool-supporting models, got %d", toolModels)
	}

	modelsByProvider := stats["models_by_provider"].(map[string]int)
	if modelsByProvider["openai"] != 2 || modelsByProvider["anthropic"] != 1 {
		t.Error("Models by provider count incorrect")
	}

	serviceEnabled := stats["service_enabled"].(bool)
	if !serviceEnabled {
		t.Error("Service should be enabled")
	}
}