package models

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// DiscoveryService provides model discovery and capability detection across providers
// It leverages the ModelProvider interface from ai-provider-kit
type DiscoveryService struct {
	providers       map[string]types.ModelProvider
	providerConfigs map[string]*config.Provider
	modelCache      map[string]*ModelInfo
	cacheExpiry     time.Duration
	lastCacheUpdate time.Time
	mu              sync.RWMutex
	enabled         bool
}

// ModelInfo extends the basic Model information with additional metadata
type ModelInfo struct {
	types.Model
	ProviderName      string                 `json:"provider_name"`
	ConfigName        string                 `json:"config_name"`
	LastUpdated       time.Time              `json:"last_updated"`
	Available         bool                   `json:"available"`
	Endpoint          string                 `json:"endpoint,omitempty"`
	Region            string                 `json:"region,omitempty"`
	ContextWindow     int                    `json:"context_window"`
	SupportedFeatures map[string]interface{} `json:"supported_features"`
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// ModelFilter defines criteria for filtering models
type ModelFilter struct {
	Provider          string            `json:"provider,omitempty"`
	Features          []string          `json:"features,omitempty"`
	MinTokens         int               `json:"min_tokens,omitempty"`
	MaxTokens         int               `json:"max_tokens,omitempty"`
	SupportsStreaming *bool             `json:"supports_streaming,omitempty"`
	SupportsTools     *bool             `json:"supports_tools,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	CustomFilters     map[string]interface{} `json:"custom_filters,omitempty"`
}

// ModelDiscoveryOptions controls how model discovery is performed
type ModelDiscoveryOptions struct {
	ForceRefresh     bool          `json:"force_refresh"`
	Timeout          time.Duration `json:"timeout"`
	IncludeInactive  bool          `json:"include_inactive"`
	CacheResults     bool          `json:"cache_results"`
	ParallelDiscovery bool         `json:"parallel_discovery"`
}

// NewDiscoveryService creates a new model discovery service
func NewDiscoveryService(cacheExpiry time.Duration) *DiscoveryService {
	return &DiscoveryService{
		providers:       make(map[string]types.ModelProvider),
		providerConfigs: make(map[string]*config.Provider),
		modelCache:      make(map[string]*ModelInfo),
		cacheExpiry:     cacheExpiry,
		enabled:         true,
	}
}

// AddProvider adds a provider to model discovery
func (ds *DiscoveryService) AddProvider(name string, provider types.ModelProvider, config *config.Provider) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.providers[name]; exists {
		return fmt.Errorf("provider %s is already registered for discovery", name)
	}

	ds.providers[name] = provider
	ds.providerConfigs[name] = config

	// Invalidate cache when new provider is added
	ds.lastCacheUpdate = time.Time{}

	log.Printf("Added provider %s to model discovery", name)
	return nil
}

// RemoveProvider removes a provider from model discovery
func (ds *DiscoveryService) RemoveProvider(name string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if _, exists := ds.providers[name]; !exists {
		return fmt.Errorf("provider %s is not registered for discovery", name)
	}

	delete(ds.providers, name)
	delete(ds.providerConfigs, name)

	// Remove cached models for this provider
	keyPrefix := name + ":"
	for key := range ds.modelCache {
		if strings.HasPrefix(key, keyPrefix) {
			delete(ds.modelCache, key)
		}
	}

	log.Printf("Removed provider %s from model discovery", name)
	return nil
}

// DiscoverModels discovers all models from all providers
func (ds *DiscoveryService) DiscoverModels(ctx context.Context, opts ModelDiscoveryOptions) (map[string][]*ModelInfo, error) {
	if !ds.enabled {
		return nil, fmt.Errorf("model discovery is disabled")
	}

	// Check cache first
	if !opts.ForceRefresh && ds.isCacheValid() {
		log.Printf("Returning cached model information")
		return ds.getCachedModels(), nil
	}

	ds.mu.RLock()
	providers := make(map[string]types.ModelProvider)
	configs := make(map[string]*config.Provider)
	for name, provider := range ds.providers {
		providers[name] = provider
		configs[name] = ds.providerConfigs[name]
	}
	ds.mu.RUnlock()

	result := make(map[string][]*ModelInfo)
	var wg sync.WaitGroup
	var mu sync.Mutex

	if opts.ParallelDiscovery {
		// Discover models in parallel
		for name, provider := range providers {
			wg.Add(1)
			go func(name string, provider types.ModelProvider, config *config.Provider) {
				defer wg.Done()
				models, err := ds.discoverProviderModels(ctx, name, provider, config, opts)
				if err != nil {
					log.Printf("Failed to discover models for provider %s: %v", name, err)
					if opts.IncludeInactive {
						mu.Lock()
						result[name] = []*ModelInfo{}
						mu.Unlock()
					}
					return
				}

				mu.Lock()
				result[name] = models
				mu.Unlock()
			}(name, provider, configs[name])
		}
		wg.Wait()
	} else {
		// Discover models sequentially
		for name, provider := range providers {
			models, err := ds.discoverProviderModels(ctx, name, provider, configs[name], opts)
			if err != nil {
				log.Printf("Failed to discover models for provider %s: %v", name, err)
				if opts.IncludeInactive {
					result[name] = []*ModelInfo{}
				}
				continue
			}
			result[name] = models
		}
	}

	// Update cache if caching is enabled
	if opts.CacheResults {
		ds.updateCache(result)
	}

	return result, nil
}

// discoverProviderModels discovers models for a single provider
func (ds *DiscoveryService) discoverProviderModels(ctx context.Context, name string, provider types.ModelProvider, config *config.Provider, opts ModelDiscoveryOptions) ([]*ModelInfo, error) {
	// Apply timeout if specified
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Get models from provider
	models, err := provider.GetModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get models from provider %s: %w", name, err)
	}

	// Convert to ModelInfo
	var modelInfos []*ModelInfo
	for _, model := range models {
		modelInfo := ds.convertToModelInfo(model, name, config)
		modelInfos = append(modelInfos, modelInfo)
	}

	return modelInfos, nil
}

// convertToModelInfo converts a basic Model to ModelInfo with additional metadata
func (ds *DiscoveryService) convertToModelInfo(model types.Model, providerName string, config *config.Provider) *ModelInfo {
	modelInfo := &ModelInfo{
		Model:             model,
		ProviderName:      providerName,
		ConfigName:        config.Name,
		LastUpdated:       time.Now(),
		Available:         true, // Assume available unless proven otherwise
		ContextWindow:     model.MaxTokens,
		SupportedFeatures: make(map[string]interface{}),
		Tags:              make([]string, 0),
		Metadata:          make(map[string]interface{}),
	}

	// Add endpoint information
	if config.BaseURL != "" {
		modelInfo.Endpoint = config.BaseURL
	}

	// Add supported features based on model capabilities
	if model.SupportsStreaming {
		modelInfo.SupportedFeatures["streaming"] = true
		modelInfo.Tags = append(modelInfo.Tags, "streaming")
	}

	if model.SupportsToolCalling {
		modelInfo.SupportedFeatures["tool_calling"] = true
		modelInfo.Tags = append(modelInfo.Tags, "tools")
	}

	if model.SupportsResponsesAPI {
		modelInfo.SupportedFeatures["responses_api"] = true
		modelInfo.Tags = append(modelInfo.Tags, "api")
	}

	// Add capability-based features
	for _, capability := range model.Capabilities {
		modelInfo.SupportedFeatures[capability] = true
		modelInfo.Tags = append(modelInfo.Tags, strings.ToLower(capability))
	}

	// Add provider-specific features
	modelInfo.SupportedFeatures["provider"] = providerName
	modelInfo.SupportedFeatures["model_family"] = ds.guessModelFamily(model.ID)

	// Add pricing information if available
	if model.Pricing.InputTokenPrice > 0 || model.Pricing.OutputTokenPrice > 0 {
		modelInfo.SupportedFeatures["pricing"] = map[string]interface{}{
			"input_price":  model.Pricing.InputTokenPrice,
			"output_price": model.Pricing.OutputTokenPrice,
			"unit":         model.Pricing.Unit,
		}
	}

	return modelInfo
}

// guessModelFamily attempts to guess the model family from the model ID
func (ds *DiscoveryService) guessModelFamily(modelID string) string {
	id := strings.ToLower(modelID)

	if strings.Contains(id, "gpt") {
		if strings.Contains(id, "4") {
			return "gpt-4"
		} else if strings.Contains(id, "3.5") {
			return "gpt-3.5-turbo"
		} else if strings.Contains(id, "3") {
			return "gpt-3"
		}
	} else if strings.Contains(id, "claude") {
		if strings.Contains(id, "3") {
			return "claude-3"
		} else if strings.Contains(id, "2") {
			return "claude-2"
		}
	} else if strings.Contains(id, "gemini") {
		return "gemini"
	} else if strings.Contains(id, "llama") {
		return "llama"
	} else if strings.Contains(id, "mistral") {
		return "mistral"
	}

	return "unknown"
}

// FilterModels filters models based on the provided criteria
func (ds *DiscoveryService) FilterModels(models map[string][]*ModelInfo, filter ModelFilter) map[string][]*ModelInfo {
	result := make(map[string][]*ModelInfo)

	for providerName, providerModels := range models {
		// Skip if provider filter is set and doesn't match
		if filter.Provider != "" && providerName != filter.Provider {
			continue
		}

		var filtered []*ModelInfo
		for _, model := range providerModels {
			if ds.modelMatchesFilter(model, filter) {
				filtered = append(filtered, model)
			}
		}

		if len(filtered) > 0 {
			result[providerName] = filtered
		}
	}

	return result
}

// modelMatchesFilter checks if a model matches the filter criteria
func (ds *DiscoveryService) modelMatchesFilter(model *ModelInfo, filter ModelFilter) bool {
	// Check features
	if len(filter.Features) > 0 {
		for _, feature := range filter.Features {
			if supported, exists := model.SupportedFeatures[feature]; !exists || !supported.(bool) {
				return false
			}
		}
	}

	// Check token limits
	if filter.MinTokens > 0 && model.MaxTokens < filter.MinTokens {
		return false
	}
	if filter.MaxTokens > 0 && model.MaxTokens > filter.MaxTokens {
		return false
	}

	// Check streaming support
	if filter.SupportsStreaming != nil {
		if *filter.SupportsStreaming != model.SupportsStreaming {
			return false
		}
	}

	// Check tool support
	if filter.SupportsTools != nil {
		if *filter.SupportsTools != model.SupportsToolCalling {
			return false
		}
	}

	// Check tags
	if len(filter.Tags) > 0 {
		modelTags := make(map[string]bool)
		for _, tag := range model.Tags {
			modelTags[tag] = true
		}

		for _, requiredTag := range filter.Tags {
			if !modelTags[requiredTag] {
				return false
			}
		}
	}

	// Check custom filters
	for key, value := range filter.CustomFilters {
		if modelValue, exists := model.Metadata[key]; !exists || modelValue != value {
			return false
		}
	}

	return true
}

// GetAllModels returns all models from all providers
func (ds *DiscoveryService) GetAllModels(ctx context.Context) (map[string][]*ModelInfo, error) {
	return ds.DiscoverModels(ctx, ModelDiscoveryOptions{
		CacheResults: true,
		ParallelDiscovery: true,
	})
}

// GetModelsByProvider returns models for a specific provider
func (ds *DiscoveryService) GetModelsByProvider(ctx context.Context, providerName string) ([]*ModelInfo, error) {
	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	providerModels, exists := models[providerName]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	return providerModels, nil
}

// FindModel finds a specific model across all providers
func (ds *DiscoveryService) FindModel(ctx context.Context, modelID string) (*ModelInfo, error) {
	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	for _, providerModels := range models {
		for _, model := range providerModels {
			if model.ID == modelID {
				return model, nil
			}
		}
	}

	return nil, fmt.Errorf("model %s not found", modelID)
}

// FindModelsByName finds models by name (partial match) across all providers
func (ds *DiscoveryService) FindModelsByName(ctx context.Context, namePattern string) ([]*ModelInfo, error) {
	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	var found []*ModelInfo
	pattern := strings.ToLower(namePattern)

	for _, providerModels := range models {
		for _, model := range providerModels {
			if strings.Contains(strings.ToLower(model.Name), pattern) ||
				strings.Contains(strings.ToLower(model.ID), pattern) {
				found = append(found, model)
			}
		}
	}

	return found, nil
}

// GetModelsByCapability returns models that support specific capabilities
func (ds *DiscoveryService) GetModelsByCapability(ctx context.Context, capabilities ...string) ([]*ModelInfo, error) {
	filter := ModelFilter{
		Features: capabilities,
	}

	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	filtered := ds.FilterModels(models, filter)

	var result []*ModelInfo
	for _, providerModels := range filtered {
		result = append(result, providerModels...)
	}

	// Sort by name for consistent results
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// GetPopularModels returns a curated list of popular models
func (ds *DiscoveryService) GetPopularModels(ctx context.Context) ([]*ModelInfo, error) {
	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	// Define popular model patterns
	popularPatterns := []string{
		"gpt-4", "gpt-3.5-turbo",
		"claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
		"gemini-pro",
		"llama-2", "llama-3",
	}

	var popular []*ModelInfo
	for _, providerModels := range models {
		for _, model := range providerModels {
			modelID := strings.ToLower(model.ID)
			for _, pattern := range popularPatterns {
				if strings.Contains(modelID, pattern) {
					popular = append(popular, model)
					break
				}
			}
		}
	}

	// Sort by provider then by name
	sort.Slice(popular, func(i, j int) bool {
		if popular[i].ProviderName != popular[j].ProviderName {
			return popular[i].ProviderName < popular[j].ProviderName
		}
		return popular[i].Name < popular[j].Name
	})

	return popular, nil
}

// UpdateCache updates the model cache with fresh data
func (ds *DiscoveryService) UpdateCache(ctx context.Context) error {
	_, err := ds.DiscoverModels(ctx, ModelDiscoveryOptions{
		ForceRefresh:     true,
		CacheResults:     true,
		ParallelDiscovery: true,
	})
	return err
}

// isCacheValid checks if the cache is still valid
func (ds *DiscoveryService) isCacheValid() bool {
	if ds.lastCacheUpdate.IsZero() {
		return false
	}
	return time.Since(ds.lastCacheUpdate) < ds.cacheExpiry
}

// getCachedModels returns models from cache
func (ds *DiscoveryService) getCachedModels() map[string][]*ModelInfo {
	result := make(map[string][]*ModelInfo)

	for key, model := range ds.modelCache {
		// Extract provider name from key (format: "provider:modelID")
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}

		providerName := parts[0]
		result[providerName] = append(result[providerName], model)
	}

	return result
}

// updateCache updates the model cache
func (ds *DiscoveryService) updateCache(models map[string][]*ModelInfo) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Clear existing cache
	ds.modelCache = make(map[string]*ModelInfo)

	// Populate cache
	for providerName, providerModels := range models {
		for _, model := range providerModels {
			key := providerName + ":" + model.ID
			ds.modelCache[key] = model
		}
	}

	ds.lastCacheUpdate = time.Now()
	log.Printf("Updated model cache with %d models from %d providers", len(ds.modelCache), len(models))
}

// SetEnabled enables or disables the discovery service
func (ds *DiscoveryService) SetEnabled(enabled bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.enabled = enabled
}

// IsEnabled returns whether the discovery service is enabled
func (ds *DiscoveryService) IsEnabled() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.enabled
}

// GetDiscoveryStats returns statistics about model discovery
func (ds *DiscoveryService) GetDiscoveryStats(ctx context.Context) (map[string]interface{}, error) {
	models, err := ds.GetAllModels(ctx)
	if err != nil {
		return nil, err
	}

	totalModels := 0
	totalProviders := len(models)
	modelsByProvider := make(map[string]int)
	modelsByFamily := make(map[string]int)
	streamingModels := 0
	toolModels := 0

	for providerName, providerModels := range models {
		modelsByProvider[providerName] = len(providerModels)
		totalModels += len(providerModels)

		for _, model := range providerModels {
			family := ds.guessModelFamily(model.ID)
			modelsByFamily[family]++

			if model.SupportsStreaming {
				streamingModels++
			}
			if model.SupportsToolCalling {
				toolModels++
			}
		}
	}

	return map[string]interface{}{
		"total_models":        totalModels,
		"total_providers":     totalProviders,
		"models_by_provider":  modelsByProvider,
		"models_by_family":    modelsByFamily,
		"streaming_models":    streamingModels,
		"tool_supporting_models": toolModels,
		"cache_valid":         ds.isCacheValid(),
		"last_cache_update":   ds.lastCacheUpdate,
		"service_enabled":     ds.enabled,
	}, nil
}