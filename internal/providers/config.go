package providers

import (
	"strings"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
)

// CoreAPIConfig contains configuration for the new Phase 3 Core API
type CoreAPIConfig struct {
	// Enable Core API for this provider
	UseCoreAPI bool `json:"useCoreAPI,omitempty" yaml:"useCoreAPI"`

	// Provider-specific features to enable with Core API
	CoreAPIFeatures []string `json:"coreAPIFeatures,omitempty" yaml:"coreAPIFeatures"`

	// Request validation settings
	Validation ValidationConfig `json:"validation,omitempty" yaml:"validation"`

	// Performance and reliability settings
	Performance PerformanceConfig `json:"performance,omitempty" yaml:"performance"`

	// Monitoring and health settings
	Monitoring MonitoringConfig `json:"monitoring,omitempty" yaml:"monitoring"`

	// Model discovery preferences
	ModelDiscovery ModelDiscoveryConfig `json:"modelDiscovery,omitempty" yaml:"modelDiscovery"`

	// Provider-specific extensions configuration
	Extensions map[string]interface{} `json:"extensions,omitempty" yaml:"extensions"`
}

// ValidationConfig controls request validation behavior
type ValidationConfig struct {
	// Enable strict validation for requests
	StrictValidation bool `json:"strictValidation" yaml:"strictValidation"`

	// Custom validation rules
	CustomRules map[string]interface{} `json:"customRules,omitempty" yaml:"customRules"`

	// Skip validation for specific fields
	SkipFields []string `json:"skipFields,omitempty" yaml:"skipFields"`
}

// PerformanceConfig controls performance settings
type PerformanceConfig struct {
	// Default timeout for requests
	DefaultTimeout time.Duration `json:"defaultTimeout,omitempty" yaml:"defaultTimeout"`

	// Maximum request size
	MaxRequestSize int64 `json:"maxRequestSize,omitempty" yaml:"maxRequestSize"`

	// Connection pooling settings
	MaxConcurrentRequests int `json:"maxConcurrentRequests,omitempty" yaml:"maxConcurrentRequests"`

	// Request retry settings
	MaxRetries int `json:"maxRetries,omitempty" yaml:"maxRetries"`
}

// MonitoringConfig controls health and monitoring settings
type MonitoringConfig struct {
	// Enable health checks
	EnableHealthChecks bool `json:"enableHealthChecks" yaml:"enableHealthChecks"`

	// Health check interval
	HealthCheckInterval time.Duration `json:"healthCheckInterval,omitempty" yaml:"healthCheckInterval"`

	// Enable metrics collection
	EnableMetrics bool `json:"enableMetrics" yaml:"enableMetrics"`

	// Custom metrics to track
	CustomMetrics []string `json:"customMetrics,omitempty" yaml:"customMetrics"`
}

// ModelDiscoveryConfig controls model discovery settings
type ModelDiscoveryConfig struct {
	// Enable automatic model discovery
	EnableAutoDiscovery bool `json:"enableAutoDiscovery" yaml:"enableAutoDiscovery"`

	// Refresh interval for model discovery
	RefreshInterval time.Duration `json:"refreshInterval,omitempty" yaml:"refreshInterval"`

	// Cache discovered models locally
	CacheModels bool `json:"cacheModels" yaml:"cacheModels"`

	// Preferred model selection criteria
	PreferredCriteria []string `json:"preferredCriteria,omitempty" yaml:"preferredCriteria"`
}

// DefaultCoreAPIConfig returns the default configuration for Core API
func DefaultCoreAPIConfig() CoreAPIConfig {
	return CoreAPIConfig{
		UseCoreAPI: true,
		CoreAPIFeatures: []string{
			"standardized_requests",
			"provider_extensions",
			"validation",
		},
		Validation: ValidationConfig{
			StrictValidation: true,
			SkipFields:      []string{},
		},
		Performance: PerformanceConfig{
			DefaultTimeout:       30 * time.Second,
			MaxConcurrentRequests: 100,
			MaxRetries:           3,
		},
		Monitoring: MonitoringConfig{
			EnableHealthChecks:  true,
			HealthCheckInterval: 60 * time.Second,
			EnableMetrics:       true,
		},
		ModelDiscovery: ModelDiscoveryConfig{
			EnableAutoDiscovery: false,
			CacheModels:        true,
		},
		Extensions: make(map[string]interface{}),
	}
}

// ProviderSpecificCoreAPIConfig returns provider-specific default configurations
func ProviderSpecificCoreAPIConfig(providerType string) CoreAPIConfig {
	config := DefaultCoreAPIConfig()

	switch strings.ToLower(providerType) {
	case "anthropic":
		config.CoreAPIFeatures = append(config.CoreAPIFeatures,
			"thinking_mode",
			"top_k_sampling",
			"system_prompts",
			"prompt_caching",
		)
		config.Extensions = map[string]interface{}{
			"enable_thinking":     true,
			"max_thinking_tokens": 20000,
			"cache_control":       true,
		}

	case "openai":
		config.CoreAPIFeatures = append(config.CoreAPIFeatures,
			"json_mode",
			"parallel_tools",
			"reproducible_results",
			"top_p_sampling",
		)
		config.Extensions = map[string]interface{}{
			"enable_json_mode":        false,
			"enable_parallel_tools":   true,
			"seed_for_reproducible":   nil,
			"max_parallel_tool_calls": 5,
		}

	case "gemini", "google":
		config.CoreAPIFeatures = append(config.CoreAPIFeatures,
			"code_execution",
			"grounding",
			"safety_settings",
		)
		config.Extensions = map[string]interface{}{
			"enable_code_execution": false,
			"grounding_enabled":     false,
			"safety_threshold":      "BLOCK_MEDIUM_AND_ABOVE",
		}

	case "deepseek":
		config.CoreAPIFeatures = append(config.CoreAPIFeatures,
			"deepseek_reasoning",
			"cost_optimized",
		)
		config.Extensions = map[string]interface{}{
			"reasoning_mode": "enhanced",
			"cost_optimization": true,
		}

	default:
		// Add generic features for unknown providers
		config.CoreAPIFeatures = append(config.CoreAPIFeatures,
			"compatibility_mode",
		)
	}

	return config
}

// MergeCoreAPIConfig merges a custom Core API config with defaults
func MergeCoreAPIConfig(custom, defaults CoreAPIConfig) CoreAPIConfig {
	merged := defaults

	// Override if custom value is set
	if custom.UseCoreAPI {
		merged.UseCoreAPI = true
	}

	if len(custom.CoreAPIFeatures) > 0 {
		merged.CoreAPIFeatures = custom.CoreAPIFeatures
	}

	// Merge validation settings
	if custom.Validation.StrictValidation != merged.Validation.StrictValidation {
		merged.Validation.StrictValidation = custom.Validation.StrictValidation
	}
	if len(custom.Validation.CustomRules) > 0 {
		merged.Validation.CustomRules = custom.Validation.CustomRules
	}
	if len(custom.Validation.SkipFields) > 0 {
		merged.Validation.SkipFields = custom.Validation.SkipFields
	}

	// Merge performance settings
	if custom.Performance.DefaultTimeout > 0 {
		merged.Performance.DefaultTimeout = custom.Performance.DefaultTimeout
	}
	if custom.Performance.MaxRequestSize > 0 {
		merged.Performance.MaxRequestSize = custom.Performance.MaxRequestSize
	}
	if custom.Performance.MaxConcurrentRequests > 0 {
		merged.Performance.MaxConcurrentRequests = custom.Performance.MaxConcurrentRequests
	}
	if custom.Performance.MaxRetries >= 0 {
		merged.Performance.MaxRetries = custom.Performance.MaxRetries
	}

	// Merge monitoring settings
	if custom.Monitoring.EnableHealthChecks {
		merged.Monitoring.EnableHealthChecks = true
	}
	if custom.Monitoring.HealthCheckInterval > 0 {
		merged.Monitoring.HealthCheckInterval = custom.Monitoring.HealthCheckInterval
	}
	if custom.Monitoring.EnableMetrics {
		merged.Monitoring.EnableMetrics = true
	}
	if len(custom.Monitoring.CustomMetrics) > 0 {
		merged.Monitoring.CustomMetrics = custom.Monitoring.CustomMetrics
	}

	// Merge model discovery settings
	if custom.ModelDiscovery.EnableAutoDiscovery {
		merged.ModelDiscovery.EnableAutoDiscovery = true
	}
	if custom.ModelDiscovery.RefreshInterval > 0 {
		merged.ModelDiscovery.RefreshInterval = custom.ModelDiscovery.RefreshInterval
	}
	if len(custom.ModelDiscovery.PreferredCriteria) > 0 {
		merged.ModelDiscovery.PreferredCriteria = custom.ModelDiscovery.PreferredCriteria
	}

	// Merge extensions
	if len(custom.Extensions) > 0 {
		if merged.Extensions == nil {
			merged.Extensions = make(map[string]interface{})
		}
		for k, v := range custom.Extensions {
			merged.Extensions[k] = v
		}
	}

	return merged
}

// ExtendProviderConfig extends the standard provider config with Core API settings
func ExtendProviderConfig(providerConfig *config.Provider) *ExtendedProviderConfig {
	return &ExtendedProviderConfig{
		Provider:    *providerConfig,
		CoreAPI:     ProviderSpecificCoreAPIConfig(providerConfig.Name),
		ExtendedAt:  time.Now(),
		Version:     "1.0.0",
	}
}

// ExtendedProviderConfig combines standard provider config with Core API features
type ExtendedProviderConfig struct {
	// Original provider configuration
	config.Provider `json:",inline" yaml:",inline"`

	// Core API specific configuration
	CoreAPI CoreAPIConfig `json:"coreAPI,omitempty" yaml:"coreAPI"`

	// Metadata about the extended configuration
	ExtendedAt time.Time `json:"extendedAt" yaml:"extendedAt"`
	Version    string    `json:"version" yaml:"version"`
}

// HasCoreAPIFeature checks if the provider has a specific Core API feature enabled
func (c *ExtendedProviderConfig) HasCoreAPIFeature(feature string) bool {
	for _, f := range c.CoreAPI.CoreAPIFeatures {
		if strings.EqualFold(f, feature) {
			return true
		}
	}
	return false
}

// GetCoreAPIExtension returns a specific extension value
func (c *ExtendedProviderConfig) GetCoreAPIExtension(key string) (interface{}, bool) {
	val, exists := c.CoreAPI.Extensions[key]
	return val, exists
}

// SetCoreAPIExtension sets a specific extension value
func (c *ExtendedProviderConfig) SetCoreAPIExtension(key string, value interface{}) {
	if c.CoreAPI.Extensions == nil {
		c.CoreAPI.Extensions = make(map[string]interface{})
	}
	c.CoreAPI.Extensions[key] = value
}