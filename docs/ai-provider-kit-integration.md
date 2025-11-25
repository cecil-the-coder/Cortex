# AI Provider Kit Integration - Core API Implementation

This document provides comprehensive information about the Core API implementation of the ai-provider-kit integration in Cortex.

## Overview

The ai-provider-kit integration enables Cortex to leverage a standardized API for interacting with multiple AI providers through a unified interface.
The Core API provides standardized access patterns, enhanced error handling, and improved performance.

## Architecture

### Core Components

1. **Provider Registry** (`internal/providers/registry.go`)
   - Manages AI provider instances using ai-provider-kit SDK
   - Handles both legacy and Core API providers
   - Provides automatic fallback when Core API is unavailable

2. **Health Monitoring** (`internal/health/monitor.go`)
   - Continuous health monitoring of AI providers
   - Alerting for consecutive failures
   - Metrics collection and performance tracking

3. **Model Discovery** (`internal/models/discovery.go`)
   - Automatic model capability detection
   - Provider-agnostic model catalog
   - Dynamic filtering based on requirements

4. **Response Conversion** (`internal/converters/response.go`)
   - Converts between standardized and provider-specific formats
   - Multi-format support (Anthropic, OpenAI, Standard, SSE)
   - Streaming and non-streaming response handling

5. **Request Conversion** (`internal/converters/request.go`)
   - Legacy to Standard request transformation
   - Validation and sanitization
   - Tool calling and streaming support

## Core API Features

### Standardized Interface

The Core API provides a uniform interface across all supported providers:

```go
type CoreChatProvider interface {
    GenerateStandardCompletion(ctx context.Context, request StandardRequest) (*StandardResponse, error)
    GenerateStandardStream(ctx context.Context, request StandardRequest) (StandardStream, error)
    GetStandardCapabilities() []string
    ValidateStandardRequest(request StandardRequest) error
}
```

### Standardized Data Structures

```go
// StandardRequest represents the unified request format
type StandardRequest struct {
    Messages       []ChatMessage      `json:"messages"`
    Model          string             `json:"model"`
    MaxTokens      int                `json:"max_tokens"`
    Temperature    float64            `json:"temperature,omitempty"`
    Stop           []string           `json:"stop,omitempty"`
    Stream         bool               `json:"stream,omitempty"`
    Tools          []Tool             `json:"tools,omitempty"`
    ToolChoice     *ToolChoice        `json:"tool_choice,omitempty"`
    Timeout        time.Duration      `json:"timeout,omitempty"`
    Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// StandardResponse represents the unified response format
type StandardResponse struct {
    ID               string                 `json:"id"`
    Object           string                 `json:"object"`
    Created          int64                  `json:"created"`
    Model            string                 `json:"model"`
    Choices          []StandardChoice       `json:"choices"`
    Usage            Usage                  `json:"usage"`
    ProviderMetadata map[string]interface{} `json:"provider_metadata,omitempty"`
}
```

## Configuration

### Basic Configuration

```json
{
  "providers": [
    {
      "name": "openai",
      "api_key": "your-openai-api-key",
      "models": ["gpt-4", "gpt-3.5-turbo"],
      "base_url": "https://api.openai.com/v1"
    },
    {
      "name": "anthropic",
      "api_key": "your-anthropic-api-key",
      "models": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
      "base_url": "https://api.anthropic.com"
    }
  ],
  "health_monitoring": {
    "enabled": true,
    "check_interval": "30s",
    "timeout": "10s",
    "alert_threshold": 3
  },
  "model_discovery": {
    "enabled": true,
    "cache_expiry": "5m",
    "parallel_discovery": true
  }
}
```

### Advanced Configuration with OAuth

```json
{
  "providers": [
    {
      "name": "openai",
      "auth_method": "oauth",
      "oauth": {
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "token_url": "https://api.openai.com/oauth/token",
        "scopes": ["api:read", "api:write"]
      },
      "models": ["gpt-4", "gpt-3.5-turbo"]
    }
  ]
}
```

## Health Monitoring

### Health Monitoring Features

- **Automatic Health Checks**: Periodic health verification of all providers
- **Failure Tracking**: Consecutive failure counting and alerting
- **Metrics Collection**: Response times, error rates, and usage statistics
- **Status Callbacks**: Custom handlers for health status changes

### Health Monitoring API

```go
// Get health status for all providers
healthStatus := registry.GetHealthMonitor().GetHealthStatus()

// Get health status for specific provider
status, err := registry.GetHealthMonitor().GetProviderHealthStatus("openai")

// Get list of healthy providers
healthy := registry.GetHealthMonitor().GetHealthyProviders()

// Get list of unhealthy providers
unhealthy := registry.GetHealthMonitor().GetUnhealthyProviders()

// Trigger manual health check
err := registry.GetHealthMonitor().TriggerManualHealthCheck("anthropic")

// Get provider metrics
metrics, err := registry.GetHealthMonitor().GetProviderMetrics("openai")
```

### Health Status Structure

```go
type ProviderHealthStatus struct {
    HealthStatus
    ProviderName     string               `json:"provider_name"`
    ProviderType     ProviderType        `json:"provider_type"`
    ConsecutiveFails int                 `json:"consecutive_fails"`
    LastSuccess      time.Time           `json:"last_success"`
    Alerts           []HealthAlert       `json:"alerts"`
    Metrics          *ProviderMetrics    `json:"metrics"`
}
```

## Model Discovery

### Discovery Service Features

- **Automatic Detection**: Discover available models from each provider
- **Capability Scanning**: Identify supported features (streaming, tool calling, etc.)
- **Smart Filtering**: Filter models by capabilities, token limits, provider
- **Caching**: Intelligent caching to reduce API calls

### Model Discovery API

```go
// Get all models from all providers
models, err := registry.GetDiscoveryService().GetAllModels(ctx)

// Get models from specific provider
openaiModels, err := registry.GetDiscoveryService().GetModelsByProvider(ctx, "openai")

// Find specific model
model, err := registry.GetDiscoveryService().FindModel(ctx, "gpt-4")

// Find models by name pattern
models, err := registry.GetDiscoveryService().FindModelsByName(ctx, "claude-3")

// Get models with specific capabilities
models, err := registry.GetDiscoveryService().GetModelsByCapability(ctx, "tool_calling", "streaming")

// Get popular curated models
popular, err := registry.GetDiscoveryService().GetPopularModels(ctx)

// Get discovery statistics
stats, err := registry.GetDiscoveryService().GetDiscoveryStats(ctx)
```

### Model Information Structure

```go
type ModelInfo struct {
    Model
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
```

### Model Filtering

```go
// Create filter to find models with specific capabilities
filter := ModelFilter{
    Features:      []string{"streaming", "tool_calling"},
    MinTokens:     8000,
    MaxTokens:     128000,
    SupportsStreaming: &[]bool{true}[0],
    SupportsTools:    &[]bool{true}[0],
    Tags:          []string{"chat", "api"},
    Provider:      "openai",
}

// Apply filter to discovered models
filtered := registry.GetDiscoveryService().FilterModels(models, filter)
```

## Request Conversion

### Legacy to Standard Conversion

The request converter seamlessly transforms legacy requests to the new standard format:

```go
// Convert legacy MessageRequest to StandardRequest
standardReq, err := registry.GetRequestConverter().ConvertFromLegacy(legacyReq)

// Convert legacy GenerateOptions to StandardRequest
standardReq, err := registry.GetRequestConverter().ConvertFromGenerateOptions(options)

// Validate converted request
err := registry.GetRequestConverter().ValidateRequest(standardReq)

// Sanitize request (clamps invalid values)
sanitized := registry.GetRequestConverter().SanitizeRequest(standardReq)
```

### Validation Rules

The converter includes comprehensive validation rules:

- Required messages validation
- Temperature range validation (0-2)
- Max tokens positivity check
- Tool choice consistency verification
- Message role sequence validation (in strict mode)
- Content length validation (in strict mode)

## Response Conversion

### Format Support

The response converter supports multiple output formats:

```go
// Convert to legacy Anthropic format
anthropicResp, err := registry.GetResponseConverter().ConvertFromStandard(
    standardResp,
    converters.FormatLegacy,
)

// Convert to OpenAI-compatible format
openaiResp, err := registry.GetResponseConverter().ConvertFromStandard(
    standardResp,
    converters.FormatOpenAI,
)

// Convert to SSE streaming format
sseData, err := registry.GetResponseConverter().ConvertStreamChunk(
    streamChunk,
    converters.FormatStream,
)

// Legacy to standard conversion
standardResp, err := registry.GetResponseConverter().ConvertLegacyResponseToStandard(
    anthropicResp,
)
```

### Streaming Support

```go
// Create streaming adapter
adapter := registry.GetResponseConverter().CreateStreamAdapter(
    standardStream,
    converters.FormatStream,
)

// Read converted stream
data := make([]byte, 1024)
n, err := adapter.Read(data)
```

## Provider-Specific Features

### OpenAI Extensions

```go
// Check if provider supports Core API
if provider.UseCoreAPI() {
    // Use standard Core API
    stream, err := provider.GenerateStandardStream(ctx, standardRequest)
} else {
    // Fallback to legacy API
    stream, err := provider.GenerateChatCompletion(ctx, generateOptions)
}

// Get provider capabilities
capabilities := provider.GetStandardCapabilities()

// Get provider extension for advanced features
extension, err := provider.GetCoreProviderExtension()
```

### Anthropic Features

The integration supports Anthropic-specific features:

- **Thinking Mode**: Automatic detection and handling
- **Tool Calling**: Standardized across providers
- **Streaming**: Unified streaming interface
- **Context Windows**: Dynamic context window detection

## Performance and Optimization

### Caching Strategies

1. **Model Discovery Cache**: 5-minute cache expiration for model information
2. **Response Conversion**: In-memory transformation without serialization
3. **Health Check Results**: Cached health status between checks

### Parallel Processing

- **Model Discovery**: Parallel model fetching from multiple providers
- **Health Checks**: Concurrent health monitoring of all providers
- **Batch Conversion**: Efficient batch response transformation

### Memory Management

- **Streaming**: Low-memory streaming responses
- **Buffered I/O**: Efficient response buffering
- **Object Pooling**: Reuse of conversion objects

## Error Handling

### Graceful Degradation

The system provides multiple layers of fallback:

1. **Core API → Legacy API**: Automatic fallback when Core API fails
2. **Multiple Providers**: Load balancing across healthy providers
3. **Response Conversion**: Fallback responses on conversion errors
4. **Circuit Breaker**: Temporary provider disable on consecutive failures

### Error Types

```go
// Provider errors
type ProviderError struct {
    Provider string
    Type     string
    Message  string
    Retryable bool
}

// Conversion errors
type ConversionError struct {
    Field      string
    Message    string
    Value      interface{}
    Suggestion string
}
```

## Monitoring and Observability

### Metrics

The system collects comprehensive metrics:

- Request/response counts per provider
- Error rates and failure patterns
- Response time distributions
- Token usage statistics
- Health check success/failure rates

### Logging

Structured logging with correlation IDs:

```go
// Enable debug mode
converter.SetDebug(true)
registry.GetRequestConverter().SetDebug(true)

// Debug individual requests/conversations
converter.DebugResponse(response)
converter.DebugRequest(request)
```

## Migration Guide

### From legacy to Core API

1. **Update Configuration**: Add health monitoring and model discovery settings
2. **Update Client Code**: Use new standardized interfaces where possible
3. **Test Compatibility**: Verify existing integrations still work
4. **Monitor Performance**: Use health monitoring to track improvements

### Backward Compatibility

The Core API implementation maintains full backward compatibility:

- Existing API endpoints remain unchanged
- Legacy request/response formats supported
- Configuration file format backward compatible
- Gradual migration path available

## Best Practices

### Configuration Best Practices

1. **Enable Health Monitoring**: Always enable for production deployments
2. **Use OAuth**: Prefer OAuth over API keys for better security
3. **Configure Timeouts**: Set appropriate timeouts for your use case
4. **Set Alert Thresholds**: Configure alert thresholds based on your SLA

### Performance

1. **Enable Caching**: Use model discovery caching to reduce API calls
2. **Parallel Operations**: Use parallel where possible (discovery, health checks)
3. **Batch Operations**: Batch convert responses when processing multiple items
4. **Streaming**: Use streaming for long responses to reduce memory usage

### Security

1. **OAuth Integration**: Use OAuth for token management and rotation
2. **API Key Rotation**: Regularly rotate API keys
3. **HTTPS Only**: Always use HTTPS for provider communications
4. **Input Validation**: Validate all inputs before processing

## Troubleshooting

### Common Issues

1. **Core API Unavailable**: System automatically falls back to legacy API
2. **Health Check Failures**: Check network connectivity and API keys
3. **Model Discovery Errors**: Verify provider credentials and permissions
4. **Performance Issues**: Enable caching and check for bottlenecks

### Debug Information

Enable debug mode for detailed troubleshooting:

```go
// Enable debug logging
converter.SetDebug(true)

// Get service health status
health := registry.GetServiceHealth()

// Get provider metrics
metrics := registry.GetHealthMonitor().GetAllMetrics()

// Get discovery statistics
stats, _ := registry.GetDiscoveryService().GetDiscoveryStats(context.Background())
```

## API Reference

### Provider Registry

```go
type SDKProviderRegistry interface {
    GetProvider(name string) (*SDKProvider, error)
    GetAllModels() map[string][]string
    ReloadProviders(cfg *config.Config) error
    GetHealthMonitor() *health.HealthMonitor
    GetDiscoveryService() *models.DiscoveryService
    GetRequestConverter() *converters.RequestConverter
    GetResponseConverter() *converters.ResponseConverter
    ConvertMessageRequest(*converters.MessageRequest) (*types.StandardRequest, error)
    ConvertResponse(*types.StandardResponse, converters.ResponseFormat) (interface{}, error)
    GetServiceHealth() map[string]interface{}
    Shutdown() error
}
```

### Health Monitor

```go
type HealthMonitor interface {
    AddProvider(name string, provider types.HealthCheckProvider, config *config.Provider) error
    RemoveProvider(name string) error
    GetHealthStatus() map[string]*ProviderHealthStatus
    GetProviderHealthStatus(name string) (*ProviderHealthStatus, error)
    GetHealthyProviders() []string
    GetUnhealthyProviders() []string
    TriggerManualHealthCheck(name string) error
    GetProviderMetrics(name string) (*types.ProviderMetrics, error)
    GetAllMetrics() map[string]*types.ProviderMetrics
    AddStatusChangeCallback(callback StatusChangeCallback)
    Start()
    Stop()
    IsEnabled() bool
}
```

### Discovery Service

```go
type DiscoveryService interface {
    AddProvider(name string, provider types.ModelProvider, config *config.Provider) error
    RemoveProvider(name string) error
    DiscoverModels(ctx context.Context, opts ModelDiscoveryOptions) (map[string][]*ModelInfo, error)
    GetAllModels(ctx context.Context) (map[string][]*ModelInfo, error)
    GetModelsByProvider(ctx context.Context, providerName string) ([]*ModelInfo, error)
    FindModel(ctx context.Context, modelID string) (*ModelInfo, error)
    FindModelsByName(ctx context.Context, namePattern string) ([]*ModelInfo, error)
    GetModelsByCapability(ctx context.Context, capabilities ...string) ([]*ModelInfo, error)
    GetPopularModels(ctx context.Context) ([]*ModelInfo, error)
    UpdateCache(ctx context.Context) error
    FilterModels(models map[string][]*ModelInfo, filter ModelFilter) map[string][]*ModelInfo
    SetEnabled(enabled bool)
    IsEnabled() bool
    GetDiscoveryStats(ctx context.Context) (map[string]interface{}, error)
}
```

## Conclusion

The AI Provider Kit Core API integration provides a robust, scalable, and maintainable foundation for AI provider interactions.
It offers significant improvements in performance, reliability, and maintainability while maintaining full backward compatibility.

For questions, issues, or contributions, please refer to the project documentation and issue tracker.