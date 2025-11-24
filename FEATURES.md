# Cortex Features

## Context-Aware Routing

The Cortex includes intelligent context-aware routing that automatically selects the best model based on token count and context window capabilities.

### Key Features

- **Automatic Context Window Detection**: Built-in knowledge of context limits for popular models
- **Smart Model Selection**: Routes to models that can handle the request context size
- **Fallback Support**: Graceful handling when no model in a group can accommodate the context
- **Configuration Overrides**: Ability to override context windows per model
- **Backward Compatibility**: Existing configurations work without changes

### Supported Models

The router comes with predefined context windows for:

#### Anthropic Models
- Claude 3.5 Sonnet: 200,000 tokens
- Claude 3.5 Haiku: 200,000 tokens
- Claude 3 Opus: 200,000 tokens
- Claude 3 Sonnet: 200,000 tokens
- Claude 3 Haiku: 200,000 tokens

#### OpenAI Models
- GPT-4 Turbo: 128,000 tokens
- GPT-4: 8,192 tokens
- GPT-4 32K: 32,768 tokens
- GPT-3.5 Turbo: 16,385 tokens
- GPT-4o: 128,000 tokens

#### Other Models
- Google Gemini 1.5 Pro: 1,000,000 tokens
- Mistral Large: 32,768 tokens
- Mixtral 8x7B: 32,768 tokens
- Cohere Command R+: 128,000 tokens
- Perplexity Sonar Pro: 127,000 tokens

### Usage Example

```json
{
  "ModelGroups": {
    "production": {
      "description": "Production models with context-aware routing",
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-prod",
          "maxContextTokens": 200000
        },
        {
          "provider": "openai",
          "model": "gpt-4",
          "alias": "gpt4-fallback",
          "maxContextTokens": 8192
        }
      ]
    }
  }
}
```

## Model Groups and Access Control

### Model Groups
- Organize models by capability, cost, or use case
- Support for model aliases for client-friendly naming
- Hierarchical access control through groups

### Client API Keys
- Fine-grained access control per client
- Model group restrictions
- Rate limiting and expiration support
- Multiple authentication methods (API Key, OAuth, Hybrid)

## Advanced Routing

### Smart Routing Logic
1. **Explicit Overrides**: `provider,model` format in requests
2. **Long Context Detection**: Automatic routing for large contexts
3. **Subagent Support**: Dynamic routing from system prompts
4. **Tool-Based Routing**: Special handling for web search, thinking mode
5. **Background Processing**: Optimize for low-latency background tasks

### Provider Features
- **Multiple Authentication Methods**: API Key, OAuth 2.0, Hybrid
- **Health Monitoring**: Provider health checks and failover
- **Load Balancing**: Distribute load across multiple providers
- **Cost Tracking**: Monitor usage and costs per provider

## Configuration

### Environment Variables
- Support for environment variable interpolation
- Secure credential management
- Flexible deployment configurations

### Validation
- Comprehensive configuration validation
- Migration support from legacy formats
- Backward compatibility guarantees

## Monitoring and Observability

### Logging
- Structured logging with configurable levels
- Request tracing and correlation IDs
- Performance metrics

### Admin API
- Real-time configuration updates
- Health checks and monitoring
- Usage statistics and analytics

## Security Features

### Authentication
- Multiple authentication mechanisms
- Token validation and refresh
- Secure credential storage

### Access Control
- Model-based access control
- Rate limiting per API key
- IP-based restrictions (configurable)

## Performance

### Optimization
- Connection pooling and reuse
- Request/response streaming
- Minimal routing overhead (<1ms)

### Scalability
- Horizontal scaling support
- Stateless design
- Load balancer friendly

## Developer Experience

### Testing
- Comprehensive test coverage
- Integration test examples
- Performance benchmarks

### Documentation
- Detailed API documentation
- Configuration examples
- Migration guides

## Extensibility

### Custom Providers
- Easy provider implementation
- Plugin architecture support
- Custom authentication methods

### Middleware
- Request/response middleware
- Custom routing logic
- Integration hooks

For detailed documentation, see:
- [Context-Aware Routing Guide](docs/context-aware-routing.md)
- [Configuration Examples](examples/)
- [API Documentation](docs/api.md)