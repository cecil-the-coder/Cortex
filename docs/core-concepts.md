# Core Concepts

Cortex provides intelligent routing capabilities that automatically optimize model selection based on request characteristics, provider health, and performance metrics.

## Intelligent Routing System

Cortex implements a 5-priority routing system that processes requests through successive layers of intelligence:

1. **Priority 1: Access Control** - API key validation, permissions, rate limiting
2. **Priority 2: Health Checks** - Model availability and performance monitoring
3. **Priority 3: Cost-Based Routing** - Budget optimization and cost efficiency
4. **Priority 4: Context-Aware Routing** - Automatic context window detection and model selection
5. **Priority 5: Vision Routing** - Automatic vision content detection and vision-capable model selection

### Context-Aware Routing

Cortex automatically detects token requirements and routes requests to models with appropriate context windows:

**Supported Context Windows:**
- **Anthropic**: Claude models (200,000 tokens)
- **OpenAI**: GPT-4 models (8,000-128,000 tokens)
- **Google**: Gemini models (up to 1,000,000 tokens)
- **Other**: Mistral, Cohere, Perplexity (32,000-127,000 tokens)

**Configuration:**
```json
{
  "ModelGroups": {
    "intelligent-routing": {
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-premium",
          "maxContextTokens": 200000,
          "supportsVision": true
        },
        {
          "provider": "openai",
          "model": "gpt-4o",
          "alias": "gpt4o-standard",
          "maxContextTokens": 128000,
          "supportsVision": true
        }
      ]
    }
  }
}
```

### Vision Routing

Automatic detection and routing of image/video content to vision-capable models:

**Vision-Capable Models:**
- **Anthropic**: Claude 3.5 Sonnet/Opus/Haiku (✅ Vision support)
- **OpenAI**: GPT-4o/GPT-4o Mini (✅ Vision support)
- **Google**: Gemini 1.5 Pro/Flash (✅ Vision + Video support)

**Vision Request Example:**
```json
{
  "model": "intelligent-routing",
  "messages": [
    {
      "role": "user",
      "content": [
        {
          "type": "text",
          "text": "What do you see in this image?"
        },
        {
          "type": "image_url",
          "image_url": {
            "url": "https://example.com/image.jpg"
          }
        }
      ]
    }
  ]
}
```

**Response with Routing Info:**
```json
{
  "model": "gpt-4o-2024-05-13",
  "provider": "openai",
  "reason": "vision content detected, context validated: 1250 tokens"
}
```

## Health Monitoring

Real-time monitoring of AI provider health with automated failover and alerting.

### Features
- **Automatic Health Checks**: Configurable intervals and timeouts
- **Performance Metrics**: Response times, success rates, error tracking
- **Alerting System**: Webhook notifications for status changes
- **Metrics Export**: Prometheus integration for monitoring

### Configuration
```json
{
  "health_monitoring": {
    "enabled": true,
    "check_interval": "30s",
    "timeout": "10s",
    "alert_threshold": 3,
    "alerts": {
      "enabled": true,
      "channels": ["log", "webhook"],
      "webhook_url": "${HEALTH_WEBHOOK_URL}"
    }
  }
}
```

### API Endpoints
```bash
# Get health status
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/health

# Manual health check
curl -X POST -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/health/check
```

## Model Discovery

Automatic detection and organization of models across providers with comprehensive metadata.

### Features
- **Model Registry**: Centralized catalog of all available models
- **Capability Detection**: Automatic identification of model capabilities
- **Performance Metrics**: Historical performance data and trends
- **Smart Filtering**: Filter models by capabilities, costs, and performance

### API Usage
```bash
# Discover all models
curl -X GET "http://localhost:8080/admin/models/discover" \
  -H "x-api-key: YOUR_ROUTER_API_KEY"

# Filter by capabilities
curl -X GET "http://localhost:8080/admin/models/capabilities?capabilities=vision" \
  -H "x-api-key: YOUR_ROUTER_API_KEY"
```

## Performance Optimization

### Routing Performance
- **Overhead**: ~5.5-8.5ms for full 5-priority intelligent routing
- **Memory Usage**: <50MB for 100+ models with full routing data
- **Scaling**: Linear performance scaling with number of models

### Caching Strategies
- **Multi-Tier Caching**: L1 memory + L2 Redis + L3 S3
- **Smart Cache Keys**: Content-aware caching for better hit rates
- **Cache Optimization**: Automatic compression and format optimization

### Monitoring Metrics
- **Response Times**: P50/P95/P99 tracking
- **Cache Hit Rates**: By cache type and provider
- **Cost Optimization**: Per-request cost tracking
- **Quality Scores**: Automated quality assessment

## Best Practices

### Model Group Organization
```json
{
  "ModelGroups": {
    "production-vision": {
      "description": "Vision-capable models for production",
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "maxContextTokens": 200000,
          "supportsVision": true
        },
        {
          "provider": "openai",
          "model": "gpt-4o",
          "maxContextTokens": 128000,
          "supportsVision": true
        }
      ]
    },
    "cost-optimized": {
      "description": "Budget-friendly models for high-volume tasks",
      "models": [
        {
          "provider": "openai",
          "model": "gpt-4o-mini",
          "maxContextTokens": 128000,
          "supportsVision": true
        }
      ]
    }
  }
}
```

### Performance Tuning
- **Group Size**: 3-7 models per group for optimal performance
- **Provider Mix**: Balance speed, cost, and capability
- **Fallback Strategy**: Include models with different capabilities in same group
- **Cost Awareness**: Implement cost-aware routing for budget control

### Monitoring Setup
```json
{
  "monitoring": {
    "prometheus_export": true,
    "jaeger_trace": true,
    "log_level": "info",
    "performance_metrics": {
      "enabled": true,
      "collection_interval": "10s"
    }
  }
}
```

## Getting Started

1. **Configure Models**: Set up providers and model groups with context/vision capabilities
2. **Enable Health Monitoring**: Set up health checks and alerting
3. **Test Routing**: Verify intelligent routing with sample requests
4. **Monitor Performance**: Set up metrics collection and dashboards
5. **Optimize Cost**: Implement cost-aware routing policies

For detailed API documentation and examples, see the [Admin API](./admin-api-usage.md) and [Authentication](./authentication.md) guides.