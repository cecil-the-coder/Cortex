# Core API Migration Guide

## Overview

This guide provides comprehensive information for migrating existing Cortex installations to the Core API implementation (AI Provider Kit integration). The Core API introduces standardized interfaces, health monitoring, model discovery, and enhanced capabilities while maintaining full backward compatibility.

## Migration Benefits

### What You Gain with the Core API

- 🆕 **Standardized Core API**: Uniform interface across all AI providers
- 🆕 **Automatic Health Monitoring**: Real-time provider health tracking and alerting
- 🆕 **Dynamic Model Discovery**: Automatic model capability detection
- 🆕 **Enhanced Performance**: Better throughput and lower latency
- 🆕 **Provider Extensions**: Access to provider-specific features
- 🆕 **Comprehensive Testing**: Full test coverage with performance benchmarks
- 🆕 **Better Observability**: Metrics, logging, and monitoring
- ✅ **Full Backward Compatibility**: No breaking changes to existing APIs

## Migration Strategy

### Supported Migration Paths

1. **Gradual Migration** (Recommended): Enable Core API features incrementally
2. **Full Migration**: Enable all Core API features at once
3. **Parallel Migration**: Run Core API alongside existing setup

### Migration Levels

| Level | Description | Effort | Risk |
|-------|-------------|--------|------|
| **Level 1** | Core API integration only | Low | Very Low |
| **Level 2** | + Health monitoring | Medium | Low |
| **Level 3** | + Model discovery | Medium | Medium |
| **Level 4** | Full Core API features | High | Low |

## Pre-Migration Checklist

### Requirements

- [ ] Go 1.21 or later
- [ ] Existing Cortex v2.x installation
- [ ] Valid API keys for all providers
- [ ] Configuration backup
- [ ] Test environment available
- [ ] Monitoring setup (optional but recommended)

### Environment Assessment

```bash
# Check current version
./Cortex --version

# Verify configuration
./Cortex --config config.json --validate

# Test current functionality
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/status
```

### Backup Current Setup

```bash
# Backup configuration
cp config.json config.json.backup.$(date +%Y%m%d)

# Backup logs
cp -R logs/ logs.backup.$(date +%Y%m%d)/

# Document current setup
./Cortex --config config.json --export-setup > current-setup.json
```

## Step-by-Step Migration

### Step 1: Update Cortex

```bash
# Stop current router (if running)
pkill Cortex

# Backup binary
cp Cortex Cortex.backup

# Download/Build Core API version
git checkout core-api
go build -o Cortex ./cmd/router

# Verify version
./Cortex --version
```

### Step 2: Update Configuration

#### Option A: Minimal Configuration (Level 1)

```json
{
  "experimental": {
    "enable_core_api": true,
    "enable_provider_extensions": true
  },
  "providers": [
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1",
      "models": ["gpt-4", "gpt-3.5-turbo"]
    }
  ],
  "router": {
    "default": "openai"
  }
}
```

#### Option B: Medium Configuration (Level 2-3)

```json
{
  "experimental": {
    "enable_core_api": true,
    "enable_provider_extensions": true,
    "enable_dynamic_providers": false
  },
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
  },
  "providers": [
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1",
      "models": ["gpt-4", "gpt-3.5-turbo"]
    }
  ]
}
```

#### Option C: Full Core API Configuration

Use the complete example from `examples/core-api-config.json`.

### Step 3: Test Core API Integration

```go
// test-phase3.go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/cecil-the-coder/ai-provider-kit/pkg/types"
    "Cortex/internal/config"
    "Cortex/internal/providers"
)

func main() {
    // Load configuration
    cfg, err := config.Load("config.json")
    if err != nil {
        log.Fatal(err)
    }

    // Create provider registry
    registry, err := providers.NewSDKProviderRegistry(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer registry.Shutdown()

    // Test Core API
    provider, err := registry.GetProvider("openai")
    if err != nil {
        log.Fatal(err)
    }

    if provider.UseCoreAPI() {
        fmt.Println("✅ Core API is enabled")

        // Test standard request
        request, err := types.NewCoreRequestBuilder().
            WithModel("gpt-3.5-turbo").
            WithMessage(types.ChatMessage{Role: "user", Content: "Hello"}).
            WithMaxTokens(10).
            Build()
        if err != nil {
            log.Fatal(err)
        }

        response, err := provider.GenerateStandardCompletion(context.Background(), *request)
        if err != nil {
            log.Printf("❌ Core API test failed: %v", err)
        } else {
            fmt.Printf("✅ Core API test success: %s\n",
                response.Choices[0].Message.Content[:min(20, len(response.Choices[0].Message.Content))])
        }
    } else {
        fmt.Println("⚠️  Core API not available, falling back to legacy")
    }
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

### Step 4: Enable Health Monitoring

```go
// test-health-monitoring.go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "Cortex/internal/config"
    "Cortex/internal/providers"
)

func main() {
    cfg, err := config.Load("config.json")
    if err != nil {
        log.Fatal(err)
    }

    registry, err := providers.NewSDKProviderRegistry(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer registry.Shutdown()

    // Test health monitoring
    health := registry.GetHealthMonitor()
    if health.IsEnabled() {
        fmt.Println("✅ Health monitoring is enabled")

        // Wait for initial health checks
        time.Sleep(5 * time.Second)

        // Get health status
        status := health.GetHealthStatus()
        for provider, healthStatus := range status {
            if healthStatus.Healthy {
                fmt.Printf("✅ %s: Healthy (Response time: %v)\n",
                    provider, healthStatus.ResponseTime)
            } else {
                fmt.Printf("❌ %s: Unhealthy - %s\n",
                    provider, healthStatus.Error)
            }
        }

        // Get healthy providers
        healthy := health.GetHealthyProviders()
        fmt.Printf("✅ Healthy providers: %v\n", healthy)
    } else {
        fmt.Println("⚠️  Health monitoring not enabled")
    }
}
```

### Step 5: Test Model Discovery

```go
// test-model-discovery.go
package main

import (
    "context"
    "fmt"
    "log"

    "Cortex/internal/config"
    "Cortex/internal/providers"
)

func main() {
    cfg, err := config.Load("config.json")
    if err != nil {
        log.Fatal(err)
    }

    registry, err := providers.NewSDKProviderRegistry(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer registry.Shutdown()

    // Test model discovery
    discovery := registry.GetDiscoveryService()
    if discovery.IsEnabled() {
        fmt.Println("✅ Model discovery is enabled")

        models, err := discovery.GetAllModels(context.Background())
        if err != nil {
            log.Printf("❌ Model discovery failed: %v", err)
        } else {
            fmt.Printf("✅ Discovered models from %d providers:\n", len(models))
            for provider, providerModels := range models {
                fmt.Printf("  %s: %d models\n", provider, len(providerModels))
            }
        }

        // Test capability-based model finding
        streamingModels, err := discovery.GetModelsByCapability(context.Background(), "streaming")
        if err == nil {
            fmt.Printf("✅ Found %d models with streaming capability\n", len(streamingModels))
        }
    } else {
        fmt.Println("⚠️  Model discovery not enabled")
    }
}
```

### Step 6: Validate Migration

```bash
# Run comprehensive tests
go run test-phase3.go
go run test-health-monitoring.go
go run test-model-discovery.go

# Start router with new configuration
./Cortex --config config.json --log-level debug

# Test existing API endpoints
curl -H "x-api-key: $ROUTER_API_KEY" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}],"max_tokens":10}' \
  http://localhost:8080/v1/chat/completions

# Test new admin endpoints
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/health

curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/models
```

## Configuration Migration

### Legacy to Core API Configuration Mapping

| Legacy Field | Core API Field | Notes |
|--------------|---------------|-------|
| `Providers` | `providers` | Same structure, enhanced options |
| `Router` | `routing` | Enhanced with load balancing |
| `ApiKey` | `security.api_key_header` | Enhanced security options |
| None | `health_monitoring` | New health monitoring section |
| None | `model_discovery` | New model discovery section |
| None | `experimental` | New experimental features |

### Automatic Configuration Migration

```bash
# Use built-in migration tool
./Cortex --migrate-config --input config.json --output config-core-api.json

# Review migration report
./Cortex --migrate-config --input config.json --output config-core-api.json --report
```

#### Migration Tool Output Example

```json
{
  "migration_summary": {
    "migrated_fields": 5,
    "added_fields": 3,
    "warnings": 1,
    "errors": 0
  },
  "changes": [
    {
      "field": "experimental.enable_core_api",
      "action": "added",
      "value": true,
      "reason": "Required for Core API features"
    },
    {
      "field": "health_monitoring.enabled",
      "action": "added",
      "value": true,
      "reason": "Enables provider health monitoring"
    },
    {
      "field": "model_discovery.enabled",
      "action": "added",
      "value": true,
      "reason": "Enables automatic model discovery"
    }
  ],
  "warnings": [
    "Some provider configurations may need manual adjustment for optimal performance"
  ]
}
```

## Best Practices

### Performance Optimization

#### 1. Enable Caching

```json
{
  "model_discovery": {
    "cache_enabled": true,
    "cache_expiry": "5m",
    "cache_size_limit": 1000
  },
  "health_monitoring": {
    "metrics_cache_duration": "30s"
  }
}
```

#### 2. Configure Parallel Operations

```json
{
  "model_discovery": {
    "parallel_discovery": true,
    "max_concurrent_discoveries": 5
  },
  "health_monitoring": {
    "parallel_checks": true
  }
}
```

#### 3. Optimize Request/Response Conversion

```json
{
  "request_conversion": {
    "enable_caching": true,
    "sanitize_requests": true,
    "strict_mode": false
  },
  "response_conversion": {
    "batch_conversion": {
      "enabled": true,
      "max_batch_size": 50
    }
  }
}
```

### Security Best Practices

#### 1. Use Environment Variables

```json
{
  "providers": [
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1"
    }
  ]
}
```

#### 2. Enable Request Validation

```json
{
  "security": {
    "enable_request_validation": true,
    "enable_response_validation": true,
    "max_request_size": "10MB",
    "rate_limit_headers": true
  }
}
```

#### 3. Configure Role-Based Access

```json
{
  "admin": {
    "enabled": true,
    "username": "admin",
    "password_hash": "${ADMIN_PASSWORD_HASH}",
    "cors": {
      "enabled": true,
      "origins": ["https://yourdomain.com"]
    }
  }
}
```

### Monitoring and Observability

#### 1. Enable Metrics Collection

```json
{
  "metrics": {
    "enabled": true,
    "endpoint": "/metrics",
    "prometheus": true,
    "collection_interval": "10s"
  }
}
```

#### 2. Configure Structured Logging

```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "structured": true,
    "include_request_id": true,
    "include_provider": true,
    "include_timing": true
  }
}
```

#### 3. Set Up Health Check Endpoints

```json
{
  "server": {
    "port": 8080,
    "health_check_endpoint": "/health",
    "readiness_check_endpoint": "/ready"
  }
}
```

### Production Deployment

#### 1. Resource Limits

```json
{
  "providers": [
    {
      "name": "openai",
      "rate_limit": {
        "requests_per_minute": 3000,
        "tokens_per_minute": 1000000
      }
    }
  ]
}
```

#### 2. Error Handling and Retry

```json
{
  "routing": {
    "failover": {
      "enabled": true,
      "timeout": "10s",
      "retry_attempts": 3,
      "exponential_backoff": true
    }
  }
}
```

#### 3. Graceful Shutdown

```bash
# Configure signal handling
./Cortex \
  --config config.json \
  --graceful-shutdown-timeout 30s \
  --shutdown-wait-completion true
```

## Troubleshooting

### Common Migration Issues

#### 1. Core API Not Available

**Symptoms**:
- Error messages about Core API not being available
- Fallback to legacy API

**Solutions**:
```json
{
  "experimental": {
    "enable_core_api": true,
    "enable_provider_extensions": true
  }
}
```

```bash
# Verify provider compatibility
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/providers/openai
```

#### 2. Health Monitoring Failures

**Symptoms**:
- All providers marked as unhealthy
- Health check timeout errors

**Solutions**:
```json
{
  "health_monitoring": {
    "timeout": "30s",
    "check_interval": "60s",
    "max_consecutive_failures": 5
  }
}
```

#### 3. Model Discovery Not Working

**Symptoms**:
- Empty model lists
- Discovery timeout errors

**Solutions**:
```json
{
  "model_discovery": {
    "discovery_timeout": "60s",
    "parallel_discovery": true,
    "retry_failed_discoveries": true
  }
}
```

### Performance Issues

#### 1. High Memory Usage

**Causes**:
- Large model cache
- Excessive logging
- Memory leaks

**Solutions**:
```json
{
  "model_discovery": {
    "cache_size_limit": 500,
    "cache_compression": true
  },
  "logging": {
    "level": "warn",
    "structured": false
  }
}
```

#### 2. Slow Response Times

**Causes**:
- Synchronous operations
- Network latency
- Resource contention

**Solutions**:
```json
{
  "health_monitoring": {
    "parallel_checks": true
  },
  "model_discovery": {
    "parallel_discovery": true,
    "cache_enabled": true
  }
}
```

### Debug Mode

Enable comprehensive debug logging:

```json
{
  "logging": {
    "level": "debug",
    "include_details": true
  },
  "experimental": {
    "debug_mode": true,
    "trace_requests": true
  }
}
```

## Rollback Procedure

### Emergency Rollback

If critical issues occur during migration:

```bash
# Stop Core API router
pkill Cortex

# Restore backup binary
cp Cortex.backup Cortex

# Restore configuration
cp config.json.backup.$(date +%Y%m%d) config.json

# Start legacy router
./Cortex --config config.json

# Verify functionality
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/status
```

### Automated Rollback Script

```bash
#!/bin/bash
# rollback.sh

BACKUP_DATE=${1:-$(date +%Y%m%d)}
SERVICE_DIR="/opt/Cortex"

cd $SERVICE_DIR

echo "Rolling back to backup from $BACKUP_DATE"

# Stop current service
sudo systemctl stop Cortex || pkill Cortex

# Restore backup
cp Cortex.backup Cortex
cp config.json.backup.$BACKUP_DATE config.json

# Start service
sudo systemctl start Cortex

# Verify
sleep 5
if curl -f -s http://localhost:8080/admin/status > /dev/null; then
    echo "✅ Rollback successful"
else
    echo "❌ Rollback failed"
    exit 1
fi
```

## Validation Checklist

### Post-Migration Validation

- [ ] Router starts without errors
- [ ] All providers are healthy
- [ ] Model discovery finds expected models
- [ ] Existing API endpoints work
- [ ] New admin endpoints work
- [ ] Performance meets expectations
- [ ] Monitoring and logging working
- [ ] Security configurations maintained
- [ ] Client applications still work
- [ ] Health monitoring alerts working

### Performance Validation

```bash
# Run performance tests
./scripts/performance-test.sh --parallel 10 --duration 60s

# Check response times
curl -w "@curl-format.txt" -H "x-api-key: $ROUTER_API_KEY" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Test"}],"max_tokens":10}' \
  http://localhost:8080/v1/chat/completions

# Monitor resource usage
top -p $(pgrep Cortex)
```

### Health Validation

```bash
# Check provider health
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/health

# Check model discovery
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/models

# Check system metrics
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/metrics
```

## Support Resources

### Documentation

- [Core API Integration Guide](docs/ai-provider-kit-integration.md)
- [Health Monitoring API](docs/health-monitoring-api.md)
- [Model Discovery API](docs/model-discovery-api.md)
- [Configuration Reference](docs/configuration-reference.md)

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/your-org/Cortex/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/Cortex/discussions)
- **Documentation**: [docs/](docs/)
- **Examples**: [examples/](examples/)

### Migration Assistance

For enterprise migration support:

1. **Migration Assessment**: Professional evaluation of current setup
2. **Migration Planning**: Custom migration strategy
3. **Implementation Support**: Hands-on migration assistance
4. **Performance Tuning**: Optimization for your specific use case
5. **Training**: Team training on Core API features

Contact: enterprise-support@your-org.com

---

## Conclusion

Core API migration provides significant benefits while maintaining backward compatibility. The suggested approach is to:

1. **Start with Level 1 migration** (Core API only)
2. **Gradually enable additional features** (health monitoring, model discovery)
3. **Monitor performance and adjust** configurations as needed
4. **Leverage new capabilities** for improved reliability and functionality

The migration process is designed to be straightforward with minimal risk, and the rollback procedures ensure safe deployment in production environments.