# Configuration Examples

This directory contains comprehensive examples for configuring Cortex in various scenarios.

## Directory Structure

```
examples/
├── auth/                    # Authentication configurations
├── database/               # Database setup examples
├── model-groups/           # Model group configurations
├── routing/                # Intelligent routing configs
├── deployment/             # Deployment examples
├── admin-api-examples.sh   # Bash admin API examples
├── admin-api-python.py     # Python admin API examples
├── core-api-usage.go       # Go SDK examples
├── vision-usage.go         # Vision routing examples
└── deprecated/             # Deprecated documentation
```

## Quick Start Examples

### Basic Setup
Copy and modify the main configuration example:
```bash
cp ../config.example.json ./my-config.json
```

### Authentication (`auth/`)
- **`oauth-basic.json`** - Basic OAuth 2.0 setup
- **`oauth-hybrid.json`** - Hybrid API key + OAuth authentication
- **`config-*-auth.json`** - Various admin authentication schemes

### Model Groups (`model-groups/`)
- **`basic.json`** - Simple model group setup
- **`enterprise.json`** - Advanced enterprise configuration
- **`multi-provider.json`** - Multiple provider failover setup
- **`migration.json`** - Migration path examples

### Intelligent Routing (`routing/`)
- **`context-aware.json`** - Context window routing example
- **`core-api.json`** - Core API integration setup
- **`vision.json`** - Vision routing configuration

### Database (`database/`)
- **MySQL and PostgreSQL** setup examples
- **Docker Compose** configurations

## Usage Examples

### Bash API Examples
```bash
# Admin API operations
./admin-api-examples.sh

# Requires: export ROUTER_API_KEY="your-admin-key"
```

### Python API Examples
```bash
# Python admin API operations
python3 admin-api-python.py

# Requires: pip install requests
```

### Go SDK Examples
```bash
# Core API usage examples
go run core-api-usage.go

# Vision routing examples
go run vision-usage.go
```

## Configuration Reference

### Essential Settings
```json
{
  "providers": [
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1",
      "models": ["gpt-4o", "gpt-4o-mini"]
    }
  ],
  "router": {
    "default": "openai"
  }
}
```

### Model Groups with Intelligent Routing
```json
{
  "ModelGroups": {
    "production": {
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-prod",
          "maxContextTokens": 200000,
          "supportsVision": true
        }
      ]
    }
  }
}
```

### Health Monitoring
```json
{
  "health_monitoring": {
    "enabled": true,
    "check_interval": "30s",
    "alert_threshold": 3,
    "alerts": {
      "enabled": true,
      "channels": ["log", "webhook"]
    }
  }
}
```

## Environment Variables

Common environment variables used in examples:

```bash
# Provider API Keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# OAuth Configuration
export GEMINI_CLIENT_ID="your-client-id"
export GEMINI_CLIENT_SECRET="your-client-secret"

# Database
export DB_HOST="localhost"
export DB_USER="cortex"
export DB_PASSWORD="secure-password"

# Admin API
export ROUTER_API_KEY="your-admin-key"
export ADMIN_DEFAULT_USER="admin"
export ADMIN_DEFAULT_PASSWORD="secure-password"
```

## Setup Instructions

1. **Choose an example** based on your use case
2. **Copy the configuration** to your preferred location
3. **Set environment variables** for your API keys and secrets
4. **Modify the configuration** to match your requirements
5. **Test the setup** with provided API examples

## Common Patterns

### Development vs Production
- **Development**: Use `config-dev-auth.json` from `auth/`
- **Production**: Use `database/` examples with proper persistence

### OAuth Integration
1. Start with `auth/oauth-basic.json`
2. Add hybrid authentication with `oauth-hybrid.json`
3. Enable admin authentication

### Multi-Provider Setup
1. Configure providers in main config
2. Set up model groups in `model-groups/`
3. Enable health monitoring
4. Configure intelligent routing

## Troubleshooting

### Configuration Validation
```bash
# Test configuration syntax
curl -X POST http://localhost:8080/admin/validate/config \
  -H "Content-Type: application/json" \
  -d @your-config.json
```

### Provider Health Checks
```bash
# Check all providers
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/health

# Trigger manual health check
curl -X POST -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/health/check
```

## Migration Paths

### From Basic to Advanced
1. **Start**: Basic provider setup
2. **Add**: Model groups
3. **Enable**: Health monitoring
4. **Configure**: Intelligent routing
5. **Implement**: Authentication

### Examples by Complexity
- **Beginner**: Basic config + model groups
- **Intermediate**: Add routing + health monitoring
- **Advanced**: OAuth + database + advanced routing
- **Enterprise**: All features + security + monitoring

## Need Help?

- See [Getting Started Guide](../getting-started.md) for setup instructions
- Check [Core Concepts](../core-concepts.md) for feature explanations
- Review [Authentication Guide](../authentication.md) for security setup