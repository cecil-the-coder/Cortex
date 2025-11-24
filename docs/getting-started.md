# Getting Started Guide

This guide will help you get Cortex up and running quickly, from installation to your first API call.

## Quick Start

### Prerequisites

- **Go 1.25+** or Docker for containerized deployment
- API keys from at least one AI provider (OpenAI, Anthropic, etc.)

### Installation

#### Option 1: Go Installation
```bash
# Clone the repository
git clone https://github.com/cecil-the-coder/Cortex.git
cd Cortex

# Install dependencies
go mod download

# Build
go build -o cortex ./cmd/router
```

#### Option 2: Docker Installation
```bash
# Pull the image
docker pull ghcr.io/cecil-the-coder/cortex:latest

# Or build from source
docker build -t cortex:latest .
```

### Configuration

1. **Copy the example configuration:**
```bash
cp config.example.json config.json
```

2. **Set your API keys:**
```bash
export ANTHROPIC_API_KEY="your-anthropic-key"
export OPENAI_API_KEY="your-openai-key"
export ROUTER_API_KEY="your-admin-key"
```

3. **Or create a `.env` file:**
```bash
echo "ANTHROPIC_API_KEY=your-key" > .env
echo "OPENAI_API_KEY=your-key" >> .env
```

### Running Cortex

#### Development Mode
```bash
# Start with hot-reload
./cortex --config config.json --hot-reload

# With admin API enabled
./cortex --config config.json --enable-admin
```

#### Docker Mode
```bash
# Basic Docker run
docker run -p 8080:8080 \
  -e ANTHROPIC_API_KEY=your-key \
  -e OPENAI_API_KEY=your-key \
  ghcr.io/cecil-the-coder/cortex:latest

# With config file
docker run -p 8080:8080 \
  -v $(pwd)/config.json:/app/config.json \
  ghcr.io/cecil-the-coder/cortex:latest
```

## First API Call

### Simple Text Request
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ROUTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic",
    "messages": [{"role": "user", "content": "Hello, Cortex!"}]
  }'
```

### Vision Request
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ROUTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic",
    "messages": [
      {
        "role": "user",
        "content": [
          {"type": "text", "text": "What do you see?"},
          {
            "type": "image_url",
            "image_url": {
              "url": "https://example.com/image.jpg"
            }
          }
        ]
      }
    ]
  }'
```

## Configuration Overview

Cortex config uses the OpenAI-compatible format with intelligent routing features:

### Basic Configuration
```json
{
  "providers": [
    {
      "name": "anthropic",
      "authMethod": "api_key",
      "APIKEY": "${ANTHROPIC_API_KEY}",
      "baseURL": "https://api.anthropic.com/v1",
      "models": ["claude-3-5-sonnet-20241022"]
    },
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1",
      "models": ["gpt-4o", "gpt-4o-mini"]
    }
  ],
  "router": {
    "default": "anthropic",
    "background": "openai"
  }
}
```

### Model Groups for Intelligent Routing
```json
{
  "ModelGroups": {
    "production": {
      "description": "Production models with auto-routing",
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-prod",
          "maxContextTokens": 200000,
          "supportsVision": true
        },
        {
          "provider": "openai",
          "model": "gpt-4o",
          "alias": "gpt4-prod",
          "maxContextTokens": 128000,
          "supportsVision": true
        }
      ]
    }
  },
  "client-api-keys": {
    "demo-key": {
      "apiKey": "demo-key-123",
      "modelGroups": ["production"]
    }
  }
}
```

## Key Features to Try

### 1. Intelligent Context Routing
Cortex automatically selects models based on context requirements:

```bash
# Large context request - auto-detects need for larger context window
curl -X POST http://localhost:8080/v1/messages \
  -H "Authorization: Bearer demo-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "production",
    "messages": [{"role": "user", "content": "Analyze this large document..."}]
  }'
```

### 2. Vision Content Detection
Cortex automatically detects images and routes to vision-capable models:

```bash
# Any request with images automatically uses vision models
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer demo-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "production",
    "messages": [
      {
        "role": "user",
        "content": [
          {"type": "text", "text": "Analyze this screenshot"},
          {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
        ]
      }
    ]
  }'
```

### 3. Health Monitoring
Check provider health and metrics:

```bash
# Check health status
curl -H "x-api-key: YOUR_ROUTER_API_KEY" http://localhost:8080/admin/health

# Get metrics
curl -H "x-api-key: YOUR_ROUTER_API_KEY" http://localhost:8080/admin/metrics
```

## Next Steps

### Production Deployment

1. **Enable Health Monitoring:**
```json
{
  "health_monitoring": {
    "enabled": true,
    "check_interval": "30s",
    "alerts": {
      "enabled": true,
      "webhook_url": "${WEBHOOK_URL}"
    }
  }
}
```

2. **Use Docker Compose:**
```yaml
version: '3.8'
services:
  cortex:
    image: ghcr.io/cecil-the-coder/cortex:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./config.json:/app/config.json
    restart: unless-stopped
```

3. **Set Up Monitoring:**
- Enable Prometheus metrics export
- Configure health alerting
- Set up log aggregation

### Advanced Configuration

- **OAuth Authentication**: Set up OAuth for enterprise providers
- **Model Discovery**: Enable automatic model discovery
- **Cost Optimization**: Implement cost-aware routing
- **Security**: Enable admin API with RBAC

### Explore the API

- **Admin API**: `/admin/v1/*` for management endpoints
- **OpenAI Compatible**: `/v1/chat/completions`, `/v1/messages`
- **Health Endpoints**: `/admin/health`, `/admin/metrics`

## Troubleshooting

### Common Issues

1. **Provider Authentication Errors**
   - Check API keys are valid
   - Verify environment variables are set
   - Ensure you have proper permissions

2. **Model Not Found**
   - Verify model names match provider offerings
   - Check provider is correctly configured
   - Use the model discovery endpoint

3. **Health Check Failures**
   - Check network connectivity to providers
   - Verify API endpoints are accessible
   - Review timeout configurations

### Debug Commands

```bash
# Check provider status
curl -H "x-api-key: YOUR_ROUTER_API_KEY" http://localhost:8080/admin/providers

# Test model discovery
curl -H "x-api-key: YOUR_ROUTER_API_KEY" http://localhost:8080/admin/models

# Get configuration
curl -H "x-api-key: YOUR_ROUTER_API_KEY" http://localhost:8080/admin/config
```

## Resources

- **[Core Concepts](./core-concepts.md)** - Learn about intelligent routing
- **[Authentication](./authentication.md)** - Configure OAuth and security
- **[Admin API](./admin-api-usage.md)** - Administrative operations
- **[Main README](../README.md)** - Complete feature overview

Need help? Check the troubleshooting section or open an issue on GitHub.