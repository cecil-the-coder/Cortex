# Cortex

A high-performance Go-based LLM router that provides unified access to multiple LLM providers with intelligent routing, OAuth authentication, and hot-reload capabilities.

## Features

### Phase 3 - AI Provider Kit Integration (Latest)
- 🆕 **Core API Support**: Standardized interface across all AI providers
- 🆕 **Health Monitoring**: Real-time provider health monitoring with alerting
- 🆕 **Model Discovery**: Automatic model capability detection and catalog
- 🆕 **Request/Response Conversion**: Universal format conversion between providers
- 🆕 **Provider Extensions**: Access to provider-specific features (thinking mode, JSON mode)
- 🆕 **Performance Benchmarks**: Built-in performance monitoring and optimization
- 🆕 **Comprehensive Testing**: Full test coverage with mock providers

### Core Features
- ✅ **Multi-Provider Support**: Anthropic, OpenAI, Google Gemini, OpenRouter, and more
- ✅ **Admin Authentication**: JWT tokens, API keys, and Two-Factor Authentication (TFA)
- ✅ **Role-Based Access Control**: Hierarchical user roles with permission management
- ✅ **Enhanced Security**: Rate limiting, audit logging, and comprehensive security headers
- ✅ **User Management**: Complete user lifecycle management with password policies
- ✅ **Model Groups**: Organize and restrict access to models with aliases
- ✅ **Client API Keys**: Fine-grained access control with per-key model restrictions
- ✅ **OAuth 2.0 Authentication**: Automatic token refresh and hybrid auth (OAuth + API keys)
- ✅ **Hot-Reload Configuration**: Update API keys and OAuth credentials without restart
- ✅ **Intelligent Routing**: Smart provider selection based on request characteristics
- ✅ **Vision Routing**: Automatic routing of image content to vision-capable models
- ✅ **Unified API**: Both Anthropic and OpenAI-compatible endpoints
- ✅ **Token Counting**: Intelligent routing based on message length and context
- ✅ **Tool Support**: Function calling support across providers
- ✅ **Streaming Support**: Server-Sent Events (SSE) for real-time responses
- ✅ **Admin API**: Management endpoints for configuration and monitoring
- ✅ **Enterprise Ready**: Production-ready with proper error handling and logging

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/cecil-the-coder/Cortex.git
cd Cortex

# Build the binary
go build -o cortex ./cmd/router

# Or install directly
go install github.com/cecil-the-coder/Cortex@latest
```

### Basic Configuration

Create `config.json`:

```json
{
  "Providers": [
    {
      "name": "anthropic",
      "authMethod": "api_key",
      "APIKEY": "${ANTHROPIC_API_KEY}",
      "baseURL": "https://api.anthropic.com/v1",
      "models": [
        "claude-3-5-sonnet-20241022",
        "claude-3-opus-20240229",
        "claude-3-haiku-20240307"
      ]
    },
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "${OPENAI_API_KEY}",
      "baseURL": "https://api.openai.com/v1",
      "models": [
        "gpt-4-turbo-preview",
        "gpt-4",
        "gpt-3.5-turbo"
      ]
    }
  ],
  "Router": {
    "default": "anthropic",
    "background": "openai",
    "think": "anthropic",
    "longContext": "anthropic",
    "webSearch": "openai",
    "vision": "openai",
    "longContextThreshold": 100000
  },
  "APIKEY": "${ROUTER_API_KEY}",
  "HOST": "0.0.0.0",
  "PORT": 8080
}
```

### Environment Variables

```bash
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export OPENAI_API_KEY="your-openai-api-key"
export ROUTER_API_KEY="your-router-admin-key"
```

### Start the Router

```bash
./cortex --config config.json
```

## Authentication Methods

### API Key Authentication
Traditional static API key authentication:

```json
{
  "name": "anthropic",
  "authMethod": "api_key",
  "APIKEY": "${ANTHROPIC_API_KEY}",
  "baseURL": "https://api.anthropic.com/v1",
  "models": ["claude-3-5-sonnet-20241022"]
}
```

### OAuth Authentication
Automatic token refresh for enterprise providers:

```json
{
  "name": "gemini",
  "authMethod": "oauth",
  "baseURL": "https://generativelanguage.googleapis.com/v1",
  "models": ["gemini-2.0-flash-exp"],
  "oauth": {
    "client_id": "${GEMINI_CLIENT_ID}",
    "client_secret": "${GEMINI_CLIENT_SECRET}",
    "access_token": "${GEMINI_ACCESS_TOKEN}",
    "refresh_token": "${GEMINI_REFRESH_TOKEN}",
    "token_url": "https://oauth2.googleapis.com/token"
  }
}
```

### Hybrid Authentication
Use both OAuth and API keys with automatic fallback:

```json
{
  "name": "openrouter",
  "authMethod": "hybrid",
  "APIKEY": "${OPENROUTER_API_KEY}",
  "oauth": {
    "client_id": "${OPENROUTER_CLIENT_ID}",
    "client_secret": "${OPENROUTER_CLIENT_SECRET}",
    "access_token": "${OPENROUTER_ACCESS_TOKEN}",
    "refresh_token": "${OPENROUTER_REFRESH_TOKEN}",
    "token_url": "https://openrouter.ai/api/v1/auth/oauth/token"
  }
}
```

## API Endpoints

### Anthropic-Compatible API

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_ROUTER_API_KEY" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 100
  }' \
  http://localhost:8080/v1/messages
```

### OpenAI-Compatible API

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ROUTER_API_KEY" \
  -d '{
    "model": "gpt-4-turbo-preview",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 100
  }' \
  http://localhost:8080/v1/chat/completions
```

### Streaming Support

Both APIs support streaming responses:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_ROUTER_API_KEY" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 100,
    "stream": true
  }' \
  http://localhost:8080/v1/messages
```

### Vision Routing Support

The router automatically detects image content and routes to vision-capable providers:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_ROUTER_API_KEY" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "messages": [{
      "role": "user",
      "content": [
        {"type": "text", "text": "What do you see in this image?"},
        {
          "type": "image",
          "source": {
            "type": "base64",
            "media_type": "image/jpeg",
            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB..."
          }
        }
      ]
    }],
    "max_tokens": 100
  }' \
  http://localhost:8080/v1/messages
```

OpenAI format also supported:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ROUTER_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{
      "role": "user",
      "content": [
        {"type": "text", "text": "Analyze this image:"},
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/"
          }
        }
      ]
    }],
    "max_tokens": 100
  }' \
  http://localhost:8080/v1/chat/completions
```

## Admin API

### Status Check

```bash
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/status
```

### Reload Configuration

```bash
curl -X POST -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/reload
```

### Validate Provider

```bash
curl -X POST -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/validate/anthropic
```

### OAuth Status

```bash
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/oauth-status/gemini
```

### OAuth Token Refresh

```bash
curl -X POST -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/oauth-refresh/gemini
```

### Model Groups Management

```bash
# List all model groups
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/model-groups

# Create new model group
curl -X POST -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_ROUTER_API_KEY" \
  -d '{"name": "new-group", "models": [...]}' \
  http://localhost:8080/admin/model-groups

# Manage client API keys
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/client-api-keys
```

## Configuration

### Provider Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique provider identifier |
| `authMethod` | string | No | One of: `api_key`, `oauth`, `hybrid` (default: `api_key`) |
| `APIKEY` | string | No | Static API key (for `api_key` or `hybrid` auth) |
| `baseURL` | string | Yes | Provider base URL |
| `models` | array | Yes | List of supported models |
| `oauth` | object | No | OAuth configuration (see OAuth section) |

### OAuth Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | OAuth client identifier |
| `client_secret` | string | Yes | OAuth client secret |
| `token_url` | string | Yes | OAuth token endpoint |
| `access_token` | string | No | Current access token |
| `refresh_token` | string | No | Token for automatic refresh |
| `expires_at` | string | No | Token expiration (ISO 8601) |
| `auth_url` | string | No | OAuth authorization URL |
| `redirect_url` | string | No | OAuth redirect URL |
| `scopes` | string | No | Required OAuth scopes |

### Router Configuration

| Field | Type | Description |
|-------|------|-------------|
| `default` | string | Default provider for requests |
| `background` | string | Provider for background tasks |
| `think` | string | Provider for thinking/reasoning tasks |
| `longContext` | string | Provider for long-context requests |
| `webSearch` | string | Provider for web-search enhanced requests |
| `vision` | string | Provider for requests containing image content |
| `longContextThreshold` | int | Token count threshold for long-context routing |

### Model Groups Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique group identifier |
| `description` | string | No | Human-readable description |
| `models` | array | Yes | List of models in the group |

Each model in a group can have:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | Yes | Provider name |
| `model` | string | Yes | Actual model name |
| `alias` | string | No | User-friendly alias |

### Client API Keys Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `apiKey` | string | Yes | Client API key |
| `allowed_models` | array | No | Specific model permissions |
| `allowed_model_groups` | array | No | Model group permissions |
| `description` | string | No | Key description for tracking |

## OAuth Authentication

### Authentication Methods

1. **API Key Only** (`api_key`): Traditional static API keys
2. **OAuth Only** (`oauth`): OAuth 2.0 with automatic refresh
3. **Hybrid** (`hybrid`): OAuth preferred, API key fallback

### Supported Providers

| Provider | OAuth Support | Auth Methods |
|----------|---------------|--------------|
| Google Gemini | ✅ Full OAuth | `oauth`, `hybrid` |
| OpenRouter | ✅ OAuth + API | `oauth`, `hybrid`, `api_key` |
| Anthropic | ❌ API Key Only | `api_key` |
| OpenAI | ❌ API Key Only | `api_key` |
| Cerebras | ❌ API Key Only | `api_key` |
| Deepseek | ❌ API Key Only | `api_key` |
| xAI | ❌ API Key Only | `api_key` |
| Mistral | ❌ API Key Only | `api_key` |
| Ollama/LM Studio | ❌ API Key Only | `api_key` |

### OAuth Quick Start

```bash
# Set environment variables
export GEMINI_CLIENT_ID="your-client-id"
export GEMINI_CLIENT_SECRET="your-client-secret"
export GEMINI_ACCESS_TOKEN="your-access-token"
export GEMINI_REFRESH_TOKEN="your-refresh-token"

# Start router with OAuth
./cortex --config examples/oauth-hybrid-config.json

# Check OAuth status
curl -H "x-api-key: $ROUTER_API_KEY" \
  http://localhost:8080/admin/oauth-status/gemini
```

For detailed OAuth setup, see [Authentication Guide](docs/authentication.md).

## Admin Authentication System

The admin API provides enterprise-grade authentication and authorization features for managing the router and its configuration.

### Authentication Methods

#### 1. JWT Token Authentication
Stateless JSON Web Token authentication with automatic refresh:

```bash
# Login and get tokens
curl -X POST http://localhost:8081/admin/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure-password"
  }'

# Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "def502009f8c4b8...",
  "user": {
    "id": "uuid-here",
    "username": "admin",
    "role": "super_admin"
  }
}

# Use token for API requests
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  http://localhost:8081/admin/v1/status
```

#### 2. API Key Authentication
For programmatic access and service integration:

```bash
# Create API key
curl -X POST http://localhost:8081/admin/v1/users/api-keys \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Service Key",
    "role": "viewer",
    "expires_in": 2592000
  }'

# Use API key
curl -H "X-API-Key: sk-admin-xyz123..." \
  http://localhost:8081/admin/v1/status
```

#### 3. Two-Factor Authentication (TFA)
Enhanced security with TOTP-based 2FA:

```bash
# Setup TFA
curl -X POST http://localhost:8081/admin/v1/auth/tfa/setup \
  -H "Authorization: Bearer <jwt-token>"

# Login with TFA
curl -X POST http://localhost:8081/admin/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure-password",
    "tfa_code": "123456"
  }'
```

### Role-Based Access Control (RBAC)

#### Role Hierarchy
```
super_admin
    └─ admin
        └─ operator
            └─ viewer
                └─ support
```

#### Permissions by Role

| Role | Permissions | Operations |
|------|-------------|------------|
| **super_admin** | `all` | Complete system access |
| **admin** | `full access` | Manage users, API keys, configuration |
| **operator** | `operational access` | Start/stop/load services, view logs |
| **viewer** | `read access` | View status, metrics, configuration |
| **support** | `support access` | Basic status and health checks |

### User Management

```bash
# Create new user
curl -X POST http://localhost:8081/admin/v1/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator1",
    "password": "secure-password",
    "email": "operator@example.com",
    "role": "operator"
  }'

# List users
curl -H "Authorization: Bearer <admin-token>" \
  http://localhost:8081/admin/v1/users

# Update user role
curl -X PATCH http://localhost:8081/admin/v1/users/user-uuid \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "viewer"}'
```

### API Key Management

```bash
# List current user's API keys
curl -H "Authorization: Bearer <jwt-token>" \
  http://localhost:8081/admin/v1/users/api-keys

# Create API key with restrictions
curl -X POST http://localhost:8081/admin/v1/users/api-keys \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Service",
    "description": "Production monitoring service",
    "role": "viewer",
    "expires_in": 2592000,
    "allowed_ips": ["192.168.1.100", "10.0.0.50"]
  }'

# Revoke API key
curl -X DELETE http://localhost:8081/admin/v1/users/api-keys/key-uuid \
  -H "Authorization: Bearer <jwt-token>"
```

### Security Features

#### Rate Limiting
Per-role rate limiting with configurable thresholds:

| Role | Requests/Min | Burst | Hourly Limit |
|------|---------------|-------|--------------|
| **super_admin** | 120 | 20 | 7200 |
| **admin** | 100 | 15 | 6000 |
| **operator** | 60 | 10 | 3600 |
| **viewer** | 30 | 5 | 1800 |
| **support** | 15 | 3 | 900 |

```bash
# Check rate limit headers
curl -I http://localhost:8081/admin/v1/status \
  -H "Authorization: Bearer <token>"

# Response headers
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1640995860
```

#### Security Headers
Comprehensive security headers for web interfaces:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: "1; mode=block"
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

#### Audit Logging
Comprehensive audit trail for security events:

```json
{
  "id": "audit-uuid",
  "user_id": "user-uuid",
  "action": "user_created",
  "resource": "users",
  "resource_id": "new-user-uuid",
  "ip_address": "192.168.1.100",
  "user_agent": "curl/7.68.0",
  "created_at": "2023-01-01T12:00:00Z"
}
```

### Quick Setup

#### 1. Using Setup Script (Recommended)
```bash
# Run the interactive setup
./setup-auth.sh

# Follow prompts to create:
# - Secure secrets
# - Initial admin user
# - Configuration files
# - SSL certificates
```

#### 2. Manual Setup
```bash
# Copy configuration template
cp config-with-admin-auth.json config.json

# Set environment variables
export AUTH_JWT_SECRET="your-secure-secret"
export ADMIN_DEFAULT_USER="admin"
export ADMIN_DEFAULT_PASSWORD="secure-password"

# Start router
./cortex --config config.json
```

#### 3. Docker Setup
```bash
# Using Docker Compose
docker-compose -f docker-compose-with-auth.yml up -d

# Environment variables for initial admin
export ADMIN_PASSWORD=your-secure-password
docker-compose -f docker-compose-with-auth.yml up -d
```

### Python Examples
```python
# Install requirements
pip install requests

# Use the AdminAPIClient
from examples.admin_api_python import AdminAPIClient

# JWT Authentication
client = AdminAPIClient()
client.authenticate_with_password("admin", "password")

# API Key Authentication
client.authenticate_with_api_key("sk-admin-12345")

# Use the client
status = client.get_status()
users = client.list_users()
```

### Shell Examples
```bash
# JWT authentication
./examples/admin-api-examples.sh localhost:8080 admin password

# API key authentication
ADMIN_API_KEY=sk-admin-12345 ./examples/admin-api-examples.sh localhost:8080

# Skip TFA setup
SKIP_TFA=true ./examples/admin-api-examples.sh localhost:8080 admin password
```

For comprehensive authentication documentation, see:
- [Authentication Guide](docs/authentication.md) - Complete authentication system including OAuth, JWT, RBAC, and TFA
- [Admin API Usage](docs/admin-api-usage.md) - Administrative operations and management
- [OpenAPI Specification](internal/admin/openapi.yaml)

## Model Groups

Model Groups provide enterprise-grade access control by allowing you to organize models into logical groups and restrict client API keys to specific models or groups.

### Key Features

- **Model Aliases**: Map user-friendly names to actual model names
- **Cross-Provider Groups**: Combine models from different providers
- **Fine-Grained Access**: Restrict API keys to specific models or groups
- **Hot-Reload Support**: Update groups and permissions without restart
- **Backward Compatibility**: Works alongside existing configurations

### Quick Example

```json
{
  "ModelGroups": [
    {
      "name": "basic-models",
      "description": "Entry-level models",
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-haiku-20240307",
          "alias": "claude-haiku"
        },
        {
          "provider": "openai",
          "model": "gpt-3.5-turbo",
          "alias": "gpt35"
        }
      ]
    }
  ],
  "ClientAPIKeys": [
    {
      "apiKey": "sk-basic-client",
      "allowed_model_groups": ["basic-models"],
      "description": "Basic access only"
    }
  ]
}
```

### Usage

```bash
# Use model alias instead of full model name
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${ROUTER_API_KEY}" \
  -H "x-client-api-key: sk-basic-client" \
  -d '{
    "model": "claude-haiku",
    "messages": [{"role": "user", "content": "Hello!"}]
  }' \
  http://localhost:8080/v1/messages
```

For comprehensive documentation, see the [Getting Started Guide](docs/getting-started.md) and [Core Concepts](docs/core-concepts.md).

## Hot-Reload Configuration

The router supports hot-reload of configuration changes:

### Supported Changes

- ✅ API key updates
- ✅ OAuth credential updates
- ✅ Provider configuration changes
- ✅ Router configuration changes
- ✅ Environment variable updates

### Automatic Detection

Changes are detected automatically via file system watching:

```bash
# Update config file
vim config.json

# Router detects changes and reloads automatically
# No restart required
```

### Manual Reload

Force manual reload via admin API:

```bash
curl -X POST -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/reload
```

## Intelligent Routing

The router intelligently selects providers based on:

### Request Characteristics

- **Token Count**: Routes long-context requests to specialized providers
- **Vision Content**: Routes requests with images to vision-capable providers
- **Tools**: Routes tool requests to providers with strong tool support
- **Thinking Mode**: Routes reasoning tasks to appropriate providers
- **Background Tasks**: Routes lower-priority requests to cost-effective providers

### Routing Logic

```go
// Example routing decisions
if tokenCount > longContextThreshold {
    provider = config.Router.LongContext
} else if hasVisionContent {
    provider = config.Router.Vision
} else if hasTools {
    provider = config.Router.Think
} else if isBackground {
    provider = config.Router.Background
} else {
    provider = config.Router.Default
}
```

## Development

### Building

```bash
# Build for current platform
go build -o cortex ./cmd/router

# Build for multiple platforms
go build -o cortex-linux ./cmd/router
GOOS=darwin go build -o cortex-macos ./cmd/router
GOOS=windows go build -o cortex.exe ./cmd/router
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/config -v

# Run with coverage
go test -cover ./...
```

### Development Setup

```bash
# Clone the repository
git clone https://github.com/cecil-the-coder/Cortex.git
cd Cortex

# Install dependencies
go mod download

# Run development server
go run ./cmd/router --config config.json
```

## Core API Integration (Phase 3)

### Using the Standardized Core API

The Phase 3 implementation provides a unified interface for all AI providers:

```go
// Create provider registry with Core API support
registry, err := providers.NewSDKProviderRegistry(cfg)
if err != nil {
    log.Fatal(err)
}

// Get provider with Core API capabilities
provider, err := registry.GetProvider("openai")
if err != nil {
    log.Fatal(err)
}

// Use standardized Core API (preferred)
if provider.UseCoreAPI() {
    // Create standard request
    request, _ := types.NewCoreRequestBuilder().
        WithModel("gpt-4").
        WithMessage(types.ChatMessage{Role: "user", Content: "Hello!"}).
        WithMaxTokens(100).
        Build()

    // Generate response using Core API
    response, err := provider.GenerateStandardCompletion(context.Background(), *request)
    if err == nil {
        fmt.Printf("Response: %s\n", response.Choices[0].Message.Content)
    }
} else {
    // Fallback to legacy API
    // ... existing code continues to work
}
```

### Health Monitoring

```go
// Get real-time health status
health := registry.GetHealthMonitor()

// Check provider health
status, _ := health.GetProviderHealthStatus("openai")
fmt.Printf("OpenAI Healthy: %t, Response Time: %.3fs\n",
    status.Healthy, status.ResponseTime)

// Get list of healthy providers
healthy := health.GetHealthyProviders()
unhealthy := health.GetUnhealthyProviders()

// Set up health change notifications
health.AddStatusChangeCallback(func(provider string, oldStatus, newStatus *health.ProviderHealthStatus) {
    log.Printf("Provider %s health changed: %t -> %t",
        provider, oldStatus.Healthy, newStatus.Healthy)
})
```

### Model Discovery

```go
// Discover all available models
discovery := registry.GetDiscoveryService()
models, _ := discovery.GetAllModels(context.Background())

// Find models by capability
streamingModels, _ := discovery.GetModelsByCapability(context.Background(), "streaming")
toolModels, _ := discovery.GetModelsByCapability(context.Background(), "tool_calling")

// Filter models by requirements
filter := models.ModelFilter{
    Features:      []string{"streaming", "tool_calling"},
    MinTokens:    8000,
    SupportsStreaming: &[]bool{true}[0],
}
filtered := discovery.FilterModels(models, filter)

// Get popular models
popular, _ := discovery.GetPopularModels(context.Background())
```

### Request/Response Conversion

```go
// Convert legacy requests to standard format
requestConverter := registry.GetRequestConverter()
standardReq, err := requestConverter.ConvertFromLegacy(legacyReq)

// Convert responses between formats
responseConverter := registry.GetResponseConverter()
anthropicResp, _ := responseConverter.ConvertFromStandard(standardResp, converters.FormatLegacy)
openaiResp, _ := responseConverter.ConvertFromStandard(standardResp, converters.FormatOpenAI)
```

### Provider-Specific Extensions

```go
// Access provider-specific features
if provider.UseCoreAPI() {
    extension, err := provider.GetCoreProviderExtension()
    if err == nil {
        // Access Anthropic thinking mode
        if provider.Name() == "anthropic" {
            // Use thinking mode features
        }

        // Access OpenAI JSON mode
        if provider.Name() == "openai" {
            // Use JSON mode features
        }
    }
}
```

## Examples

See the [examples/](examples/) directory for:

### Authentication Examples
- [Admin API Shell Examples](examples/admin-api-examples.sh) - Complete authentication workflows in bash
- [Admin API Python Examples](examples/admin-api-python.py) - Python client with comprehensive auth support
- [Authentication Configuration](config-with-admin-auth.json) - Production-ready auth configuration
- [Development Configuration](config-dev-auth.json) - Development auth settings

### Configuration Examples
- [Docker Compose with Auth](docker-compose-with-auth.yml) - Complete Docker setup with authentication
- [Environment Variables](.env.auth.template) - Environment configuration template
- [Database Schema](init-db.sql) - PostgreSQL schema for authentication
- [Setup Script](setup-auth.sh) - Interactive authentication setup
- [Redis Configuration](redis.conf) - Redis settings for sessions and rate limiting

### Phase 3 Examples
- [Core API Configuration](examples/core-api-config.json) - Complete Phase 3 setup
- [Core API Usage](examples/core-api-usage.go) - Comprehensive implementation example

### Legacy Examples
- [Vision Routing Configuration](examples/vision-routing-config.json) - Complete vision routing setup
- [Vision Usage Examples](examples/vision-usage.go) - Vision routing implementation
- [Model Groups - Basic Setup](examples/model-groups-basic.json)
- [Model Groups - Multi-Provider](examples/model-groups-multi-provider.json)
- [Model Groups - Enterprise](examples/model-groups-enterprise.json)
- [Model Groups - Migration](examples/model-groups-migration.json)
- [OAuth Hybrid Configuration](examples/oauth-hybrid-config.json)
- [API Key Only Configuration](examples/api-config.json)
- [Multi-Tenant Setup](examples/multi-tenant-config.json)
- [Load Balancing](examples/load-balance-config.json)

## 📚 Documentation

### Core Guides
- **[Getting Started Guide](./docs/getting-started.md)** - Quick start, configuration, and first API call
- **[Core Concepts](./docs/core-concepts.md)** - Intelligent routing, health monitoring, and key features
- **[Authentication Guide](./docs/authentication.md)** - OAuth, API keys, JWT, RBAC, and security setup
- **[Admin API Usage](./docs/admin-api-usage.md)** - Administrative operations and management
- **[AI Provider Kit Integration](./docs/ai-provider-kit-integration.md)** - Core API integration details

### Configuration Examples
📁 **[examples/](./docs/examples/)** - Comprehensive configuration examples organized by use case

#### Key Example Categories
- **[Authentication Setup](./docs/examples/auth/)** - OAuth, API keys, and security configurations
- **[Model Groups](./docs/examples/model-groups/)** - Intelligent routing and model organization
- **[Database Integration](./docs/examples/database/)** - Database setup and configuration
- **[Deployment Examples](./docs/examples/deployment/)** - Docker, Kubernetes, and production setups

### Development Resources
- **[Setup Guide](./SETUP.md)** - Development environment setup

## Production Deployment

### Security Considerations

#### Authentication Security
1. **JWT Secrets**: Use cryptographically secure secrets (32+ characters)
2. **Password Policies**: Enforce strong passwords with complexity requirements
3. **Two-Factor Authentication**: Enable TFA for all admin users
4. **API Key Rotation**: Regularly rotate API keys and use expiration
5. **Session Management**: Configure appropriate session timeouts

#### Configuration Security
1. **Environment Variables**: Store sensitive data in environment variables or secrets
2. **File Permissions**: Set config file permissions to 600, secrets to 400
3. **HTTPS**: Always use TLS 1.2+ in production with valid certificates
4. **Firewall**: Restrict admin API access to trusted networks/IP ranges
5. **Database Security**: Use database TLS and proper user permissions

#### Operational Security
1. **Audit Logging**: Enable comprehensive audit logging for security events
2. **Rate Limiting**: Configure appropriate rate limits per role
3. **Monitoring**: Monitor authentication failures, token refresh events
4. **Backup Strategy**: Regular backups of user data and configurations
5. **Access Control**: Follow principle of least privilege for user roles

### Performance Tuning

1. **Concurrent Requests**: Adjust Go runtime for expected load
2. **Timeouts**: Configure appropriate provider timeouts
3. **Caching**: Implement response caching where appropriate
4. **Load Balancing**: Use multiple provider instances for scaling

### Monitoring

Monitor these metrics:

- Request routing success/failure rates
- OAuth token refresh events
- API response times by provider
- Error rates by provider and error type
- Configuration reload events

### Troubleshooting

Common issues and solutions:

1. **OAuth tokens not refreshing**: Check refresh token validity
2. **Hot-reload not working**: Verify file permissions and watcher support
3. **Provider timeouts**: Increase timeout values or check network connectivity
4. **Authentication failures**: Validate API keys and OAuth credentials

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 Documentation: [docs/](docs/)
- 🐛 Issues: [GitHub Issues](https://github.com/cecil-the-coder/Cortex/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/cecil-the-coder/Cortex/discussions)

## Changelog

### Latest Features (Phase 3)

- 🆕 **Core API Integration**: Standardized interface across all AI providers with unified request/response formats
- 🆕 **Health Monitoring**: Real-time provider health tracking with alerting and automatic failover
- 🆕 **Model Discovery**: Automatic model capability detection and intelligent filtering
- 🆕 **Request/Response Conversion**: Universal format conversion between providers and legacy support
- 🆕 **Provider Extensions**: Access to provider-specific features (thinking mode, JSON mode)
- 🆕 **Performance Benchmarks**: Built-in performance monitoring and optimization tools
- 🆕 **Comprehensive Test Coverage**: Full test suite with mock providers and performance benchmarks

### Previous Features

- ✅ **Model Groups**: Organize and restrict access to models with aliases
- ✅ **Client API Keys**: Fine-grained access control with per-key model restrictions
- ✅ **Model Alias Resolution**: User-friendly model names with automatic resolution
- ✅ **Enhanced Admin API**: CRUD operations for model groups and client keys
- ✅ **OAuth 2.0 authentication**: Automatic token refresh and hybrid auth
- ✅ **Hot-reload support**: Update groups and permissions without restart
- ✅ **Production-ready examples**: Enterprise and migration configurations

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.