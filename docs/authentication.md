# Authentication Guide

Cortex provides comprehensive authentication and authorization systems for both LLM provider access and admin API security.

## Overview

Cortex implements multiple authentication layers:

- **OAuth 2.0**: For LLM provider authentication with automatic token refresh
- **API Key Authentication**: For direct provider access and admin API access
- **JWT Authentication**: For admin API user sessions
- **Role-Based Access Control (RBAC)**: For administrative permissions
- **Two-Factor Authentication (TFA)**: Optional TOTP-based security

## LLM Provider Authentication

### 1. API Key Authentication

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

### 2. OAuth Authentication

OAuth-only authentication with automatic token refresh:

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
    "token_url": "https://oauth2.googleapis.com/token",
    "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
    "scopes": "https://www.googleapis.com/auth/generative-language"
  }
}
```

### 3. Hybrid Authentication

Use both OAuth and API keys with OAuth preference:

```json
{
  "name": "openrouter",
  "authMethod": "hybrid",
  "APIKEY": "${OPENROUTER_API_KEY}",
  "baseURL": "https://openrouter.ai/api/v1",
  "models": ["anthropic/claude-3.5-sonnet"],
  "oauth": {
    "client_id": "${OPENROUTER_CLIENT_ID}",
    "client_secret": "${OPENROUTER_CLIENT_SECRET}",
    "access_token": "${OPENROUTER_ACCESS_TOKEN}",
    "refresh_token": "${OPENROUTER_REFRESH_TOKEN}",
    "token_url": "https://openrouter.ai/api/v1/auth/oauth/token"
  }
}
```

## OAuth Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `client_id` | Yes | OAuth client identifier |
| `client_secret` | Yes | OAuth client secret |
| `token_url` | Yes | OAuth token endpoint URL |
| `access_token` | Optional | Initial access token |
| `refresh_token` | Optional | Refresh token for automatic renewal |
| `expires_at` | Optional | Token expiration timestamp |
| `auth_url` | Optional | OAuth authorization URL |
| `redirect_url` | Optional | OAuth redirect URL |
| `scopes` | Optional | OAuth permission scopes |

## Provider-Specific OAuth Setup

### Google Gemini

1. **Create OAuth Credentials**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Enable Generative Language API
   - Create OAuth 2.0 credentials

2. **Environment Variables**:
```bash
export GEMINI_CLIENT_ID="your-client-id"
export GEMINI_CLIENT_SECRET="your-client-secret"
export GEMINI_ACCESS_TOKEN="your-access-token"
export GEMINI_REFRESH_TOKEN="your-refresh-token"
```

### OpenRouter

1. **Create OAuth Application**:
   - Contact OpenRouter for OAuth access
   - Register your application

## OAuth Features

### Automatic Token Refresh

The router automatically handles token refresh:

1. **Token Validation**: Checks expiration before requests
2. **Refresh Process**: Uses refresh token to obtain new access token
3. **Credential Persistence**: Updates configuration with new tokens
4. **Fallback**: Uses API key in hybrid mode if OAuth fails

### Hot-Reload Support

OAuth credentials support hot-reload without restart:

```bash
# Update configuration file
vim config.json

# Router automatically detects changes and reloads
# OAuth tokens are refreshed if needed
```

### Token Status Monitoring

Check OAuth status via admin endpoint:

```bash
curl -H "x-api-key: YOUR_ROUTER_API_KEY" \
  http://localhost:8080/admin/oauth-status/gemini
```

Response:
```json
{
  "provider_name": "gemini",
  "access_token": "ya29****",
  "refresh_token": "1/****",
  "token_type": "Bearer",
  "expires_at": "2024-03-15T14:30:00Z",
  "is_valid": true,
  "time_until_expiry": "1h45m23s"
}
```

## Admin API Authentication

### JWT Token Authentication

The primary authentication method for admin API access using JSON Web Tokens.

#### Authentication Flow

1. **Login**: POST `/admin/v1/auth/login` with credentials
2. **Token Response**: Receive JWT token and refresh token
3. **API Usage**: Include `Authorization: Bearer <token>` header
4. **Token Refresh**: Use refresh token to obtain new JWT
5. **Logout**: Invalidate tokens

#### Example Login Request

```bash
curl -X POST http://localhost:8080/admin/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure-password",
    "remember_me": false
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "def502009f8c4b8...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "user-uuid",
    "username": "admin",
    "role": "super_admin",
    "tfa_enabled": false
  }
}
```

### API Key Authentication

For programmatic access and service-to-service communication.

#### Creating API Keys

```bash
curl -X POST http://localhost:8080/admin/v1/users/api-keys \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Monitoring Service Key",
    "description": "Key for external monitoring service",
    "role": "viewer",
    "expires_in": 2592000,
    "allowed_ips": ["192.168.1.100"]
  }'
```

#### Using API Keys

```bash
# Method 1: Authorization header
curl -H "X-API-Key: your-api-key-here" \
  http://localhost:8080/admin/v1/status

# Method 2: Query parameter (not recommended for production)
curl "http://localhost:8080/admin/v1/status?api_key=your-api-key-here"
```

## Role-Based Access Control (RBAC)

### Role Hierarchy

```
super_admin
    └─ admin
        └─ operator
            └─ viewer
                └─ support
```

### Role Permissions

| Role | Permissions | Operations |
|------|-------------|------------|
| **super_admin** | `all` | Complete system access |
| **admin** | `full access` | Manage users, API keys, configuration |
| **operator** | `operational access` | Start/stop/load services, view logs |
| **viewer** | `read access` | View status, metrics, configuration |
| **support** | `support access` | Basic status and health checks |

## Two-Factor Authentication (TFA)

### Setup TFA

```bash
# 1. Initiate TFA setup
curl -X POST http://localhost:8080/admin/v1/auth/tfa/setup \
  -H "Authorization: Bearer <user-token>"

# 2. Verify TFA setup
curl -X POST http://localhost:8080/admin/v1/auth/tfa/verify \
  -H "Authorization: Bearer <user-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456",
    "remember_device": false
  }'

# 3. Login with TFA
curl -X POST http://localhost:8080/admin/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure-password",
    "tfa_code": "123456",
    "remember_me": false
  }'
```

## Security Best Practices

### LLM Provider Security

1. **Environment Variables**: Use environment variables for sensitive OAuth data
2. **File Permissions**: Secure config files with restricted permissions (600)
3. **HTTPS**: Always use HTTPS for OAuth endpoints
4. **Token Rotation**: Regularly rotate refresh tokens
5. **Scope Limitation**: Request minimum necessary scopes

### Admin API Security

1. **JWT Security**: Use strong secrets and short token lifetimes
2. **API Key Security**: Use cryptographically secure generation and rotation
3. **Network Security**: Enforce HTTPS and proper CORS policies
4. **Audit Logging**: Monitor all authentication attempts
5. **TFA**: Encourage TFA for all admin users

## Migration Guide

### From API Key to OAuth

1. **Register OAuth Application**: Create app with provider
2. **Update Configuration**: Change `authMethod` to "oauth" or "hybrid"
3. **Add OAuth Fields**: Add `oauth` configuration block
4. **Deploy and Test**: Verify OAuth authentication works

### From OAuth to Hybrid

1. **Add API Key**: Add `APIKEY` field to provider config
2. **Change Auth Method**: Set `authMethod: "hybrid"`
3. **Test Fallback**: Verify API key fallback works

## Troubleshooting

### OAuth Issues

**Invalid Client Credentials**:
- Verify client_id and client_secret
- Check OAuth application settings

**Refresh Token Expired**:
- Re-initiate OAuth flow to obtain new refresh token
- Check token expiration settings

**Token Refresh Issues**:
- Verify refresh token is valid and not expired
- Check token endpoint URL is correct
- Ensure network connectivity to OAuth endpoints

### Admin API Issues

**Invalid Token Errors**:
- Check token expiration: `echo "eyJ..." | cut -d. -f2 | base64 -d | jq .exp`
- Verify token format (3 parts separated by dots)
- Re-authenticate if needed

**Rate Limit Exceeded**:
- Check rate limit headers in response
- Implement exponential backoff in clients
- Verify appropriate role permissions

**TFA Issues**:
- Check system time synchronization
- Verify T OTP time window (30 seconds)
- Use manual entry key if QR scanning fails

## Configuration Examples

### Production Environment

```json
{
  "admin": {
    "enabled": true,
    "listen_address": "0.0.0.0:8443",
    "tls": {
      "enabled": true,
      "cert_file": "/etc/ssl/certs/router.crt",
      "key_file": "/etc/ssl/private/router.key"
    },
    "auth": {
      "jwt_secret_file": "/etc/Cortex/jwt-secret",
      "token_expiry": "30m",
      "refresh_token_expiry": "168h",
      "bcrypt_cost": 12
    },
    "database": {
      "driver": "postgres",
      "dsn": "postgres://router_user:password@localhost/go_llm_router?sslmode=require"
    },
    "security": {
      "cors": {
        "allowed_origins": ["https://admin.example.com"],
        "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization", "X-API-Key"],
        "credentials": true
      },
      "rate_limiting": {
        "enabled": true
      }
    }
  }
}
```

### Development Environment

```json
{
  "admin": {
    "listen_address": "127.0.0.1:8080",
    "tls": {
      "enabled": false
    },
    "auth": {
      "jwt_secret": "dev-secret-change-in-production",
      "token_expiry": "24h",
      "bcrypt_cost": 4
    },
    "database": {
      "driver": "sqlite",
      "dsn": "/tmp/Cortex-dev.db"
    },
    "security": {
      "cors": {
        "allowed_origins": ["http://localhost:3000"],
        "credentials": true
      }
    }
  }
}
```

For complete API reference and endpoint documentation, see the [Admin API documentation](./admin-api-usage.md).