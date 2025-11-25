# Admin API Usage Guide

This guide provides comprehensive documentation for using the admin API features of the Cortex. The admin API allows you to manage
users, API keys, model groups, access control, and monitor usage through REST endpoints with comprehensive authentication
and authorization.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Authentication & Authorization](#authentication--authorization)
  - [Authentication Methods](#authentication-methods)
  - [User Roles & Permissions](#user-roles--permissions)
  - [Two-Factor Authentication (TFA)](#two-factor-authentication-tfa)
  - [Rate Limiting](#rate-limiting)
  - [Security Headers](#security-headers)
- [API Endpoints](#api-endpoints)
  - [Authentication Endpoints](#authentication-endpoints)
  - [User Management](#user-management)
  - [API Key Management](#api-key-management)
  - [Model Group Management](#model-group-management)
  - [Access Control](#access-control)
- [Configuration](#configuration)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

The admin API provides secure programmatic access to manage and monitor your LLM router deployment. Key features include:

- **User Management**: Create and manage user accounts with role-based access control
- **Authentication**: Multiple authentication methods including JWT, API keys, and session cookies
- **Two-Factor Authentication**: TOTP-based 2FA with backup codes for enhanced security
- **API Key Management**: Create, update, delete, and validate client API keys with granular permissions
- **Model Group Management**: Organize models into logical groups with aliases
- **Access Control**: Role-based permissions and fine-grained access control per API key and model
- **Usage Monitoring**: Track usage statistics and enforce rate limits
- **Dynamic Configuration**: Update configuration without server restart
- **Security Features**: Rate limiting, audit logging, and security headers

## Quick Start

### 1. Start the Router with Admin API Enabled

```bash
# Basic usage with default admin port (8081)
./router -config config.json -enable-admin

# Custom admin server configuration
./router -config config.json -enable-admin -admin-port 9000 -admin-host 0.0.0.0

# Using test configuration
./router -config test-config.json -enable-admin
```

### 2. Authenticate and Get Access Token

```bash
# Login with username and password
curl -X POST \
     -H "Content-Type: application/json" \
     -d '{
       "username": "admin",
       "password": "your-secure-password"
     }' \
     http://localhost:8081/admin/v1/auth/login
```

The response will include a JWT token for subsequent API calls.

### 3. Make Your First Authenticated API Call

```bash
# Use the JWT token to list users
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8081/admin/v1/users
```

### 4. Run the Examples

```bash
# Bash examples
./examples/admin-api-examples.sh

# Python examples
python examples/admin-api-python.py --demo
```

## Authentication & Authorization

The admin API supports multiple authentication methods and comprehensive role-based access control (RBAC).

### Authentication Methods

#### 1. JWT Token Authentication (Recommended for APIs)

```bash
# First login to get a JWT token
POST /v1/auth/login
{
  "username": "admin",
  "password": "secure_password",
  "tfa_code": "123456"  // Required if TFA is enabled
}

# Use the token in subsequent requests
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 2. API Key Header Authentication

```bash
# For programmatic access
X-API-Key: sk-admin-123456789
```

#### 3. Session Cookie Authentication

```bash
# For web interface
Cookie: session_token=abc123def456...
```

#### 4. Query Parameter Authentication (Legacy)

```bash
# Not recommended for production
?api_key=sk-admin-123456789
```

### User Roles & Permissions

#### Role Hierarchy

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| `super_admin` | Full system access | All resources, user management, system settings |
| `admin` | Administrative access | Most resources, some limitations |
| `operator` | Operational access | Providers, models, monitoring (no users) |
| `viewer` | Read-only access | View all resources (no modifications) |
| `support` | Support access | Logs, diagnostics, monitoring |

#### Permission Categories

- **User Management**: `users.read`, `users.write`, `users.delete`
- **API Key Management**: `apikeys.read`, `apikeys.write`, `apikeys.delete`
- **Provider Management**: `providers.read`, `providers.write`, `providers.delete`
- **Model Management**: `models.read`, `models.write`
- **System Management**: `system.read`, `system.write`
- **Monitoring**: `monitoring.read`, `logs.read`

### Two-Factor Authentication (TFA)

#### Setting Up TFA

```bash
# Initiate TFA setup
POST /v1/auth/tfa/setup
{
  "password": "current_password"
}

# Response
{
  "success": true,
  "qr_code": "base64-encoded-qr-code",
  "secret": "JBSWY3DPEHPK3PXP",
  "backup_codes": ["123456", "789012", "345678"]
}
```

#### Verifying TFA

```bash
# Verify and enable TFA
POST /v1/auth/tfa/verify
{
  "code": "123456"
}
```

#### Using TFA for Login

```bash
POST /v1/auth/login
{
  "username": "admin",
  "password": "secure_password",
  "tfa_code": "123456"  // Required when TFA is enabled
}
```

### Rate Limiting

Rate limiting is applied per user role and IP address:

| Role | Requests per Minute |
|------|-------------------|
| `super_admin` | 1000 |
| `admin` | 500 |
| `operator` | 200 |
| `viewer` | 100 |
| `support` | 50 |

#### Rate Limit Headers

Every API response includes rate limit information:

```http
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 492
X-RateLimit-Reset: 2024-01-01T12:01:00Z
```

### Security Headers

The API includes comprehensive security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## API Endpoints

Base URL: `http://localhost:8081/admin/v1` (or as configured)

### Authentication Endpoints

#### Login
```http
POST /v1/auth/login
```

**Request Body:**
```json
{
  "username": "admin",
  "password": "secure_password",
  "remember_me": false,
  "tfa_code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": "user_123",
    "username": "admin",
    "email": "admin@example.com",
    "role": "super_admin",
    "tfa_enabled": true
  },
  "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "requires_tfa": false
}
```

#### Refresh Token
```http
POST /v1/auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "refresh_token_here"
}
```

#### Logout
```http
POST /v1/auth/logout
```

#### Setup TFA
```http
POST /v1/auth/tfa/setup
```

#### Verify TFA
```http
POST /v1/auth/tfa/verify
```

#### Disable TFA
```http
POST /v1/auth/tfa/disable
```

### User Management

#### List Users
```http
GET /v1/users?page=1&per_page=50&role=admin&status=active
```

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_123",
        "username": "admin",
        "email": "admin@example.com",
        "role": "super_admin",
        "status": "active",
        "full_name": "System Administrator",
        "created_at": "2024-01-15T10:30:00Z",
        "last_login": "2024-01-15T11:00:00Z",
        "tfa_enabled": true,
        "permissions": ["users.manage", "system.configure"]
      }
    ],
    "count": 1
  },
  "paging": {
    "page": 1,
    "per_page": 50,
    "total": 1,
    "total_pages": 1
  }
}
```

#### Create User
```http
POST /v1/users
```

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "role": "operator",
  "full_name": "John Doe",
  "password": "temporary_password_123",
  "force_password_change": true,
  "tfa_enabled": false,
  "permissions": ["providers.read", "models.read"]
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": "user_456",
    "username": "john_doe",
    "email": "john@example.com",
    "role": "operator",
    "status": "pending",
    "created_at": "2024-01-15T12:00:00Z"
  },
  "temporary_password": "temp_abc123xyz"
}
```

#### Update User
```http
PUT /v1/users/{id}
```

#### Delete User
```http
DELETE /v1/users/{id}
```

#### Reset User Password
```http
POST /v1/users/{id}/reset-password
```

#### Lock/Unlock User
```http
POST /v1/users/{id}/lock
POST /v1/users/{id}/unlock
```

### API Key Management

#### List API Keys
```http
GET /v1/users/api-keys?page=1&per_page=50&owner_id=user_123&permissions=models.read
```

**Response:**
```json
{
  "success": true,
  "data": {
    "api_keys": [
      {
        "id": "api_key_123",
        "owner_id": "user_123",
        "description": "Production API key",
        "key_preview": "sk-****************5678",
        "permissions": ["models.read", "providers.read"],
        "model_groups": ["production"],
        "rate_limit": 1000,
        "enabled": true,
        "created_at": "2024-01-15T10:30:00Z",
        "last_used": "2024-01-15T11:00:00Z",
        "usage_count": 15420
      }
    ],
    "count": 1
  },
  "paging": {
    "page": 1,
    "per_page": 50,
    "total": 1,
    "total_pages": 1
  }
}
```

#### Create API Key
```http
POST /v1/users/api-keys
```

**Request Body:**
```json
{
  "description": "Production API key for main application",
  "permissions": ["models.read", "providers.read"],
  "model_groups": ["production", "vision"],
  "rate_limit": 500,
  "enabled": true,
  "expires_at": "2024-12-31T23:59:59Z",
  "owner_id": "user_123",
  "api_key": "sk-custom-key-123456"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "api_key": {
      "id": "api_key_456",
      "owner_id": "user_123",
      "description": "Production API key for main application",
      "key_preview": "sk-****************5678",
      "permissions": ["models.read", "providers.read"],
      "model_groups": ["production", "vision"],
      "rate_limit": 500,
      "enabled": true,
      "created_at": "2024-01-15T12:00:00Z"
    }
  },
  "full_key": "sk-newly-generated-key-abcdef123456"
}
```

#### Update API Key
```http
PUT /v1/users/api-keys/{id}
```

**Request Body:**
```json
{
  "description": "Updated production API key",
  "permissions": ["models.read", "providers.read", "models.write"],
  "model_groups": ["production"],
  "rate_limit": 750,
  "enabled": true,
  "expires_at": "2025-01-01T00:00:00Z"
}
```

#### Delete API Key
```http
DELETE /v1/users/api-keys/{id}
```

#### Get API Key Usage
```http
GET /v1/users/api-keys/{id}/usage?period=month
```

**Response:**
```json
{
  "success": true,
  "data": {
    "usage": {
      "requests_today": 150,
      "requests_this_month": 3240,
      "total_requests": 15320,
      "last_used": "2024-01-15T10:45:00Z",
      "rate_limit_current": 500,
      "average_requests_per_day": 108,
      "requests_by_model": {
        "claude-3-5-sonnet-20241022": 1200,
        "gpt-4-turbo-preview": 890,
        "gemini-pro": 1150
      },
      "requests_by_status": {
        "success": 3200,
        "error": 35,
        "timeout": 5
      }
    }
  }
}
```

#### Validate API Key
```http
POST /v1/users/api-keys/validate
```

**Request Body:**
```json
{
  "api_key": "sk-client-key-123456",
  "model": "claude-sonnet"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "validation": {
      "api_key": "sk-************5678",
      "format_valid": true,
      "exists": true,
      "access_valid": true,
      "key_id": "api_key_456",
      "owner_id": "user_123",
      "permissions": ["models.read", "providers.read"],
      "model_access": {
        "has_access": true,
        "resolved_model": "claude-3-5-sonnet-20241022",
        "provider": "anthropic",
        "model_group": "production"
      }
    }
  }
}
```

### Model Group Management

#### List Model Groups

```http
GET /admin/model-groups
```

**Response:**
```json
{
  "success": true,
  "model_groups": {
    "production": {
      "name": "production",
      "description": "Production models",
      "model_count": 3,
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-sonnet"
        }
      ],
      "aliases": {
        "claude-sonnet": "claude-3-5-sonnet-20241022"
      }
    }
  },
  "count": 1,
  "timestamp": "2024-01-15T11:30:00Z"
}
```

#### Create Model Group

```http
POST /admin/model-groups
```

**Request Body:**
```json
{
  "name": "vision-models",
  "description": "Models with vision capabilities",
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-3-5-sonnet-20241022",
      "alias": "claude-vision"
    },
    {
      "provider": "openai",
      "model": "gpt-4-vision-preview",
      "alias": "gpt4-vision"
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "group_info": {
    "name": "vision-models",
    "description": "Models with vision capabilities",
    "model_count": 2,
    "models": [...],
    "aliases": {...}
  },
  "timestamp": "2024-01-15T11:35:00Z",
  "message": "Model group created successfully"
}
```

#### Update Model Group

```http
PUT /admin/model-groups/{group_name}
```

**Request Body:**
```json
{
  "description": "Updated vision models group",
  "models": [
    {
      "provider": "anthropic",
      "model": "claude-3-5-sonnet-20241022",
      "alias": "claude-vision"
    },
    {
      "provider": "openai",
      "model": "gpt-4-vision-preview",
      "alias": "gpt4-vision"
    },
    {
      "provider": "google",
      "model": "gemini-pro-vision",
      "alias": "gemini-vision"
    }
  ]
}
```

#### Delete Model Group

```http
DELETE /admin/model-groups/{group_name}
```

#### Get Model Group Details

```http
GET /admin/model-groups/{group_name}
```

### Access Control

#### Check Model Access

```http
POST /admin/access/check
```

**Request Body:**
```json
{
  "api_key": "sk-client-key-123456",
  "model": "claude-sonnet"
}
```

**Response:**
```json
{
  "success": true,
  "has_access": true,
  "api_key": "sk-************5678",
  "model": "claude-sonnet",
  "resolved_model": "claude-3-5-sonnet-20241022",
  "provider": "anthropic",
  "model_group": "production",
  "resolved_by": "model_group_alias",
  "reason": "Access granted",
  "timestamp": "2024-01-15T11:40:00Z"
}
```

#### Get Available Models for API Key

```http
GET /admin/access/models/{api_key}
```

**Response:**
```json
{
  "success": true,
  "api_key": "sk-************5678",
  "available_models": [
    "claude-3-5-sonnet-20241022",
    "claude-sonnet",
    "gpt-4-turbo-preview",
    "gpt4-turbo"
  ],
  "aliases": {
    "claude-sonnet": "claude-3-5-sonnet-20241022",
    "gpt4-turbo": "gpt-4-turbo-preview"
  },
  "model_count": 4,
  "timestamp": "2024-01-15T11:45:00Z"
}
```

#### Get Available Aliases for API Key

```http
GET /admin/access/aliases/{api_key}
```

#### Get Model Group Membership

```http
GET /admin/access/groups/{model}
```

## Configuration

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-enable-admin` | Enable admin API server | `false` |
| `-admin-port` | Port for admin API server | `8081` |
| `-admin-host` | Host for admin API server | `localhost` |
| `-config` | Path to configuration file | `config.json` |
| `-version` | Show version information | - |
| `-help` | Show help information | - |

### Configuration File

The admin API uses comprehensive configuration for authentication and authorization:

```json
{
  "AdminAPI": {
    "enabled": true,
    "port": 8081,
    "host": "localhost",
    "authentication": {
      "methods": ["jwt", "api_key", "session"],
      "jwt": {
        "secret": "your-jwt-secret-key",
        "expiration": "1h",
        "refresh_expiration": "7d"
      },
      "rbac": {
        "enabled": true,
        "default_role": "viewer",
        "roles": {
          "super_admin": {
            "description": "Full system access",
            "permissions": ["*"]
          },
          "admin": {
            "description": "Administrative access",
            "permissions": ["users.*", "apikeys.*", "providers.*", "models.*", "monitoring.read"]
          }
        }
      },
      "tfa": {
        "enabled": true,
        "issuer": "Go LLM Router",
        "required_for_roles": ["super_admin", "admin"],
        "backup_codes_count": 10
      },
      "rate_limiting": {
        "enabled": true,
        "limits": {
          "super_admin": 1000,
          "admin": 500,
          "operator": 200,
          "viewer": 100,
          "support": 50
        }
      },
      "security": {
        "cors": {
          "enabled": true,
          "allowed_origins": ["http://localhost:3000"]
        },
        "headers": {
          "hsts": {
            "enabled": true,
            "max_age": 31536000,
            "include_subdomains": true
          },
          "csp": {
            "enabled": true,
            "policy": "default-src 'self'"
          }
        }
      }
    },
    "audit_log": {
      "enabled": true,
      "path": "/var/log/llm-router/audit.log",
      "format": "json"
    }
  },
  "Users": {
    "admin": {
      "username": "admin",
      "password_hash": "$2a$10$...",  // bcrypt hash
      "email": "admin@example.com",
      "role": "super_admin",
      "full_name": "System Administrator",
      "tfa_enabled": true,
      "tfa_secret": "JBSWY3DPEHPK3PXP",
      "status": "active",
      "created_at": "2024-01-01T00:00:00Z"
    }
  },
  "ModelGroups": {
    "production": {
      "description": "Production models",
      "models": [
        {
          "provider": "anthropic",
          "model": "claude-3-5-sonnet-20241022",
          "alias": "claude-sonnet"
        }
      ]
    }
  }
}
```

## Examples

### Using curl with JWT Authentication

```bash
#!/bin/bash

# First, login to get JWT token
LOGIN_RESPONSE=$(curl -X POST \
     -H "Content-Type: application/json" \
     -d '{
       "username": "admin",
       "password": "your-secure-password"
     }' \
     http://localhost:8081/admin/v1/auth/login)

# Extract JWT token from response
JWT_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.jwt_token')

# Use JWT token for API calls
HEADERS="-H \"Authorization: Bearer $JWT_TOKEN\" -H \"Content-Type: application/json\""

# List all users
curl $HEADERS http://localhost:8081/admin/v1/users

# Create a new user
curl -X POST $HEADERS \
     -d '{
       "username": "john_doe",
       "email": "john@example.com",
       "role": "operator",
       "full_name": "John Doe"
     }' \
     http://localhost:8081/admin/v1/users

# Create API key for the new user
curl -X POST $HEADERS \
     -d '{
       "description": "Production API key",
       "permissions": ["models.read", "providers.read"],
       "model_groups": ["production"],
       "rate_limit": 500,
       "owner_id": "john_doe"
     }' \
     http://localhost:8081/admin/v1/users/api-keys

# Set up TFA for a user
curl -X POST $HEADERS \
     -d '{
       "password": "current_password"
     }' \
     http://localhost:8081/admin/v1/auth/tfa/setup
```

### Using Python with JWT Authentication

```python
import requests
import json

class AdminAPIClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.jwt_token = None

        # Login and get JWT token
        self._login(username, password)

    def _login(self, username, password, tfa_code=None):
        """Authenticate and get JWT token"""
        login_data = {
            "username": username,
            "password": password
        }

        if tfa_code:
            login_data["tfa_code"] = tfa_code

        response = self.session.post(
            f"{self.base_url}/admin/v1/auth/login",
            json=login_data
        )

        if response.status_code == 200:
            data = response.json()
            self.jwt_token = data['jwt_token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.jwt_token}',
                'Content-Type': 'application/json'
            })
            return data
        else:
            raise Exception(f"Login failed: {response.text}")

    def refresh_token(self, refresh_token):
        """Refresh JWT token"""
        response = self.session.post(
            f"{self.base_url}/admin/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )

        if response.status_code == 200:
            data = response.json()
            self.jwt_token = data['jwt_token']
            self.session.headers['Authorization'] = f'Bearer {self.jwt_token}'
            return data
        else:
            raise Exception(f"Token refresh failed: {response.text}")

    def list_users(self, role=None, status=None):
        """List users with optional filtering"""
        params = {}
        if role:
            params['role'] = role
        if status:
            params['status'] = status

        response = self.session.get(
            f"{self.base_url}/admin/v1/users",
            params=params
        )
        return response.json()

    def create_user(self, username, email, role, full_name=None):
        """Create a new user"""
        user_data = {
            "username": username,
            "email": email,
            "role": role
        }
        if full_name:
            user_data["full_name"] = full_name

        response = self.session.post(
            f"{self.base_url}/admin/v1/users",
            json=user_data
        )
        return response.json()

    def create_api_key(self, description, permissions, model_groups=None, owner_id=None):
        """Create API key for a user"""
        api_key_data = {
            "description": description,
            "permissions": permissions
        }
        if model_groups:
            api_key_data["model_groups"] = model_groups
        if owner_id:
            api_key_data["owner_id"] = owner_id

        response = self.session.post(
            f"{self.base_url}/admin/v1/users/api-keys",
            json=api_key_data
        )
        return response.json()

    def setup_tfa(self, password):
        """Setup two-factor authentication"""
        response = self.session.post(
            f"{self.base_url}/admin/v1/auth/tfa/setup",
            json={"password": password}
        )
        return response.json()

    def get_api_key_usage(self, api_key_id, period="month"):
        """Get usage statistics for an API key"""
        response = self.session.get(
            f"{self.base_url}/admin/v1/users/api-keys/{api_key_id}/usage",
            params={"period": period}
        )
        return response.json()

# Usage example
if __name__ == "__main__":
    try:
        # Initialize client with JWT authentication
        client = AdminAPIClient("http://localhost:8081", "admin", "secure_password")

        # List all admin users
        admin_users = client.list_users(role="admin")
        print("Admin users:", json.dumps(admin_users, indent=2))

        # Create a new operator user
        new_user = client.create_user(
            username="operator1",
            email="operator1@example.com",
            role="operator",
            full_name="Operator One"
        )
        print("Created user:", json.dumps(new_user, indent=2))

        # Create API key for the new user
        api_key = client.create_api_key(
            description="Operator production API key",
            permissions=["models.read", "providers.read"],
            model_groups=["production"],
            owner_id="operator1"
        )
        print("Created API key:", json.dumps(api_key, indent=2))

        # Setup TFA
        tfa_setup = client.setup_tfa("current_admin_password")
        print("TFA setup:", json.dumps(tfa_setup, indent=2))

    except Exception as e:
        print(f"Error: {e}")

```

### Using JavaScript with JWT Authentication

```javascript
class AdminAPIClient {
    constructor(baseURL) {
        this.baseURL = baseURL.replace(/\/$/, '');
        this.token = null;
        this.refreshToken = null;
    }

    async login(username, password, tfaCode = null) {
        const loginData = {
            username,
            password
        };

        if (tfaCode) {
            loginData.tfa_code = tfaCode;
        }

        const response = await fetch(`${this.baseURL}/admin/v1/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(loginData)
        });

        if (!response.ok) {
            throw new Error(`Login failed: ${response.statusText}`);
        }

        const data = await response.json();
        this.token = data.jwt_token;
        this.refreshToken = data.refresh_token;
        return data;
    }

    async makeAuthenticatedRequest(endpoint, options = {}) {
        if (!this.token) {
            throw new Error('Not authenticated - call login() first');
        }

        const defaultHeaders = {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
        };

        const config = {
            headers: defaultHeaders,
            ...options
        };

        let response = await fetch(`${this.baseURL}${endpoint}`, config);

        // Handle token refresh if needed
        if (response.status === 401 && this.refreshToken) {
            await this.refreshAuthToken();
            config.headers.Authorization = `Bearer ${this.token}`;
            response = await fetch(`${this.baseURL}${endpoint}`, config);
        }

        return response;
    }

    async refreshAuthToken() {
        const response = await fetch(`${this.baseURL}/admin/v1/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: this.refreshToken })
        });

        if (!response.ok) {
            throw new Error('Token refresh failed');
        }

        const data = await response.json();
        this.token = data.jwt_token;
        return data;
    }

    async listUsers(filters = {}) {
        const params = new URLSearchParams(filters);
        const response = await this.makeAuthenticatedRequest(`/admin/v1/users?${params}`);
        return await response.json();
    }

    async createUser(userData) {
        const response = await this.makeAuthenticatedRequest('/admin/v1/users', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
        return await response.json();
    }

    async createAPIKey(apiKeyData) {
        const response = await this.makeAuthenticatedRequest('/admin/v1/users/api-keys', {
            method: 'POST',
            body: JSON.stringify(apiKeyData)
        });
        return await response.json();
    }

    async setupTFA(password) {
        const response = await this.makeAuthenticatedRequest('/admin/v1/auth/tfa/setup', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
        return await response.json();
    }

    async logout() {
        if (this.token) {
            await this.makeAuthenticatedRequest('/admin/v1/auth/logout', { method: 'POST' });
        }
        this.token = null;
        this.refreshToken = null;
    }
}

// Usage example
async function adminAPIExample() {
    try {
        const client = new AdminAPIClient('http://localhost:8081');

        // Login with credentials
        await client.login('admin', 'secure_password');
        console.log('Login successful');

        // List users
        const users = await client.listUsers({ role: 'admin' });
        console.log('Admin users:', users);

        // Create new user
        const newUser = await client.createUser({
            username: 'javascript_user',
            email: 'js@example.com',
            role: 'operator',
            full_name: 'JavaScript User'
        });
        console.log('Created user:', newUser);

        // Create API key
        const apiKey = await client.createAPIKey({
            description: 'JavaScript application API key',
            permissions: ['models.read', 'providers.read'],
            model_groups: ['production'],
            owner_id: 'javascript_user'
        });
        console.log('Created API key:', apiKey);

        // Setup TFA
        const tfaSetup = await client.setupTFA('current_admin_password');
        console.log('TFA setup:', tfaSetup);

        // Logout
        await client.logout();
        console.log('Logged out');

    } catch (error) {
        console.error('API Error:', error);
    }
}

// Run the example
adminAPIExample();
```

## Error Handling

The admin API returns structured error responses:

### Error Response Format

```json
{
  "error": "true",
  "code": "authentication_error",
  "message": "Invalid authentication credentials",
  "details": {
    "field": "Authorization header",
    "reason": "JWT token is expired or invalid"
  },
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### Common Error Types

| Error Code | Description | HTTP Status | Common Causes |
|------------|-------------|-------------|--------------|
| `authentication_error` | Invalid or missing authentication | 401 | Expired JWT, invalid API key, missing credentials |
| `authorization_error` | Insufficient permissions for role | 403 | User role doesn't have required permissions |
| `validation_error` | Request validation failed | 400 | Invalid JSON, missing required fields |
| `not_found_error` | Resource not found | 404 | Invalid resource ID, user doesn't exist |
| `conflict_error` | Resource already exists | 409 | Duplicate username or email |
| `rate_limit_error` | Rate limit exceeded | 429 | Too many requests from user/IP |
| `tfa_required_error` | Two-factor authentication required | 428 | User has TFA enabled but didn't provide code |
| `tfa_invalid_error` | Invalid TFA code provided | 401 | Incorrect TOTP code |
| `service_unavailable` | Service temporarily unavailable | 503 | Maintenance, database issues |

### Handling Errors in Code

```python
import requests
import json
from typing import Dict, Any

class AdminAPIError(Exception):
    def __init__(self, response: Dict[str, Any]):
        self.code = response.get('code', 'unknown_error')
        self.message = response.get('message', 'Unknown error occurred')
        self.details = response.get('details', {})
        self.status_code = response.get('status_code', 500)
        super().__init__(f"API Error ({self.code}): {self.message}")

class AdminAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.jwt_token = None

    def _handle_response(self, response: requests.Response):
        """Handle API response and raise appropriate errors"""
        try:
            data = response.json()
        except json.JSONDecodeError:
            raise AdminAPIError({
                'code': 'invalid_response',
                'message': 'Invalid JSON response',
                'status_code': response.status_code
            })

        # Check for API-level errors
        if not data.get('success', True):
            data['status_code'] = response.status_code
            raise AdminAPIError(data)

        return data

    def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make authenticated request with error handling"""
        try:
            response = self.session.request(
                method.upper(),
                f"{self.base_url}{endpoint}",
                **kwargs
            )
            response.raise_for_status()
            return self._handle_response(response)

        except requests.exceptions.HTTPError as e:
            # Handle auth errors vs. other HTTP errors
            if e.response.status_code == 401:
                # Try to refresh token if we have one
                if self._refresh_token():
                    # Retry the request once
                    response = self.session.request(
                        method.upper(),
                        f"{self.base_url}{endpoint}",
                        **kwargs
                    )
                    response.raise_for_status()
                    return self._handle_response(response)

            # Format HTTP error as API error
            error_data = {
                'code': 'http_error',
                'message': str(e),
                'status_code': e.response.status_code
            }
            raise AdminAPIError(error_data)

        except requests.exceptions.ConnectionError as e:
            raise AdminAPIError({
                'code': 'connection_error',
                'message': 'Failed to connect to API server',
                'details': {'original_error': str(e)},
                'status_code': 503
            })

        except requests.exceptions.Timeout as e:
            raise AdminAPIError({
                'code': 'timeout_error',
                'message': 'Request timed out',
                'details': {'original_error': str(e)},
                'status_code': 408
            })

        except requests.exceptions.RequestException as e:
            raise AdminAPIError({
                'code': 'request_error',
                'message': 'Request failed',
                'details': {'original_error': str(e)},
                'status_code': 500
            })

    def login(self, username: str, password: str, tfa_code: str = None) -> Dict[str, Any]:
        """Login with comprehensive error handling"""
        try:
            login_data = {"username": username, "password": password}
            if tfa_code:
                login_data["tfa_code"] = tfa_code

            response = self.session.post(
                f"{self.base_url}/admin/v1/auth/login",
                json=login_data
            )

            data = self._handle_response(response)

            if data.get('requires_tfa') and not tfa_code:
                raise AdminAPIError({
                    'code': 'tfa_required_error',
                    'message': 'Two-factor authentication is required',
                    'details': {'next_step': 'provide_tfa_code'},
                    'status_code': 428
                })

            self.jwt_token = data['jwt_token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.jwt_token}',
                'Content-Type': 'application/json'
            })

            return data

        except AdminAPIError:
            raise
        except Exception as e:
            raise AdminAPIError({
                'code': 'login_error',
                'message': 'Login failed due to unexpected error',
                'details': {'original_error': str(e)},
                'status_code': 500
            })

    def _refresh_token(self) -> bool:
        """Attempt to refresh the JWT token"""
        if not hasattr(self, 'refresh_token') or not self.refresh_token:
            return False

        try:
            response = self.session.post(
                f"{self.base_url}/admin/v1/auth/refresh",
                json={"refresh_token": self.refresh_token}
            )

            data = self._handle_response(response)
            self.jwt_token = data['jwt_token']
            self.session.headers['Authorization'] = f'Bearer {self.jwt_token}'
            return True

        except Exception:
            return False

    def create_user_with_handling(self, **user_data):
        """Create user with comprehensive error handling"""
        try:
            return self._make_request('POST', '/admin/v1/users', json=user_data)

        except AdminAPIError as e:
            # Provide specific guidance based on error type
            if e.code == 'validation_error':
                field_errors = e.details.get('fields', {})
                if 'username' in field_errors:
                    raise AdminAPIError({
                        'code': 'username_validation_error',
                        'message': 'Username validation failed',
                        'details': {
                            'suggestion': 'Username must be 3-50 characters, alphanumeric only',
                            'original_error': field_errors['username']
                        },
                        'status_code': 400
                    })
                elif 'email' in field_errors:
                    raise AdminAPIError({
                        'code': 'email_validation_error',
                        'message': 'Email validation failed',
                        'details': {
                            'suggestion': 'Email must be a valid email address',
                            'original_error': field_errors['email']
                        },
                        'status_code': 400
                    })

            elif e.code == 'conflict_error':
                # Check if it's username or email conflict
                if 'username' in str(e.message).lower():
                    raise AdminAPIError({
                        'code': 'username_exists_error',
                        'message': 'Username already exists',
                        'details': {
                            'suggestion': 'Choose a different username',
                            'original_error': e.message
                        },
                        'status_code': 409
                    })
                elif 'email' in str(e.message).lower():
                    raise AdminAPIError({
                        'code': 'email_exists_error',
                        'message': 'Email already exists',
                        'details': {
                            'suggestion': 'Use a different email or recover existing account',
                            'original_error': e.message
                        },
                        'status_code': 409
                    })

            # Re-raise the original error if we can't provide better guidance
            raise

# Usage example with comprehensive error handling
if __name__ == "__main__":
    client = None

    try:
        # Initialize client
        client = AdminAPIClient("http://localhost:8081")

        # Login with TFA handling
        try:
            login_result = client.login("admin", "secure_password")
        except AdminAPIError as e:
            if e.code == 'tfa_required_error':
                # Prompt for TFA code
                import getpass
                tfa_code = getpass.getpass("Enter TFA code: ")
                login_result = client.login("admin", "secure_password", tfa_code)
            else:
                raise

        print("Login successful!")

        # Create user with detailed error handling
        try:
            new_user = client.create_user_with_handling(
                username="new_user",
                email="newuser@example.com",
                role="operator",
                full_name="New User"
            )
            print("User created:", new_user)

        except AdminAPIError as e:
            print(f"Failed to create user: {e.message}")
            if e.details.get('suggestion'):
                print(f"Suggestion: {e.details['suggestion']}")

            # Log the full error for debugging
            print(f"Full error details: {e.code} - {e.details}")

    except AdminAPIError as e:
        print(f"API Error: {e.message}")
        print(f"Error code: {e.code}")
        print(f"Status code: {e.status_code}")

        # Provide user-friendly guidance
        if e.status_code == 401:
            print("Suggestions:")
            print("- Check your username and password")
            print("- If TFA is enabled, make sure to provide the TFA code")
        elif e.status_code == 403:
            print("Suggestions:")
            print("- Check if your user role has sufficient permissions")
            print("- Contact your administrator for access")
        elif e.status_code == 429:
            print("Suggestions:")
            print("- Wait before making more requests")
            print("- Check your rate limit usage")

    except Exception as e:
        print(f"Unexpected error: {e}")

    finally:
        # Cleanup if needed
        if client:
            try:
                client.logout()
                print("Logged out successfully")
            except:
                pass
```

### Authentication Error Handling Best Practices

#### JWT Token Management

```javascript
class TokenManager {
    constructor() {
        this.token = null;
        this.refreshToken = null;
        this.tokenExpiry = null;
    }

    // Store token with expiry time
    setToken(jwtToken, refreshToken, expiresIn) {
        this.token = jwtToken;
        this.refreshToken = refreshToken;
        this.tokenExpiry = Date.now() + (expiresIn * 1000);
    }

    // Check if token is expired or will expire soon
    isTokenExpired() {
        return !this.token || Date.now() >= (this.tokenExpiry - 60000); // Refresh 1 minute before expiry
    }

    // Automatically refresh token if needed
    async ensureValidToken(apiClient) {
        if (this.isTokenExpired()) {
            try {
                const result = await apiClient.refreshAuthToken(this.refreshToken);
                this.setToken(result.jwt_token, result.refresh_token, result.expires_in);
                return true;
            } catch (error) {
                // Token refresh failed - need to re-login
                this.clearTokens();
                throw new Error('Session expired - please login again');
            }
        }
        return true;
    }

    clearTokens() {
        this.token = null;
        this.refreshToken = null;
        this.tokenExpiry = null;
    }
}
```

#### TFA Error Recovery

```python
class TFAHandler:
    @staticmethod
    async def handle_tfa_challenge(client, login_data):
        """Handle TFA challenges with retry logic"""
        max_attempts = 3
        current_attempt = 0

        while current_attempt < max_attempts:
            try:
                # First attempt without TFA code
                result = client.login(**login_data)
                return result

            except AdminAPIError as e:
                if e.code != 'tfa_required_error':
                    raise

                current_attempt += 1
                if current_attempt >= max_attempts:
                    raise AdminAPIError({
                        'code': 'tfa_attempts_exceeded',
                        'message': 'Maximum TFA attempts exceeded',
                        'status_code': 429
                    })

                print(f"TFA required. Attempt {current_attempt} of {max_attempts}")
                tfa_code = input("Enter TFA code (or 'cancel' to abort): ")

                if tfa_code.lower() == 'cancel':
                    raise AdminAPIError({
                        'code': 'tfa_cancelled',
                        'message': 'TFA entry cancelled by user',
                        'status_code': 401
                    })

                try:
                    # Retry with TFA code
                    result = client.login(**login_data, tfa_code=tfa_code)
                    return result

                except AdminAPIError as tfa_error:
                    if tfa_error.code == 'tfa_invalid_error':
                        print("Invalid TFA code. Please try again.")
                        continue
                    else:
                        raise
```

## Best Practices

### Security

1. **Use HTTPS** in production environments
2. **Rotate admin keys** regularly
3. **Limit admin API access** to trusted IP addresses
4. **Use principle of least privilege** for client API keys
5. **Never expose admin keys** in client-side code

### Key Management

1. **Use descriptive IDs** for API keys (e.g., "client-frontend-prod")
2. **Set appropriate expiration dates** for temporary access
3. **Implement reasonable rate limits** based on expected usage
4. **Regularly audit** API key usage and access patterns
5. **Disable unused keys** immediately

### Model Group Organization

1. **Group models by purpose** (production, development, experimental)
2. **Use consistent aliases** for easy model identification
3. **Document model capabilities** and access patterns
4. **Separate vision and text models** when appropriate
5. **Test model group changes** before production deployment

### Monitoring and Maintenance

1. **Monitor API key usage** for anomalies
2. **Set up alerts** for high error rates or failed authentication
3. **Regular backup** of configuration files
4. **Test backup and restore procedures**
5. **Document changes** and maintain configuration history

## Troubleshooting

### Common Issues

#### 1. Admin API Not Responding

**Symptoms:** Connection refused or timeout errors

**Solutions:**
- Verify the admin server is started: `./router -enable-admin`
- Check the correct admin port and host
- Ensure firewall allows connections to the admin port

#### 2. Authentication Failures

**Symptoms:** 401 Unauthorized responses

**Solutions:**
- Verify the admin API key is correct
- Check the API key is enabled in configuration
- Ensure the API key format is valid (starts with 'sk-')

#### 3. Model Access Denied

**Symptoms:** API key validation succeeds but model access fails

**Solutions:**
- Verify the API key has access to the required model groups
- Check the model exists in the accessible model groups
- Ensure model aliases are correctly configured

#### 4. Configuration Changes Not Applied

**Symptoms:** Changes made via API are not reflected

**Solutions:**
- Check for configuration validation errors
- Verify file permissions for the configuration file
- Ensure configuration backup is successful
- Check server logs for error messages

### Debugging

#### Enable Verbose Logging

```bash
# Run router with debug logging
DEBUG=true ./router -enable-admin -config config.json
```

#### Test API Endpoints

```bash
# Test basic connectivity
curl -v http://localhost:8081/admin/api-keys

# Test with verbose output
curl -v -H "Authorization: Bearer $ADMIN_KEY" \
     http://localhost:8081/admin/api-keys
```

#### Check Configuration

```bash
# Validate configuration file
./router -config config.json -version  # This will load and validate config

# Use test configuration for debugging
./router -config test-config.json -enable-admin
```

## Advanced Usage

### Custom Rate Limiting Configuration

Implement custom rate limiting per API key:

```json
{
  "client-api-tier": {
    "apiKey": "sk-premium-client-123456",
    "description": "Premium tier client",
    "modelGroups": ["production"],
    "enabled": true,
    "rateLimit": 1000  // 1000 requests per second
  }
}
```

### Model Versioning

Use model groups to manage model versions:

```json
{
  "anthropic-v3": {
    "description": "Anthropic Claude 3 models",
    "models": [
      {
        "provider": "anthropic",
        "model": "claude-3-5-sonnet-20241022",
        "alias": "claude-latest"
      }
    ]
  },
  "anthropic-v4": {
    "description": "Anthropic Claude 4 models (future)",
    "models": [
      {
        "provider": "anthropic",
        "model": "claude-4-sonnet-20250101",
        "alias": "claude-latest"
      }
    ]
  }
}
```

### Environment-Specific Configuration

Use different configurations per environment:

```bash
# Development
./router -config config-dev.json -enable-admin -admin-port 8081

# Staging
./router -config config-staging.json -enable-admin -admin-port 8082

# Production
./router -config config-prod.json -enable-admin -admin-host 0.0.0.0 -admin-port 8083
```

## Support and Additional Resources

- **Example Scripts**: See `examples/` directory for Bash and Python examples
- **Test Configuration**: Use `test-config.json` for testing and development
- **API Tests**: Run `go test ./internal/admin/` for comprehensive API testing
- **Issues**: Report bugs and request features via the project's issue tracker

## Version History

- **v1.0.0**: Initial release with API key and model group management
- **v1.1.0**: Added access control endpoints and usage monitoring
- **v1.2.0**: Enhanced error handling and validation
- **v1.3.0**: Added model aliases and advanced routing features

---

For additional help or questions, refer to the project documentation or contact the development team.