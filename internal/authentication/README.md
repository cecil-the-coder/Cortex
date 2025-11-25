# Authentication System for Cortex

This package provides a comprehensive enterprise-grade authentication system for the Cortex admin API, supporting multiple authentication methods,
role-based access control (RBAC), security features, and audit logging.

## Features

### Authentication Methods
- **JWT Sessions**: Token-based authentication for web interface
- **Admin API Keys**: Similar to existing client API keys but for admin operations
- **Password-based**: Traditional username/password authentication
- **Two-Factor Authentication (2FA)**: TOTP, SMS, and email-based 2FA

### Security Features
- **Role-Based Access Control (RBAC)**: 5 predefined roles with granular permissions
- **Rate Limiting**: Configurable per-endpoint rate limits with burst handling
- **Audit Logging**: Comprehensive audit trail for all admin actions
- **Security Monitoring**: Brute force detection, suspicious activity monitoring
- **Password Security**: Strong password policies with bcrypt hashing
- **Session Management**: Secure session handling with automatic cleanup
- **IP Allowlisting/Blocklisting**: Network-level access control
- **Security Headers**: HSTS, XSS protection, CSRF protection

### Predefined Roles

1. **Super Admin**: Full system access including user management
2. **Provider Admin**: Manage providers, models, and health monitoring
3. **Config Editor**: Edit configuration and model groups
4. **Reader**: Read-only access to metrics and status
5. **Auditor**: Access to logs and audit trail

## Architecture

### Core Components

- **Models**: Database entities (User, Role, Session, APIKey, AuditLog)
- **Interfaces**: Repository and service interfaces
- **Repository**: Database access layer (supports SQLite and MySQL)
- **Manager**: Core authentication logic
- **RBAC**: Role-based access control
- **Middleware**: HTTP middleware for authentication and authorization
- **Security**: Password management, rate limiting, TFA
- **Handlers**: HTTP handlers for admin endpoints

### Database Schema

The authentication system uses the following main tables:

- `auth_users`: User accounts and credentials
- `auth_roles`: Role definitions with permissions
- `auth_user_sessions`: User session management
- `auth_admin_api_keys`: Admin API key management
- `auth_audit_logs`: Audit trail of all actions
- `auth_security_events`: Security-related events
- `auth_tfa_*`: Two-factor authentication data

## Configuration

### Basic Configuration

```go
import "Cortex/internal/authentication"

config := &authentication.AuthenticationConfigSection{
    Enabled: true,
    Methods: []string{"jwt", "password", "api_key"},
    JWT: &authentication.JWTConfig{
        SessionExpiry:      30 * time.Minute,
        RefreshExpiry:      7 * 24 * time.Hour,
        AdminAPIKeyPrefix:  "sk-admin-",
    },
    PasswordPolicy: &authentication.PasswordPolicy{
        MinLength:      12,
        RequireUpper:   true,
        RequireLower:   true,
        RequireNumber:  true,
        RequireSpecial: true,
        DisallowCommon: true,
    },
    Security: &authentication.SecurityConfig{
        SessionTimeout:           30 * time.Minute,
        MaxFailedLoginsPerIP:     10,
        MaxFailedLoginsPerUser:   5,
        FailedLoginWindow:        15 * time.Minute,
        RequireHTTPS:             true,
        StrictTransportSecurity:  true,
    },
    TFA: &authentication.TFAConfig{
        Enabled:     true,
        Methods:     []string{"totp"},
        RequiredFor: []string{"admin"},
    },
}
```

### Environment Variables

```bash
# JWT Configuration
export JWT_SECRET="your-super-secret-jwt-key-change-in-production"
export JWT_SESSION_EXPIRY="30m"
export JWT_REFRESH_EXPIRY="168h"  # 7 days

# Security
export REQUIRE_HTTPS="true"
export ADMIN_API_KEY_PREFIX="sk-admin-"

# Password Policy
export PASSWORD_MIN_LENGTH="12"
export PASSWORD_MAX_AGE="2160h"  # 90 days

# Rate Limiting
export LOGIN_RATE_LIMIT="5/15m"
export ADMIN_API_RATE_LIMIT="1000/h"
```

## Integration

### 1. Initialize Authentication System

```go
package main

import (
    "Cortex/internal/authentication"
    "Cortex/internal/database"
)

func setupAuthentication(db database.Database) (*authentication.DefaultAuthenticationManager, error) {
    // Create repositories
    userRepo := authentication.NewUserRepository(db)
    roleRepo := authentication.NewRoleRepository(db)
    sessionRepo := authentication.NewSessionRepository(db)
    adminAPIKeyRepo := authentication.NewAdminAPIKeyRepository(db)
    auditRepo := authentication.NewAuditRepository(db)
    securityRepo := authentication.NewSecurityRepository(db)
    passwordResetRepo := authentication.NewPasswordResetRepository(db)

    // Create services
    tokenManager := authentication.NewJWTTokenManager(config)
    rbacManager := authentication.NewRBACManager(roleRepo, userRepo, auditLogger)
    tfaManager := authentication.NewTFAManager("Cortex", 2*time.Minute)
    passwordManager := authentication.NewPasswordManager(config.GetPasswordPolicy())
    rateLimiter := authentication.NewInMemoryRateLimiter()
    securityMonitor := authentication.NewSecurityMonitor(securityRepo, auditLogger, config.GetSecurityConfig())
    auditLogger := authentication.NewDefaultAuditLogger(auditRepo)

    // Create authentication manager
    authManager := authentication.NewDefaultAuthenticationManager(
        userRepo, roleRepo, sessionRepo, adminAPIKeyRepo,
        auditRepo, securityRepo, passwordResetRepo,
        tokenManager, rbacManager, tfaManager, passwordManager,
        rateLimiter, securityMonitor, auditLogger, config,
    )

    // Run migrations
    migrationRunner := authentication.NewMigrationRunner(db.GetDB())
    if err := migrationRunner.RunMigrations(context.Background(), "sqlite"); err != nil {
        return nil, fmt.Errorf("migration failed: %w", err)
    }

    return authManager, nil
}
```

### 2. Setup Middleware

```go
func setupMiddleware(authManager *authentication.DefaultAuthenticationManager) (func(http.Handler) http.Handler, func(http.Handler) http.Handler) {
    // Create authentication middleware
    authMiddleware := authentication.NewAuthMiddleware(
        authManager,
        authManager.GetTokenManager(),
        authManager.GetAuditLogger(),
        authManager.GetRateLimiter(),
    )

    // Create middleware chain
    jwtAuth := authMiddleware.JWTAuthMiddleware
    apiKeyAuth := authMiddleware.AdminAPIKeyAuthMiddleware
    securityHeaders := authMiddleware.SecurityHeadersMiddleware(config.GetSecurityConfig())

    // Combine middleware for different auth methods
    adminAuth := func(next http.Handler) http.Handler {
        return jwtAuth(apiKeyAuth(securityHeaders(next)))
    }

    // Role-based middleware
    requireAdmin := authMiddleware.RoleBasedAuthMiddleware([]string{
        authentication.PermSystemAdmin,
    })

    return adminAuth, requireAdmin
}
```

### 3. Setup HTTP Handlers

```go
func setupRoutes(authManager *authentication.DefaultAuthenticationManager, adminAuth, requireAdmin func(http.Handler) http.Handler) http.Handler {
    router := mux.NewRouter()

    // Authentication handlers
    authHandlers := authentication.NewAdminAuthHandlers(
        authManager,
        authManager.GetRBACManager(),
        authManager.GetAuditLogger(),
        config,
    )

    // Public routes
    router.HandleFunc("/v1/auth/login", authHandlers.handleLogin).Methods("POST")
    router.HandleFunc("/v1/auth/refresh", authHandlers.handleRefreshToken).Methods("POST")

    // Protected routes
    protected := router.PathPrefix("/v1/admin").Subrouter()
    protected.Use(adminAuth)

    // User management
    protected.HandleFunc("/users", authHandlers.handleListUsers).Methods("GET")
    protected.HandleFunc("/users", authHandlers.handleCreateUser).Methods("POST")
    protected.HandleFunc("/users/{id}", authHandlers.handleGetUser).Methods("GET")
    protected.HandleFunc("/users/{id}", authHandlers.handleUpdateUser).Methods("PUT")
    protected.HandleFunc("/users/{id}", authHandlers.handleDeleteUser).Methods("DELETE")

    // Current user
    protected.HandleFunc("/me", authHandlers.handleMe).Methods("GET")
    protected.HandleFunc("/logout", authHandlers.handleLogout).Methods("POST")

    // Password management
    protected.HandleFunc("/password/change", authHandlers.handleChangePassword).Methods("POST")

    // TFA
    protected.HandleFunc("/tfa/setup", authHandlers.handleSetupTFA).Methods("POST")
    protected.HandleFunc("/tfa/enable", authHandlers.handleEnableTFA).Methods("POST")
    protected.HandleFunc("/tfa/disable", authHandlers.handleDisableTFA).Methods("POST")

    // Admin-only routes
    adminOnly := router.PathPrefix("/v1/admin").Subrouter()
    adminOnly.Use(requireAdmin)

    adminOnly.HandleFunc("/roles", authHandlers.handleListRoles).Methods("GET")
    adminOnly.HandleFunc("/roles", authHandlers.handleCreateRole).Methods("POST")

    return router
}
```

## API Endpoints

### Authentication

#### POST /v1/auth/login
Login with username and password.

```json
{
    "username": "admin",
    "password": "password123",
    "tfa_code": "123456",  // Optional if TFA enabled
    "remember": false
}
```

Response:
```json
{
    "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "full_name": "Administrator",
        "role": {
            "id": 1,
            "name": "super_admin",
            "permissions": ["system:*", "user:write", ...]
        },
        "enabled": true,
        "tfa_enabled": false,
        "last_login": "2024-01-01T12:00:00Z"
    },
    "session_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": "2024-01-01T12:30:00Z",
    "permissions": ["system:*", "user:write", ...]
}
```

#### POST /v1/auth/refresh
Refresh session token.

#### POST /v1/auth/logout
Logout current session.

#### GET /v1/me
Get current user information.

### User Management

#### GET /v1/admin/users
List users with filtering and pagination.

Query parameters:
- `username`: Filter by username
- `email`: Filter by email
- `enabled`: Filter by enabled status
- `tfa_enabled`: Filter by TFA status
- `limit`: Pagination limit (default: 50)
- `offset`: Pagination offset
- `sort`: Sort field
- `order`: Sort order (asc/desc)

#### POST /v1/admin/users
Create new user.

```json
{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "StrongP@ssw0rd!",
    "full_name": "New User",
    "role_id": 2,
    "enabled": true,
    "tfa_enabled": false
}
```

#### PUT /v1/admin/users/{id}
Update user.

#### DELETE /v1/admin/users/{id}
Delete user.

#### POST /v1/admin/password/change
Change password.

### TFA Management

#### POST /v1/admin/tfa/setup
Setup two-factor authentication.

Response:
```json
{
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANS...",
    "backup_codes": ["ABCD-1234", "EFGH-5678", ...],
    "method": "totp",
    "enabled": false
}
```

#### POST /v1/admin/tfa/enable
Enable TFA with verification code.

#### POST /v1/admin/tfa/disable
Disable TFA.

## Security Best Practices

### 1. Environment Configuration
- Use environment variables for sensitive configuration
- Rotate JWT secrets regularly
- Use strong, randomly generated secrets
- Enable HTTPS in production

### 2. Password Policy
- Enforce minimum length (12+ characters)
- Require complexity (uppercase, lowercase, numbers, special chars)
- Implement password history
- Set maximum password age

### 3. Session Management
- Use appropriate session timeouts
- Implement session invalidation on logout
- Limit concurrent sessions per user
- Store session data securely

### 4. Rate Limiting
- Implement per-IP rate limiting for login attempts
- Use burst control for legitimate traffic
- Implement account lockout after failed attempts
- Monitor and alert on suspicious patterns

### 5. Audit Logging
- Log all authentication attempts
- Log privileged operations
- Include IP addresses and user agents
- Retain logs for compliance period

### 6. Two-Factor Authentication
- Require for admin accounts
- Use TOTP for primary method
- Provide backup codes
- Validate backup codes properly

## Monitoring and Troubleshooting

### Health Check

Add authentication health to existing health checks:

```go
func checkAuthenticationHealth() error {
    if authManager == nil {
        return fmt.Errorf("authentication manager not initialized")
    }

    // Test database connectivity
    if err := db.Ping(); err != nil {
        return fmt.Errorf("database connectivity issue: %w", err)
    }

    // Check rate limiter
    if rateLimiter == nil {
        return fmt.Errorf("rate limiter not initialized")
    }

    return nil
}
```

### Metrics

The authentication system automatically generates metrics for:
- Login success/failure rates
- API key usage
- Session creation/expiration
- Rate limiting triggers
- Security events

### Troubleshooting

Common issues and solutions:

1. **Login failures due to rate limiting**
   - Check IP-based rate limits
   - Verify rate limit configuration
   - Consider adjusting limits for legitimate traffic

2. **API key authentication failures**
   - Verify API key format and prefix
   - Check if key is enabled and not expired
   - Review permissions for the requested endpoint

3. **TFA setup issues**
   - Verify system time synchronization
   - Check QR code generation
   - Validate TOTP algorithm configuration

## Security Considerations

### Threat Model

The authentication system protects against:
- Brute force attacks (rate limiting, account lockout)
- Session hijacking (secure tokens, HTTPS)
- Password attacks (strong hashing, complexity requirements)
- Privilege escalation (RBAC, audit logging)
- Replay attacks (token expiration, unique tokens)

### Compliance

The system supports compliance requirements for:
- **SOX**: Audit trails, access controls
- **PCI-DSS**: Strong cryptography, access controls
- **GDPR**: Data protection, audit logs
- **HIPAA**: Audit trails, access controls

### Data Protection

- Passwords are hashed with bcrypt
- API keys are hashed before storage
- Sensitive audit data is logged appropriately
- Personal data access is controlled by RBAC

## Contributing

When modifying the authentication system:
1. Add comprehensive tests for new features
2. Update documentation for API changes
3. Consider security implications
4. Test role-based access controls
5. Verify audit logging functionality

## License

This authentication system is part of the Cortex project and follows the same licensing terms.