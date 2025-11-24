package authentication

import (
	"time"
)

// User represents an admin user in the system
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	FullName     string     `json:"full_name"`
	RoleID       int64      `json:"role_id"`
	Role         *Role      `json:"role,omitempty"` // Populated when loaded from database
	Enabled      bool       `json:"enabled"`
	TFAEnabled   bool       `json:"tfa_enabled"`
	TFASecret    string     `json:"-"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	LoginAttempts int        `json:"login_attempts"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Role represents a user role with permissions
type Role struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Permissions []string    `json:"permissions"`
	SystemRole  bool        `json:"system_role"` // Cannot be deleted
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// UserSession represents a user session
type UserSession struct {
	ID           string     `json:"id"`
	UserID       int64      `json:"user_id"`
	SessionToken string     `json:"-"` // Hashed token
	RefreshToken string     `json:"-"` // Hashed refresh token
	IPAddress    string     `json:"ip_address"`
	UserAgent    string     `json:"user_agent"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastActivity time.Time  `json:"last_activity"`
	Active       bool       `json:"active"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AdminAPIKey represents an admin API key
type AdminAPIKey struct {
	ID          int64       `json:"id"`
	KeyID       string      `json:"key_id"`
	KeyHash     string      `json:"-"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	UserID      *int64      `json:"user_id,omitempty"` // Optional user association
	Permissions []string    `json:"permissions"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	LastUsed    *time.Time  `json:"last_used,omitempty"`
	UsageCount  int64       `json:"usage_count"`
	Enabled     bool        `json:"enabled"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID          int64                  `json:"id"`
	UserID      *int64                 `json:"user_id,omitempty"`
	APIKeyID    *int64                 `json:"api_key_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	ResourceID  string                 `json:"resource_id,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	Success     bool                   `json:"success"`
	ErrorMessage string                `json:"error_message,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// PasswordResetToken represents a password reset token
type PasswordResetToken struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"created_at"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Endpoint string        `json:"endpoint"`
	Limit    int           `json:"limit"`    // Requests per window
	Window   time.Duration `json:"window"`   // Time window
	Burst    int           `json:"burst"`    // Burst size
}

// FailedLogin represents a failed login attempt
type FailedLogin struct {
	ID        int64     `json:"id"`
	IPAddress string    `json:"ip_address"`
	Username  string    `json:"username"`
	Reason    string    `json:"reason"` // "invalid_credentials", "account_locked", "tfa_required"
	Timestamp time.Time `json:"timestamp"`
}

// LoginAttempt represents a login attempt (successful or failed)
type LoginAttempt struct {
	ID        int64      `json:"id"`
	Username  string     `json:"username"`
	IPAddress string     `json:"ip_address"`
	UserAgent string     `json:"user_agent"`
	Success   bool       `json:"success"`
	Reason    string     `json:"reason,omitempty"`
	UserID    *int64     `json:"user_id,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          int64                  `json:"id"`
	Type        string                 `json:"type"` // "brute_force", "suspicious_activity", "privilege_escalation"
	Severity    string                 `json:"severity"` // "low", "medium", "high", "critical"
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	UserID      *int64                 `json:"user_id,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy  *int64                 `json:"resolved_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Predefined roles and permissions
const (
	// Role names
	RoleSuperAdmin    = "super_admin"
	RoleProviderAdmin = "provider_admin"
	RoleConfigEditor  = "config_editor"
	RoleReader        = "reader"
	RoleAuditor       = "auditor"

	// Permissions
	// System permissions
	PermSystemRead     = "system:read"
	PermSystemWrite    = "system:write"
	PermSystemAdmin    = "system:admin"

	// Provider permissions
	PermProviderRead   = "provider:read"
	PermProviderWrite  = "provider:write"
	PermProviderDelete = "provider:delete"

	// Model permissions
	PermModelRead      = "model:read"
	PermModelWrite     = "model:write"
	PermModelDelete    = "model:delete"

	// Configuration permissions
	PermConfigRead     = "config:read"
	PermConfigWrite    = "config:write"

	// User management permissions
	PermUserRead       = "user:read"
	PermUserWrite      = "user:write"
	PermUserDelete     = "user:delete"

	// API key permissions
	PermAPIKeyRead     = "apikey:read"
	PermAPIKeyWrite    = "apikey:write"
	PermAPIKeyDelete   = "apikey:delete"

	// Monitoring permissions
	PermMonitoringRead = "monitoring:read"
	PermMetricsRead    = "metrics:read"

	// Audit permissions
	PermAuditRead      = "audit:read"
	PermAuditExport    = "audit:export"

	// Health permissions
	PermHealthRead     = "health:read"
)

// DefaultRoles returns the default system roles
func DefaultRoles() []*Role {
	return []*Role{
		{
			Name:        RoleSuperAdmin,
			Description: "Super administrator with full system access",
			Permissions: []string{
				PermSystemAdmin,
				PermSystemWrite,
				PermSystemRead,
				PermProviderWrite,
				PermProviderRead,
				PermProviderDelete,
				PermModelWrite,
				PermModelRead,
				PermModelDelete,
				PermConfigWrite,
				PermConfigRead,
				PermUserWrite,
				PermUserRead,
				PermUserDelete,
				PermAPIKeyWrite,
				PermAPIKeyRead,
				PermAPIKeyDelete,
				PermMonitoringRead,
				PermMetricsRead,
				PermAuditRead,
				PermAuditExport,
				PermHealthRead,
			},
			SystemRole: true,
		},
		{
			Name:        RoleProviderAdmin,
			Description: "Provider administrator - can manage providers and models",
			Permissions: []string{
				PermProviderWrite,
				PermProviderRead,
				PermProviderDelete,
				PermModelWrite,
				PermModelRead,
				PermModelDelete,
				PermHealthRead,
				PermMonitoringRead,
				PermMetricsRead,
			},
			SystemRole: true,
		},
		{
			Name:        RoleConfigEditor,
			Description: "Configuration editor - can edit system configuration",
			Permissions: []string{
				PermConfigWrite,
				PermConfigRead,
				PermProviderWrite,
				PermProviderRead,
				PermModelWrite,
				PermModelRead,
				PermAPIKeyWrite,
				PermAPIKeyRead,
				PermMonitoringRead,
				PermMetricsRead,
				PermHealthRead,
			},
			SystemRole: true,
		},
		{
			Name:        RoleReader,
			Description: "Read-only access to system information and metrics",
			Permissions: []string{
				PermSystemRead,
				PermProviderRead,
				PermModelRead,
				PermConfigRead,
				PermMonitoringRead,
				PermMetricsRead,
				PermHealthRead,
			},
			SystemRole: true,
		},
		{
			Name:        RoleAuditor,
			Description: "Auditor - access to logs and audit trail",
			Permissions: []string{
				PermAuditRead,
				PermAuditExport,
				PermSystemRead,
				PermUserRead,
				PermAPIKeyRead,
				PermMonitoringRead,
				PermMetricsRead,
				PermHealthRead,
			},
			SystemRole: true,
		},
	}
}

// UserStatus represents user status
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
	UserStatusExpired  UserStatus = "expired"
)

// SessionStatus represents session status
type SessionStatus string

const (
	SessionStatusActive    SessionStatus = "active"
	SessionStatusExpired   SessionStatus = "expired"
	SessionStatusRevoked   SessionStatus = "revoked"
	SessionStatusSuspended SessionStatus = "suspended"
)

// APIKeyStatus represents API key status
type APIKeyStatus string

const (
	APIKeyStatusActive   APIKeyStatus = "active"
	APIKeyStatusInactive APIKeyStatus = "inactive"
	APIKeyStatusExpired  APIKeyStatus = "expired"
	APIKeyStatusRevoked  APIKeyStatus = "revoked"
)