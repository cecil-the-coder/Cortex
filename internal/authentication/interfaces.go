package authentication

import (
	"context"
	"time"
)

// UserRepository defines user-related database operations
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, int64, error)
	GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error)
	IncrementLoginAttempts(ctx context.Context, userID int64) error
	ResetLoginAttempts(ctx context.Context, userID int64) error
	LockUser(ctx context.Context, userID int64, until time.Time) error
	UnlockUser(ctx context.Context, userID int64) error
	UpdateLastLogin(ctx context.Context, userID int64) error
}

// RoleRepository defines role-related database operations
type RoleRepository interface {
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, id int64) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id int64) error
	ListRoles(ctx context.Context) ([]*Role, error)
	AssignRoleToUser(ctx context.Context, userID, roleID int64) error
	RemoveRoleFromUser(ctx context.Context, userID int64) error
	GetUserRole(ctx context.Context, userID int64) (*Role, error)
}

// SessionRepository defines session-related database operations
type SessionRepository interface {
	CreateSession(ctx context.Context, session *UserSession) error
	GetSessionByID(ctx context.Context, id string) (*UserSession, error)
	GetSessionByToken(ctx context.Context, token string) (*UserSession, error)
	UpdateSession(ctx context.Context, session *UserSession) error
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID int64) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)
	ListUserSessions(ctx context.Context, userID int64) ([]*UserSession, error)
	UpdateSessionActivity(ctx context.Context, sessionID string) error
}

// AdminAPIKeyRepository defines admin API key operations
type AdminAPIKeyRepository interface {
	CreateAdminAPIKey(ctx context.Context, key *AdminAPIKey) error
	GetAdminAPIKeyByID(ctx context.Context, id int64) (*AdminAPIKey, error)
	GetAdminAPIKeyByKeyID(ctx context.Context, keyID string) (*AdminAPIKey, error)
	GetAdminAPIKeyByHash(ctx context.Context, keyHash string) (*AdminAPIKey, error)
	UpdateAdminAPIKey(ctx context.Context, key *AdminAPIKey) error
	DeleteAdminAPIKey(ctx context.Context, id int64) error
	ListAdminAPIKeys(ctx context.Context, filter *AdminAPIKeyFilter) ([]*AdminAPIKey, int64, error)
	IncrementAPIKeyUsage(ctx context.Context, keyID int64, ipAddress string) error
	RevokeAdminAPIKey(ctx context.Context, id int64) error
}

// AuditRepository defines audit-related database operations
type AuditRepository interface {
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogByID(ctx context.Context, id int64) (*AuditLog, error)
	ListAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, int64, error)
	GetUserAuditLogs(ctx context.Context, userID int64, filter *AuditFilter) ([]*AuditLog, int64, error)
	GetResourceAuditLogs(ctx context.Context, resource, resourceID string, filter *AuditFilter) ([]*AuditLog, int64, error)
	DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
	ExportAuditLogs(ctx context.Context, filter *AuditFilter) ([]byte, error)
}

// SecurityRepository defines security-related database operations
type SecurityRepository interface {
	CreateFailedLogin(ctx context.Context, login *FailedLogin) error
	GetFailedLoginCount(ctx context.Context, ipAddress, username string, since time.Time) (int64, error)
	CleanupFailedLogins(ctx context.Context, olderThan time.Time) (int64, error)
	CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	GetSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, int64, error)
	ResolveSecurityEvent(ctx context.Context, eventID int64, resolvedBy int64) error
	GetLoginAttempts(ctx context.Context, filter *LoginAttemptFilter) ([]*LoginAttempt, int64, error)
	CreateLoginAttempt(ctx context.Context, attempt *LoginAttempt) error
}

// PasswordResetRepository defines password reset operations
type PasswordResetRepository interface {
	CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	GetPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	InvalidatePasswordResetToken(ctx context.Context, tokenID int64) error
	InvalidateUserPasswordResetTokens(ctx context.Context, userID int64) error
	CleanupExpiredTokens(ctx context.Context) (int64, error)
}

// AuthenticationManager defines core authentication operations
type AuthenticationManager interface {
	// User authentication
	AuthenticateUser(ctx context.Context, username, password, ipAddress, userAgent string) (*User, *UserSession, error)
	AuthenticateUserWithTFB(ctx context.Context, username, password, tfaCode, ipAddress, userAgent string) (*User, *UserSession, error)
	ValidateSession(ctx context.Context, sessionToken string) (*User, *UserSession, error)
	RefreshSession(ctx context.Context, refreshToken string) (*UserSession, error)
	LogoutUser(ctx context.Context, sessionToken string) error
	LogoutAllUserSessions(ctx context.Context, userID int64) error

	// Password management
	HashPassword(password string) (string, error)
	ValidatePassword(hash, password string) bool
	GeneratePasswordResetToken(ctx context.Context, userID int64) (string, error)
	ValidatePasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error)
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error

	// TFA management
	GenerateTFASecret(userID int64) (string, string, error)
	EnableTFA(ctx context.Context, userID int64, secret string) error
	DisableTFA(ctx context.Context, userID int64) error
	ValidateTFA(userID int64, code string) bool

	// API key management
	GenerateAdminAPIKey(ctx context.Context, key *AdminAPIKey) (string, error)
	ValidateAdminAPIKey(ctx context.Context, apiKey string) (*AdminAPIKey, error)
	RevokeAdminAPIKey(ctx context.Context, keyID int64) error

	// Authorization
	HasPermission(user *User, permission string) bool
	HasAnyPermission(user *User, permissions []string) bool
	HasAllPermissions(user *User, permissions []string) bool

	// Rate limiting
	CheckRateLimit(ctx context.Context, identifier, endpoint string) (bool, time.Duration, error)
	ResetRateLimit(ctx context.Context, identifier, endpoint string) error

	// User management
	CreateUser(ctx context.Context, user *User, password string) error
	GetUserByID(ctx context.Context, id int64) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*User, int64, error)

	// Security
	DetectSuspiciousActivity(ctx context.Context, ipAddress, userAgent string) ([]*SecurityEvent, error)
	LockAccount(ctx context.Context, userID int64, reason string, duration time.Duration) error
	UnlockAccount(ctx context.Context, userID int64) error
}

// TokenManager defines token generation and validation
type TokenManager interface {
	GenerateSessionToken(userID int64) (string, string, time.Time, error)
	ValidateSessionToken(token string) (*SessionClaims, error)
	GenerateRefreshToken(userID int64) (string, time.Time, error)
	ValidateRefreshToken(token string) (*RefreshClaims, error)
	GenerateAdminAPIKey(userID *int64, permissions []string) (string, error)
	InvalidateToken(token string) error
	InvalidateUserTokens(userID int64) error
}

// SessionClaims contains JWT session token claims
type SessionClaims struct {
	UserID    int64    `json:"user_id"`
	RoleID    int64    `json:"role_id"`
	SessionID string   `json:"session_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	Permissions []string `json:"permissions"`
	TokenType string   `json:"token_type"` // "session"
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
}

// RefreshClaims contains JWT refresh token claims
type RefreshClaims struct {
	UserID    int64  `json:"user_id"`
	SessionID string `json:"session_id"`
	TokenType string `json:"token_type"` // "refresh"
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

// AuditLogger defines audit logging operations
type AuditLogger interface {
	LogUserAction(ctx context.Context, userID int64, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error
	LogAPIKeyAction(ctx context.Context, apiKeyID int64, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error
	LogSystemAction(ctx context.Context, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error
	LogLoginAttempt(ctx context.Context, username, ipAddress, userAgent string, success bool, reason string, userID *int64) error
	LogSecurityEvent(ctx context.Context, event *SecurityEvent) error
}

// RateLimiter defines rate limiting interface
type RateLimiter interface {
	Allow(identifier, endpoint string) (bool, time.Duration)
	Limit(identifier, endpoint string) (int, time.Duration)
	Reset(identifier, endpoint string)
	Burst(identifier, endpoint string) int
	SetConfig(endpoint string, config *RateLimitConfig)
	GetConfig(endpoint string) (*RateLimitConfig, bool)
}

// SecurityMonitor defines security monitoring interface
type SecurityMonitor interface {
	MonitorLoginAttempt(ctx context.Context, attempt *LoginAttempt) error
	MonitorAPIAccess(ctx context.Context, userID *int64, apiKeyID *int64, ipAddress, userAgent, endpoint string) error
	DetectBruteForce(ctx context.Context, ipAddress, username string) (bool, error)
	DetectSuspiciousPattern(ctx context.Context, userID int64, actions []*AuditLog) error
	CreateSecurityAlert(ctx context.Context, alert *SecurityEvent) error
}

// Configuration interface
type AuthenticationConfig interface {
	GetJWTSecret() []byte
	GetJWTSessionExpiry() time.Duration
	GetJWTRefreshExpiry() time.Duration
	GetPasswordPolicy() *PasswordPolicy
	GetTFAIssuer() string
	GetRateLimitConfig() map[string]*RateLimitConfig
	GetSecurityConfig() *SecurityConfig
	GetAdminAPIKeyPrefix() string
	GetMaxLoginAttempts() int
	GetAccountLockoutDuration() time.Duration
	GetSessionTimeout() time.Duration
	GetPasswordResetExpiry() time.Duration
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireNumber  bool `json:"require_number"`
	RequireSpecial bool `json:"require_special"`
	MinSpecial     int  `json:"min_special"`
	MaxAge         time.Duration `json:"max_age"`
	HistoryCount   int  `json:"history_count"`
	DisallowCommon bool `json:"disallow_common"`
}

// SecurityConfig defines security settings
type SecurityConfig struct {
	SessionTimeout           time.Duration `json:"session_timeout"`
	MaxConcurrentSessions    int           `json:"max_concurrent_sessions"`
	RequireHTTPS             bool          `json:"require_https"`
	StrictTransportSecurity  bool          `json:"strict_transport_security"`
	FrameOptions             string        `json:"frame_options"`
	ContentSecurityPolicy    string        `json:"content_security_policy"`
	EnableAPIKeyRotation     bool          `json:"enable_api_key_rotation"`
	APIKeyRotationPeriod     time.Duration `json:"api_key_rotation_period"`
	EnableIPWhitelist        bool          `json:"enable_ip_whitelist"`
	IPWhitelist              []string      `json:"ip_whitelist"`
	EnableIPBlacklist        bool          `json:"enable_ip_blacklist"`
	IPBlacklist              []string      `json:"ip_blacklist"`
	MaxFailedLoginsPerIP     int           `json:"max_failed_logins_per_ip"`
	MaxFailedLoginsPerUser   int           `json:"max_failed_logins_per_user"`
	FailedLoginWindow        time.Duration `json:"failed_login_window"`
	LogLevel                 string        `json:"log_level"`
}

// Filter types for database queries

// UserFilter filters user queries
type UserFilter struct {
	Username   string
	Email      string
	RoleID     *int64
	Enabled    *bool
	TFAEnabled *bool
	Locked     *bool
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Limit      int
	Offset     int
	SortBy     string
	SortDesc   bool
}

// AdminAPIKeyFilter filters admin API key queries
type AdminAPIKeyFilter struct {
	KeyID       string
	Name        string
	UserID      *int64
	Enabled     *bool
	ExpiresFrom *time.Time
	ExpiresTo   *time.Time
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Limit       int
	Offset      int
	SortBy      string
	SortDesc    bool
}

// AuditFilter filters audit log queries
type AuditFilter struct {
	UserID      *int64
	APIKeyID    *int64
	SessionID   string
	Action      string
	Resource    string
	ResourceID  string
	IPAddress   string
	Success     *bool
	DateFrom    *time.Time
	DateTo      *time.Time
	Limit       int
	Offset      int
	SortBy      string
	SortDesc    bool
}

// SecurityEventFilter filters security event queries
type SecurityEventFilter struct {
	Type      string
	Severity  string
	Resolved  *bool
	DateFrom  *time.Time
	DateTo    *time.Time
	UserID    *int64
	Limit     int
	Offset    int
	SortBy    string
	SortDesc  bool
}

// LoginAttemptFilter filters login attempt queries
type LoginAttemptFilter struct {
	Username   string
	IPAddress  string
	Success    *bool
	DateFrom   *time.Time
	DateTo     *time.Time
	UserID     *int64
	Limit      int
	Offset     int
	SortBy     string
	SortDesc   bool
}