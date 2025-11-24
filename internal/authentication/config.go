package authentication

import (
	"encoding/json"
	"fmt"
	"time"
)

// AuthenticationConfigSection contains authentication configuration
type AuthenticationConfigSection struct {
	Enabled           bool                     `json:"enabled"`
	Methods           []string                 `json:"methods"`           // "jwt", "password", "api_key", "oauth"
	JWT               *JWTConfig               `json:"jwt,omitempty"`
	PasswordPolicy    *PasswordPolicy          `json:"password_policy,omitempty"`
	Security         *SecurityConfig          `json:"security,omitempty"`
	SessionConfig    *SessionConfig           `json:"session_config,omitempty"`
	RateLimits       map[string]*RateLimitConfig `json:"rate_limits,omitempty"`
	AdminAPIKeys     *AdminAPIKeysConfig      `json:"admin_api_keys,omitempty"`
	TFA              *TFAConfig               `json:"tfa,omitempty"`
	Audit            *AuditConfig             `json:"audit,omitempty"`
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret             string        `json:"secret"`
	SessionExpiry      time.Duration `json:"session_expiry"`
	RefreshExpiry      time.Duration `json:"refresh_expiry"`
	Issuer             string        `json:"issuer"`
	AdminAPIKeyPrefix  string        `json:"admin_api_key_prefix"`
	TokenRotationEnabled bool        `json:"token_rotation_enabled"`
}

// SessionConfig contains session configuration
type SessionConfig struct {
	Timeout             time.Duration `json:"timeout"`
	MaxConcurrent       int           `json:"max_concurrent"`
	IdleTimeout         time.Duration `json:"idle_timeout"`
	RememberMeDuration  time.Duration `json:"remember_me_duration"`
	InvalidateOnLogout  bool          `json:"invalidate_on_logout"`
}

// AdminAPIKeysConfig contains admin API key configuration
type AdminAPIKeysConfig struct {
	DefaultExpiry     time.Duration `json:"default_expiry"`
	MaxExpiry         time.Duration `json:"max_expiry"`
	AutoRotate        bool          `json:"auto_rotate"`
	RotationPeriod    time.Duration `json:"rotation_period"`
	Prefix           string        `json:"prefix"`
}

// TFAConfig contains two-factor authentication configuration
type TFAConfig struct {
	Enabled       bool          `json:"enabled"`
	Methods       []string      `json:"methods"`       // "totp", "sms", "email"
	Issuer        string        `json:"issuer"`
	TOTPWindow    time.Duration `json:"totp_window"`
	BackupCodes   int           `json:"backup_codes"`
	RequiredFor   []string      `json:"required_for"` // "admin", "all"
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Enabled         bool          `json:"enabled"`
	LogLevel        string        `json:"log_level"`
	RetentionPeriod time.Duration `json:"retention_period"`
	CompressAfter   time.Duration `json:"compress_after"`
	LogAPIKeys      bool          `json:"log_api_keys"`
	LogPasswords    bool          `json:"log_passwords"`
}

// DefaultAuthenticationConfig returns default authentication configuration
func DefaultAuthenticationConfig() *AuthenticationConfigSection {
	return &AuthenticationConfigSection{
		Enabled:    true,
		Methods:    []string{"jwt", "password", "api_key"},
		JWT: &JWTConfig{
			SessionExpiry:       30 * time.Minute,
			RefreshExpiry:       7 * 24 * time.Hour, // 7 days
			Issuer:              "Cortex",
			AdminAPIKeyPrefix:   "sk-admin-",
			TokenRotationEnabled: false,
		},
		PasswordPolicy: &PasswordPolicy{
			MinLength:      12,
			RequireUpper:   true,
			RequireLower:   true,
			RequireNumber:  true,
			RequireSpecial: true,
			MinSpecial:     1,
			MaxAge:         90 * 24 * time.Hour, // 90 days
			HistoryCount:   5,
			DisallowCommon: true,
		},
		Security: &SecurityConfig{
			SessionTimeout:           30 * time.Minute,
			MaxConcurrentSessions:    5,
			RequireHTTPS:             true,
			StrictTransportSecurity:  true,
			FrameOptions:             "DENY",
			ContentSecurityPolicy:    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
			EnableAPIKeyRotation:     false,
			APIKeyRotationPeriod:     30 * 24 * time.Hour, // 30 days
			EnableIPWhitelist:        false,
			IPBlacklist:              []string{},
			MaxFailedLoginsPerIP:     10,
			MaxFailedLoginsPerUser:   5,
			FailedLoginWindow:        15 * time.Minute,
			LogLevel:                 "info",
		},
		SessionConfig: &SessionConfig{
			Timeout:            30 * time.Minute,
			MaxConcurrent:      5,
			IdleTimeout:        15 * time.Minute,
			RememberMeDuration: 7 * 24 * time.Hour, // 7 days
			InvalidateOnLogout: true,
		},
		AdminAPIKeys: &AdminAPIKeysConfig{
			DefaultExpiry:   30 * 24 * time.Hour, // 30 days
			MaxExpiry:       365 * 24 * time.Hour, // 1 year
			AutoRotate:      false,
			RotationPeriod:  30 * 24 * time.Hour, // 30 days
			Prefix:          "sk-admin-",
		},
		TFA: &TFAConfig{
			Enabled:     false,
			Methods:     []string{"totp"},
			Issuer:      "Cortex",
			TOTPWindow:  time.Minute * 2,
			BackupCodes: 10,
			RequiredFor: []string{"admin"},
		},
		Audit: &AuditConfig{
			Enabled:         true,
			LogLevel:        "info",
			RetentionPeriod: 365 * 24 * time.Hour, // 1 year
			CompressAfter:   30 * 24 * time.Hour,  // 30 days
			LogAPIKeys:      false,
			LogPasswords:    false,
		},
		RateLimits: map[string]*RateLimitConfig{
			"login": {
				Limit:  5,
				Window: 15 * time.Minute,
				Burst:  3,
			},
			"password_reset": {
				Limit:  3,
				Window: time.Hour,
				Burst:  2,
			},
			"admin_api": {
				Limit:  1000,
				Window: time.Hour,
				Burst:  50,
			},
			"config_write": {
				Limit:  10,
				Window: time.Hour,
				Burst:  5,
			},
		},
	}
}

// ConfigAuthenticationAdapter adapts authentication config to work with existing config system
type ConfigAuthenticationAdapter struct {
	config *AuthenticationConfigSection
}

// NewConfigAuthenticationAdapter creates a new authentication config adapter
func NewConfigAuthenticationAdapter(config *AuthenticationConfigSection) *ConfigAuthenticationAdapter {
	if config == nil {
		config = DefaultAuthenticationConfig()
	}
	return &ConfigAuthenticationAdapter{config: config}
}

// GetJWTSecret returns JWT secret
func (c *ConfigAuthenticationAdapter) GetJWTSecret() []byte {
	if c.config.JWT.Secret != "" {
		return []byte(c.config.JWT.Secret)
	}
	// Return a default secret for development (in production, this should come from environment or secure storage)
	return []byte("default-jwt-secret-change-in-production")
}

// GetJWTSessionExpiry returns JWT session expiry
func (c *ConfigAuthenticationAdapter) GetJWTSessionExpiry() time.Duration {
	return c.config.JWT.SessionExpiry
}

// GetJWTRefreshExpiry returns JWT refresh expiry
func (c *ConfigAuthenticationAdapter) GetJWTRefreshExpiry() time.Duration {
	return c.config.JWT.RefreshExpiry
}

// GetPasswordPolicy returns password policy
func (c *ConfigAuthenticationAdapter) GetPasswordPolicy() *PasswordPolicy {
	return c.config.PasswordPolicy
}

// GetTFAIssuer returns TFA issuer
func (c *ConfigAuthenticationAdapter) GetTFAIssuer() string {
	return c.config.TFA.Issuer
}

// GetRateLimitConfig returns rate limit configuration
func (c *ConfigAuthenticationAdapter) GetRateLimitConfig() map[string]*RateLimitConfig {
	return c.config.RateLimits
}

// GetSecurityConfig returns security configuration
func (c *ConfigAuthenticationAdapter) GetSecurityConfig() *SecurityConfig {
	return c.config.Security
}

// GetAdminAPIKeyPrefix returns admin API key prefix
func (c *ConfigAuthenticationAdapter) GetAdminAPIKeyPrefix() string {
	return c.config.JWT.AdminAPIKeyPrefix
}

// GetMaxLoginAttempts returns maximum login attempts
func (c *ConfigAuthenticationAdapter) GetMaxLoginAttempts() int {
	return c.config.Security.MaxFailedLoginsPerUser
}

// GetAccountLockoutDuration returns account lockout duration
func (c *ConfigAuthenticationAdapter) GetAccountLockoutDuration() time.Duration {
	if c.config.Security != nil {
		return c.config.Security.FailedLoginWindow
	}
	return 15 * time.Minute // Default fallback
}

// GetSessionTimeout returns session timeout
func (c *ConfigAuthenticationAdapter) GetSessionTimeout() time.Duration {
	return c.config.SessionConfig.Timeout
}

// GetPasswordResetExpiry returns password reset token expiry
func (c *ConfigAuthenticationAdapter) GetPasswordResetExpiry() time.Duration {
	return 24 * time.Hour // Default 24 hours
}

// Validate validates the authentication configuration
func (c *ConfigAuthenticationAdapter) Validate() error {
	if !c.config.Enabled {
		return nil
	}

	if len(c.config.Methods) == 0 {
		return fmt.Errorf("at least one authentication method must be enabled")
	}

	// Validate JWT configuration
	for _, method := range c.config.Methods {
		if method == "jwt" {
			if c.config.JWT == nil {
				return fmt.Errorf("JWT method enabled but JWT configuration is missing")
			}
			if c.config.JWT.SessionExpiry <= 0 {
				return fmt.Errorf("JWT session expiry must be positive")
			}
			if c.config.JWT.RefreshExpiry <= 0 {
				return fmt.Errorf("JWT refresh expiry must be positive")
			}
		}
	}

	// Validate password policy
	if c.config.PasswordPolicy != nil {
		if c.config.PasswordPolicy.MinLength <= 0 {
			return fmt.Errorf("password minimum length must be positive")
		}
		if c.config.PasswordPolicy.MaxAge <= 0 {
			return fmt.Errorf("password max age must be positive")
		}
	}

	// Validate rate limits
	for endpoint, config := range c.config.RateLimits {
		if config.Limit <= 0 {
			return fmt.Errorf("rate limit for %s must be positive", endpoint)
		}
		if config.Window <= 0 {
			return fmt.Errorf("rate limit window for %s must be positive", endpoint)
		}
		if config.Burst <= 0 {
			return fmt.Errorf("rate limit burst for %s must be positive", endpoint)
		}
	}

	return nil
}

// ToJSON converts the configuration to JSON
func (c *ConfigAuthenticationAdapter) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c.config, "", "  ")
}

// FromJSON loads configuration from JSON
func (c *ConfigAuthenticationAdapter) FromJSON(data []byte) error {
	return json.Unmarshal(data, &c.config)
}

// Merge merges another authentication configuration into this one
func (c *ConfigAuthenticationAdapter) Merge(other *AuthenticationConfigSection) {
	if other.Enabled {
		c.config.Enabled = other.Enabled
	}

	if other.Methods != nil {
		c.config.Methods = other.Methods
	}

	if other.JWT != nil {
		if c.config.JWT == nil {
			c.config.JWT = &JWTConfig{}
		}
		if other.JWT.Secret != "" {
			c.config.JWT.Secret = other.JWT.Secret
		}
		if other.JWT.SessionExpiry > 0 {
			c.config.JWT.SessionExpiry = other.JWT.SessionExpiry
		}
		if other.JWT.RefreshExpiry > 0 {
			c.config.JWT.RefreshExpiry = other.JWT.RefreshExpiry
		}
		if other.JWT.Issuer != "" {
			c.config.JWT.Issuer = other.JWT.Issuer
		}
		if other.JWT.AdminAPIKeyPrefix != "" {
			c.config.JWT.AdminAPIKeyPrefix = other.JWT.AdminAPIKeyPrefix
		}
	}

	if other.PasswordPolicy != nil {
		if c.config.PasswordPolicy == nil {
			c.config.PasswordPolicy = &PasswordPolicy{}
		}
		if other.PasswordPolicy.MinLength > 0 {
			c.config.PasswordPolicy.MinLength = other.PasswordPolicy.MinLength
		}
		if other.PasswordPolicy.RequireUpper {
			c.config.PasswordPolicy.RequireUpper = other.PasswordPolicy.RequireUpper
		}
		if other.PasswordPolicy.RequireLower {
			c.config.PasswordPolicy.RequireLower = other.PasswordPolicy.RequireLower
		}
		if other.PasswordPolicy.RequireNumber {
			c.config.PasswordPolicy.RequireNumber = other.PasswordPolicy.RequireNumber
		}
		if other.PasswordPolicy.RequireSpecial {
			c.config.PasswordPolicy.RequireSpecial = other.PasswordPolicy.RequireSpecial
		}
		if other.PasswordPolicy.MinSpecial > 0 {
			c.config.PasswordPolicy.MinSpecial = other.PasswordPolicy.MinSpecial
		}
		if other.PasswordPolicy.MaxAge > 0 {
			c.config.PasswordPolicy.MaxAge = other.PasswordPolicy.MaxAge
		}
		if other.PasswordPolicy.HistoryCount > 0 {
			c.config.PasswordPolicy.HistoryCount = other.PasswordPolicy.HistoryCount
		}
		if other.PasswordPolicy.DisallowCommon {
			c.config.PasswordPolicy.DisallowCommon = other.PasswordPolicy.DisallowCommon
		}
	}

	if other.Security != nil {
		if c.config.Security == nil {
			c.config.Security = &SecurityConfig{}
		}
		if other.Security.SessionTimeout > 0 {
			c.config.Security.SessionTimeout = other.Security.SessionTimeout
		}
		if other.Security.MaxConcurrentSessions > 0 {
			c.config.Security.MaxConcurrentSessions = other.Security.MaxConcurrentSessions
		}
		if other.Security.RequireHTTPS {
			c.config.Security.RequireHTTPS = other.Security.RequireHTTPS
		}
		if other.Security.FrameOptions != "" {
			c.config.Security.FrameOptions = other.Security.FrameOptions
		}
		if other.Security.ContentSecurityPolicy != "" {
			c.config.Security.ContentSecurityPolicy = other.Security.ContentSecurityPolicy
		}
	}

	if other.RateLimits != nil {
		if c.config.RateLimits == nil {
			c.config.RateLimits = make(map[string]*RateLimitConfig)
		}
		for endpoint, config := range other.RateLimits {
			c.config.RateLimits[endpoint] = config
		}
	}
}

// GetConfig returns the underlying configuration
func (c *ConfigAuthenticationAdapter) GetConfig() *AuthenticationConfigSection {
	return c.config
}

// SetJWTSecret sets the JWT secret
func (c *ConfigAuthenticationAdapter) SetJWTSecret(secret string) {
	if c.config.JWT == nil {
		c.config.JWT = &JWTConfig{}
	}
	c.config.JWT.Secret = secret
}

// IsMethodEnabled checks if an authentication method is enabled
func (c *ConfigAuthenticationAdapter) IsMethodEnabled(method string) bool {
	for _, m := range c.config.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// IsTFAEnabled checks if TFA is enabled
func (c *ConfigAuthenticationAdapter) IsTFAEnabled() bool {
	return c.config.TFA != nil && c.config.TFA.Enabled
}

// IsTFAMethodEnabled checks if a specific TFA method is enabled
func (c *ConfigAuthenticationAdapter) IsTFAMethodEnabled(method string) bool {
	if !c.IsTFAEnabled() {
		return false
	}
	for _, m := range c.config.TFA.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// IsAuditEnabled checks if audit logging is enabled
func (c *ConfigAuthenticationAdapter) IsAuditEnabled() bool {
	return c.config.Audit != nil && c.config.Audit.Enabled
}