package authentication

import (
	"context"
	"fmt"
	"time"
)

// DefaultAuthenticationManager implements AuthenticationManager interface
type DefaultAuthenticationManager struct {
	userRepo            UserRepository
	roleRepo            RoleRepository
	sessionRepo         SessionRepository
	adminAPIKeyRepo     AdminAPIKeyRepository
	auditRepo           AuditRepository
	securityRepo        SecurityRepository
	passwordResetRepo   PasswordResetRepository
	tokenManager        TokenManager
	rbacManager         *RBACManager
	tfaManager          *TFAManager
	passwordManager     *PasswordManager
	rateLimiter         RateLimiter
	securityMonitor     SecurityMonitor
	auditLogger         AuditLogger
	config              AuthenticationConfig
}

// NewDefaultAuthenticationManager creates a new authentication manager
func NewDefaultAuthenticationManager(
	userRepo UserRepository,
	roleRepo RoleRepository,
	sessionRepo SessionRepository,
	adminAPIKeyRepo AdminAPIKeyRepository,
	auditRepo AuditRepository,
	securityRepo SecurityRepository,
	passwordResetRepo PasswordResetRepository,
	tokenManager TokenManager,
	rbacManager *RBACManager,
	tfaManager *TFAManager,
	passwordManager *PasswordManager,
	rateLimiter RateLimiter,
	securityMonitor SecurityMonitor,
	auditLogger AuditLogger,
	config AuthenticationConfig,
) *DefaultAuthenticationManager {
	return &DefaultAuthenticationManager{
		userRepo:          userRepo,
		roleRepo:          roleRepo,
		sessionRepo:       sessionRepo,
		adminAPIKeyRepo:   adminAPIKeyRepo,
		auditRepo:         auditRepo,
		securityRepo:      securityRepo,
		passwordResetRepo: passwordResetRepo,
		tokenManager:      tokenManager,
		rbacManager:       rbacManager,
		tfaManager:        tfaManager,
		passwordManager:   passwordManager,
		rateLimiter:       rateLimiter,
		securityMonitor:   securityMonitor,
		auditLogger:       auditLogger,
		config:            config,
	}
}

// User authentication methods

func (am *DefaultAuthenticationManager) AuthenticateUser(ctx context.Context, username, password, ipAddress, userAgent string) (*User, *UserSession, error) {
	// Check rate limiting
	allowed, resetTime := am.rateLimiter.Allow(ipAddress, "login")
	if !allowed {
		return nil, nil, fmt.Errorf("rate limit exceeded. Try again in %v", resetTime)
	}

	// Get user by username
	user, err := am.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		am.logFailedLogin(ctx, username, ipAddress, userAgent, "invalid_credentials", nil)
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is enabled
	if !user.Enabled {
		am.logFailedLogin(ctx, username, ipAddress, userAgent, "account_disabled", &user.ID)
		return nil, nil, fmt.Errorf("account is disabled")
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		am.logFailedLogin(ctx, username, ipAddress, userAgent, "account_locked", &user.ID)
		return nil, nil, fmt.Errorf("account is locked until %v", user.LockedUntil)
	}

	// Validate password
	if !am.passwordManager.ValidatePassword(user.PasswordHash, password) {
		// Increment failed login attempts
		_ = am.userRepo.IncrementLoginAttempts(ctx, user.ID)

		// Check if we should lock the account
		maxAttempts := am.config.GetMaxLoginAttempts()
		if user.LoginAttempts+1 >= maxAttempts {
			lockDuration := am.config.GetAccountLockoutDuration()
			lockedUntil := time.Now().Add(lockDuration)
			_ = am.userRepo.LockUser(ctx, user.ID, lockedUntil)
			am.logFailedLogin(ctx, username, ipAddress, userAgent, "account_locked", &user.ID)
			return nil, nil, fmt.Errorf("account locked due to too many failed attempts")
		}

		am.logFailedLogin(ctx, username, ipAddress, userAgent, "invalid_credentials", &user.ID)
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Check if TFA is required
	if user.TFAEnabled {
		_ = am.securityMonitor.MonitorLoginAttempt(ctx, &LoginAttempt{
			Username:  username,
			IPAddress: ipAddress,
			UserAgent: userAgent,
			Success:   false,
			Reason:    "tfa_required",
			UserID:    &user.ID,
			Timestamp: time.Now(),
		})
		return nil, nil, fmt.Errorf("tfa_required")
	}

	// Authentication successful - create session
	return am.createSessionForUser(ctx, user, ipAddress, userAgent)
}

func (am *DefaultAuthenticationManager) AuthenticateUserWithTFB(ctx context.Context, username, password, tfaCode, ipAddress, userAgent string) (*User, *UserSession, error) {
	// First authenticate with password
	user, _, err := am.AuthenticateUser(ctx, username, password, ipAddress, userAgent)
	if err != nil && err.Error() != "tfa_required" {
		return nil, nil, err
	}

	// If user authentication failed but not due to TFA, return error
	if user == nil {
		return nil, nil, err
	}

	// Validate TFA code
	tfaValidation, err := am.tfaManager.ValidateUserTFA(user.ID, tfaCode)
	if err != nil {
		return nil, nil, fmt.Errorf("TFA validation failed: %w", err)
	}

	if !tfaValidation.Valid {
		am.logFailedLogin(ctx, username, ipAddress, userAgent, "invalid_tfa_code", &user.ID)
		return nil, nil, fmt.Errorf("invalid TFA code")
	}

	// TFA validation successful - create session
	return am.createSessionForUser(ctx, user, ipAddress, userAgent)
}

func (am *DefaultAuthenticationManager) ValidateSession(ctx context.Context, sessionToken string) (*User, *UserSession, error) {
	// Validate JWT token
	_, err := am.tokenManager.ValidateSessionToken(sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid session token: %w", err)
	}

	// Get session from database
	session, err := am.sessionRepo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found: %w", err)
	}

	// Check if session is active and not expired
	if !session.Active || time.Now().After(session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session is inactive or expired")
	}

	// Get user
	user, err := am.userRepo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is still enabled
	if !user.Enabled {
		return nil, nil, fmt.Errorf("user account is disabled")
	}

	// Update session activity
	go func() {
		_ = am.sessionRepo.UpdateSessionActivity(context.Background(), session.ID)
	}()

	return user, session, nil
}

func (am *DefaultAuthenticationManager) RefreshSession(ctx context.Context, refreshToken string) (*UserSession, error) {
	// Validate refresh token
	claims, err := am.tokenManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get existing session
	session, err := am.sessionRepo.GetSessionByID(ctx, claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Check if session is still active
	if !session.Active {
		return nil, fmt.Errorf("session is no longer active")
	}

	// Generate new tokens
	user, err := am.userRepo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	newSessionToken, newRefreshToken, expiresAt, err := am.tokenManager.GenerateSessionToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Update session with new tokens
	session.SessionToken = HashAPIKey(newSessionToken)
	session.RefreshToken = HashAPIKey(newRefreshToken)
	session.ExpiresAt = expiresAt
	session.LastActivity = time.Now()

	err = am.sessionRepo.UpdateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Return updated session info
	return &UserSession{
		ID:             session.ID,
		UserID:         session.UserID,
		SessionToken:   newSessionToken,
		RefreshToken:   newRefreshToken,
		ExpiresAt:      expiresAt,
		LastActivity:   session.LastActivity,
		Active:         session.Active,
	}, nil
}

func (am *DefaultAuthenticationManager) LogoutUser(ctx context.Context, sessionToken string) error {
	// Invalidate JWT token
	err := am.tokenManager.InvalidateToken(sessionToken)
	if err != nil {
		return fmt.Errorf("failed to invalidate token: %w", err)
	}

	// Mark session as inactive
	session, err := am.sessionRepo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		// Session might not exist, but that's okay for logout
		return nil
	}

	session.Active = false
	return am.sessionRepo.UpdateSession(ctx, session)
}

func (am *DefaultAuthenticationManager) LogoutAllUserSessions(ctx context.Context, userID int64) error {
	// Invalidate all user tokens
	err := am.tokenManager.InvalidateUserTokens(userID)
	if err != nil {
		return fmt.Errorf("failed to invalidate user tokens: %w", err)
	}

	// Deactivate all user sessions
	return am.sessionRepo.DeleteUserSessions(ctx, userID)
}

// Password management methods

func (am *DefaultAuthenticationManager) HashPassword(password string) (string, error) {
	return am.passwordManager.HashPassword(password)
}

func (am *DefaultAuthenticationManager) ValidatePassword(hash, password string) bool {
	return am.passwordManager.ValidatePassword(hash, password)
}

func (am *DefaultAuthenticationManager) GeneratePasswordResetToken(ctx context.Context, userID int64) (string, error) {
	// Generate secure token
	token, err := GenerateSecureToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Create password reset token record
	resetToken := &PasswordResetToken{
		UserID:    userID,
		TokenHash: HashAPIKey(token),
		ExpiresAt: time.Now().Add(am.config.GetPasswordResetExpiry()),
		Used:      false,
		CreatedAt: time.Now(),
	}

	err = am.passwordResetRepo.CreatePasswordResetToken(ctx, resetToken)
	if err != nil {
		return "", fmt.Errorf("failed to store reset token: %w", err)
	}

	return token, nil
}

func (am *DefaultAuthenticationManager) ValidatePasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	tokenHash := HashAPIKey(token)
	return am.passwordResetRepo.GetPasswordResetTokenByHash(ctx, tokenHash)
}

func (am *DefaultAuthenticationManager) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate reset token
	resetToken, err := am.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid reset token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		return fmt.Errorf("reset token has expired")
	}

	// Check if token is already used
	if resetToken.Used {
		return fmt.Errorf("reset token has already been used")
	}

	// Validate new password strength
	if err := am.passwordManager.ValidatePasswordStrength(newPassword); err != nil {
		return fmt.Errorf("password does not meet requirements: %w", err)
	}

	// Hash new password
	hashedPassword, err := am.passwordManager.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Get user
	user, err := am.userRepo.GetUserByID(ctx, resetToken.UserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	user.LoginAttempts = 0  // Reset login attempts
	user.LockedUntil = nil  // Unlock account if locked
	err = am.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	// Mark token as used
	err = am.passwordResetRepo.InvalidatePasswordResetToken(ctx, resetToken.ID)
	if err != nil {
		// Log error but don't fail the operation
		go am.auditLogger.LogSystemAction(context.Background(), "reset_token_invalidation_failed", "password_reset", "", map[string]interface{}{
			"error": err.Error(),
			"token_id": resetToken.ID,
		}, false, "", "")
	}

	// Mark all user sessions as inactive
	go func() {
		_ = am.sessionRepo.DeleteUserSessions(context.Background(), resetToken.UserID)
	}()

	// Log successful password reset
	am.auditLogger.LogUserAction(ctx, resetToken.UserID, "password_reset_completed", "user", fmt.Sprintf("%d", resetToken.UserID), map[string]interface{}{
		"method": "token",
	}, true, "", "")

	return nil
}

func (am *DefaultAuthenticationManager) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	// Get user
	user, err := am.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Validate old password
	if !am.passwordManager.ValidatePassword(user.PasswordHash, oldPassword) {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password strength
	if err := am.passwordManager.ValidatePasswordStrength(newPassword); err != nil {
		return fmt.Errorf("new password does not meet requirements: %w", err)
	}

	// Hash new password
	hashedPassword, err := am.passwordManager.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update user password
	user.PasswordHash = hashedPassword
	err = am.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Log password change
	am.auditLogger.LogUserAction(ctx, userID, "password_changed", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"method": "self_service",
	}, true, "", "")

	return nil
}

// TFA management methods

func (am *DefaultAuthenticationManager) GenerateTFASecret(userID int64) (string, string, error) {
	user, err := am.userRepo.GetUserByID(context.Background(), userID)
	if err != nil {
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	setup, err := am.tfaManager.SetupTFA(user.Username)
	if err != nil {
		return "", "", fmt.Errorf("failed to setup TFA: %w", err)
	}

	return setup.Secret, setup.QRCode, nil
}

func (am *DefaultAuthenticationManager) EnableTFA(ctx context.Context, userID int64, secret string) error {
	// Generate backup codes
	backupCodes, err := am.tfaManager.GenerateBackupCodes(10)
	if err != nil {
		return fmt.Errorf("failed to generate backup codes: %w", err)
	}

	return am.tfaManager.EnableTFA(userID, secret, backupCodes)
}

func (am *DefaultAuthenticationManager) DisableTFA(ctx context.Context, userID int64) error {
	user, err := am.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.TFAEnabled = false
	user.TFASecret = ""
	err = am.userRepo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to disable TFA: %w", err)
	}

	// Log TFA disable
	am.auditLogger.LogUserAction(ctx, userID, "tfa_disabled", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"method": "totp",
	}, true, "", "")

	return nil
}

func (am *DefaultAuthenticationManager) ValidateTFA(userID int64, code string) bool {
	validation, err := am.tfaManager.ValidateUserTFA(userID, code)
	return err == nil && validation.Valid
}

// API key management methods

func (am *DefaultAuthenticationManager) GenerateAdminAPIKey(ctx context.Context, key *AdminAPIKey) (string, error) {
	// Generate API key
	generatedKey, err := am.tokenManager.GenerateAdminAPIKey(key.UserID, key.Permissions)
	if err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Hash the key for storage
	key.KeyHash = HashAPIKey(generatedKey)

	// Store in database
	err = am.adminAPIKeyRepo.CreateAdminAPIKey(ctx, key)
	if err != nil {
		return "", fmt.Errorf("failed to store API key: %w", err)
	}

	// Log API key creation
	am.auditLogger.LogUserAction(ctx, *key.UserID, "admin_api_key_created", "admin_api_key", fmt.Sprintf("%d", key.ID), map[string]interface{}{
		"key_id": key.KeyID,
		"name": key.Name,
		"permissions": key.Permissions,
	}, true, "", "")

	return generatedKey, nil
}

func (am *DefaultAuthenticationManager) ValidateAdminAPIKey(ctx context.Context, apiKey string) (*AdminAPIKey, error) {
	keyHash := HashAPIKey(apiKey)
	key, err := am.adminAPIKeyRepo.GetAdminAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check if key is enabled
	if !key.Enabled {
		return nil, fmt.Errorf("API key is disabled")
	}

	// Check if key is expired
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, fmt.Errorf("API key has expired")
	}

	// Update last used and usage count
	go func() {
		key.UsageCount++
		now := time.Now()
		key.LastUsed = &now
		_ = am.adminAPIKeyRepo.UpdateAdminAPIKey(context.Background(), key)
	}()

	return key, nil
}

func (am *DefaultAuthenticationManager) RevokeAdminAPIKey(ctx context.Context, keyID int64) error {
	err := am.adminAPIKeyRepo.RevokeAdminAPIKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	// Log API key revocation
	am.auditLogger.LogSystemAction(ctx, "admin_api_key_revoked", "admin_api_key", fmt.Sprintf("%d", keyID), map[string]interface{}{}, true, "", "")

	return nil
}

// Authorization methods

func (am *DefaultAuthenticationManager) HasPermission(user *User, permission string) bool {
	return am.rbacManager.HasPermission(user, permission)
}

func (am *DefaultAuthenticationManager) HasAnyPermission(user *User, permissions []string) bool {
	return am.rbacManager.HasAnyPermission(user, permissions)
}

func (am *DefaultAuthenticationManager) HasAllPermissions(user *User, permissions []string) bool {
	return am.rbacManager.HasAllPermissions(user, permissions)
}

// Rate limiting methods

func (am *DefaultAuthenticationManager) CheckRateLimit(ctx context.Context, identifier, endpoint string) (bool, time.Duration, error) {
	allowed, resetTime := am.rateLimiter.Allow(identifier, endpoint)
	return allowed, resetTime, nil
}

func (am *DefaultAuthenticationManager) ResetRateLimit(ctx context.Context, identifier, endpoint string) error {
	am.rateLimiter.Reset(identifier, endpoint)
	return nil
}

// Security methods

func (am *DefaultAuthenticationManager) DetectSuspiciousActivity(ctx context.Context, ipAddress, userAgent string) ([]*SecurityEvent, error) {
	// This would implement sophisticated detection logic
	// For now, return empty slice
	return []*SecurityEvent{}, nil
}

func (am *DefaultAuthenticationManager) LockAccount(ctx context.Context, userID int64, reason string, duration time.Duration) error {
	lockedUntil := time.Now().Add(duration)
	return am.userRepo.LockUser(ctx, userID, lockedUntil)
}

func (am *DefaultAuthenticationManager) UnlockAccount(ctx context.Context, userID int64) error {
	return am.userRepo.UnlockUser(ctx, userID)
}

// User management helper methods

func (am *DefaultAuthenticationManager) CreateUser(ctx context.Context, user *User, password string) error {
	// Validate password strength
	if err := am.passwordManager.ValidatePasswordStrength(password); err != nil {
		return fmt.Errorf("password does not meet requirements: %w", err)
	}

	// Hash password
	hashedPassword, err := am.passwordManager.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = hashedPassword
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	return am.userRepo.CreateUser(ctx, user)
}

func (am *DefaultAuthenticationManager) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return am.userRepo.GetUserByID(ctx, id)
}

func (am *DefaultAuthenticationManager) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	return am.userRepo.UpdateUser(ctx, user)
}

func (am *DefaultAuthenticationManager) DeleteUser(ctx context.Context, id int64) error {
	return am.userRepo.DeleteUser(ctx, id)
}

func (am *DefaultAuthenticationManager) ListUsers(ctx context.Context, filter *UserFilter) ([]*User, int64, error) {
	return am.userRepo.ListUsers(ctx, filter)
}

// Helper methods

func (am *DefaultAuthenticationManager) createSessionForUser(ctx context.Context, user *User, ipAddress, userAgent string) (*User, *UserSession, error) {
	// Reset login attempts
	_ = am.userRepo.ResetLoginAttempts(ctx, user.ID)

	// Update last login
	_ = am.userRepo.UpdateLastLogin(ctx, user.ID)

	// Generate session tokens
	sessionToken, refreshToken, expiresAt, err := am.tokenManager.GenerateSessionToken(user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session tokens: %w", err)
	}

	// Create session record
	session := &UserSession{
		UserID:       user.ID,
		SessionToken: HashAPIKey(sessionToken),
		RefreshToken: HashAPIKey(refreshToken),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		ExpiresAt:    expiresAt,
		Active:       true,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	err = am.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update user with token info for response
	user.LastLogin = &[]time.Time{time.Now()}[0]

	// Log successful login
	_ = am.securityMonitor.MonitorLoginAttempt(ctx, &LoginAttempt{
		Username:  user.Username,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		UserID:    &user.ID,
		Timestamp: time.Now(),
	})

	am.auditLogger.LogLoginAttempt(ctx, user.Username, ipAddress, userAgent, true, "success", &user.ID)

	// Return session with response tokens
	responseSession := &UserSession{
		ID:             session.ID,
		UserID:         user.ID,
		SessionToken:   sessionToken,
		RefreshToken:   refreshToken,
		ExpiresAt:      expiresAt,
		LastActivity:   session.LastActivity,
		Active:         session.Active,
	}

	return user, responseSession, nil
}

func (am *DefaultAuthenticationManager) logFailedLogin(ctx context.Context, username, ipAddress, userAgent, reason string, userID *int64) {
	// Log failed login attempt
	_ = am.securityMonitor.MonitorLoginAttempt(ctx, &LoginAttempt{
		Username:  username,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   false,
		Reason:    reason,
		UserID:    userID,
		Timestamp: time.Now(),
	})

	am.auditLogger.LogLoginAttempt(ctx, username, ipAddress, userAgent, false, reason, userID)
}