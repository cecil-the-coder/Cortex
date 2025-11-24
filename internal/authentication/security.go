package authentication

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// PasswordManager handles password hashing and validation
type PasswordManager struct {
	policy *PasswordPolicy
}

// NewPasswordManager creates a new password manager
func NewPasswordManager(policy *PasswordPolicy) *PasswordManager {
	if policy == nil {
		policy = &PasswordPolicy{
			MinLength:      12,
			RequireUpper:   true,
			RequireLower:   true,
			RequireNumber:  true,
			RequireSpecial: true,
			MinSpecial:     1,
			MaxAge:         90 * 24 * time.Hour, // 90 days
			HistoryCount:   5,
			DisallowCommon: true,
		}
	}
	return &PasswordManager{policy: policy}
}

// HashPassword creates a bcrypt hash of the password
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// ValidatePassword checks if a password matches its hash
func (pm *PasswordManager) ValidatePassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePasswordStrength checks if a password meets the policy requirements
func (pm *PasswordManager) ValidatePasswordStrength(password string) error {
	if len(password) < pm.policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", pm.policy.MinLength)
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	specialCount := 0

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
			specialCount++
		}
	}

	if pm.policy.RequireUpper && !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if pm.policy.RequireLower && !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if pm.policy.RequireNumber && !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	if pm.policy.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	if pm.policy.MinSpecial > 0 && specialCount < pm.policy.MinSpecial {
		return fmt.Errorf("password must contain at least %d special characters", pm.policy.MinSpecial)
	}

	if pm.policy.DisallowCommon && pm.isCommonPassword(password) {
		return fmt.Errorf("password is too common, please choose a stronger password")
	}

	return nil
}

// isCommonPassword checks against a list of common passwords
func (pm *PasswordManager) isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty", "letmein",
		"welcome", "monkey", "1234567890", "password1", "abc123", "Password1",
	}

	lowerPassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if subtle.ConstantTimeCompare([]byte(lowerPassword), []byte(common)) == 1 {
			return true
		}
		// Check if it contains the common password
		if strings.Contains(lowerPassword, common) {
			return true
		}
	}

	return false
}

// InMemoryRateLimiter implements rate limiting in memory
type InMemoryRateLimiter struct {
	limiters map[string]*rate.Limiter
	configs  map[string]*RateLimitConfig
	mu       sync.RWMutex
	cleanup  chan struct{}
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	rl := &InMemoryRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		configs:  make(map[string]*RateLimitConfig),
		cleanup:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupRoutine()

	return rl
}

// Allow checks if a request is allowed
func (rl *InMemoryRateLimiter) Allow(identifier, endpoint string) (bool, time.Duration, error) {
	rl.mu.RLock()
	config, exists := rl.configs[endpoint]
	if !exists {
		// Default configuration
		config = &RateLimitConfig{
			Limit:  100,
			Window: time.Minute,
			Burst:  10,
		}
	}
	rl.mu.RUnlock()

	key := identifier + ":" + endpoint

	rl.mu.Lock()
	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(config.Limit), config.Burst)
		rl.limiters[key] = limiter
	}
	rl.mu.Unlock()

	allowed := limiter.Allow()
	if !allowed {
		// Calculate when the next request will be allowed
		reservation := limiter.Reserve()
		delay := reservation.Delay()
		reservation.Cancel() // Don't actually consume a token
		return false, delay, nil
	}

	return true, 0, nil
}

// Limit returns the current limit configuration
func (rl *InMemoryRateLimiter) Limit(identifier, endpoint string) (int, time.Duration) {
	rl.mu.RLock()
	config, exists := rl.configs[endpoint]
	if !exists {
		config = &RateLimitConfig{
			Limit:  100,
			Window: time.Minute,
			Burst:  10,
		}
	}
	rl.mu.RUnlock()

	return config.Limit, config.Window
}

// Burst returns the current burst size
func (rl *InMemoryRateLimiter) Burst(identifier, endpoint string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	key := identifier + ":" + endpoint
	if limiter, exists := rl.limiters[key]; exists {
		return limiter.Burst()
	}

	return 10 // Default burst size
}

// Reset resets the rate limiter for a specific identifier
func (rl *InMemoryRateLimiter) Reset(identifier, endpoint string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	key := identifier + ":" + endpoint
	delete(rl.limiters, key)
}

// SetConfig sets rate limit configuration for an endpoint
func (rl *InMemoryRateLimiter) SetConfig(endpoint string, config *RateLimitConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.configs[endpoint] = config
}

// GetConfig gets rate limit configuration for an endpoint
func (rl *InMemoryRateLimiter) GetConfig(endpoint string) (*RateLimitConfig, bool) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	config, exists := rl.configs[endpoint]
	return config, exists
}

// cleanupRoutine periodically cleans up old rate limiters
func (rl *InMemoryRateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupOldLimiters()
		case <-rl.cleanup:
			return
		}
	}
}

// cleanupOldLimiters removes unused rate limiters
func (rl *InMemoryRateLimiter) cleanupOldLimiters() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// In a production implementation, you'd track last access time
	// For now, we'll keep it simple and not implement aging
}

// Close cleanup resources
func (rl *InMemoryRateLimiter) Close() {
	close(rl.cleanup)
}

// DefaultSecurityMonitor implements security monitoring
type DefaultSecurityMonitor struct {
	securityRepo SecurityRepository
	auditLogger  AuditLogger
	config       *SecurityConfig
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor(securityRepo SecurityRepository, auditLogger AuditLogger, config *SecurityConfig) *DefaultSecurityMonitor {
	if config == nil {
		config = &SecurityConfig{
			SessionTimeout:          30 * time.Minute,
			MaxConcurrentSessions:   5,
			RequireHTTPS:            true,
			MaxFailedLoginsPerIP:    10,
			MaxFailedLoginsPerUser:  5,
			FailedLoginWindow:      15 * time.Minute,
			LogLevel:               "info",
		}
	}
	return &DefaultSecurityMonitor{
		securityRepo: securityRepo,
		auditLogger:  auditLogger,
		config:       config,
	}
}

// MonitorLoginAttempt monitors login attempts for security
func (sm *DefaultSecurityMonitor) MonitorLoginAttempt(ctx context.Context, attempt *LoginAttempt) error {
	// Log the attempt
	if err := sm.securityRepo.CreateLoginAttempt(ctx, attempt); err != nil {
		return fmt.Errorf("failed to log login attempt: %w", err)
	}

	// Check for brute force attacks
	if !attempt.Success {
		sm.checkBruteForce(ctx, attempt)
	}

	// Check for suspicious patterns
	sm.checkSuspiciousPattern(ctx, attempt)

	return nil
}

// checkBruteForce checks for brute force attacks
func (sm *DefaultSecurityMonitor) checkBruteForce(ctx context.Context, attempt *LoginAttempt) {
	// Check IP-based brute force
	since := time.Now().Add(-sm.config.FailedLoginWindow)
	ipCount, err := sm.securityRepo.GetFailedLoginCount(ctx, attempt.IPAddress, "", since)
	if err == nil && ipCount >= int64(sm.config.MaxFailedLoginsPerIP) {
		_ = sm.createSecurityAlert(ctx, &SecurityEvent{
			Type:        "brute_force",
			Severity:    "high",
			Title:       "Brute Force Attack Detected",
			Description: fmt.Sprintf("Multiple failed login attempts from IP: %s", attempt.IPAddress),
			Details: map[string]interface{}{
				"ip_address": attempt.IPAddress,
				"failed_count": ipCount,
				"time_window": sm.config.FailedLoginWindow.String(),
			},
			IPAddress: attempt.IPAddress,
		})
	}

	// Check user-based brute force
	since = time.Now().Add(-sm.config.FailedLoginWindow)
	userCount, err := sm.securityRepo.GetFailedLoginCount(ctx, "", attempt.Username, since)
	if err == nil && userCount >= int64(sm.config.MaxFailedLoginsPerUser) {
		_ = sm.createSecurityAlert(ctx, &SecurityEvent{
			Type:        "brute_force",
			Severity:    "high",
			Title:       "Account Under Attack",
			Description: fmt.Sprintf("Multiple failed login attempts for user: %s", attempt.Username),
			Details: map[string]interface{}{
				"username": attempt.Username,
				"failed_count": userCount,
				"time_window": sm.config.FailedLoginWindow.String(),
			},
			IPAddress: attempt.IPAddress,
		})
	}
}

// checkSuspiciousPattern checks for suspicious login patterns
func (sm *DefaultSecurityMonitor) checkSuspiciousPattern(ctx context.Context, attempt *LoginAttempt) {
	// Check for logins from multiple IPs in short time
	// This would require more complex analysis of login patterns
	// For now, we'll create a placeholder
}

// createSecurityAlert creates a security alert
func (sm *DefaultSecurityMonitor) createSecurityAlert(ctx context.Context, event *SecurityEvent) error {
	event.CreatedAt = time.Now()
	err := sm.securityRepo.CreateSecurityEvent(ctx, event)
	if err != nil {
		// Log error but don't fail the operation
		sm.auditLogger.LogSystemAction(ctx, "security_alert_failed", "security_event", "", map[string]interface{}{
			"error": err.Error(),
			"event_type": event.Type,
		}, false, event.IPAddress, "")
		return err
	}

	sm.auditLogger.LogSystemAction(ctx, "security_alert_created", "security_event", "", map[string]interface{}{
		"event_id": event.ID,
		"event_type": event.Type,
		"severity": event.Severity,
		"ip_address": event.IPAddress,
	}, true, event.IPAddress, "")
	return nil
}

// DetectSuspiciousActivity detects suspicious patterns in user behavior
func (sm *DefaultSecurityMonitor) DetectSuspiciousActivity(ctx context.Context, userID int64, recentActions []*AuditLog) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Analyze recent actions for patterns
	if len(recentActions) > 50 { // Unusual activity
		events = append(events, &SecurityEvent{
			Type:        "suspicious_activity",
			Severity:    "medium",
			Title:       "High Activity Volume",
			Description: "User performed an unusually high number of actions",
			Details: map[string]interface{}{
				"user_id":      userID,
				"action_count": len(recentActions),
			},
			UserID: &userID,
		})
	}

	// Check for privilege escalation attempts
	privilegeActions := 0
	for _, action := range recentActions {
		if strings.Contains(action.Action, "role") || strings.Contains(action.Action, "permission") {
			privilegeActions++
		}
	}

	if privilegeActions > 5 { // Suspicious privilege activity
		events = append(events, &SecurityEvent{
			Type:        "privilege_escalation",
			Severity:    "high",
			Title:       "Suspicious Privilege Activity",
			Description: "User performed multiple privilege-related actions",
			Details: map[string]interface{}{
				"user_id":           userID,
				"privilege_actions": privilegeActions,
			},
			UserID: &userID,
		})
	}

	return events, nil
}

// MonitorAPIAccess monitors API access for security
func (sm *DefaultSecurityMonitor) MonitorAPIAccess(ctx context.Context, userID *int64, apiKeyID *int64, ipAddress, userAgent, endpoint string) error {
	// Log API access for monitoring
	return nil
}

// DetectBruteForce detects brute force attacks
func (sm *DefaultSecurityMonitor) DetectBruteForce(ctx context.Context, ipAddress, username string) (bool, error) {
	since := time.Now().Add(-sm.config.FailedLoginWindow)
	ipCount, err := sm.securityRepo.GetFailedLoginCount(ctx, ipAddress, "", since)
	if err != nil {
		return false, err
	}

	if ipCount >= int64(sm.config.MaxFailedLoginsPerIP) {
		return true, nil
	}

	userCount, err := sm.securityRepo.GetFailedLoginCount(ctx, "", username, since)
	if err != nil {
		return false, err
	}

	return userCount >= int64(sm.config.MaxFailedLoginsPerUser), nil
}

// DetectSuspiciousPattern detects suspicious patterns in user behavior
func (sm *DefaultSecurityMonitor) DetectSuspiciousPattern(ctx context.Context, userID int64, actions []*AuditLog) error {
	// This would implement pattern detection logic
	return nil
}

// CreateSecurityAlert creates a security alert
func (sm *DefaultSecurityMonitor) CreateSecurityAlert(ctx context.Context, alert *SecurityEvent) error {
	return sm.createSecurityAlert(ctx, alert)
}

// IPWhitelistChecker implements IP allowlisting
type IPWhitelistChecker struct {
	allowedIPs []string
	blockedIPs []string
}

// NewIPWhitelistChecker creates a new IP whitelist checker
func NewIPWhitelistChecker(allowedIPs, blockedIPs []string) *IPWhitelistChecker {
	return &IPWhitelistChecker{
		allowedIPs: allowedIPs,
		blockedIPs: blockedIPs,
	}
}

// IsAllowed checks if an IP address is allowed
func (iwc *IPWhitelistChecker) IsAllowed(ip string) bool {
	// Check blacklist first (blocked IPs take precedence)
	for _, blocked := range iwc.blockedIPs {
		if iwc.ipMatches(ip, blocked) {
			return false
		}
	}

	// If no whitelist is configured, allow all IPs except blocked ones
	if len(iwc.allowedIPs) == 0 {
		return true
	}

	// Check whitelist
	for _, allowed := range iwc.allowedIPs {
		if iwc.ipMatches(ip, allowed) {
			return true
		}
	}

	return false
}

// ipMatches checks if an IP matches a pattern (supports CIDR)
func (iwc *IPWhitelistChecker) ipMatches(ip, pattern string) bool {
	// Exact match
	if ip == pattern {
		return true
	}

	// CIDR match
	if strings.Contains(pattern, "/") {
		_, ipnet, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return false
		}
		return ipnet.Contains(testIP)
	}

	return false
}

// AuditLogger implements comprehensive audit logging
type DefaultAuditLogger struct {
	auditRepository AuditRepository
}

// NewDefaultAuditLogger creates a new default audit logger
func NewDefaultAuditLogger(auditRepository AuditRepository) *DefaultAuditLogger {
	return &DefaultAuditLogger{
		auditRepository: auditRepository,
	}
}

// LogUserAction logs a user action
func (dal *DefaultAuditLogger) LogUserAction(ctx context.Context, userID int64, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error {
	log := &AuditLog{
		UserID:      &userID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Details:     details,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Success:     success,
		Timestamp:   time.Now(),
	}

	return dal.auditRepository.CreateAuditLog(ctx, log)
}

// LogAPIKeyAction logs an API key action
func (dal *DefaultAuditLogger) LogAPIKeyAction(ctx context.Context, apiKeyID int64, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error {
	log := &AuditLog{
		APIKeyID:    &apiKeyID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Details:     details,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Success:     success,
		Timestamp:   time.Now(),
	}

	return dal.auditRepository.CreateAuditLog(ctx, log)
}

// LogSystemAction logs a system action
func (dal *DefaultAuditLogger) LogSystemAction(ctx context.Context, action, resource, resourceID string, details map[string]interface{}, success bool, ipAddress, userAgent string) error {
	log := &AuditLog{
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Details:     details,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Success:     success,
		Timestamp:   time.Now(),
	}

	return dal.auditRepository.CreateAuditLog(ctx, log)
}

// LogLoginAttempt logs a login attempt
func (dal *DefaultAuditLogger) LogLoginAttempt(ctx context.Context, username, ipAddress, userAgent string, success bool, reason string, userID *int64) error {
	details := map[string]interface{}{
		"reason": reason,
	}

	log := &AuditLog{
		UserID:      userID,
		Action:      "login_attempt",
		Resource:    "authentication",
		Details:     details,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Success:     success,
		Timestamp:   time.Now(),
	}

	if !success {
		log.Details["username"] = username
		log.ErrorMessage = reason
	}

	return dal.auditRepository.CreateAuditLog(ctx, log)
}

// LogSecurityEvent logs a security event as an audit log
func (dal *DefaultAuditLogger) LogSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	log := &AuditLog{
		Action:      "security_event",
		Resource:    "security",
		ResourceID:  fmt.Sprintf("%d", event.ID),
		Details: map[string]interface{}{
			"event_type":  event.Type,
			"severity":    event.Severity,
			"title":       event.Title,
			"description": event.Description,
			"details":     event.Details,
		},
		IPAddress: event.IPAddress,
		UserID:    event.UserID,
		Success:   true,
		Timestamp: event.CreatedAt,
	}

	return dal.auditRepository.CreateAuditLog(ctx, log)
}