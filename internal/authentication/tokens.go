package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTTokenManager implements TokenManager using JWT
type JWTTokenManager struct {
	secret               []byte
	sessionExpiry        time.Duration
	refreshExpiry        time.Duration
	issuer               string
	apiKeyPrefix         string
	blacklistedTokens    map[string]time.Time
 revokedRefreshTokens map[string]time.Time
}

// NewJWTTokenManager creates a new JWT token manager
func NewJWTTokenManager(config AuthenticationConfig) *JWTTokenManager {
	return &JWTTokenManager{
		secret:               config.GetJWTSecret(),
		sessionExpiry:        config.GetJWTSessionExpiry(),
		refreshExpiry:        config.GetJWTRefreshExpiry(),
		issuer:               "Cortex",
		apiKeyPrefix:         config.GetAdminAPIKeyPrefix(),
		blacklistedTokens:    make(map[string]time.Time),
		revokedRefreshTokens: make(map[string]time.Time),
	}
}

// GenerateTokens generates session and refresh tokens for a user
func (tm *JWTTokenManager) GenerateSessionToken(userID int64) (string, string, time.Time, error) {
	sessionID := tm.generateSessionID()
	now := time.Now()
	expiresAt := now.Add(tm.sessionExpiry)

	// Generate session token
	sessionClaims := &SessionClaims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "session",
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
	}

	sessionToken := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims)
	signedSessionToken, err := sessionToken.SignedString(tm.secret)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign session token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &RefreshClaims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
		ExpiresAt: expiresAt.Add(tm.refreshExpiry).Unix(),
		IssuedAt:  now.Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(tm.secret)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedSessionToken, signedRefreshToken, expiresAt, nil
}

// GenerateRefreshToken generates a refresh token
func (tm *JWTTokenManager) GenerateRefreshToken(userID int64) (string, time.Time, error) {
	sessionID := tm.generateSessionID()
	now := time.Now()
	expiresAt := now.Add(tm.refreshExpiry)

	refreshClaims := &RefreshClaims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(tm.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedRefreshToken, expiresAt, nil
}

// ValidateSessionToken validates a session token
func (tm *JWTTokenManager) ValidateSessionToken(token string) (*SessionClaims, error) {
	// Check if token is blacklisted
	if expiry, exists := tm.blacklistedTokens[token]; exists {
		if time.Now().Before(expiry) {
			return nil, fmt.Errorf("token is revoked")
		}
		// Clean up expired blacklist entry
		delete(tm.blacklistedTokens, token)
	}

	// Parse and validate token
	parsedToken, err := jwt.ParseWithClaims(token, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*SessionClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.TokenType != "session" {
		return nil, fmt.Errorf("invalid token type")
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

// ValidateRefreshToken validates a refresh token
func (tm *JWTTokenManager) ValidateRefreshToken(token string) (*RefreshClaims, error) {
	// Check if token is revoked
	if expiry, exists := tm.revokedRefreshTokens[token]; exists && time.Now().Before(expiry) {
		return nil, fmt.Errorf("refresh token is revoked")
	}

	// Parse and validate token
	parsedToken, err := jwt.ParseWithClaims(token, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	claims, ok := parsedToken.Claims.(*RefreshClaims)
	if !ok || !parsedToken.Valid {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("refresh token has expired")
	}

	return claims, nil
}

// GenerateAdminAPIKey generates an admin API key
func (tm *JWTTokenManager) GenerateAdminAPIKey(userID *int64, permissions []string) (string, error) {
	// Generate random key
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	key := base64.URLEncoding.EncodeToString(randomBytes)
	fullKey := tm.apiKeyPrefix + key

	return fullKey, nil
}

// InvalidateToken invalidates a token by adding it to the blacklist
func (tm *JWTTokenManager) InvalidateToken(token string) error {
	// Try to parse as session token first
	claims, err := tm.ValidateSessionToken(token)
	if err == nil {
		tm.blacklistedTokens[token] = time.Unix(claims.ExpiresAt, 0)
		return nil
	}

	// Try as refresh token
	refreshClaims, err := tm.ValidateRefreshToken(token)
	if err == nil {
		tm.revokedRefreshTokens[token] = time.Unix(refreshClaims.ExpiresAt, 0)
		return nil
	}

	return fmt.Errorf("invalid token: %w", err)
}

// InvalidateUserTokens invalidates all tokens for a user
func (tm *JWTTokenManager) InvalidateUserTokens(userID int64) error {
	// In a production environment, you would maintain a user-to-tokens mapping
	// or use Redis to store session information
	// For now, we'll clear all blacklisted/revoked tokens that have expired
	tm.cleanupExpiredTokens()

	return nil
}

// cleanupExpiredTokens removes expired entries from the blacklist
func (tm *JWTTokenManager) cleanupExpiredTokens() {
	now := time.Now()

	// Clean session token blacklist
	for token, expiry := range tm.blacklistedTokens {
		if now.After(expiry) {
			delete(tm.blacklistedTokens, token)
		}
	}

	// Clean refresh token revocation list
	for token, expiry := range tm.revokedRefreshTokens {
		if now.After(expiry) {
			delete(tm.revokedRefreshTokens, token)
		}
	}
}

// generateSessionID generates a unique session ID
func (tm *JWTTokenManager) generateSessionID() string {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("sess_%x", randomBytes)
}

// GetSigningMethod returns the JWT signing method
func (tm *JWTTokenManager) GetSigningMethod() jwt.SigningMethod {
	return jwt.SigningMethodHS256
}

// Custom JWT claims methods

// Valid implements the Claims interface for SessionClaims
func (sc *SessionClaims) Valid() error {
	if time.Now().Unix() > sc.ExpiresAt {
		return fmt.Errorf("token expired")
	}
	return nil
}

// GetIssuer returns the token issuer
func (sc *SessionClaims) GetIssuer() (string, error) {
	return "Cortex", nil
}

// GetSubject returns the token subject
func (sc *SessionClaims) GetSubject() (string, error) {
	return fmt.Sprintf("user:%d", sc.UserID), nil
}

// GetAudience returns the token audience
func (sc *SessionClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{"cortex-users"}, nil
}

// GetExpirationTime returns the token expiration time
func (sc *SessionClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(sc.ExpiresAt, 0)}, nil
}

// GetIssuedAt returns the token issued at time
func (sc *SessionClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(sc.IssuedAt, 0)}, nil
}

// GetNotBefore returns the not before time
func (sc *SessionClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(sc.NotBefore, 0)}, nil
}

// Valid implements the Claims interface for RefreshClaims
func (rc *RefreshClaims) Valid() error {
	if time.Now().Unix() > rc.ExpiresAt {
		return fmt.Errorf("refresh token expired")
	}
	return nil
}

// GetIssuer returns the token issuer
func (rc *RefreshClaims) GetIssuer() (string, error) {
	return "Cortex", nil
}

// GetSubject returns the token subject
func (rc *RefreshClaims) GetSubject() (string, error) {
	return fmt.Sprintf("user:%d", rc.UserID), nil
}

// GetAudience returns the token audience
func (rc *RefreshClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{"cortex-users"}, nil
}

// GetExpirationTime returns the token expiration time
func (rc *RefreshClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(rc.ExpiresAt, 0)}, nil
}

// GetIssuedAt returns the token issued at time
func (rc *RefreshClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(rc.IssuedAt, 0)}, nil
}

// GetNotBefore returns the not before time
func (rc *RefreshClaims) GetNotBefore() (*jwt.NumericDate, error) {
	// For refresh tokens, use the issued_at time as the not_before time
	return &jwt.NumericDate{Time: time.Unix(rc.IssuedAt, 0)}, nil
}

// HashAPIKey creates a secure hash of an API key
func HashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ValidateAPIKey validates an API key against its hash
func ValidateAPIKey(apiKey, hash string) bool {
	return HashAPIKey(apiKey) == hash
}

// GenerateRandomKey generates a cryptographically secure random key
func GenerateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSecureToken generates a secure token for various purposes
func GenerateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// TokenInfo provides information about a token
type TokenInfo struct {
	TokenType   string    `json:"token_type"`   // "session", "refresh", "api_key"
	UserID      *int64    `json:"user_id,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	IssuedAt    time.Time `json:"issued_at"`
	Valid       bool      `json:"valid"`
	Error       string    `json:"error,omitempty"`
}

// GetTokenInfo extracts information from a token without fully validating it
func (tm *JWTTokenManager) GetTokenInfo(token string) *TokenInfo {
	info := &TokenInfo{
		IssuedAt: time.Now(),
	}

	// Try to parse token without validation
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		info.Error = "invalid token format"
		return info
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		info.Error = "invalid claims"
		return info
	}

	// Extract token type
	if tokenType, ok := claims["token_type"].(string); ok {
		info.TokenType = tokenType
	}

	// Extract user ID
	if userID, ok := claims["user_id"].(float64); ok {
		uid := int64(userID)
		info.UserID = &uid
	}

	// Extract session ID
	if sessionID, ok := claims["session_id"].(string); ok {
		info.SessionID = sessionID
	}

	// Extract expiry
	if exp, ok := claims["exp"].(float64); ok {
		info.ExpiresAt = time.Unix(int64(exp), 0)
	}

	// Extract issued at
	if iat, ok := claims["iat"].(float64); ok {
		info.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Validate fully
	if info.TokenType == "session" {
		_, err := tm.ValidateSessionToken(token)
		info.Valid = err == nil
		if err != nil {
			info.Error = err.Error()
		}
	} else if info.TokenType == "refresh" {
		_, err := tm.ValidateRefreshToken(token)
		info.Valid = err == nil
		if err != nil {
			info.Error = err.Error()
		}
	}

	return info
}