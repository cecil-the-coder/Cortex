package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Context keys for storing authentication information
type contextKey string

const (
	UserContextKey    contextKey = "user"
	SessionContextKey contextKey = "session"
	TokenContextKey   contextKey = "token"
	ClaimsContextKey  contextKey = "claims"
)

// AuthMiddleware provides authentication middleware
type AuthMiddleware struct {
	authManager AuthenticationManager
	tokenManager TokenManager
	auditLogger  AuditLogger
	rateLimiter  RateLimiter
	publicPaths  map[string][]string
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(
	authManager AuthenticationManager,
	tokenManager TokenManager,
	auditLogger AuditLogger,
	rateLimiter RateLimiter,
) *AuthMiddleware {
	return &AuthMiddleware{
		authManager: authManager,
		tokenManager: tokenManager,
		auditLogger:  auditLogger,
		rateLimiter:  rateLimiter,
		publicPaths: map[string][]string{
			"GET": {
				"/health",
				"/v1/health",
				"/",
				"/login",
				"/v1/auth/login",
				"/admin/login",
				"/forgot-password",
				"/v1/auth/forgot-password",
				"/reset-password",
				"/v1/auth/reset-password",
			},
			"POST": {
				"/login",
				"/v1/auth/login",
				"/forgot-password",
				"/v1/auth/forgot-password",
				"/reset-password",
				"/v1/auth/reset-password",
			},
		},
	}
}

// JWTAuthMiddleware handles JWT authentication for admin APIs
func (am *AuthMiddleware) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path is public
		if am.isPublicPath(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from request
		token := am.extractToken(r)
		if token == "" {
			am.sendAuthError(w, http.StatusUnauthorized, "missing_token", "Authentication token is required")
			return
		}

		// Validate token
		claims, err := am.tokenManager.ValidateSessionToken(token)
		if err != nil {
			am.auditLogger.LogSystemAction(r.Context(), "token_validation_failed", "auth_token", "", map[string]interface{}{
				"error": err.Error(),
				"token": token[:min(len(token), 10)] + "...",
			}, false, am.getClientIP(r), r.Header.Get("User-Agent"))
			am.sendAuthError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
			return
		}

		// Get user and session information
		user, session, err := am.authManager.ValidateSession(r.Context(), token)
		if err != nil {
			am.auditLogger.LogSystemAction(r.Context(), "session_validation_failed", "session", claims.SessionID, map[string]interface{}{
				"error": err.Error(),
				"user_id": claims.UserID,
			}, false, am.getClientIP(r), r.Header.Get("User-Agent"))
			am.sendAuthError(w, http.StatusUnauthorized, "invalid_session", "Invalid session")
			return
		}

		// Check if session is still active
		if !session.Active || time.Now().After(session.ExpiresAt) {
			am.auditLogger.LogUserAction(r.Context(), user.ID, "session_expired", "session", session.ID, map[string]interface{}{
				"ip_address": am.getClientIP(r),
			}, true, am.getClientIP(r), r.Header.Get("User-Agent"))
			am.sendAuthError(w, http.StatusUnauthorized, "session_expired", "Session has expired")
			return
		}

		// Update session activity
		if _, _, err := am.authManager.ValidateSession(r.Context(), token); err == nil {
			// Session activity would be updated in the auth manager
		}

		// Store user and session in context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, SessionContextKey, session)
		ctx = context.WithValue(ctx, TokenContextKey, token)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		// Log successful authentication
		am.auditLogger.LogUserAction(r.Context(), user.ID, "api_access", "admin_api", "", map[string]interface{}{
			"endpoint":   r.URL.Path,
			"method":     r.Method,
			"ip_address": am.getClientIP(r),
		}, true, am.getClientIP(r), r.Header.Get("User-Agent"))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminAPIKeyAuthMiddleware handles API key authentication for admin APIs
func (am *AuthMiddleware) AdminAPIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path is public
		if am.isPublicPath(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract API key from request
		apiKey := am.extractAPIKey(r)
		if apiKey == "" {
			am.sendAuthError(w, http.StatusUnauthorized, "missing_api_key", "API key is required")
			return
		}

		// Validate API key
		keyInfo, err := am.authManager.ValidateAdminAPIKey(r.Context(), apiKey)
		if err != nil {
			am.auditLogger.LogSystemAction(r.Context(), "api_key_validation_failed", "admin_api_key", "", map[string]interface{}{
				"error": err.Error(),
				"api_key_prefix": apiKey[:min(len(apiKey), 8)],
			}, false, am.getClientIP(r), r.Header.Get("User-Agent"))
			am.sendAuthError(w, http.StatusUnauthorized, "invalid_api_key", "Invalid API key")
			return
		}

		// Check if API key is enabled and not expired
		if !keyInfo.Enabled {
			am.sendAuthError(w, http.StatusForbidden, "api_key_disabled", "API key is disabled")
			return
		}

		if keyInfo.ExpiresAt != nil && time.Now().After(*keyInfo.ExpiresAt) {
			am.sendAuthError(w, http.StatusForbidden, "api_key_expired", "API key has expired")
			return
		}

		// Get user if API key is associated with a user
		var user *User
		if keyInfo.UserID != nil {
			// User would be retrieved from the database
		}

		// Store API key info in context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, "api_key", keyInfo)
		ctx = context.WithValue(ctx, "api_key_id", keyInfo.ID)

		// Log successful API key authentication
		am.auditLogger.LogAPIKeyAction(r.Context(), keyInfo.ID, "api_access", "admin_api", "", map[string]interface{}{
			"endpoint": r.URL.Path,
			"method":   r.Method,
		}, true, am.getClientIP(r), r.Header.Get("User-Agent"))

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RoleBasedAuthMiddleware provides role-based access control
func (am *AuthMiddleware) RoleBasedAuthMiddleware(requiredPermissions []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := am.getUserFromContext(r.Context())
			if user == nil {
				am.sendAuthError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
				return
			}

			// Check permissions
			if !am.authManager.HasAllPermissions(user, requiredPermissions) {
				am.auditLogger.LogUserAction(r.Context(), user.ID, "access_denied", "admin_api", r.URL.Path, map[string]interface{}{
					"required_permissions": requiredPermissions,
					"endpoint": r.URL.Path,
					"method": r.Method,
				}, false, am.getClientIP(r), r.Header.Get("User-Agent"))
				am.sendAuthError(w, http.StatusForbidden, "insufficient_permissions", "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware provides rate limiting
func (am *AuthMiddleware) RateLimitMiddleware(endpoint string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identifier := am.getClientIP(r)

			// Check if user is authenticated for more specific rate limiting
			if user := am.getUserFromContext(r.Context()); user != nil {
				identifier = fmt.Sprintf("user:%d", user.ID)
			} else if apiKeyID := am.getAPIKeyIDFromContext(r.Context()); apiKeyID != nil {
				identifier = fmt.Sprintf("apikey:%d", *apiKeyID)
			}

			allowed, resetTime := am.rateLimiter.Allow(identifier, endpoint)
			if !allowed {
				limit, _ := am.rateLimiter.Limit(identifier, endpoint)
				resetTimeUnix := time.Now().Add(resetTime).Unix()
				headers := map[string]string{
					"X-RateLimit-Limit":     fmt.Sprintf("%d", limit),
					"X-RateLimit-Remaining": "0",
					"X-RateLimit-Reset":     fmt.Sprintf("%d", resetTimeUnix),
					"Retry-After":           fmt.Sprintf("%.0f", resetTime.Seconds()),
				}

				for key, value := range headers {
					w.Header().Set(key, value)
				}

				am.sendError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Rate limit exceeded")
				return
			}

			// Add rate limit headers
			limit, _ := am.rateLimiter.Limit(identifier, endpoint)
			burst := am.rateLimiter.Burst(identifier, endpoint)
			remaining := limit - burst
			if remaining < 0 {
				remaining = 0
			}

			resetTimeUnix := time.Now().Add(resetTime).Unix()
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTimeUnix))

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersMiddleware adds security headers
func (am *AuthMiddleware) SecurityHeadersMiddleware(securityConfig *SecurityConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HTTPS enforcement
			if securityConfig.RequireHTTPS && r.Header.Get("X-Forwarded-Proto") != "https" && r.TLS == nil {
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return
			}

			// Security headers
			if securityConfig.StrictTransportSecurity {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}

			if securityConfig.FrameOptions != "" {
				w.Header().Set("X-Frame-Options", securityConfig.FrameOptions)
			} else {
				w.Header().Set("X-Frame-Options", "DENY")
			}

			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			if securityConfig.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", securityConfig.ContentSecurityPolicy)
			}

			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			next.ServeHTTP(w, r)
		})
	}
}

// IPWhitelistMiddleware provides IP allowlisting
func (am *AuthMiddleware) IPWhitelistMiddleware(allowedIPs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowedIPs) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := am.getClientIP(r)
			if !am.isIPAllowed(clientIP, allowedIPs) {
				am.auditLogger.LogSystemAction(r.Context(), "ip_blocked", "auth", "", map[string]interface{}{
					"ip_address": clientIP,
					"allowed_ips": allowedIPs,
				}, false, clientIP, r.Header.Get("User-Agent"))
				am.sendError(w, http.StatusForbidden, "ip_blocked", "IP address not allowed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS Middleware for admin API
func (am *AuthMiddleware) CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Set CORS headers if origin is allowed or if it's a same-origin request
			if origin == "" || am.isOriginAllowed(origin, allowedOrigins) {
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper methods

func (am *AuthMiddleware) isPublicPath(method, path string) bool {
	if paths, ok := am.publicPaths[method]; ok {
		for _, publicPath := range paths {
			if strings.HasPrefix(path, publicPath) {
				return true
			}
		}
	}
	return false
}

func (am *AuthMiddleware) extractToken(r *http.Request) string {
	// Check Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return strings.TrimSpace(parts[1])
		}
	}

	// Check x-auth-token header
	token := r.Header.Get("x-auth-token")
	if token != "" {
		return strings.TrimSpace(token)
	}

	// Check query parameter
	return r.URL.Query().Get("token")
}

func (am *AuthMiddleware) extractAPIKey(r *http.Request) string {
	// Check Authorization header (Bearer token for API keys)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return strings.TrimSpace(parts[1])
		}
	}

	// Check x-api-key header
	apiKey := r.Header.Get("x-api-key")
	if apiKey != "" {
		return strings.TrimSpace(apiKey)
	}

	return ""
}

func (am *AuthMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

func (am *AuthMiddleware) isIPAllowed(ip string, allowedIPs []string) bool {
	for _, allowedIP := range allowedIPs {
		if ip == allowedIP {
			return true
		}
		// Add CIDR matching if needed in the future
	}
	return false
}

func (am *AuthMiddleware) isOriginAllowed(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return true // Same-origin request
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (am *AuthMiddleware) getUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(UserContextKey).(*User); ok {
		return user
	}
	return nil
}

func (am *AuthMiddleware) getAPIKeyIDFromContext(ctx context.Context) *int64 {
	if apiKeyID, ok := ctx.Value("api_key_id").(int64); ok {
		return &apiKeyID
	}
	return nil
}

func (am *AuthMiddleware) sendAuthError(w http.ResponseWriter, status int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]interface{}{
		"error": errorType,
		"message": message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Encode and send response
	_ = json.NewEncoder(w).Encode(response)
}

func (am *AuthMiddleware) sendError(w http.ResponseWriter, status int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]interface{}{
		"error": errorType,
		"message": message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}