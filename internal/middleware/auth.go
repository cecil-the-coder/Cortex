package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	APIKey         string
	EnableCORS     bool
	AllowedOrigins []string
	PublicPaths    []string
	// APIKeyFunc allows for dynamic API key lookup from live configuration
	APIKeyFunc     func() string
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// AuthMiddleware creates an authentication middleware
func AuthMiddleware(config *AuthConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = &AuthConfig{
			PublicPaths: []string{"/", "/health"},
		}
	}

	// Ensure public paths are set
	if config.PublicPaths == nil {
		config.PublicPaths = []string{"/", "/health"}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is public
			if isPublicPath(r.URL.Path, config.PublicPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from request
			apiKey := extractAPIKey(r)

			// Get the current API key (static or dynamic)
			var currentAPIKey string
			if config.APIKeyFunc != nil {
				currentAPIKey = config.APIKeyFunc()
			} else {
				currentAPIKey = config.APIKey
			}

			// If no API key configured, allow all requests (development mode)
			if currentAPIKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate API key
			if apiKey == "" {
				sendUnauthorized(w, "Missing API key")
				return
			}

			if apiKey != currentAPIKey {
				sendUnauthorized(w, "Invalid API key")
				return
			}

			// Authentication successful
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware creates a CORS middleware
func CORSMiddleware(config *AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !config.EnableCORS {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")

			// Check if request has an API key
			apiKey := extractAPIKey(r)

			// Get the current API key (static or dynamic)
			var currentAPIKey string
			if config.APIKeyFunc != nil {
				currentAPIKey = config.APIKeyFunc()
			} else {
				currentAPIKey = config.APIKey
			}
			hasValidKey := currentAPIKey == "" || apiKey == currentAPIKey

			// If no valid API key, restrict to localhost only
			if !hasValidKey {
				if isLocalhost(origin) {
					setCORSHeaders(w, origin)
				} else {
					// Don't set CORS headers for non-localhost without valid key
					if r.Method == http.MethodOptions {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
			} else {
				// Valid API key - check allowed origins
				if isAllowedOrigin(origin, config.AllowedOrigins) {
					setCORSHeaders(w, origin)
				} else if isLocalhost(origin) {
					// Always allow localhost
					setCORSHeaders(w, origin)
				}
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ChainMiddleware chains multiple middleware functions
func ChainMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply middleware in reverse order so they execute in the order provided
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// extractAPIKey extracts the API key from the request
func extractAPIKey(r *http.Request) string {
	// Check Authorization header (Bearer token)
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

// isPublicPath checks if a path is public
func isPublicPath(path string, publicPaths []string) bool {
	for _, publicPath := range publicPaths {
		if path == publicPath {
			return true
		}
	}
	return false
}

// isLocalhost checks if an origin is localhost
func isLocalhost(origin string) bool {
	if origin == "" {
		return false
	}

	return strings.Contains(origin, "localhost") ||
		strings.Contains(origin, "127.0.0.1") ||
		strings.Contains(origin, "[::1]")
}

// isAllowedOrigin checks if an origin is in the allowed list
func isAllowedOrigin(origin string, allowedOrigins []string) bool {
	if origin == "" {
		return false
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed || allowed == "*" {
			return true
		}
	}

	return false
}

// setCORSHeaders sets CORS headers
func setCORSHeaders(w http.ResponseWriter, origin string) {
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// sendUnauthorized sends an unauthorized response
func sendUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := ErrorResponse{
		Type:    "authentication_error",
		Message: message,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If encoding fails, we can't do much more than log it
		// In a production system, you might want to log this error
	}
}
