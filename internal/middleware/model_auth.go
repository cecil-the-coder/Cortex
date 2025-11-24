package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/access"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// Context keys for storing authentication and model access information
type contextKey string

const (
	AccessInfoKey   contextKey = "access_info"
	APIKeyIDKey     contextKey = "api_key_id"
	ModelNameKey    contextKey = "model_name"
	ProviderKey     contextKey = "provider"
)

// ModelAuthConfig holds configuration for the model authentication middleware
type ModelAuthConfig struct {
	AccessManager      *access.AccessManager
	PublicPaths       []string
	EnableLegacyFallback bool
	ModelHeader       string // Header name to extract model from (optional)
	ModelQueryParam   string // Query parameter name to extract model from (optional)
}

// ModelErrorResponse represents a model access error response
type ModelErrorResponse struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`
}

// ModelAuthMiddleware creates an enhanced authentication middleware that validates
// API keys and model access permissions
func ModelAuthMiddleware(config *ModelAuthConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = &ModelAuthConfig{
			PublicPaths:      []string{"/", "/health", "/models"},
		}
	}

	// Set defaults
	if config.PublicPaths == nil {
		config.PublicPaths = []string{"/", "/health", "/models"}
	}
	if config.ModelHeader == "" {
		config.ModelHeader = "x-model"
	}
	if config.ModelQueryParam == "" {
		config.ModelQueryParam = "model"
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
			if apiKey == "" {
				sendModelAuthError(w, "Missing API key", http.StatusUnauthorized, r.Header.Get("x-request-id"))
				return
			}

			// Extract model from request
			model, err := extractModelFromRequest(r, config.ModelHeader, config.ModelQueryParam)
			if err != nil {
				sendModelAuthError(w, err.Error(), http.StatusBadRequest, r.Header.Get("x-request-id"))
				return
			}

			if model == "" {
				sendModelAuthError(w, "Model not specified", http.StatusBadRequest, r.Header.Get("x-request-id"))
				return
			}

			// Validate API key and model access
			ctx := r.Context()
			accessInfo, err := config.AccessManager.CanAccessModel(ctx, apiKey, model)
			if err != nil {
				// Get available models for this API key to provide helpful suggestions
				availableModels := []string{}
				if models, getErr := config.AccessManager.GetAvailableModels(apiKey); getErr == nil {
					availableModels = models
				}

				// Determine appropriate status code based on error
				statusCode := http.StatusForbidden
				if strings.Contains(err.Error(), "API key validation failed") || strings.Contains(err.Error(), "invalid API key") {
					statusCode = http.StatusUnauthorized
				} else if strings.Contains(err.Error(), "model not found") {
					statusCode = http.StatusNotFound
				} else if strings.Contains(err.Error(), "rate limit") {
					statusCode = http.StatusTooManyRequests
				}

				// Use enhanced error response with model suggestions
				sendModelAccessError(w, err.Error(), statusCode, r.Header.Get("x-request-id"), model, availableModels)
				return
			}

			// Add access information to request context
			ctx = context.WithValue(ctx, AccessInfoKey, accessInfo)
			ctx = context.WithValue(ctx, ModelNameKey, accessInfo.ResolvedModel)
			ctx = context.WithValue(ctx, ProviderKey, accessInfo.ProviderName)

			// Add API key ID if available (for logging/auditing)
			if accessInfo.APIKeyConfig != nil {
				ctx = context.WithValue(ctx, APIKeyIDKey, getKeyIdentifier(accessInfo.APIKeyConfig))
			}

			// Continue with modified context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalModelAuthMiddleware is a lighter version that only validates API keys
// but doesn't require model specification (useful for endpoints that don't need model access)
func OptionalModelAuthMiddleware(config *ModelAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path is public
			if isPublicPath(r.URL.Path, config.PublicPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from request
			apiKey := extractAPIKey(r)
			if apiKey == "" {
				sendModelAuthError(w, "Missing API key", http.StatusUnauthorized, r.Header.Get("x-request-id"))
				return
			}

			// Just validate API key without model checking
			keyConfig, err := config.AccessManager.ValidateAPIKey(apiKey)
			if err != nil {
				sendModelAuthError(w, err.Error(), http.StatusUnauthorized, r.Header.Get("x-request-id"))
				return
			}

			// Add API key information to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, APIKeyIDKey, getKeyIdentifier(keyConfig))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAccessInfoFromContext retrieves access information from the request context
func GetAccessInfoFromContext(r *http.Request) (*access.AccessInfo, bool) {
	accessInfo, ok := r.Context().Value(AccessInfoKey).(*access.AccessInfo)
	return accessInfo, ok
}

// GetAPIKeyIDFromContext retrieves the API key identifier from the request context
func GetAPIKeyIDFromContext(r *http.Request) (string, bool) {
	apiKeyID, ok := r.Context().Value(APIKeyIDKey).(string)
	return apiKeyID, ok
}

// GetModelNameFromContext retrieves the resolved model name from the request context
func GetModelNameFromContext(r *http.Request) (string, bool) {
	modelName, ok := r.Context().Value(ModelNameKey).(string)
	return modelName, ok
}

// GetProviderFromContext retrieves the resolved provider from the request context
func GetProviderFromContext(r *http.Request) (string, bool) {
	provider, ok := r.Context().Value(ProviderKey).(string)
	return provider, ok
}

// extractModelFromRequest extracts the model name from various request sources
func extractModelFromRequest(r *http.Request, headerName, queryParam string) (string, error) {
	// Try to get model from path for OpenAI-compatible endpoints
	// OpenAI format: /v1/chat/completions, /v1/models/{model}, etc.
	if r == nil || r.URL == nil {
		return "", nil
	}
	path := r.URL.Path

	// Extract model from path if it's a model-specific endpoint
	if strings.HasPrefix(path, "/v1/models/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 4 {
			model := parts[3]
			if model != "" {
				return model, nil
			}
		}
	}

	// For streaming endpoints, check if model is in query string
	if strings.Contains(path, "/chat/completions") || strings.Contains(path, "/completions") {
		// Try to get model from query parameter
		if model := r.URL.Query().Get(queryParam); model != "" {
			return model, nil
		}
	}

	// Try to get model from custom header
	if model := r.Header.Get(headerName); model != "" {
		return model, nil
	}

	// For POST requests, try to parse JSON body to extract model
	if r.Method == http.MethodPost {
		// Only read body if it hasn't been read yet
		if r.Body != nil && r.ContentLength > 0 {
			// Read the body to preserve it for downstream handlers
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				return "", nil // Return empty model on read error, don't fail
			}

			// Restore the body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Parse JSON body to extract model
			var request map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &request); err == nil {
				if model, ok := request["model"].(string); ok && model != "" {
					return model, nil
				}

				// Check if this is a chat completion - model should be at top level
				if _, ok := request["messages"].([]interface{}); ok {
					// This is a chat completion, model should already be checked above
				}
			}
		}
	}

	return "", nil // No model found, but that's not necessarily an error
}

// sendModelAuthError sends a standardized error response for model authentication failures
func sendModelAuthError(w http.ResponseWriter, message string, statusCode int, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	// Create enhanced error response with more detailed information
	response := ModelErrorResponse{
		Type:      "model_access_error",
		Message:   message,
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
	}

	// Add rate limit headers if applicable
	if statusCode == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60") // Suggest retry after 60 seconds
	}

	// Add additional context for specific error types
	if statusCode == http.StatusForbidden {
		w.Header().Set("X-Error-Type", "access_denied")
		// Add hint for available models if this is a model access issue
		if strings.Contains(strings.ToLower(message), "access") || strings.Contains(strings.ToLower(message), "model") {
			w.Header().Set("X-Hint", "Check /v1/models endpoint for available models or verify API key permissions")
		}
	} else if statusCode == http.StatusNotFound {
		w.Header().Set("X-Error-Type", "model_not_found")
		w.Header().Set("X-Hint", "Verify model name spelling or check /v1/models for available options")
	} else if statusCode == http.StatusUnauthorized {
		w.Header().Set("X-Error-Type", "invalid_api_key")
		w.Header().Set("X-Hint", "Verify API key is valid and has proper permissions")
	}

	_ = json.NewEncoder(w).Encode(response)
}

// sendModelAccessError sends a more specific error for model access issues
func sendModelAccessError(w http.ResponseWriter, message string, statusCode int, requestID string, originalModel string, availableModels []string) {
	w.Header().Set("Content-Type", "application/json")

	// Set X-Error-Type header based on status code
	switch statusCode {
	case http.StatusUnauthorized:
		w.Header().Set("X-Error-Type", "invalid_api_key")
	case http.StatusNotFound:
		w.Header().Set("X-Error-Type", "model_not_found")
	case http.StatusForbidden:
		w.Header().Set("X-Error-Type", "access_denied")
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "60")
	}

	w.WriteHeader(statusCode)

	// Create comprehensive error response
	response := map[string]interface{}{
		"type":      "model_access_error",
		"message":   message,
		"timestamp": time.Now().UTC(),
		"request_id": requestID,
	}

	// Add model-specific information
	if originalModel != "" {
		response["requested_model"] = originalModel
	}

	if len(availableModels) > 0 {
		response["available_models"] = availableModels
		response["model_count"] = len(availableModels)

		// Suggest similar models if available
		similarModels := suggestSimilarModels(originalModel, availableModels)
		if len(similarModels) > 0 {
			response["suggested_alternatives"] = similarModels
		}
	}

	// Add retry information for rate limit errors
	if statusCode == http.StatusTooManyRequests {
		response["retry_after"] = 60
		response["retry_after_seconds"] = 60
	}

	// Add helpful hints
	response["hints"] = []string{
		"Use the /v1/models endpoint to see available models",
		"Verify your API key has proper model permissions",
		"Check model spelling and case sensitivity",
	}

	_ = json.NewEncoder(w).Encode(response)
}

// suggestSimilarModels suggests models that are similar to the requested model
func suggestSimilarModels(requestedModel string, availableModels []string) []string {
	if requestedModel == "" {
		return nil
	}

	requestedLower := strings.ToLower(requestedModel)
	var similar []string

	for _, model := range availableModels {
		modelLower := strings.ToLower(model)
		// Skip exact matches
		if modelLower == requestedLower {
			continue
		}
		if strings.Contains(modelLower, requestedLower) || strings.Contains(requestedLower, modelLower) {
			similar = append(similar, model)
		}
	}

	// Limit suggestions to top 3 most similar
	if len(similar) > 3 {
		similar = similar[:3]
	}

	return similar
}

// getKeyIdentifier generates a consistent identifier for an API key configuration
func getKeyIdentifier(keyConfig *config.APIKeyConfig) string {
	// For security, don't expose the actual API key
	// Use a hash or description instead
	if keyConfig.Description != "" {
		return keyConfig.Description
	}

	// Fallback to a truncated hash of the API key
	if len(keyConfig.APIKey) >= 8 {
		return "key:" + keyConfig.APIKey[:4] + "..."
	}

	return "key:unknown"
}

// ModelListHandler creates a handler that returns available models for the authenticated API key
func ModelListHandler(config *ModelAuthConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from request
		apiKey := extractAPIKey(r)
		if apiKey == "" {
			sendModelAuthError(w, "Missing API key", http.StatusUnauthorized, r.Header.Get("x-request-id"))
			return
		}

		// Get available models for this API key
		models, err := config.AccessManager.GetAvailableModels(apiKey)
		if err != nil {
			sendModelAuthError(w, err.Error(), http.StatusUnauthorized, r.Header.Get("x-request-id"))
			return
		}

		// Return OpenAI-compatible models response
		response := map[string]interface{}{
			"object": "list",
			"data":   makeModelList(models),
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// makeModelList creates an OpenAI-compatible model list structure
func makeModelList(models []string) []map[string]interface{} {
	data := make([]map[string]interface{}, len(models))

	for i, model := range models {
		data[i] = map[string]interface{}{
			"id":      model,
			"object":  "model",
			"created": time.Now().Unix(),
			"owned_by": "router",
		}
	}

	return data
}

// HealthCheckWithAuth creates a health check endpoint that includes model access manager stats
func HealthCheckWithAuth(config *ModelAuthConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats := config.AccessManager.GetStats()

		response := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
			"model_auth_stats": stats,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}