package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cecil-the-coder/Cortex/internal/access"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// TestModelAuthMiddleware tests the main model authentication middleware
func TestModelAuthMiddleware(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)
	// Clear rate limiters before tests to ensure clean state
	accessManager.ClearRateLimiters()

	middlewareConfig := &ModelAuthConfig{
		AccessManager:        accessManager,
		PublicPaths:         []string{"/", "/health", "/models"},
		EnableLegacyFallback: true,
		ModelHeader:         "x-model",
		ModelQueryParam:     "model",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store the context in the response for testing
		if r.Context() != nil {
			accessInfo, _ := GetAccessInfoFromContext(r)
			modelName, _ := GetModelNameFromContext(r)
			provider, _ := GetProviderFromContext(r)
			apiKeyID, _ := GetAPIKeyIDFromContext(r)

			response := map[string]interface{}{
				"access_info": accessInfo,
				"model_name":  modelName,
				"provider":    provider,
				"api_key_id":  apiKeyID,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}
	})

	authenticatedHandler := ModelAuthMiddleware(middlewareConfig)(handler)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           string
		queryParams    map[string]string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "public path access",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "public paths list",
			method:         "GET",
			path:           "/models",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing API key",
			method:         "POST",
			path:           "/v1/chat/completions",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Missing API key",
		},
		{
			name:   "missing model",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Model not specified",
		},
		{
			name:   "valid request with model in header",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
				"x-model":       "claude-prod", // Valid alias
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "valid request with model in query param",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
			},
			queryParams: map[string]string{
				"model": "claude-prod",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "valid request with model in body",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
				"Content-Type":  "application/json",
			},
			body:           `{"model": "claude-prod", "messages": [{"role": "user", "content": "test"}]}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "invalid API key",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer invalid-key",
				"x-model":       "claude-prod",
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid API key",
		},
		{
			name:   "model access denied",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
				"x-model":       "claude-dev", // Not in production group
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "does not have access to model",
		},
		{
			name:   "non-existent model",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
				"x-model":       "nonexistent-model",
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "model not found",
		},
		{
			name:   "unrestricted key access",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer unrestricted-api-key-456",
				"x-model":       "claude-dev",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "legacy API key access",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Authorization": "Bearer legacy-router-key",
				"x-model":       "claude-3-sonnet",
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)

			if tt.body != "" {
				req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
				if req.Header.Get("Content-Type") == "" {
					req.Header.Set("Content-Type", "application/json")
				}
			}

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add query params
			if tt.queryParams != nil {
				q := req.URL.Query()
				for key, value := range tt.queryParams {
					q.Set(key, value)
				}
				req.URL.RawQuery = q.Encode()
			}

			w := httptest.NewRecorder()
			authenticatedHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedError != "" {
				var errorResp ModelErrorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &errorResp); err != nil {
					t.Errorf("Failed to unmarshal error response: %v", err)
				} else if !strings.Contains(errorResp.Message, tt.expectedError) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedError, errorResp.Message)
				}
			}

			// For successful requests that require authentication, check context values from response
			if tt.expectedStatus == http.StatusOK && !isPublicPath(tt.path, []string{"/", "/health", "/models"}) {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
				} else {
					// Check that all context values were propagated to the handler
					if response["access_info"] == nil {
						t.Error("Access info should be in response from context")
					}
					if response["model_name"] == nil || response["model_name"] == "" {
						t.Error("Model name should be in response from context")
					}
					if response["provider"] == nil || response["provider"] == "" {
						t.Error("Provider should be in response from context")
					}
					if response["api_key_id"] == nil || response["api_key_id"] == "" {
						t.Error("API Key ID should be in response from context")
					}

					t.Logf("Context values from response - Model: %v, Provider: %v, APIKeyID: %v, AccessInfo: %v",
						response["model_name"], response["provider"], response["api_key_id"], response["access_info"])
				}
			}
		})
	}
}

// TestOptionalModelAuthMiddleware tests the optional model authentication middleware
func TestOptionalModelAuthMiddleware(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)
	accessManager.ClearRateLimiters()

	middlewareConfig := &ModelAuthConfig{
		AccessManager: accessManager,
		PublicPaths:  []string{"/", "/health"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For testing, return context info in response
		apiKeyID, _ := GetAPIKeyIDFromContext(r)
		response := map[string]interface{}{
			"api_key_id": apiKeyID,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	optionalHandler := OptionalModelAuthMiddleware(middlewareConfig)(handler)

	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "public path",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:   "valid API key",
			method: "GET",
			path:   "/private-endpoint",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing API key",
			method:         "GET",
			path:           "/private-endpoint",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:   "invalid API key",
			method: "GET",
			path:   "/private-endpoint",
			headers: map[string]string{
				"Authorization": "Bearer invalid-key",
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			optionalHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// For successful requests, check API keyID in response
			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
				} else if tt.path != "/health" {
					if response["api_key_id"] == nil || response["api_key_id"] == "" {
						t.Error("API Key ID should be in response for authenticated requests")
					}
				}
			}
		})
	}
}

// TestModelExtractionFunctions tests model extraction from requests
func TestModelExtractionFunctions(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		path          string
		headers       map[string]string
		body          string
		expectedModel string
	}{
		{
			name:   "model from header",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"x-model": "claude-prod",
			},
			expectedModel: "claude-prod",
		},
		{
			name:          "model from query param",
			method:        "POST",
			path:          "/v1/chat/completions?model=claude-prod",
			expectedModel: "claude-prod",
		},
		{
			name:   "model from body - chat completions",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:          `{"model": "claude-3-sonnet", "messages": []}`,
			expectedModel: "claude-3-sonnet",
		},
		{
			name:   "model from body - completions",
			method: "POST",
			path:   "/v1/completions",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:          `{"model": "gpt-4", "prompt": "test"}`,
			expectedModel: "gpt-4",
		},
		{
			name:   "model from models endpoint path",
			method: "GET",
			path:   "/v1/models/claude-prod",
			expectedModel: "claude-prod",
		},
		{
			name:          "no model specified",
			method:        "POST",
			path:          "/v1/chat/completions",
			expectedModel: "",
		},
		{
			name:   "invalid JSON body",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body:          `{"invalid json}`,
			expectedModel: "",
		},
		{
			name:   "empty body with content type",
			method: "POST",
			path:   "/v1/chat/completions",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			expectedModel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewReader([]byte(tt.body))
			}

			req := httptest.NewRequest(tt.method, tt.path, body)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Use the standard header and query names
			model, err := extractModelFromRequest(req, "x-model", "model")
			if err != nil {
				t.Errorf("extractModelFromRequest() failed: %v", err)
			}

			if model != tt.expectedModel {
				t.Errorf("Expected model '%s', got '%s'", tt.expectedModel, model)
			}
		})
	}
}

// TestErrorResponseFunctions tests error response formatting
func TestErrorResponseFunctions(t *testing.T) {
	// Clear rate limiters to avoid interference from previous tests
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)
	accessManager.ClearRateLimiters()

	tests := []struct {
		name           string
		statusCode     int
		message        string
		requestId      string
		originalModel  string
		availableModels []string
		expectedFields []string
	}{
		{
			name:       "basic error response",
			statusCode: http.StatusUnauthorized,
			message:    "Invalid API key",
			requestId:  "test-123",
			expectedFields: []string{"type", "message", "timestamp", "request_id"},
		},
		{
			name:           "model access error with suggestions",
			statusCode:     http.StatusForbidden,
			message:        "Access denied",
			requestId:      "test-456",
			originalModel:  "claude",
			availableModels: []string{"claude-prod", "claude-dev", "gpt-4"},
			expectedFields: []string{"type", "message", "timestamp", "request_id", "requested_model", "available_models", "suggested_alternatives", "hints"},
		},
		{
			name:           "rate limit error",
			statusCode:     http.StatusTooManyRequests,
			message:        "Rate limit exceeded",
			requestId:      "test-789",
			availableModels: []string{}, // Add empty array to trigger sendModelAccessError
			expectedFields: []string{"type", "message", "timestamp", "request_id", "retry_after"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			if tt.availableModels != nil {
				// Test sendModelAccessError (enhanced error)
				sendModelAccessError(w, tt.message, tt.statusCode, tt.requestId, tt.originalModel, tt.availableModels)
			} else {
				// Test sendModelAuthError (basic error)
				sendModelAuthError(w, tt.message, tt.statusCode, tt.requestId)
			}

			if w.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
			}

			// Check response headers
			if tt.statusCode == http.StatusTooManyRequests {
				if retryAfter := w.Header().Get("Retry-After"); retryAfter == "" {
					t.Error("Retry-After header should be set for rate limit errors")
				}
			}

			// Parse response body
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Errorf("Failed to unmarshal response: %v", err)
			}

			// Check expected fields
			for _, field := range tt.expectedFields {
				if _, exists := response[field]; !exists {
					t.Errorf("Response should contain field '%s': %v", field, response)
				}
			}

			// Check specific values
			if response["type"].(string) != "model_access_error" {
				t.Errorf("Expected type 'model_access_error', got '%s'", response["type"])
			}

			if response["message"].(string) != tt.message {
				t.Errorf("Expected message '%s', got '%s'", tt.message, response["message"])
			}

			if tt.requestId != "" {
				if response["request_id"].(string) != tt.requestId {
					t.Errorf("Expected request_id '%s', got '%s'", tt.requestId, response["request_id"])
				}
			}
		})
	}
}

// TestModelSuggestionFunctions tests model suggestion logic
func TestModelSuggestionFunctions(t *testing.T) {
	tests := []struct {
		name             string
		requestedModel   string
		availableModels  []string
		expectedCount    int
		expectedContains []string
	}{
		{
			name:           "no suggestions for empty request",
			requestedModel: "",
			availableModels: []string{"claude-prod", "gpt-4"},
			expectedCount:  0,
		},
		{
			name:             "exact match returns empty",
			requestedModel:   "claude-prod",
			availableModels:  []string{"claude-prod", "gpt-4"},
			expectedCount:    0,
		},
		{
			name:           "partial matches",
			requestedModel: "claude",
			availableModels: []string{"claude-prod", "claude-dev", "gpt-4"},
			expectedCount:  2,
			expectedContains: []string{"claude-prod", "claude-dev"},
		},
		{
			name:           "similar but different",
			requestedModel: "gpt",
			availableModels: []string{"claude-prod", "claude-pro", "gpt-4"},
			expectedCount:  1,
			expectedContains: []string{"gpt-4"},
		},
		{
			name:           "no similar models",
			requestedModel: "llama",
			availableModels: []string{"claude-prod", "gpt-4"},
			expectedCount:  0,
		},
		{
			name:           "limit to top 3 suggestions",
			requestedModel: "claude",
			availableModels: []string{"claude-1", "claude-2", "claude-3", "claude-4", "claude-5"},
			expectedCount:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := suggestSimilarModels(tt.requestedModel, tt.availableModels)

			if len(suggestions) != tt.expectedCount {
				t.Errorf("Expected %d suggestions, got %d: %v", tt.expectedCount, len(suggestions), suggestions)
			}

			for _, expected := range tt.expectedContains {
				found := false
				for _, suggestion := range suggestions {
					if suggestion == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected suggestion '%s' not found in %v", expected, suggestions)
				}
			}
		})
	}
}

// TestKeyIdentifierGeneration tests API key identifier generation
func TestKeyIdentifierGeneration(t *testing.T) {
	tests := []struct {
		name           string
		apiKeyConfig   *config.APIKeyConfig
		expectedPrefix string
	}{
		{
			name: "description used when available",
			apiKeyConfig: &config.APIKeyConfig{
				Description: "Test Key Description",
				APIKey:      "test-api-key-123",
			},
			expectedPrefix: "Test Key Description",
		},
		{
			name: "key prefix used when no description",
			apiKeyConfig: &config.APIKeyConfig{
				Description: "",
				APIKey:      "test-api-key-123",
			},
			expectedPrefix: "key:test...",
		},
		{
			name: "unknown for short key without description",
			apiKeyConfig: &config.APIKeyConfig{
				Description: "",
				APIKey:      "short",
			},
			expectedPrefix: "key:unknown",
		},
		{
			name: "key prefix used for long key without description",
			apiKeyConfig: &config.APIKeyConfig{
				Description: "",
				APIKey:      "very-long-api-key-1234567890",
			},
			expectedPrefix: "key:very...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identifier := getKeyIdentifier(tt.apiKeyConfig)

			if !strings.HasPrefix(identifier, tt.expectedPrefix) {
				t.Errorf("Expected identifier to start with '%s', got '%s'", tt.expectedPrefix, identifier)
			}

			// Ensure no full API key is exposed
			if strings.Contains(identifier, tt.apiKeyConfig.APIKey) && tt.apiKeyConfig.Description == "" {
				if len(tt.apiKeyConfig.APIKey) > 8 {
					t.Errorf("Full API key should not be exposed in identifier: %s", identifier)
				}
			}
		})
	}
}

// TestModelListHandler tests the model list endpoint
func TestModelListHandler(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	middlewareConfig := &ModelAuthConfig{
		AccessManager: accessManager,
	}

	handler := ModelListHandler(middlewareConfig)

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedModels []string
	}{
		{
			name:           "missing API key",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "invalid API key",
			headers: map[string]string{
				"Authorization": "Bearer invalid-key",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "unrestricted key gets all models",
			headers: map[string]string{
				"Authorization": "Bearer unrestricted-api-key-456",
			},
			expectedStatus: http.StatusOK,
			expectedModels: []string{"claude-prod", "claude-dev", "gpt-4"}, // Sample expected models
		},
		{
			name: "restricted key gets allowed models",
			headers: map[string]string{
				"Authorization": "Bearer prod-api-key-123",
			},
			expectedStatus: http.StatusOK,
			expectedModels: []string{"claude-prod"}, // Only production models
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/models", nil)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
				}

				if response["object"].(string) != "list" {
					t.Errorf("Expected object 'list', got '%s'", response["object"])
				}

				data, ok := response["data"].([]interface{})
				if !ok {
					t.Error("Response should have data array")
				} else {
					// Check that expected models are in the response
					responseModelIDs := make(map[string]bool)
					for _, item := range data {
						if model, ok := item.(map[string]interface{}); ok {
							if id, exists := model["id"].(string); exists {
								responseModelIDs[id] = true
							}
						}
					}

					for _, expectedModel := range tt.expectedModels {
						if !responseModelIDs[expectedModel] {
							t.Errorf("Expected model '%s' not found in response: %v", expectedModel, responseModelIDs)
						}
					}
				}
			}
		})
	}
}

// TestHealthCheckWithAuth tests the health check endpoint with auth stats
func TestHealthCheckWithAuth(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	middlewareConfig := &ModelAuthConfig{
		AccessManager: accessManager,
	}

	handler := HealthCheckWithAuth(middlewareConfig)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	// Check basic health response structure
	requiredFields := []string{"status", "timestamp", "version", "model_auth_stats"}
	for _, field := range requiredFields {
		if _, exists := response[field]; !exists {
			t.Errorf("Response should contain field '%s'", field)
		}
	}

	// Check model auth stats
	stats, ok := response["model_auth_stats"].(map[string]interface{})
	if !ok {
		t.Error("model_auth_stats should be a map")
	} else {
		requiredStats := []string{"cache_size", "rate_limiters", "cache_ttl_seconds", "legacy_fallback"}
		for _, stat := range requiredStats {
			if _, exists := stats[stat]; !exists {
				t.Errorf("Stats should contain field '%s'", stat)
			}
		}
	}
}

// TestPublicPathDetection tests public path detection logic
func TestPublicPathDetection(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		publicPaths []string
		expected   bool
	}{
		{
			name: "exact match",
			path: "/health",
			publicPaths: []string{"/", "/health", "/models"},
			expected: true,
		},
		{
			name: "root path",
			path: "/",
			publicPaths: []string{"/", "/health"},
			expected: true,
		},
		{
			name: "not in public paths",
			path: "/v1/chat/completions",
			publicPaths: []string{"/", "/health"},
			expected: false,
		},
		{
			name: "substring path (should not match)",
			path: "/health-check",
			publicPaths: []string{"/", "/health"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPublicPath(tt.path, tt.publicPaths)
			if result != tt.expected {
				t.Errorf("Expected %v for path '%s' with public paths %v, got %v",
					tt.expected, tt.path, tt.publicPaths, result)
			}
		})
	}
}

// TestContextHelpers tests context extraction and manipulation functions
func TestContextHelpers(t *testing.T) {
	// Create test access info
	accessInfo := &access.AccessInfo{
		APIKeyConfig: &config.APIKeyConfig{
			APIKey:      "test-key-123",
			Description: "Test Key",
		},
		ModelReference: &config.ModelReference{
			Provider: "anthropic",
			Model:    "claude-3-sonnet",
			Alias:    "claude-prod",
		},
		OriginalModel: "claude-prod",
		ResolvedModel: "claude-3-sonnet",
		ProviderName:  "anthropic",
		ModelGroup:    "production",
		ResolvedBy:    "alias",
	}

	// Create context with values
	ctx := context.Background()
	ctx = context.WithValue(ctx, AccessInfoKey, accessInfo)
	ctx = context.WithValue(ctx, ModelNameKey, "claude-3-sonnet")
	ctx = context.WithValue(ctx, ProviderKey, "anthropic")
	ctx = context.WithValue(ctx, APIKeyIDKey, "Test Key")

	t.Run("GetAccessInfoFromContext", func(t *testing.T) {
		retrievedInfo, exists := GetAccessInfoFromContext(
			httptest.NewRequest("GET", "/", nil).WithContext(ctx),
		)

		if !exists {
			t.Error("Access info should exist in context")
		}

		if retrievedInfo == nil {
			t.Error("Retrieved info should not be nil")
		}

		if retrievedInfo.ModelGroup != "production" {
			t.Errorf("Expected model group 'production', got '%s'", retrievedInfo.ModelGroup)
		}
	})

	t.Run("GetModelNameFromContext", func(t *testing.T) {
		modelName, exists := GetModelNameFromContext(
			httptest.NewRequest("GET", "/", nil).WithContext(ctx),
		)

		if !exists {
			t.Error("Model name should exist in context")
		}

		if modelName != "claude-3-sonnet" {
			t.Errorf("Expected model name 'claude-3-sonnet', got '%s'", modelName)
		}
	})

	t.Run("GetProviderFromContext", func(t *testing.T) {
		provider, exists := GetProviderFromContext(
			httptest.NewRequest("GET", "/", nil).WithContext(ctx),
		)

		if !exists {
			t.Error("Provider should exist in context")
		}

		if provider != "anthropic" {
			t.Errorf("Expected provider 'anthropic', got '%s'", provider)
		}
	})

	t.Run("GetAPIKeyIDFromContext", func(t *testing.T) {
		apiKeyID, exists := GetAPIKeyIDFromContext(
			httptest.NewRequest("GET", "/", nil).WithContext(ctx),
		)

		if !exists {
			t.Error("API key ID should exist in context")
		}

		if apiKeyID != "Test Key" {
			t.Errorf("Expected API key ID 'Test Key', got '%s'", apiKeyID)
		}
	})

	t.Run("missing context values", func(t *testing.T) {
		emptyCtx := context.Background()
		req := httptest.NewRequest("GET", "/", nil).WithContext(emptyCtx)

		if _, exists := GetAccessInfoFromContext(req); exists {
			t.Error("Access info should not exist in empty context")
		}

		if _, exists := GetModelNameFromContext(req); exists {
			t.Error("Model name should not exist in empty context")
		}

		if _, exists := GetProviderFromContext(req); exists {
			t.Error("Provider should not exist in empty context")
		}

		if _, exists := GetAPIKeyIDFromContext(req); exists {
			t.Error("API key ID should not exist in empty context")
		}
	})
}

// TestMiddlewareConfiguration tests middleware configuration options
func TestMiddlewareConfiguration(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("default configuration", func(t *testing.T) {
		middlewareHandler := ModelAuthMiddleware(nil)(handler)

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		middlewareHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("custom configuration", func(t *testing.T) {
		config := &ModelAuthConfig{
			AccessManager: accessManager,
			PublicPaths:  []string{"/custom-public"},
			ModelHeader:  "x-custom-model",
			ModelQueryParam: "custom_model",
		}

		middlewareHandler := ModelAuthMiddleware(config)(handler)

		// Test public path
		req := httptest.NewRequest("GET", "/custom-public", nil)
		w := httptest.NewRecorder()
		middlewareHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d for public path, got %d", http.StatusOK, w.Code)
		}

		// Test model extraction with custom header
		req = httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer prod-api-key-123")
		req.Header.Set("x-custom-model", "claude-prod")

		w = httptest.NewRecorder()
		middlewareHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d with valid credentials and model, got %d", http.StatusOK, w.Code)
		}
	})
}

// TestMiddlewareErrorHandling tests various error handling scenarios
func TestMiddlewareErrorHandling(t *testing.T) {
	cfg := createTestConfig(t)
	accessManager := access.NewAccessManager(cfg)
	accessManager.ClearRateLimiters()

	middlewareConfig := &ModelAuthConfig{
		AccessManager: accessManager,
		PublicPaths:  []string{"/"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := ModelAuthMiddleware(middlewareConfig)(handler)

	tests := []struct {
		name             string
		setupFunc        func(*access.AccessManager)
		requestFunc      func() *http.Request
		expectedStatus   int
		expectedHeader   string
		expectedValue    string
	}{
		{
			name: "invalid API key returns unauthorized header",
			requestFunc: func() *http.Request {
				req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
				req.Header.Set("Authorization", "Bearer invalid-key")
				req.Header.Set("x-model", "claude-prod")
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedHeader: "X-Error-Type",
			expectedValue:  "invalid_api_key",
		},
		{
			name: "model not found returns not found header",
			requestFunc: func() *http.Request {
				req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
				req.Header.Set("Authorization", "Bearer prod-api-key-123")
				req.Header.Set("x-model", "nonexistent-model")
				return req
			},
			expectedStatus: http.StatusNotFound,
			expectedHeader: "X-Error-Type",
			expectedValue:  "model_not_found",
		},
		{
			name: "access denied returns forbidden header",
			requestFunc: func() *http.Request {
				req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
				req.Header.Set("Authorization", "Bearer prod-api-key-123")
				req.Header.Set("x-model", "claude-dev") // Not in production
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedHeader: "X-Error-Type",
			expectedValue:  "access_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc(accessManager)
			}

			req := tt.requestFunc()
			w := httptest.NewRecorder()
			authenticatedHandler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedHeader != "" {
				headerValue := w.Header().Get(tt.expectedHeader)
				if headerValue != tt.expectedValue {
					t.Errorf("Expected header '%s' to be '%s', got '%s'",
						tt.expectedHeader, tt.expectedValue, headerValue)
				}
			}
		})
	}
}

// Helper function to create test configuration for middleware tests
func createTestConfig(t *testing.T) *config.Config {
	modelGroups := config.ModelGroups{
		"production": {
			Description: "Production models",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
			},
		},
		"development": {
			Description: "Development models",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-dev"},
			},
		},
	}

	clientAPIKeys := config.ClientAPIKeys{
		"prod": {
			APIKey:      "prod-api-key-123",
			Description: "Production key",
			ModelGroups: []string{"production"},
			Enabled:     true,
			RateLimit:   100, // Increased for testing
		},
		"unrestricted": {
			APIKey:      "unrestricted-api-key-456",
			Description: "Unrestricted key",
			ModelGroups: []string{}, // Empty = unrestricted
			Enabled:     true,
		},
	}

	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "anthropic-key-123",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-sonnet", "claude-3-haiku"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "openai-key-456",
				BaseURL:    "https://api.openai.com",
				Models:     []string{"gpt-4"},
			},
			{
				Name:       "perplexity",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "perplexity-key-789",
				BaseURL:    "https://api.perplexity.ai",
				Models:     []string{"sonar-pro"},
			},
			{
				Name:       "deepseek",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "deepseek-key-012",
				BaseURL:    "https://api.deepseek.com",
				Models:     []string{"deepseek-reasoner", "deepseek-chat"},
			},
		},
		ModelGroups:   &modelGroups,
		ClientAPIKeys: &clientAPIKeys,
		Router: config.RouterConfig{
			Default:              "anthropic",
			Background:           "openai",
			WebSearch:            "perplexity",
			Think:                "deepseek",
			LongContext:          "anthropic",
			LongContextThreshold: 100000,
		},
		APIKEY: "legacy-router-key", // For legacy fallback testing
	}

	// Validate test configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Test configuration is invalid: %v", err)
	}

	return cfg
}

// BenchmarkMiddleware benchmarks middleware operations
func BenchmarkMiddleware(b *testing.B) {
	cfg := createTestConfig(&testing.T{})
	accessManager := access.NewAccessManager(cfg)

	middlewareConfig := &ModelAuthConfig{
		AccessManager: accessManager,
		PublicPaths:   []string{"/"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := ModelAuthMiddleware(middlewareConfig)(handler)

	b.Run("public_path", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			authenticatedHandler.ServeHTTP(w, req)
		}
	})

	b.Run("authenticated_request", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			req.Header.Set("Authorization", "Bearer prod-api-key-123")
			req.Header.Set("x-model", "claude-prod")

			w := httptest.NewRecorder()
			authenticatedHandler.ServeHTTP(w, req)
		}
	})

	b.Run("model_extraction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			req.Header.Set("Authorization", "Bearer prod-api-key-123")
			req.Header.Set("x-model", "claude-prod")

			_, err := extractModelFromRequest(req, "x-model", "model")
			if err != nil {
				b.Fatalf("extractModelFromRequest failed: %v", err)
			}
		}
	})
}