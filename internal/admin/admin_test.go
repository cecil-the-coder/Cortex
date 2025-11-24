package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cecil-the-coder/Cortex/internal/server"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/access"
)

// TestAdminAPIKeyManagement comprehensively tests all API key management endpoints
func TestAdminAPIKeyManagement(t *testing.T) {
	// Create comprehensive test configuration
	cfg := createTestConfig(t)

	// Create access manager
	am := access.NewAccessManager(cfg)

	// Create test server
	srv := createTestServer(cfg, am)

	t.Run("List API Keys", func(t *testing.T) {
		tests := []struct {
			name           string
			authHeader     string
			expectedStatus int
			expectCount    int
			expectError    string
		}{
			{
				name:           "No authentication",
				authHeader:     "",
				expectedStatus: http.StatusUnauthorized,
				expectError:    "authentication_error",
			},
			{
				name:           "Invalid admin key",
				authHeader:     "Bearer invalid-admin-key",
				expectedStatus: http.StatusUnauthorized,
				expectError:    "authentication_error",
			},
			{
				name:           "Valid admin key - Authorization header",
				authHeader:     "Bearer sk-admin-123456789",
				expectedStatus: http.StatusOK,
				expectCount:    2, // We have 2 pre-configured keys
			},
			{
				name:           "Valid admin key - x-api-key header",
				authHeader:     "x-api-key: sk-admin-123456789",
				expectedStatus: http.StatusOK,
				expectCount:    2,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/admin/api-keys", nil)

				if strings.Contains(tt.authHeader, "Bearer") {
					req.Header.Set("Authorization", tt.authHeader)
				} else if tt.authHeader != "" {
					parts := strings.SplitN(tt.authHeader, ":", 2)
					if len(parts) == 2 {
						req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					}
				}

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeys(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectCount > 0 && rr.Code == http.StatusOK {
					var response server.APIKeyListResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if response.Count != tt.expectCount {
						t.Errorf("Expected %d API keys, got %d", tt.expectCount, response.Count)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
				}
			})
		}
	})

	t.Run("Create API Key", func(t *testing.T) {
		tests := []struct {
			name           string
			request        server.APIKeyCreateRequest
			expectedStatus int
			expectError    string
			validateFunc   func(*testing.T, *httptest.ResponseRecorder)
		}{
			{
				name: "Valid API key creation",
				request: server.APIKeyCreateRequest{
					ID:          "new-test-key",
					Description: "New test API key",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
					RateLimit:   100,
				},
				expectedStatus: http.StatusCreated,
				validateFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
					var response struct {
						Success   bool   `json:"success"`
						KeyID     string `json:"key_id"`
						APIKey    string `json:"api_key"`
						Timestamp string `json:"timestamp"`
						Message   string `json:"message"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.KeyID != "new-test-key" {
						t.Errorf("Expected key_id 'new-test-key', got '%s'", response.KeyID)
					}
					if response.APIKey == "" {
						t.Error("Expected API key to be returned")
					}
					if !strings.HasPrefix(response.APIKey, "sk-") {
						t.Error("Expected generated API key to start with 'sk-'")
					}
				},
			},
			{
				name: "Custom API key",
				request: server.APIKeyCreateRequest{
					ID:          "custom-key",
					Description: "Custom key",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
					APIKey:      "sk-custom-123456789",
				},
				expectedStatus: http.StatusCreated,
				validateFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
					var response struct {
						Success   bool   `json:"success"`
						KeyID     string `json:"key_id"`
						APIKey    string `json:"api_key"`
						Timestamp string `json:"timestamp"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal response: %v", err)
					}
					if response.APIKey != "sk-custom-123456789" {
						t.Errorf("Expected custom API key, got '%s'", response.APIKey)
					}
				},
			},
			{
				name: "Duplicate key ID",
				request: server.APIKeyCreateRequest{
					ID:          "test-key-1", // This already exists
					Description: "Duplicate key",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
				},
				expectedStatus: http.StatusConflict,
				expectError:    "conflict_error",
			},
			{
				name: "Invalid key ID format",
				request: server.APIKeyCreateRequest{
					ID:          "invalid key id!", // Contains invalid characters
					Description: "Invalid ID",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name: "Negative rate limit",
				request: server.APIKeyCreateRequest{
					ID:          "negative-rate",
					Description: "Negative rate",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
					RateLimit:   -10,
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name: "Nonexistent model group",
				request: server.APIKeyCreateRequest{
					ID:          "bad-group",
					Description: "Bad group key",
					ModelGroups: []string{"nonexistent-group"},
					Enabled:     true,
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body, _ := json.Marshal(tt.request)
				req := httptest.NewRequest("POST", "/admin/api-keys", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeyCreate(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.validateFunc != nil {
					tt.validateFunc(t, rr)
				}
			})
		}
	})

	t.Run("Update API Key", func(t *testing.T) {
		tests := []struct {
			name           string
			keyID          string
			request        server.APIKeyUpdateRequest
			expectedStatus int
			expectError    string
		}{
			{
				name:  "Valid update",
				keyID: "test-key-1",
				request: server.APIKeyUpdateRequest{
					Description: stringPtr("Updated description"),
					Enabled:     boolPtr(false),
					RateLimit:   intPtr(200),
				},
				expectedStatus: http.StatusOK,
			},
			{
				name:  "Clear expiration",
				keyID: "test-key-2",
				request: server.APIKeyUpdateRequest{
					ExpiresAt: stringPtr(""),
				},
				expectedStatus: http.StatusOK,
			},
			{
				name:  "Set new model groups",
				keyID: "test-key-1",
				request: server.APIKeyUpdateRequest{
					ModelGroups: &[]string{"vision-group"},
				},
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent key",
				keyID:          "nonexistent",
				request:        server.APIKeyUpdateRequest{},
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
			{
				name:  "Invalid expiration date",
				keyID: "test-key-1",
				request: server.APIKeyUpdateRequest{
					ExpiresAt: stringPtr("invalid-date"),
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name:  "Past expiration date",
				keyID: "test-key-1",
				request: server.APIKeyUpdateRequest{
					ExpiresAt: stringPtr("2020-01-01T00:00:00Z"),
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body, _ := json.Marshal(tt.request)
				req := httptest.NewRequest("PUT", "/admin/api-keys/"+tt.keyID, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeyUpdate(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}
			})
		}
	})

	t.Run("Delete API Key", func(t *testing.T) {
		tests := []struct {
			name           string
			keyID          string
			expectedStatus int
			expectError    string
		}{
			{
				name:           "Valid deletion",
				keyID:          "test-key-2",
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent key",
				keyID:          "nonexistent",
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
			{
				name:           "Empty key ID",
				keyID:          "",
				expectedStatus: http.StatusBadRequest,
				expectError:    "invalid_request",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("DELETE", "/admin/api-keys/"+tt.keyID, nil)
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeyDelete(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response struct {
						Success   bool   `json:"success"`
						KeyID     string `json:"key_id"`
						Message   string `json:"message"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.KeyID != tt.keyID {
						t.Errorf("Expected key_id '%s', got '%s'", tt.keyID, response.KeyID)
					}
				}
			})
		}
	})

	t.Run("Validate API Key", func(t *testing.T) {
		// Clear access manager cache to avoid test order dependencies
		am.ClearCache()

		// Reset configuration to original state to avoid contamination from previous tests
		// The "Update API Key" test can modify cfg.ClientAPIKeys by disabling keys
		// The "Delete API Key" test can remove keys entirely
		if cfg.ClientAPIKeys != nil {
			// Re-create test-key-1 if it was deleted or reset enabled state
			if _, exists := (*cfg.ClientAPIKeys)["test-key-1"]; exists {
				(*cfg.ClientAPIKeys)["test-key-1"].Enabled = true
			} else {
				(*cfg.ClientAPIKeys)["test-key-1"] = &config.APIKeyConfig{
					APIKey:      "sk-test-key-1-123456",
					Description: "Test API key 1",
					ModelGroups: []string{"test-group"},
					Enabled:     true,
					RateLimit:   100,
				}
			}

			// Re-create test-key-2 if it was deleted or reset enabled state
			if _, exists := (*cfg.ClientAPIKeys)["test-key-2"]; exists {
				(*cfg.ClientAPIKeys)["test-key-2"].Enabled = true
			} else {
				(*cfg.ClientAPIKeys)["test-key-2"] = &config.APIKeyConfig{
					APIKey:      "sk-test-key-2-123456",
					Description: "Test API key 2",
					ModelGroups: []string{"vision-group"},
					Enabled:     true,
					RateLimit:   50,
				}
			}
		}

		tests := []struct {
			name           string
			apiKey         string
			expectedStatus int
			expectExists   bool
			expectValid   bool
			expectError    string
		}{
			{
				name:           "Valid existing key",
				apiKey:         "sk-test-key-1-123456",
				expectedStatus: http.StatusOK,
				expectExists:   true,
				expectValid:   true,
			},
			{
				name:           "Nonexistent key",
				apiKey:         "sk-nonexistent-key",
				expectedStatus: http.StatusOK,
				expectExists:   false,
				expectValid:   false,
			},
			{
				name:           "Invalid format",
				apiKey:         "short",
				expectedStatus: http.StatusOK,
				expectExists:   false,
				expectValid:   false,
			},
			{
				name:           "Empty key",
				apiKey:         "",
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				request := map[string]string{"api_key": tt.apiKey}
				body, _ := json.Marshal(request)
				req := httptest.NewRequest("POST", "/admin/api-keys/validate", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeyValidate(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response struct {
						Success       bool   `json:"success"`
						FormatValid   bool   `json:"format_valid"`
						Exists        bool   `json:"exists"`
						AccessValid   bool   `json:"access_valid"`
						KeyID         string `json:"key_id,omitempty"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.Exists != tt.expectExists {
						t.Errorf("Expected exists=%t, got %t", tt.expectExists, response.Exists)
					}
					if response.AccessValid != tt.expectValid {
						t.Errorf("Expected access_valid=%t, got %t", tt.expectValid, response.AccessValid)
					}
					if tt.apiKey != "" && len(tt.apiKey) >= 8 && !response.FormatValid {
						t.Error("Expected format_valid=true for valid format")
					}
				}
			})
		}
	})

	t.Run("Get API Key Usage", func(t *testing.T) {
		tests := []struct {
			name           string
			keyID          string
			expectedStatus int
			expectError    string
		}{
			{
				name:           "Valid key usage",
				keyID:          "test-key-1",
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent key",
				keyID:          "nonexistent",
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/admin/api-keys/"+tt.keyID+"/usage", nil)
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAPIKeyUsage(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response server.APIKeyUsageResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.KeyID != tt.keyID {
						t.Errorf("Expected key_id '%s', got '%s'", tt.keyID, response.KeyID)
					}
					if response.Usage == nil {
						t.Error("Expected usage statistics")
					}
				}
			})
		}
	})
}

// TestAdminModelGroupManagement tests model group management endpoints
func TestAdminModelGroupManagement(t *testing.T) {
	cfg := createTestConfig(t)
	am := access.NewAccessManager(cfg)
	srv := createTestServer(cfg, am)

	t.Run("List Model Groups", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/model-groups", nil)
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")

		rr := httptest.NewRecorder()
		srv.ServeAdminModelGroups(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var response server.ModelGroupListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}

		if !response.Success {
			t.Error("Expected success=true")
		}
		if response.Count != 2 { // test-group and vision-group
			t.Errorf("Expected 2 model groups, got %d", response.Count)
		}
	})

	t.Run("Create Model Group", func(t *testing.T) {
		tests := []struct {
			name           string
			request        server.ModelGroupCreateRequest
			expectedStatus int
			expectError    string
		}{
			{
				name: "Valid model group",
				request: server.ModelGroupCreateRequest{
					Name:        "new-group",
					Description: "New test group",
					Models: []config.ModelReference{
						{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
						{Provider: "openai", Model: "gpt-4-turbo-preview", Alias: "gpt4-turbo"},
					},
				},
				expectedStatus: http.StatusCreated,
			},
			{
				name: "Duplicate group name",
				request: server.ModelGroupCreateRequest{
					Name: "test-group", // Already exists
					Models: []config.ModelReference{
						{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
					},
				},
				expectedStatus: http.StatusConflict,
				expectError:    "conflict_error",
			},
			{
				name: "Invalid group name",
				request: server.ModelGroupCreateRequest{
					Name: "invalid name!", // Contains invalid characters
					Models: []config.ModelReference{
						{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
					},
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name: "Empty models",
				request: server.ModelGroupCreateRequest{
					Name:        "empty-group",
					Description: "Group with no models",
					Models:      []config.ModelReference{},
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name: "Invalid model reference",
				request: server.ModelGroupCreateRequest{
					Name: "bad-model",
					Models: []config.ModelReference{
						{Provider: "", Model: "some-model"}, // Empty provider
					},
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body, _ := json.Marshal(tt.request)
				req := httptest.NewRequest("POST", "/admin/model-groups", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminModelGroupsCreate(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusCreated {
					var response struct {
						Success   bool           `json:"success"`
						GroupInfo server.ModelGroupInfo `json:"group_info"`
						Message   string         `json:"message"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.GroupInfo.Name != tt.request.Name {
						t.Errorf("Expected group name '%s', got '%s'", tt.request.Name, response.GroupInfo.Name)
					}
				}
			})
		}
	})

	t.Run("Update Model Group", func(t *testing.T) {
		// First create a group to update
		createReq := server.ModelGroupCreateRequest{
			Name:        "update-test",
			Description: "Group for testing updates",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
			},
		}
		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/model-groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr := httptest.NewRecorder()
		srv.ServeAdminModelGroupsCreate(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("Failed to create group for update test: %s", rr.Body.String())
		}

		tests := []struct {
			name           string
			groupName      string
			request        server.ModelGroupUpdateRequest
			expectedStatus int
			expectError    string
		}{
			{
				name:      "Valid update",
				groupName: "update-test",
				request: server.ModelGroupUpdateRequest{
					Description: stringPtr("Updated description"),
				},
				expectedStatus: http.StatusOK,
			},
			{
				name:      "Update models",
				groupName: "update-test",
				request: server.ModelGroupUpdateRequest{
					Models: &[]config.ModelReference{
						{Provider: "openai", Model: "gpt-4-turbo-preview", Alias: "gpt4t"},
						{Provider: "anthropic", Model: "claude-3-opus-20240229"},
					},
				},
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent group",
				groupName:      "nonexistent",
				request:        server.ModelGroupUpdateRequest{},
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body, _ := json.Marshal(tt.request)
				req := httptest.NewRequest("PUT", "/admin/model-groups/"+tt.groupName, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminModelGroupUpdate(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}
			})
		}
	})

	t.Run("Delete Model Group", func(t *testing.T) {
		// First create a group to delete
		createReq := server.ModelGroupCreateRequest{
			Name: "delete-test",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022"},
			},
		}
		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/model-groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr := httptest.NewRecorder()
		srv.ServeAdminModelGroupsCreate(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("Failed to create group for delete test: %s", rr.Body.String())
		}

		tests := []struct {
			name           string
			groupName      string
			expectedStatus int
			expectError    string
		}{
			{
				name:           "Valid deletion",
				groupName:      "delete-test",
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent group",
				groupName:      "nonexistent",
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("DELETE", "/admin/model-groups/"+tt.groupName, nil)
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminModelGroupDelete(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response struct {
						Success   bool   `json:"success"`
						GroupName string `json:"group_name"`
						Message   string `json:"message"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.GroupName != tt.groupName {
						t.Errorf("Expected group_name '%s', got '%s'", tt.groupName, response.GroupName)
					}
				}
			})
		}
	})

	t.Run("Get Model Group Details", func(t *testing.T) {
		tests := []struct {
			name           string
			groupName      string
			expectedStatus int
			expectError    string
		}{
			{
				name:           "Valid group",
				groupName:      "test-group",
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Nonexistent group",
				groupName:      "nonexistent",
				expectedStatus: http.StatusNotFound,
				expectError:    "not_found_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/admin/model-groups/"+tt.groupName, nil)
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminModelGroupDetails(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response struct {
						Success   bool           `json:"success"`
						GroupInfo server.ModelGroupInfo `json:"group_info"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.GroupInfo.Name != tt.groupName {
						t.Errorf("Expected group name '%s', got '%s'", tt.groupName, response.GroupInfo.Name)
					}
				}
			})
		}
	})
}

// TestAdminAccessControl tests access control endpoints
func TestAdminAccessControl(t *testing.T) {
	cfg := createTestConfig(t)
	am := access.NewAccessManager(cfg)
	srv := createTestServer(cfg, am)

	t.Run("Check Model Access", func(t *testing.T) {
		tests := []struct {
			name           string
			request        server.AccessCheckRequest
			expectedStatus int
			expectAccess   bool
			expectError    string
		}{
			{
				name: "Valid access",
				request: server.AccessCheckRequest{
					APIKey: "sk-test-key-1-123456",
					Model:  "claude-sonnet",
				},
				expectedStatus: http.StatusOK,
				expectAccess:   true,
			},
			{
				name: "Access by alias",
				request: server.AccessCheckRequest{
					APIKey: "sk-test-key-2-123456",
					Model:  "gpt4-vision",
				},
				expectedStatus: http.StatusOK,
				expectAccess:   true,
			},
			{
				name: "Invalid API key",
				request: server.AccessCheckRequest{
					APIKey: "sk-invalid-key",
					Model:  "claude-sonnet",
				},
				expectedStatus: http.StatusOK,
				expectAccess:   false,
			},
			{
				name: "Wrong model group",
				request: server.AccessCheckRequest{
					APIKey: "sk-test-key-2-123456", // Only has vision-group
					Model:  "claude-sonnet",        // In test-group
				},
				expectedStatus: http.StatusOK,
				expectAccess:   false,
			},
			{
				name: "Empty API key",
				request: server.AccessCheckRequest{
					Model: "claude-sonnet",
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
			{
				name: "Empty model",
				request: server.AccessCheckRequest{
					APIKey: "sk-test-key-1-123456",
				},
				expectedStatus: http.StatusBadRequest,
				expectError:    "validation_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				body, _ := json.Marshal(tt.request)
				req := httptest.NewRequest("POST", "/admin/access/check", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAccessCheck(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response server.AccessCheckResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if response.HasAccess != tt.expectAccess {
						t.Errorf("Expected has_access=%t, got %t", tt.expectAccess, response.HasAccess)
					}
					if response.APIKey == "" {
						t.Error("Expected masked API key in response")
					}
				}
			})
		}
	})

	t.Run("Get Available Models", func(t *testing.T) {
		tests := []struct {
			name           string
			apiKey         string
			expectedStatus int
			expectModels   bool
			expectError    string
		}{
			{
				name:           "Valid API key",
				apiKey:         "sk-test-key-1-123456",
				expectedStatus: http.StatusOK,
				expectModels:   true,
			},
			{
				name:           "Invalid API key",
				apiKey:         "sk-invalid-key",
				expectedStatus: http.StatusUnauthorized,
				expectModels:   false,
				expectError:    "access_error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "/admin/access/models/"+tt.apiKey, nil)
				req.Header.Set("Authorization", "Bearer sk-admin-123456789")

				rr := httptest.NewRecorder()
				srv.ServeAdminAvailableModels(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d. Response: %s", tt.expectedStatus, rr.Code, rr.Body.String())
				}

				if tt.expectError != "" {
					var response server.ErrorResponse
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal error response: %v", err)
					}
					if response.Type != tt.expectError {
						t.Errorf("Expected error type '%s', got '%s'", tt.expectError, response.Type)
					}
				}

				if tt.expectedStatus == http.StatusOK {
					var response struct {
						Success        bool     `json:"success"`
						AvailableModels []string `json:"available_models"`
						ModelCount     int      `json:"model_count"`
					}
					if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
						t.Errorf("Failed to unmarshal success response: %v", err)
					}
					if !response.Success {
						t.Error("Expected success=true")
					}
					if tt.expectModels && len(response.AvailableModels) == 0 {
						t.Error("Expected available models")
					}
				}
			})
		}
	})
}


// Integration Tests
func TestAdminAPIIntegration(t *testing.T) {
	cfg := createTestConfig(t)
	am := access.NewAccessManager(cfg)
	srv := createTestServer(cfg, am)

	t.Run("Complete API Key Lifecycle", func(t *testing.T) {
		// Create API key
		createReq := server.APIKeyCreateRequest{
			ID:          "lifecycle-test",
			Description: "Key for lifecycle testing",
			ModelGroups: []string{"test-group"},
			Enabled:     true,
			RateLimit:   50,
		}
		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/api-keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")

		rr := httptest.NewRecorder()
		srv.ServeAdminAPIKeyCreate(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("Failed to create API key: %s", rr.Body.String())
		}

		var createResp struct {
			Success bool   `json:"success"`
			KeyID   string `json:"key_id"`
			APIKey  string `json:"api_key"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &createResp); err != nil {
			t.Fatalf("Failed to unmarshal create response: %v", err)
		}

		if !createResp.Success {
			t.Fatal("Expected success=true")
		}

		// List API keys and verify new key exists
		req = httptest.NewRequest("GET", "/admin/api-keys", nil)
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminAPIKeys(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to list API keys: %s", rr.Body.String())
		}

		var listResp server.APIKeyListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
			t.Fatalf("Failed to unmarshal list response: %v", err)
		}

		if _, exists := listResp.APIKeys["lifecycle-test"]; !exists {
			t.Error("Created key not found in list")
		}

		// Update API key
		updateReq := server.APIKeyUpdateRequest{
			Description: stringPtr("Updated description"),
			RateLimit:   intPtr(100),
			Enabled:     boolPtr(false),
		}
		body, _ = json.Marshal(updateReq)
		req = httptest.NewRequest("PUT", "/admin/api-keys/lifecycle-test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminAPIKeyUpdate(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to update API key: %s", rr.Body.String())
		}

		// Delete API key
		req = httptest.NewRequest("DELETE", "/admin/api-keys/lifecycle-test", nil)
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminAPIKeyDelete(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to delete API key: %s", rr.Body.String())
		}

		// Verify key no longer exists
		req = httptest.NewRequest("GET", "/admin/api-keys", nil)
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminAPIKeys(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Failed to list API keys after deletion: %s", rr.Body.String())
		}

		var finalListResp server.APIKeyListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &finalListResp); err != nil {
			t.Fatalf("Failed to unmarshal final list response: %v", err)
		}

		if _, exists := finalListResp.APIKeys["lifecycle-test"]; exists {
			t.Error("Deleted key still found in list")
		}
	})

	t.Run("Model Group with Aliases Integration", func(t *testing.T) {
		// Create model group with aliases
		createReq := server.ModelGroupCreateRequest{
			Name:        "alias-test",
			Description: "Group for testing aliases",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", Alias: "claude-latest"},
				{Provider: "openai", Model: "gpt-4-turbo-preview", Alias: "gpt4"},
			},
		}
		body, _ := json.Marshal(createReq)
		req := httptest.NewRequest("POST", "/admin/model-groups", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr := httptest.NewRecorder()
		srv.ServeAdminModelGroupsCreate(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("Failed to create model group: %s", rr.Body.String())
		}

		// Test access via alias
		accessReq := server.AccessCheckRequest{
			APIKey: "sk-test-key-1-123456",
			Model:  "claude-sonnet", // Should resolve to actual model
		}
		body, _ = json.Marshal(accessReq)
		req = httptest.NewRequest("POST", "/admin/access/check", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminAccessCheck(rr, req)

		if rr.Code != http.StatusOK {
			t.Logf("Access check response: %s", rr.Body.String())
		}

		// Clean up
		req = httptest.NewRequest("DELETE", "/admin/model-groups/alias-test", nil)
		req.Header.Set("Authorization", "Bearer sk-admin-123456789")
		rr = httptest.NewRecorder()
		srv.ServeAdminModelGroupDelete(rr, req)
	})
}

// Helper functions for testing
func createTestConfig(t *testing.T) *config.Config {
	// Create test model groups
	testModelGroup := &config.ModelGroup{
		Description: "Test model group",
		Models: []config.ModelReference{
			{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", Alias: "claude-sonnet"},
			{Provider: "openai", Model: "gpt-4-turbo-preview"},
		},
	}

	visionModelGroup := &config.ModelGroup{
		Description: "Vision models group",
		Models: []config.ModelReference{
			{Provider: "openai", Model: "gpt-4-vision-preview", Alias: "gpt4-vision"},
			{Provider: "anthropic", Model: "claude-3-opus-20240229", Alias: "claude-opus"},
		},
	}

	modelGroups := config.ModelGroups{
		"test-group":   testModelGroup,
		"vision-group": visionModelGroup,
	}

	// Create test client API keys
	clientKeys := config.ClientAPIKeys{
		"test-key-1": {
			APIKey:      "sk-test-key-1-123456",
			Description: "Test API key 1",
			ModelGroups: []string{"test-group"},
			Enabled:     true,
			RateLimit:   100,
		},
		"test-key-2": {
			APIKey:      "sk-test-key-2-123456",
			Description: "Test API key 2",
			ModelGroups: []string{"vision-group"},
			Enabled:     true,
			RateLimit:   50,
		},
	}

	return &config.Config{
		APIKEY: "sk-admin-123456789",
		Host:   "localhost",
		Port:   8080,
		Router: config.RouterConfig{
			Default: "anthropic",
		},
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "test-anthropic-key",
				BaseURL:    "https://api.anthropic.com/v1",
				Models:     []string{"claude-3-5-sonnet-20241022", "claude-3-opus-20240229"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "test-openai-key",
				BaseURL:    "https://api.openai.com/v1",
				Models:     []string{"gpt-4-turbo-preview", "gpt-4-vision-preview"},
			},
		},
		ModelGroups:   &modelGroups,
		ClientAPIKeys: &clientKeys,
	}
}

func createTestServer(cfg *config.Config, am interface{}) *server.Server {
	// Create the actual server with default config
	serverConfig := server.DefaultConfig()
	serverConfig.ConfigPath = "/tmp/test-config.yaml"
	srv := server.NewServer(serverConfig, nil, nil, nil)

	// Use type assertion to set the unexported fields via public methods if they exist
	if accessManager, ok := am.(*access.AccessManager); ok {
		srv.SetAccessManager(accessManager)
	}

	// Set config function
	srv.SetConfigFunc(func() *config.Config { return cfg })

	return srv
}

// Helper functions for creating pointers
func stringPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

func intPtr(i int) *int {
	return &i
}