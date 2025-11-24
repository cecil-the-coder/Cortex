package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/cecil-the-coder/Cortex/internal/access"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/middleware"
)

// TestIntegrationEndToEndFlow tests the complete request flow with model aliases
func TestIntegrationEndToEndFlow(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-config.json")

	// Create comprehensive test configuration
	testConfig := createIntegrationTestConfig(t)

	if err := config.Save(testConfig, configPath, false); err != nil {
		t.Fatalf("Failed to save test config: %v", err)
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Create access manager
	accessManager := access.NewAccessManager(cfg)

	// Create middleware
	authMiddleware := middleware.ModelAuthMiddleware(&middleware.ModelAuthConfig{
		AccessManager: accessManager,
		PublicPaths:   []string{"/", "/health", "/models"},
	})

	// Create router
	serverRouter := mux.NewRouter()

	// Add middleware to all routes
	serverRouter.Use(authMiddleware)

	// Add model list endpoint
	serverRouter.HandleFunc("/v1/models", middleware.ModelListHandler(&middleware.ModelAuthConfig{
		AccessManager: accessManager,
	})).Methods("GET")

	// Add health check endpoint
	serverRouter.HandleFunc("/health", middleware.HealthCheckWithAuth(&middleware.ModelAuthConfig{
		AccessManager: accessManager,
	})).Methods("GET")

	// Add chat completions endpoint (mock)
	serverRouter.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		// Extract context information
		accessInfo, exists := middleware.GetAccessInfoFromContext(r)
		if !exists {
			http.Error(w, "No access info", http.StatusInternalServerError)
			return
		}

		// Return mock response with routing information
		response := map[string]interface{}{
			"id":                "chatcmpl-test",
			"object":            "chat.completion",
			"created":           time.Now().Unix(),
			"model":             accessInfo.ResolvedModel,
			"provider":          accessInfo.ProviderName,
			"routing_info": map[string]interface{}{
				"original_model":  accessInfo.OriginalModel,
				"resolved_model":  accessInfo.ResolvedModel,
				"resolved_by":     accessInfo.ResolvedBy,
				"model_group":     accessInfo.ModelGroup,
				"provider":        accessInfo.ProviderName,
				"api_key_id":      getTestKeyIdentifier(accessInfo.APIKeyConfig),
			},
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": "Test response",
					},
					"finish_reason": "stop",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Create test server
	testServer := httptest.NewServer(serverRouter)
	defer testServer.Close()

	tests := []struct {
		name           string
		apiKey         string
		requestModel   string
		expectedStatus int
		expectedResolvedModel string
		expectedProvider string
		expectedModelGroup string
	}{
		{
			name:              "production key with alias",
			apiKey:            "prod-api-key-123",
			requestModel:      "claude-prod",
			expectedStatus:    http.StatusOK,
			expectedResolvedModel: "claude-3-sonnet",
			expectedProvider: "anthropic",
			expectedModelGroup: "production",
		},
		{
			name:              "unrestricted key with direct model",
			apiKey:            "unrestricted-api-key-456",
			requestModel:      "claude-3-haiku",
			expectedStatus:    http.StatusOK,
			expectedResolvedModel: "claude-3-haiku",
			expectedProvider: "anthropic",
			expectedModelGroup: "unrestricted",
		},
		{
			name:              "development key with development alias",
			apiKey:            "dev-api-key-789",
			requestModel:      "claude-dev",
			expectedStatus:    http.StatusOK,
			expectedResolvedModel: "claude-3-haiku",
			expectedProvider: "anthropic",
			expectedModelGroup: "development",
		},
		{
			name:              "restricted key access to disallowed model",
			apiKey:            "prod-api-key-123",
			requestModel:      "claude-dev", // Not in production group
			expectedStatus:    http.StatusForbidden,
		},
		{
			name:              "invalid API key",
			apiKey:            "invalid-key",
			requestModel:      "claude-prod",
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			name:              "non-existent model",
			apiKey:            "prod-api-key-123",
			requestModel:      "nonexistent-model",
			expectedStatus:    http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request body
			requestBody := map[string]interface{}{
				"model": tt.requestModel,
				"messages": []map[string]interface{}{
					{"role": "user", "content": "Hello, world!"},
				},
				"max_tokens": 100,
			}

			bodyBytes, _ := json.Marshal(requestBody)

			// Create HTTP request
			req, err := http.NewRequest("POST", testServer.URL+"/v1/chat/completions", bytes.NewBuffer(bodyBytes))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.apiKey)

			// Send request
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			// Check status code
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}

			// For successful requests, validate response
			if tt.expectedStatus == http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}

				var response map[string]interface{}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}

				// Validate routing information
				if response["model"].(string) != tt.expectedResolvedModel {
					t.Errorf("Expected resolved model %s, got %s", tt.expectedResolvedModel, response["model"])
				}

				routingInfo, ok := response["routing_info"].(map[string]interface{})
				if !ok {
					t.Error("Response should contain routing_info")
				} else {
					if routingInfo["resolved_model"] != tt.expectedResolvedModel {
						t.Errorf("Expected resolved model %s, got %v", tt.expectedResolvedModel, routingInfo["resolved_model"])
					}

					if routingInfo["provider"] != tt.expectedProvider {
						t.Errorf("Expected provider %s, got %v", tt.expectedProvider, routingInfo["provider"])
					}

					if routingInfo["model_group"] != tt.expectedModelGroup {
						t.Errorf("Expected model group %s, got %v", tt.expectedModelGroup, routingInfo["model_group"])
					}

					if routingInfo["original_model"] != tt.requestModel {
						t.Errorf("Expected original model %s, got %v", tt.requestModel, routingInfo["original_model"])
					}
				}
			}
		})
	}
}

// TestHotReloadOfModelAccessConfig tests hot-reload functionality for model access configurations
func TestHotReloadOfModelAccessConfig(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "hot-reload-config.json")

	// Initial configuration
	initialConfig := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "anthropic-key-123",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-sonnet"},
			},
		},
		ModelGroups: &config.ModelGroups{
			"test-group": {
				Description: "Test group",
				Models: []config.ModelReference{
					{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "test-alias"},
				},
			},
		},
		ClientAPIKeys: &config.ClientAPIKeys{
			"test-key": {
				APIKey:      "test-api-key-123",
				Description: "Test key",
				ModelGroups: []string{"test-group"},
				Enabled:     true,
			},
		},
		Router: config.RouterConfig{
			Default: "anthropic",
		},
	}

	if err := config.Save(initialConfig, configPath, false); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Load initial configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	// Create access manager with initial config
	accessManager := access.NewAccessManager(cfg)

	// Test initial state
	_, err = accessManager.ValidateAPIKey("test-api-key-123")
	if err != nil {
		t.Fatalf("Initial API key validation failed: %v", err)
	}

	// Test model resolution
	modelRef, _, err := accessManager.ResolveModel(context.Background(), "test-alias")
	if err != nil {
		t.Fatalf("Initial model resolution failed: %v", err)
	}
	if modelRef.Model != "claude-3-sonnet" {
		t.Fatalf("Expected claude-3-sonnet, got %s", modelRef.Model)
	}

	// Modify and save configuration (simulate hot reload)
	// Note: Create a new config instead of copying to avoid mutex copy issues
	modifiedConfig := &config.Config{
		Providers: initialConfig.Providers,
		ModelGroups: &config.ModelGroups{},
		ClientAPIKeys: &config.ClientAPIKeys{},
		Router:       initialConfig.Router,
		APIKEY:       initialConfig.APIKEY,
		Host:         initialConfig.Host,
		Port:         initialConfig.Port,
	}

	// Copy existing model groups
	for k, v := range *initialConfig.ModelGroups {
		(*modifiedConfig.ModelGroups)[k] = v
	}

	// Copy existing API keys
	for k, v := range *initialConfig.ClientAPIKeys {
		(*modifiedConfig.ClientAPIKeys)[k] = v
	}

	// Add new model group
	(*modifiedConfig.ModelGroups)["new-test-group"] = &config.ModelGroup{
		Description: "New test group",
		Models: []config.ModelReference{
			{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "new-alias"},
		},
	}

	// Add new API key
	(*modifiedConfig.ClientAPIKeys)["new-test-key"] = &config.APIKeyConfig{
		APIKey:      "new-test-api-key-456",
		Description: "New test key",
		ModelGroups: []string{"new-test-group"},
		Enabled:     true,
	}

	// Save modified config
	if err := config.Save(modifiedConfig, configPath, false); err != nil {
		t.Fatalf("Failed to save modified config: %v", err)
	}

	// Reload configuration
	reloadedCfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to reloaded config: %v", err)
	}

	// Create new access manager with reloaded config
	newAccessManager := access.NewAccessManager(reloadedCfg)

	// Test that new API key works
	_, err = newAccessManager.ValidateAPIKey("new-test-api-key-456")
	if err != nil {
		t.Errorf("New API key validation failed after reload: %v", err)
	}

	// Test that old API key still works
	_, err = newAccessManager.ValidateAPIKey("test-api-key-123")
	if err != nil {
		t.Errorf("Old API key validation failed after reload: %v", err)
	}

	// Test that new alias works
	modelRef, _, err = newAccessManager.ResolveModel(context.Background(), "new-alias")
	if err != nil {
		t.Errorf("New alias resolution failed after reload: %v", err)
	}
	if modelRef.Model != "claude-3-sonnet" {
		t.Errorf("Expected claude-3-sonnet for new alias, got %s", modelRef.Model)
	}

	// Test that old alias still works
	modelRef, _, err = newAccessManager.ResolveModel(context.Background(), "test-alias")
	if err != nil {
		t.Errorf("Old alias resolution failed after reload: %v", err)
	}
	if modelRef.Model != "claude-3-sonnet" {
		t.Errorf("Expected claude-3-sonnet for old alias, got %s", modelRef.Model)
	}
}

// TestAdminAPIOperations tests admin API operations with persistence
func TestAdminAPIOperations(t *testing.T) {
	// Create temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "admin-test-config.json")

	// Initial configuration
	initialConfig := createIntegrationTestConfig(t)
	if err := config.Save(initialConfig, configPath, false); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test CRUD operations on model groups
	t.Run("model group CRUD", func(t *testing.T) {
		// Add new model group
		newGroup := &config.ModelGroup{
			Description: "Test group for CRUD",
			Models: []config.ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "crud-alias"},
			},
		}

		err := cfg.AddModelGroup("crud-test", newGroup)
		if err != nil {
			t.Errorf("Failed to add model group: %v", err)
		}

		// Verify group was added
		retrievedGroup, err := cfg.GetModelGroup("crud-test")
		if err != nil {
			t.Errorf("Failed to retrieve added model group: %v", err)
		}
		if retrievedGroup.Description != "Test group for CRUD" {
			t.Errorf("Expected description 'Test group for CRUD', got '%s'", retrievedGroup.Description)
		}

		// Remove model group
		err = cfg.RemoveModelGroup("crud-test")
		if err != nil {
			t.Errorf("Failed to remove model group: %v", err)
		}

		// Verify group was removed
		_, err = cfg.GetModelGroup("crud-test")
		if err == nil {
			t.Error("Should not be able to retrieve removed model group")
		}
	})

	// Test CRUD operations on client API keys
	t.Run("API key CRUD", func(t *testing.T) {
		newKey := &config.APIKeyConfig{
			APIKey:      "crud-test-key-789",
			Description: "Test key for CRUD",
			ModelGroups: []string{"production"},
			Enabled:     true,
			RateLimit:   50,
		}

		// Add new API key
		err := cfg.AddClientAPIKey("crud-test", newKey)
		if err != nil {
			t.Errorf("Failed to add client API key: %v", err)
		}

		// Verify key was added
		retrievedKey, err := cfg.GetClientAPIKey("crud-test")
		if err != nil {
			t.Errorf("Failed to retrieve added API key: %v", err)
		}
		if retrievedKey.Description != "Test key for CRUD" {
			t.Errorf("Expected description 'Test key for CRUD', got '%s'", retrievedKey.Description)
		}

		// Remove API key
		err = cfg.RemoveClientAPIKey("crud-test")
		if err != nil {
			t.Errorf("Failed to remove API key: %v", err)
		}

		// Verify key was removed
		_, err = cfg.GetClientAPIKey("crud-test")
		if err == nil {
			t.Error("Should not be able to retrieve removed API key")
		}
	})

	// Test persistence by saving and reloading
	t.Run("persistence", func(t *testing.T) {
		// Add model group and key
		testGroup := &config.ModelGroup{
			Description: "Persistence test group",
			Models: []config.ModelReference{
				{Provider: "openai", Model: "gpt-4", Alias: "persist-alias"},
			},
		}

		testKey := &config.APIKeyConfig{
			APIKey:      "persist-test-key-999",
			Description: "Persistence test key",
			ModelGroups: []string{"development"},
			Enabled:     true,
		}

		cfg.AddModelGroup("persist-test", testGroup)
		cfg.AddClientAPIKey("persist-test", testKey)

		// Save configuration
		if err := config.Save(cfg, configPath, false); err != nil {
			t.Fatalf("Failed to save configuration: %v", err)
		}

		// Reload configuration
		reloadedCfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("Failed to reload configuration: %v", err)
		}

		// Verify model group persisted
		group, err := reloadedCfg.GetModelGroup("persist-test")
		if err != nil {
			t.Errorf("Model group should persist: %v", err)
		}
		if group.Description != "Persistence test group" {
			t.Errorf("Persisted group description mismatch: expected 'Persistence test group', got '%s'", group.Description)
		}

		// Verify API key persisted
		key, err := reloadedCfg.GetClientAPIKey("persist-test")
		if err != nil {
			t.Errorf("API key should persist: %v", err)
		}
		if key.Description != "Persistence test key" {
			t.Errorf("Persisted key description mismatch: expected 'Persistence test key', got '%s'", key.Description)
		}
	})
}

// TestMultipleAPIKeysWithDifferentRestrictions tests multiple API keys with different model group restrictions
func TestMultipleAPIKeysWithDifferentRestrictions(t *testing.T) {
	cfg := createIntegrationTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	// Test keys with different access levels
	tests := []struct {
		name           string
		apiKey         string
		model          string
		expectAccess   bool
		expectedError  string
	}{
		{
			name:         "Production key accessing production model",
			apiKey:       "prod-api-key-123",
			model:        "claude-prod", // Production alias
			expectAccess: true,
		},
		{
			name:          "Production key accessing development model",
			apiKey:        "prod-api-key-123",
			model:         "claude-dev", // Development alias
			expectAccess:  false,
			expectedError: "does not have access to model",
		},
		{
			name:         "Development key accessing development model",
			apiKey:       "dev-api-key-789",
			model:        "claude-dev", // Development alias
			expectAccess: true,
		},
		{
			name:          "Development key accessing production model",
			apiKey:        "dev-api-key-789",
			model:         "claude-prod", // Production alias
			expectAccess:  false,
			expectedError: "does not have access to model",
		},
		{
			name:         "Unrestricted key accessing any model",
			apiKey:       "unrestricted-api-key-456",
			model:        "claude-prod", // Any model
			expectAccess: true,
		},
		{
			name:         "Unrestricted key accessing development model",
			apiKey:       "unrestricted-api-key-456",
			model:        "claude-dev", // Development model
			expectAccess: true,
		},
		{
			name:         "Unrestricted key accessing direct model",
			apiKey:       "unrestricted-api-key-456",
			model:        "gpt-4", // Direct model name
			expectAccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			accessInfo, err := accessManager.CanAccessModel(ctx, tt.apiKey, tt.model)

			if tt.expectAccess {
				if err != nil {
					t.Errorf("Expected access to be granted, but got error: %v", err)
				}

				if accessInfo == nil {
					t.Error("Expected access info to be returned for successful access")
				}

				if accessInfo.OriginalModel != tt.model {
					t.Errorf("Expected original model '%s', got '%s'", tt.model, accessInfo.OriginalModel)
				}

				if accessInfo.APIKeyConfig == nil {
					t.Error("Expected API key config to be present")
				}
			} else {
				if err == nil {
					t.Error("Expected access to be denied, but no error was returned")
				}

				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestComplexScenariosWithOverlappingModelGroups tests complex scenarios with overlapping model groups
func TestComplexScenariosWithOverlappingModelGroups(t *testing.T) {
	// Create configuration with overlapping model groups
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "complex-test-config.json")

	complexConfig := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "anthropic-key-123",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-sonnet", "claude-3-haiku", "claude-3-opus"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "openai-key-456",
				BaseURL:    "https://api.openai.com",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
		},
		ModelGroups: &config.ModelGroups{
			"anthropic-premium": {
				Description: "High-end Anthropic models",
				Models: []config.ModelReference{
					{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-best"},
					{Provider: "anthropic", Model: "claude-3-opus", Alias: "claude-ultimate"},
				},
			},
			"anthropic-all": {
				Description: "All Anthropic models",
				Models: []config.ModelReference{
					{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-sonnet-all"},
					{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-haiku-all"},
					{Provider: "anthropic", Model: "claude-3-opus", Alias: "claude-opus-all"},
				},
			},
			"development": {
				Description: "Development models",
				Models: []config.ModelReference{
					{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-haiku-dev"},
					{Provider: "openai", Model: "gpt-3.5-turbo", Alias: "gpt35-dev"},
				},
			},
		},
		ClientAPIKeys: &config.ClientAPIKeys{
			"premium-user": {
				APIKey:      "premium-key-789",
				Description: "Premium user with high-end models",
				ModelGroups: []string{"anthropic-premium"},
				Enabled:     true,
			},
			"full-anthropic-user": {
				APIKey:      "full-anthropic-key-012",
				Description: "Full access to all Anthropic models",
				ModelGroups: []string{"anthropic-all", "development"},
				Enabled:     true,
			},
			"limited-user": {
				APIKey:      "limited-key-345",
				Description: "Limited access user",
				ModelGroups: []string{"development"},
				Enabled:     true,
			},
		},
		Router: config.RouterConfig{
			Default: "anthropic",
		},
	}

	if err := config.Save(complexConfig, configPath, false); err != nil {
		t.Fatalf("Failed to save complex config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load complex config: %v", err)
	}

	accessManager := access.NewAccessManager(cfg)

	tests := []struct {
		name           string
		apiKey         string
		model          string
		expectAccess   bool
		expectedGroups []string // Groups that should grant access
	}{
		{
			name:           "Premium user accessing premium model",
			apiKey:         "premium-key-789",
			model:          "claude-best", // claude-3-sonnet
			expectAccess:   true,
			expectedGroups:  []string{"anthropic-premium"},
		},
		{
			name:         "Premium user accessing non-premium model",
			apiKey:       "premium-key-789",
			model:        "claude-haiku-dev", // claude-3-haiku
			expectAccess: false,
		},
		{
			name:           "Full Anthropic user accessing any Anthropic model",
			apiKey:         "full-anthropic-key-012",
			model:          "claude-opus-all", // claude-3-opus
			expectAccess:   true,
			expectedGroups:  []string{"anthropic-all"},
		},
		{
			name:           "Full Anthropic user accessing development model",
			apiKey:         "full-anthropic-key-012",
			model:          "gpt35-dev", // gpt-3.5-turbo
			expectAccess:   true,
			expectedGroups:  []string{"development"},
		},
		{
			name:           "Limited user accessing development model",
			apiKey:         "limited-key-345",
			model:          "claude-haiku-dev", // claude-3-haiku
			expectAccess:   true,
			expectedGroups:  []string{"development"},
		},
		{
			name:         "Limited user accessing premium model",
			apiKey:       "limited-key-345",
			model:        "claude-ultimate", // claude-3-opus
			expectAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			accessInfo, err := accessManager.CanAccessModel(ctx, tt.apiKey, tt.model)

			if tt.expectAccess {
				if err != nil {
					t.Errorf("Expected access to be granted, but got error: %v", err)
				}

				if len(tt.expectedGroups) > 0 {
					groupFound := false
					for _, expectedGroup := range tt.expectedGroups {
						if accessInfo.ModelGroup == expectedGroup {
							groupFound = true
							break
						}
					}
					if !groupFound {
						t.Errorf("Expected access to be granted by one of %v, but got group '%s'",
							tt.expectedGroups, accessInfo.ModelGroup)
					}
				}
			} else {
				if err == nil {
					t.Error("Expected access to be denied, but no error was returned")
				}
			}
		})
	}
}

// TestConcurrentAccessWithAPIKeys tests concurrent access with multiple API keys
func TestConcurrentAccessWithAPIKeys(t *testing.T) {
	cfg := createIntegrationTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	// Create multiple API keys for testing
	apiKeys := []string{
		"prod-api-key-123",
		"dev-api-key-789",
		"unrestricted-api-key-456",
	}

	models := []string{
		"claude-prod",   // Production alias
		"claude-dev",    // Development alias
		"gpt-4",         // Direct model
	}

	// Test concurrent access
	numWorkers := 50
	numRequests := 100

	results := make(chan error, numWorkers*numRequests)

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			for r := 0; r < numRequests; r++ {
				apiKey := apiKeys[workerID%len(apiKeys)]
				model := models[r%len(models)]

				ctx := context.Background()
				_, err := accessManager.CanAccessModel(ctx, apiKey, model)
				results <- err
			}
		}(w)
	}

	// Collect results
	successCount := 0
	errorCount := 0
	for i := 0; i < numWorkers*numRequests; i++ {
		err := <-results
		if err != nil {
			errorCount++
		} else {
			successCount++
		}
	}

	totalRequests := numWorkers * numRequests
	successRate := float64(successCount) / float64(totalRequests) * 100

	t.Logf("Concurrent access test results:")
	t.Logf("  Total requests: %d", totalRequests)
	t.Logf("  Successful: %d", successCount)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Success rate: %.2f%%", successRate)

	// We expect some errors due to access restrictions, but not all requests should fail
	if successRate == 0 {
		t.Error("All requests failed - this indicates a serious concurrent access issue")
	}

	if successRate == 100 {
		t.Error("All requests succeeded - this is unexpected since some combinations should be denied")
	}

	// Verify the access manager still works after concurrent load
	ctx := context.Background()
	accessInfo, err := accessManager.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
	if err != nil {
		t.Errorf("Access manager failed after concurrent load: %v", err)
	}
	if accessInfo == nil {
		t.Error("Access info should be available after concurrent load")
	}
}

// TestModelListEndpointWithAPIKeys tests the model list endpoint with API key restrictions
func TestModelListEndpointWithAPIKeys(t *testing.T) {
	cfg := createIntegrationTestConfig(t)
	accessManager := access.NewAccessManager(cfg)

	// Create mock server for testing
	router := mux.NewRouter()
	router.Handle("/v1/models", middleware.ModelListHandler(&middleware.ModelAuthConfig{
		AccessManager: accessManager,
	})).Methods("GET")

	testServer := httptest.NewServer(router)
	defer testServer.Close()

	tests := []struct {
		name             string
		apiKey           string
		expectedModels   []string // Sample of expected models
		expectError      bool
	}{
		{
			name:           "Production key models",
			apiKey:         "prod-api-key-123",
			expectedModels: []string{"claude-prod"}, // Should see production alias
			expectError:    false,
		},
		{
			name:           "Development key models",
			apiKey:         "dev-api-key-789",
			expectedModels: []string{"claude-dev"}, // Should see development alias
			expectError:    false,
		},
		{
			name:           "Unrestricted key models",
			apiKey:         "unrestricted-api-key-456",
			expectedModels: []string{"claude-prod", "claude-dev", "claude-3-haiku", "claude-3-sonnet", "gpt-3.5-turbo"}, // Should see all available models
			expectError:    false,
		},
		{
			name:      "Invalid API key",
			apiKey:    "invalid-key",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", testServer.URL+"/v1/models", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Authorization", "Bearer "+tt.apiKey)

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			if tt.expectError {
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, resp.StatusCode)
				}
				return
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
			}

			// Parse response
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			// Check that it's a model list response
			if response["object"].(string) != "list" {
				t.Errorf("Expected object 'list', got '%s'", response["object"])
			}

			data, ok := response["data"].([]interface{})
			if !ok {
				t.Error("Response should contain data array")
				return
			}

			// Check that expected models are present
			responseModels := make(map[string]bool)
			for _, item := range data {
				if model, ok := item.(map[string]interface{}); ok {
					if id, exists := model["id"].(string); exists {
						responseModels[id] = true
					}
				}
			}

			for _, expectedModel := range tt.expectedModels {
				if !responseModels[expectedModel] {
					t.Errorf("Expected model '%s' not found in response: %v", expectedModel, responseModels)
				}
			}

			t.Logf("API key '%s' can see %d models", tt.apiKey, len(responseModels))
		})
	}
}

// Helper function to create integration test configuration
func createIntegrationTestConfig(t *testing.T) *config.Config {
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
				{Provider: "openai", Model: "gpt-3.5-turbo"},
			},
		},
	}

	clientAPIKeys := config.ClientAPIKeys{
		"prod": {
			APIKey:      "prod-api-key-123",
			Description: "Production key",
			ModelGroups: []string{"production"},
			Enabled:     true,
		},
		"dev": {
			APIKey:      "dev-api-key-789",
			Description: "Development key",
			ModelGroups: []string{"development"},
			Enabled:     true,
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
				Models:     []string{"claude-3-sonnet", "claude-3-haiku", "claude-3-opus"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "openai-key-456",
				BaseURL:    "https://api.openai.com",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
		},
		ModelGroups:  &modelGroups,
		ClientAPIKeys: &clientAPIKeys,
		Router: config.RouterConfig{
			Default: "anthropic",
		},
		APIKEY: "legacy-router-key",
		Host:   "localhost",
		Port:   8080,
	}

	// Validate test configuration
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Test configuration is invalid: %v", err)
	}

	return cfg
}

// Helper function to check if string contains substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
			 s[len(s)-len(substr):] == substr ||
			 indexOfSubstring(s, substr) >= 0)))
}

func indexOfSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// getTestKeyIdentifier generates a consistent identifier for an API key configuration (test helper)
func getTestKeyIdentifier(keyConfig *config.APIKeyConfig) string {
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

// createBenchmarkTestConfig creates a test configuration for benchmarking (no t parameter needed)
func createBenchmarkTestConfig() *config.Config {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "anthropic-key-123",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-sonnet", "claude-3-haiku", "claude-3-opus"},
			},
			{
				Name:       "openai",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "openai-key-456",
				BaseURL:    "https://api.openai.com",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
		},
		ModelGroups: &config.ModelGroups{
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
					{Provider: "openai", Model: "gpt-3.5-turbo"},
				},
			},
			"unrestricted": {
				Description: "Unrestricted models",
				Models: []config.ModelReference{
					{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
					{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-dev"},
					{Provider: "openai", Model: "gpt-4"},
					{Provider: "openai", Model: "gpt-3.5-turbo"},
				},
			},
		},
		ClientAPIKeys: &config.ClientAPIKeys{
			"prod": {
				APIKey:      "prod-api-key-123",
				Description: "Production key",
				ModelGroups: []string{"production"},
				Enabled:     true,
			},
			"dev": {
				APIKey:      "dev-api-key-789",
				Description: "Development key",
				ModelGroups: []string{"development"},
				Enabled:     true,
			},
			"unrestricted": {
				APIKey:      "unrestricted-api-key-456",
				Description: "Unrestricted key",
				ModelGroups: []string{"unrestricted"},
				Enabled:     true,
			},
		},
		Router: config.RouterConfig{
			Default: "anthropic",
		},
		APIKEY: "legacy-router-key",
		Host:   "localhost",
		Port:   8080,
	}

	// Validate test configuration
	if err := cfg.Validate(); err != nil {
		panic(fmt.Sprintf("Benchmark configuration is invalid: %v", err))
	}

	return cfg
}

// BenchmarkIntegration benchmarks integration scenarios
func BenchmarkIntegration(b *testing.B) {
	cfg := createBenchmarkTestConfig()
	accessManager := access.NewAccessManager(cfg)

	b.Run("concurrent_api_key_validation", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ctx := context.Background()
				_, err := accessManager.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
				if err != nil {
					b.Fatalf("API key validation failed: %v", err)
				}
			}
		})
	})

	b.Run("model_resolution_with_cache", func(b *testing.B) {
		// Prime cache
		ctx := context.Background()
		accessManager.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ctx := context.Background()
				_, err := accessManager.CanAccessModel(ctx, "prod-api-key-123", "claude-prod")
				if err != nil {
					b.Fatalf("Model resolution failed: %v", err)
				}
			}
		})
	})

	b.Run("config_load_and_save", func(b *testing.B) {
		tempDir := b.TempDir()
		configPath := filepath.Join(tempDir, "benchmark-config.json")

		// Initial save
		if err := config.Save(cfg, configPath, false); err != nil {
			b.Fatalf("Failed to save initial config: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := config.Load(configPath)
			if err != nil {
				b.Fatalf("Failed to load config: %v", err)
			}
		}
	})
}