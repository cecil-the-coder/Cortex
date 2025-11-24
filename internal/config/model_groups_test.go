package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestModelGroupValidation tests model group creation and validation
func TestModelGroupValidation(t *testing.T) {
	tests := []struct {
		name          string
		modelGroups   *ModelGroups
		providers     []Provider
		wantErr       bool
		expectedError string
	}{
		{
			name: "valid model groups",
			modelGroups: &ModelGroups{
				"production": {
					Description: "Production models",
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
						{Provider: "openai", Model: "gpt-4", Alias: "gpt4-prod"},
					},
				},
				"development": {
					Description: "Development models",
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-haiku"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku"}},
				{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
			},
			wantErr: false,
		},
		{
			name: "empty model group name",
			modelGroups: &ModelGroups{
				"": {
					Description: "Invalid group",
					Models:      []ModelReference{{Provider: "anthropic", Model: "claude-3"}},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group name cannot be empty",
		},
		{
			name: "null model group",
			modelGroups: &ModelGroups{
				"test": nil,
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group test cannot be null",
		},
		{
			name: "empty models in group",
			modelGroups: &ModelGroups{
				"empty": {
					Description: "Empty group",
					Models:      []ModelReference{},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group empty must contain at least one model",
		},
		{
			name: "empty provider in model reference",
			modelGroups: &ModelGroups{
				"test": {
					Models: []ModelReference{
						{Provider: "", Model: "claude-3"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group test, model 0: provider cannot be empty",
		},
		{
			name: "nonexistent provider",
			modelGroups: &ModelGroups{
				"test": {
					Models: []ModelReference{
						{Provider: "nonexistent", Model: "model1"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group test, model 0: provider 'nonexistent' does not exist",
		},
		{
			name: "empty model in model reference",
			modelGroups: &ModelGroups{
				"test": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: ""},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group test, model 0: model cannot be empty",
		},
		{
			name: "model not exist in provider",
			modelGroups: &ModelGroups{
				"test": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "nonexistent-model"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			wantErr:       true,
			expectedError: "model group test, model 0: model 'nonexistent-model' does not exist for provider 'anthropic'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Providers:    tt.providers,
				ModelGroups:  tt.modelGroups,
				Router:       RouterConfig{Default: "anthropic"},
				Host:         "localhost",
				Port:         8080,
			}

			err := config.validateModelGroups(map[string]bool{
				"anthropic": true,
				"openai":    true,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("validateModelGroups() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestAliasValidation tests alias validation and duplicate detection
func TestAliasValidation(t *testing.T) {
	tests := []struct {
		name          string
		modelGroups   *ModelGroups
		providers     []Provider
		wantErr       bool
		expectedError string
	}{
		{
			name: "unique aliases",
			modelGroups: &ModelGroups{
				"group1": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
						{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-lite"},
					},
				},
				"group2": {
					Models: []ModelReference{
						{Provider: "openai", Model: "gpt-4", Alias: "gpt4-prod"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku"}},
				{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
			},
			wantErr: false,
		},
		{
			name: "duplicate aliases across groups",
			modelGroups: &ModelGroups{
				"group1": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
					},
				},
				"group2": {
					Models: []ModelReference{
						{Provider: "openai", Model: "gpt-4", Alias: "claude-prod"}, // Duplicate alias
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet"}},
				{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
			},
			wantErr: true, // Error message order can vary due to map iteration
		},
		{
			name: "duplicate aliases within same group",
			modelGroups: &ModelGroups{
				"single": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-dup"},
						{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-dup"}, // Duplicate alias
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku"}},
			},
			wantErr:       true,
			expectedError: "duplicate alias 'claude-dup' found in model groups 'single' and 'single'",
		},
		{
			name: "models without aliases",
			modelGroups: &ModelGroups{
				"no-aliases": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet"},
						{Provider: "openai", Model: "gpt-4"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet"}},
				{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
			},
			wantErr: false,
		},
		{
			name: "mixed aliases and no aliases",
			modelGroups: &ModelGroups{
				"mixed": {
					Models: []ModelReference{
						{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "with-alias"},
						{Provider: "anthropic", Model: "claude-3-haiku"}, // No alias
						{Provider: "openai", Model: "gpt-4", Alias: "another-alias"},
					},
				},
			},
			providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku"}},
				{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Providers:   tt.providers,
				ModelGroups: tt.modelGroups,
				Router:      RouterConfig{Default: "anthropic"},
				Host:        "localhost",
				Port:        8080,
			}

			err := config.validateModelGroups(map[string]bool{
				"anthropic": true,
				"openai":    true,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("validateModelGroups() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestClientAPIKeyValidation tests client API key validation with model group restrictions
func TestClientAPIKeyValidation(t *testing.T) {
	tests := []struct {
		name          string
		clientAPIKeys *ClientAPIKeys
		modelGroups   *ModelGroups
		wantErr       bool
		expectedError string
	}{
		{
			name: "valid client API keys with model groups",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:      "test-api-key-1",
					Description: "Client key 1",
					ModelGroups: []string{"production", "development"},
					Enabled:     true,
					RateLimit:   100,
				},
				"key2": {
					APIKey:      "test-api-key-2",
					Description: "Client key 2",
					ModelGroups: []string{"development"},
					Enabled:     true,
				},
			},
			modelGroups: &ModelGroups{
				"production": {
					Models: []ModelReference{{Provider: "anthropic", Model: "claude-3-sonnet"}},
				},
				"development": {
					Models: []ModelReference{{Provider: "anthropic", Model: "claude-3-haiku"}},
				},
			},
			wantErr: false,
		},
		{
			name: "empty API key ID",
			clientAPIKeys: &ClientAPIKeys{
				"": {
					APIKey: "test-key",
					Enabled: true,
				},
			},
			wantErr:       true,
			expectedError: "client API key ID cannot be empty",
		},
		{
			name: "null API key config",
			clientAPIKeys: &ClientAPIKeys{
				"key1": nil,
			},
			wantErr:       true,
			expectedError: "client API key config for ID 'key1' cannot be null",
		},
		{
			name: "empty API key value",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:  "",
					Enabled: true,
				},
			},
			wantErr:       true,
			expectedError: "client API key key1: apiKey cannot be empty",
		},
		{
			name: "API key too short",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:  "short",
					Enabled: true,
				},
			},
			wantErr:       true,
			expectedError: "client API key key1: apiKey must be at least 8 characters long",
		},
		{
			name: "nonexistent model group",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:      "valid-api-key-123",
					ModelGroups: []string{"nonexistent"},
					Enabled:     true,
				},
			},
			modelGroups: &ModelGroups{
				"production": {
					Models: []ModelReference{{Provider: "anthropic", Model: "claude-3"}},
				},
			},
			wantErr:       true,
			expectedError: "client API key key1: model group 'nonexistent' does not exist",
		},
		{
			name: "negative rate limit",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:     "valid-api-key-123",
					Enabled:    true,
					RateLimit: -1,
				},
			},
			wantErr:       true,
			expectedError: "client API key key1: rateLimit cannot be negative",
		},
		{
			name: "expired API key",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:     "valid-api-key-123",
					Enabled:    true,
					ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired
				},
			},
			wantErr:       true,
			expectedError: "client API key key1: expiration date has passed",
		},
		{
			name: "API key without model groups (unrestricted)",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:      "unrestricted-key-123",
					Description: "Unrestricted key",
					Enabled:     true,
					// No ModelGroups - should be allowed to access all models
				},
			},
			wantErr: false,
		},
		{
			name: "API key disabled",
			clientAPIKeys: &ClientAPIKeys{
				"key1": {
					APIKey:      "disabled-key-123",
					Description: "Disabled key",
					Enabled:     false, // Explicitly disabled
				},
			},
			wantErr: false, // Validation should pass, disabled keys are allowed in config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ClientAPIKeys: tt.clientAPIKeys,
				ModelGroups: tt.modelGroups,
			}

			err := config.validateClientAPIKeys()

			if (err != nil) != tt.wantErr {
				t.Errorf("validateClientAPIKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil {
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

// TestConfigurationMigration tests configuration migration from legacy APIKEY to new system
func TestConfigurationMigration(t *testing.T) {
	tests := []struct {
		name                string
		originalConfig      *Config
		expectedGroups      int
		expectedKeys        int
		expectLegacyKey     bool
		expectedDescription string
	}{
		{
			name: "migrate legacy config with APIKEY",
			originalConfig: &Config{
				APIKEY: "legacy-router-key-123",
				Providers: []Provider{
					{
						Name:       "anthropic",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "anthropic-key",
						BaseURL:    "https://api.anthropic.com",
						Models:     []string{"claude-3-sonnet", "claude-3-haiku"},
					},
					{
						Name:       "openai",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "openai-key",
						BaseURL:    "https://api.openai.com",
						Models:     []string{"gpt-4", "gpt-3.5-turbo"},
					},
				},
				Router: RouterConfig{
					Default: "anthropic",
				},
				Host: "localhost",
				Port: 8080,
			},
			expectedGroups:  2, // One group per provider
			expectedKeys:    1, // Legacy key migrated
			expectLegacyKey: true,
			expectedDescription: "Migrated from legacy APIKEY",
		},
		{
			name: "migrate config without APIKEY",
			originalConfig: &Config{
				APIKEY: "", // No legacy API key
				Providers: []Provider{
					{
						Name:       "anthropic",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "anthropic-key",
						BaseURL:    "https://api.anthropic.com",
						Models:     []string{"claude-3-sonnet"},
					},
				},
				Router: RouterConfig{
					Default: "anthropic",
				},
				Host: "localhost",
				Port: 8080,
			},
			expectedGroups:  1, // One group per provider
			expectedKeys:    0, // No keys migrated (no legacy APIKEY)
			expectLegacyKey: false,
		},
		{
			name: " migrate config that already has model groups",
			originalConfig: &Config{
				APIKEY: "legacy-key",
				Providers: []Provider{
					{
						Name:       "anthropic",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "anthropic-key",
						BaseURL:    "https://api.anthropic.com",
						Models:     []string{"claude-3-sonnet"},
					},
				},
				ModelGroups: &ModelGroups{
					"custom-group": {
						Description: "Custom group",
						Models: []ModelReference{
							{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-custom"},
						},
					},
				},
				Router: RouterConfig{
					Default: "anthropic",
				},
				Host: "localhost",
				Port: 8080,
			},
			expectedGroups:  1, // Should preserve existing groups
			expectedKeys:    1, // Should migrate legacy key
			expectLegacyKey: true,
		},
		{
			name: "already migrated config",
			originalConfig: &Config{
				APIKEY: "legacy-key",
				Providers: []Provider{
					{
						Name:       "anthropic",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "anthropic-key",
						BaseURL:    "https://api.anthropic.com",
						Models:     []string{"claude-3-sonnet"},
					},
				},
				ModelGroups: &ModelGroups{
					"anthropic-models": {
						Description: "All models from anthropic provider",
						Models: []ModelReference{
							{Provider: "anthropic", Model: "claude-3-sonnet"},
						},
					},
				},
				ClientAPIKeys: &ClientAPIKeys{
					"default-legacy": {
						APIKey:      "legacy-key",
						Description: "Migrated from legacy APIKEY",
						Enabled:     true,
					},
				},
				Router: RouterConfig{
					Default: "anthropic",
				},
				Host: "localhost",
				Port: 8080,
			},
			expectedGroups:  1, // Should preserve existing groups
			expectedKeys:    1, // Should preserve existing keys
			expectLegacyKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy for migration testing
			config := &Config{
				APIKEY:       tt.originalConfig.APIKEY,
				Providers:    tt.originalConfig.Providers,
				ModelGroups:  tt.originalConfig.ModelGroups,
				ClientAPIKeys: tt.originalConfig.ClientAPIKeys,
				Router:       tt.originalConfig.Router,
				Host:         tt.originalConfig.Host,
				Port:         tt.originalConfig.Port,
			}

			// Perform migration
			err := config.MigrateLegacyConfig()
			if err != nil {
				t.Fatalf("MigrateLegacyConfig() failed: %v", err)
			}

			// Check model groups
			if config.ModelGroups == nil {
				t.Error("ModelGroups should not be nil after migration")
			} else if len(*config.ModelGroups) != tt.expectedGroups {
				t.Errorf("Expected %d model groups, got %d", tt.expectedGroups, len(*config.ModelGroups))
			}

			// Check client API keys
			if config.ClientAPIKeys == nil {
				t.Error("ClientAPIKeys should not be nil after migration")
			} else if len(*config.ClientAPIKeys) != tt.expectedKeys {
				t.Errorf("Expected %d client API keys, got %d", tt.expectedKeys, len(*config.ClientAPIKeys))
			}

			// Check legacy key migration
			if tt.expectLegacyKey {
				legacyKeyFound := false
				descriptionFound := false
				var legacyKeyConfig *APIKeyConfig
				for keyID, keyConfig := range *config.ClientAPIKeys {
					if keyID == "default-legacy" && keyConfig.APIKey == tt.originalConfig.APIKEY {
						legacyKeyFound = true
						legacyKeyConfig = keyConfig
						if keyConfig.Description == tt.expectedDescription {
							descriptionFound = true
						}
						break
					}
				}
				if !legacyKeyFound {
					t.Error("Expected legacy key to be migrated")
				}
				if !descriptionFound && tt.expectedDescription != "" {
					t.Errorf("Expected description '%s', got '%s'", tt.expectedDescription, legacyKeyConfig.Description)
				}
			}

			// Validate migrated configuration
			if err := config.Validate(); err != nil {
				t.Errorf("Migrated configuration should be valid: %v", err)
			}
		})
	}
}

// TestModelGroupHelperFunctions tests helper functions for model groups
func TestModelGroupHelperFunctions(t *testing.T) {
	// Setup test configuration
	modelGroups := ModelGroups{
		"production": {
			Description: "Production models",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "claude-prod"},
				{Provider: "openai", Model: "gpt-4"},
			},
		},
		"development": {
			Description: "Development models",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-haiku", Alias: "claude-dev"},
			},
		},
	}

	clientAPIKeys := ClientAPIKeys{
		"prod-key": {
			APIKey:      "prod-api-key-123",
			Description: "Production key",
			ModelGroups: []string{"production"},
			Enabled:     true,
			RateLimit:   100,
		},
		"unrestricted-key": {
			APIKey:      "unrestricted-api-key-456",
			Description: "Unrestricted key",
			ModelGroups: []string{}, // Empty array means unrestricted
			Enabled:     true,
		},
		"disabled-key": {
			APIKey:      "disabled-api-key-789",
			Description: "Disabled key",
			ModelGroups: []string{"production"},
			Enabled:     false, // Disabled
		},
	}

	config := &Config{
		Providers: []Provider{
			{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku"}},
			{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4"}},
		},
		ModelGroups:  &modelGroups,
		ClientAPIKeys: &clientAPIKeys,
		Router:       RouterConfig{Default: "anthropic"},
		Host:         "localhost",
		Port:         8080,
	}

	// Test GetModelGroup
	t.Run("GetModelGroup", func(t *testing.T) {
		// Test existing group
		group, err := config.GetModelGroup("production")
		if err != nil {
			t.Errorf("GetModelGroup() failed for existing group: %v", err)
		}
		if group.Description != "Production models" {
			t.Errorf("Expected 'Production models', got '%s'", group.Description)
		}

		// Test non-existent group
		_, err = config.GetModelGroup("nonexistent")
		if err == nil {
			t.Error("GetModelGroup() should return error for non-existent group")
		}

		// Test with nil model groups
		config.ModelGroups = nil
		_, err = config.GetModelGroup("production")
		if err == nil {
			t.Error("GetModelGroup() should return error when ModelGroups is nil")
		}

		// Restore
		config.ModelGroups = &modelGroups
	})

	// Test GetClientAPIKey
	t.Run("GetClientAPIKey", func(t *testing.T) {
		// Test existing key
		keyConfig, err := config.GetClientAPIKey("prod-key")
		if err != nil {
			t.Errorf("GetClientAPIKey() failed for existing key: %v", err)
		}
		if keyConfig.APIKey != "prod-api-key-123" {
			t.Errorf("Expected 'prod-api-key-123', got '%s'", keyConfig.APIKey)
		}

		// Test non-existent key
		_, err = config.GetClientAPIKey("nonexistent")
		if err == nil {
			t.Error("GetClientAPIKey() should return error for non-existent key")
		}

		// Test with nil client API keys
		config.ClientAPIKeys = nil
		_, err = config.GetClientAPIKey("prod-key")
		if err == nil {
			t.Error("GetClientAPIKey() should return error when ClientAPIKeys is nil")
		}

		// Restore
		config.ClientAPIKeys = &clientAPIKeys
	})

	// Test ValidateClientAPIKey
	t.Run("ValidateClientAPIKey", func(t *testing.T) {
		// Test valid enabled key
		keyConfig, err := config.ValidateClientAPIKey("prod-api-key-123")
		if err != nil {
			t.Errorf("ValidateClientAPIKey() failed for valid key: %v", err)
		}
		if keyConfig.Description != "Production key" {
			t.Errorf("Expected 'Production key', got '%s'", keyConfig.Description)
		}

		// Test disabled key
		_, err = config.ValidateClientAPIKey("disabled-api-key-789")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error for disabled key")
		}

		// Test invalid key
		_, err = config.ValidateClientAPIKey("invalid-key")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error for invalid key")
		}

		// Test empty key
		_, err = config.ValidateClientAPIKey("")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error for empty key")
		}

		// Test with nil client API keys
		config.ClientAPIKeys = nil
		_, err = config.ValidateClientAPIKey("prod-api-key-123")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error when ClientAPIKeys is nil")
		}

		// Restore
		config.ClientAPIKeys = &clientAPIKeys
	})

	// Test GetModelReferenceByAlias
	t.Run("GetModelReferenceByAlias", func(t *testing.T) {
		// Test existing alias
		modelRef, err := config.GetModelReferenceByAlias("claude-prod")
		if err != nil {
			t.Errorf("GetModelReferenceByAlias() failed for existing alias: %v", err)
		}
		if modelRef.Provider != "anthropic" || modelRef.Model != "claude-3-sonnet" {
			t.Errorf("Expected provider 'anthropic' and model 'claude-3-sonnet', got '%s' and '%s'", modelRef.Provider, modelRef.Model)
		}

		// Test non-existent alias
		_, err = config.GetModelReferenceByAlias("nonexistent-alias")
		if err == nil {
			t.Error("GetModelReferenceByAlias() should return error for non-existent alias")
		}

		// Test with nil model groups
		config.ModelGroups = nil
		_, err = config.GetModelReferenceByAlias("claude-prod")
		if err == nil {
			t.Error("GetModelReferenceByAlias() should return error when ModelGroups is nil")
		}

		// Restore
		config.ModelGroups = &modelGroups
	})
}

// TestModelAliasResolution tests model alias resolution functionality
func TestModelAliasResolution(t *testing.T) {
	modelGroups := ModelGroups{
		"multi-provider": {
			Description: "Models from multiple providers",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "best-claude"},
				{Provider: "openai", Model: "gpt-4", Alias: "best-gpt"},
				{Provider: "anthropic", Model: "claude-3-haiku", Alias: "fast-claude"},
			},
		},
		"no-alias-group": {
			Description: "Models without aliases",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-opus"},
				{Provider: "openai", Model: "gpt-3.5-turbo"},
			},
		},
	}

	config := &Config{
		Providers: []Provider{
			{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet", "claude-3-haiku", "claude-3-opus"}},
			{Name: "openai", AuthMethod: AuthMethodAPIKey, APIKEY: "key2", BaseURL: "https://api.openai.com", Models: []string{"gpt-4", "gpt-3.5-turbo"}},
		},
		ModelGroups: &modelGroups,
	}

	tests := []struct {
		name                string
		alias               string
		expectedProvider    string
		expectedModel       string
		expectError         bool
		expectedError       string
	}{
		{
			name:             "valid alias - first provider",
			alias:            "best-claude",
			expectedProvider: "anthropic",
			expectedModel:    "claude-3-sonnet",
			expectError:      false,
		},
		{
			name:             "valid alias - second provider",
			alias:            "best-gpt",
			expectedProvider: "openai",
			expectedModel:    "gpt-4",
			expectError:      false,
		},
		{
			name:          "non-existent alias",
			alias:         "nonexistent",
			expectError:   true,
			expectedError: "model alias not found: nonexistent",
		},
		{
			name:          "empty alias",
			alias:         "",
			expectError:   true,
			expectedError: "alias cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modelRef, err := config.GetModelReferenceByAlias(tt.alias)

			if (err != nil) != tt.expectError {
				t.Errorf("GetModelReferenceByAlias() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if tt.expectError && err != nil {
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			}

			if !tt.expectError {
				if modelRef.Provider != tt.expectedProvider {
					t.Errorf("Expected provider '%s', got '%s'", tt.expectedProvider, modelRef.Provider)
				}
				if modelRef.Model != tt.expectedModel {
					t.Errorf("Expected model '%s', got '%s'", tt.expectedModel, modelRef.Model)
				}
			}
		})
	}
}

// TestModelGroupCRUDOperations tests CRUD operations for model groups and API keys
func TestModelGroupCRUDOperations(t *testing.T) {
	config := &Config{
		Providers: []Provider{
			{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3-sonnet"}},
		},
		ModelGroups: &ModelGroups{},
		ClientAPIKeys: &ClientAPIKeys{},
	}

	t.Run("AddModelGroup", func(t *testing.T) {
		// Test adding new model group
		newGroup := &ModelGroup{
			Description: "New test group",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet", Alias: "test-alias"},
			},
		}

		err := config.AddModelGroup("test-group", newGroup)
		if err != nil {
			t.Errorf("AddModelGroup() failed: %v", err)
		}

		// Verify group was added
		group, err := config.GetModelGroup("test-group")
		if err != nil {
			t.Errorf("GetModelGroup() failed for newly added group: %v", err)
		}
		if group.Description != "New test group" {
			t.Errorf("Expected 'New test group', got '%s'", group.Description)
		}

		// Test adding duplicate group
		err = config.AddModelGroup("test-group", newGroup)
		if err == nil {
			t.Error("AddModelGroup() should return error for duplicate group")
		}

		// Test nil model groups initialization
		config.ModelGroups = nil
		err = config.AddModelGroup("test-group-2", newGroup)
		if err != nil {
			t.Errorf("AddModelGroup() should initialize nil ModelGroups: %v", err)
		}

		// Restore
		config.ModelGroups = &ModelGroups{}
	})

	t.Run("AddClientAPIKey", func(t *testing.T) {
		// Test adding new API key
		newKey := &APIKeyConfig{
			APIKey:      "new-test-key-123",
			Description: "New test key",
			ModelGroups: []string{"test-group"},
			Enabled:     true,
		}

		err := config.AddClientAPIKey("test-key", newKey)
		if err != nil {
			t.Errorf("AddClientAPIKey() failed: %v", err)
		}

		// Verify key was added
		keyConfig, err := config.GetClientAPIKey("test-key")
		if err != nil {
			t.Errorf("GetClientAPIKey() failed for newly added key: %v", err)
		}
		if keyConfig.Description != "New test key" {
			t.Errorf("Expected 'New test key', got '%s'", keyConfig.Description)
		}

		// Test adding duplicate key
		err = config.AddClientAPIKey("test-key", newKey)
		if err == nil {
			t.Error("AddClientAPIKey() should return error for duplicate key")
		}

		// Test nil client API keys initialization
		config.ClientAPIKeys = nil
		err = config.AddClientAPIKey("test-key-2", newKey)
		if err != nil {
			t.Errorf("AddClientAPIKey() should initialize nil ClientAPIKeys: %v", err)
		}

		// Restore
		config.ClientAPIKeys = &ClientAPIKeys{}
	})

	t.Run("RemoveModelGroup", func(t *testing.T) {
		// Add a group first
		testGroup := &ModelGroup{
			Description: "Group to remove",
			Models: []ModelReference{
				{Provider: "anthropic", Model: "claude-3-sonnet"},
			},
		}
		config.AddModelGroup("remove-me", testGroup)

		// Test removing existing group
		err := config.RemoveModelGroup("remove-me")
		if err != nil {
			t.Errorf("RemoveModelGroup() failed: %v", err)
		}

		// Verify group was removed
		_, err = config.GetModelGroup("remove-me")
		if err == nil {
			t.Error("GetModelGroup() should return error for removed group")
		}

		// Test removing non-existent group
		err = config.RemoveModelGroup("nonexistent")
		if err == nil {
			t.Error("RemoveModelGroup() should return error for non-existent group")
		}

		// Test with nil model groups
		config.ModelGroups = nil
		err = config.RemoveModelGroup("any")
		if err == nil {
			t.Error("RemoveModelGroup() should return error when ModelGroups is nil")
		}
	})

	t.Run("RemoveClientAPIKey", func(t *testing.T) {
		// Add a key first
		testKey := &APIKeyConfig{
			APIKey: "remove-me-key-123",
			Enabled: true,
		}
		config.AddClientAPIKey("remove-me", testKey)

		// Test removing existing key
		err := config.RemoveClientAPIKey("remove-me")
		if err != nil {
			t.Errorf("RemoveClientAPIKey() failed: %v", err)
		}

		// Verify key was removed
		_, err = config.GetClientAPIKey("remove-me")
		if err == nil {
			t.Error("GetClientAPIKey() should return error for removed key")
		}

		// Test removing non-existent key
		err = config.RemoveClientAPIKey("nonexistent")
		if err == nil {
			t.Error("RemoveClientAPIKey() should return error for non-existent key")
		}

		// Test with nil client API keys
		config.ClientAPIKeys = nil
		err = config.RemoveClientAPIKey("any")
		if err == nil {
			t.Error("RemoveClientAPIKey() should return error when ClientAPIKeys is nil")
		}
	})
}

// TestCanAPIKeyAccessGroup tests the CanAPIKeyAccessGroup function
func TestCanAPIKeyAccessGroup(t *testing.T) {
	config := &Config{
		ModelGroups: &ModelGroups{
			"production": {
				Description: "Production models",
				Models: []ModelReference{
					{Provider: "anthropic", Model: "claude-3-sonnet"},
				},
			},
			"development": {
				Description: "Development models",
				Models: []ModelReference{
					{Provider: "anthropic", Model: "claude-3-haiku"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		keyConfig      *APIKeyConfig
		groupName      string
		expectedResult bool
	}{
		{
			name: "unrestricted key can access any group",
			keyConfig: &APIKeyConfig{
				ModelGroups: []string{}, // Empty = unrestricted
			},
			groupName:      "production",
			expectedResult: true,
		},
		{
			name: "restricted key can access allowed group",
			keyConfig: &APIKeyConfig{
				ModelGroups: []string{"production", "development"},
			},
			groupName:      "production",
			expectedResult: true,
		},
		{
			name: "restricted key cannot access disallowed group",
			keyConfig: &APIKeyConfig{
				ModelGroups: []string{"development"},
			},
			groupName:      "production",
			expectedResult: false,
		},
		{
			name: "restricted key with group not configured",
			keyConfig: &APIKeyConfig{
				ModelGroups: []string{"staging"}, // Group doesn't exist
			},
			groupName:      "production",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := config.CanAPIKeyAccessGroup(tt.keyConfig, tt.groupName)
			if result != tt.expectedResult {
				t.Errorf("CanAPIKeyAccessGroup() = %v, expected %v", result, tt.expectedResult)
			}
		})
	}
}

// TestEdgeCases tests edge cases and error conditions
func TestEdgeCases(t *testing.T) {
	t.Run("empty model groups", func(t *testing.T) {
		config := &Config{
			Providers: []Provider{
				{Name: "anthropic", AuthMethod: AuthMethodAPIKey, APIKEY: "key1", BaseURL: "https://api.anthropic.com", Models: []string{"claude-3"}},
			},
			ModelGroups: &ModelGroups{},
			Router:      RouterConfig{Default: "anthropic"},
			Host:        "localhost",
			Port:        8080,
		}

		// Should validate without errors
		err := config.Validate()
		if err != nil {
			t.Errorf("Config with empty model groups should be valid: %v", err)
		}

		// Helper functions should handle gracefully
		group, err := config.GetModelGroup("any")
		if err == nil {
			t.Error("GetModelGroup() should return error for empty model groups")
		}
		if group != nil {
			t.Error("GetModelGroup() should return nil group for empty model groups")
		}

		modelRef, err := config.GetModelReferenceByAlias("any")
		if err == nil {
			t.Error("GetModelReferenceByAlias() should return error for empty model groups")
		}
		if modelRef != nil {
			t.Error("GetModelReferenceByAlias() should return nil for empty model groups")
		}
	})

	t.Run("empty client API keys", func(t *testing.T) {
		config := &Config{
			ClientAPIKeys: &ClientAPIKeys{},
		}

		// Should validate without errors
		err := config.validateClientAPIKeys()
		if err != nil {
			t.Errorf("Config with empty client API keys should be valid: %v", err)
		}

		// Helper functions should handle gracefully
		keyConfig, err := config.GetClientAPIKey("any")
		if err == nil {
			t.Error("GetClientAPIKey() should return error for empty client API keys")
		}
		if keyConfig != nil {
			t.Error("GetClientAPIKey() should return nil for empty client API keys")
		}

		validationResult, err := config.ValidateClientAPIKey("any-key")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error for empty client API keys")
		}
		if validationResult != nil {
			t.Error("ValidateClientAPIKey() should return nil for empty client API keys")
		}
	})

	t.Run("nil pointers", func(t *testing.T) {
		config := &Config{
			ModelGroups:   nil,
			ClientAPIKeys: nil,
		}

		// Should not panic
		groups := config.GetAvailableModelGroups()
		if len(groups) != 0 {
			t.Errorf("GetAvailableModelGroups() should return empty slice for nil ModelGroups, got %d", len(groups))
		}

		// Should handle gracefully
		group, err := config.GetModelGroup("any")
		if err == nil {
			t.Error("GetModelGroup() should return error for nil ModelGroups")
		}
		if group != nil {
			t.Error("GetModelGroup() should return nil for nil ModelGroups")
		}

		keyConfig, err := config.GetClientAPIKey("any")
		if err == nil {
			t.Error("GetClientAPIKey() should return error for nil ClientAPIKeys")
		}
		if keyConfig != nil {
			t.Error("GetClientAPIKey() should return nil for nil ClientAPIKeys")
		}

		validationResult, err := config.ValidateClientAPIKey("any-key")
		if err == nil {
			t.Error("ValidateClientAPIKey() should return error for nil ClientAPIKeys")
		}
		if validationResult != nil {
			t.Error("ValidateClientAPIKey() should return nil for nil ClientAPIKeys")
		}

		modelRef, err := config.GetModelReferenceByAlias("any")
		if err == nil {
			t.Error("GetModelReferenceByAlias() should return error for nil ModelGroups")
		}
		if modelRef != nil {
			t.Error("GetModelReferenceByAlias() should return nil for nil ModelGroups")
		}
	})
}

// TestFullConfigurationWithModelGroups tests a complete configuration with model groups
func TestFullConfigurationWithModelGroups(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "full-config.json")

	// Create comprehensive configuration with model groups
	configContent := `{
  "Providers": [
    {
      "name": "anthropic",
      "authMethod": "api_key",
      "APIKEY": "anthropic-key-123",
      "baseURL": "https://api.anthropic.com",
      "models": ["claude-3-sonnet", "claude-3-haiku", "claude-3-opus"]
    },
    {
      "name": "openai",
      "authMethod": "api_key",
      "APIKEY": "openai-key-456",
      "baseURL": "https://api.openai.com",
      "models": ["gpt-4", "gpt-3.5-turbo"]
    }
  ],
  "Router": {
    "default": "anthropic",
    "background": "openai",
    "longContextThreshold": 100000
  },
  "APIKEY": "legacy-router-key",
  "HOST": "localhost",
  "PORT": 8080,
  "ModelGroups": {
    "production": {
      "description": "Production-grade models",
      "models": [
        {"provider": "anthropic", "model": "claude-3-sonnet", "alias": "claude-prod"},
        {"provider": "openai", "model": "gpt-4", "alias": "gpt4-prod"}
      ]
    },
    "development": {
      "description": "Development models",
      "models": [
        {"provider": "anthropic", "model": "claude-3-haiku", "alias": "claude-dev"},
        {"provider": "openai", "model": "gpt-3.5-turbo", "alias": "gpt35-dev"}
      ]
    },
    "anthropic-models": {
      "description": "All Anthropic models",
      "models": [
        {"provider": "anthropic", "model": "claude-3-sonnet", "alias": "claude-sonnet"},
        {"provider": "anthropic", "model": "claude-3-haiku", "alias": "claude-haiku"},
        {"provider": "anthropic", "model": "claude-3-opus", "alias": "claude-opus"}
      ]
    }
  },
  "ClientAPIKeys": {
    "client-1": {
      "apiKey": "client-key-123",
      "description": "Client 1 - Production access",
      "modelGroups": ["production", "anthropic-models"],
      "rateLimit": 100,
      "enabled": true
    },
    "client-2": {
      "apiKey": "client-key-456",
      "description": "Client 2 - Development access",
      "modelGroups": ["development"],
      "rateLimit": 50,
      "enabled": true
    },
    "client-admin": {
      "apiKey": "admin-key-789",
      "description": "Admin access - unrestricted",
      "modelGroups": [],
      "enabled": true
    }
  }
}`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load configuration
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test loaded configuration validation
	if err := cfg.Validate(); err != nil {
		t.Errorf("Loaded configuration should be valid: %v", err)
	}

	// Test helper functions
	groups := cfg.GetAvailableModelGroups()
	if len(groups) != 3 {
		t.Errorf("Expected 3 model groups, got %d", len(groups))
	}

	// Check production group
	prodGroup, err := cfg.GetModelGroup("production")
	if err != nil {
		t.Errorf("Failed to get production group: %v", err)
	}
	if len(prodGroup.Models) != 2 {
		t.Errorf("Production group should have 2 models, got %d", len(prodGroup.Models))
	}

	// Check alias resolution
	claudeProdRef, err := cfg.GetModelReferenceByAlias("claude-prod")
	if err != nil {
		t.Errorf("Failed to resolve claude-prod alias: %v", err)
	}
	if claudeProdRef.Provider != "anthropic" || claudeProdRef.Model != "claude-3-sonnet" {
		t.Errorf("Incorrect alias resolution: got %s:%s", claudeProdRef.Provider, claudeProdRef.Model)
	}

	// Check client API key validation
	clientKey, err := cfg.ValidateClientAPIKey("admin-key-789")
	if err != nil {
		t.Errorf("Failed to validate admin key: %v", err)
	}
	if clientKey.Description != "Admin access - unrestricted" {
		t.Errorf("Expected 'Admin access - unrestricted', got '%s'", clientKey.Description)
	}

	// Check model access permission
	client1Key, _ := cfg.GetClientAPIKey("client-1")
	canAccess := cfg.CanAPIKeyAccessGroup(client1Key, "production")
	if !canAccess {
		t.Error("Client 1 should be able to access production group")
	}

	canAccess = cfg.CanAPIKeyAccessGroup(client1Key, "development")
	if canAccess {
		t.Error("Client 1 should not be able to access development group")
	}

	// Save and reload
	if err := Save(cfg, configPath, true); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	reloaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	// Verify reloaded configuration
	if len(reloaded.Providers) != len(cfg.Providers) {
		t.Error("Reloaded configuration has different number of providers")
	}

	if len(*reloaded.ModelGroups) != len(*cfg.ModelGroups) {
		t.Error("Reloaded configuration has different number of model groups")
	}

	if len(*reloaded.ClientAPIKeys) != len(*cfg.ClientAPIKeys) {
		t.Error("Reloaded configuration has different number of client API keys")
	}
}