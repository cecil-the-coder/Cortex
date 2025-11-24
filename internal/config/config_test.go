package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// Set environment variables for testing
	os.Setenv("TEST_API_KEY", "test-key-123")
	os.Setenv("TEST_BASE_URL", "https://test.api.com")
	defer os.Unsetenv("TEST_API_KEY")
	defer os.Unsetenv("TEST_BASE_URL")

	// Write test config
	configContent := `{
  "Providers": [
    {
      "name": "test-provider",
      "authMethod": "api_key",
      "APIKEY": "${TEST_API_KEY}",
      "baseURL": "$TEST_BASE_URL",
      "models": ["model-1", "model-2"]
    }
  ],
  "Router": {
    "default": "test-provider",
    "longContextThreshold": 50000
  },
  "APIKEY": "router-key",
  "HOST": "localhost",
  "PORT": 8080
}`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify environment variable interpolation
	if cfg.Providers[0].APIKEY != "test-key-123" {
		t.Errorf("Expected API key 'test-key-123', got '%s'", cfg.Providers[0].APIKEY)
	}

	if cfg.Providers[0].BaseURL != "https://test.api.com" {
		t.Errorf("Expected base URL 'https://test.api.com', got '%s'", cfg.Providers[0].BaseURL)
	}

	// Verify other fields
	if cfg.Router.Default != "test-provider" {
		t.Errorf("Expected default router 'test-provider', got '%s'", cfg.Router.Default)
	}

	if cfg.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Port)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "key1",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
				Host: "localhost",
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "no providers",
			config: &Config{
				Providers: []Provider{},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: true,
		},
		{
			name: "no default router",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "key1",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{},
			},
			wantErr: true,
		},
		{
			name: "duplicate provider names",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "key1",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
					{
						Name:       "provider1",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "key2",
						BaseURL:    "https://api2.example.com",
						Models:     []string{"model2"},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: true,
		},
		{
			name: "router references unknown provider",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodAPIKey,
						APIKEY:     "key1",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{
					Default:   "provider1",
					LongContext: "unknown-provider",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	config := &Config{
		Providers: []Provider{
			{
				Name:       "provider1",
				AuthMethod: AuthMethodAPIKey,
				APIKEY:     "key1",
				BaseURL:    "https://api.example.com",
				Models:     []string{"model1"},
			},
		},
		Router: RouterConfig{
			Default:              "provider1",
			LongContextThreshold: 100000,
		},
		APIKEY: "router-key",
		Host:   "localhost",
		Port:   8080,
	}

	// Save without backup
	if err := Save(config, configPath, false); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Config file was not created")
	}

	// Load and verify
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loaded.Providers[0].Name != config.Providers[0].Name {
		t.Errorf("Provider name mismatch: got %s, want %s", loaded.Providers[0].Name, config.Providers[0].Name)
	}
}

func TestSaveConfigWithBackup(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	config := &Config{
		Providers: []Provider{
			{
				Name:       "provider1",
				AuthMethod: AuthMethodAPIKey,
				APIKEY:     "key1",
				BaseURL:    "https://api.example.com",
				Models:     []string{"model1"},
			},
		},
		Router: RouterConfig{
			Default: "provider1",
		},
		APIKEY: "router-key",
		Host:   "localhost",
		Port:   8080,
	}

	// Save initial config
	if err := Save(config, configPath, false); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Modify and save with backup
	config.Port = 9090
	if err := Save(config, configPath, true); err != nil {
		t.Fatalf("Failed to save config with backup: %v", err)
	}

	// Check if backup was created
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}

	backupFound := false
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" && filepath.Base(configPath) != file.Name() {
			backupFound = true
			break
		}
	}

	if !backupFound {
		t.Error("Backup file was not created")
	}
}

func TestGetProvider(t *testing.T) {
	config := &Config{
		Providers: []Provider{
			{
				Name:       "provider1",
				AuthMethod: AuthMethodAPIKey,
				APIKEY:     "key1",
				BaseURL:    "https://api1.example.com",
				Models:     []string{"model1"},
			},
			{
				Name:       "provider2",
				AuthMethod: AuthMethodAPIKey,
				APIKEY:     "key2",
				BaseURL:    "https://api2.example.com",
				Models:     []string{"model2"},
			},
		},
		Router: RouterConfig{
			Default: "provider1",
		},
	}

	// Test finding existing provider
	provider, err := config.GetProvider("provider1")
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}
	if provider.Name != "provider1" {
		t.Errorf("Got wrong provider: %s", provider.Name)
	}

	// Test non-existent provider
	_, err = config.GetProvider("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent provider")
	}
}

func TestGetProviderForModel(t *testing.T) {
	config := &Config{
		Providers: []Provider{
			{
				Name:    "provider1",
				APIKEY:  "key1",
				BaseURL: "https://api1.example.com",
				Models:  []string{"model1", "model2"},
			},
			{
				Name:       "provider2",
				AuthMethod: AuthMethodAPIKey,
				APIKEY:     "key2",
				BaseURL:    "https://api2.example.com",
				Models:     []string{"model3", "model4"},
			},
		},
		Router: RouterConfig{
			Default: "provider1",
		},
	}

	// Test finding provider for existing model
	provider, err := config.GetProviderForModel("model3")
	if err != nil {
		t.Fatalf("Failed to get provider for model: %v", err)
	}
	if provider.Name != "provider2" {
		t.Errorf("Got wrong provider: %s", provider.Name)
	}

	// Test non-existent model
	_, err = config.GetProviderForModel("nonexistent-model")
	if err == nil {
		t.Error("Expected error for non-existent model")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if len(config.Providers) == 0 {
		t.Error("Default config should have providers")
	}

	if config.Router.Default == "" {
		t.Error("Default config should have a default router")
	}

	if config.Port == 0 {
		t.Error("Default config should have a port")
	}

	if err := config.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}

func TestOAuthCredentialSet(t *testing.T) {
	tests := []struct {
		name   string
		oauth  *OAuthCredentialSet
		valid  bool
		token  string
	}{
		{
			name: "valid OAuth credentials",
			oauth: &OAuthCredentialSet{
				ClientID:     "client123",
				ClientSecret: "secret456",
				TokenURL:     "https://oauth.example.com/token",
				AccessToken:  "access123",
				RefreshToken: "refresh456",
				ExpiresAt:    time.Now().Add(1 * time.Hour), // Valid
			},
			valid: true,
			token: "access123",
		},
		{
			name: "expired OAuth credentials",
			oauth: &OAuthCredentialSet{
				ClientID:     "client123",
				ClientSecret: "secret456",
				TokenURL:     "https://oauth.example.com/token",
				AccessToken:  "access123",
				RefreshToken: "refresh456",
				ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
			},
			valid: false,
			token: "access123",
		},
		{
			name: "no access token",
			oauth: &OAuthCredentialSet{
				ClientID:     "client123",
				ClientSecret: "secret456",
				TokenURL:     "https://oauth.example.com/token",
				RefreshToken: "refresh456",
			},
			valid: false,
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.oauth.IsValid() != tt.valid {
				t.Errorf("IsValid() = %v, want %v", tt.oauth.IsValid(), tt.valid)
			}

			accessToken, _, _, _ := tt.oauth.GetTokens()
			if accessToken != tt.token {
				t.Errorf("GetTokens() accessToken = %v, want %v", accessToken, tt.token)
			}

			// Test token updates
			tt.oauth.UpdateTokens("new-access", "new-refresh", "Bearer", 3600)
			newAccessToken, newRefreshToken, newTokenType, newExpiresAt := tt.oauth.GetTokens()
			if newAccessToken != "new-access" {
				t.Errorf("After UpdateTokens, accessToken = %v, want new-access", newAccessToken)
			}
			if newRefreshToken != "new-refresh" {
				t.Errorf("After UpdateTokens, refreshToken = %v, want new-refresh", newRefreshToken)
			}
			if newTokenType != "Bearer" {
				t.Errorf("After UpdateTokens, tokenType = %v, want Bearer", newTokenType)
			}
			// Should expire approximately 1 hour from now
			if time.Until(newExpiresAt) < time.Hour-5*time.Minute || time.Until(newExpiresAt) > time.Hour+5*time.Minute {
				t.Errorf("After UpdateTokens, expiresAt should be ~1 hour from now, got %v", time.Until(newExpiresAt))
			}
		})
	}
}

func TestHybridAuthValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid hybrid auth with API key and OAuth",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodHybrid,
						APIKEY:     "api-key-123",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
						OAuth: &OAuthCredentialSet{
							ClientID:     "client123",
							ClientSecret: "secret456",
							TokenURL:     "https://oauth.example.com/token",
						},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: false,
		},
		{
			name: "valid hybrid auth with API key only",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodHybrid,
						APIKEY:     "api-key-123",
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: false,
		},
		{
			name: "valid hybrid auth with OAuth only",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodHybrid,
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
						OAuth: &OAuthCredentialSet{
							ClientID:     "client123",
							ClientSecret: "secret456",
							TokenURL:     "https://oauth.example.com/token",
						},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid hybrid auth with no authentication",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodHybrid,
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: true,
		},
		{
			name: "valid OAuth only auth",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodOAuth,
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
						OAuth: &OAuthCredentialSet{
							ClientID:     "client123",
							ClientSecret: "secret456",
							TokenURL:     "https://oauth.example.com/token",
						},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid OAuth only auth without OAuth config",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodOAuth,
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid OAuth only auth with missing token URL",
			config: &Config{
				Providers: []Provider{
					{
						Name:       "provider1",
						AuthMethod: AuthMethodOAuth,
						BaseURL:    "https://api.example.com",
						Models:     []string{"model1"},
						OAuth: &OAuthCredentialSet{
							ClientID:     "client123",
							ClientSecret: "secret456",
						},
					},
				},
				Router: RouterConfig{
					Default: "provider1",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOAuthCredentialManagement(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "oauth-config.json")

	// Create config with OAuth provider
	config := &Config{
		Providers: []Provider{
			{
				Name:       "oauth-provider",
				AuthMethod: AuthMethodOAuth,
				BaseURL:    "https://oauth.api.com",
				Models:     []string{"model1"},
				OAuth: &OAuthCredentialSet{
					ClientID:     "client123",
					ClientSecret: "secret456",
					TokenURL:     "https://oauth.example.com/token",
					AccessToken:  "access123",
					RefreshToken: "refresh456",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
				},
			},
		},
		Router: RouterConfig{
			Default: "oauth-provider",
		},
		APIKEY: "router-key",
		Host:   "localhost",
		Port:   8080,
	}

	// Save configuration
	if err := Save(config, configPath, false); err != nil {
		t.Fatalf("Failed to save OAuth config: %v", err)
	}

	// Load and verify
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load OAuth config: %v", err)
	}

	provider, err := loaded.GetProvider("oauth-provider")
	if err != nil {
		t.Fatalf("Failed to get OAuth provider: %v", err)
	}

	if provider.AuthMethod != AuthMethodOAuth {
		t.Errorf("Expected AuthMethod %s, got %s", AuthMethodOAuth, provider.AuthMethod)
	}

	if provider.OAuth == nil {
		t.Fatal("OAuth credentials should not be nil")
	}

	if !loaded.IsOAuthConfigured("oauth-provider") {
		t.Error("OAuth should be configured for oauth-provider")
	}

	if loaded.IsAPIKeyConfigured("oauth-provider") {
		t.Error("API key should not be configured for OAuth-only provider")
	}
}

func TestHybridProviderConfiguration(t *testing.T) {
	config := &Config{
		Providers: []Provider{
			{
				Name:       "hybrid-provider",
				AuthMethod: AuthMethodHybrid,
				APIKEY:     "api-key-123",
				BaseURL:    "https://hybrid.api.com",
				Models:     []string{"model1"},
				OAuth: &OAuthCredentialSet{
					ClientID:     "client123",
					ClientSecret: "secret456",
					TokenURL:     "https://oauth.example.com/token",
					AccessToken:  "access123",
					RefreshToken: "refresh456",
					ExpiresAt:    time.Now().Add(1 * time.Hour),
				},
			},
		},
		Router: RouterConfig{
			Default: "hybrid-provider",
		},
	}

	if !config.IsOAuthConfigured("hybrid-provider") {
		t.Error("OAuth should be configured for hybrid provider")
	}

	if !config.IsAPIKeyConfigured("hybrid-provider") {
		t.Error("API key should be configured for hybrid provider")
	}

	authMethod := config.GetAuthMethod("hybrid-provider")
	if authMethod != AuthMethodHybrid {
		t.Errorf("Expected AuthMethod %s, got %s", AuthMethodHybrid, authMethod)
	}
}

func TestOAuthCredentialUpdate(t *testing.T) {
	config := &Config{
		Providers: []Provider{
			{
				Name:       "oauth-provider",
				AuthMethod: AuthMethodOAuth,
				BaseURL:    "https://oauth.api.com",
				Models:     []string{"model1"},
				OAuth: &OAuthCredentialSet{
					ClientID:     "client123",
					ClientSecret: "secret456",
					TokenURL:     "https://oauth.example.com/token",
					AccessToken:  "access123",
					RefreshToken: "refresh456",
				},
			},
		},
		Router: RouterConfig{
			Default: "oauth-provider",
		},
	}

	// Update OAuth credentials
	newOAuth := &OAuthCredentialSet{
		ClientID:     "client789",
		ClientSecret: "secret654",
		TokenURL:     "https://oauth.example.com/token",
		AccessToken:  "access789",
		RefreshToken: "refresh654",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
	}

	err := config.UpdateProviderOAuthCredentials("oauth-provider", newOAuth, false, "")
	if err != nil {
		t.Fatalf("Failed to update OAuth credentials: %v", err)
	}

	provider, err := config.GetProvider("oauth-provider")
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	if provider.OAuth.ClientID != "client789" {
		t.Errorf("Expected ClientID 'client789', got '%s'", provider.OAuth.ClientID)
	}

	if provider.OAuth.AccessToken != "access789" {
		t.Errorf("Expected AccessToken 'access789', got '%s'", provider.OAuth.AccessToken)
	}
}

func TestOAuthEnvironmentVariableSupport(t *testing.T) {
	// Set environment variables for testing
	os.Setenv("OAUTH_CLIENT_ID", "env-client-123")
	os.Setenv("OAUTH_CLIENT_SECRET", "env-secret-456")
	os.Setenv("OAUTH_ACCESS_TOKEN", "env-access-123")
	os.Setenv("OAUTH_REFRESH_TOKEN", "env-refresh-456")
	defer func() {
		os.Unsetenv("OAUTH_CLIENT_ID")
		os.Unsetenv("OAUTH_CLIENT_SECRET")
		os.Unsetenv("OAUTH_ACCESS_TOKEN")
		os.Unsetenv("OAUTH_REFRESH_TOKEN")
	}()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "oauth-env-config.json")

	// Write config with environment variables
	configContent := `{
  "Providers": [
    {
      "name": "oauth-env-provider",
      "authMethod": "oauth",
      "baseURL": "https://oauth.api.com",
      "models": ["model1"],
      "oauth": {
        "client_id": "${OAUTH_CLIENT_ID}",
        "client_secret": "${OAUTH_CLIENT_SECRET}",
        "access_token": "${OAUTH_ACCESS_TOKEN}",
        "refresh_token": "${OAUTH_REFRESH_TOKEN}",
        "token_url": "https://oauth.example.com/token"
      }
    }
  ],
  "Router": {
    "default": "oauth-env-provider"
  },
  "APIKEY": "router-key",
  "HOST": "localhost",
  "PORT": 8080
}`

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Load config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	provider := cfg.Providers[0]
	if provider.OAuth.ClientID != "env-client-123" {
		t.Errorf("Expected ClientID 'env-client-123', got '%s'", provider.OAuth.ClientID)
	}

	if provider.OAuth.ClientSecret != "env-secret-456" {
		t.Errorf("Expected ClientSecret 'env-secret-456', got '%s'", provider.OAuth.ClientSecret)
	}

	if provider.OAuth.AccessToken != "env-access-123" {
		t.Errorf("Expected AccessToken 'env-access-123', got '%s'", provider.OAuth.AccessToken)
	}

	if provider.OAuth.RefreshToken != "env-refresh-456" {
		t.Errorf("Expected RefreshToken 'env-refresh-456', got '%s'", provider.OAuth.RefreshToken)
	}
}
