package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"sync"

	// "github.com/cecil-the-coder/Cortex/internal/database" // TODO: remove circular import
)

// AuthMethod represents the authentication method for a provider
type AuthMethod string

const (
	AuthMethodAPIKey AuthMethod = "api_key"
	AuthMethodOAuth  AuthMethod = "oauth"
	AuthMethodHybrid AuthMethod = "hybrid"
)

// OAuthCredentialSet represents OAuth configuration for a provider
type OAuthCredentialSet struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scopes       string `json:"scopes,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	TokenURL     string `json:"token_url,omitempty"`
	AuthURL      string `json:"auth_url,omitempty"`
	// Runtime fields (not serialized)
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	mu           sync.RWMutex `json:"-"`
}

// IsValid returns true if the OAuth token is still valid
func (o *OAuthCredentialSet) IsValid() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.AccessToken == "" {
		return false
	}

	// Consider token valid if it expires in more than 5 minutes
	return time.Now().Add(5 * time.Minute).Before(o.ExpiresAt)
}

// UpdateTokens updates the OAuth tokens atomically
func (o *OAuthCredentialSet) UpdateTokens(accessToken, refreshToken, tokenType string, expiresIn int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.AccessToken = accessToken
	o.RefreshToken = refreshToken
	o.TokenType = tokenType
	if expiresIn > 0 {
		o.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	}
}

// GetTokens returns the current tokens safely
func (o *OAuthCredentialSet) GetTokens() (accessToken, refreshToken, tokenType string, expiresAt time.Time) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return o.AccessToken, o.RefreshToken, o.TokenType, o.ExpiresAt
}

// ModelReference represents a model with provider and optional alias
type ModelReference struct {
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	Alias            string `json:"alias,omitempty"`
	MaxContextTokens *int   `json:"maxContextTokens,omitempty"` // Optional override for model context window
}

// ModelGroup represents a group of models with aliases
type ModelGroup struct {
	Description string            `json:"description,omitempty"`
	Models      []ModelReference `json:"models"`
}

// APIKeyConfig represents configuration for a client API key with restrictions
type APIKeyConfig struct {
	APIKey       string    `json:"apiKey"`
	Description  string    `json:"description,omitempty"`
	ModelGroups  []string  `json:"modelGroups,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
	RateLimit    int       `json:"rateLimit,omitempty"`
	Enabled      bool      `json:"enabled"`
}

// ClientAPIKeys manages multiple client API keys
type ClientAPIKeys map[string]*APIKeyConfig

// ModelGroups manages multiple model groups
type ModelGroups map[string]*ModelGroup

// Config represents the main configuration structure for the LLM router
type Config struct {
	Providers    []Provider      `json:"Providers"`
	Router       RouterConfig    `json:"Router"`
	APIKEY       string          `json:"APIKEY"`
	ProxyURL     string          `json:"PROXY_URL,omitempty"`
	Host         string          `json:"HOST"`
	Port         int             `json:"PORT"`
	ModelGroups  *ModelGroups    `json:"ModelGroups,omitempty"`
	ClientAPIKeys *ClientAPIKeys `json:"ClientAPIKeys,omitempty"`
	Database     *DatabaseConfigSection `json:"Database,omitempty"`
	// Runtime fields (not serialized)
	oauthCallbacks map[string]func(*OAuthCredentialSet) error `json:"-"`
	mu              sync.RWMutex                              `json:"-"`
}

// RouterConfig defines routing rules for different request types
type RouterConfig struct {
	Default              string `json:"default"`
	Background           string `json:"background,omitempty"`
	Think                string `json:"think,omitempty"`
	LongContext          string `json:"longContext,omitempty"`
	WebSearch            string `json:"webSearch,omitempty"`
	Vision               string `json:"vision,omitempty"`
	LongContextThreshold int    `json:"longContextThreshold,omitempty"`
}

// DatabaseConfigSection contains all database-related configuration
type DatabaseConfigSection struct {
	Enabled  bool                     `json:"enabled"`
	Primary  interface{}              `json:"primary,omitempty"` // TODO: use *database.DatabaseConfig when circular import resolved
	Fallback *FallbackConfig          `json:"fallback,omitempty"`
	Cache    *CacheConfig             `json:"cache,omitempty"`
}

// FallbackConfig defines how the system falls back to file-based configuration
type FallbackConfig struct {
	UseFileOnFailure bool          `json:"use_file_on_failure"`
	ConfigPath       string        `json:"config_path"`
	RetryDelay       time.Duration `json:"retry_delay"`
	SyncOnRecovery   bool          `json:"sync_on_recovery"`
}

// CacheConfig defines caching configuration for database operations
type CacheConfig struct {
 Enabled          bool          `json:"enabled"`
 TTL              time.Duration `json:"ttl"`
 MaxEntries       int           `json:"max_entries"`
 CleanupInterval  time.Duration `json:"cleanup_interval"`
}

// Provider represents an LLM provider configuration
type Provider struct {
	Name       string             `json:"name"`
	AuthMethod AuthMethod         `json:"authMethod"`
	APIKEY     string             `json:"APIKEY,omitempty"`
	BaseURL    string             `json:"baseURL"`
	Models     []string           `json:"models"`
	OAuth      *OAuthCredentialSet `json:"oauth,omitempty"`

	// Phase 3 Core API features
	UseCoreAPI      bool     `json:"useCoreAPI,omitempty"`
	CoreAPIFeatures []string `json:"coreAPIFeatures,omitempty"`
}

var (
	// Regular expressions for environment variable interpolation
	envVarRegex1 = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
	envVarRegex2 = regexp.MustCompile(`\$([A-Za-z0-9_]+)`)
)

// Load reads and parses the configuration file from the given path
// Supports environment variable interpolation in the format $VAR_NAME or ${VAR_NAME}
func Load(configPath string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", configPath)
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Interpolate environment variables
	interpolated := interpolateEnvVars(string(data))

	// Parse JSON
	var config Config
	if err := json.Unmarshal([]byte(interpolated), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Initialize runtime fields
	config.oauthCallbacks = make(map[string]func(*OAuthCredentialSet) error)

	// Migrate old configuration format for backward compatibility
	if err := config.MigrateLegacyConfig(); err != nil {
		return nil, fmt.Errorf("failed to migrate legacy configuration: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// Save writes the configuration to the specified path
// If backup is true, creates a backup of the existing file with timestamp
func Save(config *Config, configPath string, backup bool) error {
	// Validate configuration before saving
	if err := config.Validate(); err != nil {
		return fmt.Errorf("cannot save invalid configuration: %w", err)
	}

	// Create backup if requested and file exists
	if backup {
		if _, err := os.Stat(configPath); err == nil {
			if err := createBackup(configPath); err != nil {
				return fmt.Errorf("failed to create backup: %w", err)
			}
		}
	}

	// Create a copy without runtime fields for serialization
	configToSave := &Config{
		Providers:     config.Providers,
		Router:        config.Router,
		APIKEY:        config.APIKEY,
		ProxyURL:      config.ProxyURL,
		Host:          config.Host,
		Port:          config.Port,
		ModelGroups:   config.ModelGroups,
		ClientAPIKeys: config.ClientAPIKeys,
	}

	// Marshal config to JSON with indentation
	data, err := json.MarshalIndent(configToSave, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to file with appropriate permissions
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider must be configured")
	}

	if c.Router.Default == "" {
		return fmt.Errorf("router default provider must be specified")
	}

	if c.Host == "" {
		c.Host = "0.0.0.0" // Set default
	}

	if c.Port == 0 {
		c.Port = 8080 // Set default
	}

	// Validate each provider
	providerNames := make(map[string]bool)
	for i, provider := range c.Providers {
		if provider.Name == "" {
			return fmt.Errorf("provider at index %d has no name", i)
		}
		if providerNames[provider.Name] {
			return fmt.Errorf("duplicate provider name: %s", provider.Name)
		}
		providerNames[provider.Name] = true

		// Validate auth method configuration
		if err := validateProviderAuth(&provider); err != nil {
			return fmt.Errorf("provider %s auth validation failed: %w", provider.Name, err)
		}

		if provider.BaseURL == "" {
			return fmt.Errorf("provider %s has no base URL", provider.Name)
		}
		if len(provider.Models) == 0 {
			return fmt.Errorf("provider %s has no models configured", provider.Name)
		}
	}

	// Validate router references existing providers
	routerProviders := []string{
		c.Router.Default,
		c.Router.Background,
		c.Router.Think,
		c.Router.LongContext,
		c.Router.WebSearch,
		c.Router.Vision,
	}

	for _, providerName := range routerProviders {
		if providerName != "" && !providerNames[providerName] {
			return fmt.Errorf("router references unknown provider: %s", providerName)
		}
	}

	// Validate model groups
	if err := c.validateModelGroups(providerNames); err != nil {
		return fmt.Errorf("model groups validation failed: %w", err)
	}

	// Validate client API keys
	if err := c.validateClientAPIKeys(); err != nil {
		return fmt.Errorf("client API keys validation failed: %w", err)
	}

	// Validate database configuration
	if err := c.validateDatabaseConfig(); err != nil {
		return fmt.Errorf("database configuration validation failed: %w", err)
	}

	return nil
}

// validateProviderAuth validates the authentication configuration for a provider
func validateProviderAuth(provider *Provider) error {
	switch provider.AuthMethod {
	case AuthMethodAPIKey:
		if provider.APIKEY == "" {
			return fmt.Errorf("API key authentication requires APIKEY field")
		}
	case AuthMethodOAuth:
		if provider.OAuth == nil {
			return fmt.Errorf("OAuth authentication requires oauth configuration")
		}
		if provider.OAuth.ClientID == "" {
			return fmt.Errorf("OAuth authentication requires client_id")
		}
		if provider.OAuth.ClientSecret == "" {
			return fmt.Errorf("OAuth authentication requires client_secret")
		}
		if provider.OAuth.TokenURL == "" {
			return fmt.Errorf("OAuth authentication requires token_url")
		}
	case AuthMethodHybrid:
		// Hybrid requires at least one auth method to be configured
		hasAPIKey := provider.APIKEY != ""
		hasOAuth := provider.OAuth != nil && provider.OAuth.ClientID != "" && provider.OAuth.ClientSecret != ""

		if !hasAPIKey && !hasOAuth {
			return fmt.Errorf("hybrid authentication requires either API key or OAuth configuration")
		}

		// Validate OAuth if configured
		if hasOAuth && provider.OAuth.TokenURL == "" {
			return fmt.Errorf("OAuth in hybrid mode requires token_url")
		}
	default:
		return fmt.Errorf("unknown authentication method: %s", provider.AuthMethod)
	}

	return nil
}

// validateDatabaseConfig validates the database configuration
func (c *Config) validateDatabaseConfig() error {
	// TODO: Implement database validation when circular import resolved
	// For now, skip validation to allow compilation
	return nil
}

// MigrateToFile handles migration from database to file-based configuration
func (c *Config) MigrateToFile(filePath string) error {
	// This would be used to export database configuration to JSON file
	return Save(c, filePath, true)
}

// MigrateFromDatabase loads configuration from database and converts to file format
func MigrateFromDatabase(dbConfig interface{}, filePath string) error { // TODO: use *database.DatabaseConfig when circular import resolved
	// This is a placeholder for database-to-file migration
	// In a real implementation, this would load from database and save as JSON

	// For now, create a default config with database settings
	defaultCfg := DefaultConfig()
	defaultCfg.Database = &DatabaseConfigSection{
		Enabled: true,
		Primary: dbConfig,
		Fallback: &FallbackConfig{
			UseFileOnFailure: true,
			ConfigPath:       filePath,
			RetryDelay:       30 * time.Second,
			SyncOnRecovery:   true,
		},
		Cache: &CacheConfig{
			Enabled:          true,
			TTL:              5 * time.Minute,
			MaxEntries:       1000,
			CleanupInterval:  10 * time.Minute,
		},
	}

	return Save(defaultCfg, filePath, true)
}

// GetProvider returns a provider by name
func (c *Config) GetProvider(name string) (*Provider, error) {
	for _, provider := range c.Providers {
		if provider.Name == name {
			return &provider, nil
		}
	}
	return nil, fmt.Errorf("provider not found: %s", name)
}

// GetProviderForModel returns the provider that supports the given model
func (c *Config) GetProviderForModel(modelName string) (*Provider, error) {
	for _, provider := range c.Providers {
		for _, model := range provider.Models {
			if model == modelName {
				return &provider, nil
			}
		}
	}
	return nil, fmt.Errorf("no provider found for model: %s", modelName)
}

// interpolateEnvVars replaces environment variable references with their values
// Supports both $VAR_NAME and ${VAR_NAME} formats
func interpolateEnvVars(content string) string {
	// First replace ${VAR_NAME} format
	result := envVarRegex1.ReplaceAllStringFunc(content, func(match string) string {
		varName := envVarRegex1.FindStringSubmatch(match)[1]
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}
		// If variable doesn't exist, keep the original placeholder
		return match
	})

	// Then replace $VAR_NAME format (but not if it's already been replaced)
	result = envVarRegex2.ReplaceAllStringFunc(result, func(match string) string {
		// Skip if this is part of a ${} expression
		if strings.HasPrefix(match, "${") {
			return match
		}
		varName := envVarRegex2.FindStringSubmatch(match)[1]
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}
		// If variable doesn't exist, keep the original placeholder
		return match
	})

	return result
}

// createBackup creates a timestamped backup of the config file
func createBackup(configPath string) error {
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.backup.%s", configPath, timestamp)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	return os.WriteFile(backupPath, data, 0600)
}

// SetOAuthRefreshCallback sets a callback function for OAuth token refresh
func (c *Config) SetOAuthRefreshCallback(providerName string, callback func(*OAuthCredentialSet) error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.oauthCallbacks == nil {
		c.oauthCallbacks = make(map[string]func(*OAuthCredentialSet) error)
	}
	c.oauthCallbacks[providerName] = callback
}

// GetOAuthRefreshCallback gets the OAuth callback for a provider
func (c *Config) GetOAuthRefreshCallback(providerName string) func(*OAuthCredentialSet) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.oauthCallbacks == nil {
		return nil
	}
	return c.oauthCallbacks[providerName]
}

// UpdateProviderOAuthCredentials updates OAuth credentials for a provider and persists changes
func (c *Config) UpdateProviderOAuthCredentials(providerName string, oauth *OAuthCredentialSet, saveConfig bool, configPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Find the provider
	for i, provider := range c.Providers {
		if provider.Name == providerName {
			// Update OAuth credentials
			c.Providers[i].OAuth = oauth

			// Save config if requested
			if saveConfig && configPath != "" {
				if err := Save(c, configPath, true); err != nil {
					return fmt.Errorf("failed to save updated OAuth credentials: %w", err)
				}
			}

			return nil
		}
	}

	return fmt.Errorf("provider not found: %s", providerName)
}

// GetProviderOAuthCredentials safely gets OAuth credentials for a provider
func (c *Config) GetProviderOAuthCredentials(providerName string) (*OAuthCredentialSet, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, provider := range c.Providers {
		if provider.Name == providerName {
			if provider.OAuth == nil {
				return nil, fmt.Errorf("provider %s has no OAuth configuration", providerName)
			}
			return provider.OAuth, nil
		}
	}

	return nil, fmt.Errorf("provider not found: %s", providerName)
}

// IsOAuthConfigured checks if a provider has valid OAuth configuration
func (c *Config) IsOAuthConfigured(providerName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, provider := range c.Providers {
		if provider.Name == providerName {
			return provider.OAuth != nil &&
				   provider.OAuth.ClientID != "" &&
				   provider.OAuth.ClientSecret != "" &&
				   provider.OAuth.TokenURL != ""
		}
	}

	return false
}

// IsAPIKeyConfigured checks if a provider has valid API key configuration
func (c *Config) IsAPIKeyConfigured(providerName string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, provider := range c.Providers {
		if provider.Name == providerName {
			return provider.APIKEY != ""
		}
	}

	return false
}

// GetAuthMethod returns the authentication method for a provider
func (c *Config) GetAuthMethod(providerName string) AuthMethod {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, provider := range c.Providers {
		if provider.Name == providerName {
			return provider.AuthMethod
		}
	}

	return ""
}

// validateModelGroups validates model group configurations
func (c *Config) validateModelGroups(providerNames map[string]bool) error {
	if c.ModelGroups == nil {
		return nil
	}

	// Track all aliases to check for duplicates
	aliases := make(map[string]string)

	for groupName, group := range *c.ModelGroups {
		if groupName == "" {
			return fmt.Errorf("model group name cannot be empty")
		}

		if group == nil {
			return fmt.Errorf("model group %s cannot be null", groupName)
		}

		if len(group.Models) == 0 {
			return fmt.Errorf("model group %s must contain at least one model", groupName)
		}

		for i, modelRef := range group.Models {
			if modelRef.Provider == "" {
				return fmt.Errorf("model group %s, model %d: provider cannot be empty", groupName, i)
			}

			if !providerNames[modelRef.Provider] {
				return fmt.Errorf("model group %s, model %d: provider '%s' does not exist", groupName, i, modelRef.Provider)
			}

			if modelRef.Model == "" {
				return fmt.Errorf("model group %s, model %d: model cannot be empty", groupName, i)
			}

			// Validate that the model exists for the provider
			provider, err := c.GetProvider(modelRef.Provider)
			if err != nil {
				return fmt.Errorf("model group %s, model %d: failed to get provider %s: %w", groupName, i, modelRef.Provider, err)
			}

			modelExists := false
			for _, providerModel := range provider.Models {
				if providerModel == modelRef.Model {
					modelExists = true
					break
				}
			}
			if !modelExists {
				return fmt.Errorf("model group %s, model %d: model '%s' does not exist for provider '%s'", groupName, i, modelRef.Model, modelRef.Provider)
			}

			// Track aliases for duplicate detection
			if modelRef.Alias != "" {
				if existingGroup, exists := aliases[modelRef.Alias]; exists {
					return fmt.Errorf("duplicate alias '%s' found in model groups '%s' and '%s'", modelRef.Alias, existingGroup, groupName)
				}
				aliases[modelRef.Alias] = groupName
			}

			// Validate context window override if specified
			if err := ValidateContextWindow(modelRef.MaxContextTokens); err != nil {
				return fmt.Errorf("model group %s, model %d: %w", groupName, i, err)
			}
		}
	}

	return nil
}

// validateClientAPIKeys validates client API key configurations
func (c *Config) validateClientAPIKeys() error {
	if c.ClientAPIKeys == nil {
		return nil
	}

	for keyID, keyConfig := range *c.ClientAPIKeys {
		if keyID == "" {
			return fmt.Errorf("client API key ID cannot be empty")
		}

		if keyConfig == nil {
			return fmt.Errorf("client API key config for ID '%s' cannot be null", keyID)
		}

		if keyConfig.APIKey == "" {
			return fmt.Errorf("client API key %s: apiKey cannot be empty", keyID)
		}

		// Validate API key format (basic validation)
		if len(keyConfig.APIKey) < 8 {
			return fmt.Errorf("client API key %s: apiKey must be at least 8 characters long", keyID)
		}

		// Validate model groups exist
		for _, groupName := range keyConfig.ModelGroups {
			if c.ModelGroups == nil {
				return fmt.Errorf("client API key %s: model group '%s' does not exist (no model groups configured)", keyID, groupName)
			}

			if _, exists := (*c.ModelGroups)[groupName]; !exists {
				return fmt.Errorf("client API key %s: model group '%s' does not exist", keyID, groupName)
			}
		}

		// Validate rate limit if specified
		if keyConfig.RateLimit < 0 {
			return fmt.Errorf("client API key %s: rateLimit cannot be negative", keyID)
		}

		// Validate expiration if specified
		if !keyConfig.ExpiresAt.IsZero() && time.Now().After(keyConfig.ExpiresAt) {
			return fmt.Errorf("client API key %s: expiration date has passed", keyID)
		}
	}

	return nil
}

// MigrateLegacyConfig handles migration from old configuration format
func (c *Config) MigrateLegacyConfig() error {
	// Initialize model groups if nil (not present in old config)
	if c.ModelGroups == nil {
		groups := make(ModelGroups)
		c.ModelGroups = &groups

		// Create a group for each provider's models
		for _, provider := range c.Providers {
			groupName := provider.Name + "-models"
			group := &ModelGroup{
				Description: fmt.Sprintf("All models from %s provider", provider.Name),
				Models:      make([]ModelReference, 0, len(provider.Models)),
			}

			for _, model := range provider.Models {
				group.Models = append(group.Models, ModelReference{
					Provider: provider.Name,
					Model:    model,
					// No alias by default
				})
			}

			(*c.ModelGroups)[groupName] = group
		}
	}

	// Initialize client API keys if nil (not present in old config)
	if c.ClientAPIKeys == nil {
		if c.APIKEY != "" {
			// Create default client API keys with the legacy key
			keys := make(ClientAPIKeys)
			c.ClientAPIKeys = &keys

			// Create a default client API key from the legacy APIKEY
			defaultKey := &APIKeyConfig{
				APIKey:      c.APIKEY,
				Description: "Migrated from legacy APIKEY",
				ModelGroups: []string{}, // No restrictions - can access all models
				Enabled:     true,
			}

			(*c.ClientAPIKeys)["default-legacy"] = defaultKey
		} else {
			// Initialize empty client API keys
			keys := make(ClientAPIKeys)
			c.ClientAPIKeys = &keys
		}
	}

	return nil
}

// LoadOrDefault loads configuration from the given path, or returns a default config
func LoadOrDefault(configPath string) (*Config, error) {
	config, err := Load(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return DefaultConfig(), nil
		}
		return nil, err
	}
	return config, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	providers := []Provider{
		{
			Name:       "anthropic",
			AuthMethod: AuthMethodAPIKey,
			APIKEY:     "${ANTHROPIC_API_KEY}",
			BaseURL:    "https://api.anthropic.com/v1",
			Models:     []string{"claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"},
			UseCoreAPI: true,
			CoreAPIFeatures: []string{
				"thinking_mode",
				"top_k_sampling",
				"system_prompts",
				"prompt_caching",
			},
		},
		{
			Name:       "openai",
			AuthMethod: AuthMethodAPIKey,
			APIKEY:     "${OPENAI_API_KEY}",
			BaseURL:    "https://api.openai.com/v1",
			Models:     []string{"gpt-4-turbo-preview", "gpt-4", "gpt-3.5-turbo"},
			UseCoreAPI: true,
			CoreAPIFeatures: []string{
				"json_mode",
				"parallel_tools",
				"reproducible_results",
				"top_p_sampling",
			},
		},
	}

	// Create default model groups
	modelGroups := ModelGroups{}

	// Create production models group
	claudeContextWindow := 200000 // Override demonstration
	gptContextWindow := 128000

	productionGroup := &ModelGroup{
		Description: "Production models",
		Models: []ModelReference{
			{
				Provider:         "anthropic",
				Model:            "claude-3-5-sonnet-20241022",
				Alias:            "claude-sonnet-4.5",
				MaxContextTokens: &claudeContextWindow,
			},
			{
				Provider:         "openai",
				Model:            "gpt-4-turbo-preview",
				Alias:            "gpt5",
				MaxContextTokens: &gptContextWindow,
			},
		},
	}
	modelGroups["production"] = productionGroup

	// Create claude models group without duplicate alias
	claudeGroup := &ModelGroup{
		Description: "All Claude models",
		Models: []ModelReference{
			{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", Alias: "claude-sonnet-prod"},
			{Provider: "anthropic", Model: "claude-3-opus-20240229", Alias: "claude-opus-3"},
		},
	}
	modelGroups["claude-models"] = claudeGroup

	// Create provider-specific groups
	for _, provider := range providers {
		groupName := provider.Name + "-models"
		group := &ModelGroup{
			Description: fmt.Sprintf("All models from %s provider", provider.Name),
			Models:      make([]ModelReference, 0, len(provider.Models)),
		}

		for _, model := range provider.Models {
			group.Models = append(group.Models, ModelReference{
				Provider: provider.Name,
				Model:    model,
			})
		}
		modelGroups[groupName] = group
	}

	// Create default client API key
	clientAPIKeys := ClientAPIKeys{
		"default": {
			APIKey:       "${ROUTER_API_KEY}",
			Description:  "Default API key for development",
			ModelGroups:  []string{"production", "claude-models"},
			Enabled:      true,
			RateLimit:    100,
		},
	}

	// Default database configuration
	databaseConfig := &DatabaseConfigSection{
		Enabled: false, // Disabled by default for backward compatibility
		Fallback: &FallbackConfig{
			UseFileOnFailure: true,
			ConfigPath:       "config.json",
			RetryDelay:       30 * time.Second,
			SyncOnRecovery:   true,
		},
		Cache: &CacheConfig{
			Enabled:          true,
			TTL:              5 * time.Minute,
			MaxEntries:       1000,
			CleanupInterval:  10 * time.Minute,
		},
	}

	return &Config{
		Providers:     providers,
		Router: RouterConfig{
			Default:              "anthropic",
			Background:           "openai",
			Think:                "anthropic",
			LongContext:          "anthropic",
			WebSearch:            "openai",
			Vision:               "openai",
			LongContextThreshold: 100000,
		},
		APIKEY:        "${ROUTER_API_KEY}", // Keep for backward compatibility
		ProxyURL:      "",
		Host:          "0.0.0.0",
		Port:          8080,
		ModelGroups:   &modelGroups,
		ClientAPIKeys: &clientAPIKeys,
		Database:      databaseConfig,
		oauthCallbacks: make(map[string]func(*OAuthCredentialSet) error),
	}
}

// GetModelGroup returns a model group by name
func (c *Config) GetModelGroup(groupName string) (*ModelGroup, error) {
	if c.ModelGroups == nil {
		return nil, fmt.Errorf("no model groups configured")
	}

	group, exists := (*c.ModelGroups)[groupName]
	if !exists {
		return nil, fmt.Errorf("model group not found: %s", groupName)
	}

	return group, nil
}

// GetClientAPIKey returns a client API key configuration by ID
func (c *Config) GetClientAPIKey(keyID string) (*APIKeyConfig, error) {
	if c.ClientAPIKeys == nil {
		return nil, fmt.Errorf("no client API keys configured")
	}

	keyConfig, exists := (*c.ClientAPIKeys)[keyID]
	if !exists {
		return nil, fmt.Errorf("client API key not found: %s", keyID)
	}

	return keyConfig, nil
}

// ValidateClientAPIKey validates a client API key string against the configuration
func (c *Config) ValidateClientAPIKey(apiKey string) (*APIKeyConfig, error) {
	if c.ClientAPIKeys == nil {
		return nil, fmt.Errorf("no client API keys configured")
	}

	// Find the API key config that matches the provided key
	for keyID, keyConfig := range *c.ClientAPIKeys {
		if keyConfig.APIKey == apiKey {
			// Check if the key is enabled
			if !keyConfig.Enabled {
				return nil, fmt.Errorf("client API key %s is disabled", keyID)
			}

			// Check expiration
			if !keyConfig.ExpiresAt.IsZero() && time.Now().After(keyConfig.ExpiresAt) {
				return nil, fmt.Errorf("client API key %s has expired", keyID)
			}

			return keyConfig, nil
		}
	}

	return nil, fmt.Errorf("invalid client API key")
}

// GetModelReferenceByAlias finds a model reference by its alias across all model groups
func (c *Config) GetModelReferenceByAlias(alias string) (*ModelReference, error) {
	if c.ModelGroups == nil {
		return nil, fmt.Errorf("no model groups configured")
	}

	if alias == "" {
		return nil, fmt.Errorf("alias cannot be empty")
	}

	for _, group := range *c.ModelGroups {
		for _, modelRef := range group.Models {
			if modelRef.Alias == alias {
				return &modelRef, nil
			}
		}
	}

	return nil, fmt.Errorf("model alias not found: %s", alias)
}

// GetAvailableModelGroups returns a list of all available model group names
func (c *Config) GetAvailableModelGroups() []string {
	if c.ModelGroups == nil {
		return []string{}
	}

	groups := make([]string, 0, len(*c.ModelGroups))
	for groupName := range *c.ModelGroups {
		groups = append(groups, groupName)
	}

	return groups
}

// GetModelsInGroup returns all model references in a specific group
func (c *Config) GetModelsInGroup(groupName string) ([]ModelReference, error) {
	group, err := c.GetModelGroup(groupName)
	if err != nil {
		return nil, err
	}

	return group.Models, nil
}

// CanAPIKeyAccessGroup checks if a client API key can access a specific model group
func (c *Config) CanAPIKeyAccessGroup(keyConfig *APIKeyConfig, groupName string) bool {
	// If no model groups are specified, the key can access all groups
	if len(keyConfig.ModelGroups) == 0 {
		return true
	}

	// Check if the requested group is in the allowed groups
	for _, allowedGroup := range keyConfig.ModelGroups {
		if allowedGroup == groupName {
			return true
		}
	}

	return false
}

// AddClientAPIKey adds a new client API key to the configuration
func (c *Config) AddClientAPIKey(keyID string, keyConfig *APIKeyConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ClientAPIKeys == nil {
		keys := make(ClientAPIKeys)
		c.ClientAPIKeys = &keys
	}

	if _, exists := (*c.ClientAPIKeys)[keyID]; exists {
		return fmt.Errorf("client API key ID already exists: %s", keyID)
	}

	(*c.ClientAPIKeys)[keyID] = keyConfig
	return nil
}

// AddModelGroup adds a new model group to the configuration
func (c *Config) AddModelGroup(groupName string, group *ModelGroup) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ModelGroups == nil {
		groups := make(ModelGroups)
		c.ModelGroups = &groups
	}

	if _, exists := (*c.ModelGroups)[groupName]; exists {
		return fmt.Errorf("model group already exists: %s", groupName)
	}

	(*c.ModelGroups)[groupName] = group
	return nil
}

// RemoveClientAPIKey removes a client API key from the configuration
func (c *Config) RemoveClientAPIKey(keyID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ClientAPIKeys == nil {
		return fmt.Errorf("no client API keys configured")
	}

	if _, exists := (*c.ClientAPIKeys)[keyID]; !exists {
		return fmt.Errorf("client API key not found: %s", keyID)
	}

	delete(*c.ClientAPIKeys, keyID)
	return nil
}

// RemoveModelGroup removes a model group from the configuration
func (c *Config) RemoveModelGroup(groupName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ModelGroups == nil {
		return fmt.Errorf("no model groups configured")
	}

	if _, exists := (*c.ModelGroups)[groupName]; !exists {
		return fmt.Errorf("model group not found: %s", groupName)
	}

	delete(*c.ModelGroups, groupName)
	return nil
}

// FilterModelsInGroupByContext filters model references in a group based on context window requirements
func (c *Config) FilterModelsInGroupByContext(groupName string, tokenCount int, allowFallback bool) ([]ModelReference, error) {
	group, err := c.GetModelGroup(groupName)
	if err != nil {
		return nil, err
	}

	registry := GetGlobalContextRegistry()
	filteredModels := registry.FilterModelsByContext(group.Models, tokenCount, allowFallback)

	return filteredModels, nil
}

// GetModelContextWindow returns the effective context window for a given model reference
func (c *Config) GetModelContextWindow(modelRef ModelReference) int {
	registry := GetGlobalContextRegistry()
	return registry.GetContextWindowForModel(modelRef)
}

// CanModelHandleContext checks if a model reference can handle the given token count
func (c *Config) CanModelHandleContext(modelRef ModelReference, tokenCount int) bool {
	contextWindow := c.GetModelContextWindow(modelRef)
	return contextWindow >= tokenCount
}

// FindBestModelForContext finds the best model in a group that can handle the given context size
// Returns the model with the largest context window that can accommodate the request
func (c *Config) FindBestModelForContext(groupName string, tokenCount int) (*ModelReference, error) {
	filteredModels, err := c.FilterModelsInGroupByContext(groupName, tokenCount, true)
	if err != nil {
		return nil, err
	}

	if len(filteredModels) == 0 {
		return nil, fmt.Errorf("no models in group '%s' can handle context size %d tokens", groupName, tokenCount)
	}

	// Return the first model which should have the largest context window due to sorting
	return &filteredModels[0], nil
}

// ============================================================================
// Context Window Management
// ============================================================================

// DefaultContextWindow represents the default context window for models when no specific value is known
const DefaultContextWindow = 4096

// ModelContextInfo represents context window information for a model
type ModelContextInfo struct {
	ModelName      string
	ContextTokens  int
	Provider       string
	CanonicalName  string // Standardized name for matching
	SupportsVision bool   // True if model supports image processing
}

// ModelContextRegistry holds context window information for various models
type ModelContextRegistry struct {
	models map[string]ModelContextInfo // Key: lowercase model name pattern
}

// NewModelContextRegistry creates a new model context registry with predefined models
func NewModelContextRegistry() *ModelContextRegistry {
	registry := &ModelContextRegistry{
		models: make(map[string]ModelContextInfo),
	}

	// Register well-known models with their context windows
	registry.registerKnownModels()

	return registry
}

// registerKnownModels populates the registry with context window information for common models
func (r *ModelContextRegistry) registerKnownModels() {
	// Claude models (all Claude 3 models support vision)
	r.registerModel("claude-3-5-sonnet-20241022", 200000, "anthropic", "claude-3-5-sonnet", true)
	r.registerModel("claude-3-5-sonnet", 200000, "anthropic", "claude-3-5-sonnet", true)
	r.registerModel("claude-3-5-sonnet-latest", 200000, "anthropic", "claude-3-5-sonnet", true)
	r.registerModel("claude-3-5-haiku-20241022", 200000, "anthropic", "claude-3-5-haiku", true)
	r.registerModel("claude-3-5-haiku", 200000, "anthropic", "claude-3-5-haiku", true)
	r.registerModel("claude-3-opus-20240229", 200000, "anthropic", "claude-3-opus", true)
	r.registerModel("claude-3-opus", 200000, "anthropic", "claude-3-opus", true)
	r.registerModel("claude-3-opus-latest", 200000, "anthropic", "claude-3-opus", true)
	r.registerModel("claude-3-sonnet-20240229", 200000, "anthropic", "claude-3-sonnet", true)
	r.registerModel("claude-3-sonnet", 200000, "anthropic", "claude-3-sonnet", true)
	r.registerModel("claude-3-sonnet-latest", 200000, "anthropic", "claude-3-sonnet", true)
	r.registerModel("claude-3-haiku-20240307", 200000, "anthropic", "claude-3-haiku", true)
	r.registerModel("claude-3-haiku", 200000, "anthropic", "claude-3-haiku", true)
	r.registerModel("claude-3-haiku-latest", 200000, "anthropic", "claude-3-haiku", true)
	r.registerModel("claude-2.1", 200000, "anthropic", "claude-2.1", false)
	r.registerModel("claude-2.0", 100000, "anthropic", "claude-2.0", false)
	r.registerModel("claude-instant-1.2", 100000, "anthropic", "claude-instant", false)

	// GPT models (GPT-4V, GPT-4o series support vision)
	r.registerModel("gpt-4-turbo-preview", 128000, "openai", "gpt-4-turbo", false)
	r.registerModel("gpt-4-turbo", 128000, "openai", "gpt-4-turbo", false)
	r.registerModel("gpt-4-turbo-2024-04-09", 128000, "openai", "gpt-4-turbo", false)
	r.registerModel("gpt-4-0125-preview", 128000, "openai", "gpt-4-turbo", false)
	r.registerModel("gpt-4-1106-preview", 128000, "openai", "gpt-4-turbo", false)
	r.registerModel("gpt-4-vision-preview", 128000, "openai", "gpt-4-vision", true)
	r.registerModel("gpt-4-1106-vision-preview", 128000, "openai", "gpt-4-vision", true)
	r.registerModel("gpt-4", 8192, "openai", "gpt-4", false)
	r.registerModel("gpt-4-0613", 8192, "openai", "gpt-4", false)
	r.registerModel("gpt-4-32k", 32768, "openai", "gpt-4-32k", false)
	r.registerModel("gpt-4-32k-0613", 32768, "openai", "gpt-4-32k", false)
	r.registerModel("gpt-3.5-turbo", 16385, "openai", "gpt-3.5-turbo", false)
	r.registerModel("gpt-3.5-turbo-16k", 16385, "openai", "gpt-3.5-turbo", false)
	r.registerModel("gpt-3.5-turbo-0613", 16385, "openai", "gpt-3.5-turbo", false)
	r.registerModel("gpt-3.5-turbo-1106", 16385, "openai", "gpt-3.5-turbo", false)
	r.registerModel("gpt-3.5-turbo-0125", 16385, "openai", "gpt-3.5-turbo", false)
	r.registerModel("gpt-3.5-turbo-instruct", 4096, "openai", "gpt-3.5-turbo-instruct", false)
	r.registerModel("gpt-4o", 128000, "openai", "gpt-4o", true)
	r.registerModel("gpt-4o-mini", 128000, "openai", "gpt-4o-mini", true)
	r.registerModel("gpt-4o-2024-05-13", 128000, "openai", "gpt-4o", true)
	r.registerModel("gpt-4o-2024-08-06", 128000, "openai", "gpt-4o", true)

	// Other providers
	r.registerModel("gemini-pro", 32768, "google", "gemini-pro", false)
	r.registerModel("gemini-pro-vision", 16384, "google", "gemini-pro-vision", true)
	r.registerModel("gemini-1.5-pro", 1000000, "google", "gemini-1.5-pro", true)
	r.registerModel("gemini-1.5-flash", 1000000, "google", "gemini-1.5-flash", true)
	r.registerModel("llama-2-70b-chat", 4096, "meta", "llama-2", false)
	r.registerModel("llama-2-13b-chat", 4096, "meta", "llama-2", false)
	r.registerModel("llama-2-7b-chat", 4096, "meta", "llama-2", false)
	r.registerModel("codellama-34b-instruct", 16384, "meta", "codellama", false)
	r.registerModel("codellama-13b-instruct", 16384, "meta", "codellama", false)
	r.registerModel("codellama-7b-instruct", 16384, "meta", "codellama", false)
	r.registerModel("mistral-7b-instruct", 8192, "mistral", "mistral-7b", false)
	r.registerModel("mixtral-8x7b-instruct", 32768, "mistral", "mixtral-8x7b", false)
	r.registerModel("mistral-large", 32768, "mistral", "mistral-large", false)
	r.registerModel("command-r-plus", 128000, "cohere", "command-r-plus", false)
	r.registerModel("command-r", 128000, "cohere", "command-r", false)
	r.registerModel("sonar-pro", 127000, "perplexity", "sonar-pro", false)
	r.registerModel("sonar-small", 127000, "perplexity", "sonar-small", false)
	r.registerModel("deepseek-chat", 32768, "deepseek", "deepseek-chat", false)
	r.registerModel("deepseek-coder", 16384, "deepseek", "deepseek-coder", false)
	r.registerModel("deepseek-reasoner", 65536, "deepseek", "deepseek-reasoner", false)
}

// registerModel adds a model to the registry with multiple name patterns for matching
func (r *ModelContextRegistry) registerModel(modelName string, contextTokens int, provider string, canonicalName string, supportsVision bool) {
	if r.models == nil {
		r.models = make(map[string]ModelContextInfo)
	}

	// Store with lowercase name for case-insensitive matching
	lowerName := strings.ToLower(modelName)
	r.models[lowerName] = ModelContextInfo{
		ModelName:      modelName,
		ContextTokens:  contextTokens,
		Provider:       provider,
		CanonicalName:  canonicalName,
		SupportsVision: supportsVision,
	}

	// Also store some common variations for better matching
	variations := r.generateNameVariations(modelName, canonicalName)
	for _, variation := range variations {
		lowerVariation := strings.ToLower(variation)
		if _, exists := r.models[lowerVariation]; !exists {
			r.models[lowerVariation] = ModelContextInfo{
				ModelName:      modelName,
				ContextTokens:  contextTokens,
				Provider:       provider,
				CanonicalName:  canonicalName,
				SupportsVision: supportsVision,
			}
		}
	}
}

// generateNameVariations creates common name variations for better model matching
func (r *ModelContextRegistry) generateNameVariations(modelName, canonicalName string) []string {
	variations := []string{}

	// Add canonical name if different
	if canonicalName != modelName {
		variations = append(variations, canonicalName)
	}

	// Add some common pattern variations
	lowerModel := strings.ToLower(modelName)

	// Remove version numbers and dates for more general matching
	if strings.Contains(lowerModel, "-2024") {
		baseModel := strings.Split(lowerModel, "-2024")[0]
		variations = append(variations, baseModel)
	}

	if strings.Contains(lowerModel, "-2023") {
		baseModel := strings.Split(lowerModel, "-2023")[0]
		variations = append(variations, baseModel)
	}

	// Remove "latest" suffix
	if strings.HasSuffix(lowerModel, "-latest") {
		baseModel := strings.TrimSuffix(lowerModel, "-latest")
		variations = append(variations, baseModel)
	}

	// Handle specific patterns
	if strings.Contains(lowerModel, "claude-3-5-") {
		// For claude-3-5-* models, also register the pattern without the specific version
		if strings.Contains(lowerModel, "sonnet") {
			variations = append(variations, "claude-3-5-sonnet")
		}
		if strings.Contains(lowerModel, "haiku") {
			variations = append(variations, "claude-3-5-haiku")
		}
	}

	if strings.Contains(lowerModel, "claude-3-") && !strings.Contains(lowerModel, "claude-3-5-") {
		// For claude-3-* models (non-5-series)
		if strings.Contains(lowerModel, "sonnet") {
			variations = append(variations, "claude-3-sonnet")
		}
		if strings.Contains(lowerModel, "opus") {
			variations = append(variations, "claude-3-opus")
		}
		if strings.Contains(lowerModel, "haiku") {
			variations = append(variations, "claude-3-haiku")
		}
	}

	if strings.Contains(lowerModel, "gpt-4-turbo") {
		variations = append(variations, "gpt-4-turbo")
	}

	if strings.Contains(lowerModel, "gpt-3.5-turbo") {
		variations = append(variations, "gpt-3.5-turbo")
	}

	return variations
}

// GetContextWindow returns the context window for a given model name
// Returns the context window and a boolean indicating if the model was found
func (r *ModelContextRegistry) GetContextWindow(modelName string) (int, bool) {
	if r.models == nil {
		return DefaultContextWindow, false
	}

	if modelName == "" {
		return DefaultContextWindow, false
	}

	// Try exact match first (case-insensitive)
	lowerName := strings.ToLower(modelName)
	if info, exists := r.models[lowerName]; exists {
		return info.ContextTokens, true
	}

	// Try to find a partial match
	return r.findPartialMatch(modelName)
}

// findPartialMatch attempts to find a model that partially matches the given name
func (r *ModelContextRegistry) findPartialMatch(modelName string) (int, bool) {
	lowerName := strings.ToLower(modelName)

	// Look for models that contain the search string or vice versa
	for registeredName, info := range r.models {
		// Check if the model name contains our search term
		if strings.Contains(registeredName, lowerName) || strings.Contains(lowerName, registeredName) {
			// Additional check: ensure there's some reasonable overlap
			if r.calculateMatchScore(lowerName, registeredName) > 0.5 {
				return info.ContextTokens, true
			}
		}
	}

	return DefaultContextWindow, false
}

// calculateMatchScore calculates a simple match score between two model names
func (r *ModelContextRegistry) calculateMatchScore(name1, name2 string) float64 {
	if name1 == name2 {
		return 1.0
	}

	// Count common characters
	common := 0
	for _, char1 := range name1 {
		for _, char2 := range name2 {
			if char1 == char2 {
				common++
				break
			}
		}
	}

	maxLen := len(name1)
	if len(name2) > maxLen {
		maxLen = len(name2)
	}

	if maxLen == 0 {
		return 0.0
	}

	return float64(common) / float64(maxLen)
}

// GetModelInfo returns full model information if available
func (r *ModelContextRegistry) GetModelInfo(modelName string) (ModelContextInfo, bool) {
	if r.models == nil {
		return ModelContextInfo{}, false
	}

	if modelName == "" {
		return ModelContextInfo{}, false
	}

	// Try exact match first (case-insensitive)
	lowerName := strings.ToLower(modelName)
	if info, exists := r.models[lowerName]; exists {
		return info, true
	}

	// Try partial match
	if _, found := r.findPartialMatch(modelName); found {
		// Find the info that matched
		for registeredName, info := range r.models {
			lowerRegistered := strings.ToLower(registeredName)
			if strings.Contains(lowerRegistered, lowerName) || strings.Contains(lowerName, lowerRegistered) {
				if r.calculateMatchScore(lowerName, lowerRegistered) > 0.5 {
					return info, true
				}
			}
		}
	}

	return ModelContextInfo{}, false
}

// FilterModelsByContext filters model references based on their context window capacity
// Returns models that can handle the given token count, with optional fallback to smaller models
func (r *ModelContextRegistry) FilterModelsByContext(models []ModelReference, tokenCount int, allowFallback bool) []ModelReference {
	if len(models) == 0 {
		return models
	}

	var suitableModels []ModelReference
	var fallbackModels []ModelReference

	for _, modelRef := range models {
		contextWindow := r.GetContextWindowForModel(modelRef)

		if contextWindow >= tokenCount {
			suitableModels = append(suitableModels, modelRef)
		} else if allowFallback && contextWindow > 0 {
			// Include as fallback if it has some context window capacity
			fallbackModels = append(fallbackModels, modelRef)
		}
	}

	// Prefer suitable models, but allow fallback if none are suitable and fallback is allowed
	if len(suitableModels) > 0 {
		return suitableModels
	} else if allowFallback && len(fallbackModels) > 0 {
		// Sort fallback models by context window (largest first)
		return r.sortModelsByContextWindow(fallbackModels)
	}

	// No models can handle the context
	return []ModelReference{}
}

// GetContextWindowForModel returns the effective context window for a model reference
// Takes into account any override in the model reference
func (r *ModelContextRegistry) GetContextWindowForModel(modelRef ModelReference) int {
	// If model reference has an override, use it
	if modelRef.MaxContextTokens != nil && *modelRef.MaxContextTokens > 0 {
		return *modelRef.MaxContextTokens
	}

	// Look up the model in the registry
	if contextTokens, found := r.GetContextWindow(modelRef.Model); found {
		return contextTokens
	}

	return DefaultContextWindow
}

// sortModelsByContextWindow sorts models by their context window capacity (largest first)
func (r *ModelContextRegistry) sortModelsByContextWindow(models []ModelReference) []ModelReference {
	// Simple bubble sort for small slices
	for i := 0; i < len(models); i++ {
		for j := i + 1; j < len(models); j++ {
			contextI := r.GetContextWindowForModel(models[i])
			contextJ := r.GetContextWindowForModel(models[j])
			if contextJ > contextI {
				models[i], models[j] = models[j], models[i]
			}
		}
	}
	return models
}

// ValidateContextWindow validates that a context window value is reasonable
func ValidateContextWindow(contextWindow *int) error {
	if contextWindow == nil {
		return nil // nil is valid (will use default)
	}

	if *contextWindow < 0 {
		return fmt.Errorf("context window cannot be negative: %d", *contextWindow)
	}

	if *contextWindow > 2000000 {
		return fmt.Errorf("context window seems unrealistically large: %d (max recommended: 2M)", *contextWindow)
	}

	return nil
}

// Global registry instance
var globalRegistry = NewModelContextRegistry()

// GetGlobalContextRegistry returns the global model context registry
func GetGlobalContextRegistry() *ModelContextRegistry {
	return globalRegistry
}

// SupportsVision returns true if the given model supports vision capabilities
func (r *ModelContextRegistry) SupportsVision(modelName string) bool {
	if info, found := r.GetModelInfo(modelName); found {
		return info.SupportsVision
	}
	return false
}

// GetVisionModels returns a list of all models in the registry that support vision
func (r *ModelContextRegistry) GetVisionModels() []ModelContextInfo {
	var visionModels []ModelContextInfo
	for _, info := range r.models {
		// Only include canonical names to avoid duplicates
		if info.ModelName == info.CanonicalName && info.SupportsVision {
			visionModels = append(visionModels, info)
		}
	}
	return visionModels
}

// CreateVisionModelGroup creates a model group containing only vision-capable models for the given providers
func (r *ModelContextRegistry) CreateVisionModelGroup(providers []string, groupName string) *ModelGroup {
	visionGroup := &ModelGroup{
		Description: "Vision-capable models for image processing tasks",
		Models:      []ModelReference{},
	}

	for _, info := range r.GetVisionModels() {
		// Include model if it's from one of the specified providers or if providers is empty (all providers)
		shouldInclude := len(providers) == 0
		for _, provider := range providers {
			if info.Provider == provider {
				shouldInclude = true
				break
			}
		}

		if shouldInclude {
			visionGroup.Models = append(visionGroup.Models, ModelReference{
				Provider: info.Provider,
				Model:    info.ModelName,
			})
		}
	}

	return visionGroup
}
