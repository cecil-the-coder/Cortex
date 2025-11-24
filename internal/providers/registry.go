package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/factory"
	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"

	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/converters"
	"github.com/cecil-the-coder/Cortex/internal/health"
	"github.com/cecil-the-coder/Cortex/internal/models"
	"github.com/cecil-the-coder/Cortex/internal/database"
)

// SDKProviderRegistry manages AI providers using ai-provider-kit SDK
type SDKProviderRegistry struct {
	factory        *factory.DefaultProviderFactory
	coreFactory    *types.DefaultProviderFactoryExtensions
	providers      map[string]types.Provider
	coreProviders  map[string]types.CoreChatProvider
	configs        map[string]*config.Provider
	oauthHandler   *OAuthHandler
	healthMonitor  *health.HealthMonitor
	discoveryService *models.DiscoveryService
	requestConverter *converters.RequestConverter
	responseConverter *converters.ResponseConverter
	db             database.Database // Database backend for configuration persistence
	// configManager removed - using direct config
	mu             sync.RWMutex
}

// NewSDKProviderRegistry creates a new provider registry using ai-provider-kit
func NewSDKProviderRegistry(cfg *config.Config) (*SDKProviderRegistry, error) {
	f := factory.NewProviderFactory()
	factory.RegisterDefaultProviders(f)

	// Initialize core factory for Phase 3 API
	coreFactory := types.NewDefaultProviderFactoryExtensions(f)

	// Initialize services
	healthMonitor := health.NewHealthMonitor(30*time.Second, 10*time.Second, 3)
	discoveryService := models.NewDiscoveryService(5*time.Minute)
	requestConverter := converters.NewRequestConverter("gpt-3.5-turbo", 4096)
	responseConverter := converters.NewResponseConverter()

	registry := &SDKProviderRegistry{
		factory:           f,
		coreFactory:       coreFactory,
		providers:         make(map[string]types.Provider),
		coreProviders:     make(map[string]types.CoreChatProvider),
		configs:           make(map[string]*config.Provider),
		healthMonitor:     healthMonitor,
		discoveryService:  discoveryService,
		requestConverter:  requestConverter,
		responseConverter: responseConverter,
	}

	// Initialize database backend if configured
	var db database.Database

	if cfg.Database != nil && cfg.Database.Enabled {
		// Initialize database for metrics storage
		if cfg.Database.Primary != nil {
			dbConfig, ok := cfg.Database.Primary.(*database.DatabaseConfig)
			if !ok {
				log.Printf("Warning: Database configuration is not of expected type")
			} else {
				logger := slog.New(slog.NewTextHandler(log.Writer(), nil))
				dbInstance, err := database.NewDatabase(dbConfig, logger)
				if err != nil {
					log.Printf("Warning: Failed to initialize database for metrics: %v", err)
				} else {
					// Connect to database
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					if err := dbInstance.Connect(ctx); err != nil {
						log.Printf("Warning: Failed to connect to database: %v", err)
					} else {
						// Run migrations
						if err := dbInstance.Migrate(ctx); err != nil {
							log.Printf("Warning: Failed to run database migrations: %v", err)
						} else {
							db = dbInstance
							log.Printf("Database backend initialized successfully")
						}
					}
				}
			}
		}
	}

	registry.db = db

	// Initialize OAuth handler
	registry.oauthHandler = NewOAuthHandler(registry, cfg, "")

	// Use provided config directly
	effectiveConfig := cfg

	// Initialize providers from config
	for i := range effectiveConfig.Providers {
		provider := &effectiveConfig.Providers[i]
		if err := registry.registerProvider(provider); err != nil {
			return nil, fmt.Errorf("failed to register provider %s: %w", provider.Name, err)
		}
	}

	// Start health monitoring after all providers are registered
	registry.healthMonitor.Start()

	// Start background metrics collection if database is available
	if db != nil {
		go registry.startMetricsCollection()
	}

	log.Printf("Provider registry initialized with %d providers", len(effectiveConfig.Providers))
	log.Printf("Health monitoring enabled with %d providers", len(registry.healthMonitor.GetHealthStatus()))
	log.Printf("Model discovery service ready")
	if db != nil {
		log.Printf("Database metrics collection enabled")
	}

	return registry, nil
}

// registerProvider registers a single provider with the SDK
func (r *SDKProviderRegistry) registerProvider(cfg *config.Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	providerType := mapProviderType(cfg.Name)
	if providerType == "" {
		return fmt.Errorf("unknown provider type: %s", cfg.Name)
	}

	// Determine the API key to use based on authentication method
	apiKey, err := r.getAPIKeyForProvider(cfg)
	if err != nil {
		return fmt.Errorf("failed to get API key for provider %s: %w", cfg.Name, err)
	}

	providerConfig := types.ProviderConfig{
		Type:         providerType,
		Name:         cfg.Name,
		APIKey:       apiKey,
		BaseURL:      cfg.BaseURL,
		DefaultModel: cfg.Models[0], // Use first model as default
	}

	provider, err := r.factory.CreateProvider(providerType, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	// Try to create core provider if supported
	var coreProvider types.CoreChatProvider
	useCoreAPI := false

	if r.coreFactory.SupportsCoreAPI(providerType) {
		if cp, err := r.coreFactory.CreateCoreProvider(providerType, providerConfig); err == nil {
			coreProvider = cp
			useCoreAPI = true
			log.Printf("Core API enabled for provider: %s", cfg.Name)
		} else {
			log.Printf("Core API unavailable for provider %s, using legacy: %v", cfg.Name, err)
		}
	} else {
		log.Printf("Provider %s does not support Core API, using legacy interface", cfg.Name)
	}

	// Set up OAuth refresh callback if OAuth is configured
	if cfg.AuthMethod == config.AuthMethodOAuth || cfg.AuthMethod == config.AuthMethodHybrid {
		if cfg.OAuth != nil {
			r.setupOAuthRefreshCallback(cfg)
		}
	}

	// Add to health monitoring if supported
	if healthProvider, ok := provider.(types.HealthCheckProvider); ok {
		if err := r.healthMonitor.AddProvider(cfg.Name, healthProvider, cfg); err != nil {
			log.Printf("Warning: Failed to add provider %s to health monitoring: %v", cfg.Name, err)
		}
	}

	// Add to model discovery if supported
	if modelProvider, ok := provider.(types.ModelProvider); ok {
		if err := r.discoveryService.AddProvider(cfg.Name, modelProvider, cfg); err != nil {
			log.Printf("Warning: Failed to add provider %s to model discovery: %v", cfg.Name, err)
		}
	}

	// Create a copy of the config to avoid mutations
	configCopy := *cfg
	r.providers[cfg.Name] = provider
	if useCoreAPI {
		r.coreProviders[cfg.Name] = coreProvider
	}
	r.configs[cfg.Name] = &configCopy
	return nil
}

// GetProvider returns a provider wrapper by name
func (r *SDKProviderRegistry) GetProvider(name string) (*SDKProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", name)
	}

	cfg := r.configs[name]

	// Check if core provider is available
	var coreProvider types.CoreChatProvider
	useCoreAPI := false
	if cp, hasCore := r.coreProviders[name]; hasCore {
		coreProvider = cp
		useCoreAPI = true
	}

	return &SDKProvider{
		provider:     provider,
		coreProvider: coreProvider,
		config:       cfg,
		useCoreAPI:   useCoreAPI,
	}, nil
}

// SDKProvider wraps an ai-provider-kit provider and implements our Provider interface
type SDKProvider struct {
	provider     types.Provider
	coreProvider types.CoreChatProvider
	config       *config.Provider
	useCoreAPI   bool
}

// Name returns the provider name
func (p *SDKProvider) Name() string {
	return p.config.Name
}

// SendRequest is not used with SDK - we use GenerateCompletion instead
func (p *SDKProvider) SendRequest(ctx context.Context, request interface{}) (*http.Response, error) {
	return nil, fmt.Errorf("use GenerateCompletion instead of SendRequest for SDK providers")
}

// TransformRequest converts MessageRequest to SDK GenerateOptions
func (p *SDKProvider) TransformRequest(request *converters.MessageRequest, targetModel string) (*types.GenerateOptions, error) {
	// Convert messages
	messages := make([]types.ChatMessage, 0, len(request.Messages)+1)

	// Add system message if present
	if request.System != "" {
		messages = append(messages, types.ChatMessage{
			Role:    "system",
			Content: request.System,
		})
	}

	// Convert chat messages
	for _, msg := range request.Messages {
		content, err := extractMessageContent(msg.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to extract message content: %w", err)
		}

		chatMsg := types.ChatMessage{
			Role:    msg.Role,
			Content: content,
		}

		// Handle tool calls in assistant messages
		if msg.Role == "assistant" {
			toolCalls := extractToolCalls(msg.Content)
			if len(toolCalls) > 0 {
				chatMsg.ToolCalls = toolCalls
			}
		}

		// Handle tool results
		if msg.Role == "user" {
			if toolCallID := extractToolCallID(msg.Content); toolCallID != "" {
				chatMsg.Role = "tool"
				chatMsg.ToolCallID = toolCallID
			}
		}

		messages = append(messages, chatMsg)
	}

	// Convert tools
	var tools []types.Tool
	if len(request.Tools) > 0 {
		tools = make([]types.Tool, len(request.Tools))
		for i, t := range request.Tools {
			tools[i] = types.Tool{
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			}
		}
	}

	options := &types.GenerateOptions{
		Model:     targetModel,
		Messages:  messages,
		MaxTokens: request.MaxTokens,
		Stream:    request.Stream,
		Tools:     tools,
	}

	if request.Temperature > 0 {
		options.Temperature = request.Temperature
	}

	if len(request.StopSequences) > 0 {
		options.Stop = request.StopSequences
	}

	return options, nil
}

// GenerateCompletion sends a request to the provider and returns a stream
func (p *SDKProvider) GenerateCompletion(ctx context.Context, options *types.GenerateOptions) (types.ChatCompletionStream, error) {
	if p.useCoreAPI && p.coreProvider != nil {
		// Use standardized core API
		return p.generateCompletionWithCoreAPI(ctx, options)
	} else {
		// Use legacy API
		return p.provider.GenerateChatCompletion(ctx, *options)
	}
}

// generateCompletionWithCoreAPI uses the new standardized API
func (p *SDKProvider) generateCompletionWithCoreAPI(ctx context.Context, options *types.GenerateOptions) (types.ChatCompletionStream, error) {
	// Convert legacy options to standard request
	standardRequest, err := types.NewCoreRequestBuilder().
		FromGenerateOptions(*options).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to convert to standard request: %w", err)
	}

	// Use core provider
	standardStream, err := p.coreProvider.GenerateStandardStream(ctx, *standardRequest)
	if err != nil {
		return nil, fmt.Errorf("core API generation failed: %w", err)
	}

	// Convert standard stream back to legacy format for compatibility
	return &StandardToLegacyStreamAdapter{
		standardStream: standardStream,
		providerName:   p.config.Name,
	}, nil
}

// StreamResponse streams the SDK response to the HTTP response writer in Anthropic format
func (p *SDKProvider) StreamResponse(ctx context.Context, stream types.ChatCompletionStream, w http.ResponseWriter) error {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported")
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Send message_start event
	msgStartEvent := StreamEvent{
		Type: "message_start",
		Message: &AnthropicResponse{
			ID:      "msg_" + generateID(),
			Type:    "message",
			Role:    "assistant",
			Content: []ContentBlock{},
			Model:   p.config.Models[0],
			Usage:   AnthropicUsage{InputTokens: 0, OutputTokens: 0},
		},
	}
	if err := writeSSEEvent(w, "message_start", msgStartEvent); err != nil {
		return err
	}
	flusher.Flush()

	// Send content_block_start
	blockStartEvent := map[string]interface{}{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]interface{}{
			"type": "text",
			"text": "",
		},
	}
	if err := writeSSEEvent(w, "content_block_start", blockStartEvent); err != nil {
		return err
	}
	flusher.Flush()

	// Track usage for final event
	var finalUsage AnthropicUsage

	// Stream content
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk, err := stream.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("stream error: %w", err)
		}

		if chunk.Done {
			// Update usage from final chunk
			finalUsage = AnthropicUsage{
				InputTokens:  chunk.Usage.PromptTokens,
				OutputTokens: chunk.Usage.CompletionTokens,
			}
			break
		}

		// Send text delta
		if chunk.Content != "" {
			deltaEvent := map[string]interface{}{
				"type":  "content_block_delta",
				"index": 0,
				"delta": map[string]interface{}{
					"type": "text_delta",
					"text": chunk.Content,
				},
			}
			if err := writeSSEEvent(w, "content_block_delta", deltaEvent); err != nil {
				return err
			}
			flusher.Flush()
		}
	}

	// Send content_block_stop
	blockStopEvent := map[string]interface{}{
		"type":  "content_block_stop",
		"index": 0,
	}
	if err := writeSSEEvent(w, "content_block_stop", blockStopEvent); err != nil {
		return err
	}
	flusher.Flush()

	// Send message_delta with usage
	msgDeltaEvent := map[string]interface{}{
		"type": "message_delta",
		"delta": map[string]interface{}{
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
		},
		"usage": map[string]interface{}{
			"output_tokens": finalUsage.OutputTokens,
		},
	}
	if err := writeSSEEvent(w, "message_delta", msgDeltaEvent); err != nil {
		return err
	}
	flusher.Flush()

	// Send message_stop
	msgStopEvent := map[string]interface{}{
		"type": "message_stop",
	}
	if err := writeSSEEvent(w, "message_stop", msgStopEvent); err != nil {
		return err
	}
	flusher.Flush()

	return nil
}

// NonStreamingResponse handles non-streaming responses
func (p *SDKProvider) NonStreamingResponse(ctx context.Context, stream types.ChatCompletionStream) (*AnthropicResponse, error) {
	var content strings.Builder
	var usage AnthropicUsage

	for {
		chunk, err := stream.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("stream error: %w", err)
		}

		if chunk.Done {
			usage = AnthropicUsage{
				InputTokens:  chunk.Usage.PromptTokens,
				OutputTokens: chunk.Usage.CompletionTokens,
			}
			break
		}

		content.WriteString(chunk.Content)
	}

	return &AnthropicResponse{
		ID:   "msg_" + generateID(),
		Type: "message",
		Role: "assistant",
		Content: []ContentBlock{
			{
				Type: "text",
				Text: content.String(),
			},
		},
		Model:      p.config.Models[0],
		StopReason: "end_turn",
		Usage:      usage,
	}, nil
}


// Helper functions

// getAPIKeyForProvider returns the appropriate API key based on the provider's authentication method
func (r *SDKProviderRegistry) getAPIKeyForProvider(cfg *config.Provider) (string, error) {
	switch cfg.AuthMethod {
	case config.AuthMethodAPIKey:
		if cfg.APIKEY == "" {
			return "", fmt.Errorf("API key authentication requires APIKEY field")
		}
		return cfg.APIKEY, nil
	case config.AuthMethodOAuth:
		if cfg.OAuth == nil {
			return "", fmt.Errorf("OAuth authentication requires oauth configuration")
		}
		if !cfg.OAuth.IsValid() {
			return "", fmt.Errorf("OAuth token is not valid or expired")
		}
		token, _, _, _ := cfg.OAuth.GetTokens()
		if token == "" {
			return "", fmt.Errorf("OAuth access token is empty")
		}
		return token, nil
	case config.AuthMethodHybrid:
		// Prefer OAuth if available and valid, otherwise fallback to API key
		if cfg.OAuth != nil && cfg.OAuth.IsValid() {
			token, _, _, _ := cfg.OAuth.GetTokens()
			if token != "" {
				return token, nil
			}
		}
		if cfg.APIKEY != "" {
			return cfg.APIKEY, nil
		}
		return "", fmt.Errorf("hybrid authentication has no valid token or API key")
	default:
		return "", fmt.Errorf("unknown authentication method: %s", cfg.AuthMethod)
	}
}

// setupOAuthRefreshCallback sets up the OAuth token refresh callback for a provider
func (r *SDKProviderRegistry) setupOAuthRefreshCallback(cfg *config.Provider) {
	if r.oauthHandler == nil {
		log.Printf("Warning: OAuth handler not initialized for provider: %s", cfg.Name)
		return
	}

	// Set up the refresh callback that will be called when tokens are refreshed
	refreshCallback := func(oauth *config.OAuthCredentialSet) error {
		// Get the latest access token
		accessToken, _, _, _ := oauth.GetTokens()
		if accessToken != "" {
			// Update the provider's API key in the registry
			if err := r.RefreshProviderAPIKey(cfg.Name, accessToken); err != nil {
				log.Printf("Failed to update provider API key after OAuth refresh for %s: %v", cfg.Name, err)
				return err
			}
			log.Printf("Successfully updated provider API key after OAuth refresh for: %s", cfg.Name)
		}
		return nil
	}

	// Register the callback with the OAuth handler
	r.oauthHandler.SetRefreshCallback(cfg.Name, refreshCallback)
	log.Printf("OAuth refresh callback set up for provider: %s", cfg.Name)
}

// RefreshProviderAPIKey refreshes a provider's API key (useful for OAuth token refresh)
func (r *SDKProviderRegistry) RefreshProviderAPIKey(providerName string, newAPIKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.providers[providerName]
	if !ok {
		return fmt.Errorf("provider not found: %s", providerName)
	}

	cfg := r.configs[providerName]
	if cfg == nil {
		return fmt.Errorf("provider config not found: %s", providerName)
	}

	// Update provider in SDK if API supports dynamic key updates
	// This depends on the ai-provider-kit implementation
	providerType := mapProviderType(cfg.Name)
	if providerType == "" {
		return fmt.Errorf("unknown provider type: %s", cfg.Name)
	}

	providerConfig := types.ProviderConfig{
		Type:         providerType,
		Name:         cfg.Name,
		APIKey:       newAPIKey,
		BaseURL:      cfg.BaseURL,
		DefaultModel: cfg.Models[0],
	}

	// Create new provider instance with updated key
	newProvider, err := r.factory.CreateProvider(providerType, providerConfig)
	if err != nil {
		return fmt.Errorf("failed to create provider with new API key: %w", err)
	}

	// Atomically replace the provider
	r.providers[providerName] = newProvider
	log.Printf("API key refreshed for provider: %s", providerName)

	return nil
}


// ValidateAuthProvider checks if a provider's authentication method is properly configured
func (r *SDKProviderRegistry) ValidateAuthProvider(providerName string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg, ok := r.configs[providerName]
	if !ok {
		return fmt.Errorf("provider not found: %s", providerName)
	}

	switch cfg.AuthMethod {
	case config.AuthMethodAPIKey:
		if cfg.APIKEY == "" {
			return fmt.Errorf("API key is required for API key authentication")
		}
	case config.AuthMethodOAuth:
		if cfg.OAuth == nil {
			return fmt.Errorf("OAuth configuration is required for OAuth authentication")
		}
		if cfg.OAuth.ClientID == "" || cfg.OAuth.ClientSecret == "" || cfg.OAuth.TokenURL == "" {
			return fmt.Errorf("OAuth client details are incomplete")
		}
	case config.AuthMethodHybrid:
		hasAPIKey := cfg.APIKEY != ""
		hasOAuth := cfg.OAuth != nil && cfg.OAuth.ClientID != "" && cfg.OAuth.ClientSecret != ""
		if !hasAPIKey && !hasOAuth {
			return fmt.Errorf("hybrid authentication requires at least API key or OAuth configuration")
		}
	default:
		return fmt.Errorf("unknown authentication method: %s", cfg.AuthMethod)
	}

	return nil
}

// GetProviderAuthMethod returns the authentication method for a provider
func (r *SDKProviderRegistry) GetProviderAuthMethod(providerName string) config.AuthMethod {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cfg, ok := r.configs[providerName]; ok {
		return cfg.AuthMethod
	}
	return ""
}

func mapProviderType(name string) types.ProviderType {
	switch strings.ToLower(name) {
	case "anthropic":
		return types.ProviderTypeAnthropic
	case "openai":
		return types.ProviderTypeOpenAI
	case "openrouter":
		return types.ProviderTypeOpenRouter
	case "gemini", "google":
		return types.ProviderTypeGemini
	case "ollama":
		return types.ProviderTypeOllama
	case "cerebras":
		return types.ProviderTypeCerebras
	case "deepseek":
		return types.ProviderTypeDeepseek
	case "mistral":
		return types.ProviderTypeMistral
	case "xai":
		return types.ProviderTypexAI
	case "qwen":
		return types.ProviderTypeQwen
	default:
		// Try OpenAI-compatible for unknown providers
		return types.ProviderTypeOpenAI
	}
}

func extractMessageContent(content interface{}) (string, error) {
	switch c := content.(type) {
	case string:
		return c, nil
	case []interface{}:
		// Extract text from content blocks
		var text strings.Builder
		for _, block := range c {
			if blockMap, ok := block.(map[string]interface{}); ok {
				if blockMap["type"] == "text" {
					if t, ok := blockMap["text"].(string); ok {
						text.WriteString(t)
					}
				}
			}
		}
		return text.String(), nil
	default:
		// Try to marshal as JSON and use as content
		jsonBytes, err := json.Marshal(content)
		if err != nil {
			return "", err
		}
		return string(jsonBytes), nil
	}
}

func extractToolCalls(content interface{}) []types.ToolCall {
	blocks, ok := content.([]interface{})
	if !ok {
		return nil
	}

	var toolCalls []types.ToolCall
	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}

		if blockMap["type"] == "tool_use" {
			var args string
			if input, ok := blockMap["input"]; ok {
				argsBytes, _ := json.Marshal(input)
				args = string(argsBytes)
			}
			toolCall := types.ToolCall{
				ID:   blockMap["id"].(string),
				Type: "function",
				Function: types.ToolCallFunction{
					Name:      blockMap["name"].(string),
					Arguments: args,
				},
			}
			toolCalls = append(toolCalls, toolCall)
		}
	}

	return toolCalls
}

func extractToolCallID(content interface{}) string {
	blocks, ok := content.([]interface{})
	if !ok {
		return ""
	}

	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}

		if blockMap["type"] == "tool_result" {
			if id, ok := blockMap["tool_use_id"].(string); ok {
				return id
			}
		}
	}

	return ""
}

func writeSSEEvent(w io.Writer, eventType string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, jsonData)
	return err
}

func generateID() string {
	// Simple ID generation - in production use uuid
	return fmt.Sprintf("%d", (time.Now().UnixNano()/1000000)%10000000000)
}

// GetAllModels returns all models from all providers
func (r *SDKProviderRegistry) GetAllModels() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string][]string)
	for name, cfg := range r.configs {
		result[name] = cfg.Models
	}
	return result
}

// ReloadProviders updates provider configurations from a new config
// This operation is atomic - providers are updated without disrupting ongoing requests
func (r *SDKProviderRegistry) ReloadProviders(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate the new configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create temporary maps for the new configuration
	newProviders := make(map[string]types.Provider)
	newCoreProviders := make(map[string]types.CoreChatProvider)
	newConfigs := make(map[string]*config.Provider)

	// Track providers to remove
	providersToRemove := make(map[string]bool)
	for name := range r.providers {
		providersToRemove[name] = true
	}

	// Initialize or update providers from new config
	for i := range cfg.Providers {
		provider := &cfg.Providers[i]

		// This provider exists in the new config, don't remove it
		delete(providersToRemove, provider.Name)

		// Create or update this provider
		providerType := mapProviderType(provider.Name)
		if providerType == "" {
			return fmt.Errorf("unknown provider type: %s", provider.Name)
		}

		// Determine the API key to use based on authentication method
		apiKey, err := r.getAPIKeyForProvider(provider)
		if err != nil {
			return fmt.Errorf("failed to get API key for provider %s: %w", provider.Name, err)
		}

		providerConfig := types.ProviderConfig{
			Type:         providerType,
			Name:         provider.Name,
			APIKey:       apiKey,
			BaseURL:      provider.BaseURL,
			DefaultModel: provider.Models[0], // Use first model as default
		}

		newProvider, err := r.factory.CreateProvider(providerType, providerConfig)
		if err != nil {
			return fmt.Errorf("failed to create provider %s: %w", provider.Name, err)
		}

		// Try to create core provider if supported
		var coreProvider types.CoreChatProvider
		useCoreAPI := false

		if r.coreFactory.SupportsCoreAPI(providerType) {
			if cp, err := r.coreFactory.CreateCoreProvider(providerType, providerConfig); err == nil {
				coreProvider = cp
				useCoreAPI = true
				log.Printf("Core API enabled for reloaded provider: %s", provider.Name)
			} else {
				log.Printf("Core API unavailable for reloaded provider %s, using legacy: %v", provider.Name, err)
			}
		} else {
			log.Printf("Reloaded provider %s does not support Core API, using legacy interface", provider.Name)
		}

		newProviders[provider.Name] = newProvider
		if useCoreAPI {
			newCoreProviders[provider.Name] = coreProvider
		}

		// Create a copy of the provider config to store
		providerCopy := *provider
		newConfigs[provider.Name] = &providerCopy

		// Set up OAuth refresh callback if OAuth is configured
		if provider.AuthMethod == config.AuthMethodOAuth || provider.AuthMethod == config.AuthMethodHybrid {
			if provider.OAuth != nil {
				r.setupOAuthRefreshCallback(provider)
			}
		}

		// Add to health monitoring if supported
		if healthProvider, ok := newProvider.(types.HealthCheckProvider); ok {
			if err := r.healthMonitor.AddProvider(provider.Name, healthProvider, provider); err != nil {
				log.Printf("Warning: Failed to add reloaded provider %s to health monitoring: %v", provider.Name, err)
			}
		}

		// Add to model discovery if supported
		if modelProvider, ok := newProvider.(types.ModelProvider); ok {
			if err := r.discoveryService.AddProvider(provider.Name, modelProvider, provider); err != nil {
				log.Printf("Warning: Failed to add reloaded provider %s to model discovery: %v", provider.Name, err)
			}
		}
	}

	// Remove providers from services if they were removed from config
	for name := range providersToRemove {
		if err := r.healthMonitor.RemoveProvider(name); err != nil {
			log.Printf("Warning: Failed to remove provider %s from health monitoring: %v", name, err)
		}
		if err := r.discoveryService.RemoveProvider(name); err != nil {
			log.Printf("Warning: Failed to remove provider %s from model discovery: %v", name, err)
		}
	}

	// Atomically replace the old providers with the new ones
	r.providers = newProviders
	r.coreProviders = newCoreProviders
	r.configs = newConfigs

	// Log removed providers
	for name := range providersToRemove {
		log.Printf("Provider '%s' removed from configuration", name)
	}

	log.Printf("Providers reloaded successfully: %d providers configured (with %d Core API providers)", len(newProviders), len(newCoreProviders))
	return nil
}

// GetProviderConfig returns the current configuration for a provider
func (r *SDKProviderRegistry) GetProviderConfig(name string) (*config.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg, ok := r.configs[name]
	if !ok {
		return nil, fmt.Errorf("provider not found: %s", name)
	}
	return cfg, nil
}

// GetAllProviderConfigs returns all provider configurations
func (r *SDKProviderRegistry) GetAllProviderConfigs() map[string]*config.Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]*config.Provider)
	for name, cfg := range r.configs {
		// Create a copy to avoid modifications to the original
		providerCopy := *cfg
		result[name] = &providerCopy
	}
	return result
}

// ValidateProviderAPIKey checks if a provider's API key is valid by making a minimal test request
func (r *SDKProviderRegistry) ValidateProviderAPIKey(providerName string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[providerName]
	if !ok {
		return fmt.Errorf("provider not found: %s", providerName)
	}

	// Create a simple test request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// For now, we'll just check that the provider is accessible
	// In a production environment, you might want to make a minimal API call
	// to verify the API key is valid
	options := &types.GenerateOptions{
		Model:    "test",
		Messages: []types.ChatMessage{},
		MaxTokens: 1,
	}

	_, err := provider.GenerateChatCompletion(ctx, *options)
	if err != nil {
		return fmt.Errorf("API key validation failed for provider %s: %w", providerName, err)
	}

	return nil
}

// GetOAuthHandler returns the OAuth handler for managing tokens
func (r *SDKProviderRegistry) GetOAuthHandler() *OAuthHandler {
	return r.oauthHandler
}

// SetConfigPath updates the config path for OAuth persistence
func (r *SDKProviderRegistry) SetConfigPath(configPath string) {
	if r.oauthHandler != nil {
		r.oauthHandler.SetConfigPath(configPath)
	}
}

// New Core API methods for advanced usage

// GenerateStandardCompletion uses the standardized core API directly
func (p *SDKProvider) GenerateStandardCompletion(ctx context.Context, request types.StandardRequest) (*types.StandardResponse, error) {
	if !p.useCoreAPI || p.coreProvider == nil {
		return nil, fmt.Errorf("core API not available for provider: %s", p.config.Name)
	}
	return p.coreProvider.GenerateStandardCompletion(ctx, request)
}

// GenerateStandardStream uses the standardized core API for streaming
func (p *SDKProvider) GenerateStandardStream(ctx context.Context, request types.StandardRequest) (types.StandardStream, error) {
	if !p.useCoreAPI || p.coreProvider == nil {
		return nil, fmt.Errorf("core API not available for provider: %s", p.config.Name)
	}
	return p.coreProvider.GenerateStandardStream(ctx, request)
}

// GetStandardCapabilities returns provider's standardized capabilities
func (p *SDKProvider) GetStandardCapabilities() []string {
	if p.useCoreAPI && p.coreProvider != nil {
		return p.coreProvider.GetStandardCapabilities()
	}
	return []string{}
}

// UseCoreAPI returns whether this provider is using the new core API
func (p *SDKProvider) UseCoreAPI() bool {
	return p.useCoreAPI && p.coreProvider != nil
}

// GetCoreProviderExtension returns the provider's core extension
func (p *SDKProvider) GetCoreProviderExtension() (types.CoreProviderExtension, error) {
	if !p.useCoreAPI || p.coreProvider == nil {
		return nil, fmt.Errorf("core API not available for provider: %s", p.config.Name)
	}
	return p.coreProvider.GetCoreExtension(), nil
}

// ValidateStandardRequest validates a standard request for this provider
func (p *SDKProvider) ValidateStandardRequest(request types.StandardRequest) error {
	if !p.useCoreAPI || p.coreProvider == nil {
		return fmt.Errorf("core API not available for provider: %s", p.config.Name)
	}
	return p.coreProvider.ValidateStandardRequest(request)
}

// ============================================================================
// Service Accessor Methods
// ============================================================================

// GetHealthMonitor returns the health monitoring service
func (r *SDKProviderRegistry) GetHealthMonitor() *health.HealthMonitor {
	return r.healthMonitor
}

// GetDiscoveryService returns the model discovery service
func (r *SDKProviderRegistry) GetDiscoveryService() *models.DiscoveryService {
	return r.discoveryService
}

// GetRequestConverter returns the request converter service
func (r *SDKProviderRegistry) GetRequestConverter() *converters.RequestConverter {
	return r.requestConverter
}

// GetResponseConverter returns the response converter service
func (r *SDKProviderRegistry) GetResponseConverter() *converters.ResponseConverter {
	return r.responseConverter
}

// ConvertMessageRequest converts a legacy MessageRequest to StandardRequest
func (r *SDKProviderRegistry) ConvertMessageRequest(messageReq *converters.MessageRequest) (*types.StandardRequest, error) {
	return r.requestConverter.ConvertFromLegacy(messageReq)
}

// ConvertResponse converts a StandardResponse to the specified format
func (r *SDKProviderRegistry) ConvertResponse(response *types.StandardResponse, targetFormat converters.ResponseFormat) (interface{}, error) {
	return r.responseConverter.ConvertFromStandard(response, targetFormat)
}

// GetServiceHealth returns the health status of all services
func (r *SDKProviderRegistry) GetServiceHealth() map[string]interface{} {
	health := make(map[string]interface{})

	// Health monitor status
	health["health_monitor"] = map[string]interface{}{
		"enabled": r.healthMonitor.IsEnabled(),
		"monitored_providers": len(r.healthMonitor.GetHealthStatus()),
		"stats": r.healthMonitor.GetMonitoringStats(),
	}

	// Discovery service status
	health["discovery_service"] = map[string]interface{}{
		"enabled": r.discoveryService.IsEnabled(),
	}

	// Registry status
	r.mu.RLock()
	health["registry"] = map[string]interface{}{
		"total_providers": len(r.providers),
		"core_api_providers": len(r.coreProviders),
		"oauth_enabled": r.oauthHandler != nil,
	}
	r.mu.RUnlock()

	return health
}

// startMetricsCollection starts background collection of health and performance metrics
func (r *SDKProviderRegistry) startMetricsCollection() {
	if r.db == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second) // Collect metrics every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.collectAndStoreMetrics()
		}
	}
}

// collectAndStoreMetrics collects current metrics and stores them in the database
func (r *SDKProviderRegistry) collectAndStoreMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get health status from all providers
	healthStatus := r.healthMonitor.GetHealthStatus()

	// Convert health status to database metrics
	var metrics []*database.RequestMetrics
	timestamp := time.Now()

	for providerName, status := range healthStatus {
		// Create a metrics entry for each provider's health
		metric := &database.RequestMetrics{
			Timestamp:     timestamp,
			RequestID:     fmt.Sprintf("health_%s_%d", providerName, timestamp.Unix()),
			ProviderID:    0, // We'll need to map provider names to IDs
			ModelID:       0, // Not applicable for health checks
			RequestType:   "health_check",
			InputTokens:   0,
			OutputTokens:  0,
			TotalTokens:   0,
			LatencyMs:     int(status.ResponseTime * 1000), // Convert seconds to milliseconds
			StatusCode:    200,
			ErrorMessage:  "",
			RequestSize:   0,
			ResponseSize:  0,
			Streaming:     false,
			VisionContent: false,
			ToolUse:       false,
			ThinkingMode:  false,
			Cost:          0.0,
		}

		if !status.Healthy {
			metric.StatusCode = 500
			metric.ErrorMessage = status.Message
		}

		metrics = append(metrics, metric)
	}

	// Store metrics in database
	if err := r.db.StoreBatchRequestMetrics(ctx, metrics); err != nil {
		log.Printf("Warning: Failed to store health metrics: %v", err)
	}
}

// GetConfigManager removed - config manager not available

// GetDatabase returns the database instance
func (r *SDKProviderRegistry) GetDatabase() database.Database {
	return r.db
}

// SaveProviderToDatabase saves a provider configuration to the database
func (r *SDKProviderRegistry) SaveProviderToDatabase(provider *config.Provider) error {
	if r.db == nil {
		return fmt.Errorf("database not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Convert config.Provider to database.Provider
	dbProvider := &database.Provider{
		Name:            provider.Name,
		AuthMethod:      string(provider.AuthMethod),
		BaseURL:         provider.BaseURL,
		UseCoreAPI:      provider.UseCoreAPI,
		CoreAPIFeatures: provider.CoreAPIFeatures,
		Enabled:         true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Handle OAuth credentials
	if provider.OAuth != nil {
		dbProvider.OAuth = &database.OAuthCredentialSet{
			ClientID:     provider.OAuth.ClientID,
			ClientSecret: provider.OAuth.ClientSecret,
			TokenURL:     provider.OAuth.TokenURL,
			AccessToken:  provider.OAuth.AccessToken,
			RefreshToken: provider.OAuth.RefreshToken,
			ExpiresAt:    &provider.OAuth.ExpiresAt,
		}
	}

	// Check if provider already exists
	existing, err := r.db.GetProviderByName(ctx, provider.Name)
	if err != nil {
		// Provider doesn't exist, create it
		if err := r.db.CreateProvider(ctx, dbProvider); err != nil {
			return fmt.Errorf("failed to create provider in database: %w", err)
		}
		log.Printf("Provider %s saved to database", provider.Name)
	} else {
		// Provider exists, update it
		dbProvider.ID = existing.ID
		dbProvider.CreatedAt = existing.CreatedAt
		if err := r.db.UpdateProvider(ctx, dbProvider); err != nil {
			return fmt.Errorf("failed to update provider in database: %w", err)
		}
		log.Printf("Provider %s updated in database", provider.Name)
	}

	return nil
}

// LoadProviderFromDatabase loads a provider configuration from the database
func (r *SDKProviderRegistry) LoadProviderFromDatabase(name string) (*config.Provider, error) {
	if r.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbProvider, err := r.db.GetProviderByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider from database: %w", err)
	}

	// Convert database.Provider back to config.Provider
	provider := &config.Provider{
		Name:            dbProvider.Name,
		AuthMethod:      config.AuthMethod(dbProvider.AuthMethod),
		BaseURL:         dbProvider.BaseURL,
		UseCoreAPI:      dbProvider.UseCoreAPI,
		CoreAPIFeatures: dbProvider.CoreAPIFeatures,
		Models:          []string{}, // Models would be loaded separately
	}

	// Handle OAuth credentials
	if dbProvider.OAuth.ClientID != "" {
	 expiresAt := time.Time{}
		if dbProvider.OAuth.ExpiresAt != nil {
			expiresAt = *dbProvider.OAuth.ExpiresAt
		}
		provider.OAuth = &config.OAuthCredentialSet{
			ClientID:     dbProvider.OAuth.ClientID,
			ClientSecret: dbProvider.OAuth.ClientSecret,
			TokenURL:     dbProvider.OAuth.TokenURL,
			AccessToken:  dbProvider.OAuth.AccessToken,
			RefreshToken: dbProvider.OAuth.RefreshToken,
			ExpiresAt:    expiresAt,
		}
	}

	return provider, nil
}

// UpdateProviderConfigurationInDatabase updates a provider configuration in the database
func (r *SDKProviderRegistry) UpdateProviderConfigurationInDatabase(name string, provider *config.Provider) error {
	if r.db == nil {
		return fmt.Errorf("database not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get existing provider
	existing, err := r.db.GetProviderByName(ctx, name)
	if err != nil {
		return fmt.Errorf("provider not found in database: %w", err)
	}

	// Update fields
	existing.AuthMethod = string(provider.AuthMethod)
	existing.BaseURL = provider.BaseURL
	existing.UseCoreAPI = provider.UseCoreAPI
	existing.CoreAPIFeatures = provider.CoreAPIFeatures
	existing.UpdatedAt = time.Now()

	if err := r.db.UpdateProvider(ctx, existing); err != nil {
		return fmt.Errorf("failed to update provider in database: %w", err)
	}

	log.Printf("Provider %s configuration updated in database", name)
	return nil
}

// Shutdown gracefully shuts down all services
func (r *SDKProviderRegistry) Shutdown() error {
	log.Println("Shutting down provider registry services...")

	// Stop health monitoring
	if r.healthMonitor.IsEnabled() {
		r.healthMonitor.Stop()
		log.Println("Health monitoring stopped")
	}

	// Disable discovery service
	r.discoveryService.SetEnabled(false)
	log.Println("Model discovery service disabled")

	// Close database connection
	if r.db != nil {
		if err := r.db.Close(); err != nil {
			log.Printf("Warning: Error closing database connection: %v", err)
		} else {
			log.Println("Database connection closed")
		}
	}

// Config manager removed - no unsubscribe needed

	log.Println("Provider registry services shut down gracefully")
	return nil
}
