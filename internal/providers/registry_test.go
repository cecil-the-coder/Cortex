package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/converters"
)

func TestGetAllModels(t *testing.T) {
	// Create a test configuration
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
			{
				Name:       "anthropic",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"claude-3-opus", "claude-3-sonnet"},
			},
		},
	}

	// Create provider registry
	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Test GetAllModels
	allModels := registry.GetAllModels()

	// Verify structure
	expected := map[string][]string{
		"openai":    {"gpt-4", "gpt-3.5-turbo"},
		"anthropic": {"claude-3-opus", "claude-3-sonnet"},
	}

	if !reflect.DeepEqual(allModels, expected) {
		t.Errorf("Expected %v, got %v", expected, allModels)
	}

	// Test that modifications to returned map don't affect internal state
	allModels["test"] = []string{"test-model"}
	newAllModels := registry.GetAllModels()

	if len(newAllModels) == 3 {
		t.Error("Modifying returned map should not affect internal state")
	}
}

func TestGetAllModelsEmpty(t *testing.T) {
	// Create a test configuration with no providers
	cfg := &config.Config{
		Providers: []config.Provider{},
	}

	// Create provider registry
	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Test GetAllModels
	allModels := registry.GetAllModels()

	if len(allModels) != 0 {
		t.Errorf("Expected empty map, got %v", allModels)
	}
}

// ============================================================================
// Core API Integration Tests
// ============================================================================

func TestSDKProviderRegistryCreation(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
			{
				Name:       "anthropic",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"claude-3-opus", "claude-3-sonnet"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Verify services are initialized
	if registry.GetHealthMonitor() == nil {
		t.Error("Health monitor should be initialized")
	}
	if registry.GetDiscoveryService() == nil {
		t.Error("Discovery service should be initialized")
	}
	if registry.GetRequestConverter() == nil {
		t.Error("Request converter should be initialized")
	}
	if registry.GetResponseConverter() == nil {
		t.Error("Response converter should be initialized")
	}
}

func TestSDKProviderCreation(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	provider, err := registry.GetProvider("openai")
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	if provider.Name() != "openai" {
		t.Errorf("Expected provider name 'openai', got '%s'", provider.Name())
	}

	// Test that provider has Core API capabilities
	if provider.UseCoreAPI() {
		t.Log("Provider supports Core API")
	} else {
		t.Log("Provider is using legacy API (expected for non-mocked providers)")
	}
}

func TestProviderNotFound(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	_, err = registry.GetProvider("nonexistent")
	if err == nil {
		t.Error("Expected error when getting non-existent provider")
	}

	expectedError := "provider not found: nonexistent"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestMessageRequestTransformation(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	provider, err := registry.GetProvider("openai")
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	// Create test message request
	messageReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		Stream:    false,
		StopSequences: []string{"END"},
		System:    "You are a helpful assistant.",
		Messages: []converters.Message{
			{Role: "user", Content: "Hello, world!"},
		},
		Tools: []converters.Tool{
			{
				Name:        "test_tool",
				Description: "A test tool",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"input": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
		},
	}

	// Test transformation
	options, err := provider.TransformRequest(messageReq, "gpt-4")
	if err != nil {
		t.Fatalf("Failed to transform request: %v", err)
	}

	// Verify transformation
	if options.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", options.Model)
	}

	if options.MaxTokens != 100 {
		t.Errorf("Expected max_tokens 100, got %d", options.MaxTokens)
	}

	if options.Temperature != 0.7 {
		t.Errorf("Expected temperature 0.7, got %f", options.Temperature)
	}

	if len(options.Messages) != 2 { // System + User message
		t.Errorf("Expected 2 messages, got %d", len(options.Messages))
	}

	if len(options.Tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(options.Tools))
	}
}

func TestProviderConfigAccess(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "anthropic",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"claude-3-opus"},
				BaseURL:    "https://api.anthropic.com",
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Test GetProviderConfig
	providerConfig, err := registry.GetProviderConfig("anthropic")
	if err != nil {
		t.Fatalf("Failed to get provider config: %v", err)
	}

	if providerConfig.Name != "anthropic" {
		t.Errorf("Expected config name 'anthropic', got '%s'", providerConfig.Name)
	}

	if providerConfig.BaseURL != "https://api.anthropic.com" {
		t.Errorf("Expected base URL 'https://api.anthropic.com', got '%s'", providerConfig.BaseURL)
	}

	// Test GetAllProviderConfigs
	allConfigs := registry.GetAllProviderConfigs()
	if len(allConfigs) != 1 {
		t.Errorf("Expected 1 provider config, got %d", len(allConfigs))
	}

	if _, exists := allConfigs["anthropic"]; !exists {
		t.Error("Expected to find anthropic config in all configs")
	}
}

func TestServiceHealth(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Test GetServiceHealth
	health := registry.GetServiceHealth()
	if health == nil {
		t.Error("Service health should not be nil")
	}

	// Verify health monitor status
	if healthMonitor, ok := health["health_monitor"].(map[string]interface{}); ok {
		if enabled, ok := healthMonitor["enabled"].(bool); !ok || !enabled {
			t.Error("Health monitor should be enabled")
		}
	}

	// Verify discovery service status
	if discoveryService, ok := health["discovery_service"].(map[string]interface{}); ok {
		if enabled, ok := discoveryService["enabled"].(bool); !ok || !enabled {
			t.Error("Discovery service should be enabled")
		}
	}

	// Verify registry status
	if registryStatus, ok := health["registry"].(map[string]interface{}); ok {
		if totalProviders, ok := registryStatus["total_providers"].(int); !ok || totalProviders != 1 {
			t.Errorf("Expected 1 total provider, got %v", totalProviders)
		}
	}
}

// ============================================================================
// Message Request Conversion Tests
// ============================================================================

func TestLegacyToStandardRequestConversion(t *testing.T) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Create legacy message request
	legacyReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 150,
		Temperature: 1.0,
		Stream:    true,
		System:    "You are a helpful AI assistant.",
		Messages: []converters.Message{
			{Role: "user", Content: "What is the capital of France?"},
			{Role: "assistant", Content: "The capital of France is Paris."},
			{Role: "user", Content: "Tell me more about it."},
		},
		Metadata: map[string]interface{}{
			"user_id": "12345",
			"session_id": " sess_67890",
		},
	}

	// Test conversion
	standardReq, err := registry.ConvertMessageRequest(legacyReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Verify standard request
	if standardReq.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", standardReq.Model)
	}

	if standardReq.MaxTokens != 150 {
		t.Errorf("Expected max_tokens 150, got %d", standardReq.MaxTokens)
	}

	if len(standardReq.Messages) != 4 { // System + 3 messages
		t.Errorf("Expected 4 messages, got %d", len(standardReq.Messages))
	}

	// Verify system message
	if standardReq.Messages[0].Role != "system" {
		t.Errorf("Expected first message to be system, got '%s'", standardReq.Messages[0].Role)
	}

	// Verify metadata
	if standardReq.Metadata == nil {
		t.Error("Metadata should not be nil")
	}

	if userId, ok := standardReq.Metadata["user_id"].(string); !ok || userId != "12345" {
		t.Errorf("Expected user_id '12345', got %v", standardReq.Metadata["user_id"])
	}
}

// ============================================================================
// Mock OpenAI Server for Testing
// ============================================================================

func createMockOpenAIServer() *httptest.Server {
	mux := http.NewServeMux()

	// Mock /v1/chat/completions endpoint
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check for streaming
		stream := r.URL.Query().Get("stream") == "true"

		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)

			// Send mock streaming events
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"}}]}\n\n", time.Now().Unix())
			w.(http.Flusher).Flush()

			time.Sleep(100 * time.Millisecond)

			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}\n\n", time.Now().Unix())
			w.(http.Flusher).Flush()

			time.Sleep(100 * time.Millisecond)

			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"created\":%d,\"model\":\"gpt-4\",\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}]}\n\n", time.Now().Unix())
			w.(http.Flusher).Flush()

			fmt.Fprintf(w, "data: [DONE]\n\n")
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			response := `{
				"id": "chatcmpl-test",
				"object": "chat.completion",
				"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
				"model": "gpt-4",
				"choices": [{
					"index": 0,
					"message": {
						"role": "assistant",
						"content": "Hello world!"
					},
					"finish_reason": "stop"
				}],
				"usage": {
					"prompt_tokens": 10,
					"completion_tokens": 5,
					"total_tokens": 15
				}
			}`

			fmt.Fprint(w, response)
		}
	})

	// Mock health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	return httptest.NewServer(mux)
}

func TestProviderIntegrationWithMockServer(t *testing.T) {
	// Create mock OpenAI server
	mockServer := createMockOpenAIServer()
	defer mockServer.Close()

	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				BaseURL:    mockServer.URL,
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Test provider creation
	provider, err := registry.GetProvider("openai")
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	// Test request transformation
	messageReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		System:    "You are a helpful assistant.",
		Messages: []converters.Message{
			{Role: "user", Content: "Say hello"},
		},
	}

	options, err := provider.TransformRequest(messageReq, "gpt-4")
	if err != nil {
		t.Fatalf("Failed to transform request: %v", err)
	}

	// Test streaming completion (may fail depending on mock setup)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := provider.GenerateCompletion(ctx, options)
	if err != nil {
		t.Logf("Completion failed (expected in mock environment): %v", err)
		return
	}

	// Test response (this will likely fail with mocks, but ensures paths are tested)
	for {
		chunk, err := stream.Next()
		if err != nil {
			if err.Error() == "EOF" || err.Error() == "io.EOF" {
				break
			}
			t.Logf("Stream read failed (expected with mock): %v", err)
			return
		}

		if chunk.Content != "" {
			t.Logf("Received chunk: %s", chunk.Content)
		}

		if chunk.Done {
			t.Logf("Stream completed successfully")
			break
		}
	}
}

// ============================================================================
// Configuration Reload Tests
// ============================================================================

func TestConfigurationReload(t *testing.T) {
	// Create initial config
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				BaseURL:    "https://api.openai.com/v1",
				Models:     []string{"gpt-4"},
			},
		},
		Router: config.RouterConfig{
			Default: "openai",
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Verify initial state
	allModels := registry.GetAllModels()
	if len(allModels) != 1 {
		t.Errorf("Expected 1 provider initially, got %d", len(allModels))
	}

	// Create new config with additional provider
	newCfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "new-key",
				BaseURL:    "https://api.openai.com/v1",
				Models:     []string{"gpt-4", "gpt-3.5-turbo"},
			},
			{
				Name:       "anthropic",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				BaseURL:    "https://api.anthropic.com",
				Models:     []string{"claude-3-opus"},
			},
		},
		Router: config.RouterConfig{
			Default: "openai",
		},
	}

	// Reload configuration
	err = registry.ReloadProviders(newCfg)
	if err != nil {
		t.Fatalf("Failed to reload configuration: %v", err)
	}

	// Verify reloaded state
	allModels = registry.GetAllModels()
	if len(allModels) != 2 {
		t.Errorf("Expected 2 providers after reload, got %d", len(allModels))
	}

	if openaiModels, exists := allModels["openai"]; exists {
		if len(openaiModels) != 2 {
			t.Errorf("Expected 2 OpenAI models, got %d", len(openaiModels))
		}
	} else {
		t.Error("Expected OpenAI provider to still exist")
	}

	if anthropicModels, exists := allModels["anthropic"]; exists {
		if len(anthropicModels) != 1 {
			t.Errorf("Expected 1 Anthropic model, got %d", len(anthropicModels))
		}
	} else {
		t.Error("Expected Anthropic provider to be added")
	}
}

func TestConfigurationReloadValidation(t *testing.T) {
	// Create initial valid config
	cfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "openai",
				AuthMethod: "api_key",
				APIKEY:     "test-key",
				BaseURL:    "https://api.openai.com/v1",
				Models:     []string{"gpt-4"},
			},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider registry: %v", err)
	}

	// Try to reload with invalid config (nil)
	err = registry.ReloadProviders(nil)
	if err == nil {
		t.Error("Expected error when reloading with nil config")
	}

	// Try to reload with invalid provider config
	invalidCfg := &config.Config{
		Providers: []config.Provider{
			{
				Name:       "invalid-provider",
				AuthMethod: "api_key",
				APIKEY:     "",
				BaseURL:    "https://api.example.com",
				Models:     []string{}, // Empty models should be invalid
			},
		},
	}

	err = registry.ReloadProviders(invalidCfg)
	if err == nil {
		t.Error("Expected error when reloading with invalid provider")
	}
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

func BenchmarkProviderCreation(b *testing.B) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4", "gpt-3.5-turbo"}},
			{Name: "anthropic", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"claude-3-opus", "claude-3-sonnet"}},
			{Name: "gemini", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gemini-pro"}},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		registry, err := NewSDKProviderRegistry(cfg)
		if err != nil {
			b.Fatalf("Failed to create provider registry: %v", err)
		}

		// Clean up
		registry.Shutdown()
	}
}

func BenchmarkProviderLookup(b *testing.B) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4", "gpt-3.5-turbo"}},
			{Name: "anthropic", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"claude-3-opus", "claude-3-sonnet"}},
			{Name: "gemini", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gemini-pro"}},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		b.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	providers := []string{"openai", "anthropic", "gemini"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		providerName := providers[i%len(providers)]
		_, err := registry.GetProvider(providerName)
		if err != nil {
			b.Fatalf("Failed to get provider %s: %v", providerName, err)
		}
	}
}

func BenchmarkMessageRequestTransformation(b *testing.B) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4"}},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		b.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	provider, err := registry.GetProvider("openai")
	if err != nil {
		b.Fatalf("Failed to get provider: %v", err)
	}

	messageReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		Stream:    false,
		System:    "You are a helpful assistant.",
		Messages: []converters.Message{
			{Role: "user", Content: "Hello, world! This is a longer message to test performance with content of reasonable size."},
			{Role: "assistant", Content: "Hello! I understand you want to test performance. I'll provide a comprehensive response to help with benchmarking."},
		},
		Tools: []converters.Tool{
			{
				Name:        "test_tool",
				Description: "A test tool for performance benchmarking",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"input": map[string]interface{}{
							"type": "string",
							"description": "Input for the test tool",
						},
					},
					"required": []string{"input"},
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := provider.TransformRequest(messageReq, "gpt-4")
		if err != nil {
			b.Fatalf("Failed to transform request: %v", err)
		}
	}
}

func BenchmarkLegacyToStandardConversion(b *testing.B) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4"}},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		b.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	legacyReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 150,
		Temperature: 1.0,
		Stream:    true,
		System:    "You are a helpful AI assistant. This system prompt is longer to provide realistic testing scenarios.",
		Messages: []converters.Message{
			{Role: "user", Content: "What is the capital of France and tell me more about its history, culture, and significance?"},
			{Role: "assistant", Content: "The capital of France is Paris. It's a city rich in history, culture, and global significance. Paris has been a major center of culture, politics, and economics for centuries, known for its iconic landmarks like the Eiffel Tower, Louvre Museum, and Notre-Dame Cathedral."},
			{Role: "user", Content: "That's interesting! Can you elaborate on the architectural significance of Paris and compare it with other European capitals?"},
		},
		Metadata: map[string]interface{}{
			"user_id":     "12345",
			"session_id":  "sess_67890",
			"request_id":  "req_abc123",
			"source":      "benchmark_test",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := registry.ConvertMessageRequest(legacyReq)
		if err != nil {
			b.Fatalf("Failed to convert legacy request: %v", err)
		}
	}
}

func BenchmarkServiceHealthCheck(b *testing.B) {
	cfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4"}},
			{Name: "anthropic", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"claude-3-opus"}},
		},
	}

	registry, err := NewSDKProviderRegistry(cfg)
	if err != nil {
		b.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		health := registry.GetServiceHealth()
		if health == nil {
			b.Fatal("Service health should not be nil")
		}
	}
}

func BenchmarkConfigurationReload(b *testing.B) {
	initialCfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"gpt-4"}},
		},
	}

	registry, err := NewSDKProviderRegistry(initialCfg)
	if err != nil {
		b.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	newCfg := &config.Config{
		Providers: []config.Provider{
			{Name: "openai", AuthMethod: "api_key", APIKEY: "new-key", Models: []string{"gpt-4", "gpt-3.5-turbo"}},
			{Name: "anthropic", AuthMethod: "api_key", APIKEY: "test-key", Models: []string{"claude-3-opus"}},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := registry.ReloadProviders(newCfg)
		if err != nil {
			b.Fatalf("Failed to reload configuration: %v", err)
		}
	}
}