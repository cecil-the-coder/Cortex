//go:build example
// +build example

// This example demonstrates comprehensive usage of the Phase 3 Core API integration.
// It includes provider-specific extensions, health monitoring, and model discovery.
//
// To use this example, copy it to your main application and update the imports
// to point to the correct internal packages.
//
// NOTE: This example requires build tags to compile.
// To build: go build -tags=example ./docs/examples

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	// "github.com/cecil-the-coder/Cortex/internal/config"
	// "github.com/cecil-the-coder/Cortex/internal/converters"
	// "github.com/cecil-the-coder/Cortex/internal/providers"
)

// This example demonstrates comprehensive usage of the Phase 3 Core API integration
// It includes provider-specific extensions, health monitoring, and model discovery

func main() {
	// Initialize configuration
	cfg, err := loadConfiguration()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create provider registry with Core API support
	registry, err := providers.NewSDKProviderRegistry(cfg)
	if err != nil {
		log.Fatalf("Failed to create provider registry: %v", err)
	}
	defer registry.Shutdown()

	// Demonstrate various Core API capabilities
	demonstrateProviderCapabilities(registry)
	demonstrateHealthMonitoring(registry)
	demonstrateModelDiscovery(registry)
	demonstrateRequestConversion(registry)
	demonstrateResponseConversion(registry)
	demonstrateProviderSpecificFeatures(registry)
	demonstrateStreamingSupport(registry)
	demonstrateErrorHandling(registry)
}

func loadConfiguration() (*config.Config, error) {
	// Load configuration (you can read from file, env vars, etc.)
	return &config.Config{
		Providers: []config.Provider{
			{
				Name:        "openai",
				AuthMethod:  config.AuthMethodAPIKey,
				APIKEY:      os.Getenv("OPENAI_API_KEY"),
				Models:      []string{"gpt-4", "gpt-3.5-turbo"},
				BaseURL:     "https://api.openai.com/v1",
			},
			{
				Name:        "anthropic",
				AuthMethod:  config.AuthMethodAPIKey,
				APIKEY:      os.Getenv("ANTHROPIC_API_KEY"),
				Models:      []string{"claude-3-opus", "claude-3-sonnet", "claude-3-haiku"},
				BaseURL:     "https://api.anthropic.com",
			},
		},
	}, nil
}

func demonstrateProviderCapabilities(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Provider Capabilities Demo ===")

	// Get available providers
	allModels := registry.GetAllModels()

	fmt.Printf("Available providers and models:\n")
	for provider, models := range allModels {
		fmt.Printf("- %s: %v\n", provider, models)
	}

	// Get service health status
	health := registry.GetServiceHealth()
	fmt.Printf("\nService health: %+v\n", health)
}

func demonstrateHealthMonitoring(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Health Monitoring Demo ===")

	healthMonitor := registry.GetHealthMonitor()

	// Get health status for all providers
	status := healthMonitor.GetHealthStatus()

	fmt.Printf("Health status:\n")
	for provider, health := range status {
		fmt.Printf("  %s: Healthy=%t, LastCheck=%v, ResponseTime=%.3fs\n",
			provider, health.Healthy, health.LastChecked.Format(time.RFC3339), health.ResponseTime)

		if len(health.Alerts) > 0 {
			fmt.Printf("    Alerts: %d\n", len(health.Alerts))
		}
	}

	// Get healthy and unhealthy providers
	healthy := healthMonitor.GetHealthyProviders()
	unhealthy := healthMonitor.GetUnhealthyProviders()

	fmt.Printf("Healthy providers: %v\n", healthy)
	fmt.Printf("Unhealthy providers: %v\n", unhealthy)

	// Get monitoring statistics
	stats := healthMonitor.GetMonitoringStats()
	fmt.Printf("Monitoring stats: %+v\n", stats)
}

func demonstrateModelDiscovery(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Model Discovery Demo ===")

	discovery := registry.GetDiscoveryService()
	ctx := context.Background()

	// Get all models with capabilities
	allModels, err := discovery.GetAllModels(ctx)
	if err != nil {
		log.Printf("Failed to get all models: %v", err)
		return
	}

	fmt.Printf("Discovered models from %d providers:\n", len(allModels))
	for provider, models := range allModels {
		fmt.Printf("\n%s Provider:\n", provider)
		for _, model := range models {
			fmt.Printf("  - %s (%s): MaxTokens=%d, Streaming=%t, Tools=%t\n",
				model.Name, model.ID, model.ContextWindow,
				model.SupportsStreaming, model.SupportsToolCalling)

			// Show supported features
			if len(model.SupportedFeatures) > 2 {
				fmt.Printf("    Features: %v\n", model.SupportedFeatures)
			}
		}
	}

	// Find models with specific capabilities
	streamingModels, err := discovery.GetModelsByCapability(ctx, "streaming")
	if err == nil {
		fmt.Printf("\nModels supporting streaming: %d\n", len(streamingModels))
		for _, model := range streamingModels[:3] { // Show first 3
			fmt.Printf("  - %s (%s)\n", model.Name, model.ProviderName)
		}
	}

	// Get popular models
	popularModels, err := discovery.GetPopularModels(ctx)
	if err == nil {
		fmt.Printf("\nPopular models: %d\n", len(popularModels))
		for _, model := range popularModels[:3] { // Show first 3
			fmt.Printf("  - %s (%s)\n", model.Name, model.ProviderName)
		}
	}

	// Get discovery statistics
	stats, err := discovery.GetDiscoveryStats(ctx)
	if err == nil {
		fmt.Printf("\nDiscovery statistics: %+v\n", stats)
	}
}

func demonstrateRequestConversion(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Request Conversion Demo ===")

	requestConverter := registry.GetRequestConverter()

	// Create a legacy message request
	legacyReq := &converters.MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		Stream:    false,
		System:    "You are a helpful assistant.",
		Messages: []converters.Message{
			{Role: "user", Content: "Explain the benefits of the new Core API in Cortex."},
		},
		Tools: []converters.Tool{
			{
				Name:        "code_example",
				Description: "Generate code examples",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"language": map[string]interface{}{
							"type":        "string",
							"description": "Programming language",
						},
					},
					"required": []string{"language"},
				},
			},
		},
		StopSequences: []string{"END"},
		Metadata: map[string]interface{}{
			"user_id":     "demo_user",
			"session_id":  "demo_session_123",
		},
	}

	// Convert to standard request
	standardReq, err := requestConverter.ConvertFromLegacy(legacyReq)
	if err != nil {
		log.Printf("Failed to convert legacy request: %v", err)
		return
	}

	fmt.Printf("Converted to StandardRequest:\n")
	fmt.Printf("  Model: %s\n", standardReq.Model)
	fmt.Printf("  MaxTokens: %d\n", standardReq.MaxTokens)
	fmt.Printf("  Messages: %d\n", len(standardReq.Messages))
	fmt.Printf("  Tools: %d\n", len(standardReq.Tools))
	fmt.Printf("  Metadata keys: %v\n", getMapKeys(standardReq.Metadata))

	// Validate the converted request
	err = requestConverter.ValidateRequest(standardReq)
	if err != nil {
		log.Printf("Request validation failed: %v", err)
	} else {
		fmt.Printf("Request validation: PASSED\n")
	}

	// Demonstrate sanitization
	sanitized := requestConverter.SanitizeRequest(standardReq)
	fmt.Printf("Sanitized request: Model=%s, MaxTokens=%d\n",
		sanitized.Model, sanitized.MaxTokens)
}

func demonstrateResponseConversion(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Response Conversion Demo ===")

	responseConverter := registry.GetResponseConverter()

	// Create a standard response for demonstration
	standardResp := &types.StandardResponse{
		ID:      "resp_demo_123",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4",
		Choices: []types.StandardChoice{
			{
				Index: 0,
				Message: types.ChatMessage{
					Role:    "assistant",
					Content: "The Core API in Cortex provides standardized access to multiple AI providers with features like health monitoring, model discovery, and automatic format conversion.",
				},
				FinishReason: "stop",
			},
		},
		Usage: types.Usage{
			PromptTokens:     15,
			CompletionTokens: 25,
			TotalTokens:      40,
		},
		ProviderMetadata: map[string]interface{}{
			"provider":        "openai",
			"region":          "us-west-2",
			"response_time":   1.234,
			"core_api_used":   true,
		},
	}

	// Convert to different formats
	supportedFormats := responseConverter.GetSupportedFormats()
	fmt.Printf("Supported formats: %v\n", supportedFormats)

	// Convert to Anthropic format
	anthropicResp, err := responseConverter.ConvertFromStandard(standardResp, converters.FormatLegacy)
	if err != nil {
		log.Printf("Failed to convert to Anthropic format: %v", err)
	} else {
		fmt.Printf("\nConverted to Anthropic format:\n")
		if resp, ok := anthropicResp.(*converters.AnthropicResponse); ok {
			fmt.Printf("  ID: %s\n", resp.ID)
			fmt.Printf("  Type: %s\n", resp.Type)
			fmt.Printf("  Content length: %d\n", len(resp.Content))
			fmt.Printf("  Usage: %+v\n", resp.Usage)
		}
	}

	// Convert to OpenAI format
	openaiResp, err := responseConverter.ConvertFromStandard(standardResp, converters.FormatOpenAI)
	if err != nil {
		log.Printf("Failed to convert to OpenAI format: %v", err)
	} else {
		fmt.Printf("\nConverted to OpenAI format:\n")
		if resp, ok := openaiResp.(map[string]interface{}); ok {
			fmt.Printf("  ID: %v\n", resp["id"])
			fmt.Printf("  Object: %v\n", resp["object"])
			fmt.Printf("  Model: %v\n", resp["model"])
		}
	}

	// Validate responses
	issues1 := responseConverter.ValidateResponse(anthropicResp)
	issues2 := responseConverter.ValidateResponse(openaiResp)
	fmt.Printf("\nValidation issues - Anthropic: %d, OpenAI: %d\n", len(issues1), len(issues2))
}

func demonstrateProviderSpecificFeatures(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Provider-Specific Features Demo ===")

	providers := []string{"openai", "anthropic"}

	for _, providerName := range providers {
		fmt.Printf("\n--- %s Provider ---\n", providerName)

		provider, err := registry.GetProvider(providerName)
		if err != nil {
			log.Printf("Failed to get provider %s: %v", providerName, err)
			continue
		}

		// Check Core API availability
		if provider.UseCoreAPI() {
			fmt.Printf("Core API: ENABLED\n")

			// Get capabilities
			capabilities := provider.GetStandardCapabilities()
			fmt.Printf("Capabilities: %v\n", capabilities)

			// Get provider extension
			if extension, err := provider.GetCoreProviderExtension(); err == nil {
				fmt.Printf("Provider extension available: %T\n", extension)

				// Try to access provider-specific features
				if providerName == "anthropic" {
					fmt.Printf("  Anthropic-specific features available (thinking mode, etc.)\n")
				}

				if providerName == "openai" {
					fmt.Printf("  OpenAI-specific features available (JSON mode, etc.)\n")
				}
			}
		} else {
			fmt.Printf("Core API: DISABLED (using legacy API)\n")
		}

		// Test request transformation
		messageReq := &converters.MessageRequest{
			Model: "gpt-4",
			Messages: []converters.Message{
				{Role: "user", Content: "Hello from " + providerName},
			},
		}

		options, err := provider.TransformRequest(messageReq, "gpt-4")
		if err != nil {
			log.Printf("Failed to transform request for %s: %v", providerName, err)
		} else {
			fmt.Printf("Request transformation: SUCCESS\n")
			fmt.Printf("  Model: %s, Messages: %d\n", options.Model, len(options.Messages))
		}
	}
}

func demonstrateStreamingSupport(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Streaming Support Demo ===")

	for _, providerName := range []string{"openai", "anthropic"} {
		fmt.Printf("\n--- %s Streaming Demo ---\n", providerName)

		provider, err := registry.GetProvider(providerName)
		if err != nil {
			log.Printf("Failed to get provider %s: %v", providerName, err)
			continue
		}

		// Create streaming request
		messageReq := &converters.MessageRequest{
			Model:     "gpt-3.5-turbo", // Use smaller model for demo
			MaxTokens: 50,
			Temperature: 0.7,
			Stream:    true,
			Messages: []converters.Message{
				{Role: "user", Content: "Write a 3-word response about streaming"},
			},
		}

		options, err := provider.TransformRequest(messageReq, "gpt-3.5-turbo")
		if err != nil {
			log.Printf("Failed to create streaming options for %s: %v", providerName, err)
			continue
		}

		// Test streaming with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		fmt.Printf("Starting stream from %s...\n", providerName)

		start := time.Now()
		stream, err := provider.GenerateCompletion(ctx, options)
		if err != nil {
			log.Printf("Failed to start stream from %s: %v", providerName, err)
			continue
		}

		chunkCount := 0
		totalContent := ""

		for {
			chunk, err := stream.Next()
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				log.Printf("Stream error from %s: %v", providerName, err)
				break
			}

			chunkCount++
			if chunk.Content != "" {
				totalContent += chunk.Content
			}

			if chunkCount > 5 { // Limit demo chunks
				fmt.Printf("  ... (limited to 5 chunks for demo)\n")
				break
			}
		}

		duration := time.Since(start)
		fmt.Printf("Stream completed: %d chunks, %d chars, %.2fs\n",
			chunkCount, len(totalContent), duration.Seconds())
	}
}

func demonstrateErrorHandling(registry *providers.SDKProviderRegistry) {
	fmt.Println("\n=== Error Handling Demo ===")

	// Test with non-existent provider
	_, err := registry.GetProvider("non-existent")
	if err != nil {
		fmt.Printf("Expected error for non-existent provider: %v\n", err)
	}

	// Test invalid configuration
	invalidConfig := &config.Config{
		Providers: []config.Provider{
			{Name: "invalid", APIKEY: "", Models: []string{}},
		},
	}

	_, err = providers.NewSDKProviderRegistry(invalidConfig)
	if err != nil {
		fmt.Printf("Expected error for invalid config: %v\n", err)
	}

	// Test request validation
	requestConverter := registry.GetRequestConverter()
	invalidReq := &types.StandardRequest{
		Model:     "",       // Invalid: empty model
		MaxTokens: -100,     // Invalid: negative tokens
		Messages:  []types.ChatMessage{}, // Invalid: no messages
	}

	err = requestConverter.ValidateRequest(invalidReq)
	if err != nil {
		fmt.Printf("Expected validation error: %v\n", err)
	}

	// Test response validation
	responseConverter := registry.GetResponseConverter()
	issues := responseConverter.ValidateResponse(nil)
	if len(issues) > 0 {
		fmt.Printf("Expected validation issues for nil response: %v\n", issues)
	}

	// Test health monitoring with invalid provider
	healthMonitor := registry.GetHealthMonitor()
	err = healthMonitor.TriggerManualHealthCheck("non-existent")
	if err != nil {
		fmt.Printf("Expected error for non-existent provider health check: %v\n", err)
	}
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}