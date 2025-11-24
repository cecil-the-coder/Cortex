package config

import (
	"testing"
)

func TestModelContextRegistry(t *testing.T) {
	registry := NewModelContextRegistry()

	tests := []struct {
		name           string
		model          string
		expectedWindow int
		expectedFound  bool
	}{
		{
			name:           "Claude 3.5 Sonnet exact match",
			model:          "claude-3-5-sonnet-20241022",
			expectedWindow: 200000,
			expectedFound:  true,
		},
		{
			name:           "GPT-4 Turbo exact match",
			model:          "gpt-4-turbo-preview",
			expectedWindow: 128000,
			expectedFound:  true,
		},
		{
			name:           "Claude 3 Sonnet partial match",
			model:          "claude-3-sonnet",
			expectedWindow: 200000,
			expectedFound:  true,
		},
		{
			name:           "GPT-3.5 Turbo partial match",
			model:          "gpt-3.5-turbo",
			expectedWindow: 16385,
			expectedFound:  true,
		},
		{
			name:           "Unknown model",
			model:          "unknown-model-xyz",
			expectedWindow: DefaultContextWindow,
			expectedFound:  false,
		},
		{
			name:           "Empty model name",
			model:          "",
			expectedWindow: DefaultContextWindow,
			expectedFound:  false,
		},
		{
			name:           "Case insensitive match",
			model:          "CLAUDE-3-SONNET",
			expectedWindow: 200000,
			expectedFound:  true,
		},
		{
			name:           "Gemini 1.5 Pro",
			model:          "gemini-1.5-pro",
			expectedWindow: 1000000,
			expectedFound:  true,
		},
		{
			name:           "Llama 2 model",
			model:          "llama-2-70b-chat",
			expectedWindow: 4096,
			expectedFound:  true,
		},
		{
			name:           "Mistral model",
			model:          "mixtral-8x7b-instruct",
			expectedWindow: 32768,
			expectedFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextWindow, found := registry.GetContextWindow(tt.model)

			if found != tt.expectedFound {
				t.Errorf("GetContextWindow(%q) found = %v, expected %v", tt.model, found, tt.expectedFound)
			}

			if contextWindow != tt.expectedWindow {
				t.Errorf("GetContextWindow(%q) = %d, expected %d", tt.model, contextWindow, tt.expectedWindow)
			}
		})
	}
}

func TestModelContextInfo(t *testing.T) {
	registry := NewModelContextRegistry()

	tests := []struct {
		name              string
		model             string
		expectedFound     bool
		expectedModelName string
		expectedProvider  string
	}{
		{
			name:              "Claude model info",
			model:             "claude-3-opus-20240229",
			expectedFound:     true,
			expectedModelName: "claude-3-opus-20240229",
			expectedProvider:  "anthropic",
		},
		{
			name:              "OpenAI model info",
			model:             "gpt-4",
			expectedFound:     true,
			expectedModelName: "gpt-4",
			expectedProvider:  "openai",
		},
		{
			name:              "Unknown model info",
			model:             "unknown-model",
			expectedFound:     false,
			expectedModelName: "",
			expectedProvider:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, found := registry.GetModelInfo(tt.model)

			if found != tt.expectedFound {
				t.Errorf("GetModelInfo(%q) found = %v, expected %v", tt.model, found, tt.expectedFound)
			}

			if found {
				if info.ModelName != tt.expectedModelName {
					t.Errorf("GetModelInfo(%q) ModelName = %s, expected %s", tt.model, info.ModelName, tt.expectedModelName)
				}

				if info.Provider != tt.expectedProvider {
					t.Errorf("GetModelInfo(%q) Provider = %s, expected %s", tt.model, info.Provider, tt.expectedProvider)
				}

				if info.ContextTokens <= 0 {
					t.Errorf("GetModelInfo(%q) ContextTokens should be positive, got %d", tt.model, info.ContextTokens)
				}
			}
		})
	}
}

func TestFilterModelsByContext(t *testing.T) {
	registry := NewModelContextRegistry()

	// Create test model references with different context windows
	models := []ModelReference{
		{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", Alias: "sonnet"},
		{Provider: "openai", Model: "gpt-4", Alias: "gpt4-small"},                      // 8K context
		{Provider: "openai", Model: "gpt-4-turbo-preview", Alias: "gpt4-turbo"},
		{Provider: "anthropic", Model: "claude-3-haiku", Alias: "haiku"},
	}

	tests := []struct {
		name          string
		tokenCount    int
		allowFallback bool
		expectedCount int
	}{
		{
			name:          "Small context - all models should qualify",
			tokenCount:    1000,
			allowFallback: false,
			expectedCount: 4,
		},
		{
			name:          "Medium context - some models excluded",
			tokenCount:    10000,
			allowFallback: false,
			expectedCount: 3, // GPT-4 (8K) excluded
		},
		{
			name:          "Large context - only high-capacity models",
			tokenCount:    100000,
			allowFallback: false,
			expectedCount: 2, // Only Claude 3.5 Sonnet and GPT-4 Turbo
		},
		{
			name:          "Very large context - fallback disabled",
			tokenCount:    500000,
			allowFallback: false,
			expectedCount: 0, // No models can handle this
		},
		{
			name:          "Very large context - fallback allowed",
			tokenCount:    500000,
			allowFallback: true,
			expectedCount: 4, // All models returned as fallbacks
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := registry.FilterModelsByContext(models, tt.tokenCount, tt.allowFallback)

			if len(filtered) != tt.expectedCount {
				t.Errorf("FilterModelsByContext() returned %d models, expected %d", len(filtered), tt.expectedCount)
			}

			// Verify that returned models can handle the context (if fallback is disabled)
			if !tt.allowFallback {
				for _, modelRef := range filtered {
					contextWindow := registry.GetContextWindowForModel(modelRef)
					if contextWindow < tt.tokenCount {
						t.Errorf("Returned model %s cannot handle context %d (window: %d)", modelRef.Model, tt.tokenCount, contextWindow)
					}
				}
			}
		})
	}
}

func TestGetContextWindowForModel(t *testing.T) {
	registry := NewModelContextRegistry()

	// Test without override
	modelRef := ModelReference{
		Provider: "anthropic",
		Model:    "claude-3-sonnet",
		Alias:    "sonnet",
	}

	contextWindow := registry.GetContextWindowForModel(modelRef)
	if contextWindow != 200000 {
		t.Errorf("Expected context window 200000 for claude-3-sonnet, got %d", contextWindow)
	}

	// Test with override
	overrideWindow := 150000
	modelRef.MaxContextTokens = &overrideWindow

	contextWindow = registry.GetContextWindowForModel(modelRef)
	if contextWindow != 150000 {
		t.Errorf("Expected overridden context window 150000, got %d", contextWindow)
	}

	// Test with zero override (should use registry)
	overrideWindow = 0
	modelRef.MaxContextTokens = &overrideWindow

	contextWindow = registry.GetContextWindowForModel(modelRef)
	if contextWindow != 200000 {
		t.Errorf("Expected registry context window 200000 when override is 0, got %d", contextWindow)
	}

	// Test with unknown model
	modelRef = ModelReference{
		Provider: "unknown",
		Model:    "unknown-model",
	}

	contextWindow = registry.GetContextWindowForModel(modelRef)
	if contextWindow != DefaultContextWindow {
		t.Errorf("Expected default context window %d for unknown model, got %d", DefaultContextWindow, contextWindow)
	}
}

func TestValidateContextWindow(t *testing.T) {
	tests := []struct {
		name        string
		context     *int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Nil context window",
			context:     nil,
			expectError: false,
		},
		{
			name:        "Positive context window",
			context:     intPtr(100000),
			expectError: false,
		},
		{
			name:        "Zero context window",
			context:     intPtr(0),
			expectError: false,
		},
		{
			name:        "Negative context window",
			context:     intPtr(-1),
			expectError: true,
			errorMsg:    "context window cannot be negative",
		},
		{
			name:        "Unrealistically large context window",
			context:     intPtr(3000000),
			expectError: true,
			errorMsg:    "context window seems unrealistically large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContextWindow(tt.context)

			if (err != nil) != tt.expectError {
				t.Errorf("ValidateContextWindow() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if tt.expectError && err != nil {
				if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("ValidateContextWindow() error = %v, expected to contain %s", err, tt.errorMsg)
				}
			}
		})
	}
}

func testNameVariations(t *testing.T) {
	registry := NewModelContextRegistry()

	// Test that name variations work correctly
	testCases := []struct {
		searchTerm    string
		expectedFound bool
		description   string
	}{
		{"claude-3-5-sonnet", true, "Canonical name"},
		{"claude-3-5-sonnet-20241022", true, "Full versioned name"},
		{"claude-3-5-sonnet-latest", true, "Latest version"},
		{"gpt-4-turbo", true, "Turbo family name"},
		{"gpt-4-turbo-preview", true, "Full turbo preview name"},
		{"gpt-3.5-turbo", true, "GPT 3.5 family name"},
		{"claude-3-sonnet", true, "Claude 3 sonnet family"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			_, found := registry.GetContextWindow(tc.searchTerm)
			if found != tc.expectedFound {
				t.Errorf("GetContextWindow(%q) found = %v, expected %v", tc.searchTerm, found, tc.expectedFound)
			}
		})
	}
}

func TestGlobalContextRegistry(t *testing.T) {
	registry := GetGlobalContextRegistry()

	if registry == nil {
		t.Error("GetGlobalContextRegistry() should not return nil")
	}

	// Test that the global registry has some models
	contextWindow, found := registry.GetContextWindow("claude-3-5-sonnet")
	if !found {
		t.Error("Global registry should have claude-3-5-sonnet model")
	}

	if contextWindow <= 0 {
		t.Errorf("Global registry should return positive context window, got %d", contextWindow)
	}
}

func TestModelContextRegistrySortByContext(t *testing.T) {
	registry := NewModelContextRegistry()

	models := []ModelReference{
		{Provider: "openai", Model: "gpt-4", Alias: "gpt4-small"},           // 8K
		{Provider: "anthropic", Model: "claude-3-5-sonnet-20241022", Alias: "sonnet"}, // 200K
		{Provider: "openai", Model: "gpt-4-turbo-preview", Alias: "gpt4-turbo"},       // 128K
	}

	sorted := registry.sortModelsByContextWindow(models)

	// Verify sorting (largest context window first)
	context1 := registry.GetContextWindowForModel(sorted[0])
	context2 := registry.GetContextWindowForModel(sorted[1])
	context3 := registry.GetContextWindowForModel(sorted[2])

	if context1 < context2 || context2 < context3 {
		t.Errorf("Models not sorted correctly by context window: %d, %d, %d", context1, context2, context3)
	}

	// Verify the largest is first (should be Claude 3.5 Sonnet with 200K)
	expectedModel := "claude-3-5-sonnet-20241022"
	if sorted[0].Model != expectedModel {
		t.Errorf("Expected first model to be %s, got %s", expectedModel, sorted[0].Model)
	}
}

// Helper function to create a pointer to an int
func intPtr(i int) *int {
	return &i
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
			 s[len(s)-len(substr):] == substr ||
			 containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}