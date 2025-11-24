package converters

import (
	"errors"
	"testing"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
)

// ============================================================================
// Basic RequestConverter Tests
// ============================================================================

func TestNewRequestConverter(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	if converter == nil {
		t.Fatal("RequestConverter should not be nil")
	}

	if converter.defaultModel != "gpt-3.5-turbo" {
		t.Errorf("Expected default model 'gpt-3.5-turbo', got '%s'", converter.defaultModel)
	}

	if converter.maxTokensLimit != 4096 {
		t.Errorf("Expected max tokens limit 4096, got %d", converter.maxTokensLimit)
	}

	if converter.strictMode != false {
		t.Error("Strict mode should be false by default")
	}

	if len(converter.validationRules) == 0 {
		t.Error("Should have default validation rules")
	}
}

func TestNewRequestConverterWithCustomParams(t *testing.T) {
	converter := NewRequestConverter("claude-3-opus", 200000)

	if converter.defaultModel != "claude-3-opus" {
		t.Errorf("Expected default model 'claude-3-opus', got '%s'", converter.defaultModel)
	}

	if converter.maxTokensLimit != 200000 {
		t.Errorf("Expected max tokens limit 200000, got %d", converter.maxTokensLimit)
	}
}

func TestSetStrictMode(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	ruleCount := len(converter.validationRules)

	// Enable strict mode
	converter.SetStrictMode(true)

	if !converter.strictMode {
		t.Error("Strict mode should be enabled")
	}

	if len(converter.validationRules) <= ruleCount {
		t.Error("Strict mode should add additional validation rules")
	}

	// Disable strict mode
	converter.SetStrictMode(false)

	if converter.strictMode {
		t.Error("Strict mode should be disabled")
	}
}

func TestAddValidationRule(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	initialRuleCount := len(converter.validationRules)

	// Add custom validation rule
	customRule := ValidationRule{
		Name: "test_rule",
		Description: "Test validation rule",
		Validate: func(request types.StandardRequest) error {
			return nil
		},
	}

	converter.AddValidationRule(customRule)

	if len(converter.validationRules) != initialRuleCount+1 {
		t.Errorf("Expected rule count to increase by 1, got %d", len(converter.validationRules))
	}

	// Check if rule was added by looking for it
	found := false
	for _, rule := range converter.validationRules {
		if rule.Name == "test_rule" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Custom validation rule not found in rules list")
	}
}

// ============================================================================
// MessageRequest Conversion Tests
// ============================================================================

func TestConvertFromLegacyBasic(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		Stream:    false,
		System:    "You are a helpful assistant.",
		Messages: []Message{
			{Role: "user", Content: "Hello, world!"},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Verify basic conversion
	if standardReq.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", standardReq.Model)
	}

	if standardReq.MaxTokens != 100 {
		t.Errorf("Expected max_tokens 100, got %d", standardReq.MaxTokens)
	}

	if standardReq.Temperature != 0.7 {
		t.Errorf("Expected temperature 0.7, got %f", standardReq.Temperature)
	}

	if standardReq.Stream != false {
		t.Error("Expected stream to be false")
	}

	// Verify messages
	if len(standardReq.Messages) != 2 { // System + User
		t.Errorf("Expected 2 messages, got %d", len(standardReq.Messages))
	}

	if standardReq.Messages[0].Role != "system" {
		t.Errorf("Expected first message role 'system', got '%s'", standardReq.Messages[0].Role)
	}

	if standardReq.Messages[0].Content != "You are a helpful assistant." {
		t.Errorf("Expected system message content 'You are a helpful assistant.', got '%s'", standardReq.Messages[0].Content)
	}

	if standardReq.Messages[1].Role != "user" {
		t.Errorf("Expected second message role 'user', got '%s'", standardReq.Messages[1].Role)
	}

	if standardReq.Messages[1].Content != "Hello, world!" {
		t.Errorf("Expected user message content 'Hello, world!', got '%s'", standardReq.Messages[1].Content)
	}
}

func TestConvertFromLegacyWithDefaults(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Messages: []Message{
			{Role: "user", Content: "Hello!"},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Check default model
	if standardReq.Model != "gpt-3.5-turbo" {
		t.Errorf("Expected default model 'gpt-3.5-turbo', got '%s'", standardReq.Model)
	}

	// Check default max tokens
	if standardReq.MaxTokens != 1000 { // Default should be applied
		t.Errorf("Expected default max_tokens 1000, got %d", standardReq.MaxTokens)
	}

	// Verify no system message was added (since none was provided)
	if len(standardReq.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(standardReq.Messages))
	}

	if standardReq.Messages[0].Role != "user" {
		t.Errorf("Expected message role 'user', got '%s'", standardReq.Messages[0].Role)
	}
}

func TestConvertFromLegacyWithTools(t *testing.T) {
	converter := NewRequestConverter("gpt-4", 8192)

	messageReq := &MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 150,
		Messages: []Message{
			{Role: "user", Content: "What's the weather?"},
		},
		Tools: []Tool{
			{
				Name:        "get_weather",
				Description: "Get current weather for a location",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"location": map[string]interface{}{
							"type": "string",
							"description": "The city and state, e.g. San Francisco, CA",
						},
					},
					"required": []string{"location"},
				},
			},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Verify tools were converted
	if len(standardReq.Tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(standardReq.Tools))
	}

	tool := standardReq.Tools[0]
	if tool.Name != "get_weather" {
		t.Errorf("Expected tool name 'get_weather', got '%s'", tool.Name)
	}

	if tool.Description != "Get current weather for a location" {
		t.Errorf("Expected tool description 'Get current weather for a location', got '%s'", tool.Description)
	}

	if tool.InputSchema == nil {
		t.Error("Tool input schema should not be nil")
	}

	// Verify tool choice was set
	if standardReq.ToolChoice == nil {
		t.Error("Tool choice should be set when tools are provided")
	}

	if standardReq.ToolChoice.Mode != types.ToolChoiceAuto {
		t.Errorf("Expected tool choice mode 'auto', got '%s'", standardReq.ToolChoice.Mode)
	}
}

func TestConvertFromLegacyWithStopSequences(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Model:     "gpt-3.5-turbo",
		MaxTokens: 100,
		Messages: []Message{
			{Role: "user", Content: "Hello!"},
		},
		StopSequences: []string{"END", "STOP", "\n"},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	if len(standardReq.Stop) != 3 {
		t.Errorf("Expected 3 stop sequences, got %d", len(standardReq.Stop))
	}

	expectedStops := []string{"END", "STOP", "\n"}
	for i, stop := range expectedStops {
		if i >= len(standardReq.Stop) || standardReq.Stop[i] != stop {
			t.Errorf("Expected stop sequence '%s' at index %d, got '%s'", stop, i, standardReq.Stop[i])
		}
	}
}

func TestConvertFromLegacyWithMetadata(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	metadata := map[string]interface{}{
		"user_id":    "12345",
		"session_id": "sess_67890",
		"priority":   "high",
	}

	messageReq := &MessageRequest{
		Model:    "gpt-3.5-turbo",
		Messages: []Message{{Role: "user", Content: "Hello!"}},
		Metadata: metadata,
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Verify original metadata was preserved
	if standardReq.Metadata["user_id"] != "12345" {
		t.Errorf("Expected user_id '12345', got %v", standardReq.Metadata["user_id"])
	}

	if standardReq.Metadata["session_id"] != "sess_67890" {
		t.Errorf("Expected session_id 'sess_67890', got %v", standardReq.Metadata["session_id"])
	}

	// Verify conversion metadata was added
	if _, exists := standardReq.Metadata["_converted_at"]; !exists {
		t.Error("Expected _converted_at metadata to be added")
	}

	if _, exists := standardReq.Metadata["_converter_version"]; !exists {
		t.Error("Expected _converter_version metadata to be added")
	}
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

func TestConvertFromLegacyNilRequest(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	_, err := converter.ConvertFromLegacy(nil)
	if err == nil {
		t.Error("Expected error when converting nil request")
	}

	var convErr *ConversionError
	if !errors.As(err, &convErr) {
		t.Error("Expected ConversionError")
	}
}

func TestConvertFromLegacyEmptyMessages(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Model:    "gpt-3.5-turbo",
		Messages: []Message{}, // Empty messages
	}

	_, err := converter.ConvertFromLegacy(messageReq)
	if err == nil {
		t.Error("Expected error when converting request with empty messages")
	}
}

func TestConvertFromLegacyInvalidTool(t *testing.T) {
	converter := NewRequestConverter("gpt-4", 8192)

	messageReq := &MessageRequest{
		Model:    "gpt-4",
		Messages: []Message{{Role: "user", Content: "Hello!"}},
		Tools: []Tool{
			{
				Name: "", // Empty name should cause error
				InputSchema: map[string]interface{}{
					"type": "object",
				},
			},
		},
	}

	_, err := converter.ConvertFromLegacy(messageReq)
	if err == nil {
		t.Error("Expected error when converting request with invalid tool")
	}

	var convErr *ConversionError
	if ok := errors.As(err, &convErr); ok {
		if convErr.Field != "tools[0].name" {
			t.Errorf("Expected error field 'tools[0].name', got '%s'", convErr.Field)
		}
	} else {
		t.Errorf("Expected ConversionError, got %T", err)
	}
}

func TestConvertFromLegacyNilToolSchema(t *testing.T) {
	converter := NewRequestConverter("gpt-4", 8192)

	messageReq := &MessageRequest{
		Model:    "gpt-4",
		Messages: []Message{{Role: "user", Content: "Hello!"}},
		Tools: []Tool{
			{
				Name:        "test_tool",
				InputSchema: nil, // Nil schema should cause error
			},
		},
	}

	_, err := converter.ConvertFromLegacy(messageReq)
	if err == nil {
		t.Error("Expected error when converting request with nil tool schema")
	}
}

// ============================================================================
// Content Format Tests
// ============================================================================

func TestConvertFromLegacyStringContent(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Model:    "gpt-3.5-turbo",
		Messages: []Message{
			{Role: "user", Content: "Simple string content"},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	if standardReq.Messages[0].Content != "Simple string content" {
		t.Errorf("Expected content 'Simple string content', got '%s'", standardReq.Messages[0].Content)
	}
}

func TestConvertFromLegacyContentBlocks(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	// Anthropic-style content blocks
	contentBlocks := []interface{}{
		map[string]interface{}{
			"type": "text",
			"text": "Hello from content block",
		},
		map[string]interface{}{
			"type": "text",
			"text": "Second block",
		},
	}

	messageReq := &MessageRequest{
		Model:    "gpt-3.5-turbo",
		Messages: []Message{
			{Role: "user", Content: contentBlocks},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	expectedContent := "Hello from content blockSecond block"
	if standardReq.Messages[0].Content != expectedContent {
		t.Errorf("Expected content '%s', got '%s'", expectedContent, standardReq.Messages[0].Content)
	}
}

func TestConvertFromLegacyToolCalls(t *testing.T) {
	converter := NewRequestConverter("gpt-4", 8192)

	// Message with tool calls (content blocks with tool_use)
	toolCallContent := []interface{}{
		map[string]interface{}{
			"type": "tool_use",
			"id":   "call_123",
			"name": "get_weather",
			"input": map[string]interface{}{
				"location": "New York, NY",
			},
		},
	}

	// Tool result
	toolResultContent := []interface{}{
		map[string]interface{}{
			"type": "tool_result",
			"tool_use_id": "call_123",
			"content": "The weather in New York is 72°F and sunny.",
		},
	}

	messageReq := &MessageRequest{
		Model:    "gpt-4",
		Messages: []Message{
			{Role: "assistant", Content: toolCallContent},
			{Role: "user", Content: toolResultContent},
		},
	}

	standardReq, err := converter.ConvertFromLegacy(messageReq)
	if err != nil {
		t.Fatalf("Failed to convert legacy request: %v", err)
	}

	// Verify assistant message has tool calls
	assistantMsg := standardReq.Messages[0]
	if assistantMsg.Role != "assistant" {
		t.Errorf("Expected assistant role, got '%s'", assistantMsg.Role)
	}

	if len(assistantMsg.ToolCalls) != 1 {
		t.Errorf("Expected 1 tool call, got %d", len(assistantMsg.ToolCalls))
	}

	toolCall := assistantMsg.ToolCalls[0]
	if toolCall.ID != "call_123" {
		t.Errorf("Expected tool call ID 'call_123', got '%s'", toolCall.ID)
	}

	if toolCall.Function.Name != "get_weather" {
		t.Errorf("Expected function name 'get_weather', got '%s'", toolCall.Function.Name)
	}

	// Verify tool result message
	toolMsg := standardReq.Messages[1]
	if toolMsg.Role != "tool" {
		t.Errorf("Expected tool role, got '%s'", toolMsg.Role)
	}

	if toolMsg.ToolCallID != "call_123" {
		t.Errorf("Expected tool call ID 'call_123', got '%s'", toolMsg.ToolCallID)
	}
}

// ============================================================================
// Validation Tests
// ============================================================================

func TestValidateRequest(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	validRequest := &types.StandardRequest{
		Messages: []types.ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello!"},
		},
		Model:          "gpt-3.5-turbo",
		MaxTokens:      100,
		Temperature:    0.7,
	}

	err := converter.ValidateRequest(validRequest)
	if err != nil {
		t.Errorf("Valid request should pass validation: %v", err)
	}
}

func TestValidateRequestNil(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	err := converter.ValidateRequest(nil)
	if err == nil {
		t.Error("Expected error when validating nil request")
	}

	var convErr *ConversionError
	if ok := errors.As(err, &convErr); ok {
		if convErr.Field != "request" {
			t.Errorf("Expected error field 'request', got '%s'", convErr.Field)
		}
	} else {
		t.Error("Expected ConversionError")
	}
}

func TestValidateRequestNoMessages(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	invalidRequest := &types.StandardRequest{
		Model:     "gpt-3.5-turbo",
		MaxTokens: 100,
		Messages:  []types.ChatMessage{}, // No messages
	}

	err := converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when validating request with no messages")
	}
}

func TestValidateRequestTemperatureRange(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	// Test temperature too high
	invalidRequest := &types.StandardRequest{
		Model:       "gpt-3.5-turbo",
		MaxTokens:   100,
		Temperature: 3.0, // Too high
		Messages: []types.ChatMessage{
			{Role: "user", Content: "Hello!"},
		},
	}

	err := converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when validating request with temperature > 2")
	}

	// Test negative temperature
	invalidRequest.Temperature = -1.0
	err = converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when validating request with negative temperature")
	}

	// Test valid temperature
	invalidRequest.Temperature = 1.5
	err = converter.ValidateRequest(invalidRequest)
	if err != nil {
		t.Errorf("Valid temperature should pass validation: %v", err)
	}
}

func TestValidateRequestMaxTokens(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	// Test negative max tokens
	invalidRequest := &types.StandardRequest{
		Model:      "gpt-3.5-turbo",
		MaxTokens:  -100, // Invalid
		Messages: []types.ChatMessage{
			{Role: "user", Content: "Hello!"},
		},
	}

	err := converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when validating request with negative max tokens")
	}

	// Test valid max tokens
	invalidRequest.MaxTokens = 100
	err = converter.ValidateRequest(invalidRequest)
	if err != nil {
		t.Errorf("Valid max tokens should pass validation: %v", err)
	}
}

func TestValidateRequestToolChoiceConsistency(t *testing.T) {
	converter := NewRequestConverter("gpt-4", 8192)

	// Test tool choice without tools
	invalidRequest := &types.StandardRequest{
		Model:      "gpt-4",
		MaxTokens:  100,
		ToolChoice: &types.ToolChoice{Mode: types.ToolChoiceAuto},
		Messages: []types.ChatMessage{
			{Role: "user", Content: "Hello!"},
		},
		// No tools provided
	}

	err := converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when tool choice is provided without tools")
	}

	// Test tool choice with tools
	invalidRequest.Tools = []types.Tool{
		{Name: "test_tool", InputSchema: map[string]interface{}{"type": "object"}},
	}
	err = converter.ValidateRequest(invalidRequest)
	if err != nil {
		t.Errorf("Tool choice with tools should pass validation: %v", err)
	}
}

// ============================================================================
// Strict Mode Validation Tests
// ============================================================================

func TestStrictModeValidation(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)
	converter.SetStrictMode(true)

	// Test invalid message sequence
	invalidRequest := &types.StandardRequest{
		Model:     "gpt-3.5-turbo",
		MaxTokens: 100,
		Messages: []types.ChatMessage{
			{Role: "user", Content: "Hello!"},
			{Role: "system", Content: "You are helpful."}, // System in wrong position
		},
	}

	err := converter.ValidateRequest(invalidRequest)
	if err == nil {
		t.Error("Expected error when validating invalid message sequence in strict mode")
	}

	// Test valid message sequence
	validRequest := &types.StandardRequest{
		Model:     "gpt-3.5-turbo",
		MaxTokens: 100,
		Messages: []types.ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello!"},
		},
	}

	err = converter.ValidateRequest(validRequest)
	if err != nil {
		t.Errorf("Valid message sequence should pass validation in strict mode: %v", err)
	}
}

// ============================================================================
// Request Sanitization Tests
// ============================================================================

func TestSanitizeRequest(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	invalidRequest := &types.StandardRequest{
		Model:       "", // Empty model
		MaxTokens:   5000, // Above limit
		Temperature: 3.0, // Above range
		Messages: []types.ChatMessage{
			{Role: "user", Content: "Hello!"},
		},
		Metadata: nil, // Will be initialized
	}

	sanitized := converter.SanitizeRequest(invalidRequest)

	if sanitized == nil {
		t.Fatal("Sanitized request should not be nil")
	}

	// Verify model was set to default
	if sanitized.Model != "gpt-3.5-turbo" {
		t.Errorf("Expected sanitized model to be default 'gpt-3.5-turbo', got '%s'", sanitized.Model)
	}

	// Verify temperature was clamped
	if sanitized.Temperature != 2.0 {
		t.Errorf("Expected sanitized temperature to be clamped to 2.0, got %f", sanitized.Temperature)
	}

	// Verify max tokens was clamped
	if sanitized.MaxTokens != 4096 {
		t.Errorf("Expected sanitized max tokens to be clamped to 4096, got %d", sanitized.MaxTokens)
	}

	// Verify metadata was initialized
	if sanitized.Metadata == nil {
		t.Error("Sanitized metadata should be initialized")
	}

	// Verify sanitization metadata was added
	if _, exists := sanitized.Metadata["_sanitized_at"]; !exists {
		t.Error("Expected _sanitized_at metadata to be added")
	}

	if _, exists := sanitized.Metadata["_sanitizer_version"]; !exists {
		t.Error("Expected _sanitizer_version metadata to be added")
	}
}

func TestSanitizeRequestNil(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	sanitized := converter.SanitizeRequest(nil)
	if sanitized != nil {
		t.Error("Sanitizing nil request should return nil")
	}
}

// ============================================================================
// Utility Function Tests
// ============================================================================

func TestGetConversionHints(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	hints := converter.GetConversionHints()
	if len(hints) == 0 {
		t.Error("Should have conversion hints")
	}

	// Verify some expected hints are present
	expectedHints := []string{
		"Use a valid model name or configure a default model",
		"Temperature should be between 0 (deterministic) and 2 (creative)",
		"Max tokens should be reasonable for your use case",
	}

	for _, expectedHint := range expectedHints {
		found := false
		for _, hint := range hints {
			if hint == expectedHint {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected hint not found: %s", expectedHint)
		}
	}
}

func TestDebugRequest(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	// This is more of a test to ensure it doesn't panic
	// The actual output is logged, so we can't easily verify it in tests

	// Test with nil request
	converter.DebugRequest(nil) // Should not panic

	// Test with valid request
	validRequest := &types.StandardRequest{
		Model:       "gpt-3.5-turbo",
		MaxTokens:   100,
		Temperature: 0.7,
		Messages: []types.ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello!"},
		},
		Tools: []types.Tool{
			{Name: "test_tool", InputSchema: map[string]interface{}{"type": "object"}},
		},
		Stop:     []string{"END"},
		Metadata: map[string]interface{}{"user_id": "123"},
	}

	converter.DebugRequest(validRequest) // Should not panic
}

// ============================================================================
// Integration Tests - ConvertFromGenerateOptions
// ============================================================================

func TestConvertFromGenerateOptions(t *testing.T) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	generateOptions := types.GenerateOptions{
		Model:       "gpt-4",
		Messages:    []types.ChatMessage{{Role: "user", Content: "Hello!"}},
		MaxTokens:   150,
		Temperature: 0.8,
		Stream:      true,
		Stop:        []string{"STOP"},
	}

	standardReq, err := converter.ConvertFromGenerateOptions(generateOptions)
	if err != nil {
		t.Fatalf("Failed to convert from generate options: %v", err)
	}

	if standardReq.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", standardReq.Model)
	}

	if standardReq.MaxTokens != 150 {
		t.Errorf("Expected max_tokens 150, got %d", standardReq.MaxTokens)
	}

	if standardReq.Temperature != 0.8 {
		t.Errorf("Expected temperature 0.8, got %f", standardReq.Temperature)
	}

	if standardReq.Stream != true {
		t.Error("Expected stream to be true")
	}

	if len(standardReq.Stop) != 1 || standardReq.Stop[0] != "STOP" {
		t.Errorf("Expected stop sequence ['STOP'], got %v", standardReq.Stop)
	}
}

// ============================================================================
// Performance Tests
// ============================================================================

func BenchmarkConvertFromLegacy(b *testing.B) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	messageReq := &MessageRequest{
		Model:     "gpt-4",
		MaxTokens: 100,
		Temperature: 0.7,
		Stream:    false,
		System:    "You are a helpful assistant.",
		Messages: []Message{
			{Role: "user", Content: "Hello, world!"},
			{Role: "assistant", Content: "Hello! How can I help you today?"},
			{Role: "user", Content: "Tell me about the weather."},
		},
		Tools: []Tool{
			{
				Name:        "get_weather",
				Description: "Get current weather",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"location": map[string]interface{}{"type": "string"},
					},
				},
			},
		},
		StopSequences: []string{"END"},
		Metadata: map[string]interface{}{
			"user_id": "12345",
			"session_id": "sess_67890",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ConvertFromLegacy(messageReq)
		if err != nil {
			b.Fatalf("Failed to convert request: %v", err)
		}
	}
}

func BenchmarkValidateRequest(b *testing.B) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	validRequest := &types.StandardRequest{
		Messages: []types.ChatMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Hello!"},
			{Role: "assistant", Content: "Hello! How can I help you today?"},
			{Role: "user", Content: "Tell me about programming."},
		},
		Model:       "gpt-3.5-turbo",
		MaxTokens:   100,
		Temperature: 0.7,
		Stream:      false,
		Tools: []types.Tool{
			{Name: "tool1", InputSchema: map[string]interface{}{"type": "object"}},
		},
		Stop:        []string{"END", "STOP"},
		Metadata:    map[string]interface{}{"key": "value"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := converter.ValidateRequest(validRequest)
		if err != nil {
			b.Fatalf("Valid request should pass validation: %v", err)
		}
	}
}

func BenchmarkSanitizeRequest(b *testing.B) {
	converter := NewRequestConverter("gpt-3.5-turbo", 4096)

	// Create request that needs sanitization
	invalidRequest := &types.StandardRequest{
		Model:       "",
		MaxTokens:   10000,
		Temperature: -1.5,
		Messages:    []types.ChatMessage{{Role: "user", Content: "Hello!"}},
		Metadata:    nil,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = converter.SanitizeRequest(invalidRequest)
	}
}