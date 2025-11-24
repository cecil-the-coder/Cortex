package converters

import (
	"bytes"
	"testing"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
)

// ============================================================================
// Basic ResponseConverter Tests
// ============================================================================

func TestNewResponseConverter(t *testing.T) {
	converter := NewResponseConverter()

	if converter == nil {
		t.Fatal("ResponseConverter should not be nil")
	}

	if !converter.enableMetadata {
		t.Error("Metadata should be enabled by default")
	}

	if !converter.preserveProviderInfo {
		t.Error("Provider info preservation should be enabled by default")
	}

	if !converter.fallbackOnError {
		t.Error("Fallback on error should be enabled by default")
	}

	if converter.debugMode {
		t.Error("Debug mode should be disabled by default")
	}
}

func TestResponseConverterConfiguration(t *testing.T) {
	converter := NewResponseConverter()

	// Test metadata setting
	converter.SetMetadata(false)
	if converter.enableMetadata {
		t.Error("Metadata should be disabled")
	}

	converter.SetMetadata(true)
	if !converter.enableMetadata {
		t.Error("Metadata should be enabled")
	}

	// Test provider info setting
	converter.SetProviderInfo(false)
	if converter.preserveProviderInfo {
		t.Error("Provider info should be disabled")
	}

	converter.SetProviderInfo(true)
	if !converter.preserveProviderInfo {
		t.Error("Provider info should be enabled")
	}

	// Test fallback setting
	converter.SetFallback(false)
	if converter.fallbackOnError {
		t.Error("Fallback should be disabled")
	}

	converter.SetFallback(true)
	if !converter.fallbackOnError {
		t.Error("Fallback should be enabled")
	}

	// Test debug setting
	converter.SetDebug(true)
	if !converter.debugMode {
		t.Error("Debug mode should be enabled")
	}

	converter.SetDebug(false)
	if converter.debugMode {
		t.Error("Debug mode should be disabled")
	}
}

func TestGetSupportedFormats(t *testing.T) {
	converter := NewResponseConverter()

	formats := converter.GetSupportedFormats()
	if len(formats) != 4 {
		t.Errorf("Expected 4 formats, got %d", len(formats))
	}

	expectedFormats := []ResponseFormat{FormatLegacy, FormatOpenAI, FormatStandard, FormatStream}
	for _, expected := range expectedFormats {
		found := false
		for _, format := range formats {
			if format == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected format %s not found", expected)
		}
	}
}

func TestGetFormatDescription(t *testing.T) {
	converter := NewResponseConverter()

	testCases := map[ResponseFormat]string{
		FormatLegacy:   "Legacy Anthropic message format with content blocks",
		FormatOpenAI:   "OpenAI-compatible chat completion format",
		FormatStandard: "Standardized AI provider format (no conversion)",
		FormatStream:   "Server-Sent Events (SSE) streaming format",
	}

	for format, expectedDesc := range testCases {
		desc := converter.GetFormatDescription(format)
		if desc != expectedDesc {
			t.Errorf("Expected description '%s' for format %s, got '%s'", expectedDesc, format, desc)
		}
	}

	// Test unknown format
	unknownDesc := converter.GetFormatDescription("unknown")
	if unknownDesc != "Unknown format" {
		t.Errorf("Expected 'Unknown format' for unknown format, got '%s'", unknownDesc)
	}
}

// ============================================================================
// Standard Response Creation Helpers
// ============================================================================

func createTestStandardResponse() *types.StandardResponse {
	return &types.StandardResponse{
		ID:      "resp_123",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4",
		Choices: []types.StandardChoice{
			{
				Index: 0,
				Message: types.ChatMessage{
					Role:    "assistant",
					Content: "Hello, world!",
				},
				FinishReason: "stop",
			},
		},
		Usage: types.Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
		ProviderMetadata: map[string]interface{}{
			"provider": "openai",
			"region":   "us-west-2",
		},
	}
}

func createTestStreamChunk() *types.StandardStreamChunk {
	return &types.StandardStreamChunk{
		ID:      "chunk_123",
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   "gpt-4",
		Choices: []types.StandardStreamChoice{
			{
				Index: 0,
				Delta: types.ChatMessage{
					Role:    "assistant",
					Content: "Hello",
				},
			},
		},
		Done: false,
	}
}

func createTestStreamChunkWithUsage() *types.StandardStreamChunk {
	return &types.StandardStreamChunk{
		ID:      "chunk_final",
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   "gpt-4",
		Choices: []types.StandardStreamChoice{
			{
				Index:        0,
				Delta:        types.ChatMessage{},
				FinishReason: "stop",
			},
		},
		Usage: &types.Usage{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
		Done: true,
	}
}

// ============================================================================
// Standard Response Conversion Tests
// ============================================================================

func TestConvertFromStandardToLegacy(t *testing.T) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	converted, err := converter.ConvertFromStandard(response, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert to legacy format: %v", err)
	}

	anthropicResponse, ok := converted.(*AnthropicResponse)
	if !ok {
		t.Fatal("Expected AnthropicResponse type")
	}

	// Verify basic conversion
	if anthropicResponse.ID != "resp_123" {
		t.Errorf("Expected ID 'resp_123', got '%s'", anthropicResponse.ID)
	}

	if anthropicResponse.Type != "message" {
		t.Errorf("Expected type 'message', got '%s'", anthropicResponse.Type)
	}

	if anthropicResponse.Role != "assistant" {
		t.Errorf("Expected role 'assistant', got '%s'", anthropicResponse.Role)
	}

	if anthropicResponse.Model != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%s'", anthropicResponse.Model)
	}

	// Verify content
	if len(anthropicResponse.Content) != 1 {
		t.Errorf("Expected 1 content block, got %d", len(anthropicResponse.Content))
	}

	contentBlock := anthropicResponse.Content[0]
	if contentBlock.Type != "text" {
		t.Errorf("Expected content block type 'text', got '%s'", contentBlock.Type)
	}

	if contentBlock.Text != "Hello, world!" {
		t.Errorf("Expected content 'Hello, world!', got '%s'", contentBlock.Text)
	}

	// Verify usage
	if anthropicResponse.Usage.InputTokens != 10 {
		t.Errorf("Expected input tokens 10, got %d", anthropicResponse.Usage.InputTokens)
	}

	if anthropicResponse.Usage.OutputTokens != 5 {
		t.Errorf("Expected output tokens 5, got %d", anthropicResponse.Usage.OutputTokens)
	}

	// Verify finish reason
	if anthropicResponse.StopReason != "end_turn" {
		t.Errorf("Expected stop reason 'end_turn', got '%s'", anthropicResponse.StopReason)
	}

	// Verify provider metadata is included
	if anthropicResponse.Metadata == nil {
		t.Error("Expected provider metadata to be included")
	}

	if anthropicResponse.Metadata["provider"] != "openai" {
		t.Errorf("Expected provider 'openai', got %v", anthropicResponse.Metadata["provider"])
	}
}

func TestConvertFromStandardToLegacyWithoutMetadata(t *testing.T) {
	converter := NewResponseConverter()
	converter.SetMetadata(false)

	response := createTestStandardResponse()

	converted, err := converter.ConvertFromStandard(response, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert to legacy format: %v", err)
	}

	anthropicResponse := converted.(*AnthropicResponse)

	if anthropicResponse.Metadata != nil {
		t.Error("Expected no metadata when metadata is disabled")
	}
}

func TestConvertFromStandardToLegacyWithoutProviderInfo(t *testing.T) {
	converter := NewResponseConverter()
	converter.SetProviderInfo(false)

	response := createTestStandardResponse()

	converted, err := converter.ConvertFromStandard(response, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert to legacy format: %v", err)
	}

	anthropicResponse := converted.(*AnthropicResponse)

	if anthropicResponse.Metadata != nil {
		t.Error("Expected no provider metadata when provider info is disabled")
	}
}

func TestConvertFromStandardToOpenAI(t *testing.T) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	converted, err := converter.ConvertFromStandard(response, FormatOpenAI)
	if err != nil {
		t.Fatalf("Failed to convert to OpenAI format: %v", err)
	}

	openaiResponse, ok := converted.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} type")
	}

	// Verify basic conversion
	if openaiResponse["id"] != "resp_123" {
		t.Errorf("Expected ID 'resp_123', got '%v'", openaiResponse["id"])
	}

	if openaiResponse["object"] != "chat.completion" {
		t.Errorf("Expected object 'chat.completion', got '%v'", openaiResponse["object"])
	}

	if openaiResponse["model"] != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%v'", openaiResponse["model"])
	}

	// Verify choices
	choices, ok := openaiResponse["choices"].([]map[string]interface{})
	if !ok || len(choices) != 1 {
		t.Fatal("Expected 1 choice")
	}

	choice := choices[0]
	if choice["index"] != 0 {
		t.Errorf("Expected choice index 0, got '%v'", choice["index"])
	}

	// Verify message
	message := choice["message"].(map[string]interface{})
	if message["role"] != "assistant" {
		t.Errorf("Expected message role 'assistant', got '%v'", message["role"])
	}

	if message["content"] != "Hello, world!" {
		t.Errorf("Expected message content 'Hello, world!', got '%v'", message["content"])
	}

	if choice["finish_reason"] != "stop" {
		t.Errorf("Expected finish reason 'stop', got '%v'", choice["finish_reason"])
	}

	// Verify usage
	usage := openaiResponse["usage"].(map[string]interface{})
	if usage["prompt_tokens"] != int64(10) {
		t.Errorf("Expected prompt tokens 10, got '%v'", usage["prompt_tokens"])
	}

	if usage["completion_tokens"] != int64(5) {
		t.Errorf("Expected completion tokens 5, got '%v'", usage["completion_tokens"])
	}

	if usage["total_tokens"] != int64(15) {
		t.Errorf("Expected total tokens 15, got '%v'", usage["total_tokens"])
	}

	// Verify provider metadata
	if openaiResponse["provider_metadata"] == nil {
		t.Error("Expected provider metadata to be included")
	}
}

func TestConvertFromStandardToStandard(t *testing.T) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	converted, err := converter.ConvertFromStandard(response, FormatStandard)
	if err != nil {
		t.Fatalf("Failed to convert to standard format: %v", err)
	}

	// Should return the same object
	if converted != response {
		t.Error("Should return the same response object for Standard format")
	}
}

func TestConvertFromStandardUnsupportedFormat(t *testing.T) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	_, err := converter.ConvertFromStandard(response, "unsupported")
	if err == nil {
		t.Error("Expected error for unsupported format")
	}

	if err.Error() != "unsupported target format: unsupported" {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}
}

func TestConvertFromStandardNilResponse(t *testing.T) {
	converter := NewResponseConverter()

	_, err := converter.ConvertFromStandard(nil, FormatLegacy)
	if err == nil {
		t.Error("Expected error for nil response")
	}
}

func TestConvertFromStandardEmptyChoices(t *testing.T) {
	converter := NewResponseConverter()

	response := &types.StandardResponse{
		ID:      "resp_123",
		Model:   "gpt-4",
		Choices: []types.StandardChoice{}, // Empty choices
	}

	_, err := converter.ConvertFromStandard(response, FormatLegacy)
	if err == nil {
		t.Error("Expected error for response with no choices")
	}

	if err.Error() != "no choices in response" {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}
}

// ============================================================================
// Streaming Chunk Conversion Tests
// ============================================================================

func TestConvertStreamChunkToLegacy(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunk()

	converted, err := converter.ConvertStreamChunk(chunk, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk to legacy format: %v", err)
	}

	eventData, ok := converted.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} type")
	}

	// Verify event structure
	if eventData["type"] != "content_block_delta" {
		t.Errorf("Expected event type 'content_block_delta', got '%v'", eventData["type"])
	}

	if eventData["index"] != 0 {
		t.Errorf("Expected event index 0, got '%v'", eventData["index"])
	}

	// Verify delta content
	delta := eventData["delta"].(map[string]interface{})
	if delta["type"] != "text_delta" {
		t.Errorf("Expected delta type 'text_delta', got '%v'", delta["type"])
	}

	if delta["text"] != "Hello" {
		t.Errorf("Expected delta text 'Hello', got '%v'", delta["text"])
	}
}

func TestConvertStreamChunkToLegacyWithFinishReason(t *testing.T) {
	converter := NewResponseConverter()

	chunk := &types.StandardStreamChunk{
		Choices: []types.StandardStreamChoice{
			{
				Index:        0,
				FinishReason: "stop",
				Delta:        types.ChatMessage{},
			},
		},
	}

	converted, err := converter.ConvertStreamChunk(chunk, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk: %v", err)
	}

	eventData := converted.(map[string]interface{})
	if eventData["type"] != "content_block_stop" {
		t.Errorf("Expected event type 'content_block_stop', got '%v'", eventData["type"])
	}
}

func TestConvertStreamChunkToLegacyDone(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunkWithUsage()

	converted, err := converter.ConvertStreamChunk(chunk, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to convert done chunk to legacy format: %v", err)
	}

	eventData := converted.(map[string]interface{})
	if eventData["type"] != "message_stop" {
		t.Errorf("Expected event type 'message_stop', got '%v'", eventData["type"])
	}

	// Verify usage is included
	usage := eventData["usage"].(map[string]interface{})
	if usage["output_tokens"] != int64(5) {
		t.Errorf("Expected output tokens 5, got '%v'", usage["output_tokens"])
	}
}

func TestConvertStreamChunkToOpenAI(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunk()

	converted, err := converter.ConvertStreamChunk(chunk, FormatOpenAI)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk to OpenAI format: %v", err)
	}

	openaiChunk, ok := converted.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map[string]interface{} type")
	}

	// Verify basic structure
	if openaiChunk["id"] != "chunk_123" {
		t.Errorf("Expected ID 'chunk_123', got '%v'", openaiChunk["id"])
	}

	if openaiChunk["object"] != "chat.completion.chunk" {
		t.Errorf("Expected object 'chat.completion.chunk', got '%v'", openaiChunk["object"])
	}

	if openaiChunk["model"] != "gpt-4" {
		t.Errorf("Expected model 'gpt-4', got '%v'", openaiChunk["model"])
	}

	// Verify choices
	choices, ok := openaiChunk["choices"].([]map[string]interface{})
	if !ok || len(choices) != 1 {
		t.Fatal("Expected 1 choice")
	}

	choice := choices[0]
	if choice["index"] != 0 {
		t.Errorf("Expected choice index 0, got '%v'", choice["index"])
	}

	// Verify delta
	delta := choice["delta"].(map[string]interface{})
	if delta["role"] != "assistant" {
		t.Errorf("Expected delta role 'assistant', got '%v'", delta["role"])
	}

	if delta["content"] != "Hello" {
		t.Errorf("Expected delta content 'Hello', got '%v'", delta["content"])
	}
}

func TestConvertStreamChunkToOpenAIWithUsage(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunkWithUsage()

	converted, err := converter.ConvertStreamChunk(chunk, FormatOpenAI)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk with usage: %v", err)
	}

	openaiChunk := converted.(map[string]interface{})

	usage, ok := openaiChunk["usage"].(map[string]interface{})
	if !ok {
		t.Error("Expected usage to be included")
		return
	}

	if usage["prompt_tokens"] != int64(10) {
		t.Errorf("Expected prompt tokens 10, got '%v'", usage["prompt_tokens"])
	}

	if usage["completion_tokens"] != int64(5) {
		t.Errorf("Expected completion tokens 5, got '%v'", usage["completion_tokens"])
	}

	if usage["total_tokens"] != int64(15) {
		t.Errorf("Expected total tokens 15, got '%v'", usage["total_tokens"])
	}
}

func TestConvertStreamChunkToStandard(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunk()

	converted, err := converter.ConvertStreamChunk(chunk, FormatStandard)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk to standard format: %v", err)
	}

	// Should return the same object
	if converted != chunk {
		t.Error("Should return the same chunk object for Standard format")
	}
}

func TestConvertStreamChunkToSSE(t *testing.T) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunk()

	converted, err := converter.ConvertStreamChunk(chunk, FormatStream)
	if err != nil {
		t.Fatalf("Failed to convert stream chunk to SSE format: %v", err)
	}

	sseData, ok := converted.([]byte)
	if !ok {
		t.Fatal("Expected []byte type")
	}

	// Verify SSE format
	if !bytes.Contains(sseData, []byte("event: content_block_delta")) {
		t.Error("Expected SSE event type")
	}

	if !bytes.Contains(sseData, []byte("data: ")) {
		t.Error("Expected SSE data")
	}

	if !bytes.Contains(sseData, []byte("\n\n")) {
		t.Error("Expected SSE event terminator")
	}

	// Verify content is properly JSON-encoded
	if !bytes.Contains(sseData, []byte("Hello")) {
		t.Error("Expected content in SSE data")
	}
}

func TestConvertStreamChunkNilChunk(t *testing.T) {
	converter := NewResponseConverter()

	_, err := converter.ConvertStreamChunk(nil, FormatLegacy)
	if err == nil {
		t.Error("Expected error for nil chunk")
	}

	if err.Error() != "stream chunk cannot be nil" {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}
}

func TestConvertStreamChunkEmptyChoices(t *testing.T) {
	converter := NewResponseConverter()

	chunk := &types.StandardStreamChunk{
		Choices: []types.StandardStreamChoice{}, // Empty choices
	}

	_, err := converter.ConvertStreamChunk(chunk, FormatLegacy)
	if err == nil {
		t.Error("Expected error for chunk with no choices")
	}

	if err.Error() != "no choices in stream chunk" {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}
}

// ============================================================================
// Response Validation Tests
// ============================================================================

func TestValidateResponseAnthropic(t *testing.T) {
	converter := NewResponseConverter()

	// Valid Anthropic response
	validResponse := &AnthropicResponse{
		ID:   "test_123",
		Type: "message",
		Content: []ContentBlock{
			{Type: "text", Text: "Hello!"},
		},
	}

	issues := converter.ValidateResponse(validResponse)
	if len(issues) > 0 {
		t.Errorf("Expected no validation issues, got %v", issues)
	}

	// Invalid Anthropic response (missing ID)
	invalidResponse := &AnthropicResponse{
		Type: "message",
		Content: []ContentBlock{
			{Type: "text", Text: "Hello!"},
		},
	}

	issues = converter.ValidateResponse(invalidResponse)
	if len(issues) == 0 {
		t.Error("Expected validation issues for missing ID")
	}

	// Invalid Anthropic response (no content)
	invalidResponse.ID = "test_123"
	invalidResponse.Content = []ContentBlock{}

	issues = converter.ValidateResponse(invalidResponse)
	if len(issues) == 0 {
		t.Error("Expected validation issues for no content")
	}
}

func TestValidateResponseMap(t *testing.T) {
	converter := NewResponseConverter()

	// Valid map response
	validResponse := map[string]interface{}{
		"id": "test_123",
		"choices": []interface{}{
			map[string]interface{}{
				"message": map[string]interface{}{
					"role": "assistant",
					"content": "Hello!",
				},
			},
		},
	}

	issues := converter.ValidateResponse(validResponse)
	if len(issues) > 0 {
		t.Errorf("Expected no validation issues, got %v", issues)
	}

	// Invalid map response (missing ID)
	invalidResponse := map[string]interface{}{
		"choices": []interface{}{},
	}

	issues = converter.ValidateResponse(invalidResponse)
	if len(issues) == 0 {
		t.Error("Expected validation issues for missing ID")
	}

	// Invalid map response (missing choices)
	invalidResponse["id"] = "test_123"
	delete(invalidResponse, "choices")

	issues = converter.ValidateResponse(invalidResponse)
	if len(issues) == 0 {
		t.Error("Expected validation issues for missing choices")
	}
}

func TestValidateResponseStandard(t *testing.T) {
	converter := NewResponseConverter()

	// Valid standard response
	validResponse := &types.StandardResponse{
		ID:    "test_123",
		Model: "gpt-4",
		Choices: []types.StandardChoice{
			{
				Message: types.ChatMessage{
					Role:    "assistant",
					Content: "Hello!",
				},
			},
		},
	}

	issues := converter.ValidateResponse(validResponse)
	if len(issues) > 0 {
		t.Errorf("Expected no validation issues, got %v", issues)
	}

	// Invalid standard response (missing ID)
	invalidResponse := &types.StandardResponse{
		Model:   "gpt-4",
		Choices: []types.StandardChoice{},
	}

	issues = converter.ValidateResponse(invalidResponse)
	if len(issues) != 2 { // Missing ID and no choices
		t.Errorf("Expected 2 validation issues, got %d", len(issues))
	}
}

func TestValidateResponseNil(t *testing.T) {
	converter := NewResponseConverter()

	issues := converter.ValidateResponse(nil)
	if len(issues) != 1 {
		t.Errorf("Expected 1 validation issue for nil response, got %d", len(issues))
	}

	if issues[0] != "response is nil" {
		t.Errorf("Expected 'response is nil' error, got '%s'", issues[0])
	}
}

func TestValidateResponseUnknownType(t *testing.T) {
	converter := NewResponseConverter()

	issues := converter.ValidateResponse("unknown type")
	if len(issues) != 1 {
		t.Errorf("Expected 1 validation issue for unknown type, got %d", len(issues))
	}

	if issues[0] != "unknown response type: string" {
		t.Errorf("Expected 'unknown response type: string' error, got '%s'", issues[0])
	}
}

// ============================================================================
// Legacy to Standard Conversion Tests
// ============================================================================

func TestConvertLegacyResponseToStandard(t *testing.T) {
	converter := NewResponseConverter()

	anthropicResponse := &AnthropicResponse{
		ID:         "msg_123",
		Type:       "message",
		Role:       "assistant",
		Content: []ContentBlock{
			{Type: "text", Text: "Hello from Anthropic!"},
		},
		Model:      "claude-3-opus",
		StopReason: "end_turn",
		Usage: AnthropicUsage{
			InputTokens:  12,
			OutputTokens: 8,
		},
		Metadata: map[string]interface{}{
			"provider": "anthropic",
		},
	}

	standardResponse, err := converter.ConvertLegacyResponseToStandard(anthropicResponse)
	if err != nil {
		t.Fatalf("Failed to convert legacy response to standard: %v", err)
	}

	// Verify basic conversion
	if standardResponse.ID != "msg_123" {
		t.Errorf("Expected ID 'msg_123', got '%s'", standardResponse.ID)
	}

	if standardResponse.Model != "claude-3-opus" {
		t.Errorf("Expected model 'claude-3-opus', got '%s'", standardResponse.Model)
	}

	if standardResponse.Object != "chat.completion" {
		t.Errorf("Expected object 'chat.completion', got '%s'", standardResponse.Object)
	}

	// Verify choices
	if len(standardResponse.Choices) != 1 {
		t.Errorf("Expected 1 choice, got %d", len(standardResponse.Choices))
	}

	choice := standardResponse.Choices[0]
	if choice.Index != 0 {
		t.Errorf("Expected choice index 0, got %d", choice.Index)
	}

	if choice.Message.Role != "assistant" {
		t.Errorf("Expected message role 'assistant', got '%s'", choice.Message.Role)
	}

	if choice.Message.Content != "Hello from Anthropic!" {
		t.Errorf("Expected message content 'Hello from Anthropic!', got '%s'", choice.Message.Content)
	}

	if choice.FinishReason != "stop" {
		t.Errorf("Expected finish reason 'stop', got '%s'", choice.FinishReason)
	}

	// Verify usage
	if standardResponse.Usage.PromptTokens != 12 {
		t.Errorf("Expected prompt tokens 12, got %d", standardResponse.Usage.PromptTokens)
	}

	if standardResponse.Usage.CompletionTokens != 8 {
		t.Errorf("Expected completion tokens 8, got %d", standardResponse.Usage.CompletionTokens)
	}

	if standardResponse.Usage.TotalTokens != 20 {
		t.Errorf("Expected total tokens 20, got %d", standardResponse.Usage.TotalTokens)
	}

	// Verify metadata
	if standardResponse.ProviderMetadata == nil {
		t.Error("Expected provider metadata to be included")
	}

	if standardResponse.ProviderMetadata["provider"] != "anthropic" {
		t.Errorf("Expected provider 'anthropic', got %v", standardResponse.ProviderMetadata["provider"])
	}
}

func TestConvertLegacyResponseToStandardNil(t *testing.T) {
	converter := NewResponseConverter()

	_, err := converter.ConvertLegacyResponseToStandard(nil)
	if err == nil {
		t.Error("Expected error for nil response")
	}

	if err.Error() != "anthropic response cannot be nil" {
		t.Errorf("Expected specific error message, got '%s'", err.Error())
	}
}

func TestConvertLegacyResponseToStandardNoContent(t *testing.T) {
	converter := NewResponseConverter()

	anthropicResponse := &AnthropicResponse{
		ID:   "msg_123",
		Type: "message",
		Content: []ContentBlock{
			{Type: "image"}, // No text block
		},
		Model: "claude-3-opus",
	}

	standardResponse, err := converter.ConvertLegacyResponseToStandard(anthropicResponse)
	if err != nil {
		t.Fatalf("Failed to convert legacy response: %v", err)
	}

	// Should have empty content
	if standardResponse.Choices[0].Message.Content != "" {
		t.Errorf("Expected empty content when no text block found, got '%s'", standardResponse.Choices[0].Message.Content)
	}
}

// ============================================================================
// Batch Conversion Tests
// ============================================================================

func TestBatchConvertValid(t *testing.T) {
	converter := NewResponseConverter()

	responses := []*types.StandardResponse{
		createTestStandardResponse(),
		createTestStandardResponse(),
	}

	results, err := converter.BatchConvert(responses, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to batch convert: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	for i, result := range results {
		if _, ok := result.(*AnthropicResponse); !ok {
			t.Errorf("Expected AnthropicResponse result at index %d, got %T", i, result)
		}
	}
}

func TestBatchConvertEmpty(t *testing.T) {
	converter := NewResponseConverter()

	results, err := converter.BatchConvert([]*types.StandardResponse{}, FormatLegacy)
	if err != nil {
		t.Fatalf("Failed to batch convert empty list: %v", err)
	}

	if results != nil {
		t.Error("Expected nil results for empty list")
	}
}

func TestBatchConvertWithFallback(t *testing.T) {
	converter := NewResponseConverter()

	// Create one valid and one invalid response
	responses := []*types.StandardResponse{
		createTestStandardResponse(),
		{
			ID:      "invalid",
			Model:   "invalid",
			Choices: []types.StandardChoice{}, // Invalid - no choices
		},
	}

	results, err := converter.BatchConvert(responses, FormatLegacy)
	if err != nil {
		t.Fatalf("Expected batch convert to succeed with fallback, got error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	// First should be valid conversion
	if _, ok := results[0].(*AnthropicResponse); !ok {
		t.Error("First result should be valid AnthropometricResponse")
	}

	// Second should be fallback response
	if fallback, ok := results[1].(map[string]interface{}); !ok {
		t.Error("Second result should be fallback map")
	} else {
		if fallback["error"] != "conversion_failed" {
			t.Error("Expected error field in fallback response")
		}
	}
}

func TestBatchConvertWithoutFallback(t *testing.T) {
	converter := NewResponseConverter()
	converter.SetFallback(false) // Disable fallback

	responses := []*types.StandardResponse{
		{
			ID:      "invalid",
			Model:   "invalid",
			Choices: []types.StandardChoice{}, // Invalid - no choices
		},
	}

	_, err := converter.BatchConvert(responses, FormatLegacy)
	if err == nil {
		t.Error("Expected error when fallback is disabled and conversion fails")
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestConvertFinishReason(t *testing.T) {
	converter := NewResponseConverter()

	testCases := map[string]string{
		"stop":        "end_turn",
		"end_turn":    "end_turn",
		"length":      "max_tokens",
		"max_tokens":  "max_tokens",
		"tool_calls":  "tool_use",
		"tool_use":    "tool_use",
		"content_filter": "content_filter",
		"unknown":     "end_turn",
	}

	for input, expected := range testCases {
		result := converter.convertFinishReason(input)
		if result != expected {
			t.Errorf("Expected finish reason '%s' for input '%s', got '%s'", expected, input, result)
		}
	}
}

func TestConvertFinishReasonToOpenAI(t *testing.T) {
	converter := NewResponseConverter()

	testCases := map[string]string{
		"stop":        "stop",
		"end_turn":    "stop",
		"length":      "length",
		"max_tokens":  "length",
		"tool_calls":  "tool_calls",
		"tool_use":    "tool_calls",
		"content_filter": "content_filter",
		"unknown":     "stop",
	}

	for input, expected := range testCases {
		result := converter.convertFinishReasonToOpenAI(input)
		if result != expected {
			t.Errorf("Expected OpenAI finish reason '%s' for input '%s', got '%s'", expected, input, result)
		}
	}
}

// ============================================================================
// Debug Tests
// ============================================================================

func TestDebugResponse(t *testing.T) {
	converter := NewResponseConverter()

	// Test with debug disabled (should not panic)
	converter.SetDebug(false)
	converter.DebugResponse(createTestStandardResponse())
	converter.DebugResponse(&AnthropicResponse{})
	converter.DebugResponse(map[string]interface{}{})

	// Test with debug enabled (should not panic)
	converter.SetDebug(true)
	converter.DebugResponse(createTestStandardResponse())
	converter.DebugResponse(&AnthropicResponse{})
	converter.DebugResponse(map[string]interface{}{})
}

// ============================================================================
// Performance Tests
// ============================================================================

func BenchmarkConvertFromStandard(b *testing.B) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ConvertFromStandard(response, FormatLegacy)
		if err != nil {
			b.Fatalf("Failed to convert: %v", err)
		}
	}
}

func BenchmarkConvertStreamChunk(b *testing.B) {
	converter := NewResponseConverter()
	chunk := createTestStreamChunk()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ConvertStreamChunk(chunk, FormatOpenAI)
		if err != nil {
			b.Fatalf("Failed to convert chunk: %v", err)
		}
	}
}

func BenchmarkConvertLegacyResponseToStandard(b *testing.B) {
	converter := NewResponseConverter()
	anthropicResponse := &AnthropicResponse{
		ID:   "msg_123",
		Type: "message",
		Content: []ContentBlock{
			{Type: "text", Text: "Hello from Anthropic!"},
		},
		Model:      "claude-3-opus",
		StopReason: "end_turn",
		Usage: AnthropicUsage{
			InputTokens:  12,
			OutputTokens: 8,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := converter.ConvertLegacyResponseToStandard(anthropicResponse)
		if err != nil {
			b.Fatalf("Failed to convert legacy response: %v", err)
		}
	}
}

func BenchmarkValidateResponse(b *testing.B) {
	converter := NewResponseConverter()
	response := createTestStandardResponse()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = converter.ValidateResponse(response)
	}
}

