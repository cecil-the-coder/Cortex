package converters

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
)

// Anthropic response types (moved here to avoid import cycle)

// AnthropicResponse represents an Anthropic-compatible response
type AnthropicResponse struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Role       string         `json:"role"`
	Content    []ContentBlock `json:"content"`
	Model      string         `json:"model"`
	StopReason string         `json:"stop_reason,omitempty"`
	Usage      AnthropicUsage `json:"usage"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ContentBlock represents a content block in Anthropic format
type ContentBlock struct {
	Type string      `json:"type"`
	Text string      `json:"text,omitempty"`
}

// AnthropicUsage represents token usage in Anthropic format
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ResponseConverter handles conversion between StandardResponse and legacy formats
// It provides streaming response conversion utilities and error handling
type ResponseConverter struct {
	enableMetadata     bool
	preserveProviderInfo bool
	fallbackOnError     bool
	debugMode          bool
}

// ResponseFormat represents the target response format
type ResponseFormat string

const (
	FormatLegacy     ResponseFormat = "legacy"      // Legacy Anthropic format
	FormatOpenAI     ResponseFormat = "openai"      // OpenAI-compatible format
	FormatStandard   ResponseFormat = "standard"    // Standard format (no conversion)
	FormatStream     ResponseFormat = "stream"      // Streaming format
)

// ConversionMetrics tracks conversion performance and errors
type ConversionMetrics struct {
	TotalConversions   int64         `json:"total_conversions"`
	SuccessfulConversions int64      `json:"successful_conversions"`
	FailedConversions  int64         `json:"failed_conversions"`
	ConversionErrors   []string      `json:"conversion_errors"`
	AverageLatency     time.Duration `json:"average_latency"`
	LastConversionTime time.Time     `json:"last_conversion_time"`
}

// NewResponseConverter creates a new response converter with default settings
func NewResponseConverter() *ResponseConverter {
	return &ResponseConverter{
		enableMetadata:      true,
		preserveProviderInfo: true,
		fallbackOnError:      true,
		debugMode:           false,
	}
}

// SetMetadata enables or disables metadata preservation in conversions
func (rc *ResponseConverter) SetMetadata(enabled bool) {
	rc.enableMetadata = enabled
}

// SetProviderInfo enables or disables provider info preservation
func (rc *ResponseConverter) SetProviderInfo(enabled bool) {
	rc.preserveProviderInfo = enabled
}

// SetFallback enables or disables fallback behavior on conversion errors
func (rc *ResponseConverter) SetFallback(enabled bool) {
	rc.fallbackOnError = enabled
}

// SetDebug enables or disables debug logging
func (rc *ResponseConverter) SetDebug(enabled bool) {
	rc.debugMode = enabled
}

// ConvertFromStandard converts a StandardResponse to the specified legacy format
func (rc *ResponseConverter) ConvertFromStandard(response *types.StandardResponse, targetFormat ResponseFormat) (interface{}, error) {
	if response == nil {
		return nil, fmt.Errorf("response cannot be nil")
	}

	startTime := time.Now()
	defer func() {
		if rc.debugMode {
			log.Printf("Response conversion took: %v", time.Since(startTime))
		}
	}()

	switch targetFormat {
	case FormatLegacy:
		return rc.convertToAnthropicFormat(response)
	case FormatOpenAI:
		return rc.convertToOpenAIFormat(response)
	case FormatStandard:
		return response, nil // Already in standard format
	default:
		return nil, fmt.Errorf("unsupported target format: %s", targetFormat)
	}
}

// ConvertStreamChunk converts a StandardStreamChunk to the specified format
func (rc *ResponseConverter) ConvertStreamChunk(chunk *types.StandardStreamChunk, targetFormat ResponseFormat) (interface{}, error) {
	if chunk == nil {
		return nil, fmt.Errorf("stream chunk cannot be nil")
	}

	switch targetFormat {
	case FormatLegacy:
		return rc.convertStreamChunkToAnthropic(chunk)
	case FormatOpenAI:
		return rc.convertStreamChunkToOpenAI(chunk)
	case FormatStandard:
		return chunk, nil
	case FormatStream:
		return rc.convertToSSEFormat(chunk)
	default:
		return nil, fmt.Errorf("unsupported target format: %s", targetFormat)
	}
}

// ConvertToLegacyAnthropic converts a StandardResponse to legacy Anthropic format
func (rc *ResponseConverter) convertToAnthropicFormat(response *types.StandardResponse) (*AnthropicResponse, error) {
	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	choice := response.Choices[0]

	// Convert content blocks
	content := []ContentBlock{
		{
			Type: "text",
			Text: choice.Message.Content,
		},
	}

	// Convert usage
	usage := AnthropicUsage{
		InputTokens:  response.Usage.PromptTokens,
		OutputTokens: response.Usage.CompletionTokens,
	}

	anthropicResponse := &AnthropicResponse{
		ID:         response.ID,
		Type:       "message",
		Role:       "assistant",
		Content:    content,
		Model:      response.Model,
		StopReason: rc.convertFinishReason(choice.FinishReason),
		Usage:      usage,
	}

	// Add provider metadata if enabled
	if rc.enableMetadata && rc.preserveProviderInfo && len(response.ProviderMetadata) > 0 {
		if anthropicResponse.Metadata == nil {
			anthropicResponse.Metadata = make(map[string]interface{})
		}
		for k, v := range response.ProviderMetadata {
			anthropicResponse.Metadata[k] = v
		}
	}

	return anthropicResponse, nil
}

// ConvertToOpenAIFormat converts a StandardResponse to OpenAI-compatible format
func (rc *ResponseConverter) convertToOpenAIFormat(response *types.StandardResponse) (map[string]interface{}, error) {
	// Create OpenAI-compatible response structure
	openaiResponse := map[string]interface{}{
		"id":      response.ID,
		"object":  response.Object,
		"created": response.Created,
		"model":   response.Model,
		"choices": rc.convertChoicesToOpenAI(response.Choices),
		"usage": map[string]interface{}{
			"prompt_tokens":     int64(response.Usage.PromptTokens),
			"completion_tokens": int64(response.Usage.CompletionTokens),
			"total_tokens":      int64(response.Usage.TotalTokens),
		},
	}

	// Add provider metadata if enabled
	if rc.enableMetadata && rc.preserveProviderInfo && len(response.ProviderMetadata) > 0 {
		openaiResponse["provider_metadata"] = response.ProviderMetadata
	}

	return openaiResponse, nil
}

// ConvertStreamChunkToAnthropic converts a StandardStreamChunk to Anthropic streaming format
func (rc *ResponseConverter) convertStreamChunkToAnthropic(chunk *types.StandardStreamChunk) (map[string]interface{}, error) {
	if len(chunk.Choices) == 0 {
		return nil, fmt.Errorf("no choices in stream chunk")
	}

	choice := chunk.Choices[0]

	// Handle different streaming events based on content
	eventData := map[string]interface{}{
		"type": "content_block_delta",
		"index": 0,
	}

	if choice.Delta.Content != "" {
		eventData["type"] = "content_block_delta"
		eventData["delta"] = map[string]interface{}{
			"type": "text_delta",
			"text": choice.Delta.Content,
		}
	}

	if choice.FinishReason != "" {
		eventData = map[string]interface{}{
			"type": "content_block_stop",
			"index": 0,
		}
	}

	if chunk.Done {
		eventData = map[string]interface{}{
			"type": "message_stop",
		}
	}

	// Add usage information if available
	if chunk.Usage != nil {
		eventData["usage"] = map[string]interface{}{
			"output_tokens": int64(chunk.Usage.CompletionTokens),
		}
	}

	return eventData, nil
}

// ConvertStreamChunkToOpenAI converts a StandardStreamChunk to OpenAI streaming format
func (rc *ResponseConverter) convertStreamChunkToOpenAI(chunk *types.StandardStreamChunk) (map[string]interface{}, error) {
	openaiChunk := map[string]interface{}{
		"id":      chunk.ID,
		"object":  "chat.completion.chunk",
		"created": chunk.Created,
		"model":   chunk.Model,
		"choices": rc.convertStreamChoicesToOpenAI(chunk.Choices),
	}

	// Add usage if available (usually only on final chunk)
	if chunk.Usage != nil {
		openaiChunk["usage"] = map[string]interface{}{
			"prompt_tokens":     int64(chunk.Usage.PromptTokens),
			"completion_tokens": int64(chunk.Usage.CompletionTokens),
			"total_tokens":      int64(chunk.Usage.TotalTokens),
		}
	}

	return openaiChunk, nil
}

// ConvertToSSEFormat converts a chunk to Server-Sent Events format
func (rc *ResponseConverter) convertToSSEFormat(chunk *types.StandardStreamChunk) ([]byte, error) {
	var events []string

	// Convert to appropriate internal format first
	anthropicEvent, err := rc.convertStreamChunkToAnthropic(chunk)
	if err != nil {
		return nil, err
	}

	// Determine event type
	eventType := "content_block_delta"
	if chunk.Done {
		eventType = "message_stop"
	}

	// Build SSE event
	eventJSON, err := json.Marshal(anthropicEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	events = append(events, fmt.Sprintf("event: %s", eventType))
	events = append(events, fmt.Sprintf("data: %s", string(eventJSON)))
	events = append(events, "") // Empty line to end the event

	return []byte(strings.Join(events, "\n") + "\n"), nil
}

// convertChoicesToOpenAI converts standard choices to OpenAI format
func (rc *ResponseConverter) convertChoicesToOpenAI(choices []types.StandardChoice) []map[string]interface{} {
	openaiChoices := make([]map[string]interface{}, len(choices))

	for i, choice := range choices {
		openaiChoice := map[string]interface{}{
			"index":           choice.Index,
			"message":         rc.convertChatMessageToOpenAI(choice.Message),
			"finish_reason":   rc.convertFinishReasonToOpenAI(choice.FinishReason),
		}
		openaiChoices[i] = openaiChoice
	}

	return openaiChoices
}

// convertStreamChoicesToOpenAI converts streaming choices to OpenAI format
func (rc *ResponseConverter) convertStreamChoicesToOpenAI(choices []types.StandardStreamChoice) []map[string]interface{} {
	openaiChoices := make([]map[string]interface{}, len(choices))

	for i, choice := range choices {
		openaiChoice := map[string]interface{}{
			"index":           choice.Index,
			"delta":           rc.convertChatMessageToOpenAI(choice.Delta),
		}

		if choice.FinishReason != "" {
			openaiChoice["finish_reason"] = rc.convertFinishReasonToOpenAI(choice.FinishReason)
		}

		openaiChoices[i] = openaiChoice
	}

	return openaiChoices
}

// convertChatMessageToOpenAI converts a chat message to OpenAI format
func (rc *ResponseConverter) convertChatMessageToOpenAI(message types.ChatMessage) map[string]interface{} {
	openaiMessage := map[string]interface{}{
		"role":    message.Role,
		"content": message.Content,
	}

	// Add tool calls if present
	if len(message.ToolCalls) > 0 {
		toolCalls := make([]map[string]interface{}, len(message.ToolCalls))
		for i, tc := range message.ToolCalls {
			toolCalls[i] = map[string]interface{}{
				"id":   tc.ID,
				"type": tc.Type,
				"function": map[string]interface{}{
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				},
			}
		}
		openaiMessage["tool_calls"] = toolCalls
	}

	// Add tool call ID if present
	if message.ToolCallID != "" {
		openaiMessage["tool_call_id"] = message.ToolCallID
	}

	return openaiMessage
}

// convertFinishReason converts finish reason between formats
func (rc *ResponseConverter) convertFinishReason(reason string) string {
	switch strings.ToLower(reason) {
	case "stop", "end_turn":
		return "end_turn"
	case "length", "max_tokens":
		return "max_tokens"
	case "tool_calls", "tool_use":
		return "tool_use"
	case "content_filter":
		return "content_filter"
	default:
		return "end_turn"
	}
}

// convertFinishReasonToOpenAI converts finish reason to OpenAI format
func (rc *ResponseConverter) convertFinishReasonToOpenAI(reason string) string {
	switch strings.ToLower(reason) {
	case "stop", "end_turn":
		return "stop"
	case "length", "max_tokens":
		return "length"
	case "tool_calls", "tool_use":
		return "tool_calls"
	case "content_filter":
		return "content_filter"
	default:
		return "stop"
	}
}

// CreateStreamAdapter creates a streaming adapter that converts standard streams to legacy format
func (rc *ResponseConverter) CreateStreamAdapter(standardStream types.StandardStream, targetFormat ResponseFormat) io.Reader {
	return &StreamAdapter{
		converter:     rc,
		standardStream: standardStream,
		targetFormat:  targetFormat,
	}
}

// StreamAdapter adapts a StandardStream to different streaming formats
type StreamAdapter struct {
	converter      *ResponseConverter
	standardStream types.StandardStream
	targetFormat   ResponseFormat
	buffer         []byte
	closed         bool
}

// Read implements io.Reader for the stream adapter
func (sa *StreamAdapter) Read(p []byte) (int, error) {
	if sa.closed {
		return 0, io.EOF
	}

	// If we have buffered data, return it first
	if len(sa.buffer) > 0 {
		copied := copy(p, sa.buffer)
		sa.buffer = sa.buffer[copied:]
		return copied, nil
	}

	// Get next chunk from standard stream
	chunk, err := sa.standardStream.Next()
	if err != nil {
		if err == io.EOF {
			sa.closed = true
			return 0, io.EOF
		}
		return 0, fmt.Errorf("stream error: %w", err)
	}

	// Convert chunk to target format
	var convertedBytes []byte
	switch sa.targetFormat {
	case FormatLegacy:
		event, err := sa.converter.convertStreamChunkToAnthropic(chunk)
		if err != nil {
			return 0, fmt.Errorf("conversion error: %w", err)
		}
		convertedBytes, err = json.Marshal(event)
		if err != nil {
			return 0, fmt.Errorf("marshal error: %w", err)
		}
	case FormatStream:
		convertedBytes, err = sa.converter.convertToSSEFormat(chunk)
		if err != nil {
			return 0, fmt.Errorf("SSE conversion error: %w", err)
		}
	default:
		return 0, fmt.Errorf("unsupported stream format: %s", sa.targetFormat)
	}

	// Copy converted data to buffer and return requested amount
	sa.buffer = convertedBytes
	return sa.Read(p)
}

// ConvertLegacyResponseToStandard converts a legacy Anthropic response to StandardResponse
func (rc *ResponseConverter) ConvertLegacyResponseToStandard(anthropicResponse *AnthropicResponse) (*types.StandardResponse, error) {
	if anthropicResponse == nil {
		return nil, fmt.Errorf("anthropic response cannot be nil")
	}

	// Extract content from the first text block
	var content string
	for _, block := range anthropicResponse.Content {
		if block.Type == "text" {
			content = block.Text
			break
		}
	}

	// Create standard choice
	choice := types.StandardChoice{
		Index:        0,
		Message: types.ChatMessage{
			Role:    "assistant",
			Content: content,
		},
		FinishReason: rc.convertAnthropicFinishReason(anthropicResponse.StopReason),
	}

	// Create standard usage
	usage := types.Usage{
		PromptTokens:     anthropicResponse.Usage.InputTokens,
		CompletionTokens: anthropicResponse.Usage.OutputTokens,
		TotalTokens:      anthropicResponse.Usage.InputTokens + anthropicResponse.Usage.OutputTokens,
	}

	// Create standard response
	standardResponse := &types.StandardResponse{
		ID:      anthropicResponse.ID,
		Model:   anthropicResponse.Model,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Choices: []types.StandardChoice{choice},
		Usage:   usage,
	}

	// Add provider metadata if available
	if anthropicResponse.Metadata != nil && rc.enableMetadata {
		standardResponse.ProviderMetadata = anthropicResponse.Metadata
	}

	return standardResponse, nil
}

// convertAnthropicFinishReason converts Anthropic finish reason to standard format
func (rc *ResponseConverter) convertAnthropicFinishReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "content_filter":
		return "content_filter"
	default:
		return "stop"
	}
}

// BatchConvert converts multiple responses in batch
func (rc *ResponseConverter) BatchConvert(responses []*types.StandardResponse, targetFormat ResponseFormat) ([]interface{}, error) {
	if len(responses) == 0 {
		return nil, nil
	}

	results := make([]interface{}, len(responses))
	var errors []error

	for i, response := range responses {
		converted, err := rc.ConvertFromStandard(response, targetFormat)
		if err != nil {
			errors = append(errors, fmt.Errorf("response %d: %w", i, err))

			// Use fallback if enabled
			if rc.fallbackOnError {
				results[i] = rc.createFallbackResponse(response)
				continue
			}

			return nil, fmt.Errorf("batch conversion failed: %v", errors)
		}
		results[i] = converted
	}

	return results, nil
}

// createFallbackResponse creates a minimal fallback response when conversion fails
func (rc *ResponseConverter) createFallbackResponse(response *types.StandardResponse) map[string]interface{} {
	fallback := map[string]interface{}{
		"id":      response.ID,
		"model":   response.Model,
		"error":   "conversion_failed",
		"content": "Response conversion failed - original content preserved",
	}

	if len(response.Choices) > 0 {
		fallback["original_content"] = response.Choices[0].Message.Content
	}

	return fallback
}

// ValidateResponse validates a converted response for common issues
func (rc *ResponseConverter) ValidateResponse(response interface{}) []string {
	var issues []string

	if response == nil {
		return append(issues, "response is nil")
	}

	// Type switch to check different response formats
	switch r := response.(type) {
	case *AnthropicResponse:
		if r.ID == "" {
			issues = append(issues, "anthropic response missing ID")
		}
		if len(r.Content) == 0 {
			issues = append(issues, "anthropic response has no content")
		}
	case map[string]interface{}:
		if id, ok := r["id"].(string); !ok || id == "" {
			issues = append(issues, "response missing ID field")
		}
		if _, ok := r["choices"]; !ok {
			issues = append(issues, "response missing choices field")
		}
	case *types.StandardResponse:
		if r.ID == "" {
			issues = append(issues, "standard response missing ID")
		}
		if len(r.Choices) == 0 {
			issues = append(issues, "standard response has no choices")
		}
	default:
		issues = append(issues, fmt.Sprintf("unknown response type: %T", r))
	}

	return issues
}

// GetSupportedFormats returns the list of supported conversion formats
func (rc *ResponseConverter) GetSupportedFormats() []ResponseFormat {
	return []ResponseFormat{
		FormatLegacy,
		FormatOpenAI,
		FormatStandard,
		FormatStream,
	}
}

// GetFormatDescription returns a description of a conversion format
func (rc *ResponseConverter) GetFormatDescription(format ResponseFormat) string {
	switch format {
	case FormatLegacy:
		return "Legacy Anthropic message format with content blocks"
	case FormatOpenAI:
		return "OpenAI-compatible chat completion format"
	case FormatStandard:
		return "Standardized AI provider format (no conversion)"
	case FormatStream:
		return "Server-Sent Events (SSE) streaming format"
	default:
		return "Unknown format"
	}
}

// DebugResponse logs detailed information about a response for debugging
func (rc *ResponseConverter) DebugResponse(response interface{}) {
	if !rc.debugMode {
		return
	}

	log.Printf("DEBUG: Response {")
	log.Printf("  Type: %T", response)

	switch r := response.(type) {
	case *types.StandardResponse:
		log.Printf("  StandardResponse {")
		log.Printf("    ID: %s", r.ID)
		log.Printf("    Model: %s", r.Model)
		log.Printf("    Object: %s", r.Object)
		log.Printf("    Created: %d", r.Created)
		log.Printf("    Choices: %d", len(r.Choices))
		log.Printf("    Usage: %+v", r.Usage)
		log.Printf("    ProviderMetadata: %v", r.ProviderMetadata)
		log.Printf("  }")
	case *AnthropicResponse:
		log.Printf("  AnthropicResponse {")
		log.Printf("    ID: %s", r.ID)
		log.Printf("    Type: %s", r.Type)
		log.Printf("    Role: %s", r.Role)
		log.Printf("    Model: %s", r.Model)
		log.Printf("    StopReason: %s", r.StopReason)
		log.Printf("    Content blocks: %d", len(r.Content))
		log.Printf("    Usage: %+v", r.Usage)
		log.Printf("  }")
	case map[string]interface{}:
		log.Printf("  MapResponse {")
		for k, v := range r {
			log.Printf("    %s: %v", k, v)
		}
		log.Printf("  }")
	}

	log.Printf("}")
}