package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// AnthropicAdapter is a passthrough adapter for Anthropic-compatible providers
// It performs minimal transformation since the format is already correct
type AnthropicAdapter struct{}

// NewAnthropicAdapter creates a new Anthropic adapter
func NewAnthropicAdapter() *AnthropicAdapter {
	return &AnthropicAdapter{}
}

// TransformRequest passes through the request with minimal validation
// Since the input is already in Anthropic format, we just return it
func (a *AnthropicAdapter) TransformRequest(anthropicReq *AnthropicRequest) (interface{}, error) {
	if anthropicReq == nil {
		return nil, fmt.Errorf("anthropic request is nil")
	}

	// Validate required fields
	if anthropicReq.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	if len(anthropicReq.Messages) == 0 {
		return nil, fmt.Errorf("messages array cannot be empty")
	}

	if anthropicReq.MaxTokens <= 0 {
		return nil, fmt.Errorf("max_tokens must be greater than 0")
	}

	// Validate messages
	for i, msg := range anthropicReq.Messages {
		if msg.Role != "user" && msg.Role != "assistant" {
			return nil, fmt.Errorf("message %d has invalid role: %s (must be 'user' or 'assistant')", i, msg.Role)
		}

		if msg.Content == nil {
			return nil, fmt.Errorf("message %d has nil content", i)
		}
	}

	// Return the request as-is for Anthropic-compatible providers
	return anthropicReq, nil
}

// TransformResponse passes through the response with minimal processing
// For Anthropic providers, the response is already in the correct format
func (a *AnthropicAdapter) TransformResponse(providerResp io.ReadCloser) (io.ReadCloser, error) {
	if providerResp == nil {
		return nil, fmt.Errorf("provider response is nil")
	}

	// For streaming responses, we can pass through directly
	// For non-streaming, we validate the structure

	// We'll do a minimal validation by reading and re-wrapping
	// This is a passthrough, so we want to minimize overhead

	// For production use, you might want to:
	// 1. Just return providerResp directly for maximum performance
	// 2. Or add optional validation based on configuration

	return a.passthroughWithValidation(providerResp)
}

// passthroughWithValidation validates the response structure but passes it through
func (a *AnthropicAdapter) passthroughWithValidation(providerResp io.ReadCloser) (io.ReadCloser, error) {
	// Read the response
	data, err := io.ReadAll(providerResp)
	providerResp.Close()

	if err != nil {
		return nil, fmt.Errorf("failed to read provider response: %w", err)
	}

	// Check if it's a streaming response (starts with "event: ")
	if len(data) > 7 && string(data[:7]) == "event: " {
		// Streaming response - pass through without validation
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	// For non-streaming, do basic JSON validation
	var response AnthropicResponse
	if err := json.Unmarshal(data, &response); err != nil {
		// If it's not a valid Anthropic response, check if it's an error response
		var errorResp map[string]interface{}
		if jsonErr := json.Unmarshal(data, &errorResp); jsonErr == nil {
			// It's valid JSON but not an Anthropic response - might be an error
			return io.NopCloser(bytes.NewReader(data)), nil
		}
		return nil, fmt.Errorf("invalid anthropic response format: %w", err)
	}

	// Validate response structure
	if response.Type != "message" {
		return nil, fmt.Errorf("invalid response type: %s (expected 'message')", response.Type)
	}

	if response.Role != "assistant" {
		return nil, fmt.Errorf("invalid response role: %s (expected 'assistant')", response.Role)
	}

	// Return the original data
	return io.NopCloser(bytes.NewReader(data)), nil
}

// CloneRequest creates a deep copy of an Anthropic request
// This is useful for retries or request modification
func CloneRequest(req *AnthropicRequest) (*AnthropicRequest, error) {
	if req == nil {
		return nil, nil
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var clone AnthropicRequest
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	return &clone, nil
}

// ValidateAnthropicRequest performs comprehensive validation on an Anthropic request
func ValidateAnthropicRequest(req *AnthropicRequest) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}

	// Required fields
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}

	if len(req.Messages) == 0 {
		return fmt.Errorf("messages array cannot be empty")
	}

	if req.MaxTokens <= 0 {
		return fmt.Errorf("max_tokens must be greater than 0")
	}

	// Validate max_tokens is reasonable (not too large)
	if req.MaxTokens > 200000 {
		return fmt.Errorf("max_tokens exceeds maximum allowed value (200000)")
	}

	// Validate messages
	hasUserMessage := false
	for i, msg := range req.Messages {
		// Validate role
		if msg.Role != "user" && msg.Role != "assistant" {
			return fmt.Errorf("message %d has invalid role: %s (must be 'user' or 'assistant')", i, msg.Role)
		}

		if msg.Role == "user" {
			hasUserMessage = true
		}

		// Validate content
		if msg.Content == nil {
			return fmt.Errorf("message %d has nil content", i)
		}

		// First message must be from user
		if i == 0 && msg.Role != "user" {
			return fmt.Errorf("first message must have role 'user'")
		}

		// Validate alternating roles (if more than one message)
		if i > 0 {
			prevRole := req.Messages[i-1].Role
			if prevRole == msg.Role {
				return fmt.Errorf("messages %d and %d have the same role: %s (roles should alternate)", i-1, i, msg.Role)
			}
		}
	}

	if !hasUserMessage {
		return fmt.Errorf("at least one message must have role 'user'")
	}

	// Validate temperature
	if req.Temperature != nil {
		if *req.Temperature < 0 || *req.Temperature > 1 {
			return fmt.Errorf("temperature must be between 0 and 1")
		}
	}

	// Validate top_p
	if req.TopP != nil {
		if *req.TopP < 0 || *req.TopP > 1 {
			return fmt.Errorf("top_p must be between 0 and 1")
		}
	}

	// Validate top_k
	if req.TopK != nil {
		if *req.TopK < 0 {
			return fmt.Errorf("top_k must be non-negative")
		}
	}

	// Validate tools
	for i, tool := range req.Tools {
		if tool.Name == "" {
			return fmt.Errorf("tool %d has empty name", i)
		}

		if tool.InputSchema == nil {
			return fmt.Errorf("tool %d (%s) has nil input_schema", i, tool.Name)
		}

		// Validate input_schema has required fields
		if schemaType, ok := tool.InputSchema["type"]; !ok || schemaType != "object" {
			return fmt.Errorf("tool %d (%s) input_schema must have type 'object'", i, tool.Name)
		}
	}

	return nil
}

// GetAdapterForProvider returns the appropriate adapter for a given provider type
func GetAdapterForProvider(providerType string) Adapter {
	switch providerType {
	case "openai":
		return NewOpenAIAdapter()
	case "anthropic":
		return NewAnthropicAdapter()
	case "azure":
		// Azure OpenAI uses OpenAI format
		return NewOpenAIAdapter()
	case "bedrock":
		// AWS Bedrock with Anthropic models uses Anthropic format
		return NewAnthropicAdapter()
	case "vertex":
		// Google Vertex AI with Anthropic models uses Anthropic format
		return NewAnthropicAdapter()
	default:
		// Default to Anthropic format for unknown providers
		return NewAnthropicAdapter()
	}
}

// SanitizeRequest removes sensitive information from a request for logging
func SanitizeRequest(req *AnthropicRequest) *AnthropicRequest {
	if req == nil {
		return nil
	}

	// Create a shallow copy
	sanitized := *req

	// Remove or redact sensitive content
	// For example, you might want to truncate long messages or remove image data
	sanitizedMessages := make([]AnthropicMessage, len(req.Messages))
	for i, msg := range req.Messages {
		sanitizedMessages[i] = msg

		// If content contains images, redact the base64 data
		if blocks, ok := msg.Content.([]ContentBlock); ok {
			sanitizedBlocks := make([]ContentBlock, len(blocks))
			for j, block := range blocks {
				sanitizedBlocks[j] = block
				if block.Type == "image" && block.Source != nil {
					sanitizedBlocks[j].Source = &ImageSource{
						Type:      block.Source.Type,
						MediaType: block.Source.MediaType,
						Data:      "[REDACTED]",
					}
				}
			}
			sanitizedMessages[i].Content = sanitizedBlocks
		}
	}

	sanitized.Messages = sanitizedMessages

	return &sanitized
}
