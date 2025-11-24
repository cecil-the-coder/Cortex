package converters

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
)

// MessageRequest represents the Anthropic-compatible request (moved here to avoid import cycle)
type MessageRequest struct {
	Model         string                 `json:"model"`
	Messages      []Message              `json:"messages"`
	MaxTokens     int                    `json:"max_tokens"`
	Temperature   float64                `json:"temperature,omitempty"`
	TopP          float64                `json:"top_p,omitempty"`
	TopK          int                    `json:"top_k,omitempty"`
	Stream        bool                   `json:"stream,omitempty"`
	StopSequences []string               `json:"stop_sequences,omitempty"`
	System        string                 `json:"system,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Tools         []Tool                 `json:"tools,omitempty"`
}

// Message represents a chat message
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// Tool represents a tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema,omitempty"`
}

// RequestConverter handles conversion between legacy GenerateOptions and StandardRequest
// It provides validation, error handling, and transformation utilities
type RequestConverter struct {
	defaultModel    string
	maxTokensLimit  int
	strictMode      bool
	validationRules []ValidationRule
}

// ValidationRule defines a custom validation rule for requests
type ValidationRule struct {
	Name        string
	Description string
	Validate    func(types.StandardRequest) error
}

// ConversionError represents an error that occurred during request conversion
type ConversionError struct {
	Message    string
	Field      string
	Value      interface{}
	Suggestion string
}

func (e *ConversionError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("%s (field: %s, value: %v, suggestion: %s)", e.Message, e.Field, e.Value, e.Suggestion)
	}
	return fmt.Sprintf("%s (field: %s, value: %v)", e.Message, e.Field, e.Value)
}

// NewRequestConverter creates a new request converter with default settings
func NewRequestConverter(defaultModel string, maxTokensLimit int) *RequestConverter {
	converter := &RequestConverter{
		defaultModel:   defaultModel,
		maxTokensLimit: maxTokensLimit,
		strictMode:     false,
		validationRules: []ValidationRule{
			{
				Name:        "required_messages",
				Description: "At least one message is required",
				Validate:    validateRequiredMessages,
			},
			{
				Name:        "temperature_range",
				Description: "Temperature must be between 0 and 2",
				Validate:    validateTemperatureRange,
			},
			{
				Name:        "max_tokens_positive",
				Description: "Max tokens must be positive",
				Validate:    validateMaxTokensPositive,
			},
			{
				Name:        "tool_choice_consistency",
				Description: "Tool choice requires tools to be provided",
				Validate:    validateToolChoiceConsistency,
			},
		},
	}

	// Add more strict validation rules if strict mode is enabled
	if converter.strictMode {
		converter.validationRules = append(converter.validationRules,
			ValidationRule{
				Name:        "message_role_sequence",
				Description: "Messages must follow proper role sequence",
				Validate:    validateMessageRoleSequence,
			},
			ValidationRule{
				Name:        "content_length",
				Description: "Content length must be reasonable",
				Validate:    validateContentLength,
			},
		)
	}

	return converter
}

// SetStrictMode enables or disables strict validation mode
func (rc *RequestConverter) SetStrictMode(strict bool) {
	rc.strictMode = strict

	// Rebuild validation rules based on strict mode
	if strict {
		rc.validationRules = append(rc.validationRules,
			ValidationRule{
				Name:        "message_role_sequence",
				Description: "Messages must follow proper role sequence",
				Validate:    validateMessageRoleSequence,
			},
			ValidationRule{
				Name:        "content_length",
				Description: "Content length must be reasonable",
				Validate:    validateContentLength,
			},
		)
	}
}

// AddValidationRule adds a custom validation rule
func (rc *RequestConverter) AddValidationRule(rule ValidationRule) {
	rc.validationRules = append(rc.validationRules, rule)
}

// ConvertFromLegacy converts a legacy MessageRequest to StandardRequest
func (rc *RequestConverter) ConvertFromLegacy(messageReq *MessageRequest) (*types.StandardRequest, error) {
	if messageReq == nil {
		return nil, &ConversionError{
			Message: "message request cannot be nil",
			Field:   "request",
		}
	}

	// Convert messages
	messages, err := rc.convertMessages(messageReq.Messages, messageReq.System)
	if err != nil {
		return nil, fmt.Errorf("failed to convert messages: %w", err)
	}

	// Convert tools
	tools, err := rc.convertTools(messageReq.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tools: %w", err)
	}

	// Convert tool choice
	toolChoice, err := rc.convertToolChoice(messageReq.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tool choice: %w", err)
	}

	// Build standard request
	request := &types.StandardRequest{
		Messages:       messages,
		Model:          rc.resolveModel(messageReq.Model),
		MaxTokens:      rc.resolveMaxTokens(messageReq.MaxTokens),
		Temperature:    messageReq.Temperature,
		Stop:           messageReq.StopSequences,
		Stream:         messageReq.Stream,
		Tools:          tools,
		ToolChoice:     toolChoice,
		Timeout:        0, // Will be set by caller if needed
		Metadata:       rc.convertMetadata(messageReq.Metadata),
	}

	// Validate the converted request
	if err := rc.ValidateRequest(request); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return request, nil
}

// ConvertFromGenerateOptions converts legacy GenerateOptions to StandardRequest
func (rc *RequestConverter) ConvertFromGenerateOptions(options types.GenerateOptions) (*types.StandardRequest, error) {
	request, err := types.NewCoreRequestBuilder().
		FromGenerateOptions(options).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build standard request from generate options: %w", err)
	}

	// Apply additional validation
	if err := rc.ValidateRequest(request); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return request, nil
}

// ValidateRequest validates a StandardRequest using configured rules
func (rc *RequestConverter) ValidateRequest(request *types.StandardRequest) error {
	if request == nil {
		return &ConversionError{
			Message: "request cannot be nil",
			Field:   "request",
		}
	}

	for _, rule := range rc.validationRules {
		if err := rule.Validate(*request); err != nil {
			return fmt.Errorf("validation rule '%s' failed: %w", rule.Name, err)
		}
	}

	return nil
}

// convertMessages converts legacy messages to standard chat messages
func (rc *RequestConverter) convertMessages(legacyMessages []Message, systemPrompt string) ([]types.ChatMessage, error) {
	var messages []types.ChatMessage

	// Add system message if provided
	if systemPrompt != "" {
		messages = append(messages, types.ChatMessage{
			Role:    "system",
			Content: systemPrompt,
		})
	}

	for i, msg := range legacyMessages {
		content, err := rc.extractMessageContent(msg.Content)
		if err != nil {
			return nil, &ConversionError{
				Message:    fmt.Sprintf("failed to extract content from message %d", i),
				Field:      fmt.Sprintf("messages[%d].content", i),
				Value:      msg.Content,
				Suggestion: "Ensure content is a string or valid content structure",
			}
		}

		chatMsg := types.ChatMessage{
			Role:    msg.Role,
			Content: content,
		}

		// Handle tool calls in assistant messages
		if msg.Role == "assistant" {
			toolCalls := rc.extractToolCalls(msg.Content)
			if len(toolCalls) > 0 {
				chatMsg.ToolCalls = toolCalls
			}
		}

		// Handle tool results
		if msg.Role == "user" {
			if toolCallID := rc.extractToolCallID(msg.Content); toolCallID != "" {
				chatMsg.Role = "tool"
				chatMsg.ToolCallID = toolCallID
			}
		}

		messages = append(messages, chatMsg)
	}

	return messages, nil
}

// convertTools converts legacy tools to standard tools
func (rc *RequestConverter) convertTools(legacyTools []Tool) ([]types.Tool, error) {
	if len(legacyTools) == 0 {
		return nil, nil
	}

	tools := make([]types.Tool, len(legacyTools))
	for i, t := range legacyTools {
		tools[i] = types.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		}

		// Validate tool structure
		if t.Name == "" {
			return nil, &ConversionError{
				Message:    "tool name cannot be empty",
				Field:      fmt.Sprintf("tools[%d].name", i),
				Value:      t.Name,
				Suggestion: "Provide a valid tool name",
			}
		}

		if t.InputSchema == nil {
			return nil, &ConversionError{
				Message:    "tool input schema cannot be nil",
				Field:      fmt.Sprintf("tools[%d].input_schema", i),
				Value:      t.InputSchema,
				Suggestion: "Provide a valid JSON schema for the tool input",
			}
		}
	}

	return tools, nil
}

// convertToolChoice determines the appropriate tool choice based on tools provided
func (rc *RequestConverter) convertToolChoice(legacyTools []Tool) (*types.ToolChoice, error) {
	if len(legacyTools) == 0 {
		return nil, nil
	}

	// Default to auto mode when tools are provided
	return &types.ToolChoice{
		Mode: types.ToolChoiceAuto,
	}, nil
}

// resolveModel resolves the model to use, applying defaults if necessary
func (rc *RequestConverter) resolveModel(model string) string {
	if model == "" {
		if rc.defaultModel != "" {
			log.Printf("Using default model: %s", rc.defaultModel)
			return rc.defaultModel
		}
		return "gpt-3.5-turbo" // Fallback default
	}
	return model
}

// resolveMaxTokens resolves the max tokens to use, applying limits if necessary
func (rc *RequestConverter) resolveMaxTokens(maxTokens int) int {
	if maxTokens <= 0 {
		return 1000 // Default if not specified
	}

	// Always clamp to maxTokensLimit if it's set
	if rc.maxTokensLimit > 0 {
		if maxTokens > rc.maxTokensLimit {
			log.Printf("Clamping max_tokens from %d to limit %d", maxTokens, rc.maxTokensLimit)
			return rc.maxTokensLimit
		}
	}

	return maxTokens
}

// convertMetadata converts legacy metadata to standard metadata
func (rc *RequestConverter) convertMetadata(legacyMetadata map[string]interface{}) map[string]interface{} {
	if legacyMetadata == nil {
		return make(map[string]interface{})
	}

	metadata := make(map[string]interface{})
	for k, v := range legacyMetadata {
		metadata[k] = v
	}

	// Add conversion metadata
	metadata["_converted_at"] = time.Now().Unix()
	metadata["_converter_version"] = "1.0"

	return metadata
}

// extractMessageContent extracts string content from various message content formats
func (rc *RequestConverter) extractMessageContent(content interface{}) (string, error) {
	switch c := content.(type) {
	case string:
		return c, nil
	case []interface{}:
		// Extract text from content blocks (Anthropic format)
		var text strings.Builder
		for _, block := range c {
			if blockMap, ok := block.(map[string]interface{}); ok {
				if blockType, ok := blockMap["type"].(string); ok {
					if blockType == "text" {
						if t, ok := blockMap["text"].(string); ok {
							text.WriteString(t)
						}
					} else if blockType == "tool_result" {
						// Extract content from tool_result blocks
						if content, ok := blockMap["content"].(string); ok {
							text.WriteString(content)
						}
					}
				}
			}
		}
		// If we have tool_use blocks but no text blocks, that's valid for tool calls
		result := text.String()
		if result == "" {
			// Check if this is a tool-only message (no text content, only tool_use)
			hasToolUse := false
			for _, block := range c {
				if blockMap, ok := block.(map[string]interface{}); ok {
					if blockType, ok := blockMap["type"].(string); ok && blockType == "tool_use" {
						hasToolUse = true
						break
					}
				}
			}
			if hasToolUse {
				return "", nil // Empty content is fine for tool-only messages
			}

			return "", &ConversionError{
				Message:    "no text content found in content blocks",
				Field:      "content",
				Value:      content,
				Suggestion: "Include at least one text block in the content array or tool_use blocks for tool calls",
			}
		}
		return result, nil
	default:
		// Try to marshal as JSON and use as string content
		return fmt.Sprintf("%v", c), nil
	}
}

// extractToolCalls extracts tool calls from message content
func (rc *RequestConverter) extractToolCalls(content interface{}) []types.ToolCall {
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

		if blockType, ok := blockMap["type"].(string); ok && blockType == "tool_use" {
			var args string
			if input, ok := blockMap["input"]; ok {
				if argsBytes, err := json.Marshal(input); err == nil {
					args = string(argsBytes)
				} else {
					args = fmt.Sprintf("%v", input)
				}
			}

			toolCall := types.ToolCall{
				ID:   getStringValue(blockMap, "id"),
				Type: "function",
				Function: types.ToolCallFunction{
					Name:      getStringValue(blockMap, "name"),
					Arguments: args,
				},
			}
			toolCalls = append(toolCalls, toolCall)
		}
	}

	return toolCalls
}

// extractToolCallID extracts tool call ID from message content
func (rc *RequestConverter) extractToolCallID(content interface{}) string {
	blocks, ok := content.([]interface{})
	if !ok {
		return ""
	}

	for _, block := range blocks {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}

		if blockType, ok := blockMap["type"].(string); ok && blockType == "tool_result" {
			return getStringValue(blockMap, "tool_use_id")
		}
	}

	return ""
}


// Validation rule implementations

func validateRequiredMessages(request types.StandardRequest) error {
	if len(request.Messages) == 0 {
		return &ConversionError{
			Message:    "at least one message is required",
			Field:      "messages",
			Suggestion: "Add at least one message to the request",
		}
	}
	return nil
}

func validateTemperatureRange(request types.StandardRequest) error {
	if request.Temperature < 0 || request.Temperature > 2 {
		return &ConversionError{
			Message:    "temperature must be between 0 and 2",
			Field:      "temperature",
			Value:      request.Temperature,
			Suggestion: "Set temperature to a value between 0 (more deterministic) and 2 (more creative)",
		}
	}
	return nil
}

func validateMaxTokensPositive(request types.StandardRequest) error {
	if request.MaxTokens < 0 {
		return &ConversionError{
			Message:    "max_tokens must be non-negative",
			Field:      "max_tokens",
			Value:      request.MaxTokens,
			Suggestion: "Set max_tokens to a positive integer or 0 for default",
		}
	}
	return nil
}

func validateToolChoiceConsistency(request types.StandardRequest) error {
	if request.ToolChoice != nil && len(request.Tools) == 0 {
		return &ConversionError{
			Message:    "tool_choice specified but no tools provided",
			Field:      "tool_choice",
			Value:      request.ToolChoice,
			Suggestion: "Provide tools in the request or remove tool_choice",
		}
	}
	return nil
}

func validateMessageRoleSequence(request types.StandardRequest) error {
	if len(request.Messages) < 2 {
		return nil // Not enough messages to validate sequence
	}

	// Check for proper role sequence (should alternate appropriately)
	for i := 0; i < len(request.Messages); i++ {
		currRole := request.Messages[i].Role

		// System messages should only appear at the beginning (position 0)
		if currRole == "system" && i > 0 {
			return &ConversionError{
				Message:    "system message should only appear at the beginning",
				Field:      fmt.Sprintf("messages[%d].role", i),
				Value:      currRole,
				Suggestion: "Move system message to the beginning of the conversation",
			}
		}

		// Tool messages should follow assistant messages
		if currRole == "tool" && (i == 0 || request.Messages[i-1].Role != "assistant") {
			return &ConversionError{
				Message:    "tool message should follow assistant message with tool calls",
				Field:      fmt.Sprintf("messages[%d].role", i),
				Value:      currRole,
				Suggestion: "Ensure tool messages come after appropriate assistant messages",
			}
		}
	}

	return nil
}

func validateContentLength(request types.StandardRequest) error {
	maxContentLength := 100000 // 100k characters limit

	for i, msg := range request.Messages {
		if len(msg.Content) > maxContentLength {
			return &ConversionError{
				Message:    "message content too long",
				Field:      fmt.Sprintf("messages[%d].content", i),
				Value:      len(msg.Content),
				Suggestion: fmt.Sprintf("Reduce content length to under %d characters", maxContentLength),
			}
		}
	}

	return nil
}

// SanitizeRequest sanitizes a request by removing or fixing common issues
func (rc *RequestConverter) SanitizeRequest(request *types.StandardRequest) *types.StandardRequest {
	if request == nil {
		return nil
	}

	// Create a copy to avoid modifying the original
	sanitized := *request

	// Ensure model is set
	if sanitized.Model == "" {
		sanitized.Model = rc.resolveModel("")
	}

	// Ensure reasonable temperature
	if sanitized.Temperature < 0 {
		sanitized.Temperature = 0
	} else if sanitized.Temperature > 2 {
		sanitized.Temperature = 2
	}

	// Ensure reasonable max tokens
	sanitized.MaxTokens = rc.resolveMaxTokens(sanitized.MaxTokens)

	// Initialize metadata if nil
	if sanitized.Metadata == nil {
		sanitized.Metadata = make(map[string]interface{})
	}

	// Add sanitization metadata
	sanitized.Metadata["_sanitized_at"] = time.Now().Unix()
	sanitized.Metadata["_sanitizer_version"] = "1.0"

	return &sanitized
}

// GetConversionHints returns hints for common conversion issues
func (rc *RequestConverter) GetConversionHints() []string {
	return []string{
		"Use a valid model name or configure a default model",
		"Temperature should be between 0 (deterministic) and 2 (creative)",
		"Max tokens should be reasonable for your use case",
		"Messages should follow proper conversational flow",
		"Provide input schemas for all tools",
		"Include tool choice only when tools are provided",
		"Keep content length reasonable to avoid rate limits",
	}
}

// DebugRequest logs detailed information about a request for debugging
func (rc *RequestConverter) DebugRequest(request *types.StandardRequest) {
	if request == nil {
		log.Printf("DEBUG: Request is nil")
		return
	}

	log.Printf("DEBUG: StandardRequest {")
	log.Printf("  Model: %s", request.Model)
	log.Printf("  MaxTokens: %d", request.MaxTokens)
	log.Printf("  Temperature: %.2f", request.Temperature)
	log.Printf("  Stream: %t", request.Stream)
	log.Printf("  Messages: %d", len(request.Messages))
	log.Printf("  Tools: %d", len(request.Tools))
	log.Printf("  ToolChoice: %v", request.ToolChoice)
	log.Printf("  Stop: %v", request.Stop)
	log.Printf("  Metadata keys: %v", getMapKeys(request.Metadata))

	for i, msg := range request.Messages {
		log.Printf("  Message[%d]: Role=%s, ContentLength=%d", i, msg.Role, len(msg.Content))
		if len(msg.ToolCalls) > 0 {
			log.Printf("    ToolCalls: %d", len(msg.ToolCalls))
		}
	}

	log.Printf("}")
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// getStringValue extracts a string value from a map with the given key
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
		return fmt.Sprintf("%v", val)
	}
	return ""
}