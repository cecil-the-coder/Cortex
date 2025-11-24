package providers

import (
	"io"
)

// Adapter defines the interface for transforming requests and responses
// between different LLM provider formats
type Adapter interface {
	// TransformRequest converts an Anthropic-format request to the provider's format
	TransformRequest(anthropicReq *AnthropicRequest) (interface{}, error)

	// TransformResponse converts the provider's response back to Anthropic format
	TransformResponse(providerResp io.ReadCloser) (io.ReadCloser, error)
}

// AnthropicRequest represents the Anthropic API request format
type AnthropicRequest struct {
	Model         string              `json:"model"`
	Messages      []AnthropicMessage  `json:"messages"`
	MaxTokens     int                 `json:"max_tokens"`
	System        interface{}         `json:"system,omitempty"` // Can be string or []SystemBlock
	Temperature   *float64            `json:"temperature,omitempty"`
	TopP          *float64            `json:"top_p,omitempty"`
	TopK          *int                `json:"top_k,omitempty"`
	StopSequences []string            `json:"stop_sequences,omitempty"`
	Stream        bool                `json:"stream,omitempty"`
	Tools         []AnthropicTool     `json:"tools,omitempty"`
	ToolChoice    interface{}         `json:"tool_choice,omitempty"` // Can be string or object
	Metadata      *RequestMetadata    `json:"metadata,omitempty"`
}

// AnthropicMessage represents a message in Anthropic format
type AnthropicMessage struct {
	Role    string                   `json:"role"` // "user" or "assistant"
	Content interface{}              `json:"content"` // Can be string or []ContentBlock
}

// ContentBlock represents different types of content in Anthropic messages
type ContentBlock struct {
	Type   string      `json:"type"` // "text", "image", "tool_use", "tool_result"
	Text   string      `json:"text,omitempty"`
	Source *ImageSource `json:"source,omitempty"`

	// Tool use fields
	ID    string      `json:"id,omitempty"`
	Name  string      `json:"name,omitempty"`
	Input interface{} `json:"input,omitempty"`

	// Tool result fields
	ToolUseID string      `json:"tool_use_id,omitempty"`
	Content   interface{} `json:"content,omitempty"` // Can be string or []ContentBlock
	IsError   bool        `json:"is_error,omitempty"`
}

// ImageSource represents an image in Anthropic format
type ImageSource struct {
	Type      string `json:"type"` // "base64"
	MediaType string `json:"media_type"` // "image/jpeg", "image/png", etc.
	Data      string `json:"data"` // base64-encoded image data
}

// SystemBlock represents a system message block
type SystemBlock struct {
	Type  string `json:"type"` // "text"
	Text  string `json:"text"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

// CacheControl represents prompt caching configuration
type CacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

// AnthropicTool represents a tool definition in Anthropic format
type AnthropicTool struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	InputSchema  map[string]interface{} `json:"input_schema"`
	CacheControl *CacheControl          `json:"cache_control,omitempty"`
}

// RequestMetadata contains additional request metadata
type RequestMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

// AnthropicResponse represents the Anthropic API response format
type AnthropicResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"` // "message"
	Role         string                  `json:"role"` // "assistant"
	Content      []ContentBlock          `json:"content"`
	Model        string                  `json:"model"`
	StopReason   string                  `json:"stop_reason,omitempty"` // "end_turn", "max_tokens", "stop_sequence", "tool_use"
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage          `json:"usage"`
}

// AnthropicUsage represents token usage information
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// StreamEvent represents a server-sent event in Anthropic streaming format
type StreamEvent struct {
	Type  string      `json:"type"`
	Index int         `json:"index,omitempty"`
	Delta interface{} `json:"delta,omitempty"`

	// For message_start event
	Message *AnthropicResponse `json:"message,omitempty"`

	// For content_block_start event
	ContentBlock *ContentBlock `json:"content_block,omitempty"`

	// For message_delta event
	Usage *AnthropicUsage `json:"usage,omitempty"`

	// Common fields
	StopReason   string `json:"stop_reason,omitempty"`
	StopSequence string `json:"stop_sequence,omitempty"`
}

// TextDelta represents incremental text in streaming
type TextDelta struct {
	Type string `json:"type"` // "text_delta"
	Text string `json:"text"`
}

// InputJSONDelta represents incremental tool input in streaming
type InputJSONDelta struct {
	Type        string `json:"type"` // "input_json_delta"
	PartialJSON string `json:"partial_json"`
}
