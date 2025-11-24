package server

import "time"

// OpenAI Chat Request Types

// OpenAIChatRequest represents an OpenAI chat completion request
type OpenAIChatRequest struct {
	Model            string             `json:"model"`
	Messages         []OpenAIMessage    `json:"messages"`
	MaxTokens        *int               `json:"max_tokens,omitempty"`
	Temperature      *float64           `json:"temperature,omitempty"`
	TopP             *float64           `json:"top_p,omitempty"`
	N                *int               `json:"n,omitempty"`
	Stream           bool               `json:"stream,omitempty"`
	Stop             interface{}        `json:"stop,omitempty"`
	PresencePenalty  *float64           `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64           `json:"frequency_penalty,omitempty"`
	LogitBias        map[string]int     `json:"logit_bias,omitempty"`
	User             string             `json:"user,omitempty"`
	Tools            []OpenAIToolDef    `json:"tools,omitempty"`
	ToolChoice       interface{}        `json:"tool_choice,omitempty"`
	ResponseFormat   *OpenAIResponseFormat `json:"response_format,omitempty"`
}

// OpenAIMessage represents a message in OpenAI format
type OpenAIMessage struct {
	Role       string      `json:"role"`
	Content    interface{} `json:"content"`
	Name       string      `json:"name,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

// OpenAIToolDef represents a tool definition in OpenAI format
type OpenAIToolDef struct {
	Type     string              `json:"type"`
	Function OpenAIFunctionDef   `json:"function"`
}

// OpenAIFunctionDef represents a function definition in OpenAI format
type OpenAIFunctionDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ToolCall represents a tool call in OpenAI format
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall represents a function call in OpenAI format
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// OpenAIResponseFormat represents response format options
type OpenAIResponseFormat struct {
	Type       string                 `json:"type"`
	JsonSchema map[string]interface{} `json:"json_schema,omitempty"`
}

// OpenAI Chat Response Types

// OpenAIChatResponse represents an OpenAI chat completion response
type OpenAIChatResponse struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	Choices           []OpenAIChoice `json:"choices"`
	Usage             OpenAIUsage    `json:"usage"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
}

// OpenAIChoice represents a choice in OpenAI response
type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
	LogProbs     interface{}   `json:"logprobs,omitempty"`
}

// OpenAIUsage represents token usage in OpenAI format
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAI Streaming Types

// OpenAIStreamChunk represents a chunk in OpenAI streaming format
type OpenAIStreamChunk struct {
	ID                string               `json:"id"`
	Object            string               `json:"object"`
	Created           int64                `json:"created"`
	Model             string               `json:"model"`
	Choices           []OpenAIStreamChoice `json:"choices"`
	SystemFingerprint string               `json:"system_fingerprint,omitempty"`
}

// OpenAIStreamChoice represents a choice in OpenAI streaming format
type OpenAIStreamChoice struct {
	Index        int                 `json:"index"`
	Delta        OpenAIMessageDelta  `json:"delta"`
	FinishReason *string             `json:"finish_reason"`
	LogProbs     interface{}         `json:"logprobs,omitempty"`
}

// OpenAIMessageDelta represents a message delta in streaming
type OpenAIMessageDelta struct {
	Role      string     `json:"role,omitempty"`
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Models Endpoint Types

// ModelsResponse represents the response from /v1/models endpoint
type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

// ModelInfo represents a model in the models list response
type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// Error Response Types

// OpenAIErrorResponse represents an error response in OpenAI format
type OpenAIErrorResponse struct {
	Error OpenAIError `json:"error"`
}

// OpenAIError represents an error in OpenAI format
type OpenAIError struct {
	Message string      `json:"message"`
	Type    string      `json:"type"`
	Param   interface{} `json:"param"`
	Code    interface{} `json:"code"`
}

// Helper functions for creating responses

// NewOpenAIChatResponse creates a new OpenAI chat response
func NewOpenAIChatResponse(model, content string, usage OpenAIUsage) *OpenAIChatResponse {
	return &OpenAIChatResponse{
		ID:      generateOpenAIResponseID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []OpenAIChoice{
			{
				Index: 0,
				Message: OpenAIMessage{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: "stop",
			},
		},
		Usage: usage,
	}
}

// NewOpenAIStreamChunk creates a new OpenAI stream chunk
func NewOpenAIStreamChunk(model string, responseID string, created int64) *OpenAIStreamChunk {
	return &OpenAIStreamChunk{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []OpenAIStreamChoice{},
	}
}

// NewOpenAIStreamChunkWithContent creates a new OpenAI stream chunk with content
func NewOpenAIStreamChunkWithContent(model, responseID string, created int64, content string) *OpenAIStreamChunk {
	return &OpenAIStreamChunk{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []OpenAIStreamChoice{
			{
				Index: 0,
				Delta: OpenAIMessageDelta{
					Content: content,
				},
				FinishReason: nil,
			},
		},
	}
}

// NewOpenAIStreamChunkWithRole creates a new OpenAI stream chunk with role
func NewOpenAIStreamChunkWithRole(model, responseID string, created int64) *OpenAIStreamChunk {
	return &OpenAIStreamChunk{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []OpenAIStreamChoice{
			{
				Index: 0,
				Delta: OpenAIMessageDelta{
					Role: "assistant",
				},
				FinishReason: nil,
			},
		},
	}
}

// NewOpenAIStreamChunkWithFinishReason creates a new OpenAI stream chunk with finish reason
func NewOpenAIStreamChunkWithFinishReason(model, responseID string, created int64, finishReason string) *OpenAIStreamChunk {
	return &OpenAIStreamChunk{
		ID:      responseID,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []OpenAIStreamChoice{
			{
				Index:        0,
				Delta:        OpenAIMessageDelta{},
				FinishReason: &finishReason,
			},
		},
	}
}

// generateOpenAIResponseID generates a unique OpenAI response ID
func generateOpenAIResponseID() string {
	return "chatcmpl-" + time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString generates a random string of specified length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}