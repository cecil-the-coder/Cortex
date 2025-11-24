package providers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// OpenAIAdapter converts between Anthropic and OpenAI formats
type OpenAIAdapter struct{}

// NewOpenAIAdapter creates a new OpenAI adapter
func NewOpenAIAdapter() *OpenAIAdapter {
	return &OpenAIAdapter{}
}

// OpenAIRequest represents the OpenAI ChatCompletion API request format
type OpenAIRequest struct {
	Model            string           `json:"model"`
	Messages         []OpenAIMessage  `json:"messages"`
	MaxTokens        int              `json:"max_tokens,omitempty"`
	Temperature      *float64         `json:"temperature,omitempty"`
	TopP             *float64         `json:"top_p,omitempty"`
	Stop             interface{}      `json:"stop,omitempty"` // Can be string or []string
	Stream           bool             `json:"stream,omitempty"`
	Tools            []OpenAITool     `json:"tools,omitempty"`
	ToolChoice       interface{}      `json:"tool_choice,omitempty"` // "auto", "none", or object
	User             string           `json:"user,omitempty"`
	FrequencyPenalty *float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64         `json:"presence_penalty,omitempty"`
	N                *int             `json:"n,omitempty"`
}

// OpenAIMessage represents a message in OpenAI format
type OpenAIMessage struct {
	Role       string      `json:"role"` // "system", "user", "assistant", "tool"
	Content    interface{} `json:"content,omitempty"` // Can be string or []OpenAIContentPart
	Name       string      `json:"name,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

// OpenAIContentPart represents different content types in OpenAI messages
type OpenAIContentPart struct {
	Type     string        `json:"type"` // "text", "image_url"
	Text     string        `json:"text,omitempty"`
	ImageURL *ImageURL     `json:"image_url,omitempty"`
}

// ImageURL represents an image in OpenAI format
type ImageURL struct {
	URL    string `json:"url"` // Can be URL or data URI
	Detail string `json:"detail,omitempty"` // "auto", "low", "high"
}

// ToolCall represents a tool call in OpenAI format
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall represents a function call
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// OpenAITool represents a tool definition in OpenAI format
type OpenAITool struct {
	Type     string           `json:"type"` // "function"
	Function OpenAIFunction   `json:"function"`
}

// OpenAIFunction represents a function definition
type OpenAIFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// OpenAIResponse represents the OpenAI API response format
type OpenAIResponse struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"` // "chat.completion"
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	Choices           []OpenAIChoice `json:"choices"`
	Usage             OpenAIUsage    `json:"usage"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
}

// OpenAIChoice represents a completion choice
type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason,omitempty"` // "stop", "length", "tool_calls", "content_filter"
	LogProbs     interface{}   `json:"logprobs,omitempty"`
}

// OpenAIUsage represents token usage
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIStreamChunk represents a streaming response chunk
type OpenAIStreamChunk struct {
	ID                string               `json:"id"`
	Object            string               `json:"object"` // "chat.completion.chunk"
	Created           int64                `json:"created"`
	Model             string               `json:"model"`
	Choices           []OpenAIStreamChoice `json:"choices"`
	SystemFingerprint string               `json:"system_fingerprint,omitempty"`
}

// OpenAIStreamChoice represents a streaming choice
type OpenAIStreamChoice struct {
	Index        int                  `json:"index"`
	Delta        OpenAIMessageDelta   `json:"delta"`
	FinishReason *string              `json:"finish_reason"`
	LogProbs     interface{}          `json:"logprobs,omitempty"`
}

// OpenAIMessageDelta represents incremental message updates
type OpenAIMessageDelta struct {
	Role      string          `json:"role,omitempty"`
	Content   string          `json:"content,omitempty"`
	ToolCalls []ToolCallDelta `json:"tool_calls,omitempty"`
}

// ToolCallDelta represents a tool call delta in OpenAI streaming
type ToolCallDelta struct {
	Index    *int         `json:"index"`
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function FunctionCall `json:"function,omitempty"`
}

// TransformRequest converts an Anthropic request to OpenAI format
func (a *OpenAIAdapter) TransformRequest(anthropicReq *AnthropicRequest) (interface{}, error) {
	if anthropicReq == nil {
		return nil, fmt.Errorf("anthropic request is nil")
	}

	openaiReq := &OpenAIRequest{
		Model:       anthropicReq.Model,
		Messages:    make([]OpenAIMessage, 0),
		MaxTokens:   anthropicReq.MaxTokens,
		Temperature: anthropicReq.Temperature,
		TopP:        anthropicReq.TopP,
		Stream:      anthropicReq.Stream,
	}

	// Handle system prompt - convert to system message
	if anthropicReq.System != nil {
		systemMsg, err := a.convertSystemToMessage(anthropicReq.System)
		if err != nil {
			return nil, fmt.Errorf("failed to convert system prompt: %w", err)
		}
		if systemMsg != nil {
			openaiReq.Messages = append(openaiReq.Messages, *systemMsg)
		}
	}

	// Convert messages
	for _, msg := range anthropicReq.Messages {
		openaiMsg, err := a.convertMessage(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to convert message: %w", err)
		}
		openaiReq.Messages = append(openaiReq.Messages, openaiMsg...)
	}

	// Convert tools
	if len(anthropicReq.Tools) > 0 {
		openaiReq.Tools = make([]OpenAITool, 0, len(anthropicReq.Tools))
		for _, tool := range anthropicReq.Tools {
			openaiTool := a.convertTool(tool)
			openaiReq.Tools = append(openaiReq.Tools, openaiTool)
		}
	}

	// Convert tool choice
	if anthropicReq.ToolChoice != nil {
		openaiReq.ToolChoice = a.convertToolChoice(anthropicReq.ToolChoice)
	}

	// Convert stop sequences
	if len(anthropicReq.StopSequences) > 0 {
		if len(anthropicReq.StopSequences) == 1 {
			openaiReq.Stop = anthropicReq.StopSequences[0]
		} else {
			openaiReq.Stop = anthropicReq.StopSequences
		}
	}

	// Add user metadata if present
	if anthropicReq.Metadata != nil && anthropicReq.Metadata.UserID != "" {
		openaiReq.User = anthropicReq.Metadata.UserID
	}

	return openaiReq, nil
}

// convertSystemToMessage converts Anthropic system prompt to OpenAI system message
func (a *OpenAIAdapter) convertSystemToMessage(system interface{}) (*OpenAIMessage, error) {
	var systemText string

	switch v := system.(type) {
	case string:
		systemText = v
	case []interface{}:
		// Handle array of system blocks
		var parts []string
		for _, block := range v {
			blockMap, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if blockType, ok := blockMap["type"].(string); ok && blockType == "text" {
				if text, ok := blockMap["text"].(string); ok {
					parts = append(parts, text)
				}
			}
		}
		systemText = strings.Join(parts, "\n")
	default:
		// Try to marshal and unmarshal to handle struct types
		data, err := json.Marshal(system)
		if err != nil {
			return nil, fmt.Errorf("invalid system format: %w", err)
		}

		var blocks []SystemBlock
		if err := json.Unmarshal(data, &blocks); err == nil {
			var parts []string
			for _, block := range blocks {
				if block.Type == "text" {
					parts = append(parts, block.Text)
				}
			}
			systemText = strings.Join(parts, "\n")
		} else {
			// Fallback: treat as string
			systemText = string(data)
		}
	}

	if systemText == "" {
		return nil, nil
	}

	return &OpenAIMessage{
		Role:    "system",
		Content: systemText,
	}, nil
}

// convertMessage converts an Anthropic message to OpenAI format
// Returns a slice because tool_result messages may need to be split
func (a *OpenAIAdapter) convertMessage(msg AnthropicMessage) ([]OpenAIMessage, error) {
	// Handle simple string content
	if strContent, ok := msg.Content.(string); ok {
		return []OpenAIMessage{{
			Role:    msg.Role,
			Content: strContent,
		}}, nil
	}

	// Handle array of content blocks
	contentBlocks, err := a.parseContentBlocks(msg.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse content blocks: %w", err)
	}

	// Check if this is a tool result message
	hasToolResult := false
	for _, block := range contentBlocks {
		if block.Type == "tool_result" {
			hasToolResult = true
			break
		}
	}

	if hasToolResult {
		return a.convertToolResultMessage(contentBlocks)
	}

	// Check if this is a tool use message
	hasToolUse := false
	for _, block := range contentBlocks {
		if block.Type == "tool_use" {
			hasToolUse = true
			break
		}
	}

	if hasToolUse {
		return a.convertToolUseMessage(msg.Role, contentBlocks)
	}

	// Regular message with mixed content
	return a.convertRegularMessage(msg.Role, contentBlocks)
}

// parseContentBlocks converts interface{} to []ContentBlock
func (a *OpenAIAdapter) parseContentBlocks(content interface{}) ([]ContentBlock, error) {
	data, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}

	var blocks []ContentBlock
	if err := json.Unmarshal(data, &blocks); err != nil {
		return nil, err
	}

	return blocks, nil
}

// convertRegularMessage converts a regular message with text/image content
func (a *OpenAIAdapter) convertRegularMessage(role string, blocks []ContentBlock) ([]OpenAIMessage, error) {
	// If only one text block, use simple string content
	if len(blocks) == 1 && blocks[0].Type == "text" {
		return []OpenAIMessage{{
			Role:    role,
			Content: blocks[0].Text,
		}}, nil
	}

	// Multiple blocks or mixed content
	parts := make([]OpenAIContentPart, 0, len(blocks))
	for _, block := range blocks {
		switch block.Type {
		case "text":
			parts = append(parts, OpenAIContentPart{
				Type: "text",
				Text: block.Text,
			})
		case "image":
			if block.Source != nil {
				dataURI := fmt.Sprintf("data:%s;base64,%s",
					block.Source.MediaType,
					block.Source.Data)
				parts = append(parts, OpenAIContentPart{
					Type: "image_url",
					ImageURL: &ImageURL{
						URL: dataURI,
					},
				})
			}
		}
	}

	return []OpenAIMessage{{
		Role:    role,
		Content: parts,
	}}, nil
}

// convertToolUseMessage converts a message with tool_use blocks
func (a *OpenAIAdapter) convertToolUseMessage(role string, blocks []ContentBlock) ([]OpenAIMessage, error) {
	msg := OpenAIMessage{
		Role:      role,
		ToolCalls: make([]ToolCall, 0),
	}

	var textParts []string

	for _, block := range blocks {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "tool_use":
			// Convert input to JSON string
			argsJSON, err := json.Marshal(block.Input)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal tool input: %w", err)
			}

			msg.ToolCalls = append(msg.ToolCalls, ToolCall{
				ID:   block.ID,
				Type: "function",
				Function: FunctionCall{
					Name:      block.Name,
					Arguments: string(argsJSON),
				},
			})
		}
	}

	// Set content if there's text
	if len(textParts) > 0 {
		msg.Content = strings.Join(textParts, "\n")
	}

	return []OpenAIMessage{msg}, nil
}

// convertToolResultMessage converts tool_result blocks to OpenAI tool messages
func (a *OpenAIAdapter) convertToolResultMessage(blocks []ContentBlock) ([]OpenAIMessage, error) {
	messages := make([]OpenAIMessage, 0)

	for _, block := range blocks {
		if block.Type != "tool_result" {
			continue
		}

		var contentStr string
		switch v := block.Content.(type) {
		case string:
			contentStr = v
		case []interface{}:
			// Handle array of content blocks
			var parts []string
			for _, contentBlock := range v {
				if blockMap, ok := contentBlock.(map[string]interface{}); ok {
					if blockType, ok := blockMap["type"].(string); ok && blockType == "text" {
						if text, ok := blockMap["text"].(string); ok {
							parts = append(parts, text)
						}
					}
				}
			}
			contentStr = strings.Join(parts, "\n")
		default:
			// Marshal to JSON as fallback
			data, err := json.Marshal(block.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal tool result content: %w", err)
			}
			contentStr = string(data)
		}

		messages = append(messages, OpenAIMessage{
			Role:       "tool",
			Content:    contentStr,
			ToolCallID: block.ToolUseID,
		})
	}

	return messages, nil
}

// convertTool converts an Anthropic tool to OpenAI format
func (a *OpenAIAdapter) convertTool(tool AnthropicTool) OpenAITool {
	return OpenAITool{
		Type: "function",
		Function: OpenAIFunction{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  tool.InputSchema,
		},
	}
}

// convertToolChoice converts Anthropic tool_choice to OpenAI format
func (a *OpenAIAdapter) convertToolChoice(toolChoice interface{}) interface{} {
	// Handle string values
	if str, ok := toolChoice.(string); ok {
		switch str {
		case "auto":
			return "auto"
		case "any":
			return "required"
		default:
			return "auto"
		}
	}

	// Handle object with type and name
	if choiceMap, ok := toolChoice.(map[string]interface{}); ok {
		if choiceType, ok := choiceMap["type"].(string); ok {
			switch choiceType {
			case "auto":
				return "auto"
			case "any":
				return "required"
			case "tool":
				if name, ok := choiceMap["name"].(string); ok {
					return map[string]interface{}{
						"type": "function",
						"function": map[string]interface{}{
							"name": name,
						},
					}
				}
			}
		}
	}

	return "auto"
}

// TransformResponse converts an OpenAI response back to Anthropic format
func (a *OpenAIAdapter) TransformResponse(providerResp io.ReadCloser) (io.ReadCloser, error) {
	if providerResp == nil {
		return nil, fmt.Errorf("provider response is nil")
	}

	// Read the first few bytes to determine if this is a streaming response
	peekReader := bufio.NewReader(providerResp)
	firstBytes, err := peekReader.Peek(6)
	if err != nil && err != io.EOF {
		providerResp.Close()
		return nil, fmt.Errorf("failed to peek response: %w", err)
	}

	// Check if it's a streaming response (starts with "data: ")
	isStreaming := len(firstBytes) >= 6 && string(firstBytes[:6]) == "data: "

	if isStreaming {
		return a.transformStreamingResponse(peekReader, providerResp)
	}

	return a.transformNonStreamingResponse(peekReader, providerResp)
}

// transformNonStreamingResponse converts a non-streaming OpenAI response
func (a *OpenAIAdapter) transformNonStreamingResponse(reader *bufio.Reader, closer io.ReadCloser) (io.ReadCloser, error) {
	defer closer.Close()

	var openaiResp OpenAIResponse
	if err := json.NewDecoder(reader).Decode(&openaiResp); err != nil {
		return nil, fmt.Errorf("failed to decode OpenAI response: %w", err)
	}

	// Convert to Anthropic format
	anthropicResp := a.convertOpenAIResponse(&openaiResp)

	// Marshal back to JSON
	data, err := json.Marshal(anthropicResp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal anthropic response: %w", err)
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

// convertOpenAIResponse converts OpenAI response to Anthropic format
func (a *OpenAIAdapter) convertOpenAIResponse(openaiResp *OpenAIResponse) *AnthropicResponse {
	anthropicResp := &AnthropicResponse{
		ID:    openaiResp.ID,
		Type:  "message",
		Role:  "assistant",
		Model: openaiResp.Model,
		Usage: AnthropicUsage{
			InputTokens:  openaiResp.Usage.PromptTokens,
			OutputTokens: openaiResp.Usage.CompletionTokens,
		},
		Content: make([]ContentBlock, 0),
	}

	if len(openaiResp.Choices) > 0 {
		choice := openaiResp.Choices[0]

		// Convert finish reason
		anthropicResp.StopReason = a.convertFinishReason(choice.FinishReason)

		// Convert message content
		msg := choice.Message

		// Handle tool calls
		if len(msg.ToolCalls) > 0 {
			for _, toolCall := range msg.ToolCalls {
				var input interface{}
				if toolCall.Function.Arguments != "" {
					_ = json.Unmarshal([]byte(toolCall.Function.Arguments), &input)
				}

				anthropicResp.Content = append(anthropicResp.Content, ContentBlock{
					Type:  "tool_use",
					ID:    toolCall.ID,
					Name:  toolCall.Function.Name,
					Input: input,
				})
			}
			anthropicResp.StopReason = "tool_use"
		}

		// Handle text content
		if msg.Content != nil {
			if strContent, ok := msg.Content.(string); ok && strContent != "" {
				anthropicResp.Content = append([]ContentBlock{{
					Type: "text",
					Text: strContent,
				}}, anthropicResp.Content...)
			}
		}
	}

	// Ensure at least one content block
	if len(anthropicResp.Content) == 0 {
		anthropicResp.Content = append(anthropicResp.Content, ContentBlock{
			Type: "text",
			Text: "",
		})
	}

	return anthropicResp
}

// convertFinishReason converts OpenAI finish reason to Anthropic stop reason
func (a *OpenAIAdapter) convertFinishReason(finishReason string) string {
	switch finishReason {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "content_filter":
		return "end_turn"
	default:
		return "end_turn"
	}
}

// transformStreamingResponse converts a streaming OpenAI response
func (a *OpenAIAdapter) transformStreamingResponse(reader *bufio.Reader, closer io.ReadCloser) (io.ReadCloser, error) {
	pipeReader, pipeWriter := io.Pipe()

	go func() {
		defer closer.Close()
		defer pipeWriter.Close()

		scanner := bufio.NewScanner(reader)
		var messageID string
		var model string
		contentIndex := 0
		currentToolCall := make(map[int]*ToolCall)
		inputTokens := 0
		outputTokens := 0

		for scanner.Scan() {
			line := scanner.Text()

			if line == "" || !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")

			if data == "[DONE]" {
				// Send final message_delta with usage
				finalEvent := StreamEvent{
					Type: "message_delta",
					Delta: map[string]interface{}{
						"stop_reason": "end_turn",
					},
					Usage: &AnthropicUsage{
						OutputTokens: outputTokens,
					},
				}
				eventJSON, _ := json.Marshal(finalEvent)
				fmt.Fprintf(pipeWriter, "event: message_delta\ndata: %s\n\n", eventJSON)

				// Send message_stop event
				stopEvent := StreamEvent{
					Type: "message_stop",
				}
				stopJSON, _ := json.Marshal(stopEvent)
				fmt.Fprintf(pipeWriter, "event: message_stop\ndata: %s\n\n", stopJSON)
				return
			}

			var chunk OpenAIStreamChunk
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue
			}

			if messageID == "" {
				messageID = chunk.ID
				model = chunk.Model

				// Send message_start event
				startEvent := StreamEvent{
					Type: "message_start",
					Message: &AnthropicResponse{
						ID:      messageID,
						Type:    "message",
						Role:    "assistant",
						Model:   model,
						Content: []ContentBlock{},
						Usage: AnthropicUsage{
							InputTokens:  inputTokens,
							OutputTokens: 0,
						},
					},
				}
				startJSON, _ := json.Marshal(startEvent)
				fmt.Fprintf(pipeWriter, "event: message_start\ndata: %s\n\n", startJSON)
			}

			if len(chunk.Choices) == 0 {
				continue
			}

			choice := chunk.Choices[0]
			delta := choice.Delta

			// Handle role
			if delta.Role != "" && delta.Role == "assistant" {
				// Role is already set in message_start
				continue
			}

			// Handle text content
			if delta.Content != "" {
				// Check if we need to start a new content block
				if contentIndex == 0 {
					blockEvent := StreamEvent{
						Type:  "content_block_start",
						Index: contentIndex,
						ContentBlock: &ContentBlock{
							Type: "text",
							Text: "",
						},
					}
					blockJSON, _ := json.Marshal(blockEvent)
					fmt.Fprintf(pipeWriter, "event: content_block_start\ndata: %s\n\n", blockJSON)
				}

				// Send content_block_delta
				deltaEvent := StreamEvent{
					Type:  "content_block_delta",
					Index: contentIndex,
					Delta: TextDelta{
						Type: "text_delta",
						Text: delta.Content,
					},
				}
				deltaJSON, _ := json.Marshal(deltaEvent)
				fmt.Fprintf(pipeWriter, "event: content_block_delta\ndata: %s\n\n", deltaJSON)

				outputTokens++
			}

			// Handle tool calls
			if len(delta.ToolCalls) > 0 {
				for _, tc := range delta.ToolCalls {
					index := tc.Index
					if index == nil {
						idx := 0
						index = &idx
					}

					existing, exists := currentToolCall[*index]
					if !exists {
						// New tool call - send content_block_start
						contentIndex++
						existing = &ToolCall{
							ID:   tc.ID,
							Type: "function",
							Function: FunctionCall{
								Name:      tc.Function.Name,
								Arguments: "",
							},
						}
						currentToolCall[*index] = existing

						blockEvent := StreamEvent{
							Type:  "content_block_start",
							Index: contentIndex,
							ContentBlock: &ContentBlock{
								Type:  "tool_use",
								ID:    tc.ID,
								Name:  tc.Function.Name,
								Input: map[string]interface{}{},
							},
						}
						blockJSON, _ := json.Marshal(blockEvent)
						fmt.Fprintf(pipeWriter, "event: content_block_start\ndata: %s\n\n", blockJSON)
					}

					// Accumulate arguments
					if tc.Function.Arguments != "" {
						existing.Function.Arguments += tc.Function.Arguments

						// Send input_json_delta
						deltaEvent := StreamEvent{
							Type:  "content_block_delta",
							Index: contentIndex,
							Delta: InputJSONDelta{
								Type:        "input_json_delta",
								PartialJSON: tc.Function.Arguments,
							},
						}
						deltaJSON, _ := json.Marshal(deltaEvent)
						fmt.Fprintf(pipeWriter, "event: content_block_delta\ndata: %s\n\n", deltaJSON)
					}
				}
			}

			// Handle finish reason
			if choice.FinishReason != nil && *choice.FinishReason != "" {
				// Send content_block_stop for the last block
				stopEvent := StreamEvent{
					Type:  "content_block_stop",
					Index: contentIndex,
				}
				stopJSON, _ := json.Marshal(stopEvent)
				fmt.Fprintf(pipeWriter, "event: content_block_stop\ndata: %s\n\n", stopJSON)
			}
		}

		if err := scanner.Err(); err != nil {
			pipeWriter.CloseWithError(fmt.Errorf("scanner error: %w", err))
		}
	}()

	return pipeReader, nil
}
