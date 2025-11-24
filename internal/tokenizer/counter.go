package tokenizer

import (
	"encoding/json"
	"fmt"

	"github.com/pkoukk/tiktoken-go"
)

// Message represents an Anthropic-style message
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // can be string or []ContentBlock
}

// ContentBlock represents a content block in a message
type ContentBlock struct {
	Type   string                 `json:"type"`
	Text   string                 `json:"text,omitempty"`
	Source map[string]interface{} `json:"source,omitempty"`
}

// Tool represents a tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

// CountTokens counts the total number of tokens in messages, system prompt, and tools
// using the cl100k_base encoding (same as GPT-4 and Claude)
func CountTokens(messages []Message, system string, tools []Tool) (int, error) {
	// Initialize the tiktoken encoder with cl100k_base encoding
	encoding, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		return 0, fmt.Errorf("failed to get tiktoken encoding: %w", err)
	}

	totalTokens := 0

	// Count tokens in system prompt
	if system != "" {
		tokens := encoding.Encode(system, nil, nil)
		totalTokens += len(tokens)
		// Add overhead tokens for system message formatting
		totalTokens += 4 // Approximate overhead for role formatting
	}

	// Count tokens in messages
	for _, msg := range messages {
		msgTokens, err := countMessageTokens(msg, encoding)
		if err != nil {
			return 0, fmt.Errorf("failed to count tokens for message: %w", err)
		}
		totalTokens += msgTokens
		// Add overhead tokens for message formatting (role, delimiters, etc.)
		totalTokens += 4
	}

	// Count tokens in tools
	for _, tool := range tools {
		toolTokens, err := countToolTokens(tool, encoding)
		if err != nil {
			return 0, fmt.Errorf("failed to count tokens for tool %s: %w", tool.Name, err)
		}
		totalTokens += toolTokens
	}

	// Add base overhead for the conversation structure
	if len(messages) > 0 {
		totalTokens += 3
	}

	return totalTokens, nil
}

// countMessageTokens counts tokens in a single message
func countMessageTokens(msg Message, encoding *tiktoken.Tiktoken) (int, error) {
	tokens := 0

	// Count tokens in role
	roleTokens := encoding.Encode(msg.Role, nil, nil)
	tokens += len(roleTokens)

	// Count tokens in content
	switch content := msg.Content.(type) {
	case string:
		// Simple string content
		contentTokens := encoding.Encode(content, nil, nil)
		tokens += len(contentTokens)

	case []interface{}:
		// Array of content blocks
		for _, block := range content {
			blockTokens, err := countContentBlock(block, encoding)
			if err != nil {
				return 0, err
			}
			tokens += blockTokens
		}

	case []ContentBlock:
		// Typed array of content blocks
		for _, block := range content {
			blockTokens, err := countContentBlockTyped(block, encoding)
			if err != nil {
				return 0, err
			}
			tokens += blockTokens
		}

	case map[string]interface{}:
		// Single content block as map
		blockTokens, err := countContentBlock(content, encoding)
		if err != nil {
			return 0, err
		}
		tokens += blockTokens

	case nil:
		// Empty content
		tokens += 0

	default:
		// Try to marshal and count as JSON
		contentJSON, err := json.Marshal(content)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal content: %w", err)
		}
		contentTokens := encoding.Encode(string(contentJSON), nil, nil)
		tokens += len(contentTokens)
	}

	return tokens, nil
}

// countContentBlock counts tokens in a content block (interface{} type)
func countContentBlock(block interface{}, encoding *tiktoken.Tiktoken) (int, error) {
	blockMap, ok := block.(map[string]interface{})
	if !ok {
		// If not a map, try to marshal it
		blockJSON, err := json.Marshal(block)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal content block: %w", err)
		}
		tokens := encoding.Encode(string(blockJSON), nil, nil)
		return len(tokens), nil
	}

	tokens := 0

	// Count tokens in type field
	if blockType, ok := blockMap["type"].(string); ok {
		typeTokens := encoding.Encode(blockType, nil, nil)
		tokens += len(typeTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in text field
	if text, ok := blockMap["text"].(string); ok {
		textTokens := encoding.Encode(text, nil, nil)
		tokens += len(textTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in source field (for images, documents, etc.)
	if source, ok := blockMap["source"]; ok && source != nil {
		sourceJSON, err := json.Marshal(source)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal source: %w", err)
		}
		sourceTokens := encoding.Encode(string(sourceJSON), nil, nil)
		tokens += len(sourceTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in tool_use_id field (for tool results)
	if toolUseID, ok := blockMap["tool_use_id"].(string); ok {
		idTokens := encoding.Encode(toolUseID, nil, nil)
		tokens += len(idTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in content field (for tool results)
	if content, ok := blockMap["content"]; ok && content != nil {
		switch c := content.(type) {
		case string:
			contentTokens := encoding.Encode(c, nil, nil)
			tokens += len(contentTokens)
			tokens += 2 // Overhead for field structure
		default:
			contentJSON, err := json.Marshal(content)
			if err != nil {
				return 0, fmt.Errorf("failed to marshal content: %w", err)
			}
			contentTokens := encoding.Encode(string(contentJSON), nil, nil)
			tokens += len(contentTokens)
			tokens += 2 // Overhead for field structure
		}
	}

	// Count tokens in input field (for tool use)
	if input, ok := blockMap["input"]; ok && input != nil {
		inputJSON, err := json.Marshal(input)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal input: %w", err)
		}
		inputTokens := encoding.Encode(string(inputJSON), nil, nil)
		tokens += len(inputTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in name field (for tool use)
	if name, ok := blockMap["name"].(string); ok {
		nameTokens := encoding.Encode(name, nil, nil)
		tokens += len(nameTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in id field (for tool use)
	if id, ok := blockMap["id"].(string); ok {
		idTokens := encoding.Encode(id, nil, nil)
		tokens += len(idTokens)
		tokens += 2 // Overhead for field structure
	}

	return tokens, nil
}

// countContentBlockTyped counts tokens in a typed ContentBlock
func countContentBlockTyped(block ContentBlock, encoding *tiktoken.Tiktoken) (int, error) {
	tokens := 0

	// Count tokens in type
	if block.Type != "" {
		typeTokens := encoding.Encode(block.Type, nil, nil)
		tokens += len(typeTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in text
	if block.Text != "" {
		textTokens := encoding.Encode(block.Text, nil, nil)
		tokens += len(textTokens)
		tokens += 2 // Overhead for field structure
	}

	// Count tokens in source
	if block.Source != nil && len(block.Source) > 0 {
		sourceJSON, err := json.Marshal(block.Source)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal source: %w", err)
		}
		sourceTokens := encoding.Encode(string(sourceJSON), nil, nil)
		tokens += len(sourceTokens)
		tokens += 2 // Overhead for field structure
	}

	return tokens, nil
}

// countToolTokens counts tokens in a tool definition
func countToolTokens(tool Tool, encoding *tiktoken.Tiktoken) (int, error) {
	tokens := 0

	// Count tokens in name
	nameTokens := encoding.Encode(tool.Name, nil, nil)
	tokens += len(nameTokens)
	tokens += 2 // Overhead for field structure

	// Count tokens in description
	descTokens := encoding.Encode(tool.Description, nil, nil)
	tokens += len(descTokens)
	tokens += 2 // Overhead for field structure

	// Count tokens in input_schema
	if tool.InputSchema != nil && len(tool.InputSchema) > 0 {
		schemaJSON, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return 0, fmt.Errorf("failed to marshal input_schema: %w", err)
		}
		schemaTokens := encoding.Encode(string(schemaJSON), nil, nil)
		tokens += len(schemaTokens)
		tokens += 2 // Overhead for field structure
	}

	// Add base overhead for tool structure
	tokens += 5

	return tokens, nil
}

// CountString is a helper function to count tokens in a simple string
func CountString(text string) (int, error) {
	encoding, err := tiktoken.GetEncoding("cl100k_base")
	if err != nil {
		return 0, fmt.Errorf("failed to get tiktoken encoding: %w", err)
	}

	tokens := encoding.Encode(text, nil, nil)
	return len(tokens), nil
}
