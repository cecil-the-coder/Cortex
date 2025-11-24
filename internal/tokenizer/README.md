# Tokenizer Package

This package provides token counting functionality for the Go LLM Router, compatible with both Anthropic and OpenAI message formats.

## Features

- **Accurate Token Counting**: Uses the `cl100k_base` encoding (same as GPT-4 and Claude)
- **Multi-format Support**: Handles string content, content blocks, and complex message structures
- **System Prompts**: Counts tokens in system messages
- **Tool Definitions**: Includes tool schemas in token counts
- **Type Flexibility**: Supports both typed and untyped content structures

## Installation

The package uses the `tiktoken-go` library, which is already included in the project dependencies:

```bash
go get github.com/pkoukk/tiktoken-go
```

## Usage

### Basic Message Counting

```go
import "Cortex/internal/tokenizer"

messages := []tokenizer.Message{
    {
        Role:    "user",
        Content: "Hello, how are you?",
    },
}

count, err := tokenizer.CountTokens(messages, "", nil)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Token count: %d\n", count)
```

### With System Prompt

```go
messages := []tokenizer.Message{
    {
        Role:    "user",
        Content: "What's the capital of France?",
    },
}

system := "You are a helpful geography assistant."

count, err := tokenizer.CountTokens(messages, system, nil)
```

### With Tools

```go
messages := []tokenizer.Message{
    {
        Role:    "user",
        Content: "What's the weather in Tokyo?",
    },
}

tools := []tokenizer.Tool{
    {
        Name:        "get_weather",
        Description: "Get the current weather for a location",
        InputSchema: map[string]interface{}{
            "type": "object",
            "properties": map[string]interface{}{
                "location": map[string]interface{}{
                    "type":        "string",
                    "description": "The city name",
                },
            },
            "required": []string{"location"},
        },
    },
}

count, err := tokenizer.CountTokens(messages, "", tools)
```

### Multimodal Content (Content Blocks)

```go
messages := []tokenizer.Message{
    {
        Role: "user",
        Content: []interface{}{
            map[string]interface{}{
                "type": "text",
                "text": "What's in this image?",
            },
            map[string]interface{}{
                "type": "image",
                "source": map[string]interface{}{
                    "type":       "base64",
                    "media_type": "image/jpeg",
                    "data":       "base64_encoded_image_data",
                },
            },
        },
    },
}

count, err := tokenizer.CountTokens(messages, "", nil)
```

### Tool Use and Results

```go
messages := []tokenizer.Message{
    {
        Role:    "user",
        Content: "Search for information",
    },
    {
        Role: "assistant",
        Content: []interface{}{
            map[string]interface{}{
                "type": "text",
                "text": "I'll search for that.",
            },
            map[string]interface{}{
                "type": "tool_use",
                "id":   "toolu_123",
                "name": "web_search",
                "input": map[string]interface{}{
                    "query": "Go programming",
                },
            },
        },
    },
    {
        Role: "user",
        Content: []interface{}{
            map[string]interface{}{
                "type":        "tool_result",
                "tool_use_id": "toolu_123",
                "content":     "Search results...",
            },
        },
    },
}

count, err := tokenizer.CountTokens(messages, "", nil)
```

### Simple String Counting

```go
text := "The quick brown fox jumps over the lazy dog."
count, err := tokenizer.CountString(text)
```

## Data Types

### Message

```go
type Message struct {
    Role    string      `json:"role"`
    Content interface{} `json:"content"` // can be string or []ContentBlock
}
```

### ContentBlock

```go
type ContentBlock struct {
    Type   string                 `json:"type"`
    Text   string                 `json:"text,omitempty"`
    Source map[string]interface{} `json:"source,omitempty"`
}
```

### Tool

```go
type Tool struct {
    Name        string                 `json:"name"`
    Description string                 `json:"description"`
    InputSchema map[string]interface{} `json:"input_schema"`
}
```

## Token Counting Algorithm

The token counter:

1. **Encodes text using cl100k_base**: Same encoding used by GPT-4, GPT-3.5-turbo, and Claude
2. **Adds formatting overhead**: Accounts for role markers, delimiters, and structure
3. **Handles complex content**: Properly counts tokens in JSON schemas, tool definitions, and nested structures
4. **Supports multiple content types**: Text, images, tool use, tool results, etc.

### Overhead Calculations

- **Per message**: 4 tokens (role + delimiters)
- **Per content block field**: 2 tokens (field structure)
- **Per tool**: 5 tokens base + field overhead
- **System prompt**: 4 tokens overhead
- **Conversation base**: 3 tokens

## Performance

The tokenizer is optimized for production use:

- Efficient encoding with tiktoken-go
- Minimal memory allocations
- Handles large conversations efficiently

See benchmarks in `counter_test.go`:

```bash
go test -bench=. ./internal/tokenizer/
```

## Error Handling

All functions return errors for:

- Encoding initialization failures
- JSON marshaling errors
- Invalid content structures

Always check errors:

```go
count, err := tokenizer.CountTokens(messages, system, tools)
if err != nil {
    log.Printf("Failed to count tokens: %v", err)
    // Handle error appropriately
}
```

## Testing

Run tests:

```bash
go test -v ./internal/tokenizer/
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./internal/tokenizer/
```

## Compatibility

This tokenizer is compatible with:

- **Anthropic Claude API**: Messages, system prompts, tools
- **OpenAI Chat API**: Similar message format
- **Custom implementations**: Flexible content types

## Notes

- The token counts include overhead for API formatting
- Actual API usage may vary slightly based on the provider's implementation
- Image tokens are counted based on the base64 data size, not the actual token cost (which varies by provider)
- For production use, consider adding caching for frequently counted messages
