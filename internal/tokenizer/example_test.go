package tokenizer_test

import (
	"fmt"
	"log"

	"github.com/cecil-the-coder/Cortex/internal/tokenizer"
)

// Example_basic demonstrates basic token counting for simple messages
func Example_basic() {
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
	// Output will vary based on encoding, but should be > 0
}

// Example_withSystemPrompt shows how to count tokens with a system prompt
func Example_withSystemPrompt() {
	messages := []tokenizer.Message{
		{
			Role:    "user",
			Content: "What's the capital of France?",
		},
	}

	system := "You are a helpful geography assistant."

	count, err := tokenizer.CountTokens(messages, system, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Total tokens (with system prompt): %d\n", count)
}

// Example_withTools demonstrates token counting when tools are included
func Example_withTools() {
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
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Total tokens (with tools): %d\n", count)
}

// Example_multimodalContent shows token counting for messages with multiple content blocks
func Example_multimodalContent() {
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
						"data":       "...",
					},
				},
			},
		},
	}

	count, err := tokenizer.CountTokens(messages, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Multimodal message tokens: %d\n", count)
}

// Example_conversation demonstrates token counting for a full conversation
func Example_conversation() {
	messages := []tokenizer.Message{
		{
			Role:    "user",
			Content: "Can you help me write some code?",
		},
		{
			Role:    "assistant",
			Content: "Of course! I'd be happy to help. What would you like to create?",
		},
		{
			Role:    "user",
			Content: "I need a function to reverse a string in Go.",
		},
		{
			Role:    "assistant",
			Content: "Here's a simple function to reverse a string in Go:\n\n```go\nfunc ReverseString(s string) string {\n    runes := []rune(s)\n    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {\n        runes[i], runes[j] = runes[j], runes[i]\n    }\n    return string(runes)\n}\n```",
		},
	}

	system := "You are an expert Go programmer."

	count, err := tokenizer.CountTokens(messages, system, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Full conversation tokens: %d\n", count)
}

// Example_toolUse shows token counting for tool use and tool results
func Example_toolUse() {
	messages := []tokenizer.Message{
		{
			Role:    "user",
			Content: "Search for information about Go programming",
		},
		{
			Role: "assistant",
			Content: []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "I'll search for that information.",
				},
				map[string]interface{}{
					"type": "tool_use",
					"id":   "toolu_01234567890",
					"name": "web_search",
					"input": map[string]interface{}{
						"query": "Go programming language features",
					},
				},
			},
		},
		{
			Role: "user",
			Content: []interface{}{
				map[string]interface{}{
					"type":        "tool_result",
					"tool_use_id": "toolu_01234567890",
					"content":     "Go is a statically typed, compiled programming language...",
				},
			},
		},
		{
			Role:    "assistant",
			Content: "Based on the search results, Go is a statically typed language known for its simplicity and efficiency.",
		},
	}

	tools := []tokenizer.Tool{
		{
			Name:        "web_search",
			Description: "Search the web for information",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	count, err := tokenizer.CountTokens(messages, "", tools)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Tool use conversation tokens: %d\n", count)
}

// Example_countString shows simple string token counting
func Example_countString() {
	text := "The quick brown fox jumps over the lazy dog."

	count, err := tokenizer.CountString(text)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("String '%s' has %d tokens\n", text, count)
}
