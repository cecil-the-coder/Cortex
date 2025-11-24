package tokenizer

import (
	"testing"
)

func TestCountTokens_SimpleMessage(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Hello, how are you?",
		},
	}

	count, err := CountTokens(messages, "", nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Simple message token count: %d", count)
}

func TestCountTokens_WithSystemPrompt(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "What is the weather like?",
		},
	}

	system := "You are a helpful weather assistant that provides accurate weather information."

	count, err := CountTokens(messages, system, nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Message with system prompt token count: %d", count)
}

func TestCountTokens_MultipleMessages(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Hello!",
		},
		{
			Role:    "assistant",
			Content: "Hi there! How can I help you today?",
		},
		{
			Role:    "user",
			Content: "I need help with my code.",
		},
	}

	count, err := CountTokens(messages, "", nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Multiple messages token count: %d", count)
}

func TestCountTokens_ContentBlocks(t *testing.T) {
	messages := []Message{
		{
			Role: "user",
			Content: []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "Hello, I have a question about this image.",
				},
				map[string]interface{}{
					"type": "image",
					"source": map[string]interface{}{
						"type": "base64",
						"media_type": "image/jpeg",
						"data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
					},
				},
			},
		},
	}

	count, err := CountTokens(messages, "", nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Content blocks token count: %d", count)
}

func TestCountTokens_WithTools(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "What's the weather in San Francisco?",
		},
	}

	tools := []Tool{
		{
			Name:        "get_weather",
			Description: "Get the current weather in a given location",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"location": map[string]interface{}{
						"type":        "string",
						"description": "The city and state, e.g. San Francisco, CA",
					},
					"unit": map[string]interface{}{
						"type": "string",
						"enum": []string{"celsius", "fahrenheit"},
					},
				},
				"required": []string{"location"},
			},
		},
	}

	count, err := CountTokens(messages, "", tools)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Messages with tools token count: %d", count)
}

func TestCountTokens_ComplexConversation(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Can you help me search for information?",
		},
		{
			Role: "assistant",
			Content: []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "I'll help you search. Let me use the search tool.",
				},
				map[string]interface{}{
					"type": "tool_use",
					"id":   "toolu_01A09q90qw90lq917835lq9",
					"name": "web_search",
					"input": map[string]interface{}{
						"query": "latest news",
					},
				},
			},
		},
		{
			Role: "user",
			Content: []interface{}{
				map[string]interface{}{
					"type":        "tool_result",
					"tool_use_id": "toolu_01A09q90qw90lq917835lq9",
					"content":     "Here are the latest news articles...",
				},
			},
		},
	}

	system := "You are a helpful AI assistant with access to web search."

	tools := []Tool{
		{
			Name:        "web_search",
			Description: "Search the web for information",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "The search query",
					},
				},
				"required": []string{"query"},
			},
		},
	}

	count, err := CountTokens(messages, system, tools)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Complex conversation token count: %d", count)
}

func TestCountTokens_EmptyInput(t *testing.T) {
	count, err := CountTokens([]Message{}, "", nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 tokens for empty input, got %d", count)
	}
}

func TestCountTokens_MultipleTools(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Help me with some tasks",
		},
	}

	tools := []Tool{
		{
			Name:        "calculator",
			Description: "Perform mathematical calculations",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"expression": map[string]interface{}{
						"type":        "string",
						"description": "The mathematical expression to evaluate",
					},
				},
				"required": []string{"expression"},
			},
		},
		{
			Name:        "file_reader",
			Description: "Read contents of a file",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "The file path to read",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "web_search",
			Description: "Search the web",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
				},
				"required": []string{"query"},
			},
		},
	}

	count, err := CountTokens(messages, "", tools)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Multiple tools token count: %d", count)
}

func TestCountString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Simple", "Hello, world!"},
		{"Empty", ""},
		{"Long", "This is a much longer string that contains multiple sentences. It should result in a higher token count than the simple examples. Let's add even more text to make sure we're properly counting tokens across a longer piece of content."},
		{"Code", `func main() { fmt.Println("Hello, World!") }`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := CountString(tt.input)
			if err != nil {
				t.Fatalf("CountString failed: %v", err)
			}

			t.Logf("%s: %q = %d tokens", tt.name, tt.input, count)
		})
	}
}

func TestCountTokens_TypedContentBlocks(t *testing.T) {
	messages := []Message{
		{
			Role: "user",
			Content: []ContentBlock{
				{
					Type: "text",
					Text: "This is a typed content block",
				},
			},
		},
	}

	count, err := CountTokens(messages, "", nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Typed content blocks token count: %d", count)
}

func TestCountTokens_LongSystemPrompt(t *testing.T) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Hello",
		},
	}

	system := `You are Claude, an AI assistant created by Anthropic. You are helpful, harmless, and honest.

Your capabilities include:
- Answering questions across a wide range of topics
- Helping with analysis, writing, math, coding, and creative tasks
- Engaging in open-ended conversation
- Providing explanations and breaking down complex topics

You should:
- Be direct and honest
- Admit when you don't know something
- Decline requests for harmful or unethical content
- Respect intellectual property and privacy
- Maintain high standards of accuracy

Please provide thoughtful, well-reasoned responses while being concise when appropriate.`

	count, err := CountTokens(messages, system, nil)
	if err != nil {
		t.Fatalf("CountTokens failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected non-zero token count")
	}

	t.Logf("Long system prompt token count: %d", count)
}

func BenchmarkCountTokens_SimpleMessage(b *testing.B) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Hello, how are you today?",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CountTokens(messages, "", nil)
		if err != nil {
			b.Fatalf("CountTokens failed: %v", err)
		}
	}
}

func BenchmarkCountTokens_ComplexConversation(b *testing.B) {
	messages := []Message{
		{
			Role:    "user",
			Content: "Can you help me with a task?",
		},
		{
			Role: "assistant",
			Content: []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": "Of course! I'll use a tool to help.",
				},
				map[string]interface{}{
					"type": "tool_use",
					"id":   "toolu_123",
					"name": "helper",
					"input": map[string]interface{}{
						"param": "value",
					},
				},
			},
		},
	}

	tools := []Tool{
		{
			Name:        "helper",
			Description: "A helper tool",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"param": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CountTokens(messages, "You are a helpful assistant", tools)
		if err != nil {
			b.Fatalf("CountTokens failed: %v", err)
		}
	}
}
