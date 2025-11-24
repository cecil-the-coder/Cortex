package server

import (
	"testing"
	"time"
)

func TestValidateOpenAIRequest(t *testing.T) {
	s := &Server{}

	tests := []struct {
		name    string
		req     OpenAIChatRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: OpenAIChatRequest{
				Model: "gpt-4",
				Messages: []OpenAIMessage{
					{Role: "user", Content: "Hello"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing model",
			req: OpenAIChatRequest{
				Messages: []OpenAIMessage{
					{Role: "user", Content: "Hello"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty messages",
			req: OpenAIChatRequest{
				Model:    "gpt-4",
				Messages: []OpenAIMessage{},
			},
			wantErr: true,
		},
		{
			name: "invalid role",
			req: OpenAIChatRequest{
				Model: "gpt-4",
				Messages: []OpenAIMessage{
					{Role: "invalid", Content: "Hello"},
				},
			},
			wantErr: true,
		},
		{
			name: "system message included",
			req: OpenAIChatRequest{
				Model: "gpt-4",
				Messages: []OpenAIMessage{
					{Role: "system", Content: "You are helpful"},
					{Role: "user", Content: "Hello"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateOpenAIRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOpenAIRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvertOpenAIToInternal(t *testing.T) {
	s := &Server{}

	maxTokens := 100
	temperature := 0.7

	req := &OpenAIChatRequest{
		Model:       "gpt-4",
		MaxTokens:   &maxTokens,
		Temperature: &temperature,
		Messages: []OpenAIMessage{
			{Role: "system", Content: "You are a helpful assistant"},
			{Role: "user", Content: "Hello"},
		},
	}

	internal := s.convertOpenAIToInternal(req)

	if internal.Model != "gpt-4" {
		t.Errorf("Expected model gpt-4, got %s", internal.Model)
	}

	if internal.System != "You are a helpful assistant" {
		t.Errorf("Expected system message, got %s", internal.System)
	}

	if len(internal.Messages) != 1 {
		t.Errorf("Expected 1 message (without system), got %d", len(internal.Messages))
	}

	if internal.MaxTokens != 100 {
		t.Errorf("Expected max_tokens 100, got %d", internal.MaxTokens)
	}

	if internal.Temperature != 0.7 {
		t.Errorf("Expected temperature 0.7, got %f", internal.Temperature)
	}
}

func TestOpenAIResponseHelpers(t *testing.T) {
	model := "gpt-4"
	content := "Hello world"
	usage := OpenAIUsage{
		PromptTokens:     10,
		CompletionTokens: 5,
		TotalTokens:      15,
	}

	// Test NewOpenAIChatResponse
	response := NewOpenAIChatResponse(model, content, usage)

	if response.Object != "chat.completion" {
		t.Errorf("Expected object 'chat.completion', got %s", response.Object)
	}

	if response.Model != model {
		t.Errorf("Expected model %s, got %s", model, response.Model)
	}

	if len(response.Choices) != 1 {
		t.Errorf("Expected 1 choice, got %d", len(response.Choices))
	}

	if response.Choices[0].Message.Content != content {
		t.Errorf("Expected content %s, got %s", content, response.Choices[0].Message.Content)
	}

	// Test stream chunk helpers
	responseID := "test-id"
	created := time.Now().Unix()

	// Role chunk
	roleChunk := NewOpenAIStreamChunkWithRole(model, responseID, created)
	if roleChunk.Choices[0].Delta.Role != "assistant" {
		t.Errorf("Expected role 'assistant', got %s", roleChunk.Choices[0].Delta.Role)
	}

	// Content chunk
	contentChunk := NewOpenAIStreamChunkWithContent(model, responseID, created, "test")
	if contentChunk.Choices[0].Delta.Content != "test" {
		t.Errorf("Expected content 'test', got %s", contentChunk.Choices[0].Delta.Content)
	}

	// Finish reason chunk
	finishReason := "stop"
	finishChunk := NewOpenAIStreamChunkWithFinishReason(model, responseID, created, finishReason)
	if *finishChunk.Choices[0].FinishReason != finishReason {
		t.Errorf("Expected finish reason %s, got %s", finishReason, *finishChunk.Choices[0].FinishReason)
	}
}

func TestConvertMessages(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "Hello"},
		{Role: "assistant", Content: "Hi there!"},
	}

	result := convertMessages(msgs)

	if len(result) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(result))
	}

	if result[0].Role != "user" || result[0].Content != "Hello" {
		t.Errorf("First message conversion failed: got %+v", result[0])
	}

	if result[1].Role != "assistant" || result[1].Content != "Hi there!" {
		t.Errorf("Second message conversion failed: got %+v", result[1])
	}
}