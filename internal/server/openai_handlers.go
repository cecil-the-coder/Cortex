package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	"github.com/cecil-the-coder/Cortex/internal/converters"
	"github.com/cecil-the-coder/Cortex/internal/providers"
)

// HandleOpenAIChatCompletions handles POST /v1/chat/completions
func (s *Server) HandleOpenAIChatCompletions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse OpenAI request
	var req OpenAIChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendOpenAIError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("Invalid JSON: %v", err), nil, nil)
		return
	}
	defer r.Body.Close()

	// Validate request
	if err := s.validateOpenAIRequest(&req); err != nil {
		s.sendOpenAIError(w, http.StatusBadRequest, "invalid_request_error",
			err.Error(), nil, nil)
		return
	}

	// Convert OpenAI request to internal MessageRequest for routing
	internalReq := s.convertOpenAIToInternal(&req)

	// Count tokens
	if s.countTokens != nil {
		tokenCount, err := s.countTokens(internalReq.Model, internalReq.Messages)
		if err != nil {
			log.Printf("Warning: Failed to count tokens: %v", err)
		} else {
			log.Printf("Input tokens: %d for model %s", tokenCount, internalReq.Model)
		}
	}

	// Route request
	decision, err := s.routeRequest(ctx, internalReq)
	if err != nil {
		s.sendOpenAIError(w, http.StatusInternalServerError, "server_error",
			fmt.Sprintf("Failed to route request: %v", err), nil, nil)
		return
	}

	log.Printf("Routing decision: provider=%s, model=%s, reason=%s",
		decision.Provider, decision.Model, decision.Reasoning)

	// Get SDK provider
	sdkRegistry, ok := s.sdkProviders.(*providers.SDKProviderRegistry)
	if !ok {
		s.sendOpenAIError(w, http.StatusInternalServerError, "server_error",
			"SDK provider registry not configured", nil, nil)
		return
	}

	provider, err := sdkRegistry.GetProvider(decision.Provider)
	if err != nil {
		s.sendOpenAIError(w, http.StatusInternalServerError, "server_error",
			fmt.Sprintf("Provider not found: %v", err), nil, nil)
		return
	}

	// Convert to provider format
	providerReq := s.convertInternalToProviderRequest(internalReq)

	// Transform for target provider
	options, err := provider.TransformRequest(providerReq, decision.Model)
	if err != nil {
		s.sendOpenAIError(w, http.StatusInternalServerError, "server_error",
			fmt.Sprintf("Failed to transform request: %v", err), nil, nil)
		return
	}

	// Generate completion
	stream, err := provider.GenerateCompletion(ctx, options)
	if err != nil {
		s.sendOpenAIError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("Upstream provider error: %v", err), nil, nil)
		return
	}
	defer stream.Close()

	// Handle streaming vs non-streaming
	if req.Stream {
		s.streamOpenAIResponse(ctx, stream, w, decision.Model)
	} else {
		s.nonStreamingOpenAIResponse(ctx, stream, w, decision.Model)
	}
}

// HandleOpenAIModels handles GET /v1/models
func (s *Server) HandleOpenAIModels(w http.ResponseWriter, r *http.Request) {
	// Build models list from configuration
	models := make([]ModelInfo, 0)
	created := time.Now().Unix() - 86400*30 // 30 days ago

	// Get models from provider registry
	if sdkRegistry, ok := s.sdkProviders.(*providers.SDKProviderRegistry); ok {
		allModels := sdkRegistry.GetAllModels()
		for providerName, modelList := range allModels {
			for _, model := range modelList {
				models = append(models, ModelInfo{
					ID:      model,
					Object:  "model",
					Created: created,
					OwnedBy: providerName,
				})
			}
		}
	}

	// Add virtual router model
	models = append(models, ModelInfo{
		ID:      "router",
		Object:  "model",
		Created: created,
		OwnedBy: "Cortex",
	})

	response := ModelsResponse{
		Object: "list",
		Data:   models,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateOpenAIRequest validates an OpenAI chat completion request
func (s *Server) validateOpenAIRequest(req *OpenAIChatRequest) error {
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}

	if len(req.Messages) == 0 {
		return fmt.Errorf("messages array cannot be empty")
	}

	// Validate messages
	for i, msg := range req.Messages {
		validRoles := map[string]bool{
			"system": true, "user": true, "assistant": true, "tool": true,
		}
		if !validRoles[msg.Role] {
			return fmt.Errorf("message %d has invalid role: %s", i, msg.Role)
		}
	}

	return nil
}

// convertOpenAIToInternal converts OpenAI request to internal format
func (s *Server) convertOpenAIToInternal(req *OpenAIChatRequest) *MessageRequest {
	internal := &MessageRequest{
		Model:    req.Model,
		Messages: make([]Message, 0, len(req.Messages)),
		Stream:   req.Stream,
		Metadata: make(map[string]interface{}),
	}

	// Set max_tokens with default
	if req.MaxTokens != nil {
		internal.MaxTokens = *req.MaxTokens
	} else {
		internal.MaxTokens = 4096 // Default
	}

	// Set temperature
	if req.Temperature != nil {
		internal.Temperature = *req.Temperature
	}

	// Set top_p
	if req.TopP != nil {
		internal.TopP = *req.TopP
	}

	// Convert stop sequences
	if req.Stop != nil {
		switch v := req.Stop.(type) {
		case string:
			internal.StopSequences = []string{v}
		case []interface{}:
			for _, s := range v {
				if str, ok := s.(string); ok {
					internal.StopSequences = append(internal.StopSequences, str)
				}
			}
		}
	}

	// Extract system message and convert messages
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			// Extract system message content
			if content, ok := msg.Content.(string); ok {
				internal.System = content
			}
			continue
		}

		internal.Messages = append(internal.Messages, Message{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}

	// Convert tools to metadata for routing detection
	if len(req.Tools) > 0 {
		// Check for web_search tool
		for _, tool := range req.Tools {
			if tool.Function.Name == "web_search" {
				internal.Metadata["has_web_search"] = true
			}
		}
	}

	return internal
}

// convertInternalToProviderRequest converts internal format to provider format
func (s *Server) convertInternalToProviderRequest(req *MessageRequest) *converters.MessageRequest {
	return &converters.MessageRequest{
		Model:         req.Model,
		Messages:      convertMessages(req.Messages),
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		Stream:        req.Stream,
		StopSequences: req.StopSequences,
		System:        req.System,
		Metadata:      req.Metadata,
	}
}

// convertMessages converts between server Message and converters Message
func convertMessages(msgs []Message) []converters.Message {
	result := make([]converters.Message, len(msgs))
	for i, msg := range msgs {
		result[i] = converters.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}
	return result
}

// streamOpenAIResponse streams the response in OpenAI format
func (s *Server) streamOpenAIResponse(ctx context.Context, stream types.ChatCompletionStream, w http.ResponseWriter, model string) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendOpenAIError(w, http.StatusInternalServerError, "server_error",
			"Streaming not supported", nil, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Generate response ID
	responseID := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	// Send initial chunk with role
	initialChunk := NewOpenAIStreamChunkWithRole(model, responseID, created)
	s.writeOpenAIStreamChunk(w, initialChunk)
	flusher.Flush()

	// Stream content
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		chunk, err := stream.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Stream error: %v", err)
			return
		}

		if chunk.Done {
			// Send final chunk with finish_reason
			finishReason := "stop"
			finalChunk := NewOpenAIStreamChunkWithFinishReason(model, responseID, created, finishReason)
			s.writeOpenAIStreamChunk(w, finalChunk)
			break
		}

		// Send content chunk
		if chunk.Content != "" {
			contentChunk := NewOpenAIStreamChunkWithContent(model, responseID, created, chunk.Content)
			s.writeOpenAIStreamChunk(w, contentChunk)
			flusher.Flush()
		}
	}

	// Send [DONE]
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// writeOpenAIStreamChunk writes a single SSE chunk
func (s *Server) writeOpenAIStreamChunk(w io.Writer, chunk *OpenAIStreamChunk) {
	data, _ := json.Marshal(chunk)
	fmt.Fprintf(w, "data: %s\n\n", data)
}

// nonStreamingOpenAIResponse handles non-streaming responses
func (s *Server) nonStreamingOpenAIResponse(ctx context.Context, stream types.ChatCompletionStream, w http.ResponseWriter, model string) {
	var content strings.Builder
	var usage OpenAIUsage

	for {
		chunk, err := stream.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			s.sendOpenAIError(w, http.StatusBadGateway, "upstream_error",
				fmt.Sprintf("Stream error: %v", err), nil, nil)
			return
		}

		if chunk.Done {
			usage = OpenAIUsage{
				PromptTokens:     chunk.Usage.PromptTokens,
				CompletionTokens: chunk.Usage.CompletionTokens,
				TotalTokens:      chunk.Usage.PromptTokens + chunk.Usage.CompletionTokens,
			}
			break
		}

		content.WriteString(chunk.Content)
	}

	response := NewOpenAIChatResponse(model, content.String(), usage)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendOpenAIError sends an error in OpenAI format
func (s *Server) sendOpenAIError(w http.ResponseWriter, statusCode int, errorType, message string, param, code interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := OpenAIErrorResponse{
		Error: OpenAIError{
			Message: message,
			Type:    errorType,
			Param:   param,
			Code:    code,
		},
	}

	json.NewEncoder(w).Encode(response)
}