package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/converters"
	"github.com/cecil-the-coder/Cortex/internal/providers"
)

// HandleMessages handles POST /v1/messages requests
func (s *Server) HandleMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req MessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Validate request
	if err := s.validateMessageRequest(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	// Extract model information from context if available (set by model access middleware)
	resolvedModel := req.Model
	originalModel := req.Model
	apiKeyID := ""

	if modelNameFromCtx, ok := getModelNameFromContext(r); ok {
		resolvedModel = modelNameFromCtx
	}

	if originalModelFromCtx, ok := getOriginalModelFromContext(r); ok {
		originalModel = originalModelFromCtx
	}

	if apiKeyIDFromCtx, ok := getAPIKeyIDFromContext(r); ok {
		apiKeyID = apiKeyIDFromCtx
	}

	// Use resolved model for token counting for more accurate results
	modelForTokenCount := resolvedModel

	// Count input tokens
	var tokenCount int
	if s.countTokens != nil {
		var countErr error
		tokenCount, countErr = s.countTokens(modelForTokenCount, req.Messages)
		if countErr != nil {
			log.Printf("Warning: Failed to count tokens: %v", countErr)
			// Continue anyway - token counting is not critical
		} else {
			log.Printf("Input tokens: %d for model %s (original: %s)", tokenCount, modelForTokenCount, originalModel)
		}
	}

	// Route request to determine provider and model
	decision, err := s.routeRequest(ctx, &req)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "routing_error",
			fmt.Sprintf("Failed to route request: %v", err))
		return
	}

	// Log comprehensive routing decision information
	logMsg := fmt.Sprintf("Routing decision: provider=%s, model=%s, reason=%s",
		decision.Provider, decision.Model, decision.Reasoning)

	if decision.OriginalModel != "" {
		logMsg += fmt.Sprintf(", original_model=%s", decision.OriginalModel)
	}
	if decision.ResolvedModel != "" {
		logMsg += fmt.Sprintf(", resolved_model=%s", decision.ResolvedModel)
	}
	if decision.ResolvedBy != "" {
		logMsg += fmt.Sprintf(", resolved_by=%s", decision.ResolvedBy)
	}
	if decision.ModelGroup != "" {
		logMsg += fmt.Sprintf(", model_group=%s", decision.ModelGroup)
	}
	if apiKeyID != "" {
		logMsg += fmt.Sprintf(", api_key=%s", apiKeyID)
	}

	log.Println(logMsg)

	// Get SDK provider from registry
	sdkRegistry, ok := s.sdkProviders.(*providers.SDKProviderRegistry)
	if !ok {
		s.sendError(w, http.StatusInternalServerError, "provider_error",
			"SDK provider registry not configured")
		return
	}

	provider, err := sdkRegistry.GetProvider(decision.Provider)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "provider_error",
			fmt.Sprintf("Provider not found: %v", err))
		return
	}

	// Convert to provider MessageRequest format
	// Use the resolved model from routing decision for more accurate provider selection
	targetModel := req.Model
	if decision.ResolvedModel != "" {
		targetModel = decision.ResolvedModel
	}

	providerReq := &converters.MessageRequest{
		Model:         targetModel,
		Messages:      make([]converters.Message, len(req.Messages)),
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		TopK:          req.TopK,
		Stream:        req.Stream,
		StopSequences: req.StopSequences,
		System:        req.System,
		Metadata:      req.Metadata,
	}

	// Add model alias information to metadata for response handling
	if decision.ResolvedModel != "" && decision.ResolvedModel != req.Model {
		if providerReq.Metadata == nil {
			providerReq.Metadata = make(map[string]interface{})
		}
		providerReq.Metadata["original_model"] = req.Model
		providerReq.Metadata["resolved_model"] = decision.ResolvedModel
		providerReq.Metadata["resolved_by"] = decision.ResolvedBy
		if decision.ModelGroup != "" {
			providerReq.Metadata["model_group"] = decision.ModelGroup
		}
	}

	// Convert messages
	for i, msg := range req.Messages {
		providerReq.Messages[i] = converters.Message{
			Role:    msg.Role,
			Content: msg.Content,
		}
	}

	// Transform request for the target provider
	options, err := provider.TransformRequest(providerReq, decision.Model)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "transform_error",
			fmt.Sprintf("Failed to transform request: %v", err))
		return
	}

	// Generate completion using SDK
	stream, err := provider.GenerateCompletion(ctx, options)
	if err != nil {
		s.sendError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("Upstream provider error: %v", err))
		return
	}
	defer stream.Close()

	// Handle streaming vs non-streaming
	if req.Stream {
		if err := provider.StreamResponse(ctx, stream, w); err != nil {
			log.Printf("Error streaming response: %v", err)
		}
	} else {
		response, err := provider.NonStreamingResponse(ctx, stream)
		if err != nil {
			s.sendError(w, http.StatusBadGateway, "upstream_error",
				fmt.Sprintf("Failed to get response: %v", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// HandleCountTokens handles POST /v1/messages/count_tokens requests
func (s *Server) HandleCountTokens(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req TokenCountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Validate request
	if req.Model == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", "Model is required")
		return
	}

	if len(req.Messages) == 0 {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", "Messages are required")
		return
	}

	// Extract resolved model information from context if available
	targetModel := req.Model
	originalModel := req.Model

	if modelNameFromCtx, ok := getModelNameFromContext(r); ok {
		targetModel = modelNameFromCtx
	}

	if originalModelFromCtx, ok := getOriginalModelFromContext(r); ok {
		originalModel = originalModelFromCtx
	}

	// Count tokens using resolved model for more accurate counting
	if s.countTokens == nil {
		s.sendError(w, http.StatusInternalServerError, "tokenizer_error",
			"Token counting not configured")
		return
	}

	tokenCount, err := s.countTokens(targetModel, req.Messages)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "tokenizer_error",
			fmt.Sprintf("Failed to count tokens: %v", err))
		return
	}

	// Send enhanced response with model resolution information
	response := map[string]interface{}{
		"input_tokens": tokenCount,
	}

	// Add model resolution information if applicable
	if targetModel != originalModel {
		response["model"] = map[string]interface{}{
			"original": originalModel,
			"resolved": targetModel,
		}
	} else {
		response["model"] = targetModel
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// validateMessageRequest validates a message request
func (s *Server) validateMessageRequest(req *MessageRequest) error {
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}

	if len(req.Messages) == 0 {
		return fmt.Errorf("messages are required")
	}

	if req.MaxTokens <= 0 {
		return fmt.Errorf("max_tokens must be positive")
	}

	// Validate message roles
	for i, msg := range req.Messages {
		if msg.Role != "user" && msg.Role != "assistant" {
			return fmt.Errorf("invalid role '%s' at message %d", msg.Role, i)
		}
	}

	return nil
}

// handleStreamingResponse handles streaming SSE responses
func (s *Server) handleStreamingResponse(ctx context.Context, w http.ResponseWriter,
	upstreamResp *http.Response, provider Provider) {

	// Set headers for SSE streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

	// Get flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendError(w, http.StatusInternalServerError, "streaming_error",
			"Streaming not supported")
		return
	}

	// Flush headers
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Create buffered reader for upstream response
	reader := bufio.NewReader(upstreamResp.Body)

	// Stream events
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			log.Println("Client disconnected during streaming")
			return
		default:
		}

		// Read line from upstream
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				// Stream complete
				return
			}
			log.Printf("Error reading stream: %v", err)
			return
		}

		// Write line to client
		if _, err := w.Write(line); err != nil {
			log.Printf("Error writing to client: %v", err)
			return
		}

		// Flush immediately for real-time streaming
		flusher.Flush()
	}
}

// handleNonStreamingResponse handles non-streaming responses
func (s *Server) handleNonStreamingResponse(w http.ResponseWriter, upstreamResp *http.Response) {
	// Copy headers
	for key, values := range upstreamResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set content type if not already set
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	// Write status code
	w.WriteHeader(upstreamResp.StatusCode)

	// Copy body
	if _, err := io.Copy(w, upstreamResp.Body); err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}

// proxyErrorResponse proxies error responses from upstream
func (s *Server) proxyErrorResponse(w http.ResponseWriter, upstreamResp *http.Response) {
	// Read error response body
	body, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		s.sendError(w, http.StatusBadGateway, "upstream_error",
			"Failed to read upstream error response")
		return
	}

	// Try to parse as JSON error
	var errorResp map[string]interface{}
	if err := json.Unmarshal(body, &errorResp); err != nil {
		// Not JSON, send as plain error
		s.sendError(w, upstreamResp.StatusCode, "upstream_error",
			string(body))
		return
	}

	// Forward the error response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(upstreamResp.StatusCode)
	_, _ = w.Write(body)
}

// sendError sends a JSON error response
func (s *Server) sendError(w http.ResponseWriter, statusCode int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Type:    errorType,
		Message: message,
	}

	_ = json.NewEncoder(w).Encode(response)
}

// StreamEvent represents an SSE event
type StreamEvent struct {
	Event string
	Data  string
	ID    string
}

// WriteSSE writes an SSE event to the response writer
func WriteSSE(w io.Writer, event StreamEvent) error {
	var buf bytes.Buffer

	if event.Event != "" {
		fmt.Fprintf(&buf, "event: %s\n", event.Event)
	}

	if event.ID != "" {
		fmt.Fprintf(&buf, "id: %s\n", event.ID)
	}

	if event.Data != "" {
		// Split data by newlines for proper SSE format
		for _, line := range bytes.Split([]byte(event.Data), []byte("\n")) {
			fmt.Fprintf(&buf, "data: %s\n", line)
		}
	}

	buf.WriteString("\n")

	_, err := w.Write(buf.Bytes())
	return err
}

// StreamTransformer transforms upstream events to Anthropic format
type StreamTransformer interface {
	Transform(upstreamEvent []byte) ([]byte, error)
	IsComplete(upstreamEvent []byte) bool
}

// handleTransformedStreaming handles streaming with transformation
func (s *Server) handleTransformedStreaming(ctx context.Context, w http.ResponseWriter,
	upstreamResp *http.Response, transformer StreamTransformer) {

	// Set headers for SSE streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendError(w, http.StatusInternalServerError, "streaming_error",
			"Streaming not supported")
		return
	}

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	reader := bufio.NewReader(upstreamResp.Body)

	for {
		select {
		case <-ctx.Done():
			log.Println("Client disconnected during streaming")
			return
		default:
		}

		// Read event from upstream
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error reading stream: %v", err)
			return
		}

		// Skip empty lines
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		// Transform event
		transformedLine, err := transformer.Transform(line)
		if err != nil {
			log.Printf("Error transforming event: %v", err)
			continue
		}

		// Write to client
		if _, err := w.Write(transformedLine); err != nil {
			log.Printf("Error writing to client: %v", err)
			return
		}

		flusher.Flush()

		// Check if streaming is complete
		if transformer.IsComplete(line) {
			return
		}
	}
}

// HandleAdminReload handles POST /admin/reload requests
func (s *Server) HandleAdminReload(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Check if config reload function is available
	if s.reloadConfig == nil {
		s.sendError(w, http.StatusNotImplemented, "not_implemented", "Config reload not available")
		return
	}

	log.Printf("Manual config reload requested via admin endpoint")

	// Trigger the reload
	err := s.reloadConfig()
	if err != nil {
		log.Printf("Manual config reload failed: %v", err)
		s.sendError(w, http.StatusInternalServerError, "reload_error",
			fmt.Sprintf("Failed to reload configuration: %v", err))
		return
	}

	log.Printf("Manual config reload completed successfully")

	// Send success response
	response := struct {
		Success   bool   `json:"success"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}{
		Success:   true,
		Message:   "Configuration reloaded successfully",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// HandleAdminStatus handles GET /admin/status requests
func (s *Server) HandleAdminStatus(w http.ResponseWriter, r *http.Request) {
	// Only allow GET method
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Get current provider information
	var providerInfo []map[string]interface{}

	if s.sdkProviders != nil {
		if registry, ok := s.sdkProviders.(*providers.SDKProviderRegistry); ok {
			allConfigs := registry.GetAllProviderConfigs()
			for name, cfg := range allConfigs {
				providerInfo = append(providerInfo, map[string]interface{}{
					"name":     name,
					"baseURL":  cfg.BaseURL,
					"models":   cfg.Models,
					"hasKey":   cfg.APIKEY != "" && cfg.APIKEY != "${ANTHROPIC_API_KEY}" && cfg.APIKEY != "${OPENAI_API_KEY}",
				})
			}
		}
	}

	response := struct {
		Status      string                   `json:"status"`
		Timestamp   string                   `json:"timestamp"`
		Version     string                   `json:"version,omitempty"`
		Providers   []map[string]interface{} `json:"providers"`
		ConfigPath  string                   `json:"configPath,omitempty"`
		Reloadable  bool                     `json:"reloadable"`
	}{
		Status:     "running",
		Timestamp:  time.Now().Format(time.RFC3339),
		Providers:  providerInfo,
		Reloadable: s.reloadConfig != nil,
	}

	// Add version info if available
	if s.config != nil {
		response.ConfigPath = s.config.ConfigPath
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// HandleAdminProviderValidate handles POST /admin/validate/:provider requests
func (s *Server) HandleAdminProviderValidate(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Extract provider name from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "Provider name is required")
		return
	}

	providerName := pathParts[2]

	log.Printf("Validating provider API key: %s", providerName)

	// Check if provider exists
	if s.sdkProviders == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Providers not initialized")
		return
	}

	registry, ok := s.sdkProviders.(*providers.SDKProviderRegistry)
	if !ok {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Provider registry not available")
		return
	}

	// Validate the provider's API key
	err := registry.ValidateProviderAPIKey(providerName)
	if err != nil {
		log.Printf("Provider validation failed for %s: %v", providerName, err)
		s.sendError(w, http.StatusBadRequest, "validation_error",
			fmt.Sprintf("Provider validation failed: %v", err))
		return
	}

	log.Printf("Provider validation succeeded for %s", providerName)

	// Send success response
	response := struct {
		Success   bool   `json:"success"`
		Message   string `json:"message"`
		Provider  string `json:"provider"`
		Timestamp string `json:"timestamp"`
	}{
		Success:   true,
		Message:   "Provider API key is valid",
		Provider:  providerName,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ContextWithTimeout creates a context with timeout
func ContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 5 * time.Minute // Default 5 minute timeout
	}
	return context.WithTimeout(parent, timeout)
}

// Helper functions for extracting context information from model access middleware

// getModelNameFromContext extracts the resolved model name from the request context
func getModelNameFromContext(r *http.Request) (string, bool) {
	if r == nil || r.Context() == nil {
		return "", false
	}

	if val := r.Context().Value("model_name"); val != nil {
		if modelName, ok := val.(string); ok {
			return modelName, true
		}
	}
	return "", false
}

// getOriginalModelFromContext extracts the original model name from the request context
func getOriginalModelFromContext(r *http.Request) (string, bool) {
	if r == nil || r.Context() == nil {
		return "", false
	}

	// Try to get from access info first
	if val := r.Context().Value("access_info"); val != nil {
		// This would be the AccessInfo struct but we'll use interface{} to avoid circular imports
		if accessInfoMap, ok := val.(map[string]interface{}); ok {
			if originalModel, exists := accessInfoMap["OriginalModel"]; exists {
				if modelStr, ok := originalModel.(string); ok {
					return modelStr, true
				}
			}
		}
	}

	return "", false
}

// getAPIKeyIDFromContext extracts the API key identifier from the request context
func getAPIKeyIDFromContext(r *http.Request) (string, bool) {
	if r == nil || r.Context() == nil {
		return "", false
	}

	if val := r.Context().Value("api_key_id"); val != nil {
		if apiKeyID, ok := val.(string); ok {
			return apiKeyID, true
		}
	}
	return "", false
}

// getProviderFromContext extracts the provider name from the request context
func getProviderFromContext(r *http.Request) (string, bool) {
	if r == nil || r.Context() == nil {
		return "", false
	}

	if val := r.Context().Value("provider"); val != nil {
		if provider, ok := val.(string); ok {
			return provider, true
		}
	}
	return "", false
}

// enhanceResponseWithModelInfo enhances a response with model alias information
func enhanceResponseWithModelInfo(response interface{}, decision *RouteDecision) {
	// This function can be used to add model alias information to response metadata
	// Implementation depends on the response structure
	if decision == nil || decision.ResolvedModel == "" || decision.ResolvedModel == decision.Model {
		return // No alias information to add
	}

	// Implementation would depend on response structure
	// This is a placeholder for future enhancement
}
