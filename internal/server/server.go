package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/access"
)

// ReloadConfigFunc is a function type for reloading configuration
type ReloadConfigFunc func() error

// Server represents the HTTP server
type Server struct {
	httpServer   *http.Server
	router       *http.ServeMux
	config       *Config

	// Dependencies
	countTokens  TokenCountFunc
	routeRequest RouteFunc
	providers    ProviderRegistry
	sdkProviders interface{} // Stores *providers.SDKProviderRegistry when using SDK
	reloadConfig ReloadConfigFunc // Function to reload configuration

	// Extended dependencies for admin API
	accessManager *access.AccessManager
	configFunc    func() *config.Config // Function to get current configuration
}

// Config holds server configuration
type Config struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	APIKey          string
	EnableCORS      bool
	AllowedOrigins  []string
	ConfigPath      string // Path to the configuration file
}

// TokenCountFunc is a function type for token counting
type TokenCountFunc func(model string, messages []Message) (int, error)

// RouteFunc is a function type for routing
type RouteFunc func(ctx context.Context, request *MessageRequest) (*RouteDecision, error)

// ProviderRegistry interface for managing providers
type ProviderRegistry interface {
	GetProvider(name string) (Provider, error)
}

// Provider interface for upstream API providers
type Provider interface {
	Name() string
	SendRequest(ctx context.Context, request interface{}) (*http.Response, error)
	TransformRequest(request *MessageRequest, targetModel string) (interface{}, error)
	StreamResponse(ctx context.Context, response *http.Response, writer http.ResponseWriter) error
}

// RouteDecision represents the routing decision
type RouteDecision struct {
	Provider       string
	Model          string
	Reasoning      string

	// Model access information
	AccessInfo     interface{} // Using interface{} to avoid circular import
	OriginalModel  string      // The original model requested by client
	ResolvedModel  string      // The actual model that will be used
	ResolvedBy     string      // How the model was resolved: "alias", "direct", or "provider-fallback"
	ModelGroup     string      // The model group that granted access
}

// Message represents a chat message
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// MessageRequest represents the Anthropic-compatible request
type MessageRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature,omitempty"`
	TopP        float64   `json:"top_p,omitempty"`
	TopK        int       `json:"top_k,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
	StopSequences []string `json:"stop_sequences,omitempty"`
	System      string    `json:"system,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TokenCountRequest represents a token counting request
type TokenCountRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	System   string    `json:"system,omitempty"`
}

// TokenCountResponse represents the token count response
type TokenCountResponse struct {
	InputTokens int `json:"input_tokens"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// DefaultConfig returns default server configuration
func DefaultConfig() *Config {
	return &Config{
		Host:            "127.0.0.1",
		Port:            8080,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    300 * time.Second, // Long timeout for streaming
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		EnableCORS:      true,
		AllowedOrigins:  []string{"http://127.0.0.1", "http://localhost"},
	}
}

// NewServer creates a new Server instance
func NewServer(cfg *Config, countTokens TokenCountFunc, routeRequest RouteFunc, providers ProviderRegistry) *Server {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	s := &Server{
		config:       cfg,
		countTokens:  countTokens,
		routeRequest: routeRequest,
		providers:    providers,
		router:       http.NewServeMux(),
	}

	s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:      s.router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return s
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoint (public)
	s.router.HandleFunc("/health", s.HandleHealth)
	s.router.HandleFunc("/", s.HandleRoot)

	// Admin endpoints
	s.router.HandleFunc("POST /admin/reload", s.HandleAdminReload)
	s.router.HandleFunc("GET /admin/status", s.HandleAdminStatus)
	s.router.HandleFunc("POST /admin/validate/", s.HandleAdminProviderValidate)

	// Admin API Key Management endpoints
	s.router.HandleFunc("GET /admin/api-keys", s.ServeAdminAPIKeys)
	s.router.HandleFunc("POST /admin/api-keys", s.ServeAdminAPIKeyCreate)
	s.router.HandleFunc("PUT /admin/api-keys/", s.ServeAdminAPIKeyUpdate)      // /admin/api-keys/{id}
	s.router.HandleFunc("DELETE /admin/api-keys/", s.ServeAdminAPIKeyDelete)    // /admin/api-keys/{id}
	s.router.HandleFunc("POST /admin/api-keys/validate", s.ServeAdminAPIKeyValidate)
	s.router.HandleFunc("GET /admin/api-keys/", s.ServeAdminAPIKeyUsage)         // /admin/api-keys/{id}/usage

	// Admin Model Group Management endpoints
	s.router.HandleFunc("GET /admin/model-groups", s.ServeAdminModelGroups)
	s.router.HandleFunc("POST /admin/model-groups", s.ServeAdminModelGroupsCreate)
	s.router.HandleFunc("GET /admin/model-groups/", s.ServeAdminModelGroupDetails) // /admin/model-groups/{name}
	s.router.HandleFunc("PUT /admin/model-groups/", s.ServeAdminModelGroupUpdate)  // /admin/model-groups/{name}
	s.router.HandleFunc("DELETE /admin/model-groups/", s.ServeAdminModelGroupDelete)// /admin/model-groups/{name}

	// Admin Access Control endpoints
	s.router.HandleFunc("POST /admin/access/check", s.ServeAdminAccessCheck)
	s.router.HandleFunc("GET /admin/access/models/", s.ServeAdminAvailableModels)   // /admin/access/models/{api_key}
	s.router.HandleFunc("GET /admin/access/aliases/", s.ServeAdminAvailableAliases)  // /admin/access/aliases/{api_key}
	s.router.HandleFunc("GET /admin/access/groups/", s.ServeAdminModelGroupMembership)// /admin/access/groups/{model}

	// Anthropic API endpoints
	s.router.HandleFunc("POST /v1/messages", s.HandleMessages)
	s.router.HandleFunc("POST /v1/messages/count_tokens", s.HandleCountTokens)

	// OpenAI-compatible API endpoints
	s.router.HandleFunc("POST /v1/chat/completions", s.HandleOpenAIChatCompletions)
	s.router.HandleFunc("GET /v1/models", s.HandleOpenAIModels)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	log.Printf("Starting server on %s:%d", s.config.Host, s.config.Port)

	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down server...")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown error: %w", err)
	}

	log.Println("Server stopped")
	return nil
}

// Run starts the server with graceful shutdown
func (s *Server) Run() error {
	// Create error channel
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		serverErrors <- s.Start()
	}()

	// Setup signal handling
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Wait for error or shutdown signal
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		log.Printf("Received signal: %v", sig)

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()

		// Attempt graceful shutdown
		if err := s.Shutdown(ctx); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		return nil
	}
}

// Handler returns the current HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// SetHandler sets the HTTP handler (used for wrapping with middleware)
func (s *Server) SetHandler(handler http.Handler) {
	s.httpServer.Handler = handler
}

// SetSDKProviders sets the SDK provider registry
func (s *Server) SetSDKProviders(sdkProviders interface{}) {
	s.sdkProviders = sdkProviders
}

// SetReloadConfigFunc sets the configuration reload function
func (s *Server) SetReloadConfigFunc(reloadFunc ReloadConfigFunc) {
	s.reloadConfig = reloadFunc
}

// SetAccessManager sets the access manager for the admin API
func (s *Server) SetAccessManager(am *access.AccessManager) {
	s.accessManager = am
}

// SetConfigFunc sets the configuration getter function for the admin API
func (s *Server) SetConfigFunc(configFunc func() *config.Config) {
	s.configFunc = configFunc
}

// GetConfigPath returns the path to the configuration file
func (s *Server) GetConfigPath() string {
	return s.config.ConfigPath
}

// HandleRoot handles requests to the root endpoint
func (s *Server) HandleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"service":"Cortex","version":"1.0.0","status":"running"}`))
}

// HandleHealth handles health check requests
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}
