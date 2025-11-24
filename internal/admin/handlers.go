package admin

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/cecil-the-coder/Cortex/internal/access"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/providers"
	"github.com/cecil-the-coder/Cortex/internal/server"
)

// AdminServer provides comprehensive admin API functionality
type AdminServer struct {
	router             *mux.Router
	providerRegistry   *providers.SDKProviderRegistry
	configFunc         func() *config.Config
	accessManager      *access.AccessManager
	server             *server.Server
	wsUpgrader         websocket.Upgrader
	wsClients          map[*websocket.Conn]bool
	wsMutex           sync.RWMutex
	wsHub              *WebSocketHub
	rateLimiter       map[string]*RateLimiter
	rateMutex         sync.RWMutex
	auditLogger       *AuditLogger
	cfg               *AdminConfig
	adminAPIKeys      []string
}

// AdminConfig holds configuration for the admin server
type AdminConfig struct {
	Version           string
	EnableRateLimit   bool
	RateLimitPerMin   int
	EnableAuditLog    bool
	AuditLogPath      string
	EnableCORS        bool
	AllowedOrigins    []string
	AdminAPIKeys      []string
	EnableWS          bool
}

// RateLimiter implements simple rate limiting
type RateLimiter struct {
	requests []time.Time
	limit    int
	window   time.Duration
}

// AuditLogger handles activity logging and audit trails
type AuditLogger struct {
	enabled bool
	logPath string
	logger  *log.Logger
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	User          string                 `json:"user"`
	Action        string                 `json:"action"`
	Resource      string                 `json:"resource"`
	ResourceID    string                 `json:"resource_id,omitempty"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	Success       bool                   `json:"success"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	RequestData   map[string]interface{} `json:"request_data,omitempty"`
	ResponseData  map[string]interface{} `json:"response_data,omitempty"`
}

// APIError represents a standardized API error response
type APIError struct {
	Error     string      `json:"error"`
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	Details   interface{} `json:"details,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// APIResponse represents a standardized API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Paging    *PagingInfo `json:"paging,omitempty"`
	Meta      *MetaInfo   `json:"meta,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// PagingInfo contains pagination information
type PagingInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// MetaInfo contains metadata for responses
type MetaInfo struct {
	Version     string            `json:"version"`
	Processing  int64             `json:"processing_ms"`
	Headers     map[string]string `json:"headers,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// FilterOptions contains filtering and sorting options
type FilterOptions struct {
	Query    string            `json:"query,omitempty"`
	SortBy   string            `json:"sort_by,omitempty"`
	SortDesc bool              `json:"sort_desc,omitempty"`
	Status   string            `json:"status,omitempty"`
	DateFrom string            `json:"date_from,omitempty"`
	DateTo   string            `json:"date_to,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
	Filters  map[string]string `json:"filters,omitempty"`
}

// PaginatedRequest contains pagination parameters
type PaginatedRequest struct {
	Page      int               `json:"page"`       // Default: 1
	PerPage   int               `json:"per_page"`   // Default: 50, Max: 1000
	Filter    FilterOptions     `json:"filter,omitempty"`
	Search    string            `json:"search,omitempty"`
	Export    string            `json:"export,omitempty"` // "json", "csv"
}

// BulkOperationRequest contains bulk operation parameters
type BulkOperationRequest struct {
	Action   string      `json:"action"`    // "create", "update", "delete"
	Items    []interface{} `json:"items"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

// BulkOperationResponse contains bulk operation results
type BulkOperationResponse struct {
	Success      bool                   `json:"success"`
	Total        int                    `json:"total"`
	Successful   int                    `json:"successful"`
	Failed       int                    `json:"failed"`
	Results      []BulkOperationResult  `json:"results"`
	Errors       []string               `json:"errors,omitempty"`
	Timestamp    string                 `json:"timestamp"`
}

// BulkOperationResult represents the result of a single bulk operation item
type BulkOperationResult struct {
	Index       int         `json:"index"`
	Success     bool        `json:"success"`
	ID          string      `json:"id,omitempty"`
	Error       string      `json:"error,omitempty"`
	Data        interface{} `json:"data,omitempty"`
}

// NewAdminServer creates a new admin server instance
func NewAdminServer(cfg *AdminConfig, providerRegistry *providers.SDKProviderRegistry, configFunc func() *config.Config, accessMgr *access.AccessManager, srv *server.Server) *AdminServer {
	admin := &AdminServer{
		router:           mux.NewRouter(),
		providerRegistry: providerRegistry,
		configFunc:       configFunc,
		accessManager:    accessMgr,
		server:           srv,
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				if !cfg.EnableCORS {
					return true
				}
				origin := r.Header.Get("Origin")
				for _, allowed := range cfg.AllowedOrigins {
					if origin == allowed || strings.HasSuffix(origin, allowed) {
						return true
					}
				}
				return false
			},
		},
		wsClients:    make(map[*websocket.Conn]bool),
		rateLimiter:  make(map[string]*RateLimiter),
		auditLogger:  NewAuditLogger(cfg.EnableAuditLog, cfg.AuditLogPath),
		cfg:          cfg,
		adminAPIKeys: cfg.AdminAPIKeys,
	}

	// Setup routes
	admin.setupRoutes(cfg.Version)

	return admin
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(enabled bool, logPath string) *AuditLogger {
	al := &AuditLogger{
		enabled: enabled,
		logPath: logPath,
	}

	if enabled {
		if logPath != "" {
			file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			if err != nil {
				log.Printf("Warning: Failed to create audit log file: %v", err)
			} else {
				al.logger = log.New(file, "", log.LstdFlags|log.Lmicroseconds)
			}
		} else {
			al.logger = log.New(os.Stdout, "[AUDIT] ", log.LstdFlags|log.Lmicroseconds)
		}
	}

	return al
}

// setupRoutes configures all admin API routes
func (a *AdminServer) setupRoutes(apiVersion string) {
	v1 := a.router.PathPrefix("/v1").Subrouter()

	// Provider Management
	providers := v1.PathPrefix("/providers").Subrouter()
	providers.HandleFunc("", a.handleListProviders).Methods("GET")
	providers.HandleFunc("", a.handleCreateProvider).Methods("POST")
	providers.HandleFunc("/{id}", a.handleGetProvider).Methods("GET")
	providers.HandleFunc("/{id}", a.handleUpdateProvider).Methods("PUT")
	providers.HandleFunc("/{id}", a.handleDeleteProvider).Methods("DELETE")
	providers.HandleFunc("/{id}/health", a.handleTriggerHealthCheck).Methods("POST")
	providers.HandleFunc("/{id}/metrics", a.handleGetProviderMetrics).Methods("GET")
	providers.HandleFunc("/{id}/validate", a.handleValidateProvider).Methods("POST")
	providers.HandleFunc("/bulk", a.handleBulkProviderOperations).Methods("POST")

	// User Management (API Keys)
	users := v1.PathPrefix("/users").Subrouter()
	users.HandleFunc("/api-keys", a.handleListAPIKeys).Methods("GET")
	users.HandleFunc("/api-keys", a.handleCreateAPIKey).Methods("POST")
	users.HandleFunc("/api-keys/{id}", a.handleGetAPIKey).Methods("GET")
	users.HandleFunc("/api-keys/{id}", a.handleUpdateAPIKey).Methods("PUT")
	users.HandleFunc("/api-keys/{id}", a.handleDeleteAPIKey).Methods("DELETE")
	users.HandleFunc("/api-keys/{id}/usage", a.handleGetAPIKeyUsage).Methods("GET")
	users.HandleFunc("/api-keys/validate", a.handleValidateAPIKey).Methods("POST")
	users.HandleFunc("/api-keys/bulk", a.handleBulkAPIKeyOperations).Methods("POST")

	// Model Management
	models := v1.PathPrefix("/models").Subrouter()
	models.HandleFunc("", a.handleListModels).Methods("GET")
	models.HandleFunc("/discover", a.handleDiscoverModels).Methods("POST")
	models.HandleFunc("/{model}", a.handleGetModel).Methods("GET")
	models.HandleFunc("/routing/analytics", a.handleGetRoutingAnalytics).Methods("GET")
	models.HandleFunc("/groups", a.handleListModelGroups).Methods("GET")
	models.HandleFunc("/groups", a.handleCreateModelGroup).Methods("POST")
	models.HandleFunc("/groups/{name}", a.handleGetModelGroup).Methods("GET")
	models.HandleFunc("/groups/{name}", a.handleUpdateModelGroup).Methods("PUT")
	models.HandleFunc("/groups/{name}", a.handleDeleteModelGroup).Methods("DELETE")
	models.HandleFunc("/groups/bulk", a.handleBulkModelGroupOperations).Methods("POST")

	// Configuration Management
	config := v1.PathPrefix("/config").Subrouter()
	config.HandleFunc("", a.handleGetConfig).Methods("GET")
	config.HandleFunc("", a.handleUpdateConfig).Methods("PUT")
	config.HandleFunc("/validate", a.handleValidateConfig).Methods("POST")
	config.HandleFunc("/reload", a.handleReloadConfig).Methods("POST")
	config.HandleFunc("/export", a.handleExportConfig).Methods("GET")
	config.HandleFunc("/import", a.handleImportConfig).Methods("POST")
	config.HandleFunc("/backup", a.handleCreateBackup).Methods("POST")
	config.HandleFunc("/backups", a.handleListBackups).Methods("GET")
	config.HandleFunc("/backups/{id}", a.handleRestoreBackup).Methods("POST")

	// Monitoring & Analytics
	monitoring := v1.PathPrefix("/monitoring").Subrouter()
	monitoring.HandleFunc("/status", a.handleSystemStatus).Methods("GET")
	monitoring.HandleFunc("/health", a.handleSystemHealth).Methods("GET")
	monitoring.HandleFunc("/metrics", a.handleSystemMetrics).Methods("GET")
	monitoring.HandleFunc("/analytics", a.handleAnalytics).Methods("GET")
	monitoring.HandleFunc("/logs", a.handleLogs).Methods("GET")
	monitoring.HandleFunc("/alerts", a.handleAlerts).Methods("GET")
	monitoring.HandleFunc("/performance", a.handlePerformanceMetrics).Methods("GET")

	// System Management
	system := v1.PathPrefix("/system").Subrouter()
	system.HandleFunc("/info", a.handleSystemInfo).Methods("GET")
	system.HandleFunc("/version", a.handleVersion).Methods("GET")
	system.HandleFunc("/uptime", a.handleUptime).Methods("GET")
	system.HandleFunc("/database/status", a.handleDatabaseStatus).Methods("GET")
	system.HandleFunc("/cache/status", a.handleCacheStatus).Methods("GET")
	system.HandleFunc("/maintenance", a.handleMaintenance).Methods("POST")
	system.HandleFunc("/database/backup", a.handleDatabaseBackup).Methods("POST")
	system.HandleFunc("/database/restore", a.handleDatabaseRestore).Methods("POST")

	// WebSocket support for real-time updates
	v1.HandleFunc("/ws", a.handleWebSocket)

	// API Documentation
	v1.HandleFunc("/specs", a.handleAPISpecs).Methods("GET")
	v1.HandleFunc("/docs", a.handleAPIDocs).Methods("GET")
}

// GetRouter returns the configured admin router
func (a *AdminServer) GetRouter() http.Handler {
	return a.router
}

// Authentication middleware
func (a *AdminServer) authenticateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from headers or query parameters
		apiKey := r.Header.Get("Authorization")
		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key")
		}
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		// Check API key validity
		if !a.isValidAdminAPIKey(apiKey) {
			a.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid or missing admin API key")
			return
		}

		// Apply rate limiting
		if !a.checkRateLimit(r) {
			a.sendError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Too many requests")
			return
		}

		// Log access attempt
		a.logAccess(r, "API_ACCESS", "", "", true)

		next.ServeHTTP(w, r)
	}
}

// isValidAdminAPIKey checks if the provided API key is valid for admin access
func (a *AdminServer) isValidAdminAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}

	// Remove "Bearer " prefix if present
	if strings.HasPrefix(apiKey, "Bearer ") {
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
	}

	// Check against main admin API key
	cfg := a.configFunc()
	if cfg != nil && apiKey == cfg.APIKEY {
		return true
	}

	// Check against client API keys with admin privileges
	if cfg != nil && cfg.ClientAPIKeys != nil {
		for _, keyConfig := range *cfg.ClientAPIKeys {
			if keyConfig.APIKey == apiKey && keyConfig.Enabled {
				// Check if this key has admin privileges (could be a custom field in the future)
				if strings.Contains(strings.ToLower(keyConfig.Description), "admin") {
					return true
				}
			}
		}
	}

	// Check against hardcoded admin API keys from config (for development)
	for _, adminKey := range a.adminAPIKeys {
		if apiKey == adminKey {
			return true
		}
	}

	return false
}

// checkRateLimit implements simple rate limiting
func (a *AdminServer) checkRateLimit(r *http.Request) bool {
	if !a.cfg.EnableRateLimit {
		return true
	}

	clientIP := getClientIP(r)

	a.rateMutex.Lock()
	defer a.rateMutex.Unlock()

	limiter, exists := a.rateLimiter[clientIP]
	if !exists {
		limiter = &RateLimiter{
			requests: make([]time.Time, 0),
			limit:    a.cfg.RateLimitPerMin,
			window:   time.Minute,
		}
		a.rateLimiter[clientIP] = limiter
	}

	now := time.Time{}

	// Remove old requests outside the window
	for len(limiter.requests) > 0 && now.Sub(limiter.requests[0]) > limiter.window {
		limiter.requests = limiter.requests[1:]
	}

	// Check if we're over the limit
	if len(limiter.requests) >= limiter.limit {
		return false
	}

	// Add this request
	limiter.requests = append(limiter.requests, now)
	return true
}

// logAccess logs admin API access for audit purposes
func (a *AdminServer) logAccess(r *http.Request, action, resource, resourceID string, success bool) {
	if !a.auditLogger.enabled {
		return
	}

	entry := AuditEntry{
		Timestamp:    time.Now(),
		User:         extractUserFromRequest(r),
		Action:       action,
		Resource:     resource,
		ResourceID:   resourceID,
		IPAddress:    getClientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
		Success:      success,
	}

	a.auditLogger.logEntry(entry)
}

// logEntry writes an audit log entry
func (al *AuditLogger) logEntry(entry AuditEntry) {
	if !al.enabled || al.logger == nil {
		return
	}

	// Convert to JSON for structured logging
	if data, err := json.Marshal(entry); err == nil {
		al.logger.Println(string(data))
	}
}

// sendError sends a standardized error response
func (a *AdminServer) sendError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	response := APIError{
		Error:     "true",
		Code:      errorCode,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// sendResponse sends a standardized success response
func (a *AdminServer) sendResponse(w http.ResponseWriter, statusCode int, data interface{}, paging *PagingInfo, meta *MetaInfo) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		Paging:    paging,
		Meta:      meta,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// parsePagination extracts pagination parameters from request
func (a *AdminServer) parsePagination(r *http.Request) (int, int, error) {
	query := r.URL.Query()

	page, err := strconv.Atoi(query.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	perPage, err := strconv.Atoi(query.Get("per_page"))
	if err != nil || perPage < 1 || perPage > 1000 {
		perPage = 50
	}

	return page, perPage, nil
}

// parseFilterOptions extracts filtering options from request
func (a *AdminServer) parseFilterOptions(r *http.Request) FilterOptions {
	query := r.URL.Query()

	options := FilterOptions{
		Query:    query.Get("q"),
		SortBy:   query.Get("sort_by"),
		SortDesc: query.Get("sort_desc") == "true",
		Status:   query.Get("status"),
		DateFrom: query.Get("date_from"),
		DateTo:   query.Get("date_to"),
		Tags:     strings.Split(query.Get("tags"), ","),
		Filters:  make(map[string]string),
	}

	// Extract custom filters
	for key, values := range query {
		if strings.HasPrefix(key, "filter_") {
			filterKey := strings.TrimPrefix(key, "filter_")
			if len(values) > 0 {
				options.Filters[filterKey] = values[0]
			}
		}
	}

	return options
}

// getClientIP extracts the real client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// The first IP in the list is the original client
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// extractUserFromRequest extracts user identification from request
func extractUserFromRequest(r *http.Request) string {
	// Try to get user from API key (simplified)
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "api_key:" + maskAPIKey(apiKey)
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return "api_key:" + maskAPIKey(strings.TrimPrefix(auth, "Bearer "))
		}
		return "auth:" + auth[:min(len(auth), 10)]
	}

	return getClientIP(r)
}

// maskAPIKey creates a masked version of an API key for logging
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return strings.Repeat("*", len(apiKey))
	}
	return apiKey[:4] + strings.Repeat("*", len(apiKey)-8) + apiKey[len(apiKey)-4:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleAPISpecs handles API specification requests
func (a *AdminServer) handleAPISpecs(w http.ResponseWriter, r *http.Request) {
	// Return OpenAPI/Swagger specification for the admin API
	specs := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]string{
			"title":       "Cortex Admin API",
			"description": "Administrative API for Cortex LLM Router",
			"version":     "1.0.0",
		},
		"servers": []map[string]string{
			{
				"url":   "/v1",
				"description": "Admin API v1",
			},
		},
		"paths": map[string]interface{}{
			"/providers": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List providers",
					"description": "Get a list of all configured providers",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Successful response",
						},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Create provider",
					"description": "Create a new provider configuration",
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "Provider created successfully",
						},
					},
				},
			},
			"/users/api-keys": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "List API keys",
					"description": "Get a list of all API keys",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Successful response",
						},
					},
				},
				"post": map[string]interface{}{
					"summary":     "Create API key",
					"description": "Create a new API key",
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "API key created successfully",
						},
					},
				},
			},
		},
	}

	a.sendResponse(w, http.StatusOK, specs, nil, nil)
}

// handleAPIDocs handles API documentation requests
func (a *AdminServer) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	// Return HTML documentation page for the admin API
	docsHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Cortex Admin API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .method { font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }
        .get { background: #61affe; }
        .post { background: #49cc90; }
        .put { background: #fca130; }
        .delete { background: #f93e3e; }
    </style>
</head>
<body>
    <h1>Cortex Admin API Documentation</h1>
    <p>Welcome to the Cortex Admin API documentation. This API provides comprehensive management capabilities for the Cortex LLM Router.</p>

    <h2>Authentication</h2>
    <p>All API endpoints require authentication using an API key. Include the key in the Authorization header:</p>
    <pre>Authorization: Bearer YOUR_API_KEY</pre>

    <h2>Endpoints</h2>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/providers
        <p>List all configured providers</p>
    </div>

    <div class="endpoint">
        <span class="method post">POST</span> /v1/providers
        <p>Create a new provider</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/providers/{id}
        <p>Get provider details</p>
    </div>

    <div class="endpoint">
        <span class="method put">PUT</span> /v1/providers/{id}
        <p>Update provider configuration</p>
    </div>

    <div class="endpoint">
        <span class="method delete">DELETE</span> /v1/providers/{id}
        <p>Delete a provider</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/users/api-keys
        <p>List all API keys</p>
    </div>

    <div class="endpoint">
        <span class="method post">POST</span> /v1/users/api-keys
        <p>Create a new API key</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/models
        <p>List available models</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/config
        <p>Get current configuration</p>
    </div>

    <div class="endpoint">
        <span class="method put">PUT</span> /v1/config
        <p>Update configuration</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/monitoring/status
        <p>Get system status</p>
    </div>

    <div class="endpoint">
        <span class="method get">GET</span> /v1/system/info
        <p>Get system information</p>
    </div>

    <h2>Rate Limiting</h2>
    <p>API requests may be rate limited to prevent abuse. Check the response headers for rate limit information.</p>

    <h2>Error Handling</h2>
    <p>Errors are returned in JSON format with consistent structure:</p>
    <pre>
{
    "error": "true",
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "timestamp": "2023-01-01T00:00:00Z"
}
</pre>

    <footer>
        <p>For more detailed information, see the API specification at <a href="/v1/specs">/v1/specs</a></p>
    </footer>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(docsHTML))
}