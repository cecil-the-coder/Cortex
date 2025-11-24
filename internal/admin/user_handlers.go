package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// APIKeyInfo represents API key information for admin API
type APIKeyInfo struct {
	ID            string     `json:"id"`
	APIKey        string     `json:"api_key,omitempty"` // Only returned during creation
	Description   string     `json:"description"`
	ModelGroups   []string   `json:"model_groups"`
	Enabled       bool       `json:"enabled"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RateLimit     *int       `json:"rate_limit,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	UsageStats    *APIKeyUsage `json:"usage_stats,omitempty"`
	Permissions   []string   `json:"permissions,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// APIKeyUsage represents API key usage statistics
type APIKeyUsage struct {
	TotalRequests      int64     `json:"total_requests"`
	TodayRequests      int64     `json:"today_requests"`
	ThisMonthRequests  int64     `json:"this_month_requests"`
	TokensInput        int64     `json:"tokens_input"`
	TokensOutput       int64     `json:"tokens_output"`
	EstimatedCost      float64   `json:"estimated_cost"`
	LastRequestTime    *time.Time `json:"last_request_time,omitempty"`
	ModelsUsed         map[string]int64 `json:"models_used,omitempty"`
	RateLimitHits      int64     `json:"rate_limit_hits,omitempty"`
}

// APIKeyCreateRequest represents a request to create a new API key
type APIKeyCreateRequest struct {
	ID          string                 `json:"id"`
	APIKey      string                 `json:"api_key,omitempty"`
	Description string                 `json:"description"`
	ModelGroups []string               `json:"model_groups"`
	Enabled     bool                   `json:"enabled"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	RateLimit   *int                   `json:"rate_limit,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	AutoGenerate string                `json:"auto_generate,omitempty"` // "random", "uuid"
}

// APIKeyUpdateRequest represents a request to update an existing API key
type APIKeyUpdateRequest struct {
	Description *string                `json:"description,omitempty"`
	ModelGroups *[]string              `json:"model_groups,omitempty"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	RateLimit   *int                   `json:"rate_limit,omitempty"`
	Permissions *[]string              `json:"permissions,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// APIKeyValidationRequest represents a request to validate an API key
type APIKeyValidationRequest struct {
	APIKey       string `json:"api_key"`
	Model        string `json:"model,omitempty"`
	CheckAccess  bool   `json:"check_access,omitempty"`
}

// APIKeyValidationResponse represents API key validation result
type APIKeyValidationResponse struct {
	Valid        bool                   `json:"valid"`
	KeyID        string                 `json:"key_id,omitempty"`
	Permissions  []string               `json:"permissions,omitempty"`
	ModelGroups  []string               `json:"model_groups,omitempty"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
	AccessInfo   map[string]interface{} `json:"access_info,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
}

// handleListAPIKeys handles GET /v1/users/api-keys
func (a *AdminServer) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	page, perPage, err := a.parsePagination(r)
	if err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_pagination", "Invalid pagination parameters")
		return
	}

	filter := a.parseFilterOptions(r)

	// Get configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ClientAPIKeys == nil {
		a.sendResponse(w, http.StatusOK, []APIKeyInfo{}, nil, nil)
		return
	}

	var apiKeys []APIKeyInfo
	now := time.Now()

	for keyID, keyConfig := range *cfg.ClientAPIKeys {
		// Apply filters
		if filter.Status != "" {
			isExpired := !keyConfig.ExpiresAt.IsZero() && now.After(keyConfig.ExpiresAt)
			if filter.Status == "active" && (!keyConfig.Enabled || isExpired) {
				continue
			}
			if filter.Status == "inactive" && keyConfig.Enabled && !isExpired {
				continue
			}
			if filter.Status == "expired" && !isExpired {
				continue
			}
		}

		if filter.Query != "" {
			query := strings.ToLower(filter.Query)
			if !strings.Contains(strings.ToLower(keyID), query) &&
				!strings.Contains(strings.ToLower(keyConfig.Description), query) {
				continue
			}
		}

		// Convert to API key info
		keyInfo := APIKeyInfo{
			ID:          keyID,
			Description: keyConfig.Description,
			ModelGroups: keyConfig.ModelGroups,
			Enabled:     keyConfig.Enabled,
			RateLimit:   &keyConfig.RateLimit,
			CreatedAt:   time.Now(), // Would track actual creation time
			UpdatedAt:   time.Now(), // Would track actual update time
			Permissions: []string{"api_access"}, // Default permissions
			Tags:        []string{}, // Could be added to config
			Metadata:    make(map[string]interface{}),
		}

		if !keyConfig.ExpiresAt.IsZero() {
			keyInfo.ExpiresAt = &keyConfig.ExpiresAt
		}

		apiKeys = append(apiKeys, keyInfo)
	}

	// Apply sorting
	if filter.SortBy != "" {
		a.sortAPIKeys(apiKeys, filter.SortBy, filter.SortDesc)
	}

	// Apply pagination
	total := len(apiKeys)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedKeys := apiKeys[start:end]

	paging := &PagingInfo{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: (total + perPage - 1) / perPage,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"total_keys": total,
			"filter_applied": filter.Query != "",
		},
	}

	a.sendResponse(w, http.StatusOK, paginatedKeys, paging, meta)
	a.logAccess(r, "LIST_API_KEYS", "api_keys", "", true)
}

// handleGetAPIKey handles GET /v1/users/api-keys/{id}
func (a *AdminServer) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "API key ID is required")
		return
	}

	// Get API key configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ClientAPIKeys == nil {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	keyConfig, exists := (*cfg.ClientAPIKeys)[keyID]
	if !exists {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	// Convert to response format
	keyInfo := APIKeyInfo{
		ID:          keyID,
		Description: keyConfig.Description,
		ModelGroups: keyConfig.ModelGroups,
		Enabled:     keyConfig.Enabled,
		RateLimit:   &keyConfig.RateLimit,
		CreatedAt:   time.Now(), // Would track actual creation time
		UpdatedAt:   time.Now(), // Would track actual update time
		Permissions: []string{"api_access"},
		Tags:        []string{},
		Metadata:    make(map[string]interface{}),
	}

	if !keyConfig.ExpiresAt.IsZero() {
		keyInfo.ExpiresAt = &keyConfig.ExpiresAt
	}

	// Get usage statistics (placeholder - would need actual usage tracking)
	keyInfo.UsageStats = &APIKeyUsage{
		TotalRequests:     0,
		TodayRequests:     0,
		ThisMonthRequests: 0,
		TokensInput:       0,
		TokensOutput:      0,
		EstimatedCost:     0,
		ModelsUsed:        make(map[string]int64),
		RateLimitHits:     0,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, keyInfo, nil, meta)
	a.logAccess(r, "GET_API_KEY", "api_key", keyID, true)
}

// handleCreateAPIKey handles POST /v1/users/api-keys
func (a *AdminServer) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req APIKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate request
	if err := a.validateAPIKeyCreateRequest(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Check if API key ID already exists
	cfg := a.configFunc()
	if cfg != nil && cfg.ClientAPIKeys != nil {
		if _, exists := (*cfg.ClientAPIKeys)[req.ID]; exists {
			a.sendError(w, http.StatusConflict, "api_key_exists", "API key with this ID already exists")
			a.logAccess(r, "CREATE_API_KEY", "api_key", req.ID, false)
			return
		}
	}

	// Generate API key if not provided
	apiKey := ""
	if req.APIKey != "" {
		apiKey = req.APIKey
	} else {
		generatedKey, err := a.generateAPIKey(req.AutoGenerate)
		if err != nil {
			a.sendError(w, http.StatusInternalServerError, "generation_failed", "Failed to generate API key")
			return
		}
		apiKey = generatedKey
	}

	// Create API key configuration
	newKeyConfig := &config.APIKeyConfig{
		APIKey:      apiKey,
		Description: req.Description,
		ModelGroups: req.ModelGroups,
		Enabled:     req.Enabled,
	}

	if req.ExpiresAt != nil {
		newKeyConfig.ExpiresAt = *req.ExpiresAt
	}
	if req.RateLimit != nil {
		newKeyConfig.RateLimit = *req.RateLimit
	}

	// Add to configuration
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "config_unavailable", "Configuration not available")
		return
	}

	err := cfg.AddClientAPIKey(req.ID, newKeyConfig)
	if err != nil {
		a.sendError(w, http.StatusInternalServerError, "creation_failed", "Failed to create API key: "+err.Error())
		a.logAccess(r, "CREATE_API_KEY", "api_key", req.ID, false)
		return
	}

	// Save configuration
	configPath := a.server.GetConfigPath()
	if configPath != "" {
		if err := config.Save(cfg, configPath, true); err != nil {
			// Rollback
			cfg.RemoveClientAPIKey(req.ID)
			a.sendError(w, http.StatusInternalServerError, "save_failed", "Failed to save configuration: "+err.Error())
			a.logAccess(r, "CREATE_API_KEY", "api_key", req.ID, false)
			return
		}
	}

	// Create response
	keyInfo := APIKeyInfo{
		ID:          req.ID,
		APIKey:      apiKey, // Only return full key during creation
		Description: req.Description,
		ModelGroups: req.ModelGroups,
		Enabled:     req.Enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Permissions: req.Permissions,
		Tags:        req.Tags,
		Metadata:    req.Metadata,
	}

	if req.ExpiresAt != nil {
		keyInfo.ExpiresAt = req.ExpiresAt
	}
	if req.RateLimit != nil {
		keyInfo.RateLimit = req.RateLimit
	}

	response := map[string]interface{}{
		"message": "API key created successfully",
		"api_key": keyInfo,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusCreated, response, nil, meta)
	a.logAccess(r, "CREATE_API_KEY", "api_key", req.ID, true)
}

// handleUpdateAPIKey handles PUT /v1/users/api-keys/{id}
func (a *AdminServer) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "API key ID is required")
		return
	}

	var req APIKeyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Get existing API key configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ClientAPIKeys == nil {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	keyConfig, exists := (*cfg.ClientAPIKeys)[keyID]
	if !exists {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	// Apply updates
	if req.Description != nil {
		keyConfig.Description = *req.Description
	}
	if req.ModelGroups != nil {
		keyConfig.ModelGroups = *req.ModelGroups
	}
	if req.Enabled != nil {
		keyConfig.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		if req.ExpiresAt.IsZero() {
			keyConfig.ExpiresAt = time.Time{}
		} else {
			keyConfig.ExpiresAt = *req.ExpiresAt
		}
	}
	if req.RateLimit != nil {
		keyConfig.RateLimit = *req.RateLimit
	}

	// Validate updated configuration
	if err := cfg.Validate(); err != nil {
		a.sendError(w, http.StatusBadRequest, "validation_error", "Invalid configuration: "+err.Error())
		return
	}

	// Save configuration
	configPath := a.server.GetConfigPath()
	if configPath != "" {
		if err := config.Save(cfg, configPath, true); err != nil {
			a.sendError(w, http.StatusInternalServerError, "save_failed", "Failed to save configuration: "+err.Error())
			return
		}
	}

	// Create response
	keyInfo := APIKeyInfo{
		ID:          keyID,
		Description: keyConfig.Description,
		ModelGroups: keyConfig.ModelGroups,
		Enabled:     keyConfig.Enabled,
		RateLimit:   &keyConfig.RateLimit,
		UpdatedAt:   time.Now(),
		Tags:        req.Tags,
		Metadata:    req.Metadata,
	}

	if !keyConfig.ExpiresAt.IsZero() {
		keyInfo.ExpiresAt = &keyConfig.ExpiresAt
	}

	response := map[string]interface{}{
		"message": "API key updated successfully",
		"api_key": keyInfo,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "UPDATE_API_KEY", "api_key", keyID, true)
}

// handleDeleteAPIKey handles DELETE /v1/users/api-keys/{id}
func (a *AdminServer) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "API key ID is required")
		return
	}

	// Get configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ClientAPIKeys == nil {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	// Check if API key exists
	_, exists := (*cfg.ClientAPIKeys)[keyID]
	if !exists {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		a.logAccess(r, "DELETE_API_KEY", "api_key", keyID, false)
		return
	}

	// Remove API key
	err := cfg.RemoveClientAPIKey(keyID)
	if err != nil {
		a.sendError(w, http.StatusInternalServerError, "deletion_failed", "Failed to delete API key: "+err.Error())
		return
	}

	// Save configuration
	configPath := a.server.GetConfigPath()
	if configPath != "" {
		if err := config.Save(cfg, configPath, true); err != nil {
			a.sendError(w, http.StatusInternalServerError, "save_failed", "Failed to save configuration: "+err.Error())
			return
		}
	}

	response := map[string]interface{}{
		"message":     "API key deleted successfully",
		"api_key_id":  keyID,
		"deleted_at":  time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "DELETE_API_KEY", "api_key", keyID, true)
}

// handleGetAPIKeyUsage handles GET /v1/users/api-keys/{id}/usage
func (a *AdminServer) handleGetAPIKeyUsage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "API key ID is required")
		return
	}

	// Validate API key exists
	cfg := a.configFunc()
	if cfg == nil || cfg.ClientAPIKeys == nil {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	_, exists := (*cfg.ClientAPIKeys)[keyID]
	if !exists {
		a.sendError(w, http.StatusNotFound, "api_key_not_found", "API key not found")
		return
	}

	// Get usage statistics (placeholder - would need actual usage tracking)
	usageStats := APIKeyUsage{
		TotalRequests:     0,
		TodayRequests:     0,
		ThisMonthRequests: 0,
		TokensInput:       0,
		TokensOutput:      0,
		EstimatedCost:     0,
		ModelsUsed:        make(map[string]int64),
		RateLimitHits:     0,
	}

	// Get date range from query parameters
	dateFrom := r.URL.Query().Get("date_from")
	dateTo := r.URL.Query().Get("date_to")

	response := map[string]interface{}{
		"api_key_id": keyID,
		"usage":      usageStats,
		"date_from":  dateFrom,
		"date_to":    dateTo,
		"generated_at": time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"note": "Usage statistics tracking is not implemented yet",
		},
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_API_KEY_USAGE", "api_key", keyID, true)
}

// handleValidateAPIKey handles POST /v1/users/api-keys/validate
func (a *AdminServer) handleValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req APIKeyValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	if req.APIKey == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "API key is required")
		return
	}

	cfg := a.configFunc()

	// Validate API key format
	formatValid := a.validateAPIKeyFormat(req.APIKey)

	// Check if API key exists and is valid
	var keyConfig *config.APIKeyConfig
	var keyID string
	var valid bool

	if cfg != nil && cfg.ClientAPIKeys != nil {
		for id, config := range *cfg.ClientAPIKeys {
			if config.APIKey == req.APIKey {
				keyID = id
				keyConfig = config
				// Check if enabled and not expired
				now := time.Now()
				if config.Enabled && (config.ExpiresAt.IsZero() || now.Before(config.ExpiresAt)) {
					valid = true
				}
				break
			}
		}
	}

	response := APIKeyValidationResponse{
		Valid: formatValid && valid,
	}

	if valid {
		response.KeyID = keyID
		response.ModelGroups = keyConfig.ModelGroups
		response.Permissions = []string{"api_access"} // Default permissions
		if !keyConfig.ExpiresAt.IsZero() {
			response.ExpiresAt = &keyConfig.ExpiresAt
		}

		// Check model access if requested
		if req.CheckAccess && req.Model != "" && a.accessManager != nil {
			accessInfo, err := a.accessManager.CanAccessModel(r.Context(), req.APIKey, req.Model)
			response.AccessInfo = map[string]interface{}{
				"can_access": err == nil,
				"access_info": accessInfo,
				"error": func() string {
					if err != nil {
						return err.Error()
					}
					return ""
				}(),
			}

			if err != nil {
				response.Warnings = append(response.Warnings, "Model access check failed: "+err.Error())
			}
		}
	} else if formatValid {
		response.KeyID = "<unknown>"
		response.Warnings = append(response.Warnings, "API key format is valid but key not found or invalid")
	} else {
		response.Warnings = append(response.Warnings, "API key format is invalid")
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "VALIDATE_API_KEY", "api_key", func() string {
		if response.KeyID != "" {
			return response.KeyID
		}
		return "<unknown>"
	}(), response.Valid)
}

// handleBulkAPIKeyOperations handles POST /v1/users/api-keys/bulk
func (a *AdminServer) handleBulkAPIKeyOperations(w http.ResponseWriter, r *http.Request) {
	var req BulkOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	results := make([]BulkOperationResult, len(req.Items))
	successful := 0
	failed := 0
	var errors []string

	cfg := a.configFunc()

	for i, item := range req.Items {
		result := BulkOperationResult{
			Index: i,
			Success: false,
		}

		// Process based on action type
		switch req.Action {
		case "validate":
			// Handle validation
			if apiKeyData, ok := item.(map[string]interface{}); ok {
				apiKey, _ := apiKeyData["api_key"].(string)
				if apiKey != "" {
					valid := a.validateAPIKeyFormat(apiKey)
					result.Success = valid
					if valid {
						successful++
					} else {
						failed++
						result.Error = "Invalid API key format"
					}
				} else {
					failed++
					result.Error = "Missing API key"
				}
			}
		case "enable", "disable":
			// Handle enable/disable operations
			if keyData, ok := item.(map[string]interface{}); ok {
				keyID, _ := keyData["id"].(string)
				if keyID != "" && cfg != nil && cfg.ClientAPIKeys != nil {
					if keyConfig, exists := (*cfg.ClientAPIKeys)[keyID]; exists {
						keyConfig.Enabled = (req.Action == "enable")
						result.Success = true
						result.ID = keyID
						successful++
					} else {
						failed++
						result.Error = "API key not found"
					}
				} else {
					failed++
					result.Error = "Missing API key ID"
				}
			}
		default:
			failed++
			result.Error = "Unsupported action: " + req.Action
		}

		results[i] = result
	}

	// Save configuration if there were changes
	if successful > 0 && (req.Action == "enable" || req.Action == "disable") {
		configPath := a.server.GetConfigPath()
		if configPath != "" {
			config.Save(cfg, configPath, true)
		}
	}

	response := BulkOperationResponse{
		Success:    successful > 0,
		Total:      len(req.Items),
		Successful: successful,
		Failed:     failed,
		Results:    results,
		Errors:     errors,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
	}

	a.sendResponse(w, http.StatusOK, response, nil, nil)
	a.logAccess(r, "BULK_API_KEY_OPERATIONS", "api_keys", req.Action, response.Success)
}

// Helper methods

// generateAPIKey generates a new API key
func (a *AdminServer) generateAPIKey(method string) (string, error) {
	if method == "uuid" {
		// Generate UUID-based API key
		return "sk-" + generateUUID(), nil
	}

	// Default random generation (similar to server implementation)
	return generateAPIKey(""), nil
}

// validateAPIKeyCreateRequest validates API key creation request
func (a *AdminServer) validateAPIKeyCreateRequest(req *APIKeyCreateRequest) error {
	if req.ID == "" {
		return fmt.Errorf("API key ID is required")
	}

	if !a.isValidKeyID(req.ID) {
		return fmt.Errorf("API key ID must contain only alphanumeric characters, hyphens, and underscores")
	}

	if req.APIKey != "" && !a.validateAPIKeyFormat(req.APIKey) {
		return fmt.Errorf("Invalid API key format")
	}

	if req.RateLimit != nil && *req.RateLimit < 0 {
		return fmt.Errorf("Rate limit cannot be negative")
	}

	if req.ExpiresAt != nil && !req.ExpiresAt.IsZero() && req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("Expiration date cannot be in the past")
	}

	return nil
}

// validateAPIKeyFormat validates API key format
func (a *AdminServer) validateAPIKeyFormat(apiKey string) bool {
	if len(apiKey) < 8 {
		return false
	}

	// Basic validation: allow alphanumeric, hyphens, underscores
	for _, char := range apiKey {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// isValidKeyID validates API key ID format
func (a *AdminServer) isValidKeyID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}

	for _, char := range id {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// sortAPIKeys sorts API keys based on the specified field
func (a *AdminServer) sortAPIKeys(apiKeys []APIKeyInfo, sortBy string, desc bool) {
	// Simple bubble sort for demonstration
	for i := 0; i < len(apiKeys)-1; i++ {
		for j := i + 1; j < len(apiKeys); j++ {
			shouldSwap := false

			switch sortBy {
			case "id":
				if desc {
					shouldSwap = apiKeys[i].ID < apiKeys[j].ID
				} else {
					shouldSwap = apiKeys[i].ID > apiKeys[j].ID
				}
			case "description":
				if desc {
					shouldSwap = apiKeys[i].Description < apiKeys[j].Description
				} else {
					shouldSwap = apiKeys[i].Description > apiKeys[j].Description
				}
			case "created_at":
				if desc {
					shouldSwap = apiKeys[i].CreatedAt.Before(apiKeys[j].CreatedAt)
				} else {
					shouldSwap = apiKeys[i].CreatedAt.After(apiKeys[j].CreatedAt)
				}
			case "enabled":
				if desc {
					shouldSwap = !apiKeys[i].Enabled && apiKeys[j].Enabled
				} else {
					shouldSwap = apiKeys[i].Enabled && !apiKeys[j].Enabled
				}
			default:
				// Default sort by ID
				if desc {
					shouldSwap = apiKeys[i].ID < apiKeys[j].ID
				} else {
					shouldSwap = apiKeys[i].ID > apiKeys[j].ID
				}
			}

			if shouldSwap {
				apiKeys[i], apiKeys[j] = apiKeys[j], apiKeys[i]
			}
		}
	}
}