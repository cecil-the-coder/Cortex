package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"crypto/rand"
	"encoding/hex"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/access"
)

// Admin API endpoint for managing API keys and model groups

// APIKeyListResponse represents the response for listing API keys
type APIKeyListResponse struct {
	Success   bool                    `json:"success"`
	APIKeys   map[string]APIKeyInfo   `json:"api_keys"`
	Count     int                     `json:"count"`
	Timestamp string                  `json:"timestamp"`
}

// APIKeyInfo represents API key information without exposing the actual key
type APIKeyInfo struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	ModelGroups []string  `json:"model_groups,omitempty"`
	ExpiresAt   *string   `json:"expires_at,omitempty"` // Pointer for null/omission
	RateLimit   *int      `json:"rate_limit,omitempty"` // Pointer for null/omission
	Enabled     bool      `json:"enabled"`
	CreatedAt   string    `json:"created_at,omitempty"`
	KeyPreview  string    `json:"key_preview,omitempty"` // First 4 chars + "..."

}

// APIKeyCreateRequest represents a request to create a new API key
type APIKeyCreateRequest struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	ModelGroups []string `json:"model_groups,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`   // ISO 8601 format
	RateLimit   int      `json:"rate_limit,omitempty"`   // Requests per second (0 = unlimited)
	Enabled     bool     `json:"enabled"`                 // Default: true
	APIKey      string   `json:"api_key,omitempty"`       // Optional: auto-generated if not provided
}

// APIKeyUpdateRequest represents a request to update an API key
type APIKeyUpdateRequest struct {
	Description *string  `json:"description,omitempty"`  // Use pointers for optional updates
	ModelGroups *[]string `json:"model_groups,omitempty"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
	RateLimit   *int     `json:"rate_limit,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
}

// APIKeyUsageResponse represents usage statistics for an API key
type APIKeyUsageResponse struct {
	Success        bool                   `json:"success"`
	KeyID          string                 `json:"key_id"`
	Usage          map[string]interface{} `json:"usage"`
	AvailableModels []string              `json:"available_models"`
	AccessibleGroups []string             `json:"accessible_groups"`
	Timestamp      string                 `json:"timestamp"`
}

// ModelGroupListResponse represents the response for listing model groups
type ModelGroupListResponse struct {
	Success     bool                    `json:"success"`
	ModelGroups map[string]ModelGroupInfo `json:"model_groups"`
	Count       int                     `json:"count"`
	Timestamp   string                  `json:"timestamp"`
}

// ModelGroupInfo represents model group information
type ModelGroupInfo struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	ModelCount  int                     `json:"model_count"`
	Models      []ModelReferenceInfo    `json:"models"`
	Aliases     map[string]string       `json:"aliases,omitempty"` // alias -> actual model mapping
}

// ModelReferenceInfo represents a model reference within a group
type ModelReferenceInfo struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Alias    string `json:"alias,omitempty"`
}

// ModelGroupCreateRequest represents a request to create a new model group
type ModelGroupCreateRequest struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Models      []config.ModelReference  `json:"models"`
}

// ModelGroupUpdateRequest represents a request to update a model group
type ModelGroupUpdateRequest struct {
	Description *string                  `json:"description,omitempty"`
	Models      *[]config.ModelReference `json:"models,omitempty"`
}

// AccessCheckRequest represents a request to check model access
type AccessCheckRequest struct {
	APIKey string `json:"api_key"`
	Model  string `json:"model"`
}

// AccessCheckResponse represents the response for model access check
type AccessCheckResponse struct {
	Success       bool                   `json:"success"`
	HasAccess     bool                   `json:"has_access"`
	APIKey        string                 `json:"api_key,omitempty"`
	Model         string                 `json:"model"`
	ResolvedModel string                 `json:"resolved_model,omitempty"`
	Provider      string                 `json:"provider,omitempty"`
	ModelGroup    string                 `json:"model_group,omitempty"`
	ResolvedBy    string                 `json:"resolved_by,omitempty"`
	Reason        string                 `json:"reason,omitempty"`
	Timestamp     string                 `json:"timestamp"`
}

// AccessControl interface to abstract config operations
type AccessControl interface {
	GetClientAPIKey(keyID string) (*config.APIKeyConfig, error)
	AddClientAPIKey(keyID string, keyConfig *config.APIKeyConfig) error
	RemoveClientAPIKey(keyID string) error
	GetModelGroup(groupName string) (*config.ModelGroup, error)
	AddModelGroup(groupName string, group *config.ModelGroup) error
	RemoveModelGroup(groupName string) error
	GetAvailableModelGroups() []string
	GetModelsInGroup(groupName string) ([]config.ModelReference, error)
	ValidateClientAPIKey(apiKey string) (*config.APIKeyConfig, error)
	CanAPIKeyAccessGroup(keyConfig *config.APIKeyConfig, groupName string) bool
	GetModelReferenceByAlias(alias string) (*config.ModelReference, error)
}

// ServeAdminAPIKeys handles GET /admin/api-keys (list all API keys)
func (s *Server) ServeAdminAPIKeys(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Get current configuration (should be injected or available via dependencies)
	// For now, we'll access it through the access manager if available
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Get API keys
	var apiKeys map[string]APIKeyInfo

	if cfg != nil && cfg.ClientAPIKeys != nil {
		apiKeys = make(map[string]APIKeyInfo)

		for keyID, keyConfig := range *cfg.ClientAPIKeys {
			keyInfo := APIKeyInfo{
				ID:          keyID,
				Description: keyConfig.Description,
				ModelGroups: keyConfig.ModelGroups,
				Enabled:     keyConfig.Enabled,
				KeyPreview:  s.maskAPIKey(keyConfig.APIKey),
			}

			// Handle optional fields
			if !keyConfig.ExpiresAt.IsZero() {
				expiresAt := keyConfig.ExpiresAt.UTC().Format(time.RFC3339)
				keyInfo.ExpiresAt = &expiresAt
			}

			if keyConfig.RateLimit > 0 {
				keyInfo.RateLimit = &keyConfig.RateLimit
			}

			apiKeys[keyID] = keyInfo
		}
	}

	response := APIKeyListResponse{
		Success:   true,
		APIKeys:   apiKeys,
		Count:     len(apiKeys),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAPIKeyCreate handles POST /admin/api-keys (create new API key)
func (s *Server) ServeAdminAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Parse request body
	var req APIKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Validate request
	if err := s.validateAPIKeyCreateRequest(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Generate API key if not provided
	apiKey := req.APIKey
	if apiKey == "" {
		var err error
		apiKey, err = s.generateAPIKey()
		if err != nil {
			s.sendError(w, http.StatusInternalServerError, "generation_error", "Failed to generate API key")
			return
		}
	}

	// Parse expiration date
	var expiresAt time.Time
	if req.ExpiresAt != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			s.sendError(w, http.StatusBadRequest, "validation_error", "Invalid expiration date format. Use ISO 8601 format.")
			return
		}
		if !expiresAt.IsZero() && expiresAt.Before(time.Now()) {
			s.sendError(w, http.StatusBadRequest, "validation_error", "Expiration date cannot be in the past")
			return
		}
	}

	// Create API key config
	keyConfig := &config.APIKeyConfig{
		APIKey:      apiKey,
		Description: req.Description,
		ModelGroups: req.ModelGroups,
		ExpiresAt:   expiresAt,
		RateLimit:   req.RateLimit,
		Enabled:     req.Enabled,
	}

	// Validate model groups before adding to configuration
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Check if all model groups exist
	if err := s.validateAPIKeyModelGroups(req.ModelGroups, cfg); err != nil {
		s.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	err := cfg.AddClientAPIKey(req.ID, keyConfig)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.sendError(w, http.StatusConflict, "conflict_error", err.Error())
		} else {
			s.sendError(w, http.StatusInternalServerError, "creation_error", err.Error())
		}
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		// Rollback the change
		_ = cfg.RemoveClientAPIKey(req.ID)
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	// Return created key info
	response := struct {
		Success   bool      `json:"success"`
		KeyID     string    `json:"key_id"`
		APIKey    string    `json:"api_key"` // Return full key only during creation
		Timestamp string    `json:"timestamp"`
		Message   string    `json:"message"`
	}{
		Success:   true,
		KeyID:     req.ID,
		APIKey:    apiKey,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "API key created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAPIKeyUpdate handles PUT /admin/api-keys/{id} (update API key)
func (s *Server) ServeAdminAPIKeyUpdate(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPut {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only PUT method is allowed")
		return
	}

	// Extract key ID from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "API key ID is required")
		return
	}
	keyID := pathParts[2]

	// Parse request body
	var req APIKeyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Get access control interface
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Get existing API key config
	keyConfig, err := cfg.GetClientAPIKey(keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Update fields if provided
	if req.Description != nil {
		keyConfig.Description = *req.Description
	}
	if req.ModelGroups != nil {
		keyConfig.ModelGroups = *req.ModelGroups
	}
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			keyConfig.ExpiresAt = time.Time{} // Clear expiration
		} else {
			expiresAt, parseErr := time.Parse(time.RFC3339, *req.ExpiresAt)
			if parseErr != nil {
				s.sendError(w, http.StatusBadRequest, "validation_error", "Invalid expiration date format. Use ISO 8601 format.")
				return
			}
			if !expiresAt.IsZero() && expiresAt.Before(time.Now()) {
				s.sendError(w, http.StatusBadRequest, "validation_error", "Expiration date cannot be in the past")
				return
			}
			keyConfig.ExpiresAt = expiresAt
		}
	}
	if req.RateLimit != nil {
		keyConfig.RateLimit = *req.RateLimit
	}
	if req.Enabled != nil {
		keyConfig.Enabled = *req.Enabled
	}

	// Validate updated configuration
	if err := cfg.Validate(); err != nil {
		s.sendError(w, http.StatusBadRequest, "validation_error", fmt.Sprintf("Invalid configuration: %v", err))
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	// Return updated key info
	keyInfo := APIKeyInfo{
		ID:          keyID,
		Description: keyConfig.Description,
		ModelGroups: keyConfig.ModelGroups,
		Enabled:     keyConfig.Enabled,
		KeyPreview:  s.maskAPIKey(keyConfig.APIKey),
	}

	if !keyConfig.ExpiresAt.IsZero() {
		expiresAt := keyConfig.ExpiresAt.UTC().Format(time.RFC3339)
		keyInfo.ExpiresAt = &expiresAt
	}
	if keyConfig.RateLimit > 0 {
		keyInfo.RateLimit = &keyConfig.RateLimit
	}

	response := struct {
		Success   bool      `json:"success"`
		KeyInfo   APIKeyInfo `json:"key_info"`
		Timestamp string    `json:"timestamp"`
		Message   string    `json:"message"`
	}{
		Success:   true,
		KeyInfo:   keyInfo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "API key updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAPIKeyDelete handles DELETE /admin/api-keys/{id} (delete/disable API key)
func (s *Server) ServeAdminAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodDelete {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only DELETE method is allowed")
		return
	}

	// Extract key ID from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "API key ID is required")
		return
	}
	keyID := pathParts[2]

	// Get configuration
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Check if key exists
	_, err := cfg.GetClientAPIKey(keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Remove the key
	err = cfg.RemoveClientAPIKey(keyID)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "deletion_error", err.Error())
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	response := struct {
		Success   bool   `json:"success"`
		KeyID     string `json:"key_id"`
		Timestamp string `json:"timestamp"`
		Message   string `json:"message"`
	}{
		Success:   true,
		KeyID:     keyID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "API key deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAPIKeyValidate handles POST /admin/api-keys/validate (validate API key format and existence)
func (s *Server) ServeAdminAPIKeyValidate(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Parse request body
	var req struct {
		APIKey string `json:"api_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	if req.APIKey == "" {
		s.sendError(w, http.StatusBadRequest, "validation_error", "API key is required")
		return
	}

	// Validate API key format
	formatValid := s.validateAPIKeyFormat(req.APIKey)

	// Check if API key exists in configuration
	var keyConfig *config.APIKeyConfig
	var keyID string
	cfg := s.getConfig()

	if cfg != nil && cfg.ClientAPIKeys != nil {
		for id, config := range *cfg.ClientAPIKeys {
			if config.APIKey == req.APIKey {
				keyConfig = config
				keyID = id
				break
			}
		}
	}

	exists := keyConfig != nil

	// Validate the API key using the access manager
	accessValid := false
	var accessError string
	if am := s.getAccessManager(); am != nil {
		if accessManager, ok := am.(*access.AccessManager); ok {
			validatedConfig, err := accessManager.ValidateAPIKey(req.APIKey)
			if err == nil {
				// Additional checks for enabled status and expiration
				if validatedConfig.Enabled && (validatedConfig.ExpiresAt.IsZero() || time.Now().Before(validatedConfig.ExpiresAt)) {
					accessValid = true
				} else {
					if !validatedConfig.Enabled {
						accessError = "API key is disabled"
					} else {
						accessError = "API key has expired"
					}
				}
			} else {
				accessError = err.Error()
			}
		}
	}

	response := struct {
		Success       bool   `json:"success"`
		APIKey        string `json:"api_key,omitempty"`
		FormatValid   bool   `json:"format_valid"`
		Exists        bool   `json:"exists"`
		AccessValid   bool   `json:"access_valid,omitempty"`
		KeyID         string `json:"key_id,omitempty"`
		AccessError   string `json:"access_error,omitempty"`
		Timestamp     string `json:"timestamp"`
	}{
		Success:     true,
		FormatValid: formatValid,
		Exists:      exists,
		AccessValid: accessValid,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	if exists {
		response.APIKey = s.maskAPIKey(req.APIKey)
		response.KeyID = keyID
	}

	if accessError != "" {
		response.AccessError = accessError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAPIKeyUsage handles GET /admin/api-keys/{id}/usage (get API key usage statistics)
func (s *Server) ServeAdminAPIKeyUsage(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Extract key ID from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "API key ID is required")
		return
	}
	keyID := pathParts[2]

	// Get configuration
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Get API key config
	keyConfig, err := cfg.GetClientAPIKey(keyID)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Get usage statistics (placeholder - would need to integrate with actual usage tracking)
	usage := map[string]interface{}{
		"requests_today":    0,
		"requests_this_month": 0,
		"total_requests":    0,
		"last_used":         nil,
		"rate_limit_current": keyConfig.RateLimit,
	}

	// Get available models for this key
	var availableModels []string
	var accessibleGroups []string

	if am := s.getAccessManager(); am != nil {
		if accessManager, ok := am.(*access.AccessManager); ok {
			models, err := accessManager.GetAvailableModels(keyConfig.APIKey)
			if err == nil {
				availableModels = models
			}
			accessibleGroups = keyConfig.ModelGroups
		}
	} else {
		// Fallback to basic group listing if access manager not available
		accessibleGroups = keyConfig.ModelGroups
	}

	response := APIKeyUsageResponse{
		Success:           true,
		KeyID:             keyID,
		Usage:             usage,
		AvailableModels:   availableModels,
		AccessibleGroups:  accessibleGroups,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper methods

// authenticateAdminRequest checks if the request has proper admin authentication
func (s *Server) authenticateAdminRequest(r *http.Request) bool {
	// For now, use the existing main API key for admin operations
	// In the future, this could be enhanced with dedicated admin keys

	// Extract API key from request
	apiKey := s.extractAPIKey(r)
	if apiKey == "" {
		return false
	}

	// Validate against main admin key
	cfg := s.getConfig()
	if cfg != nil && cfg.APIKEY != "" {
		// Support both direct match and environment variable match
		if apiKey == cfg.APIKEY {
			return true
		}
	}

	return false
}

// extractAPIKey extracts API key from request headers or query parameters
func (s *Server) extractAPIKey(r *http.Request) string {
	// Check Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return strings.TrimSpace(parts[1])
		}
	}

	// Check x-api-key header
	apiKey := r.Header.Get("x-api-key")
	if apiKey != "" {
		return strings.TrimSpace(apiKey)
	}

	// Check query parameter
	return r.URL.Query().Get("api_key")
}

// validateAPIKeyCreateRequest validates API key creation request
func (s *Server) validateAPIKeyCreateRequest(req *APIKeyCreateRequest) error {
	if req.ID == "" {
		return fmt.Errorf("API key ID is required")
	}

	// Validate ID format (alphanumeric, hyphens, underscores)
	if !s.isValidKeyID(req.ID) {
		return fmt.Errorf("API key ID must contain only alphanumeric characters, hyphens, and underscores")
	}

	if req.APIKey != "" && !s.validateAPIKeyFormat(req.APIKey) {
		return fmt.Errorf("Invalid API key format. API key must be at least 8 characters long and contain only valid characters")
	}

	if req.RateLimit < 0 {
		return fmt.Errorf("Rate limit cannot be negative")
	}

	return nil
}

// validateAPIKeyModelGroups validates that all model groups exist
func (s *Server) validateAPIKeyModelGroups(modelGroups []string, cfg *config.Config) error {
	for _, groupName := range modelGroups {
		if cfg.ModelGroups == nil {
			return fmt.Errorf("model group '%s' does not exist (no model groups configured)", groupName)
		}

		if _, exists := (*cfg.ModelGroups)[groupName]; !exists {
			return fmt.Errorf("model group '%s' does not exist", groupName)
		}
	}
	return nil
}

// validateAPIKeyFormat validates the format of an API key
func (s *Server) validateAPIKeyFormat(apiKey string) bool {
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
func (s *Server) isValidKeyID(id string) bool {
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

// generateAPIKey generates a new random API key
func (s *Server) generateAPIKey() (string, error) {
	bytes := make([]byte, 24) // 192 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(bytes), nil
}

// maskAPIKey returns a masked version of the API key for display
func (s *Server) maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return strings.Repeat("*", len(apiKey))
	}
	return apiKey[:4] + strings.Repeat("*", len(apiKey)-8) + apiKey[len(apiKey)-4:]
}

// getAccessControl returns an AccessControl interface implementation
func (s *Server) getAccessControl() AccessControl {
	cfg := s.getConfig()
	am := s.getAccessManager()
	if cfg != nil && am != nil {
		return &configAccessControl{am: am, cfg: cfg}
	}
	return nil
}

// getAccessManager returns the access manager if available
func (s *Server) getAccessManager() interface{} {
	return s.accessManager
}

// getConfig returns the current configuration
func (s *Server) getConfig() *config.Config {
	if s.configFunc != nil {
		return s.configFunc()
	}
	return nil
}

// saveConfiguration saves the current configuration with backup
func (s *Server) saveConfiguration(backup bool) error {
	// Try to get the current configuration and save it
	cfg := s.getConfig()
	if cfg == nil {
		return fmt.Errorf("configuration not available")
	}

	// Use the server's config path or determine it
	configPath := ""
	if s.config != nil && s.config.ConfigPath != "" {
		configPath = s.config.ConfigPath
	} else {
		// Try to get config path from the access manager's current configuration
		// This is a fallback - ideally the configPath should be passed to the server
		return fmt.Errorf("config path not available - please set ConfigPath in server configuration")
	}

	// Save using the config package Save function
	return config.Save(cfg, configPath, backup)
}

// configAccessControl implements AccessControl interface using config and access manager
type configAccessControl struct {
	am  interface{} // *access.AccessManager
	cfg *config.Config
}

func (c *configAccessControl) GetClientAPIKey(keyID string) (*config.APIKeyConfig, error) {
	return c.cfg.GetClientAPIKey(keyID)
}

func (c *configAccessControl) AddClientAPIKey(keyID string, keyConfig *config.APIKeyConfig) error {
	return c.cfg.AddClientAPIKey(keyID, keyConfig)
}

func (c *configAccessControl) RemoveClientAPIKey(keyID string) error {
	return c.cfg.RemoveClientAPIKey(keyID)
}

func (c *configAccessControl) GetModelGroup(groupName string) (*config.ModelGroup, error) {
	return c.cfg.GetModelGroup(groupName)
}

func (c *configAccessControl) AddModelGroup(groupName string, group *config.ModelGroup) error {
	return c.cfg.AddModelGroup(groupName, group)
}

func (c *configAccessControl) RemoveModelGroup(groupName string) error {
	return c.cfg.RemoveModelGroup(groupName)
}

func (c *configAccessControl) GetAvailableModelGroups() []string {
	return c.cfg.GetAvailableModelGroups()
}

func (c *configAccessControl) GetModelsInGroup(groupName string) ([]config.ModelReference, error) {
	return c.cfg.GetModelsInGroup(groupName)
}

func (c *configAccessControl) ValidateClientAPIKey(apiKey string) (*config.APIKeyConfig, error) {
	return c.cfg.ValidateClientAPIKey(apiKey)
}

func (c *configAccessControl) CanAPIKeyAccessGroup(keyConfig *config.APIKeyConfig, groupName string) bool {
	return c.cfg.CanAPIKeyAccessGroup(keyConfig, groupName)
}

func (c *configAccessControl) GetModelReferenceByAlias(alias string) (*config.ModelReference, error) {
	return c.cfg.GetModelReferenceByAlias(alias)
}

// ServeAdminModelGroups handles GET /admin/model-groups (list all model groups)
func (s *Server) ServeAdminModelGroups(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Get model groups
	groupNames := accessCtrl.GetAvailableModelGroups()
	modelGroups := make(map[string]ModelGroupInfo)

	for _, groupName := range groupNames {
		group, err := accessCtrl.GetModelGroup(groupName)
		if err != nil {
			continue // Skip invalid groups
		}

		// Convert models to info format
		models := make([]ModelReferenceInfo, len(group.Models))
		aliases := make(map[string]string)

		for i, modelRef := range group.Models {
			models[i] = ModelReferenceInfo{
				Provider: modelRef.Provider,
				Model:    modelRef.Model,
				Alias:    modelRef.Alias,
			}
			if modelRef.Alias != "" {
				aliases[modelRef.Alias] = modelRef.Model
			}
		}

		groupInfo := ModelGroupInfo{
			Name:        groupName,
			Description: group.Description,
			ModelCount:  len(group.Models),
			Models:      models,
			Aliases:     aliases,
		}

		modelGroups[groupName] = groupInfo
	}

	response := ModelGroupListResponse{
		Success:     true,
		ModelGroups: modelGroups,
		Count:       len(modelGroups),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminModelGroupsCreate handles POST /admin/model-groups (create new model group)
func (s *Server) ServeAdminModelGroupsCreate(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Parse request body
	var req ModelGroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Validate request
	if err := s.validateModelGroupCreateRequest(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Create model group
	group := &config.ModelGroup{
		Description: req.Description,
		Models:      req.Models,
	}

	// Add to configuration
	err := accessCtrl.AddModelGroup(req.Name, group)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			s.sendError(w, http.StatusConflict, "conflict_error", err.Error())
		} else {
			s.sendError(w, http.StatusInternalServerError, "creation_error", err.Error())
		}
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		// Rollback the change
		_ = accessCtrl.RemoveModelGroup(req.Name)
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	// Convert to response format
	models := make([]ModelReferenceInfo, len(req.Models))
	aliases := make(map[string]string)

	for i, modelRef := range req.Models {
		models[i] = ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
		}
		if modelRef.Alias != "" {
			aliases[modelRef.Alias] = modelRef.Model
		}
	}

	groupInfo := ModelGroupInfo{
		Name:        req.Name,
		Description: req.Description,
		ModelCount:  len(req.Models),
		Models:      models,
		Aliases:     aliases,
	}

	response := struct {
		Success     bool            `json:"success"`
		GroupInfo   ModelGroupInfo  `json:"group_info"`
		Timestamp   string          `json:"timestamp"`
		Message     string          `json:"message"`
	}{
		Success:   true,
		GroupInfo: groupInfo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "Model group created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminModelGroupUpdate handles PUT /admin/model-groups/{name} (update model group)
func (s *Server) ServeAdminModelGroupUpdate(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPut {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only PUT method is allowed")
		return
	}

	// Extract group name from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "Model group name is required")
		return
	}
	groupName := pathParts[2]

	// Parse request body
	var req ModelGroupUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Get existing model group
	group, err := accessCtrl.GetModelGroup(groupName)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Update fields if provided
	if req.Description != nil {
		group.Description = *req.Description
	}
	if req.Models != nil {
		group.Models = *req.Models
	}

	// Validate updated configuration
	if err := s.validateModelGroup(groupName, group); err != nil {
		s.sendError(w, http.StatusBadRequest, "validation_error", fmt.Sprintf("Invalid configuration: %v", err))
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	// Convert to response format
	models := make([]ModelReferenceInfo, len(group.Models))
	aliases := make(map[string]string)

	for i, modelRef := range group.Models {
		models[i] = ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
		}
		if modelRef.Alias != "" {
			aliases[modelRef.Alias] = modelRef.Model
		}
	}

	groupInfo := ModelGroupInfo{
		Name:        groupName,
		Description: group.Description,
		ModelCount:  len(group.Models),
		Models:      models,
		Aliases:     aliases,
	}

	response := struct {
		Success     bool            `json:"success"`
		GroupInfo   ModelGroupInfo  `json:"group_info"`
		Timestamp   string          `json:"timestamp"`
		Message     string          `json:"message"`
	}{
		Success:   true,
		GroupInfo: groupInfo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "Model group updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminModelGroupDelete handles DELETE /admin/model-groups/{name} (delete model group)
func (s *Server) ServeAdminModelGroupDelete(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodDelete {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only DELETE method is allowed")
		return
	}

	// Extract group name from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "Model group name is required")
		return
	}
	groupName := pathParts[2]

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Check if group exists
	_, err := accessCtrl.GetModelGroup(groupName)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Remove the group
	err = accessCtrl.RemoveModelGroup(groupName)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "deletion_error", err.Error())
		return
	}

	// Save configuration with backup
	if err := s.saveConfiguration(true); err != nil {
		s.sendError(w, http.StatusInternalServerError, "save_error", fmt.Sprintf("Failed to save configuration: %v", err))
		return
	}

	response := struct {
		Success   bool   `json:"success"`
		GroupName string `json:"group_name"`
		Timestamp string `json:"timestamp"`
		Message   string `json:"message"`
	}{
		Success:   true,
		GroupName: groupName,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "Model group deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminModelGroupDetails handles GET /admin/model-groups/{name} (get specific model group details)
func (s *Server) ServeAdminModelGroupDetails(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Extract group name from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[2] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "Model group name is required")
		return
	}
	groupName := pathParts[2]

	// Get access control interface
	accessCtrl := s.getAccessControl()
	if accessCtrl == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access control not available")
		return
	}

	// Get model group
	group, err := accessCtrl.GetModelGroup(groupName)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}

	// Convert to response format
	models := make([]ModelReferenceInfo, len(group.Models))
	aliases := make(map[string]string)

	for i, modelRef := range group.Models {
		models[i] = ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
		}
		if modelRef.Alias != "" {
			aliases[modelRef.Alias] = modelRef.Model
		}
	}

	groupInfo := ModelGroupInfo{
		Name:        groupName,
		Description: group.Description,
		ModelCount:  len(group.Models),
		Models:      models,
		Aliases:     aliases,
	}

	response := struct {
		Success   bool           `json:"success"`
		GroupInfo ModelGroupInfo `json:"group_info"`
		Timestamp string         `json:"timestamp"`
	}{
		Success:   true,
		GroupInfo: groupInfo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAccessCheck handles POST /admin/access/check (check if API key can access model)
func (s *Server) ServeAdminAccessCheck(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	// Parse request body
	var req AccessCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request_error", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	defer r.Body.Close()

	// Validate request
	if req.APIKey == "" {
		s.sendError(w, http.StatusBadRequest, "validation_error", "API key is required")
		return
	}
	if req.Model == "" {
		s.sendError(w, http.StatusBadRequest, "validation_error", "Model is required")
		return
	}

	// Get access manager
	am := s.getAccessManager()
	if am == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access manager not available")
		return
	}

	// Convert to proper interface for type assertion
	var accessManager *access.AccessManager
	if manager, ok := am.(*access.AccessManager); ok {
		accessManager = manager
	} else {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Invalid access manager type")
		return
	}

	// Check access
	ctx := r.Context()
	accessInfo, err := accessManager.CanAccessModel(ctx, req.APIKey, req.Model)

	response := AccessCheckResponse{
		Success:   true,
		APIKey:    s.maskAPIKey(req.APIKey),
		Model:     req.Model,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if err != nil {
		response.HasAccess = false
		response.Reason = err.Error()
	} else {
		response.HasAccess = true
		response.ResolvedModel = accessInfo.ResolvedModel
		response.Provider = accessInfo.ProviderName
		response.ModelGroup = accessInfo.ModelGroup
		response.ResolvedBy = accessInfo.ResolvedBy
		response.Reason = "Access granted"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAvailableModels handles GET /admin/access/models/{api_key} (get available models for API key)
func (s *Server) ServeAdminAvailableModels(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Extract API key from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "API key is required")
		return
	}
	apiKey := pathParts[3]

	// Get access manager
	am := s.getAccessManager()
	if am == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access manager not available")
		return
	}

	// Convert to proper interface for type assertion
	var accessManager *access.AccessManager
	if manager, ok := am.(*access.AccessManager); ok {
		accessManager = manager
	} else {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Invalid access manager type")
		return
	}

	// Get available models
	models, err := accessManager.GetAvailableModels(apiKey)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, "access_error", err.Error())
		return
	}

	// Get aliases separately
	cfg := s.getConfig()
	aliases := make(map[string]string)
	if cfg != nil && cfg.ModelGroups != nil {
		for _, group := range *cfg.ModelGroups {
			for _, modelRef := range group.Models {
				if modelRef.Alias != "" {
					aliases[modelRef.Alias] = modelRef.Model
				}
			}
		}
	}

	response := struct {
		Success        bool              `json:"success"`
		APIKey         string            `json:"api_key"`
		AvailableModels []string          `json:"available_models"`
		Aliases        map[string]string  `json:"aliases,omitempty"`
		ModelCount     int               `json:"model_count"`
		Timestamp      string            `json:"timestamp"`
	}{
		Success:        true,
		APIKey:         s.maskAPIKey(apiKey),
		AvailableModels: models,
		Aliases:        aliases,
		ModelCount:     len(models),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminAvailableAliases handles GET /admin/access/aliases/{api_key} (get available aliases for API key)
func (s *Server) ServeAdminAvailableAliases(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Extract API key from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "API key is required")
		return
	}
	apiKey := pathParts[3]

	// Get access manager
	am := s.getAccessManager()
	if am == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Access manager not available")
		return
	}

	// Convert to proper interface for type assertion
	var accessManager *access.AccessManager
	if manager, ok := am.(*access.AccessManager); ok {
		accessManager = manager
	} else {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Invalid access manager type")
		return
	}

	// Get available models (includes aliases)
	_, err := accessManager.GetAvailableModels(apiKey)
	if err != nil {
		s.sendError(w, http.StatusUnauthorized, "access_error", err.Error())
		return
	}

	// Filter to only aliases
	cfg := s.getConfig()
	aliases := make(map[string]string)
	if cfg != nil && cfg.ModelGroups != nil {
		// Get all possible aliases
		for _, group := range *cfg.ModelGroups {
			for _, modelRef := range group.Models {
				if modelRef.Alias != "" {
					aliases[modelRef.Alias] = modelRef.Model
				}
			}
		}
	}

	// Get API key config to check access
	cfgAccessCtrl := s.getAccessControl()
	if cfgAccessCtrl != nil {
		_, err := cfgAccessCtrl.ValidateClientAPIKey(apiKey)
		if err == nil {
			// Filter aliases that the API key can actually access
			filteredAliases := make(map[string]string)
			for alias, _ := range aliases {
				// Check if API key can access the model
				ctx := r.Context()
				if accessInfo, err := accessManager.CanAccessModel(ctx, apiKey, alias); err == nil {
					filteredAliases[alias] = accessInfo.ResolvedModel
				}
			}
			aliases = filteredAliases
		}
	}

	response := struct {
		Success       bool              `json:"success"`
		APIKey        string            `json:"api_key"`
		AvailableAliases map[string]string `json:"available_aliases"`
		AliasCount    int               `json:"alias_count"`
		Timestamp     string            `json:"timestamp"`
	}{
		Success:          true,
		APIKey:           s.maskAPIKey(apiKey),
		AvailableAliases: aliases,
		AliasCount:       len(aliases),
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ServeAdminModelGroupMembership handles GET /admin/access/groups/{model} (get model group membership)
func (s *Server) ServeAdminModelGroupMembership(w http.ResponseWriter, r *http.Request) {
	// Only allow admin key authentication
	if !s.authenticateAdminRequest(r) {
		s.sendError(w, http.StatusUnauthorized, "authentication_error", "Invalid admin API key")
		return
	}

	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET method is allowed")
		return
	}

	// Extract model from URL path
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 4 || pathParts[3] == "" {
		s.sendError(w, http.StatusBadRequest, "invalid_request", "Model name is required")
		return
	}
	modelName := pathParts[3]

	// Get configuration
	cfg := s.getConfig()
	if cfg == nil {
		s.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	// Find which groups contain this model
	memberGroups := make([]string, 0)
	groupDetails := make(map[string]interface{})

	if cfg.ModelGroups != nil {
		for groupName, group := range *cfg.ModelGroups {
			containsModel := false
			var matchingModel *config.ModelReference
			var alias string

			for _, modelRef := range group.Models {
				// Check direct model match
				if modelRef.Model == modelName {
					containsModel = true
					matchingModel = &modelRef
					alias = modelRef.Alias
					break
				}
				// Check alias match
				if modelRef.Alias == modelName {
					containsModel = true
					matchingModel = &modelRef
					alias = modelRef.Alias
					break
				}
			}

			if containsModel {
				memberGroups = append(memberGroups, groupName)
				groupDetails[groupName] = map[string]interface{}{
					"provider": matchingModel.Provider,
					"model":    matchingModel.Model,
					"alias":    alias,
					"group_name": groupName,
					"description": group.Description,
				}
			}
		}
	}

	// Check providers for this model
	providerInfo := make(map[string]interface{})
	var hasProvider bool
	if cfg.Providers != nil {
		for _, provider := range cfg.Providers {
			for _, model := range provider.Models {
				if model == modelName {
					hasProvider = true
					providerInfo["provider"] = provider.Name
					providerInfo["auth_method"] = provider.AuthMethod
					providerInfo["base_url"] = provider.BaseURL
					break
				}
			}
		}
	}

	response := struct {
		Success        bool                     `json:"success"`
		Model          string                   `json:"model"`
		MemberGroups   []string                 `json:"member_groups"`
		GroupDetails   map[string]interface{}   `json:"group_details"`
		ProviderInfo   map[string]interface{}   `json:"provider_info,omitempty"`
		HasProvider    bool                     `json:"has_provider"`
		Timestamp      string                   `json:"timestamp"`
	}{
		Success:      true,
		Model:        modelName,
		MemberGroups: memberGroups,
		GroupDetails: groupDetails,
		ProviderInfo: providerInfo,
		HasProvider:  hasProvider,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper validation methods

// validateModelGroupCreateRequest validates model group creation request
func (s *Server) validateModelGroupCreateRequest(req *ModelGroupCreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("Model group name is required")
	}

	if !s.isValidModelGroupName(req.Name) {
		return fmt.Errorf("Model group name must contain only alphanumeric characters, hyphens, and underscores")
	}

	if len(req.Models) == 0 {
		return fmt.Errorf("Model group must contain at least one model")
	}

	// Validate each model reference
	for i, modelRef := range req.Models {
		if modelRef.Provider == "" {
			return fmt.Errorf("Model %d: provider cannot be empty", i)
		}
		if modelRef.Model == "" {
			return fmt.Errorf("Model %d: model cannot be empty", i)
		}
	}

	return nil
}

// validateModelGroup validates a model group configuration
func (s *Server) validateModelGroup(groupName string, group *config.ModelGroup) error {
	if len(group.Models) == 0 {
		return fmt.Errorf("Model group must contain at least one model")
	}

	// Validate each model reference
	for i, modelRef := range group.Models {
		if modelRef.Provider == "" {
			return fmt.Errorf("Model %d: provider cannot be empty", i)
		}
		if modelRef.Model == "" {
			return fmt.Errorf("Model %d: model cannot be empty", i)
		}
	}

	return nil
}

// isValidModelGroupName validates model group name format
func (s *Server) isValidModelGroupName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}

	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
		     (char >= 'A' && char <= 'Z') ||
		     (char >= '0' && char <= '9') ||
		     char == '-' || char == '_') {
			return false
		}
	}

	return true
}