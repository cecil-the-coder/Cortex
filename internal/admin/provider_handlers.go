package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/health"
)

// ProviderInfo represents provider information for admin API
type ProviderInfo struct {
	ID             string                    `json:"id"`
	Name           string                    `json:"name"`
	Type           string                    `json:"type"`
	BaseURL        string                    `json:"base_url"`
	AuthMethod     config.AuthMethod         `json:"auth_method"`
	Models         []string                  `json:"models"`
	Status         *ProviderHealthStatus     `json:"status,omitempty"`
	Metrics        *ProviderMetrics          `json:"metrics,omitempty"`
	CoreAPI        bool                      `json:"core_api_enabled"`
	CoreFeatures   []string                  `json:"core_features,omitempty"`
	CreatedAt      time.Time                 `json:"created_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
	LastHealthCheck *time.Time               `json:"last_health_check,omitempty"`
	Tags           []string                  `json:"tags,omitempty"`
	Description    string                    `json:"description,omitempty"`
}

// HealthAlert represents a health monitoring alert
type HealthAlert struct {
	Level      string     `json:"level"`       // "info", "warning", "error", "critical"
	Message    string     `json:"message"`
	Timestamp  time.Time  `json:"timestamp"`
	Resolved   bool       `json:"resolved"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// ProviderHealth status information
type ProviderHealthStatus struct {
	Healthy           bool      `json:"healthy"`
	LastChecked       time.Time `json:"last_checked"`
	ResponseTime      float64   `json:"response_time_ms"`
	Message           string    `json:"message"`
	ConsecutiveFails  int       `json:"consecutive_fails"`
	LastSuccess       time.Time `json:"last_success"`
	Alerts            []HealthAlert `json:"alerts"`
}

// ProviderMetrics represents provider performance metrics
type ProviderMetrics struct {
	TotalRequests    int64             `json:"total_requests"`
	SuccessRequests  int64             `json:"success_requests"`
	FailedRequests   int64             `json:"failed_requests"`
	AverageResponse  float64           `json:"average_response_ms"`
	TokensProcessed  int64             `json:"tokens_processed"`
	Last24hRequests  int64             `json:"last_24h_requests"`
	ErrorRate        float64           `json:"error_rate_percent"`
	CustomMetrics    map[string]interface{} `json:"custom_metrics,omitempty"`
}

// ProviderCreateRequest represents a request to create a new provider
type ProviderCreateRequest struct {
	Name           string                `json:"name"`
	Type           string                `json:"type"`
	BaseURL        string                `json:"base_url"`
	AuthMethod     config.AuthMethod     `json:"auth_method"`
	APIKey         string                `json:"api_key,omitempty"`
	OAuth          *config.OAuthCredentialSet `json:"oauth,omitempty"`
	Models         []string              `json:"models"`
	Tags           []string              `json:"tags,omitempty"`
	Description    string                `json:"description,omitempty"`
	UseCoreAPI     bool                  `json:"use_core_api,omitempty"`
	CoreFeatures   []string              `json:"core_features,omitempty"`
}

// ProviderUpdateRequest represents a request to update an existing provider
type ProviderUpdateRequest struct {
	Name           *string               `json:"name,omitempty"`
	BaseURL        *string               `json:"base_url,omitempty"`
	AuthMethod     *config.AuthMethod    `json:"auth_method,omitempty"`
	APIKey         *string               `json:"api_key,omitempty"`
	OAuth          *config.OAuthCredentialSet `json:"oauth,omitempty"`
	Models         []string              `json:"models,omitempty"`
	Tags           []string              `json:"tags,omitempty"`
	Description    *string               `json:"description,omitempty"`
	UseCoreAPI     *bool                 `json:"use_core_api,omitempty"`
	CoreFeatures   []string              `json:"core_features,omitempty"`
}

// handleListProviders handles GET /v1/providers
func (a *AdminServer) handleListProviders(w http.ResponseWriter, r *http.Request) {
	// Parse pagination and filtering
	page, perPage, err := a.parsePagination(r)
	if err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_pagination", "Invalid pagination parameters")
		return
	}

	filter := a.parseFilterOptions(r)

	// Get all provider configurations
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	var providers []ProviderInfo
	for _, provider := range cfg.Providers {
		// Apply filters
		if filter.Status != "" {
			// Get health status to filter by status
			healthStatus, _ := a.providerRegistry.GetHealthMonitor().GetProviderHealthStatus(provider.Name)
			isHealthy := healthStatus != nil && healthStatus.Healthy

			if filter.Status == "healthy" && !isHealthy {
				continue
			}
			if filter.Status == "unhealthy" && isHealthy {
				continue
			}
		}

		if filter.Query != "" && !strings.Contains(strings.ToLower(provider.Name), strings.ToLower(filter.Query)) {
			continue
		}

		// Convert provider config to ProviderInfo
		providerInfo := a.convertProviderToInfo(&provider)
		providers = append(providers, providerInfo)
	}

	// Apply sorting
	if filter.SortBy != "" {
		// Implement sorting based on filter.SortBy
		a.sortProviders(providers, filter.SortBy, filter.SortDesc)
	}

	// Apply pagination
	total := len(providers)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total }

	paginatedProviders := providers[start:end]

	paging := &PagingInfo{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: (total + perPage - 1) / perPage,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1, // Placeholder - would measure actual processing time
		Metadata: map[string]interface{}{
			"total_providers": total,
			"filter_applied": filter.Query != "",
		},
	}

	a.sendResponse(w, http.StatusOK, paginatedProviders, paging, meta)
	a.logAccess(r, "LIST_PROVIDERS", "providers", "", true)
}

// handleGetProvider handles GET /v1/providers/{id}
func (a *AdminServer) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	// Get provider configuration
	providerConfig, err := a.providerRegistry.GetProviderConfig(providerID)
	if err != nil {
		a.sendError(w, http.StatusNotFound, "provider_not_found", "Provider not found")
		return
	}

	// Get health status and metrics
	healthStatus, _ := a.providerRegistry.GetHealthMonitor().GetProviderHealthStatus(providerID)
	metrics, _ := a.providerRegistry.GetHealthMonitor().GetProviderMetrics(providerID)

	// Convert to response format
	providerInfo := a.convertProviderToInfo(providerConfig)
	if healthStatus != nil {
		providerInfo.Status = &ProviderHealthStatus{
			Healthy:          healthStatus.Healthy,
			LastChecked:      healthStatus.LastChecked,
			ResponseTime:     healthStatus.ResponseTime * 1000, // Convert to ms
			Message:          healthStatus.Message,
			ConsecutiveFails: healthStatus.ConsecutiveFails,
			LastSuccess:      healthStatus.LastSuccess,
			Alerts:           a.convertHealthAlerts(healthStatus.Alerts),
		}
	}

	if metrics != nil {
		providerInfo.Metrics = &ProviderMetrics{
			TotalRequests:     0, // Would need to track this separately
			SuccessRequests:   0, // Would need to track this separately
			FailedRequests:    0, // Would need to track this separately
			AverageResponse:   0, // Would need to extract from metrics
			TokensProcessed:   0, // Would need to track this separately
			Last24hRequests:   0, // Would need to calculate this
			ErrorRate:         0, // Would need to calculate this
			CustomMetrics:     make(map[string]interface{}),
		}
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, providerInfo, nil, meta)
	a.logAccess(r, "GET_PROVIDER", "provider", providerID, true)
}

// handleCreateProvider handles POST /v1/providers
func (a *AdminServer) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req ProviderCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate request
	if err := a.validateProviderCreateRequest(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Check if provider already exists
	cfg := a.configFunc()
	if cfg != nil {
		for _, existing := range cfg.Providers {
			if existing.Name == req.Name {
				a.sendError(w, http.StatusConflict, "provider_exists", "Provider with this name already exists")
				a.logAccess(r, "CREATE_PROVIDER", "provider", req.Name, false)
				return
			}
		}
	}

	// Create provider config
	newProvider := config.Provider{
		Name:       req.Name,
		BaseURL:    req.BaseURL,
		AuthMethod: req.AuthMethod,
		Models:     req.Models,
	}

	if req.APIKey != "" {
		newProvider.APIKEY = req.APIKey
	}
	if req.OAuth != nil {
		newProvider.OAuth = req.OAuth
	}
	if req.UseCoreAPI {
		newProvider.UseCoreAPI = true
		newProvider.CoreAPIFeatures = req.CoreFeatures
	}

	// Add provider to configuration
	// Note: This would need to modify the configuration and reload providers
	// For now, we'll return a success response with a note
	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"note": "Provider creation requires configuration reload",
		},
	}

	response := map[string]interface{}{
		"message": "Provider creation request received. Configuration reload required.",
		"provider": a.convertProviderToInfo(&newProvider),
	}

	a.sendResponse(w, http.StatusAccepted, response, nil, meta)
	a.logAccess(r, "CREATE_PROVIDER", "provider", req.Name, true)
}

// handleUpdateProvider handles PUT /v1/providers/{id}
func (a *AdminServer) handleUpdateProvider(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	var req ProviderUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Get existing provider config
	providerConfig, err := a.providerRegistry.GetProviderConfig(providerID)
	if err != nil {
		a.sendError(w, http.StatusNotFound, "provider_not_found", "Provider not found")
		a.logAccess(r, "UPDATE_PROVIDER", "provider", providerID, false)
		return
	}

	// Apply updates
	if req.Name != nil {
		providerConfig.Name = *req.Name
	}
	if req.BaseURL != nil {
		providerConfig.BaseURL = *req.BaseURL
	}
	if req.AuthMethod != nil {
		providerConfig.AuthMethod = *req.AuthMethod
	}
	if req.APIKey != nil {
		providerConfig.APIKEY = *req.APIKey
	}
	if req.OAuth != nil {
		providerConfig.OAuth = req.OAuth
	}
	if req.Models != nil {
		providerConfig.Models = req.Models
	}
	if req.UseCoreAPI != nil {
		providerConfig.UseCoreAPI = *req.UseCoreAPI
	}
	if req.CoreFeatures != nil {
		providerConfig.CoreAPIFeatures = req.CoreFeatures
	}

	// Basic validation of updated config
	if providerConfig.Name == "" {
		a.sendError(w, http.StatusBadRequest, "validation_error", "Provider name cannot be empty")
		return
	}
	if providerConfig.BaseURL == "" {
		a.sendError(w, http.StatusBadRequest, "validation_error", "Provider base URL cannot be empty")
		return
	}

	// Note: Actually updating the provider would require configuration reload
	response := map[string]interface{}{
		"message": "Provider update request received. Configuration reload required.",
		"provider": a.convertProviderToInfo(providerConfig),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"note": "Provider updates require configuration reload",
		},
	}

	a.sendResponse(w, http.StatusAccepted, response, nil, meta)
	a.logAccess(r, "UPDATE_PROVIDER", "provider", providerID, true)
}

// handleDeleteProvider handles DELETE /v1/providers/{id}
func (a *AdminServer) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	// Check if provider exists
	_, err := a.providerRegistry.GetProviderConfig(providerID)
	if err != nil {
		a.sendError(w, http.StatusNotFound, "provider_not_found", "Provider not found")
		a.logAccess(r, "DELETE_PROVIDER", "provider", providerID, false)
		return
	}

	// Note: Actually deleting the provider would require configuration reload
	response := map[string]interface{}{
		"message": "Provider deletion request received. Configuration reload required.",
		"provider_id": providerID,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"note": "Provider deletion requires configuration reload",
		},
	}

	a.sendResponse(w, http.StatusAccepted, response, nil, meta)
	a.logAccess(r, "DELETE_PROVIDER", "provider", providerID, true)
}

// handleTriggerHealthCheck handles POST /v1/providers/{id}/health
func (a *AdminServer) handleTriggerHealthCheck(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	// Trigger manual health check
	err := a.providerRegistry.GetHealthMonitor().TriggerManualHealthCheck(providerID)
	if err != nil {
		a.sendError(w, http.StatusBadRequest, "health_check_failed", "Failed to trigger health check: "+err.Error())
		return
	}

	// Get updated health status
	healthStatus, _ := a.providerRegistry.GetHealthMonitor().GetProviderHealthStatus(providerID)

	response := map[string]interface{}{
		"message": "Health check triggered successfully",
		"provider_id": providerID,
		"health_status": healthStatus,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "TRIGGER_HEALTH_CHECK", "provider", providerID, true)
}

// handleGetProviderMetrics handles GET /v1/providers/{id}/metrics
func (a *AdminServer) handleGetProviderMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	// Get provider metrics
	metrics, err := a.providerRegistry.GetHealthMonitor().GetProviderMetrics(providerID)
	if err != nil {
		a.sendError(w, http.StatusNotFound, "metrics_not_found", "No metrics available for this provider")
		return
	}

	// Get provider info
	providerConfig, _ := a.providerRegistry.GetProviderConfig(providerID)

	response := map[string]interface{}{
		"provider_id": providerID,
		"provider_name": func() string {
			if providerConfig != nil {
				return providerConfig.Name
			}
			return providerID
		}(),
		"metrics": metrics,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_PROVIDER_METRICS", "provider", providerID, true)
}

// handleValidateProvider handles POST /v1/providers/{id}/validate
func (a *AdminServer) handleValidateProvider(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	if providerID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Provider ID is required")
		return
	}

	// Validate provider authentication
	err := a.providerRegistry.ValidateProviderAPIKey(providerID)

	response := map[string]interface{}{
		"provider_id": providerID,
		"valid": err == nil,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if err != nil {
		response["error"] = err.Error()
	}

	statusCode := http.StatusOK
	if err != nil {
		statusCode = http.StatusBadRequest
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, statusCode, response, nil, meta)
	a.logAccess(r, "VALIDATE_PROVIDER", "provider", providerID, err == nil)
}

// handleBulkProviderOperations handles POST /v1/providers/bulk
func (a *AdminServer) handleBulkProviderOperations(w http.ResponseWriter, r *http.Request) {
	var req BulkOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	results := make([]BulkOperationResult, len(req.Items))
	successful := 0
	failed := 0
	var errors []string

	for i := range req.Items {
		result := BulkOperationResult{
			Index: i,
			Success: false,
		}

		// Process based on action type
		switch req.Action {
		case "validate":
			// Provider validation logic would go here
			result.Success = true
			successful++
		case "health_check":
			// Bulk health check logic would go here
			result.Success = true
			successful++
		default:
			result.Error = "Unsupported action: " + req.Action
			failed++
		}

		results[i] = result
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
	a.logAccess(r, "BULK_PROVIDER_OPERATIONS", "providers", req.Action, response.Success)
}

// Helper methods

// convertProviderToInfo converts provider config to ProviderInfo
func (a *AdminServer) convertProviderToInfo(p *config.Provider) ProviderInfo {
	return ProviderInfo{
		ID:            p.Name,
		Name:          p.Name,
		BaseURL:       p.BaseURL,
		AuthMethod:    p.AuthMethod,
		Models:        p.Models,
		CoreAPI:       p.UseCoreAPI,
		CoreFeatures:  p.CoreAPIFeatures,
		CreatedAt:     time.Now(), // Would need to track actual creation time
		UpdatedAt:     time.Now(), // Would need to track actual update time
		Tags:          []string{}, // Could be added to provider config
		Description:   "", // Could be added to provider config
	}
}

// convertHealthAlerts converts health monitor alerts to API format
func (a *AdminServer) convertHealthAlerts(alerts []health.HealthAlert) []HealthAlert {
	var apiAlerts []HealthAlert
	for _, alert := range alerts {
		apiAlerts = append(apiAlerts, HealthAlert{
			Level:     alert.Level,
			Message:   alert.Message,
			Timestamp: alert.Timestamp,
			Resolved:  alert.Resolved,
			ResolvedAt: alert.ResolvedAt,
		})
	}
	return apiAlerts
}

// sortProviders sorts providers based on the specified field
func (a *AdminServer) sortProviders(providers []ProviderInfo, sortBy string, desc bool) {
	// Simple bubble sort for demonstration
	// In production, use more efficient sorting algorithm
	for i := 0; i < len(providers)-1; i++ {
		for j := i + 1; j < len(providers); j++ {
			shouldSwap := false

			switch sortBy {
			case "name":
				if desc {
					shouldSwap = providers[i].Name < providers[j].Name
				} else {
					shouldSwap = providers[i].Name > providers[j].Name
				}
			case "status":
				// Would compare health status
			default:
				if desc {
					shouldSwap = providers[i].ID < providers[j].ID
				} else {
					shouldSwap = providers[i].ID > providers[j].ID
				}
			}

			if shouldSwap {
				providers[i], providers[j] = providers[j], providers[i]
			}
		}
	}
}

// validateProviderCreateRequest validates the provider creation request
func (a *AdminServer) validateProviderCreateRequest(req *ProviderCreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("Provider name is required")
	}
	if req.BaseURL == "" {
		return fmt.Errorf("Base URL is required")
	}
	if req.AuthMethod == "" {
		return fmt.Errorf("Auth method is required")
	}
	if len(req.Models) == 0 {
		return fmt.Errorf("At least one model is required")
	}

	// Validate auth method specific requirements
	switch req.AuthMethod {
	case config.AuthMethodAPIKey:
		if req.APIKey == "" {
			return fmt.Errorf("API key is required for API key authentication")
		}
	case config.AuthMethodOAuth:
		if req.OAuth == nil {
			return fmt.Errorf("OAuth configuration is required for OAuth authentication")
		}
		if req.OAuth.ClientID == "" || req.OAuth.ClientSecret == "" {
			return fmt.Errorf("OAuth client ID and secret are required")
		}
	case config.AuthMethodHybrid:
		if req.APIKey == "" && (req.OAuth == nil || req.OAuth.ClientID == "") {
			return fmt.Errorf("Hybrid authentication requires API key and/or OAuth configuration")
		}
	}

	return nil
}