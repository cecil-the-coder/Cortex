package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/gorilla/mux"
)

// ModelInfo represents model information for admin API
type ModelInfo struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Provider         string                 `json:"provider"`
	ContextWindow    int                    `json:"context_window"`
	SupportsVision   bool                   `json:"supports_vision"`
	SupportsTools    bool                   `json:"supports_tools"`
	FeatureSupport   map[string]bool        `json:"feature_support"`
	Status           string                 `json:"status"` // "active", "inactive", "deprecated"
	Tags             []string               `json:"tags,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CustomProperties map[string]interface{} `json:"custom_properties,omitempty"`
}

// ModelGroupInfo represents model group information for admin API
type ModelGroupInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Models      []ModelReferenceInfo   `json:"models"`
	Aliases     map[string]string      `json:"aliases,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Stats       *ModelGroupStats       `json:"stats,omitempty"`
}

// ModelReferenceInfo represents a model reference in a group
type ModelReferenceInfo struct {
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	Alias            string `json:"alias,omitempty"`
	MaxContextTokens *int   `json:"max_context_tokens,omitempty"`
	Weight           int    `json:"weight,omitempty"` // For routing decisions
	Priority         int    `json:"priority,omitempty"` // For fallback selection
}

// ModelGroupStats contains statistics for a model group
type ModelGroupStats struct {
	TotalRequests      int64             `json:"total_requests"`
	SuccessfulRequests int64             `json:"successful_requests"`
	FailedRequests     int64             `json:"failed_requests"`
	AverageResponse    float64           `json:"average_response_ms"`
	TokensProcessed    int64             `json:"tokens_processed"`
	ModelBreakdown     map[string]int64  `json:"model_breakdown"`
	Last24hRequests    int64             `json:"last_24h_requests"`
	ErrorRate          float64           `json:"error_rate_percent"`
}

// RoutingAnalytics contains routing analytics data
type RoutingAnalytics struct {
	TotalRouted        int64                    `json:"total_routed"`
	ProviderBreakdown  map[string]int64         `json:"provider_breakdown"`
	ModelBreakdown     map[string]int64         `json:"model_breakdown"`
	RouteReasons       map[string]int64         `json:"route_reasons"`
	ContextWindows     map[string]int64         `json:"context_windows"`
	VisionRequests     int64                    `json:"vision_requests"`
	ToolRequests       int64                    `json:"tool_requests"`
	AverageConfidence  float64                  `json:"average_confidence"`
	RoutingLatency     float64                  `json:"routing_latency_ms"`
	Period             string                   `json:"period"` // "1h", "24h", "7d", "30d"
	Timestamp          time.Time                `json:"timestamp"`
}

// ModelDiscoveryRequest represents a request to discover models
type ModelDiscoveryRequest struct {
	Providers []string `json:"providers,omitempty"`
	Refresh   bool     `json:"refresh"`   // Force refresh discovery cache
	DeepScan  bool     `json:"deep_scan"` // Perform comprehensive scan
}

// ModelDiscoveryResponse contains discovered models information
type ModelDiscoveryResponse struct {
	ProviderInfos map[string]ProviderDiscoveryInfo `json:"provider_infos"`
	TotalModels   int                             `json:"total_models"`
	Timestamp     time.Time                       `json:"timestamp"`
	CacheStatus   string                          `json:"cache_status"`
}

// ProviderDiscoveryInfo contains discovery information for a provider
type ProviderDiscoveryInfo struct {
	Name         string      `json:"name"`
	Status       string      `json:"status"` // "success", "error", "partial"
	Models       []string    `json:"models"`
	Errors       []string    `json:"errors,omitempty"`
	Capabilities []string    `json:"capabilities,omitempty"`
	CachedAt     *time.Time  `json:"cached_at,omitempty"`
	LastRefresh  *time.Time  `json:"last_refresh,omitempty"`
}

// ModelGroupCreateRequest represents a request to create a model group
type ModelGroupCreateRequest struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Models      []config.ModelReference  `json:"models"`
	Tags        []string                 `json:"tags,omitempty"`
	Metadata    map[string]interface{}   `json:"metadata,omitempty"`
}

// ModelGroupUpdateRequest represents a request to update a model group
type ModelGroupUpdateRequest struct {
	Description *string                  `json:"description,omitempty"`
	Models      *[]config.ModelReference `json:"models,omitempty"`
	Tags        []string                 `json:"tags,omitempty"`
	Metadata    map[string]interface{}   `json:"metadata,omitempty"`
}

// handleListModels handles GET /v1/models
func (a *AdminServer) handleListModels(w http.ResponseWriter, r *http.Request) {
	page, perPage, err := a.parsePagination(r)
	if err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_pagination", "Invalid pagination parameters")
		return
	}

	filter := a.parseFilterOptions(r)

	// Get all models from all providers
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	var models []ModelInfo
	registry := config.GetGlobalContextRegistry()

	for _, provider := range cfg.Providers {
		for _, modelName := range provider.Models {
			// Apply filters
			if filter.Query != "" {
				query := strings.ToLower(filter.Query)
				if !strings.Contains(strings.ToLower(modelName), query) &&
					!strings.Contains(strings.ToLower(provider.Name), query) {
					continue
				}
			}

			if filter.Status != "" && filter.Status != "active" {
				continue // All models are considered active for now
			}

			// Get model context window info
			contextWindow, _ := registry.GetContextWindow(modelName)
			if contextWindow == 0 {
				contextWindow = 4096 // Default
			}

			// Get model capabilities
			supportsVision := registry.SupportsVision(modelName)

			modelInfo := ModelInfo{
				ID:             fmt.Sprintf("%s:%s", provider.Name, modelName),
				Name:           modelName,
				Provider:       provider.Name,
				ContextWindow:  contextWindow,
				SupportsVision: supportsVision,
				SupportsTools:  true, // Assume all support tools unless specified otherwise
				FeatureSupport: map[string]bool{
					"chat":        true,
					"completion":  true,
					"vision":      supportsVision,
					"tools":       true,
					"streaming":   true,
				},
				Status:           "active",
				Tags:            []string{},
				Description:      "",
				Metadata:         make(map[string]interface{}),
				CustomProperties: make(map[string]interface{}),
			}

			models = append(models, modelInfo)
		}
	}

	// Apply sorting
	if filter.SortBy != "" {
		a.sortModels(models, filter.SortBy, filter.SortDesc)
	}

	// Apply pagination
	total := len(models)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedModels := models[start:end]

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
			"total_models": total,
			"providers": len(cfg.Providers),
		},
	}

	a.sendResponse(w, http.StatusOK, paginatedModels, paging, meta)
	a.logAccess(r, "LIST_MODELS", "models", "", true)
}

// handleGetModel handles GET /v1/models/{model}
func (a *AdminServer) handleGetModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	modelName := vars["model"]

	if modelName == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Model name is required")
		return
	}

	// Parse provider and model name
	parts := strings.SplitN(modelName, ":", 2)
	var providerName, actualModelName string
	if len(parts) == 2 {
		providerName, actualModelName = parts[0], parts[1]
	} else {
		actualModelName = modelName
	}

	// Find the model
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Configuration not available")
		return
	}

	var foundProvider *config.Provider
	var foundModel string

	for _, provider := range cfg.Providers {
		if providerName != "" && provider.Name != providerName {
			continue
		}

		for _, model := range provider.Models {
			if model == actualModelName {
				foundProvider = &provider
				foundModel = model
				break
			}
		}
		if foundProvider != nil {
			break
		}
	}

	if foundProvider == nil {
		a.sendError(w, http.StatusNotFound, "model_not_found", "Model not found")
		return
	}

	// Get detailed model information
	registry := config.GetGlobalContextRegistry()
	contextWindow, _ := registry.GetContextWindow(foundModel)
	if contextWindow == 0 {
		contextWindow = 4096
	}

	modelInfo := ModelInfo{
		ID:             fmt.Sprintf("%s:%s", foundProvider.Name, foundModel),
		Name:           foundModel,
		Provider:       foundProvider.Name,
		ContextWindow:  contextWindow,
		SupportsVision: registry.SupportsVision(foundModel),
		SupportsTools:  true,
		FeatureSupport: map[string]bool{
			"chat":        true,
			"completion":  true,
			"vision":      registry.SupportsVision(foundModel),
			"tools":       true,
			"streaming":   true,
		},
		Status:           "active",
		Tags:            []string{},
		Description:      "",
		Metadata:         map[string]interface{}{
			"auth_method": foundProvider.AuthMethod,
			"base_url":    foundProvider.BaseURL,
		},
		CustomProperties: map[string]interface{}{
			"registered_at": time.Now().Format(time.RFC3339),
		},
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, modelInfo, nil, meta)
	a.logAccess(r, "GET_MODEL", "model", modelName, true)
}

// handleDiscoverModels handles POST /v1/models/discover
func (a *AdminServer) handleDiscoverModels(w http.ResponseWriter, r *http.Request) {
	var req ModelDiscoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Get discovery service
	discoveryService := a.providerRegistry.GetDiscoveryService()
	if discoveryService == nil {
		a.sendError(w, http.StatusServiceUnavailable, "service_unavailable", "Discovery service not available")
		return
	}

	// Trigger model discovery
	discoveryResult := make(map[string]ProviderDiscoveryInfo)
	totalModels := 0

	// Get all provider configs
	allConfigs := a.providerRegistry.GetAllProviderConfigs()

	for providerName, providerConfig := range allConfigs {
		// Skip if providers are specified and this one is not in the list
		if len(req.Providers) > 0 {
			found := false
			for _, p := range req.Providers {
				if p == providerName {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		providerInfo := ProviderDiscoveryInfo{
			Name:  providerName,
			Models: providerConfig.Models,
			Capabilities: []string{
				"chat",
				"completion",
				"streaming",
			},
			LastRefresh: &time.Time{},
		}

		// Check if provider supports vision models
		registry := config.GetGlobalContextRegistry()
		for _, model := range providerConfig.Models {
			if registry.SupportsVision(model) {
				providerInfo.Capabilities = append(providerInfo.Capabilities, "vision")
				break
			}
		}

		discoveryResult[providerName] = providerInfo
		totalModels += len(providerConfig.Models)
	}

	response := ModelDiscoveryResponse{
		ProviderInfos: discoveryResult,
		TotalModels:   totalModels,
		Timestamp:     time.Now(),
		CacheStatus:   "current",
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"refresh_triggered": req.Refresh,
			"deep_scan":        req.DeepScan,
		},
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "DISCOVER_MODELS", "models discovery", "", true)
}

// handleGetRoutingAnalytics handles GET /v1/models/routing/analytics
func (a *AdminServer) handleGetRoutingAnalytics(w http.ResponseWriter, r *http.Request) {
	// Get period from query parameters (default: 24h)
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	// Placeholder analytics data - in production, this would query actual metrics
	analytics := RoutingAnalytics{
		TotalRouted:       0,
		ProviderBreakdown: map[string]int64{},
		ModelBreakdown:    map[string]int64{},
		RouteReasons:      map[string]int64{
			"default":     0,
			"context":     0,
			"vision":      0,
			"tools":       0,
			"performance": 0,
		},
		ContextWindows: map[string]int64{
			"4k":   0,
			"8k":   0,
			"16k":  0,
			"32k":  0,
			"64k":  0,
			"128k": 0,
			"200k": 0,
		},
		VisionRequests:    0,
		ToolRequests:      0,
		AverageConfidence: 0.0,
		RoutingLatency:    0.0,
		Period:            period,
		Timestamp:         time.Now(),
	}

	// Get configuration for provider data
	cfg := a.configFunc()
	if cfg != nil {
		for _, provider := range cfg.Providers {
			analytics.ProviderBreakdown[provider.Name] = 0
			for _, model := range provider.Models {
				analytics.ModelBreakdown[model] = 0
			}
		}
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"period":               period,
			"analytics_available":   false,
			"note":                 "Analytics tracking is not implemented yet",
		},
	}

	response := map[string]interface{}{
		"analytics": analytics,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_ROUTING_ANALYTICS", "routing analytics", period, true)
}

// handleListModelGroups handles GET /v1/models/groups
func (a *AdminServer) handleListModelGroups(w http.ResponseWriter, r *http.Request) {
	page, perPage, err := a.parsePagination(r)
	if err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_pagination", "Invalid pagination parameters")
		return
	}

	filter := a.parseFilterOptions(r)

	// Get all model groups
	cfg := a.configFunc()
	if cfg == nil || cfg.ModelGroups == nil {
		a.sendResponse(w, http.StatusOK, []ModelGroupInfo{}, nil, nil)
		return
	}

	var groups []ModelGroupInfo

	for groupName, group := range *cfg.ModelGroups {
		// Apply filters
		if filter.Query != "" {
			query := strings.ToLower(filter.Query)
			if !strings.Contains(strings.ToLower(groupName), query) &&
				!strings.Contains(strings.ToLower(group.Description), query) {
				continue
			}
		}

		// Convert models
		var models []ModelReferenceInfo
		for _, modelRef := range group.Models {
			modelInfo := ModelReferenceInfo{
				Provider: modelRef.Provider,
				Model:    modelRef.Model,
				Alias:    modelRef.Alias,
				MaxContextTokens: modelRef.MaxContextTokens,
				Weight:   1, // Default weight
				Priority: 1, // Default priority
			}
			models = append(models, modelInfo)
		}

		// Create aliases map
		aliases := make(map[string]string)
		for _, model := range models {
			if model.Alias != "" {
				aliases[model.Alias] = model.Model
			}
		}

		groupInfo := ModelGroupInfo{
			Name:        groupName,
			Description: group.Description,
			Models:      models,
			Aliases:     aliases,
			CreatedAt:   time.Now(), // Would track actual creation time
			UpdatedAt:   time.Now(), // Would track actual update time
			Tags:        []string{}, // Could be added to config
			Metadata:    make(map[string]interface{}),
		}

		groups = append(groups, groupInfo)
	}

	// Apply sorting
	if filter.SortBy != "" {
		a.sortModelGroups(groups, filter.SortBy, filter.SortDesc)
	}

	// Apply pagination
	total := len(groups)
	start := (page - 1) * perPage
	end := start + perPage
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedGroups := groups[start:end]

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
			"total_groups": total,
		},
	}

	a.sendResponse(w, http.StatusOK, paginatedGroups, paging, meta)
	a.logAccess(r, "LIST_MODEL_GROUPS", "model groups", "", true)
}

// handleCreateModelGroup handles POST /v1/models/groups
func (a *AdminServer) handleCreateModelGroup(w http.ResponseWriter, r *http.Request) {
	var req ModelGroupCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate request
	if err := a.validateModelGroupCreateRequest(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Check if group already exists
	cfg := a.configFunc()
	if cfg != nil && cfg.ModelGroups != nil {
		if _, exists := (*cfg.ModelGroups)[req.Name]; exists {
			a.sendError(w, http.StatusConflict, "group_exists", "Model group with this name already exists")
			a.logAccess(r, "CREATE_MODEL_GROUP", "model group", req.Name, false)
			return
		}
	}

	// Create model group configuration
	newGroup := &config.ModelGroup{
		Description: req.Description,
		Models:      req.Models,
	}

	// Add to configuration
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "config_unavailable", "Configuration not available")
		return
	}

	err := cfg.AddModelGroup(req.Name, newGroup)
	if err != nil {
		a.sendError(w, http.StatusInternalServerError, "creation_failed", "Failed to create model group: "+err.Error())
		return
	}

	// Save configuration
	configPath := a.server.GetConfigPath()
	if configPath != "" {
		if err := config.Save(cfg, configPath, true); err != nil {
			// Rollback
			cfg.RemoveModelGroup(req.Name)
			a.sendError(w, http.StatusInternalServerError, "save_failed", "Failed to save configuration: "+err.Error())
			a.logAccess(r, "CREATE_MODEL_GROUP", "model group", req.Name, false)
			return
		}
	}

	// Create response
	// Convert models to response format
	var models []ModelReferenceInfo
	for _, modelRef := range req.Models {
		models = append(models, ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
			MaxContextTokens: modelRef.MaxContextTokens,
		})
	}

	groupInfo := ModelGroupInfo{
		Name:        req.Name,
		Description: req.Description,
		Models:      models,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Tags:        req.Tags,
		Metadata:    req.Metadata,
	}

	response := map[string]interface{}{
		"message":     "Model group created successfully",
		"group_info":  groupInfo,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusCreated, response, nil, meta)
	a.logAccess(r, "CREATE_MODEL_GROUP", "model group", req.Name, true)
}

// handleGetModelGroup handles GET /v1/models/groups/{name}
func (a *AdminServer) handleGetModelGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupName := vars["name"]

	if groupName == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Model group name is required")
		return
	}

	// Get model group configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ModelGroups == nil {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		return
	}

	group, exists := (*cfg.ModelGroups)[groupName]
	if !exists {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		return
	}

	// Convert models to response format
	var models []ModelReferenceInfo
	for _, modelRef := range group.Models {
		models = append(models, ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
			MaxContextTokens: modelRef.MaxContextTokens,
		})
	}

	// Create aliases map
	aliases := make(map[string]string)
	for _, model := range models {
		if model.Alias != "" {
			aliases[model.Alias] = model.Model
		}
	}

	groupInfo := ModelGroupInfo{
		Name:        groupName,
		Description: group.Description,
		Models:      models,
		Aliases:     aliases,
		CreatedAt:   time.Now(), // Would track actual creation time
		UpdatedAt:   time.Now(), // Would track actual update time
		Tags:        []string{}, // Could be added to config
		Metadata:    make(map[string]interface{}),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, groupInfo, nil, meta)
	a.logAccess(r, "GET_MODEL_GROUP", "model group", groupName, true)
}

// handleUpdateModelGroup handles PUT /v1/models/groups/{name}
func (a *AdminServer) handleUpdateModelGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupName := vars["name"]

	if groupName == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Model group name is required")
		return
	}

	var req ModelGroupUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Get existing model group configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ModelGroups == nil {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		return
	}

	group, exists := (*cfg.ModelGroups)[groupName]
	if !exists {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		return
	}

	// Apply updates
	if req.Description != nil {
		group.Description = *req.Description
	}
	if req.Models != nil {
		group.Models = *req.Models
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
	var models []ModelReferenceInfo
	for _, modelRef := range group.Models {
		models = append(models, ModelReferenceInfo{
			Provider: modelRef.Provider,
			Model:    modelRef.Model,
			Alias:    modelRef.Alias,
			MaxContextTokens: modelRef.MaxContextTokens,
		})
	}

	groupInfo := ModelGroupInfo{
		Name:        groupName,
		Description: group.Description,
		Models:      models,
		UpdatedAt:   time.Now(),
		Tags:        req.Tags,
		Metadata:    req.Metadata,
	}

	response := map[string]interface{}{
		"message":     "Model group updated successfully",
		"group_info":  groupInfo,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "UPDATE_MODEL_GROUP", "model group", groupName, true)
}

// handleDeleteModelGroup handles DELETE /v1/models/groups/{name}
func (a *AdminServer) handleDeleteModelGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	groupName := vars["name"]

	if groupName == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Model group name is required")
		return
	}

	// Get configuration
	cfg := a.configFunc()
	if cfg == nil || cfg.ModelGroups == nil {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		return
	}

	// Check if group exists
	_, exists := (*cfg.ModelGroups)[groupName]
	if !exists {
		a.sendError(w, http.StatusNotFound, "group_not_found", "Model group not found")
		a.logAccess(r, "DELETE_MODEL_GROUP", "model group", groupName, false)
		return
	}

	// Remove model group
	err := cfg.RemoveModelGroup(groupName)
	if err != nil {
		a.sendError(w, http.StatusInternalServerError, "deletion_failed", "Failed to delete model group: "+err.Error())
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
		"message":      "Model group deleted successfully",
		"group_name":   groupName,
		"deleted_at":   time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "DELETE_MODEL_GROUP", "model group", groupName, true)
}

// handleBulkModelGroupOperations handles POST /v1/models/groups/bulk
func (a *AdminServer) handleBulkModelGroupOperations(w http.ResponseWriter, r *http.Request) {
	var req BulkOperationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	results := make([]BulkOperationResult, len(req.Items))
	successful := 0
	failed := 0
	var errors []string

	for i, item := range req.Items {
		result := BulkOperationResult{
			Index: i,
			Success: false,
		}

		// Process based on action type
		switch req.Action {
		case "validate":
			// Model group validation logic
			if groupData, ok := item.(map[string]interface{}); ok {
				name, _ := groupData["name"].(string)
				if name != "" && a.isValidModelGroupName(name) {
					result.Success = true
					result.ID = name
					successful++
				} else {
					failed++
					result.Error = "Invalid model group format or name"
				}
			}
		default:
			failed++
			result.Error = "Unsupported action: " + req.Action
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
	a.logAccess(r, "BULK_MODEL_GROUP_OPERATIONS", "model groups", req.Action, response.Success)
}

// Helper methods

// sortModels sorts models based on the specified field
func (a *AdminServer) sortModels(models []ModelInfo, sortBy string, desc bool) {
	// Simple bubble sort for demonstration
	for i := 0; i < len(models)-1; i++ {
		for j := i + 1; j < len(models); j++ {
			shouldSwap := false

			switch sortBy {
			case "name":
				if desc {
					shouldSwap = models[i].Name < models[j].Name
				} else {
					shouldSwap = models[i].Name > models[j].Name
				}
			case "provider":
				if desc {
					shouldSwap = models[i].Provider < models[j].Provider
				} else {
					shouldSwap = models[i].Provider > models[j].Provider
				}
			case "context_window":
				if desc {
					shouldSwap = models[i].ContextWindow < models[j].ContextWindow
				} else {
					shouldSwap = models[i].ContextWindow > models[j].ContextWindow
				}
			default:
				// Default sort by ID
				if desc {
					shouldSwap = models[i].ID < models[j].ID
				} else {
					shouldSwap = models[i].ID > models[j].ID
				}
			}

			if shouldSwap {
				models[i], models[j] = models[j], models[i]
			}
		}
	}
}

// sortModelGroups sorts model groups based on the specified field
func (a *AdminServer) sortModelGroups(groups []ModelGroupInfo, sortBy string, desc bool) {
	// Simple bubble sort for demonstration
	for i := 0; i < len(groups)-1; i++ {
		for j := i + 1; j < len(groups); j++ {
			shouldSwap := false

			switch sortBy {
			case "name":
				if desc {
					shouldSwap = groups[i].Name < groups[j].Name
				} else {
					shouldSwap = groups[i].Name > groups[j].Name
				}
			case "description":
				if desc {
					shouldSwap = groups[i].Description < groups[j].Description
				} else {
					shouldSwap = groups[i].Description > groups[j].Description
				}
			case "model_count":
				if desc {
					shouldSwap = len(groups[i].Models) < len(groups[j].Models)
				} else {
					shouldSwap = len(groups[i].Models) > len(groups[j].Models)
				}
			default:
				// Default sort by name
				if desc {
					shouldSwap = groups[i].Name < groups[j].Name
				} else {
					shouldSwap = groups[i].Name > groups[j].Name
				}
			}

			if shouldSwap {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}
}

// validateModelGroupCreateRequest validates model group creation request
func (a *AdminServer) validateModelGroupCreateRequest(req *ModelGroupCreateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("Model group name is required")
	}

	if !a.isValidModelGroupName(req.Name) {
		return fmt.Errorf("Model group name must contain only alphanumeric characters, hyphens, and underscores")
	}

	if len(req.Models) == 0 {
		return fmt.Errorf("At least one model is required")
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

// isValidModelGroupName validates model group name format
func (a *AdminServer) isValidModelGroupName(name string) bool {
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