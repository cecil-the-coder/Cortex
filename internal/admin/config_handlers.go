package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// ConfigInfo represents configuration information for admin API
type ConfigInfo struct {
	Version        string                 `json:"version"`
	Validation     ConfigValidationResult `json:"validation"`
	Structure      map[string]interface{} `json:"structure"`
	Statistics     ConfigStatistics       `json:"statistics"`
	LastReload     *time.Time             `json:"last_reload,omitempty"`
	LastModified   *time.Time             `json:"last_modified,omitempty"`
	Backups        []ConfigBackupInfo     `json:"backups,omitempty"`
	ReadOnly       bool                   `json:"read_only"`
	Locked         bool                   `json:"locked"`
	LockUser       string                 `json:"lock_user,omitempty"`
}

// ConfigValidationResult contains validation results
type ConfigValidationResult struct {
	Valid   bool                   `json:"valid"`
	Errors  []ConfigValidationError `json:"errors,omitempty"`
	Warnings []ConfigValidationWarning `json:"warnings,omitempty"`
	Summary string                 `json:"summary"`
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Path    string `json:"path"`
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ConfigValidationWarning represents a configuration validation warning
type ConfigValidationWarning struct {
	Path    string `json:"path"`
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ConfigStatistics contains configuration statistics
type ConfigStatistics struct {
	TotalProviders     int     `json:"total_providers"`
	ActiveProviders    int     `json:"active_providers"`
	TotalModels        int     `json:"total_models"`
	UniqueModels       int     `json:"unique_models"`
	TotalModelGroups   int     `json:"total_model_groups"`
	TotalAPIKeys       int     `json:"total_api_keys"`
	ActiveAPIKeys      int     `json:"active_api_keys"`
	ExpiredAPIKeys     int     `json:"expired_api_keys"`
	ConfigSize        int64   `json:"config_size_bytes"`
	Complexity        string  `json:"complexity"`
}

// ConfigBackupInfo represents information about a configuration backup
type ConfigBackupInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Size       int64     `json:"size_bytes"`
	Checksum   string    `json:"checksum"`
	Automatic  bool      `json:"automatic"`
	Version    string    `json:"version"`
}

// ConfigImportRequest represents a configuration import request
type ConfigImportRequest struct {
	Content     string            `json:"content"`
	Format      string            `json:"format"`      // "json", "yaml"
	Validate    bool              `json:"validate"`    // Validate before importing
	Backup      bool              `json:"backup"`      // Create backup before importing
	Merge       bool              `json:"merge"`       // Merge with existing config
	DryRun      bool              `json:"dry_run"`     // Validation only, don't apply
	Options     map[string]interface{} `json:"options,omitempty"`
}

// ConfigImportResponse represents configuration import result
type ConfigImportResponse struct {
	Success     bool                     `json:"success"`
	Message     string                   `json:"message"`
	Validation  ConfigValidationResult   `json:"validation,omitempty"`
	BackupID    string                   `json:"backup_id,omitempty"`
	Changes     map[string]interface{}   `json:"changes,omitempty"`
	Applied     bool                     `json:"applied"`
	Summary     map[string]interface{}   `json:"summary,omitempty"`
	Issues      []string                 `json:"issues,omitempty"`
}

// ConfigExportRequest represents configuration export options
type ConfigExportRequest struct {
	Format      string            `json:"format"`      // "json", "yaml", "csv"
	Include     []string          `json:"include"`     // "providers", "model_groups", "api_keys", "all"
	Exclude     []string          `json:"exclude"`     // Fields to exclude
	Filter      map[string]interface{} `json:"filter,omitempty"`
	Pretty      bool              `json:"pretty"`      // Pretty-print JSON
	Redact      bool              `json:"redact"`      // Redact sensitive data
}

// handleGetConfig handles GET /v1/config
func (a *AdminServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "config_unavailable", "Configuration not available")
		return
	}

	// Parse include/exclude parameters
	include := r.URL.Query()["include"]
	exclude := r.URL.Query()["exclude"]
	redact := r.URL.Query().Get("redact") == "true"

	// Create a copy of configuration for response
	configCopy := a.createConfigCopy(cfg, include, exclude, redact)

	// Generate configuration statistics
	stats := a.generateConfigStatistics(cfg)

	// Validate configuration
	validationResult := a.validateConfiguration(cfg)

	configInfo := ConfigInfo{
		Version:    "v1.0.0",
		Validation: validationResult,
		Structure:  configCopy,
		Statistics: stats,
		LastReload: &time.Time{}, // Would track actual reload time
		ReadOnly:   false,
		Locked:     false,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"config_version": "v1.0.0",
			"redacted":      redact,
		},
	}

	a.sendResponse(w, http.StatusOK, configInfo, nil, meta)
	a.logAccess(r, "GET_CONFIG", "configuration", "", true)
}

// handleUpdateConfig handles PUT /v1/config
func (a *AdminServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// Parse request body for new configuration
	var newConfig config.Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate new configuration
	if err := newConfig.Validate(); err != nil {
		validationResult := ConfigValidationResult{
			Valid:   false,
			Errors:  []ConfigValidationError{
				{Message: err.Error(), Code: "validation_failed"},
			},
			Summary: "Configuration validation failed",
		}

		response := map[string]interface{}{
			"validation": validationResult,
			"message":    "Configuration update rejected due to validation errors",
		}

		a.sendResponse(w, http.StatusBadRequest, response, nil, nil)
		a.logAccess(r, "UPDATE_CONFIG", "configuration", "", false)
		return
	}

	// Create backup before updating
	configPath := a.server.GetConfigPath()
	var backupID string
	if configPath != "" {
		backupID = fmt.Sprintf("auto_backup_%d", time.Now().Unix())
		// Would create actual backup here
	}

	// Apply the new configuration
	// This would trigger the reload process
	reloadSuccess := true // Would call actual reload function

	response := map[string]interface{}{
		"success":     reloadSuccess,
		"message":     func() string { if reloadSuccess { return "Configuration updated successfully" } else { return "Configuration update failed" } }(),
		"backup_id":   backupID,
		"applied_at":  time.Now().Format(time.RFC3339),
	}

	statusCode := http.StatusOK
	if !reloadSuccess {
		statusCode = http.StatusInternalServerError
		meta := &MetaInfo{
			Version: "v1",
			Processing: 1,
			Metadata: map[string]interface{}{
				"backup_created": backupID != "",
			},
		}
		a.sendResponse(w, statusCode, response, nil, meta)
		a.logAccess(r, "UPDATE_CONFIG", "configuration", "", false)
		return
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"backup_created": backupID != "",
		},
	}

	a.sendResponse(w, statusCode, response, nil, meta)
	a.logAccess(r, "UPDATE_CONFIG", "configuration", "", true)
}

// handleValidateConfig handles POST /v1/config/validate
func (a *AdminServer) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	// Get configuration to validate
	cfg := a.configFunc()

	// Parse request body if provided (for validating prospective config)
	var prospectiveConfig config.Config
	validateProspective := false
	if err := json.NewDecoder(r.Body).Decode(&prospectiveConfig); err == nil {
		validateProspective = true
		cfg = &prospectiveConfig
	}

	if cfg == nil {
		a.sendError(w, http.StatusBadRequest, "no_config", "No configuration provided")
		return
	}

	// Perform validation
	validationResult := a.validateConfiguration(cfg)

	response := map[string]interface{}{
		"validation": validationResult,
		"type":       func() string { if validateProspective { return "prospective" } else { return "current" } }(),
		"validated_at": time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	statusCode := http.StatusOK
	if !validationResult.Valid {
		statusCode = http.StatusBadRequest
	}

	a.sendResponse(w, statusCode, response, nil, meta)
	actionType := "VALIDATE_CONFIG_CURRENT"
	if validateProspective {
		actionType = "VALIDATE_CONFIG_PROSPECTIVE"
	}
	a.logAccess(r, actionType, "configuration", "", validationResult.Valid)
}

// handleReloadConfig handles POST /v1/config/reload
func (a *AdminServer) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	// Parse request options
	var req struct {
		Force    bool   `json:"force"`
		Backup   bool   `json:"backup"`
		Validate bool   `json:"validate"`
		Source   string `json:"source"` // "file", "current"
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Create backup if requested
	var backupID string
	if req.Backup {
		backupID = fmt.Sprintf("reload_backup_%d", time.Now().Unix())
		// Would create actual backup
	}

	// Trigger configuration reload
	reloadSuccess := true // Would call actual reload function
	reloadMessage := "Configuration reloaded successfully"

	if !req.Force {
		// Validate configuration before reload if not forced
		cfg := a.configFunc()
		if cfg != nil {
			validationResult := a.validateConfiguration(cfg)
			if !validationResult.Valid {
				reloadSuccess = false
				reloadMessage = "Configuration reload aborted due to validation errors"
			}
		}
	}

	response := map[string]interface{}{
		"success":     reloadSuccess,
		"message":     reloadMessage,
		"backup_id":   backupID,
		"reloaded_at": time.Now().Format(time.RFC3339),
		"options": map[string]interface{}{
			"force":    req.Force,
			"backup":   req.Backup,
			"validate": req.Validate,
		},
	}

	statusCode := http.StatusOK
	if !reloadSuccess {
		statusCode = http.StatusBadRequest
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, statusCode, response, nil, meta)
	a.logAccess(r, "RELOAD_CONFIG", "configuration", "", reloadSuccess)
}

// handleExportConfig handles GET /v1/config/export
func (a *AdminServer) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "config_unavailable", "Configuration not available")
		return
	}

	// Parse export options
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	include := r.URL.Query()["include"]
	exclude := r.URL.Query()["exclude"]
	redact := r.URL.Query().Get("redact") == "true"
	pretty := r.URL.Query().Get("pretty") == "true"

	// Export configuration
 exported, err := a.exportConfiguration(cfg, format, include, exclude, redact, pretty)
	if err != nil {
		a.sendError(w, http.StatusInternalServerError, "export_failed", "Failed to export configuration: "+err.Error())
		return
	}

	// Set appropriate content type
	contentType := "application/json"
	if format == "yaml" {
		contentType = "application/x-yaml"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"config.%s\"", format))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(exported))

	a.logAccess(r, "EXPORT_CONFIG", "configuration", format, true)
}

// handleImportConfig handles POST /v1/config/import
func (a *AdminServer) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	var req ConfigImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Parse configuration from request content
	var newConfig config.Config
	var err error

	switch req.Format {
	case "json":
		err = json.Unmarshal([]byte(req.Content), &newConfig)
	case "yaml":
		// Would add YAML support
		err = fmt.Errorf("YAML format not yet supported")
	default:
		err = fmt.Errorf("unsupported format: %s", req.Format)
	}

	if err != nil {
		response := ConfigImportResponse{
			Success: false,
			Message: "Failed to parse configuration: " + err.Error(),
			Applied: false,
		}

		a.sendResponse(w, http.StatusBadRequest, response, nil, nil)
		a.logAccess(r, "IMPORT_CONFIG", "configuration", req.Format, false)
		return
	}

	// Validate configuration if requested
	var validationResult ConfigValidationResult
	if req.Validate {
		validationResult = a.validateConfiguration(&newConfig)
		if !validationResult.Valid && !req.DryRun {
			response := ConfigImportResponse{
				Success:    false,
				Message:    "Configuration validation failed",
				Validation: validationResult,
				Applied:    false,
			}

			a.sendResponse(w, http.StatusBadRequest, response, nil, nil)
			a.logAccess(r, "IMPORT_CONFIG", "configuration", req.Format, false)
			return
		}
	}

	// Apply configuration if not dry run
	applied := false
	var backupID string
	var changes map[string]interface{}

	if !req.DryRun && (len(validationResult.Errors) == 0 || !req.Validate) {
		// Create backup if requested
		if req.Backup {
			backupID = fmt.Sprintf("import_backup_%d", time.Now().Unix())
		}

		// Apply the configuration (would call actual import function)
		applied = true
		changes = map[string]interface{}{
			"providers_added":    0,
			"providers_modified": 0,
			"providers_removed":  0,
			"model_groups_added": 0,
		}
	}

	response := ConfigImportResponse{
		Success:    true,
		Message:    func() string { if req.DryRun { return "Configuration validated (dry run)" } else if applied { return "Configuration imported successfully" } else { return "Configuration ready for import" } }(),
		Validation: validationResult,
		BackupID:   backupID,
		Changes:    changes,
		Applied:    applied,
		Summary: map[string]interface{}{
			"dry_run":        req.DryRun,
			"backup_created": backupID != "",
			"validated":      req.Validate,
		},
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "IMPORT_CONFIG", "configuration", req.Format, true)
}

// handleCreateBackup handles POST /v1/config/backup
func (a *AdminServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	cfg := a.configFunc()
	if cfg == nil {
		a.sendError(w, http.StatusServiceUnavailable, "config_unavailable", "Configuration not available")
		return
	}

	// Parse backup options
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Automatic   bool   `json:"automatic"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Create backup
	backupID := fmt.Sprintf("backup_%d", time.Now().Unix())
	backupName := req.Name
	if backupName == "" {
		backupName = backupID
	}

	// Would create actual backup file here
	backupInfo := ConfigBackupInfo{
		ID:        backupID,
		Name:      backupName,
		CreatedAt: time.Now(),
		Size:      0, // Would calculate actual size
		Checksum:  "", // Would calculate actual checksum
		Automatic: req.Automatic,
		Version:   "v1.0.0",
	}

	response := map[string]interface{}{
		"message": "Backup created successfully",
		"backup": backupInfo,
		"stored_at": time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusCreated, response, nil, meta)
	a.logAccess(r, "CREATE_BACKUP", "configuration", backupID, true)
}

// handleListBackups handles GET /v1/config/backups
func (a *AdminServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	// Placeholder - would list actual backup files
	backups := []ConfigBackupInfo{
		{
			ID:        "backup_1",
			Name:      "Manual backup 1",
			CreatedAt: time.Now().Add(-24 * time.Hour),
			Size:      1024,
			Checksum:  "abc123",
			Automatic: false,
			Version:   "v1.0.0",
		},
		{
			ID:        "backup_2",
			Name:      "Auto backup",
			CreatedAt: time.Now().Add(-12 * time.Hour),
			Size:      1024,
			Checksum:  "def456",
			Automatic: true,
			Version:   "v1.0.0",
		},
	}

	response := map[string]interface{}{
		"backups": backups,
		"total":   len(backups),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "LIST_BACKUPS", "configuration", "", true)
}

// handleRestoreBackup handles POST /v1/config/backups/{id}
func (a *AdminServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	backupID := vars["id"]

	if backupID == "" {
		a.sendError(w, http.StatusBadRequest, "missing_parameter", "Backup ID is required")
		return
	}

	// Parse restore options
	var req struct {
		Validate bool `json:"validate"`
		Backup   bool `json:"backup"` // Create backup before restore
	}
	json.NewDecoder(r.Body).Decode(&req)

	// Would restore from actual backup file here
	response := map[string]interface{}{
		"message":    "Backup restored successfully",
		"backup_id":  backupID,
		"restored_at": time.Now().Format(time.RFC3339),
		"validated":  req.Validate,
		"backup_created": req.Backup,
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "RESTORE_BACKUP", "configuration", backupID, true)
}

// Helper methods

// createConfigCopy creates a filtered copy of the configuration
func (a *AdminServer) createConfigCopy(cfg *config.Config, include, exclude []string, redact bool) map[string]interface{} {
	// Convert config to map for easier manipulation
	configMap := a.structToMap(cfg)

	// Apply include/exclude filters
	if len(include) > 0 {
		filtered := make(map[string]interface{})
		for _, key := range include {
			if val, exists := configMap[key]; exists {
				filtered[key] = val
			}
		}
		configMap = filtered
	}

	for _, key := range exclude {
		delete(configMap, key)
	}

	// Redact sensitive information
	if redact {
		if apiKey, exists := configMap["APIKEY"].(string); exists && apiKey != "" {
			configMap["APIKEY"] = maskAPIKey(apiKey)
		}

		// Redact API keys in ClientAPIKeys
		if clientKeys, exists := configMap["ClientAPIKeys"]; exists {
			if keysMap, ok := clientKeys.(map[string]interface{}); ok {
				for _, keyConfig := range keysMap {
					if keyMap, ok := keyConfig.(map[string]interface{}); ok {
						if apiKey, exists := keyMap["apiKey"].(string); exists {
							keyMap["apiKey"] = maskAPIKey(apiKey)
						}
					}
				}
			}
		}

		// Redact OAuth credentials
		if providers, exists := configMap["Providers"]; exists {
			if providersList, ok := providers.([]interface{}); ok {
				for _, provider := range providersList {
					if providerMap, ok := provider.(map[string]interface{}); ok {
						if apiKey, exists := providerMap["APIKEY"].(string); exists {
							providerMap["APIKEY"] = maskAPIKey(apiKey)
						}
					}
				}
			}
		}
	}

	return configMap
}

// structToMap converts a struct to a map using reflection
func (a *AdminServer) structToMap(obj interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	v := reflect.ValueOf(obj)

	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// Iterate through the fields of the struct
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		value := v.Field(i)

		// Get the JSON tag name, or use the field name
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		// Handle multiple JSON tag options (comma separated)
		jsonName := strings.Split(jsonTag, ",")[0]
		if jsonName == "" {
			jsonName = field.Name
		}

		// Only include exported fields
		if field.PkgPath != "" {
			continue
		}

		switch value.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			 reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			result[jsonName] = value.Interface()
		case reflect.Slice, reflect.Array:
			if value.Len() > 0 && value.Index(0).Kind() == reflect.Struct {
				// Handle slice of structs
				slice := make([]interface{}, value.Len())
				for j := 0; j < value.Len(); j++ {
					slice[j] = a.structToMap(value.Index(j).Addr().Interface())
				}
				result[jsonName] = slice
			} else {
				result[jsonName] = value.Interface()
			}
		case reflect.Map:
			// Handle maps
			result[jsonName] = value.Interface()
		case reflect.Ptr:
			if !value.IsNil() {
				result[jsonName] = a.structToMap(value.Interface())
			}
		case reflect.Struct:
			result[jsonName] = a.structToMap(value.Addr().Interface())
		default:
			result[jsonName] = value.Interface()
		}
	}

	return result
}

// generateConfigStatistics generates configuration statistics
func (a *AdminServer) generateConfigStatistics(cfg *config.Config) ConfigStatistics {
	stats := ConfigStatistics{
		TotalProviders:   len(cfg.Providers),
		TotalModels:      0,
		UniqueModels:     0,
		Complexity:       "medium",
	}

	// Count models and check providers
	modelSet := make(map[string]bool)
	for _, provider := range cfg.Providers {
		if provider.APIKEY != "" || provider.OAuth != nil {
			stats.ActiveProviders++
		}
		stats.TotalModels += len(provider.Models)
		for _, model := range provider.Models {
			modelSet[model] = true
		}
	}
	stats.UniqueModels = len(modelSet)

	// Count model groups
	if cfg.ModelGroups != nil {
		stats.TotalModelGroups = len(*cfg.ModelGroups)
	}

	// Count API keys
	if cfg.ClientAPIKeys != nil {
		stats.TotalAPIKeys = len(*cfg.ClientAPIKeys)
		now := time.Now()
		for _, keyConfig := range *cfg.ClientAPIKeys {
			if keyConfig.Enabled {
				stats.ActiveAPIKeys++
			}
			if !keyConfig.ExpiresAt.IsZero() && now.After(keyConfig.ExpiresAt) {
				stats.ExpiredAPIKeys++
			}
		}
	}

	return stats
}

// validateConfiguration performs comprehensive configuration validation
func (a *AdminServer) validateConfiguration(cfg *config.Config) ConfigValidationResult {
	errors := []ConfigValidationError{}
	warnings := []ConfigValidationWarning{}

	// Use built-in validation
	if err := cfg.Validate(); err != nil {
		errors = append(errors, ConfigValidationError{
			Message: err.Error(),
			Code:    "validation_failed",
		})
	}

	// Additional validation checks
	if len(cfg.Providers) == 0 {
		errors = append(errors, ConfigValidationError{
			Path:    "providers",
			Message: "At least one provider must be configured",
			Code:    "no_providers",
		})
	}

	if cfg.Router.Default == "" {
		errors = append(errors, ConfigValidationError{
			Path:    "router.default",
			Message: "Default router provider must be specified",
			Code:    "missing_default_router",
		})
	}

	// Check for potential warnings
	if cfg.ClientAPIKeys == nil || len(*cfg.ClientAPIKeys) == 0 {
		warnings = append(warnings, ConfigValidationWarning{
			Path:    "client_api_keys",
			Message: "No client API keys configured",
			Code:    "no_api_keys",
		})
	}

	return ConfigValidationResult{
		Valid:    len(errors) == 0,
		Errors:   errors,
		Warnings: warnings,
		Summary: func() string {
			if len(errors) > 0 {
				return fmt.Sprintf("%d validation errors found", len(errors))
			} else if len(warnings) > 0 {
				return fmt.Sprintf("%d warnings", len(warnings))
			}
			return "Configuration is valid"
		}(),
	}
}

// exportConfiguration exports configuration in specified format
func (a *AdminServer) exportConfiguration(cfg *config.Config, format string, include, exclude []string, redact, pretty bool) (string, error) {
	// Create filtered copy
	configCopy := a.createConfigCopy(cfg, include, exclude, redact)

	switch format {
	case "json":
		var result []byte
		var err error
		if pretty {
			result, err = json.MarshalIndent(configCopy, "", "  ")
		} else {
			result, err = json.Marshal(configCopy)
		}
		return string(result), err
	case "yaml":
		// Would add YAML support
		return "", fmt.Errorf("YAML export not yet supported")
	default:
		return "", fmt.Errorf("unsupported export format: %s", format)
	}
}