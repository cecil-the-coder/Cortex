package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// BaseRepository provides common functionality for all repository implementations
type BaseRepository struct {
	db     *sql.DB
	logger *slog.Logger
	dbType string
}

// NewBaseRepository creates a new base repository
func NewBaseRepository(db *sql.DB, logger *slog.Logger, dbType string) *BaseRepository {
	return &BaseRepository{
		db:     db,
		logger: logger,
		dbType: dbType,
	}
}

// Common implementation methods that work for both SQLite and MySQL

func (r *BaseRepository) CreateProvider(ctx context.Context, provider *Provider) error {
	if provider == nil {
		return fmt.Errorf("provider cannot be nil")
	}

	// Validate provider fields
	if strings.TrimSpace(provider.Name) == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	validAuthMethods := []string{"api_key", "oauth", "hybrid"}
	isValidAuth := false
	for _, method := range validAuthMethods {
		if provider.AuthMethod == method {
			isValidAuth = true
			break
		}
	}
	if !isValidAuth {
		return fmt.Errorf("invalid auth method: %s", provider.AuthMethod)
	}

	if strings.TrimSpace(provider.BaseURL) == "" {
		return fmt.Errorf("provider base URL cannot be empty")
	}

	query := `
		INSERT INTO providers (name, auth_method, api_key, base_url, use_core_api, core_api_features,
			oauth_credentials, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	if r.dbType == "mysql" {
		query = strings.ReplaceAll(query, "?", "%s")
		query = fmt.Sprintf(query, "?", "?", "?", "?", "?", "?", "?", "?", "?", "?")
	}

	result, err := r.db.ExecContext(ctx, query,
		provider.Name,
		provider.AuthMethod,
		provider.APIKey,
		provider.BaseURL,
		provider.UseCoreAPI,
		nullStringSlice(provider.CoreAPIFeatures),
		nullOAuthCred(provider.OAuth),
		provider.Enabled,
		time.Now(),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get provider ID: %w", err)
	}

	provider.ID = id
	return nil
}

func (r *BaseRepository) GetProvider(ctx context.Context, id int64) (*Provider, error) {
	query := `
		SELECT id, name, auth_method, api_key, base_url, use_core_api, core_api_features,
			oauth_credentials, enabled, created_at, updated_at
		FROM providers
		WHERE id = ?
	`

	var provider Provider
	var coreAPIFeatures sql.NullString
	var oauthBytes []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&provider.ID,
		&provider.Name,
		&provider.AuthMethod,
		&provider.APIKey,
		&provider.BaseURL,
		&provider.UseCoreAPI,
		&coreAPIFeatures,
		&oauthBytes,
		&provider.Enabled,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("provider not found")
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	if coreAPIFeatures.Valid {
		provider.CoreAPIFeatures = strings.Split(coreAPIFeatures.String, ",")
	}

	if len(oauthBytes) > 0 {
		provider.OAuth = &OAuthCredentialSet{}
		// TODO: Unmarshal OAuth credentials from JSON
	}

	return &provider, nil
}

func (r *BaseRepository) GetProviderByName(ctx context.Context, name string) (*Provider, error) {
	query := `
		SELECT id, name, auth_method, api_key, base_url, use_core_api, core_api_features,
			oauth_credentials, enabled, created_at, updated_at
		FROM providers
		WHERE name = ?
	`

	var provider Provider
	var coreAPIFeatures sql.NullString
	var oauthBytes []byte

	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&provider.ID,
		&provider.Name,
		&provider.AuthMethod,
		&provider.APIKey,
		&provider.BaseURL,
		&provider.UseCoreAPI,
		&coreAPIFeatures,
		&oauthBytes,
		&provider.Enabled,
		&provider.CreatedAt,
		&provider.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("provider not found")
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	if coreAPIFeatures.Valid {
		provider.CoreAPIFeatures = strings.Split(coreAPIFeatures.String, ",")
	}

	if len(oauthBytes) > 0 {
		provider.OAuth = &OAuthCredentialSet{}
		// TODO: Unmarshal OAuth credentials from JSON
	}

	return &provider, nil
}

func (r *BaseRepository) UpdateProvider(ctx context.Context, provider *Provider) error {
	query := `
		UPDATE providers
		SET name = ?, auth_method = ?, api_key = ?, base_url = ?, use_core_api = ?,
			core_api_features = ?, oauth_credentials = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		provider.Name,
		provider.AuthMethod,
		provider.APIKey,
		provider.BaseURL,
		provider.UseCoreAPI,
		nullStringSlice(provider.CoreAPIFeatures),
		nullOAuthCred(provider.OAuth),
		provider.Enabled,
		time.Now(),
		provider.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	return nil
}

func (r *BaseRepository) DeleteProvider(ctx context.Context, id int64) error {
	query := "DELETE FROM providers WHERE id = ?"
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("provider not found")
	}

	return nil
}

func (r *BaseRepository) ListProviders(ctx context.Context, filter *ProviderFilter) ([]*Provider, error) {
	query := `
		SELECT id, name, auth_method, api_key, base_url, use_core_api, core_api_features,
			oauth_credentials, enabled, created_at, updated_at
		FROM providers
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	if filter.Name != "" {
		query += fmt.Sprintf(" AND name LIKE $%d", argIndex)
		args = append(args, "%"+filter.Name+"%")
		argIndex++
	}

	if filter.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argIndex)
		args = append(args, *filter.Enabled)
		argIndex++
	}

	query += " ORDER BY name"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
	}

	// Replace $1, $2 with ? for MySQL
	if r.dbType == "mysql" {
		query = strings.ReplaceAll(query, "$", "?")
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}
	defer rows.Close()

	var providers []*Provider
	for rows.Next() {
		var provider Provider
		var coreAPIFeatures sql.NullString
		var oauthBytes []byte

		err := rows.Scan(
			&provider.ID,
			&provider.Name,
			&provider.AuthMethod,
			&provider.APIKey,
			&provider.BaseURL,
			&provider.UseCoreAPI,
			&coreAPIFeatures,
			&oauthBytes,
			&provider.Enabled,
			&provider.CreatedAt,
			&provider.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan provider: %w", err)
		}

		if coreAPIFeatures.Valid {
			provider.CoreAPIFeatures = strings.Split(coreAPIFeatures.String, ",")
		}

		if len(oauthBytes) > 0 {
			provider.OAuth = &OAuthCredentialSet{}
			// TODO: Unmarshal OAuth credentials from JSON
		}

		providers = append(providers, &provider)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating providers: %w", err)
	}

	return providers, nil
}

func (r *BaseRepository) StoreRequestMetrics(ctx context.Context, metrics *RequestMetrics) error {
	if metrics == nil {
		return fmt.Errorf("metrics cannot be nil")
	}

	// Validate metrics fields
	if strings.TrimSpace(metrics.RequestID) == "" {
		return fmt.Errorf("request ID cannot be empty")
	}

	if metrics.ProviderID <= 0 {
		return fmt.Errorf("provider ID must be positive")
	}

	if metrics.ModelID <= 0 {
		return fmt.Errorf("model ID must be positive")
	}

	if metrics.InputTokens < 0 {
		return fmt.Errorf("input tokens cannot be negative")
	}

	if metrics.OutputTokens < 0 {
		return fmt.Errorf("output tokens cannot be negative")
	}

	if metrics.TotalTokens < 0 {
		return fmt.Errorf("total tokens cannot be negative")
	}

	if metrics.LatencyMs < 0 {
		return fmt.Errorf("latency cannot be negative")
	}

	if metrics.StatusCode <= 0 {
		return fmt.Errorf("status code must be positive")
	}

	if metrics.Cost < 0 {
		return fmt.Errorf("cost cannot be negative")
	}

	query := `
		INSERT INTO request_metrics (
			timestamp, request_id, api_key_id, provider_id, model_id, model_group_id,
			request_type, input_tokens, output_tokens, total_tokens, latency_ms,
			status_code, error_message, request_size_bytes, response_size_bytes,
			streaming, vision_content, tool_use, thinking_mode, cost, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		metrics.Timestamp,
		metrics.RequestID,
		nullInt64(metrics.APIKeyID),
		metrics.ProviderID,
		metrics.ModelID,
		nullInt64(metrics.ModelGroupID),
		metrics.RequestType,
		metrics.InputTokens,
		metrics.OutputTokens,
		metrics.TotalTokens,
		metrics.LatencyMs,
		metrics.StatusCode,
		nullString(metrics.ErrorMessage),
		metrics.RequestSize,
		metrics.ResponseSize,
		metrics.Streaming,
		metrics.VisionContent,
		metrics.ToolUse,
		metrics.ThinkingMode,
		metrics.Cost,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to store request metrics: %w", err)
	}

	return nil
}

func (r *BaseRepository) StoreBatchRequestMetrics(ctx context.Context, metrics []*RequestMetrics) error {
	if len(metrics) == 0 {
		return nil
	}

	// Begin transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO request_metrics (
			timestamp, request_id, api_key_id, provider_id, model_id, model_group_id,
			request_type, input_tokens, output_tokens, total_tokens, latency_ms,
			status_code, error_message, request_size_bytes, response_size_bytes,
			streaming, vision_content, tool_use, thinking_mode, cost, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, metric := range metrics {
		_, err := stmt.ExecContext(ctx,
			metric.Timestamp,
			metric.RequestID,
			nullInt64(metric.APIKeyID),
			metric.ProviderID,
			metric.ModelID,
			nullInt64(metric.ModelGroupID),
			metric.RequestType,
			metric.InputTokens,
			metric.OutputTokens,
			metric.TotalTokens,
			metric.LatencyMs,
			metric.StatusCode,
			nullString(metric.ErrorMessage),
			metric.RequestSize,
			metric.ResponseSize,
			metric.Streaming,
			metric.VisionContent,
			metric.ToolUse,
			metric.ThinkingMode,
			metric.Cost,
			time.Now(),
		)

		if err != nil {
			return fmt.Errorf("failed to execute batch insert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}

	r.logger.Debug("Stored batch request metrics", "count", len(metrics))
	return nil
}

func (r *BaseRepository) GetRequestMetrics(ctx context.Context, query *MetricsQuery) ([]*RequestMetrics, error) {
	sqlQuery := `
		SELECT id, timestamp, request_id, api_key_id, provider_id, model_id, model_group_id,
			request_type, input_tokens, output_tokens, total_tokens, latency_ms,
			status_code, error_message, request_size_bytes, response_size_bytes,
			streaming, vision_content, tool_use, thinking_mode, cost, created_at
		FROM request_metrics
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	if query.ProviderID != nil {
		sqlQuery += fmt.Sprintf(" AND provider_id = $%d", argIndex)
		args = append(args, *query.ProviderID)
		argIndex++
	}

	if query.ModelID != nil {
		sqlQuery += fmt.Sprintf(" AND model_id = $%d", argIndex)
		args = append(args, *query.ModelID)
		argIndex++
	}

	if query.APIKeyID != nil {
		sqlQuery += fmt.Sprintf(" AND api_key_id = $%d", argIndex)
		args = append(args, *query.APIKeyID)
		argIndex++
	}

	if query.StatusCode != nil {
		sqlQuery += fmt.Sprintf(" AND status_code = $%d", argIndex)
		args = append(args, *query.StatusCode)
		argIndex++
	}

	if !query.TimeRange.From.IsZero() {
		sqlQuery += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, query.TimeRange.From)
		argIndex++
	}

	if !query.TimeRange.To.IsZero() {
		sqlQuery += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, query.TimeRange.To)
		argIndex++
	}

	// Add ordering
	if query.OrderBy != "" {
		sqlQuery += " ORDER BY " + query.OrderBy
	} else {
		sqlQuery += " ORDER BY timestamp DESC"
	}

	// Add limit and offset
	if query.Limit > 0 {
		sqlQuery += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, query.Limit)
		argIndex++

		if query.Offset > 0 {
			sqlQuery += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, query.Offset)
		}
	}

	// Replace $1, $2 with ? for MySQL
	if r.dbType == "mysql" {
		sqlQuery = strings.ReplaceAll(sqlQuery, "$", "?")
	}

	rows, err := r.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get request metrics: %w", err)
	}
	defer rows.Close()

	var metrics []*RequestMetrics
	for rows.Next() {
		var metric RequestMetrics
		var errMsg sql.NullString

		err := rows.Scan(
			&metric.ID,
			&metric.Timestamp,
			&metric.RequestID,
			&metric.APIKeyID,
			&metric.ProviderID,
			&metric.ModelID,
			&metric.ModelGroupID,
			&metric.RequestType,
			&metric.InputTokens,
			&metric.OutputTokens,
			&metric.TotalTokens,
			&metric.LatencyMs,
			&metric.StatusCode,
			&errMsg,
			&metric.RequestSize,
			&metric.ResponseSize,
			&metric.Streaming,
			&metric.VisionContent,
			&metric.ToolUse,
			&metric.ThinkingMode,
			&metric.Cost,
			&metric.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan metric: %w", err)
		}

		if errMsg.Valid {
			metric.ErrorMessage = errMsg.String
		}

		metrics = append(metrics, &metric)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating metrics: %w", err)
	}

	return metrics, nil
}

func (r *BaseRepository) CleanupOldMetrics(ctx context.Context, olderThan time.Time) error {
	query := "DELETE FROM request_metrics WHERE created_at < ?"
	result, err := r.db.ExecContext(ctx, query, olderThan)
	if err != nil {
		return fmt.Errorf("failed to cleanup old metrics: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get cleanup count: %w", err)
	}

	r.logger.Info("Cleaned up old metrics", "count", rowsAffected, "older_than", olderThan)
	return nil
}

func (r *BaseRepository) GetMetricsRetention(ctx context.Context) (time.Duration, error) {
	// Default retention period of 30 days
	return 30 * 24 * time.Hour, nil
}

func (r *BaseRepository) GetProviderHealthStats(ctx context.Context, providerID int64, timeRange TimeRange) (map[string]interface{}, error) {
	query := `
		SELECT
			COUNT(*) as total_requests,
			AVG(latency_ms) as avg_latency,
			SUM(cost) as total_cost,
			SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
			SUM(CASE WHEN status_code < 400 THEN 1 ELSE 0 END) as success_count
		FROM request_metrics
		WHERE provider_id = ? AND timestamp >= ? AND timestamp <= ?
	`

	var totalRequests int64
	var avgLatency float64
	var totalCost float64
	var errorCount int64
	var successCount int64

	err := r.db.QueryRowContext(ctx, query, providerID, timeRange.From, timeRange.To).Scan(
		&totalRequests,
		&avgLatency,
		&totalCost,
		&errorCount,
		&successCount,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get provider health stats: %w", err)
	}

	return map[string]interface{}{
		"total_requests": totalRequests,
		"avg_latency_ms": avgLatency,
		"total_cost":     totalCost,
		"error_count":    errorCount,
		"success_count":  successCount,
		"success_rate":   float64(successCount) / float64(totalRequests) * 100,
	}, nil
}

func (r *BaseRepository) GetSystemMetrics(ctx context.Context, timeRange TimeRange) (map[string]interface{}, error) {
	// Handle empty time range
	if timeRange.From.IsZero() || timeRange.To.IsZero() {
		return map[string]interface{}{
			"total_requests":     int64(0),
			"active_providers":   int64(0),
			"active_models":      int64(0),
			"total_tokens":       int64(0),
			"total_cost":         0.0,
		}, nil
	}

	query := `
		SELECT
			COUNT(*) as total_requests,
			COUNT(DISTINCT provider_id) as active_providers,
			COUNT(DISTINCT model_id) as active_models,
			SUM(input_tokens + output_tokens) as total_tokens,
			SUM(cost) as total_cost
		FROM request_metrics
		WHERE timestamp >= ? AND timestamp <= ?
	`

	var totalRequests, activeProviders, activeModels, totalTokens int64
	var totalCost float64

	err := r.db.QueryRowContext(ctx, query, timeRange.From, timeRange.To).Scan(
		&totalRequests,
		&activeProviders,
		&activeModels,
		&totalTokens,
		&totalCost,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get system metrics: %w", err)
	}

	return map[string]interface{}{
		"total_requests":   totalRequests,
		"active_providers": activeProviders,
		"active_models":    activeModels,
		"total_tokens":     totalTokens,
		"total_cost":       totalCost,
	}, nil
}

// Helper functions for NULL handling
func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func nullStringSlice(slice []string) sql.NullString {
	if len(slice) == 0 {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: strings.Join(slice, ","), Valid: true}
}

func nullInt64(i *int64) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Int64: *i, Valid: true}
}

func nullOAuthCred(oauth *OAuthCredentialSet) []byte {
	if oauth == nil {
		return nil
	}
	// TODO: Marshal OAuth to JSON
	return []byte("{}")
}

// Additional MetricsRepository methods

func (r *BaseRepository) BatchRecordRequests(ctx context.Context, metrics []*RequestMetrics) error {
	return r.StoreBatchRequestMetrics(ctx, metrics)
}

func (r *BaseRepository) RecordProviderHealth(ctx context.Context, health interface{}) error {
	// For now, this is a no-op as provider health is tracked separately
	// TODO: Implement provider health recording if needed
	return nil
}

func (r *BaseRepository) AggregateMetrics(ctx context.Context) error {
	// For now, this is a no-op as aggregation is handled in GetAggregatedMetrics
	// TODO: Implement background metrics aggregation if needed
	return nil
}