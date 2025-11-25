package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
)

// Implement remaining ConfigRepository methods for SQLite
func (s *SQLiteDatabase) CreateProvider(ctx context.Context, provider *Provider) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.CreateProvider(ctx, provider)
}

func (s *SQLiteDatabase) GetProvider(ctx context.Context, id int64) (*Provider, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetProvider(ctx, id)
}

func (s *SQLiteDatabase) GetProviderByName(ctx context.Context, name string) (*Provider, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetProviderByName(ctx, name)
}

func (s *SQLiteDatabase) UpdateProvider(ctx context.Context, provider *Provider) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.UpdateProvider(ctx, provider)
}

func (s *SQLiteDatabase) DeleteProvider(ctx context.Context, id int64) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.DeleteProvider(ctx, id)
}

func (s *SQLiteDatabase) ListProviders(ctx context.Context, filter *ProviderFilter) ([]*Provider, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.ListProviders(ctx, filter)
}

func (s *SQLiteDatabase) CreateModel(ctx context.Context, model *Model) error {
	query := `
		INSERT INTO models (provider_id, model_name, display_name, max_context_tokens,
			supports_vision, supports_tools, input_cost_per_1k, output_cost_per_1k,
			enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.ExecContext(ctx, query,
		model.ProviderID,
		model.ModelName,
		nullString(model.DisplayName),
		model.MaxContextTokens,
		model.SupportsVision,
		model.SupportsTools,
		model.InputCostPer1k,
		model.OutputCostPer1k,
		model.Enabled,
		time.Now(),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create model: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get model ID: %w", err)
	}

	model.ID = id
	return nil
}

func (s *SQLiteDatabase) GetModel(ctx context.Context, id int64) (*Model, error) {
	query := `
		SELECT id, provider_id, model_name, display_name, max_context_tokens,
			supports_vision, supports_tools, input_cost_per_1k, output_cost_per_1k,
			enabled, created_at, updated_at
		FROM models
		WHERE id = ?
	`

	var model Model
	var displayName sql.NullString

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&displayName,
		&model.MaxContextTokens,
		&model.SupportsVision,
		&model.SupportsTools,
		&model.InputCostPer1k,
		&model.OutputCostPer1k,
		&model.Enabled,
		&model.CreatedAt,
		&model.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("model not found")
		}
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	if displayName.Valid {
		model.DisplayName = displayName.String
	}

	return &model, nil
}

func (s *SQLiteDatabase) GetModelByName(ctx context.Context, providerID int64, modelName string) (*Model, error) {
	query := `
		SELECT id, provider_id, model_name, display_name, max_context_tokens,
			supports_vision, supports_tools, input_cost_per_1k, output_cost_per_1k,
			enabled, created_at, updated_at
		FROM models
		WHERE provider_id = ? AND model_name = ?
	`

	var model Model
	var displayName sql.NullString

	err := s.db.QueryRowContext(ctx, query, providerID, modelName).Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&displayName,
		&model.MaxContextTokens,
		&model.SupportsVision,
		&model.SupportsTools,
		&model.InputCostPer1k,
		&model.OutputCostPer1k,
		&model.Enabled,
		&model.CreatedAt,
		&model.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("model not found")
		}
		return nil, fmt.Errorf("failed to get model: %w", err)
	}

	if displayName.Valid {
		model.DisplayName = displayName.String
	}

	return &model, nil
}

func (s *SQLiteDatabase) UpdateModel(ctx context.Context, model *Model) error {
	query := `
		UPDATE models
		SET provider_id = ?, model_name = ?, display_name = ?, max_context_tokens = ?,
			supports_vision = ?, supports_tools = ?, input_cost_per_1k = ?,
			output_cost_per_1k = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.ExecContext(ctx, query,
		model.ProviderID,
		model.ModelName,
		nullString(model.DisplayName),
		model.MaxContextTokens,
		model.SupportsVision,
		model.SupportsTools,
		model.InputCostPer1k,
		model.OutputCostPer1k,
		model.Enabled,
		time.Now(),
		model.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update model: %w", err)
	}

	return nil
}

func (s *SQLiteDatabase) DeleteModel(ctx context.Context, id int64) error {
	query := "DELETE FROM models WHERE id = ?"
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete model: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("model not found")
	}

	return nil
}

func (s *SQLiteDatabase) ListModels(ctx context.Context, filter *ModelFilter) ([]*Model, error) {
	query := `
		SELECT id, provider_id, model_name, display_name, max_context_tokens,
			supports_vision, supports_tools, input_cost_per_1k, output_cost_per_1k,
			enabled, created_at, updated_at
		FROM models
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	if filter.ProviderID != nil {
		query += fmt.Sprintf(" AND provider_id = $%d", argIndex)
		args = append(args, *filter.ProviderID)
		argIndex++
	}

	if filter.ModelName != "" {
		query += fmt.Sprintf(" AND model_name LIKE $%d", argIndex)
		args = append(args, "%"+filter.ModelName+"%")
		argIndex++
	}

	if filter.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argIndex)
		args = append(args, *filter.Enabled)
		argIndex++
	}

	query += " ORDER BY model_name"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
	}

	// Replace $1, $2 with ? for MySQL compatibility (though this is SQLite)
	query = s.replaceQueryPlaceholders(query)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	defer rows.Close()

	var models []*Model
	for rows.Next() {
		var model Model
		var displayName sql.NullString

		err := rows.Scan(
			&model.ID,
			&model.ProviderID,
			&model.ModelName,
			&displayName,
			&model.MaxContextTokens,
			&model.SupportsVision,
			&model.SupportsTools,
			&model.InputCostPer1k,
			&model.OutputCostPer1k,
			&model.Enabled,
			&model.CreatedAt,
			&model.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan model: %w", err)
		}

		if displayName.Valid {
			model.DisplayName = displayName.String
		}

		models = append(models, &model)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating models: %w", err)
	}

	return models, nil
}

// MetricsRepository implementation
func (s *SQLiteDatabase) StoreRequestMetrics(ctx context.Context, metrics *RequestMetrics) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.StoreRequestMetrics(ctx, metrics)
}

func (s *SQLiteDatabase) StoreBatchRequestMetrics(ctx context.Context, metrics []*RequestMetrics) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.StoreBatchRequestMetrics(ctx, metrics)
}

func (s *SQLiteDatabase) GetRequestMetrics(ctx context.Context, query *MetricsQuery) ([]*RequestMetrics, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetRequestMetrics(ctx, query)
}

func (s *SQLiteDatabase) GetAggregatedMetrics(ctx context.Context, query *AggregatedQuery) ([]*AggregatedMetrics, error) {
	// Basic implementation - can be enhanced for better aggregation
	var sqlQuery string
	var args []interface{}

	switch query.GroupBy {
	case "hour":
		sqlQuery = `
			SELECT datetime(timestamp, 'start of hour') as time_bucket,
				COUNT(*) as count,
				SUM(total_tokens) as tokens,
				SUM(cost) as cost,
				AVG(latency_ms) as latency
			FROM request_metrics
			WHERE timestamp >= ? AND timestamp <= ?
			GROUP BY datetime(timestamp, 'start of hour')
			ORDER BY time_bucket
		`
	case "day":
		sqlQuery = `
			SELECT date(timestamp) as time_bucket,
				COUNT(*) as count,
				SUM(total_tokens) as tokens,
				SUM(cost) as cost,
				AVG(latency_ms) as latency
			FROM request_metrics
			WHERE timestamp >= ? AND timestamp <= ?
			GROUP BY date(timestamp)
			ORDER BY time_bucket
		`
	default:
		return nil, fmt.Errorf("unsupported group by: %s", query.GroupBy)
	}

	args = []interface{}{query.TimeRange.From, query.TimeRange.To}

	rows, err := s.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated metrics: %w", err)
	}
	defer rows.Close()

	var aggregated []*AggregatedMetrics
	for rows.Next() {
		var agg AggregatedMetrics
		var timeBucket sql.NullString
		var count, tokens int64
		var cost, latency float64

		err := rows.Scan(&timeBucket, &count, &tokens, &cost, &latency)
		if err != nil {
			return nil, fmt.Errorf("failed to scan aggregated metrics: %w", err)
		}

		agg.Labels = make(map[string]string)
		if timeBucket.Valid {
			agg.Labels["time_bucket"] = timeBucket.String
		}
		agg.Values = map[string]interface{}{
			"count":   count,
			"tokens":  tokens,
			"cost":    cost,
			"latency": latency,
		}
		// Parse time_bucket back to time.Time if needed
		// For simplicity, using current time
		agg.Timestamp = time.Now()

		aggregated = append(aggregated, &agg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating aggregated metrics: %w", err)
	}

	return aggregated, nil
}

func (s *SQLiteDatabase) CleanupOldMetrics(ctx context.Context, olderThan time.Time) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.CleanupOldMetrics(ctx, olderThan)
}

func (s *SQLiteDatabase) GetMetricsRetention(ctx context.Context) (time.Duration, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetMetricsRetention(ctx)
}

func (s *SQLiteDatabase) GetProviderHealthStats(ctx context.Context, providerID int64, timeRange TimeRange) (map[string]interface{}, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetProviderHealthStats(ctx, providerID, timeRange)
}

func (s *SQLiteDatabase) GetSystemMetrics(ctx context.Context, timeRange TimeRange) (map[string]interface{}, error) {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.GetSystemMetrics(ctx, timeRange)
}

// Additional MetricsRepository methods
func (s *SQLiteDatabase) BatchRecordRequests(ctx context.Context, metrics []*RequestMetrics) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.BatchRecordRequests(ctx, metrics)
}

func (s *SQLiteDatabase) RecordProviderHealth(ctx context.Context, health interface{}) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.RecordProviderHealth(ctx, health)
}

func (s *SQLiteDatabase) AggregateMetrics(ctx context.Context) error {
	baseRepo := NewBaseRepository(s.db, s.logger, "sqlite")
	return baseRepo.AggregateMetrics(ctx)
}

// Remaining ConfigRepository methods (placeholders for now)
func (s *SQLiteDatabase) CreateModelGroup(ctx context.Context, group *ModelGroup) error {
	query := `
		INSERT INTO model_groups (name, description, created_at, updated_at)
		VALUES (?, ?, ?, ?)
	`

	result, err := s.db.ExecContext(ctx, query,
		group.Name,
		nullString(group.Description),
		time.Now(),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create model group: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get model group ID: %w", err)
	}

	group.ID = id
	return nil
}

func (s *SQLiteDatabase) GetModelGroup(ctx context.Context, id int64) (*ModelGroup, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM model_groups
		WHERE id = ?
	`

	var group ModelGroup
	var description sql.NullString

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&group.ID,
		&group.Name,
		&description,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("model group not found")
		}
		return nil, fmt.Errorf("failed to get model group: %w", err)
	}

	if description.Valid {
		group.Description = description.String
	}

	return &group, nil
}

func (s *SQLiteDatabase) GetModelGroupByName(ctx context.Context, name string) (*ModelGroup, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM model_groups
		WHERE name = ?
	`

	var group ModelGroup
	var description sql.NullString

	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&group.ID,
		&group.Name,
		&description,
		&group.CreatedAt,
		&group.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("model group not found")
		}
		return nil, fmt.Errorf("failed to get model group: %w", err)
	}

	if description.Valid {
		group.Description = description.String
	}

	return &group, nil
}

func (s *SQLiteDatabase) UpdateModelGroup(ctx context.Context, group *ModelGroup) error {
	query := `
		UPDATE model_groups
		SET name = ?, description = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := s.db.ExecContext(ctx, query,
		group.Name,
		nullString(group.Description),
		time.Now(),
		group.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update model group: %w", err)
	}

	return nil
}

func (s *SQLiteDatabase) DeleteModelGroup(ctx context.Context, id int64) error {
	query := "DELETE FROM model_groups WHERE id = ?"
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete model group: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("model group not found")
	}

	return nil
}

func (s *SQLiteDatabase) ListModelGroups(ctx context.Context) ([]*ModelGroup, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM model_groups
		ORDER BY name
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list model groups: %w", err)
	}
	defer rows.Close()

	var groups []*ModelGroup
	for rows.Next() {
		var group ModelGroup
		var description sql.NullString

		err := rows.Scan(
			&group.ID,
			&group.Name,
			&description,
			&group.CreatedAt,
			&group.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan model group: %w", err)
		}

		if description.Valid {
			group.Description = description.String
		}

		groups = append(groups, &group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating model groups: %w", err)
	}

	return groups, nil
}

func (s *SQLiteDatabase) AddGroupMember(ctx context.Context, member *GroupMember) error {
	query := `
		INSERT INTO group_members (group_id, provider_id, model_id, alias, max_context_tokens_override, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := s.db.ExecContext(ctx, query,
		member.GroupID,
		member.ProviderID,
		member.ModelID,
		nullString(member.Alias),
		nullInt(member.MaxContextTokensOverride),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to add group member: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get group member ID: %w", err)
	}

	member.ID = id
	return nil
}

func (s *SQLiteDatabase) RemoveGroupMember(ctx context.Context, id int64) error {
	query := "DELETE FROM group_members WHERE id = ?"
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to remove group member: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("group member not found")
	}

	return nil
}

func (s *SQLiteDatabase) GetGroupMembers(ctx context.Context, groupID int64) ([]*GroupMember, error) {
	query := `
		SELECT id, group_id, provider_id, model_id, alias, max_context_tokens_override, created_at
		FROM group_members
		WHERE group_id = ?
		ORDER BY created_at
	`

	rows, err := s.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group members: %w", err)
	}
	defer rows.Close()

	var members []*GroupMember
	for rows.Next() {
		var member GroupMember
		var alias sql.NullString
		var maxTokensOverride sql.NullInt64

		err := rows.Scan(
			&member.ID,
			&member.GroupID,
			&member.ProviderID,
			&member.ModelID,
			&alias,
			&maxTokensOverride,
			&member.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan group member: %w", err)
		}

		if alias.Valid {
			member.Alias = alias.String
		}

		if maxTokensOverride.Valid {
			val := int(maxTokensOverride.Int64)
			member.MaxContextTokensOverride = &val
		}

		members = append(members, &member)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group members: %w", err)
	}

	return members, nil
}

// Implement remaining methods as placeholders for now
func (s *SQLiteDatabase) CreateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	// TODO: Implement API key management
	return fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) GetAPIKey(ctx context.Context, id int64) (*ClientAPIKey, error) {
	// TODO: Implement API key management
	return nil, fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) GetAPIKeyByKeyID(ctx context.Context, keyID string) (*ClientAPIKey, error) {
	// TODO: Implement API key management
	return nil, fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) UpdateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	// TODO: Implement API key management
	return fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) DeleteAPIKey(ctx context.Context, id int64) error {
	// TODO: Implement API key management
	return fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) ListAPIKeys(ctx context.Context, filter *APIKeyFilter) ([]*ClientAPIKey, error) {
	// TODO: Implement API key management
	return nil, fmt.Errorf("API key management not implemented yet")
}

func (s *SQLiteDatabase) GetRouterConfig(ctx context.Context) (*RouterConfig, error) {
	// TODO: Implement router configuration management
	return nil, fmt.Errorf("Router configuration management not implemented yet")
}

func (s *SQLiteDatabase) UpdateRouterConfig(ctx context.Context, config *RouterConfig) error {
	// TODO: Implement router configuration management
	return fmt.Errorf("Router configuration management not implemented yet")
}

func (s *SQLiteDatabase) ExportConfig(ctx context.Context) (*config.Config, error) {
	// TODO: Implement configuration export
	return nil, fmt.Errorf("Configuration export not implemented yet")
}

func (s *SQLiteDatabase) ImportConfig(ctx context.Context, cfg *config.Config) error {
	// TODO: Implement configuration import
	return fmt.Errorf("Configuration import not implemented yet")
}

// Helper functions
func (s *SQLiteDatabase) replaceQueryPlaceholders(query string) string {
	// SQLite uses ? natively, so no replacement needed
	return query
}


func nullInt(i *int) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
}