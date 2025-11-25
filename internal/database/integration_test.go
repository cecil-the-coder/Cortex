package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
)

// TestDatabaseIntegration tests integration between different database types
func TestDatabaseIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Test SQLite integration
	t.Run("SQLite integration", func(t *testing.T) {
		db, _ := setupTestDB(t)
		defer db.Close()

		testFullWorkflow(t, db)
	})

	// Test MySQL integration if available
	t.Run("MySQL integration", func(t *testing.T) {
		mysqlDB := setupTestMySQLIfExists(t)
		if mysqlDB == nil {
			t.Skip("MySQL not available for integration testing")
		}
		defer mysqlDB.Close()
		defer cleanupMySQLTestDatabase(t, mysqlDB)

		testFullWorkflow(t, mysqlDB)
	})
}

// testFullWorkflow runs a complete workflow test on a database implementation
func testFullWorkflow(t *testing.T, db Database) {
	ctx := context.Background()

	// Test database health
	err := db.HealthCheck(ctx)
	assert.NoError(t, err)
	assert.NoError(t, db.Ping(ctx))

	// Test basic CRUD operations
	testCRUDWorkflow(t, db)

	// Test metrics operations
	testMetricsWorkflow(t, db)

	// Test transactions
	testTransactionWorkflow(t, db)

	// Test batch operations
	testBatchWorkflow(t, db)
}

// testCRUDWorkflow tests create, read, update, delete operations
func testCRUDWorkflow(t *testing.T, db Database) {
	ctx := context.Background()

	// Create provider
	provider := &Provider{
		Name:       "integration-test-provider",
		AuthMethod: "api_key",
		APIKey:     "integration-key",
		BaseURL:    "https://integration.example.com",
		UseCoreAPI: true,
		CoreAPIFeatures: []string{"streaming", "tools"},
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)
	assert.NotZero(t, provider.ID)

	// Retrieve provider
	retrieved, err := db.GetProvider(ctx, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, provider.Name, retrieved.Name)
	assert.Equal(t, provider.AuthMethod, retrieved.AuthMethod)

	// Create model
	model := &Model{
		ProviderID:       provider.ID,
		ModelName:        "integration-test-model",
		DisplayName:      "Integration Test Model",
		MaxContextTokens: 4096,
		SupportsVision:   true,
		SupportsTools:    true,
		InputCostPer1k:   0.002,
		OutputCostPer1k:  0.004,
		Enabled:          true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(t, err)
	assert.NotZero(t, model.ID)

	// Retrieve model
	retrievedModel, err := db.GetModel(ctx, model.ID)
	require.NoError(t, err)
	assert.Equal(t, model.ModelName, retrievedModel.ModelName)
	assert.Equal(t, model.DisplayName, retrievedModel.DisplayName)

	// Update provider
	provider.BaseURL = "https://updated-integration.example.com"
	provider.Enabled = false
	err = db.UpdateProvider(ctx, provider)
	require.NoError(t, err)

	// Verify update
	updatedProvider, err := db.GetProvider(ctx, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://updated-integration.example.com", updatedProvider.BaseURL)
	assert.False(t, updatedProvider.Enabled)

	// Create model group
	group := &ModelGroup{
		Name:        "integration-test-group",
		Description: "A test model group for integration testing",
	}

	err = db.CreateModelGroup(ctx, group)
	require.NoError(t, err)
	assert.NotZero(t, group.ID)

	// Add model to group
	member := &GroupMember{
		GroupID:                 group.ID,
		ProviderID:              provider.ID,
		ModelID:                 model.ID,
		Alias:                   "integration-alias",
		MaxContextTokensOverride: intPtr(2048), // Test pointer field
	}

	err = db.AddGroupMember(ctx, member)
	require.NoError(t, err)
	assert.NotZero(t, member.ID)

	// Get group members
	members, err := db.GetGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, "integration-alias", members[0].Alias)
	assert.Equal(t, intPtr(2048), members[0].MaxContextTokensOverride)

	// List model groups
	groups, err := db.ListModelGroups(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(groups), 1)

	// List providers with filters
	enabled := false
	filter := &ProviderFilter{
		Name:    "%integration%",
		Enabled: &enabled,
		Limit:   10,
	}

	providers, err := db.ListProviders(ctx, filter)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(providers), 1)

	// List models with filters
	providerID := provider.ID
	enabled = true // Fix: should be true since we created the model as enabled
	modelFilter := &ModelFilter{
		ProviderID: &providerID,
		ModelName:  "integration",
		Enabled:    &enabled,
		Limit:      10,
	}

	models, err := db.ListModels(ctx, modelFilter)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(models), 1)

	// Delete operations
	err = db.RemoveGroupMember(ctx, member.ID)
	require.NoError(t, err)

	err = db.DeleteModelGroup(ctx, group.ID)
	require.NoError(t, err)

	err = db.DeleteModel(ctx, model.ID)
	require.NoError(t, err)

	err = db.DeleteProvider(ctx, provider.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = db.GetProvider(ctx, provider.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// testMetricsWorkflow tests metrics storage and retrieval
func testMetricsWorkflow(t *testing.T, db Database) {
	ctx := context.Background()

	// Create test provider and model
	provider := &Provider{
		Name:       "metrics-integration-provider",
		AuthMethod: "api_key",
		APIKey:     "metrics-key",
		BaseURL:    "https://metrics.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "metrics-integration-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(t, err)

	// Test single metrics storage
	now := time.Now()
	metrics := &RequestMetrics{
		RequestID:    "metrics-integration-req",
		ProviderID:   provider.ID,
		ModelID:      model.ID,
		RequestType:  "chat",
		InputTokens:  250,
		OutputTokens: 125,
		TotalTokens:  375,
		LatencyMs:    2000,
		StatusCode:   200,
		RequestSize:  1000,
		ResponseSize: 2000,
		Streaming:    true,
		VisionContent: true,
		ToolUse:      false,
		ThinkingMode: false,
		Cost:         0.015,
		Timestamp:    now,
	}

	err = db.StoreRequestMetrics(ctx, metrics)
	require.NoError(t, err)

	// Test batch metrics storage
	batch := make([]*RequestMetrics, 20)
	for i := 0; i < 20; i++ {
		batch[i] = &RequestMetrics{
			RequestID:     fmt.Sprintf("metrics-batch-req-%d", i),
			ProviderID:    provider.ID,
			ModelID:       model.ID,
			RequestType:   "chat",
			InputTokens:   200 + i*5,
			OutputTokens:  100 + i*3,
			TotalTokens:   300 + i*8,
			LatencyMs:     1500 + i*50,
			StatusCode:    200,
			RequestSize:   800 + i*20,
			ResponseSize:  1600 + i*40,
			Streaming:     i%3 == 0,
			VisionContent: i%4 == 0,
			ToolUse:       i%2 == 0,
			ThinkingMode:  i%5 == 0,
			Cost:          0.01 + float64(i)*0.001,
			Timestamp:     now.Add(time.Duration(i) * time.Minute),
		}
	}

	err = db.StoreBatchRequestMetrics(ctx, batch)
	require.NoError(t, err)

	// Test metrics retrieval
	query := &MetricsQuery{
		ProviderID: &provider.ID,
		ModelID:    &model.ID,
		TimeRange:  TimeRange{From: now.Add(-time.Hour), To: now.Add(time.Hour)},
		Limit:      25,
		OrderBy:    "timestamp ASC",
	}

	retrieved, err := db.GetRequestMetrics(ctx, query)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(retrieved), 20)

	// Verify batch data
	batchFound := 0
	for _, m := range retrieved {
		if m.RequestID == "metrics-integration-req" {
			assert.Equal(t, 375, m.TotalTokens)
			assert.Equal(t, true, m.Streaming)
			assert.Equal(t, true, m.VisionContent)
		}
		if m.RequestID != "metrics-integration-req" {
			batchFound++
		}
	}
	assert.GreaterOrEqual(t, batchFound, 20)

	// Test aggregated metrics
	aggQuery := &AggregatedQuery{
		TimeRange:    TimeRange{From: now.Add(-time.Hour), To: now.Add(time.Hour)},
		GroupBy:      "hour",
		Metrics:      []string{"count", "tokens", "cost", "latency"},
		TimeInterval: "1h",
	}

	_, err = db.GetAggregatedMetrics(ctx, aggQuery)
	require.NoError(t, err)
	// Should have at least one aggregation result

	// Test provider health stats
	timeRange := TimeRange{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	healthStats, err := db.GetProviderHealthStats(ctx, provider.ID, timeRange)
	require.NoError(t, err)

	assert.Contains(t, healthStats, "total_requests")
	assert.Contains(t, healthStats, "avg_latency_ms")
	assert.Contains(t, healthStats, "success_rate")
	assert.Contains(t, healthStats, "total_cost")

	// Test system metrics
	systemStats, err := db.GetSystemMetrics(ctx, timeRange)
	require.NoError(t, err)

	assert.Contains(t, systemStats, "total_requests")
	assert.Contains(t, systemStats, "active_providers")
	assert.Contains(t, systemStats, "active_models")
	assert.Contains(t, systemStats, "total_tokens")

	// Test metrics cleanup
	cutoffTime := now.Add(-time.Hour * 24)
	err = db.CleanupOldMetrics(ctx, cutoffTime)
	require.NoError(t, err)

	// Get metrics retention period
	retention, err := db.GetMetricsRetention(ctx)
	require.NoError(t, err)
	assert.Greater(t, retention, time.Duration(0))
}

// testTransactionWorkflow tests transaction support
func testTransactionWorkflow(t *testing.T, db Database) {
	ctx := context.Background()

	t.Run("successful transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)

		// Create provider in transaction
		provider := &Provider{
			Name:       "tx-integration-provider",
			AuthMethod: "api_key",
			APIKey:     "tx-integration-key",
			BaseURL:    "https://tx-integration.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		require.NoError(t, err)
		assert.NotZero(t, provider.ID)

		// Create model in transaction
		model := &Model{
			ProviderID: provider.ID,
			ModelName:  "tx-integration-model",
			Enabled:    true,
		}

		err = tx.CreateModel(ctx, model)
		require.NoError(t, err)
		assert.NotZero(t, model.ID)

		// Store metrics in transaction
		metrics := &RequestMetrics{
			RequestID:    "tx-integration-req",
			ProviderID:   provider.ID,
			ModelID:      model.ID,
			RequestType:  "chat",
			InputTokens:  100,
			OutputTokens: 50,
			TotalTokens:  150,
			LatencyMs:    1000,
			StatusCode:   200,
			Cost:         0.005,
			Timestamp:    time.Now(),
		}

		err = tx.StoreRequestMetrics(ctx, metrics)
		require.NoError(t, err)

		// Commit transaction
		err = tx.Commit()
		require.NoError(t, err)

		// Verify data persisted
		retrievedProvider, err := db.GetProvider(ctx, provider.ID)
		require.NoError(t, err)
		assert.Equal(t, provider.Name, retrievedProvider.Name)

		retrievedModel, err := db.GetModel(ctx, model.ID)
		require.NoError(t, err)
		assert.Equal(t, model.ModelName, retrievedModel.ModelName)

		// Query metrics
		query := &MetricsQuery{
			ProviderID: &provider.ID,
			Limit:      1,
		}
		retrievedMetrics, err := db.GetRequestMetrics(ctx, query)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(retrievedMetrics), 1)

		// Cleanup
		db.DeleteModel(ctx, model.ID)
		db.DeleteProvider(ctx, provider.ID)
	})

	t.Run("rollback transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)

		// Create provider in transaction
		provider := &Provider{
			Name:       "rollback-integration-provider",
			AuthMethod: "api_key",
			APIKey:     "rollback-integration-key",
			BaseURL:    "https://rollback-integration.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		require.NoError(t, err)

		// Rollback transaction
		err = tx.Rollback()
		require.NoError(t, err)

		// Verify data was not persisted
		_, err = db.GetProvider(ctx, provider.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// testBatchWorkflow tests batch processing capabilities
func testBatchWorkflow(t *testing.T, db Database) {
	ctx := context.Background()

	// Create test provider and model
	provider := &Provider{
		Name:       "batch-integration-provider",
		AuthMethod: "api_key",
		APIKey:     "batch-integration-key",
		BaseURL:    "https://batch-integration.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "batch-integration-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(t, err)

	// Test large batch processing
	batchSizes := []int{10, 50, 100, 200}

	for _, batchSize := range batchSizes {
		t.Run(fmt.Sprintf("batch_size_%d", batchSize), func(t *testing.T) {
			batch := make([]*RequestMetrics, batchSize)
			now := time.Now()

			for i := 0; i < batchSize; i++ {
				batch[i] = &RequestMetrics{
					RequestID:     fmt.Sprintf("batch-test-req-%d", i),
					ProviderID:    provider.ID,
					ModelID:       model.ID,
					RequestType:   "chat",
					InputTokens:   100 + i*2,
					OutputTokens:  50 + i,
					TotalTokens:   150 + i*3,
					LatencyMs:     1000 + i*10,
					StatusCode:    200,
					RequestSize:   500 + i*5,
					ResponseSize:  1000 + i*10,
					Streaming:     i%3 == 0,
					VisionContent: i%4 == 0,
					ToolUse:       i%2 == 0,
					ThinkingMode:  i%5 == 0,
					Cost:          0.005 + float64(i)*0.001,
					Timestamp:     now.Add(time.Duration(i) * time.Millisecond),
				}
			}

			// Measure batch insertion time
			start := time.Now()
			err = db.StoreBatchRequestMetrics(ctx, batch)
			assert.NoError(t, err)
			duration := time.Since(start)

			// Verify performance is reasonable (should complete within reasonable time)
			assert.Less(t, duration, time.Second*10, "Batch insertion took too long")

			// Give some time for async processing if applicable
			time.Sleep(100 * time.Millisecond)

			// Verify all metrics were stored
			query := &MetricsQuery{
				ProviderID: &provider.ID,
				TimeRange:  TimeRange{From: now.Add(-time.Minute), To: now.Add(time.Minute)},
				Limit:      batchSize + 100,
			}

			stored, err := db.GetRequestMetrics(ctx, query)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(stored), batchSize)
		})
	}

	// Cleanup
	db.DeleteModel(ctx, model.ID)
	db.DeleteProvider(ctx, provider.ID)
}

// Helper functions
func intPtr(i int) *int {
	return &i
}

func setupTestMySQLIfExists(t *testing.T) *MySQLDatabase {
	mysqlDB, _ := setupTestMySQL(t)
	return mysqlDB
}

func cleanupMySQLTestDatabase(t *testing.T, mysqlDB *MySQLDatabase) {
	if mysqlDB == nil {
		return
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/",
		mysqlDB.config.Username,
		mysqlDB.config.Password,
		mysqlDB.config.Host,
		mysqlDB.config.Port,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Logf("Failed to open MySQL connection for cleanup: %v", err)
		return
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", mysqlDB.config.Database))
	if err != nil {
		t.Logf("Failed to cleanup test MySQL database: %v", err)
	}
}

// Benchmark database operations
func BenchmarkDatabaseOperations(b *testing.B) {
	// SQLite benchmarks
	b.Run("SQLite", func(b *testing.B) {
		logger := slog.Default()
		tempDir := b.TempDir()
		dbPath := filepath.Join(tempDir, "bench.db")

		config := &DatabaseConfig{
			Type:            "sqlite",
			SQLitePath:      dbPath,
			SQLiteWALMode:   true,
			SQLiteCacheSize: 2000,
			MaxOpenConns:    1,
			MaxIdleConns:    1,
			BatchSize:       100,
			FlushInterval:   time.Second * 5,
		}

		db, err := NewSQLiteDatabase(config, logger)
		require.NoError(b, err)

		ctx := context.Background()
		err = db.Connect(ctx)
		require.NoError(b, err)

		err = db.Migrate(ctx)
		require.NoError(b, err)

		defer db.Close()

		benchmarkProviderCRUD(b, db)
		benchmarkMetricsStorage(b, db)
		benchmarkBatchStorage(b, db)
	})
}

func benchmarkProviderCRUD(b *testing.B, db Database) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider := &Provider{
			Name:       fmt.Sprintf("bench-provider-%d", i),
			AuthMethod: "api_key",
			APIKey:     fmt.Sprintf("bench-key-%d", i),
			BaseURL:    "https://bench.example.com",
			Enabled:    true,
		}

		// Create
		err := db.CreateProvider(ctx, provider)
		require.NoError(b, err)

		// Get
		_, err = db.GetProvider(ctx, provider.ID)
		require.NoError(b, err)

		// Update
		provider.BaseURL = "https://bench-updated.example.com"
		err = db.UpdateProvider(ctx, provider)
		require.NoError(b, err)

		// Delete
		err = db.DeleteProvider(ctx, provider.ID)
		require.NoError(b, err)
	}
}

func benchmarkMetricsStorage(b *testing.B, db Database) {
	ctx := context.Background()

	// Setup provider and model
	provider := &Provider{
		Name:       "bench-metrics-provider",
		AuthMethod: "api_key",
		APIKey:     "bench-metrics-key",
		BaseURL:    "https://bench-metrics.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(b, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "bench-metrics-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(b, err)

	defer func() {
		db.DeleteModel(ctx, model.ID)
		db.DeleteProvider(ctx, provider.ID)
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := &RequestMetrics{
			RequestID:     fmt.Sprintf("bench-req-%d", i),
			ProviderID:    provider.ID,
			ModelID:       model.ID,
			RequestType:   "chat",
			InputTokens:   100 + i,
			OutputTokens:  50 + i,
			TotalTokens:   150 + i*2,
			LatencyMs:     1000 + i*10,
			StatusCode:    200,
			Cost:          0.005 + float64(i)*0.001,
			Timestamp:     time.Now(),
		}

		err := db.StoreRequestMetrics(ctx, metrics)
		require.NoError(b, err)
	}
}

func benchmarkBatchStorage(b *testing.B, db Database) {
	ctx := context.Background()

	// Setup provider and model
	provider := &Provider{
		Name:       "bench-batch-provider",
		AuthMethod: "api_key",
		APIKey:     "bench-batch-key",
		BaseURL:    "https://bench-batch.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(b, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "bench-batch-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(b, err)

	defer func() {
		db.DeleteModel(ctx, model.ID)
		db.DeleteProvider(ctx, provider.ID)
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := make([]*RequestMetrics, 50)
		now := time.Now()

		for j := 0; j < 50; j++ {
			batch[j] = &RequestMetrics{
				RequestID:     fmt.Sprintf("bench-batch-%d-%d", i, j),
				ProviderID:    provider.ID,
				ModelID:       model.ID,
				RequestType:   "chat",
				InputTokens:   100,
				OutputTokens:  50,
				TotalTokens:   150,
				LatencyMs:     1000,
				StatusCode:    200,
				Cost:          0.005,
				Timestamp:     now.Add(time.Duration(j) * time.Millisecond),
			}
		}

		err := db.StoreBatchRequestMetrics(ctx, batch)
		require.NoError(b, err)
	}
}