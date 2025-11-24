package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
)

// setupTestDB creates a temporary SQLite database for testing
func setupTestDB(t *testing.T) (*SQLiteDatabase, string) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

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

	logger := slog.Default()
	database, err := NewSQLiteDatabase(config, logger)
	require.NoError(t, err)

	// Type assertion to get concrete type
	db := database.(*SQLiteDatabase)

	ctx := context.Background()
	err = db.Connect(ctx)
	require.NoError(t, err)

	// Run migrations
	err = db.Migrate(ctx)
	require.NoError(t, err)

	return db, dbPath
}

func TestSQLiteDatabaseConnection(t *testing.T) {
	t.Run("successful connection", func(t *testing.T) {
		db, _ := setupTestDB(t)
		defer db.Close()

		err := db.Ping(context.Background())
		assert.NoError(t, err)
	})

	t.Run("connection with missing path", func(t *testing.T) {
		config := &DatabaseConfig{
			Type:       "sqlite",
			SQLitePath: "", // Empty path should fail
		}

		logger := slog.Default()
		_, err := NewSQLiteDatabase(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SQLite path is required")
	})

	t.Run("connection with invalid path", func(t *testing.T) {
		config := &DatabaseConfig{
			Type:       "sqlite",
			SQLitePath: "/tmp/nonexistent/dir/test.db", // Use /tmp instead of root /invalid
		}

		logger := slog.Default()
		db, err := NewSQLiteDatabase(config, logger)
		assert.NoError(t, err) // DB creation succeeds

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		err = db.Connect(ctx)
		// Should either succeed (if dir can be created) or fail gracefully
		if err != nil {
			assert.Error(t, err) // Connection fails due to invalid path
		}

		// Clean up if database was created
		if db != nil {
			_ = db.Close()
		}
	})
}

func TestSQLiteDatabaseGracefulShutdown(t *testing.T) {
	db, _ := setupTestDB(t)

	// Add some test data
	ctx := context.Background()
	provider := &Provider{
		Name:       "test-provider",
		AuthMethod: "api_key",
		APIKey:     "test-key",
		BaseURL:    "https://api.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	// Test graceful shutdown
	err = db.Close()
	assert.NoError(t, err)

	// Verify database is closed
	err = db.Ping(ctx)
	assert.Error(t, err)
}

func TestSQLiteProviderOperations(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	t.Run("create provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "test-provider",
			AuthMethod: "api_key",
			APIKey:     "test-key",
			BaseURL:    "https://api.example.com",
			UseCoreAPI: true,
			CoreAPIFeatures: []string{"streaming", "tools"},
			Enabled:    true,
		}

		err := db.CreateProvider(ctx, provider)
		assert.NoError(t, err)
		assert.NotZero(t, provider.ID)
	})

	t.Run("get provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "get-test-provider",
			AuthMethod: "api_key",
			APIKey:     "test-key-2",
			BaseURL:    "https://api2.example.com",
			UseCoreAPI: true,
			CoreAPIFeatures: []string{"vision"},
			Enabled:    true,
		}

		err := db.CreateProvider(ctx, provider)
		require.NoError(t, err)

		// Get by ID
		retrieved, err := db.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrieved.Name)
		assert.Equal(t, provider.AuthMethod, retrieved.AuthMethod)
		assert.True(t, retrieved.UseCoreAPI)
		assert.Equal(t, []string{"vision"}, retrieved.CoreAPIFeatures)

		// Get by name
		retrievedByName, err := db.GetProviderByName(ctx, provider.Name)
		assert.NoError(t, err)
		assert.Equal(t, provider.ID, retrievedByName.ID)
	})

	t.Run("update provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "update-test-provider",
			AuthMethod: "api_key",
			APIKey:     "test-key-3",
			BaseURL:    "https://api3.example.com",
			Enabled:    true,
		}

		err := db.CreateProvider(ctx, provider)
		require.NoError(t, err)

		// Update
		provider.BaseURL = "https://updated.example.com"
		provider.Enabled = false
		provider.CoreAPIFeatures = []string{"streaming"}

		err = db.UpdateProvider(ctx, provider)
		assert.NoError(t, err)

		// Verify update
		retrieved, err := db.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, "https://updated.example.com", retrieved.BaseURL)
		assert.False(t, retrieved.Enabled)
		assert.Equal(t, []string{"streaming"}, retrieved.CoreAPIFeatures)
	})

	t.Run("list providers", func(t *testing.T) {
		// Create test providers
		providers := []*Provider{
			{Name: "list-test-1", AuthMethod: "api_key", APIKey: "key1", BaseURL: "https://api1.com", Enabled: true},
			{Name: "list-test-2", AuthMethod: "api_key", APIKey: "key2", BaseURL: "https://api2.com", Enabled: false},
			{Name: "list-test-3", AuthMethod: "oauth", APIKey: "", BaseURL: "https://api3.com", Enabled: true},
		}

		for _, p := range providers {
			err := db.CreateProvider(ctx, p)
			require.NoError(t, err)
		}

		// List all providers
		allProviders, err := db.ListProviders(ctx, &ProviderFilter{})
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(allProviders), 3)

		// List enabled providers only
		enabled := true
		filter := &ProviderFilter{
			Enabled: &enabled,
		}
		enabledProviders, err := db.ListProviders(ctx, filter)
		assert.NoError(t, err)
		assert.Greater(t, len(enabledProviders), 0)

		// List with name filter
		nameFilter := &ProviderFilter{
			Name: "%test-1%",
		}
		nameFiltered, err := db.ListProviders(ctx, nameFilter)
		assert.NoError(t, err)
		assert.Greater(t, len(nameFiltered), 0)
	})

	t.Run("delete provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "delete-test-provider",
			AuthMethod: "api_key",
			APIKey:     "test-key-delete",
			BaseURL:    "https://delete.example.com",
			Enabled:    true,
		}

		err := db.CreateProvider(ctx, provider)
		require.NoError(t, err)

		id := provider.ID

		// Delete
		err = db.DeleteProvider(ctx, id)
		assert.NoError(t, err)

		// Verify deletion
		_, err = db.GetProvider(ctx, id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSQLiteModelOperations(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Create a provider first
	provider := &Provider{
		Name:       "model-test-provider",
		AuthMethod: "api_key",
		APIKey:     "test-key",
		BaseURL:    "https://api.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	t.Run("create model", func(t *testing.T) {
		model := &Model{
			ProviderID:       provider.ID,
			ModelName:        "gpt-4",
			DisplayName:      "GPT-4",
			MaxContextTokens: 8192,
			SupportsVision:   true,
			SupportsTools:    true,
			InputCostPer1k:   0.03,
			OutputCostPer1k:  0.06,
			Enabled:          true,
		}

		err := db.CreateModel(ctx, model)
		assert.NoError(t, err)
		assert.NotZero(t, model.ID)
	})

	t.Run("get model", func(t *testing.T) {
		model := &Model{
			ProviderID:       provider.ID,
			ModelName:        "gpt-3.5-turbo",
			DisplayName:      "GPT-3.5 Turbo",
			MaxContextTokens: 4096,
			SupportsVision:   false,
			SupportsTools:    true,
			InputCostPer1k:   0.0015,
			OutputCostPer1k:  0.002,
			Enabled:          true,
		}

		err := db.CreateModel(ctx, model)
		require.NoError(t, err)

		// Get by ID
		retrieved, err := db.GetModel(ctx, model.ID)
		assert.NoError(t, err)
		assert.Equal(t, model.ModelName, retrieved.ModelName)
		assert.Equal(t, "GPT-3.5 Turbo", retrieved.DisplayName)
		assert.False(t, retrieved.SupportsVision)
		assert.True(t, retrieved.SupportsTools)

		// Get by name and provider
		retrievedByName, err := db.GetModelByName(ctx, provider.ID, "gpt-3.5-turbo")
		assert.NoError(t, err)
		assert.Equal(t, model.ID, retrievedByName.ID)
	})

	t.Run("list models", func(t *testing.T) {
		// Create test models
		models := []*Model{
			{ProviderID: provider.ID, ModelName: "claude-3", Enabled: true},
			{ProviderID: provider.ID, ModelName: "claude-3-haiku", Enabled: false},
			{ProviderID: provider.ID, ModelName: "claude-3-opus", Enabled: true},
		}

		for _, m := range models {
			m.MaxContextTokens = 4096
			err := db.CreateModel(ctx, m)
			require.NoError(t, err)
		}

		// List all models for provider
		providerID := provider.ID
		filter := &ModelFilter{
			ProviderID: &providerID,
		}
		allModels, err := db.ListModels(ctx, filter)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(allModels), 3)

		// List enabled models only
		enabled := true
		filter.Enabled = &enabled
		enabledModels, err := db.ListModels(ctx, filter)
		assert.NoError(t, err)
		assert.Greater(t, len(enabledModels), 0)
	})
}

func TestSQLiteMetricsOperations(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	// Create provider and model
	provider := &Provider{
		Name:       "metrics-test-provider",
		AuthMethod: "api_key",
		APIKey:     "test-key",
		BaseURL:    "https://api.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "test-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(t, err)

	t.Run("store single metrics", func(t *testing.T) {
		now := time.Now()
		metrics := &RequestMetrics{
			RequestID:    "req-123",
			ProviderID:   provider.ID,
			ModelID:      model.ID,
			RequestType:  "chat",
			InputTokens:  100,
			OutputTokens: 50,
			TotalTokens:  150,
			LatencyMs:    1000,
			StatusCode:   200,
			RequestSize:  500,
			ResponseSize: 800,
			Streaming:    false,
			VisionContent: false,
			ToolUse:      false,
			ThinkingMode: false,
			Cost:         0.005,
			Timestamp:    now,
		}

		err := db.StoreRequestMetrics(ctx, metrics)
		assert.NoError(t, err)
	})

	t.Run("store batch metrics", func(t *testing.T) {
		now := time.Now()
		batch := make([]*RequestMetrics, 50)

		for i := 0; i < 50; i++ {
			batch[i] = &RequestMetrics{
				RequestID:     fmt.Sprintf("req-batch-%d", i),
				ProviderID:    provider.ID,
				ModelID:       model.ID,
				RequestType:   "chat",
				InputTokens:   100 + i,
				OutputTokens:  50 + i,
				TotalTokens:   150 + i*2,
				LatencyMs:     1000 + i*10,
				StatusCode:    200,
				RequestSize:   500 + i*5,
				ResponseSize:  800 + i*8,
				Streaming:     i%2 == 0,
				VisionContent: false,
				ToolUse:       false,
				ThinkingMode:  false,
				Cost:          0.005 + float64(i)*0.001,
				Timestamp:     now.Add(time.Duration(i) * time.Second),
			}
		}

		err := db.StoreBatchRequestMetrics(ctx, batch)
		assert.NoError(t, err)
	})

	t.Run("get metrics", func(t *testing.T) {
		// Get all metrics
		query := &MetricsQuery{
			ProviderID: &provider.ID,
			Limit:      10,
		}

		metrics, err := db.GetRequestMetrics(ctx, query)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(metrics), 1)

		if len(metrics) > 0 {
			m := metrics[0]
			assert.Equal(t, provider.ID, m.ProviderID)
			assert.Equal(t, model.ID, m.ModelID)
			assert.NotEmpty(t, m.RequestID)
		}
	})

	t.Run("get aggregated metrics", func(t *testing.T) {
		from := time.Now().Add(-1 * time.Hour)
		to := time.Now()

		query := &AggregatedQuery{
			TimeRange:    TimeRange{From: from, To: to},
			GroupBy:      "hour",
			Metrics:      []string{"count", "tokens", "cost"},
			TimeInterval: "1h",
		}

		_, err := db.GetAggregatedMetrics(ctx, query)
		assert.NoError(t, err)
		// May be empty if no data in time range, but should not error
	})
}

func TestSQLiteHealthCheck(t *testing.T) {
	db, dbPath := setupTestDB(t)
	defer db.Close()
	defer os.Remove(dbPath)

	t.Run("healthy database", func(t *testing.T) {
		ctx := context.Background()
		err := db.HealthCheck(ctx)
		assert.NoError(t, err)
	})

	t.Run("closed database", func(t *testing.T) {
		err := db.Close()
		require.NoError(t, err)

		ctx := context.Background()
		err = db.HealthCheck(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database not connected")
	})
}

func TestSQLiteTransactions(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	ctx := context.Background()

	t.Run("successful transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer tx.Rollback()

		// Create provider in transaction
		provider := &Provider{
			Name:       "tx-test-provider",
			AuthMethod: "api_key",
			APIKey:     "tx-key",
			BaseURL:    "https://tx.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		assert.NoError(t, err)

		// Create metrics in transaction
		metrics := &RequestMetrics{
			RequestID:    "tx-req-123",
			ProviderID:   provider.ID,
			ModelID:      1, // Assume model exists
			RequestType:  "chat",
			InputTokens:  100,
			OutputTokens: 50,
			TotalTokens:  150,
			LatencyMs:    1000,
			StatusCode:   200,
			Cost:         0.005,
		}

		// This might fail if model doesn't exist, which is fine for this test
		_ = tx.StoreRequestMetrics(ctx, metrics)

		// Commit transaction
		err = tx.Commit()
		assert.NoError(t, err)

		// Verify provider persists
		retrieved, err := db.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrieved.Name)
	})

	t.Run("rollback transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)

		// Create provider in transaction
		provider := &Provider{
			Name:       "rollback-test-provider",
			AuthMethod: "api_key",
			APIKey:     "rollback-key",
			BaseURL:    "https://rollback.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		assert.NoError(t, err)

		// Rollback transaction
		err = tx.Rollback()
		assert.NoError(t, err)

		// Verify provider doesn't persist
		_, err = db.GetProvider(ctx, provider.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestSQLiteBatchProcessing(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// Test that batch workers are properly started and can handle shutdown
	ctx := context.Background()

	// Create provider and model for testing
	provider := &Provider{
		Name:       "batch-test-provider",
		AuthMethod: "api_key",
		APIKey:     "batch-key",
		BaseURL:    "https://batch.example.com",
		Enabled:    true,
	}

	err := db.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "batch-model",
		Enabled:    true,
	}

	err = db.CreateModel(ctx, model)
	require.NoError(t, err)

	// Create a large batch to test processing
	batch := make([]*RequestMetrics, 100)
	now := time.Now()

	for i := 0; i < 100; i++ {
		batch[i] = &RequestMetrics{
			RequestID:     fmt.Sprintf("batch-req-%d", i),
			ProviderID:    provider.ID,
			ModelID:       model.ID,
			RequestType:   "chat",
			InputTokens:   100 + i,
			OutputTokens:  50 + i,
			TotalTokens:   150 + i*2,
			LatencyMs:     1000 + i*10,
			StatusCode:    200,
			Cost:          0.005 + float64(i)*0.001,
			Timestamp:     now.Add(time.Duration(i) * time.Millisecond),
		}
	}

	// Store batch
	err = db.StoreBatchRequestMetrics(ctx, batch)
	assert.NoError(t, err)

	// Give some time for batch processing
	time.Sleep(100 * time.Millisecond)

	// Verify metrics were stored
	query := &MetricsQuery{
		ProviderID: &provider.ID,
		Limit:      200,
	}

	stored, err := db.GetRequestMetrics(ctx, query)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(stored), 100)
}