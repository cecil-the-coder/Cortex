package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/go-sql-driver/mysql"
	"log/slog"
)

// getMySQLTestConfig returns MySQL configuration for testing
// These tests require a MySQL test instance to be running
func getMySQLTestConfig(t *testing.T) *DatabaseConfig {
	// Skip tests if MySQL environment variables are not set
	host := os.Getenv("MYSQL_TEST_HOST")
	if host == "" {
		host = "localhost"
	}

	portStr := os.Getenv("MYSQL_TEST_PORT")
	port := 3306
	if portStr != "" {
		if parsedPort, err := strconv.Atoi(portStr); err == nil {
			port = parsedPort
		}
	}

	database := os.Getenv("MYSQL_TEST_DATABASE")
	if database == "" {
		database = "go_llm_router_test"
	}

	username := os.Getenv("MYSQL_TEST_USERNAME")
	if username == "" {
		username = "root"
	}

	password := os.Getenv("MYSQL_TEST_PASSWORD")
	if password == "" {
		t.Skip("MySQL test password not set. Set MYSQL_TEST_PASSWORD to run MySQL tests.")
		return nil
	}

	return &DatabaseConfig{
		Type:           "mysql",
		Host:           host,
		Port:           port,
		Database:       database,
		Username:       username,
		Password:       password,
		MaxOpenConns:   10,
		MaxIdleConns:   5,
		ConnMaxLifetime: time.Hour,
		ConnMaxIdleTime: time.Minute * 30,
		MySQLCharset:   "utf8mb4",
		MySQLCollation: "utf8mb4_unicode_ci",
		MySQLParseTime: true,
		BatchSize:      100,
		FlushInterval:  time.Second * 10,
	}
}

// setupTestMySQL creates a test MySQL database and returns connection
func setupTestMySQL(t *testing.T) (*MySQLDatabase, string) {
	config := getMySQLTestConfig(t)
	if config == nil {
		t.Skip("Skipping MySQL tests - configuration not available")
	}

	// Create test database if it doesn't exist
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/",
		config.Username,
		config.Password,
		config.Host,
		config.Port,
	)

	db, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	defer db.Close()

	// Create database
	_, err = db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", config.Database))
	require.NoError(t, err)

	logger := slog.Default()
	database, err := NewMySQLDatabase(config, logger)
	require.NoError(t, err)

	// Type assertion to get concrete type
	mysqlDB := database.(*MySQLDatabase)

	ctx := context.Background()
	err = mysqlDB.Connect(ctx)
	require.NoError(t, err)

	// Run migrations
	err = mysqlDB.Migrate(ctx)
	require.NoError(t, err)

	return mysqlDB, config.Database
}

func TestMySQLDatabaseConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	t.Run("successful connection", func(t *testing.T) {
		err := mysqlDB.Ping(context.Background())
		assert.NoError(t, err)
	})

	t.Run("health check", func(t *testing.T) {
		err := mysqlDB.HealthCheck(context.Background())
		assert.NoError(t, err)
	})

	t.Run("connection with retry logic", func(t *testing.T) {
		// Test that retry logic works by connecting with a bad config first
		badConfig := *mysqlDB.config
		badConfig.Password = "wrong_password"

		logger := slog.Default()
		badDB, err := NewMySQLDatabase(&badConfig, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		err = badDB.Connect(ctx)
		assert.Error(t, err) // Should fail with retries
		assert.Contains(t, err.Error(), "failed to connect to MySQL")
	})
}

func TestMySQLProviderOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	ctx := context.Background()

	t.Run("create provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "mysql-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-test-key",
			BaseURL:    "https://mysql-api.example.com",
			UseCoreAPI: true,
			CoreAPIFeatures: []string{"streaming", "tools"},
			Enabled:    true,
		}

		err := mysqlDB.CreateProvider(ctx, provider)
		assert.NoError(t, err)
		assert.NotZero(t, provider.ID)
	})

	t.Run("get provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "mysql-get-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-get-test-key",
			BaseURL:    "https://mysql-get.example.com",
			UseCoreAPI: true,
			CoreAPIFeatures: []string{"vision"},
			Enabled:    true,
		}

		err := mysqlDB.CreateProvider(ctx, provider)
		require.NoError(t, err)

		// Get by ID
		retrieved, err := mysqlDB.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrieved.Name)
		assert.Equal(t, provider.AuthMethod, retrieved.AuthMethod)
		assert.True(t, retrieved.UseCoreAPI)
		assert.Equal(t, []string{"vision"}, retrieved.CoreAPIFeatures)

		// Get by name
		retrievedByName, err := mysqlDB.GetProviderByName(ctx, provider.Name)
		assert.NoError(t, err)
		assert.Equal(t, provider.ID, retrievedByName.ID)
	})

	t.Run("update provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "mysql-update-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-update-key",
			BaseURL:    "https://mysql-update.example.com",
			Enabled:    true,
		}

		err := mysqlDB.CreateProvider(ctx, provider)
		require.NoError(t, err)

		// Update
		provider.BaseURL = "https://mysql-updated.example.com"
		provider.Enabled = false
		provider.CoreAPIFeatures = []string{"streaming", "vision"}

		err = mysqlDB.UpdateProvider(ctx, provider)
		assert.NoError(t, err)

		// Verify update
		retrieved, err := mysqlDB.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, "https://mysql-updated.example.com", retrieved.BaseURL)
		assert.False(t, retrieved.Enabled)
		assert.Equal(t, []string{"streaming", "vision"}, retrieved.CoreAPIFeatures)
	})

	t.Run("list providers", func(t *testing.T) {
		// Create test providers
		providers := []*Provider{
			{Name: "mysql-list-test-1", AuthMethod: "api_key", APIKey: "key1", BaseURL: "https://api1.com", Enabled: true},
			{Name: "mysql-list-test-2", AuthMethod: "api_key", APIKey: "key2", BaseURL: "https://api2.com", Enabled: false},
			{Name: "mysql-list-test-3", AuthMethod: "oauth", APIKey: "", BaseURL: "https://api3.com", Enabled: true},
		}

		for _, p := range providers {
			err := mysqlDB.CreateProvider(ctx, p)
			require.NoError(t, err)
		}

		// List all providers
		allProviders, err := mysqlDB.ListProviders(ctx, &ProviderFilter{})
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(allProviders), 3)

		// List enabled providers only
		enabled := true
		filter := &ProviderFilter{
			Enabled: &enabled,
		}
		enabledProviders, err := mysqlDB.ListProviders(ctx, filter)
		assert.NoError(t, err)
		assert.Greater(t, len(enabledProviders), 0)

		// List with name filter
		nameFilter := &ProviderFilter{
			Name: "%list-test-1%",
		}
		nameFiltered, err := mysqlDB.ListProviders(ctx, nameFilter)
		assert.NoError(t, err)
		assert.Greater(t, len(nameFiltered), 0)
	})

	t.Run("delete provider", func(t *testing.T) {
		provider := &Provider{
			Name:       "mysql-delete-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-delete-key",
			BaseURL:    "https://mysql-delete.example.com",
			Enabled:    true,
		}

		err := mysqlDB.CreateProvider(ctx, provider)
		require.NoError(t, err)

		id := provider.ID

		// Delete
		err = mysqlDB.DeleteProvider(ctx, id)
		assert.NoError(t, err)

		// Verify deletion
		_, err = mysqlDB.GetProvider(ctx, id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestMySQLModelOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	ctx := context.Background()

	// Create a provider first
	provider := &Provider{
		Name:       "mysql-model-test-provider",
		AuthMethod: "api_key",
		APIKey:     "mysql-model-test-key",
		BaseURL:    "https://mysql-model.example.com",
		Enabled:    true,
	}

	err := mysqlDB.CreateProvider(ctx, provider)
	require.NoError(t, err)

	t.Run("create model", func(t *testing.T) {
		model := &Model{
			ProviderID:       provider.ID,
			ModelName:        "mysql-gpt-4",
			DisplayName:      "MySQL GPT-4",
			MaxContextTokens: 8192,
			SupportsVision:   true,
			SupportsTools:    true,
			InputCostPer1k:   0.03,
			OutputCostPer1k:  0.06,
			Enabled:          true,
		}

		err := mysqlDB.CreateModel(ctx, model)
		assert.NoError(t, err)
		assert.NotZero(t, model.ID)
	})

	t.Run("get model", func(t *testing.T) {
		model := &Model{
			ProviderID:       provider.ID,
			ModelName:        "mysql-gpt-3.5-turbo",
			DisplayName:      "MySQL GPT-3.5 Turbo",
			MaxContextTokens: 4096,
			SupportsVision:   false,
			SupportsTools:    true,
			InputCostPer1k:   0.0015,
			OutputCostPer1k:  0.002,
			Enabled:          true,
		}

		err := mysqlDB.CreateModel(ctx, model)
		require.NoError(t, err)

		// Get by ID
		retrieved, err := mysqlDB.GetModel(ctx, model.ID)
		assert.NoError(t, err)
		assert.Equal(t, model.ModelName, retrieved.ModelName)
		assert.Equal(t, "MySQL GPT-3.5 Turbo", retrieved.DisplayName)
		assert.False(t, retrieved.SupportsVision)
		assert.True(t, retrieved.SupportsTools)

		// Get by name and provider
		retrievedByName, err := mysqlDB.GetModelByName(ctx, provider.ID, "mysql-gpt-3.5-turbo")
		assert.NoError(t, err)
		assert.Equal(t, model.ID, retrievedByName.ID)
	})
}

func TestMySQLMetricsOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	ctx := context.Background()

	// Create provider and model
	provider := &Provider{
		Name:       "mysql-metrics-test-provider",
		AuthMethod: "api_key",
		APIKey:     "mysql-metrics-test-key",
		BaseURL:    "https://mysql-metrics.example.com",
		Enabled:    true,
	}

	err := mysqlDB.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "mysql-test-model",
		Enabled:    true,
	}

	err = mysqlDB.CreateModel(ctx, model)
	require.NoError(t, err)

	t.Run("store single metrics", func(t *testing.T) {
		now := time.Now()
		metrics := &RequestMetrics{
			RequestID:    "mysql-req-123",
			ProviderID:   provider.ID,
			ModelID:      model.ID,
			RequestType:  "chat",
			InputTokens:  150,
			OutputTokens: 75,
			TotalTokens:  225,
			LatencyMs:    1500,
			StatusCode:   200,
			RequestSize:  750,
			ResponseSize: 1200,
			Streaming:    true,
			VisionContent: false,
			ToolUse:      true,
			ThinkingMode: false,
			Cost:         0.0075,
			Timestamp:    now,
		}

		err := mysqlDB.StoreRequestMetrics(ctx, metrics)
		assert.NoError(t, err)
	})

	t.Run("store batch metrics", func(t *testing.T) {
		now := time.Now()
		batch := make([]*RequestMetrics, 100)

		for i := 0; i < 100; i++ {
			batch[i] = &RequestMetrics{
				RequestID:     fmt.Sprintf("mysql-batch-req-%d", i),
				ProviderID:    provider.ID,
				ModelID:       model.ID,
				RequestType:   "chat",
				InputTokens:   150 + i*2,
				OutputTokens:  75 + i,
				TotalTokens:   225 + i*3,
				LatencyMs:     1500 + i*20,
				StatusCode:    200,
				RequestSize:   750 + i*10,
				ResponseSize:  1200 + i*15,
				Streaming:     i%3 == 0,
				VisionContent: i%4 == 0,
				ToolUse:       i%2 == 0,
				ThinkingMode:  i%5 == 0,
				Cost:          0.0075 + float64(i)*0.002,
				Timestamp:     now.Add(time.Duration(i) * time.Second),
			}
		}

		err := mysqlDB.StoreBatchRequestMetrics(ctx, batch)
		assert.NoError(t, err)
	})

	t.Run("get metrics", func(t *testing.T) {
		// Get all metrics
		query := &MetricsQuery{
			ProviderID: &provider.ID,
			Limit:      50,
			OrderBy:    "timestamp DESC",
		}

		metrics, err := mysqlDB.GetRequestMetrics(ctx, query)
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

		_, err := mysqlDB.GetAggregatedMetrics(ctx, query)
		assert.NoError(t, err)
		// May be empty if no data in time range, but should not error
	})
}

func TestMySQLTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	ctx := context.Background()

	t.Run("successful transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := mysqlDB.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer tx.Rollback()

		// Create provider in transaction
		provider := &Provider{
			Name:       "mysql-tx-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-tx-key",
			BaseURL:    "https://mysql-tx.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		assert.NoError(t, err)

		// Commit transaction
		err = tx.Commit()
		assert.NoError(t, err)

		// Verify provider persists
		retrieved, err := mysqlDB.GetProvider(ctx, provider.ID)
		assert.NoError(t, err)
		assert.Equal(t, provider.Name, retrieved.Name)
	})

	t.Run("rollback transaction", func(t *testing.T) {
		// Begin transaction
		tx, err := mysqlDB.BeginTx(ctx, nil)
		require.NoError(t, err)

		// Create provider in transaction
		provider := &Provider{
			Name:       "mysql-rollback-test-provider",
			AuthMethod: "api_key",
			APIKey:     "mysql-rollback-key",
			BaseURL:    "https://mysql-rollback.example.com",
			Enabled:    true,
		}

		err = tx.CreateProvider(ctx, provider)
		assert.NoError(t, err)

		// Rollback transaction
		err = tx.Rollback()
		assert.NoError(t, err)

		// Verify provider doesn't persist
		_, err = mysqlDB.GetProvider(ctx, provider.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestMySQLHealthStats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MySQL integration tests in short mode")
	}

	mysqlDB, _ := setupTestMySQL(t)
	defer mysqlDB.Close()

	ctx := context.Background()

	// Create test data
	provider := &Provider{
		Name:       "health-test-provider",
		AuthMethod: "api_key",
		APIKey:     "health-test-key",
		BaseURL:    "https://health.example.com",
		Enabled:    true,
	}

	err := mysqlDB.CreateProvider(ctx, provider)
	require.NoError(t, err)

	model := &Model{
		ProviderID: provider.ID,
		ModelName:  "health-test-model",
		Enabled:    true,
	}

	err = mysqlDB.CreateModel(ctx, model)
	require.NoError(t, err)

	// Add some test metrics
	now := time.Now()
	for i := 0; i < 10; i++ {
		metrics := &RequestMetrics{
			RequestID:    fmt.Sprintf("health-req-%d", i),
			ProviderID:   provider.ID,
			ModelID:      model.ID,
			RequestType:  "chat",
			InputTokens:  100,
			OutputTokens: 50,
			TotalTokens:  150,
			LatencyMs:    1000 + i*100,
			StatusCode:   200,
			Cost:         0.005,
			Timestamp:    now.Add(-time.Duration(i) * time.Minute),
		}

		err = mysqlDB.StoreRequestMetrics(ctx, metrics)
		require.NoError(t, err)
	}

	t.Run("provider health stats", func(t *testing.T) {
		timeRange := TimeRange{
			From: now.Add(-1 * time.Hour),
			To:   now,
		}

		stats, err := mysqlDB.GetProviderHealthStats(ctx, provider.ID, timeRange)
		assert.NoError(t, err)

		assert.Contains(t, stats, "total_requests")
		assert.Contains(t, stats, "avg_latency_ms")
		assert.Contains(t, stats, "total_cost")
		assert.Contains(t, stats, "error_count")
		assert.Contains(t, stats, "success_count")
		assert.Contains(t, stats, "success_rate")

		requests, ok := stats["total_requests"].(int64)
		assert.True(t, ok)
		assert.GreaterOrEqual(t, requests, int64(10))
	})

	t.Run("system metrics", func(t *testing.T) {
		timeRange := TimeRange{
			From: now.Add(-1 * time.Hour),
			To:   now,
		}

		stats, err := mysqlDB.GetSystemMetrics(ctx, timeRange)
		assert.NoError(t, err)

		assert.Contains(t, stats, "total_requests")
		assert.Contains(t, stats, "active_providers")
		assert.Contains(t, stats, "active_models")
		assert.Contains(t, stats, "total_input_tokens")
		assert.Contains(t, stats, "total_output_tokens")
		assert.Contains(t, stats, "total_cost")
	})
}