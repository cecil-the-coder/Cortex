package database

import (
	"context"
	"database/sql/driver"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
)

// Test interfaces and types
func TestProviderValidation(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name     string
		provider *Provider
		wantErr  bool
	}{
		{
			name: "valid provider",
			provider: &Provider{
				Name:       "test-provider",
				AuthMethod: "api_key",
				APIKey:     "test-key",
				BaseURL:    "https://api.example.com",
				Enabled:    true,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			provider: &Provider{
				AuthMethod: "api_key",
				APIKey:     "test-key",
				BaseURL:    "https://api.example.com",
				Enabled:    true,
			},
			wantErr: true,
		},
		{
			name: "invalid auth method",
			provider: &Provider{
				Name:       "test-provider",
				AuthMethod: "invalid",
				APIKey:     "test-key",
				BaseURL:    "https://api.example.com",
				Enabled:    true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock database
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			repo := NewBaseRepository(db, logger, "sqlite")

			// Only set up SQL mocks if validation should pass
			if !tt.wantErr {
				mock.ExpectExec("INSERT INTO providers").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}
			// For validation errors, we don't expect any SQL calls

			err = repo.CreateProvider(context.Background(), tt.provider)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Only check expectations if we set up any
			if !tt.wantErr {
				assert.NoError(t, mock.ExpectationsWereMet())
			}
		})
	}
}

func TestRequestMetricsValidation(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name    string
		metrics *RequestMetrics
		wantErr bool
	}{
		{
			name: "valid metrics",
			metrics: &RequestMetrics{
				RequestID:    "req-123",
				ProviderID:   1,
				ModelID:      1,
				RequestType:  "chat",
				InputTokens:  100,
				OutputTokens: 50,
				TotalTokens:  150,
				LatencyMs:    1000,
				StatusCode:   200,
				Cost:         0.005,
			},
			wantErr: false,
		},
		{
			name: "empty request ID",
			metrics: &RequestMetrics{
				ProviderID:   1,
				ModelID:      1,
				RequestType:  "chat",
				InputTokens:  100,
				OutputTokens: 50,
				TotalTokens:  150,
				LatencyMs:    1000,
				StatusCode:   200,
				Cost:         0.005,
			},
			wantErr: true,
		},
		{
			name: "negative tokens",
			metrics: &RequestMetrics{
				RequestID:    "req-123",
				ProviderID:   1,
				ModelID:      1,
				RequestType:  "chat",
				InputTokens:  -100,
				OutputTokens: 50,
				TotalTokens:  150,
				LatencyMs:    1000,
				StatusCode:   200,
				Cost:         0.005,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock database
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			repo := NewBaseRepository(db, logger, "sqlite")

			// Only set up SQL mocks if validation should pass
			if !tt.wantErr {
				mock.ExpectExec("INSERT INTO request_metrics").
					WillReturnResult(sqlmock.NewResult(1, 1))
			}
			// For validation errors, we don't expect any SQL calls

			err = repo.StoreRequestMetrics(context.Background(), tt.metrics)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Only check expectations if we set up any
			if !tt.wantErr {
				assert.NoError(t, mock.ExpectationsWereMet())
			}
		})
	}
}

func TestTimeRangeValidation(t *testing.T) {
	tests := []struct {
		name     string
		timeRange TimeRange
		wantErr  bool
	}{
		{
			name: "valid time range",
			timeRange: TimeRange{
				From: time.Now().Add(-24 * time.Hour),
				To:   time.Now(),
			},
			wantErr: false,
		},
		{
			name: "from after to",
			timeRange: TimeRange{
				From: time.Now(),
				To:   time.Now().Add(-24 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "empty time range",
			timeRange: TimeRange{
				From: time.Time{},
				To:   time.Time{},
			},
			wantErr: false, // Empty time range now returns zero values instead of error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Set up mock database
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()

			logger := slog.Default()
			repo := NewBaseRepository(db, logger, "sqlite")

			if !tt.wantErr {
				rows := sqlmock.NewRows([]string{"total_requests", "active_providers", "active_models", "total_tokens", "total_cost"}).
					AddRow(100, 5, 10, 50000, 25.50)
				mock.ExpectQuery("SELECT").WillReturnRows(rows)
			} else {
				// For invalid time range, we expect validation error before SQL is executed
			}

			_, err = repo.GetSystemMetrics(ctx, tt.timeRange)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestFilterTypes(t *testing.T) {
	t.Run("ProviderFilter defaults", func(t *testing.T) {
		filter := &ProviderFilter{}

		assert.Equal(t, "", filter.Name)
		assert.Nil(t, filter.Enabled)
		assert.Equal(t, 0, filter.Limit)
		assert.Equal(t, 0, filter.Offset)
	})

	t.Run("ProviderFilter with values", func(t *testing.T) {
		enabled := true
		filter := &ProviderFilter{
			Name:    "test",
			Enabled: &enabled,
			Limit:   10,
			Offset:  5,
		}

		assert.Equal(t, "test", filter.Name)
		assert.Equal(t, &enabled, filter.Enabled)
		assert.Equal(t, 10, filter.Limit)
		assert.Equal(t, 5, filter.Offset)
	})

	t.Run("ModelFilter defaults", func(t *testing.T) {
		filter := &ModelFilter{}

		assert.Nil(t, filter.ProviderID)
		assert.Equal(t, "", filter.ModelName)
		assert.Nil(t, filter.Enabled)
		assert.Equal(t, 0, filter.Limit)
		assert.Equal(t, 0, filter.Offset)
	})

	t.Run("ModelFilter with values", func(t *testing.T) {
		providerID := int64(1)
		enabled := true
		filter := &ModelFilter{
			ProviderID: &providerID,
			ModelName:  "gpt-4",
			Enabled:    &enabled,
			Limit:      20,
			Offset:     10,
		}

		assert.Equal(t, &providerID, filter.ProviderID)
		assert.Equal(t, "gpt-4", filter.ModelName)
		assert.Equal(t, &enabled, filter.Enabled)
		assert.Equal(t, 20, filter.Limit)
		assert.Equal(t, 10, filter.Offset)
	})
}

func TestDatabaseConfigDefaults(t *testing.T) {
	config := &DatabaseConfig{}

	// Test default values
	assert.Equal(t, "", config.Type)
	assert.Equal(t, "", config.Host)
	assert.Equal(t, 0, config.Port)
	assert.Equal(t, "", config.Database)
	assert.Equal(t, "", config.Username)
	assert.Equal(t, "", config.Password)

	// Test connection pool defaults
	assert.Equal(t, 0, config.MaxOpenConns)
	assert.Equal(t, 0, config.MaxIdleConns)
	assert.Equal(t, time.Duration(0), config.ConnMaxLifetime)
	assert.Equal(t, time.Duration(0), config.ConnMaxIdleTime)

	// Test performance tuning defaults
	assert.Equal(t, 0, config.BatchSize)
	assert.Equal(t, time.Duration(0), config.FlushInterval)

	// Test SQLite defaults
	assert.Equal(t, "", config.SQLitePath)
	assert.Equal(t, false, config.SQLiteWALMode)
	assert.Equal(t, 0, config.SQLiteCacheSize)

	// Test MySQL defaults
	assert.Equal(t, "", config.MySQLCharset)
	assert.Equal(t, "", config.MySQLCollation)
	assert.Equal(t, false, config.MySQLParseTime)
}

func TestOAuthCredentialSet(t *testing.T) {
	now := time.Now()

	creds := &OAuthCredentialSet{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenURL:     "https://oauth.example.com/token",
		ExpiresAt:    &now,
	}

	assert.Equal(t, "test-client-id", creds.ClientID)
	assert.Equal(t, "test-client-secret", creds.ClientSecret)
	assert.Equal(t, "test-access-token", creds.AccessToken)
	assert.Equal(t, "test-refresh-token", creds.RefreshToken)
	assert.Equal(t, "https://oauth.example.com/token", creds.TokenURL)
	assert.Equal(t, &now, creds.ExpiresAt)

	// Test with nil ExpiresAt
	creds.ExpiresAt = nil
	assert.Nil(t, creds.ExpiresAt)
}

func TestAggregatedMetricsStructure(t *testing.T) {
	labels := map[string]string{
		"provider": "openai",
		"model":    "gpt-4",
	}

	values := map[string]interface{}{
		"count":   int64(100),
		"tokens":  int64(50000),
		"cost":    5.50,
		"latency": 1000.5,
	}

	agg := &AggregatedMetrics{
		Labels:    labels,
		Values:    values,
		Timestamp: time.Now(),
	}

	assert.Equal(t, labels, agg.Labels)
	assert.Equal(t, values, agg.Values)
	assert.NotNil(t, agg.Timestamp)
	assert.Equal(t, "openai", agg.Labels["provider"])
	assert.Equal(t, "gpt-4", agg.Labels["model"])
	assert.Equal(t, int64(100), agg.Values["count"])
	assert.Equal(t, int64(50000), agg.Values["tokens"])
	assert.Equal(t, 5.50, agg.Values["cost"])
	assert.Equal(t, 1000.5, agg.Values["latency"])
}

func TestMetricsQueryStructure(t *testing.T) {
	providerID := int64(1)
	modelID := int64(2)
	apiKeyID := int64(3)
	statusCode := 200
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	query := &MetricsQuery{
		ProviderID:   &providerID,
		ModelID:      &modelID,
		APIKeyID:     &apiKeyID,
		StatusCode:   &statusCode,
		TimeRange:    TimeRange{From: from, To: to},
		Limit:        100,
		Offset:       10,
		OrderBy:      "timestamp DESC",
	}

	assert.Equal(t, &providerID, query.ProviderID)
	assert.Equal(t, &modelID, query.ModelID)
	assert.Equal(t, &apiKeyID, query.APIKeyID)
	assert.Equal(t, &statusCode, query.StatusCode)
	assert.Equal(t, from, query.TimeRange.From)
	assert.Equal(t, to, query.TimeRange.To)
	assert.Equal(t, 100, query.Limit)
	assert.Equal(t, 10, query.Offset)
	assert.Equal(t, "timestamp DESC", query.OrderBy)
}

func TestAggregatedQueryStructure(t *testing.T) {
	from := time.Now().Add(-7 * 24 * time.Hour)
	to := time.Now()

	query := &AggregatedQuery{
		TimeRange:    TimeRange{From: from, To: to},
		GroupBy:      "day",
		Metrics:      []string{"count", "tokens", "cost", "latency"},
		TimeInterval: "1d",
	}

	assert.Equal(t, from, query.TimeRange.From)
	assert.Equal(t, to, query.TimeRange.To)
	assert.Equal(t, "day", query.GroupBy)
	assert.Equal(t, []string{"count", "tokens", "cost", "latency"}, query.Metrics)
	assert.Equal(t, "1d", query.TimeInterval)
}

// Mock driver for testing SQL errors
type mockDriver struct {
	mssql  bool
	err    error
}

func (d *mockDriver) Open(name string) (driver.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	return nil, fmt.Errorf("mock connection")
}

func TestDatabaseConnections(t *testing.T) {
	tests := []struct {
		name    string
		config  *DatabaseConfig
		wantErr bool
	}{
		{
			name: "empty config",
			config: &DatabaseConfig{
				Type: "",
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			config: &DatabaseConfig{
				Type: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			_, err := NewDatabase(tt.config, logger)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNullHelpers(t *testing.T) {
	t.Run("nullString", func(t *testing.T) {
		// Test empty string
		null := nullString("")
		assert.False(t, null.Valid)
		assert.Equal(t, "", null.String)

		// Test non-empty string
		null = nullString("test")
		assert.True(t, null.Valid)
		assert.Equal(t, "test", null.String)
	})

	t.Run("nullStringSlice", func(t *testing.T) {
		// Test empty slice
		null := nullStringSlice([]string{})
		assert.False(t, null.Valid)

		// Test non-empty slice
		null = nullStringSlice([]string{"a", "b", "c"})
		assert.True(t, null.Valid)
		assert.Equal(t, "a,b,c", null.String)
	})

	t.Run("nullInt64", func(t *testing.T) {
		// Test nil pointer
		null := nullInt64(nil)
		assert.False(t, null.Valid)

		// Test valid pointer
		val := int64(42)
		null = nullInt64(&val)
		assert.True(t, null.Valid)
		assert.Equal(t, int64(42), null.Int64)
	})
}