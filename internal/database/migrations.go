package database

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
	"log/slog"
)

// Migration represents a database migration
type Migration struct {
	Version     string
	Description string
	Up          MigrationFunc
	Down        MigrationFunc
}

type MigrationFunc func(ctx context.Context, db *sql.DB) error

// Migrator handles database migrations
type Migrator struct {
	db         *sql.DB
	migrations []Migration
	logger     *slog.Logger
}

// NewMigrator creates a new migrator
func NewMigrator(db *sql.DB, logger *slog.Logger) *Migrator {
	return &Migrator{
		db:     db,
		logger: logger,
	}
}

// AddMigration adds a migration to the migrator
func (m *Migrator) AddMigration(migration Migration) {
	m.migrations = append(m.migrations, migration)
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	// Create migrations table if it doesn't exist
	if err := m.createMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get current version
	currentVersion, err := m.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	m.logger.Info("starting database migration",
		"current_version", currentVersion,
		"pending_migrations", m.countPendingMigrations(currentVersion))

	// Sort migrations by version
	if err := m.sortMigrations(); err != nil {
		return fmt.Errorf("failed to sort migrations: %w", err)
	}

	// Apply pending migrations
	for _, migration := range m.migrations {
		if m.compareVersions(migration.Version, currentVersion) > 0 {
			m.logger.Info("applying migration",
				"version", migration.Version,
				"description", migration.Description)

			start := time.Now()
			if err := migration.Up(ctx, m.db); err != nil {
				return fmt.Errorf("migration %s failed: %w", migration.Version, err)
			}

			if err := m.recordMigration(ctx, migration.Version); err != nil {
				return fmt.Errorf("failed to record migration %s: %w", migration.Version, err)
			}

			duration := time.Since(start)
			m.logger.Info("migration applied successfully",
				"version", migration.Version,
				"duration_ms", duration.Milliseconds())

			currentVersion = migration.Version
		}
	}

	m.logger.Info("database migration completed successfully",
		"final_version", currentVersion)

	return nil
}

// createMigrationsTable creates the schema migrations table
func (m *Migrator) createMigrationsTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			version TEXT NOT NULL UNIQUE,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`

	_, err := m.db.ExecContext(ctx, query)
	return err
}

// getCurrentVersion returns the currently applied migration version
func (m *Migrator) getCurrentVersion(ctx context.Context) (string, error) {
	query := `SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1`

	var version string
	err := m.db.QueryRowContext(ctx, query).Scan(&version)
	if err == sql.ErrNoRows {
		return "0.0.0", nil
	}
	if err != nil {
		return "", err
	}

	return version, nil
}

// recordMigration records a migration as applied
func (m *Migrator) recordMigration(ctx context.Context, version string) error {
	query := `INSERT INTO schema_migrations (version) VALUES (?)`
	_, err := m.db.ExecContext(ctx, query, version)
	return err
}

// compareVersions compares two version strings
func (m *Migrator) compareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int

		if i < len(v1Parts) {
			if _, err := fmt.Sscanf(v1Parts[i], "%d", &v1Num); err != nil {
				v1Num = 0
			}
		}

		if i < len(v2Parts) {
			if _, err := fmt.Sscanf(v2Parts[i], "%d", &v2Num); err != nil {
				v2Num = 0
			}
		}

		if v1Num < v2Num {
			return -1
		} else if v1Num > v2Num {
			return 1
		}
	}

	return 0
}

// sortMigrations sorts migrations by version
func (m *Migrator) sortMigrations() error {
	sort.Slice(m.migrations, func(i, j int) bool {
		return m.compareVersions(m.migrations[i].Version, m.migrations[j].Version) < 0
	})
	return nil
}

// countPendingMigrations counts migrations that need to be applied
func (m *Migrator) countPendingMigrations(currentVersion string) int {
	count := 0
	for _, migration := range m.migrations {
		if m.compareVersions(migration.Version, currentVersion) > 0 {
			count++
		}
	}
	return count
}

// InitializeMigrations adds all initial migrations to the migrator
func InitializeMigrations(m *Migrator) {
	// Initial schema migration
	m.AddMigration(Migration{
		Version:     "1.0.0",
		Description: "Initial database schema",
		Up: func(ctx context.Context, db *sql.DB) error {
			migrations := []string{
				createProvidersTableSQL,
				createModelsTableSQL,
				createModelGroupsTableSQL,
				createModelGroupMembersTableSQL,
				createClientAPIKeysTableSQL,
				createAPIKeyModelGroupAccessTableSQL,
				createRouterConfigTableSQL,
				createRequestMetricsTableSQL,
				createProviderHealthTableSQL,
				createHourlyProviderMetricsTableSQL,
				createDailyModelUsageTableSQL,
			}

			for _, migration := range migrations {
				if _, err := db.ExecContext(ctx, migration); err != nil {
					return fmt.Errorf("failed to execute migration: %w", err)
				}
			}

			// Insert default router config
			if _, err := db.ExecContext(ctx, getDefaultRouterConfigSQL); err != nil {
				return fmt.Errorf("failed to insert default router config: %w", err)
			}

			return nil
		},
		Down: func(ctx context.Context, db *sql.DB) error {
			tables := []string{
				"daily_model_usage",
				"hourly_provider_metrics",
				"provider_health",
				"request_metrics",
				"router_config",
				"api_key_model_group_access",
				"client_api_keys",
				"group_members",
				"model_groups",
				"models",
				"providers",
				"schema_migrations",
			}

			for _, table := range tables {
				if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", table)); err != nil {
					return fmt.Errorf("failed to drop table %s: %w", table, err)
				}
			}

			return nil
		},
	})

	// Cost tracking columns are now included in initial schema, so this migration is deprecated
	// Keeping it for historical purposes but making it a no-op
	m.AddMigration(Migration{
		Version:     "1.1.0",
		Description: "Add cost tracking to models table (no-op - already in initial schema)",
		Up: func(ctx context.Context, db *sql.DB) error {
			// Columns already exist in initial schema
			return nil
		},
		Down: func(ctx context.Context, db *sql.DB) error {
			// SQLite doesn't support DROP COLUMN, but MySQL does
			// This would need to be handled based on the database type
			return fmt.Errorf("migration down is not supported for this change")
		},
	})

	// Add indexes for performance
	m.AddMigration(Migration{
		Version:     "1.2.0",
		Description: "Add performance indexes",
		Up: func(ctx context.Context, db *sql.DB) error {
			indexes := []string{
				"CREATE INDEX IF NOT EXISTS idx_request_metrics_timestamp ON request_metrics(timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_request_metrics_provider ON request_metrics(provider_id, timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_request_metrics_model ON request_metrics(model_id, timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_request_metrics_status ON request_metrics(status_code, timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_provider_health_timestamp ON provider_health(provider_id, timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_provider_health_status ON provider_health(status, timestamp)",
				"CREATE INDEX IF NOT EXISTS idx_hourly_provider_timestamp ON hourly_provider_metrics(hour_timestamp, provider_id)",
				"CREATE INDEX IF NOT EXISTS idx_daily_model_date ON daily_model_usage(date_timestamp, model_id)",
			}

			for _, query := range indexes {
				if _, err := db.ExecContext(ctx, query); err != nil {
					return fmt.Errorf("failed to create index: %w", err)
				}
			}

			return nil
		},
		Down: func(ctx context.Context, db *sql.DB) error {
			// Indexes would be dropped with tables, so no down migration needed
			return nil
		},
	})

	// OAuth configuration columns are now included in initial schema, so this migration is deprecated
	// Keeping it for historical purposes but making it a no-op
	m.AddMigration(Migration{
		Version:     "1.3.0",
		Description: "Add OAuth configuration to providers table (no-op - already in initial schema)",
		Up: func(ctx context.Context, db *sql.DB) error {
			// Columns already exist in initial schema
			return nil
		},
		Down: func(ctx context.Context, db *sql.DB) error {
			return fmt.Errorf("migration down is not supported for this change")
		},
	})
}

// SQL schema definitions
const (
	createProvidersTableSQL = `
		CREATE TABLE providers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			auth_method TEXT NOT NULL CHECK(auth_method IN ('api_key', 'oauth', 'hybrid')),
			api_key TEXT,
			base_url TEXT NOT NULL,
			use_core_api INTEGER DEFAULT 0,
			core_api_features TEXT,
			oauth_credentials BLOB,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	createModelsTableSQL = `
		CREATE TABLE models (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			provider_id INTEGER NOT NULL,
			model_name TEXT NOT NULL,
			display_name TEXT,
			max_context_tokens INTEGER DEFAULT 4096,
			supports_vision INTEGER DEFAULT 0,
			supports_tools INTEGER DEFAULT 0,
			input_cost_per_1k REAL DEFAULT 0,
			output_cost_per_1k REAL DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE,
			UNIQUE(provider_id, model_name)
		)
	`

	createModelGroupsTableSQL = `
		CREATE TABLE model_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	createModelGroupMembersTableSQL = `
		CREATE TABLE group_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id INTEGER NOT NULL,
			provider_id INTEGER NOT NULL,
			model_id INTEGER NOT NULL,
			alias TEXT,
			max_context_tokens_override INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (group_id) REFERENCES model_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE,
			FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE,
			UNIQUE(group_id, model_id)
		)
	`

	createClientAPIKeysTableSQL = `
		CREATE TABLE client_api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key_id TEXT NOT NULL UNIQUE,
			api_key_hash TEXT NOT NULL,
			description TEXT,
			rate_limit INTEGER DEFAULT 0,
			expires_at DATETIME,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	createAPIKeyModelGroupAccessTableSQL = `
		CREATE TABLE api_key_model_group_access (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			api_key_id INTEGER NOT NULL,
			model_group_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (api_key_id) REFERENCES client_api_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (model_group_id) REFERENCES model_groups(id) ON DELETE CASCADE,
			UNIQUE(api_key_id, model_group_id)
		)
	`

	createRouterConfigTableSQL = `
		CREATE TABLE router_config (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			default_provider TEXT NOT NULL,
			background_provider TEXT,
			think_provider TEXT,
			long_context_provider TEXT,
			web_search_provider TEXT,
			vision_provider TEXT,
			long_context_threshold INTEGER DEFAULT 100000,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	createRequestMetricsTableSQL = `
		CREATE TABLE request_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL,
			request_id TEXT NOT NULL,
			api_key_id INTEGER,
			provider_id INTEGER NOT NULL,
			model_id INTEGER NOT NULL,
			model_group_id INTEGER,
			request_type TEXT NOT NULL CHECK(request_type IN ('completions', 'chat', 'embeddings')),
			input_tokens INTEGER DEFAULT 0,
			output_tokens INTEGER DEFAULT 0,
			total_tokens INTEGER DEFAULT 0,
			latency_ms INTEGER NOT NULL,
			status_code INTEGER NOT NULL,
			error_message TEXT,
			request_size_bytes INTEGER DEFAULT 0,
			response_size_bytes INTEGER DEFAULT 0,
			streaming INTEGER DEFAULT 0,
			vision_content INTEGER DEFAULT 0,
			tool_use INTEGER DEFAULT 0,
			thinking_mode INTEGER DEFAULT 0,
			cost REAL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (api_key_id) REFERENCES client_api_keys(id),
			FOREIGN KEY (provider_id) REFERENCES providers(id),
			FOREIGN KEY (model_id) REFERENCES models(id),
			FOREIGN KEY (model_group_id) REFERENCES model_groups(id)
		)
	`

	createProviderHealthTableSQL = `
		CREATE TABLE provider_health (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			provider_id INTEGER NOT NULL,
			timestamp DATETIME NOT NULL,
			health_check_type TEXT NOT NULL CHECK(health_check_type IN ('ping', 'model_list', 'auth_test')),
			status TEXT NOT NULL CHECK(status IN ('healthy', 'degraded', 'unhealthy')),
			response_time_ms INTEGER,
			error_message TEXT,
			success_rate_percent REAL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE
		)
	`

	createHourlyProviderMetricsTableSQL = `
		CREATE TABLE hourly_provider_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			provider_id INTEGER NOT NULL,
			hour_timestamp DATETIME NOT NULL,
			total_requests INTEGER DEFAULT 0,
			successful_requests INTEGER DEFAULT 0,
			failed_requests INTEGER DEFAULT 0,
			total_input_tokens INTEGER DEFAULT 0,
			total_output_tokens INTEGER DEFAULT 0,
			total_cost REAL DEFAULT 0,
			avg_latency_ms REAL DEFAULT 0,
			max_latency_ms INTEGER DEFAULT 0,
			min_latency_ms INTEGER DEFAULT 0,
			unique_clients INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE,
			UNIQUE(provider_id, hour_timestamp)
		)
	`

	createDailyModelUsageTableSQL = `
		CREATE TABLE daily_model_usage (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			model_id INTEGER NOT NULL,
			date_timestamp DATE NOT NULL,
			total_requests INTEGER DEFAULT 0,
			total_input_tokens INTEGER DEFAULT 0,
			total_output_tokens INTEGER DEFAULT 0,
			total_cost REAL DEFAULT 0,
			avg_latency_ms REAL DEFAULT 0,
			unique_clients INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE,
			UNIQUE(model_id, date_timestamp)
		)
	`

	getDefaultRouterConfigSQL = `
		INSERT INTO router_config (default_provider, long_context_threshold)
		VALUES ('anthropic', 100000)
	`
)