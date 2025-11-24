package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	goconfig "github.com/cecil-the-coder/Cortex/internal/config"
)

// SQLiteDatabase implements Database interface for SQLite
type SQLiteDatabase struct {
	db     *sql.DB
	config *DatabaseConfig
	logger *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	// Graceful shutdown management
	shutdownMutex sync.Mutex
	isShuttingDown bool
	batchQueue     chan []*RequestMetrics
	batchWorkers   int
	wg             sync.WaitGroup
}

// NewSQLiteDatabase creates a new SQLite database instance
func NewSQLiteDatabase(config *DatabaseConfig, logger *slog.Logger) (Database, error) {
	if config.SQLitePath == "" {
		return nil, fmt.Errorf("SQLite path is required")
	}

	// Ensure directory exists
	dir := filepath.Dir(config.SQLitePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create SQLite directory: %w", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	db := &SQLiteDatabase{
		config:       config,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
		batchQueue:   make(chan []*RequestMetrics, 1000),
		batchWorkers: 2,
	}

	return db, nil
}

// Connect establishes connection to SQLite database
func (s *SQLiteDatabase) Connect(ctx context.Context) error {
	dsn := s.config.SQLitePath

	// Add SQLite specific parameters
	params := []string{
		"cache=shared",
		"mode=rwc",
		"pragma busy_timeout=30000", // 30 second timeout
		"pragma foreign_keys=ON", // Enable foreign keys
		"pragma synchronous=NORMAL", // Reasonable sync mode
		"pragma temp_store=MEMORY", // Store temp tables in memory
	}

	if s.config.SQLiteWALMode {
		params = append(params, "_journal_mode=WAL")
	}

	if s.config.SQLiteCacheSize > 0 {
		params = append(params, fmt.Sprintf("cache_size=%d", s.config.SQLiteCacheSize))
	}

	// Build DSN with parameters
	if len(params) > 0 {
		dsn += "?" + params[0]
		for _, param := range params[1:] {
			dsn += "&" + param
		}
	}

	var err error
	s.db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Setup connection pool
	if err := SetupConnectionPool(s.db, s.config, "sqlite"); err != nil {
		return fmt.Errorf("failed to setup connection pool: %w", err)
	}

	// Test connection
	if err := s.db.Ping(); err != nil {
		return fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	// Start background batch workers
	s.startBatchWorkers()

	s.logger.Info("Connected to SQLite database", "path", s.config.SQLitePath)
	return nil
}

// Close closes the database connection gracefully
func (s *SQLiteDatabase) Close() error {
	s.shutdownMutex.Lock()
	defer s.shutdownMutex.Unlock()

	if s.isShuttingDown {
		return nil // Already shutting down
	}

	s.isShuttingDown = true
	s.logger.Info("Starting graceful shutdown of SQLite database")

	// Cancel context to signal shutdown
	s.cancel()

	// Close batch queue to stop accepting new items
	close(s.batchQueue)

	// Wait for all batch workers to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All batch workers completed")
	case <-time.After(30 * time.Second):
		s.logger.Warn("Timeout waiting for batch workers, proceeding with shutdown")
	}

	// Close database connection
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			s.logger.Error("Error closing SQLite database", "error", err)
			return err
		}
	}

	s.logger.Info("SQLite database closed gracefully")
	return nil
}

// Ping checks database connectivity
func (s *SQLiteDatabase) Ping(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}
	return s.db.PingContext(ctx)
}

// BeginTx starts a new transaction
func (s *SQLiteDatabase) BeginTx(ctx context.Context, opts *sql.TxOptions) (Transaction, error) {
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &SQLiteTransaction{tx: tx, db: s}, nil
}

// Migrate runs database migrations
func (s *SQLiteDatabase) Migrate(ctx context.Context) error {
	migrator := NewMigrator(s.db, s.logger)
	InitializeMigrations(migrator)
	return migrator.Migrate(ctx)
}

// GetVersion returns current database version
func (s *SQLiteDatabase) GetVersion() (string, error) {
	migrator := NewMigrator(s.db, s.logger)
	return migrator.getCurrentVersion(context.Background())
}

// HealthCheck performs comprehensive health check
func (s *SQLiteDatabase) HealthCheck(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database not connected")
	}

	// Check basic connectivity
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Check if we can perform a simple query
	var result string
	err := s.db.QueryRowContext(ctx, "SELECT 'health_check'").Scan(&result)
	if err != nil {
		return fmt.Errorf("database health check query failed: %w", err)
	}

	if result != "health_check" {
		return fmt.Errorf("unexpected health check result: %s", result)
	}

	// Check database file size for SQLite
	if stat, err := os.Stat(s.config.SQLitePath); err != nil {
		return fmt.Errorf("failed to stat database file: %w", err)
	} else if stat.Size() == 0 {
		return fmt.Errorf("database file is empty")
	}

	return nil
}

// startBatchWorkers starts background workers for batch processing
func (s *SQLiteDatabase) startBatchWorkers() {
	for i := 0; i < s.batchWorkers; i++ {
		s.wg.Add(1)
		go s.batchWorker(i)
	}
}

// batchWorker processes batches of metrics
func (s *SQLiteDatabase) batchWorker(workerID int) {
	defer s.wg.Done()

	s.logger.Debug("Started SQLite batch worker", "worker_id", workerID)

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug("SQLite batch worker stopping", "worker_id", workerID)
			return
		case batch, ok := <-s.batchQueue:
			if !ok {
				s.logger.Debug("SQLite batch worker terminating (queue closed)", "worker_id", workerID)
				return
			}

			if err := s.processBatch(batch); err != nil {
				s.logger.Error("Failed to process batch in SQLite worker",
					"worker_id", workerID,
					"batch_size", len(batch),
					"error", err)
			}
		}
	}
}

// processBatch processes a batch of metrics
func (s *SQLiteDatabase) processBatch(batch []*RequestMetrics) error {
	if len(batch) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, metrics := range batch {
		if err := tx.StoreRequestMetrics(ctx, metrics); err != nil {
			return fmt.Errorf("failed to store metrics: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	s.logger.Debug("Processed batch successfully", "batch_size", len(batch))
	return nil
}

// SQLiteTransaction implements Transaction interface for SQLite
type SQLiteTransaction struct {
	tx *sql.Tx
	db *SQLiteDatabase
}

// Commit commits the transaction
func (t *SQLiteTransaction) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *SQLiteTransaction) Rollback() error {
	return t.tx.Rollback()
}

// ConfigRepository methods (delegates to implementation)
func (t *SQLiteTransaction) CreateProvider(ctx context.Context, provider *Provider) error {
	return t.db.CreateProvider(ctx, provider)
}

func (t *SQLiteTransaction) GetProvider(ctx context.Context, id int64) (*Provider, error) {
	return t.db.GetProvider(ctx, id)
}

func (t *SQLiteTransaction) GetProviderByName(ctx context.Context, name string) (*Provider, error) {
	return t.db.GetProviderByName(ctx, name)
}

func (t *SQLiteTransaction) UpdateProvider(ctx context.Context, provider *Provider) error {
	return t.db.UpdateProvider(ctx, provider)
}

func (t *SQLiteTransaction) DeleteProvider(ctx context.Context, id int64) error {
	return t.db.DeleteProvider(ctx, id)
}

func (t *SQLiteTransaction) ListProviders(ctx context.Context, filter *ProviderFilter) ([]*Provider, error) {
	return t.db.ListProviders(ctx, filter)
}

func (t *SQLiteTransaction) CreateModel(ctx context.Context, model *Model) error {
	return t.db.CreateModel(ctx, model)
}

func (t *SQLiteTransaction) GetModel(ctx context.Context, id int64) (*Model, error) {
	return t.db.GetModel(ctx, id)
}

func (t *SQLiteTransaction) GetModelByName(ctx context.Context, providerID int64, modelName string) (*Model, error) {
	return t.db.GetModelByName(ctx, providerID, modelName)
}

func (t *SQLiteTransaction) UpdateModel(ctx context.Context, model *Model) error {
	return t.db.UpdateModel(ctx, model)
}

func (t *SQLiteTransaction) DeleteModel(ctx context.Context, id int64) error {
	return t.db.DeleteModel(ctx, id)
}

func (t *SQLiteTransaction) ListModels(ctx context.Context, filter *ModelFilter) ([]*Model, error) {
	return t.db.ListModels(ctx, filter)
}

func (t *SQLiteTransaction) CreateModelGroup(ctx context.Context, group *ModelGroup) error {
	return t.db.CreateModelGroup(ctx, group)
}

func (t *SQLiteTransaction) GetModelGroup(ctx context.Context, id int64) (*ModelGroup, error) {
	return t.db.GetModelGroup(ctx, id)
}

func (t *SQLiteTransaction) GetModelGroupByName(ctx context.Context, name string) (*ModelGroup, error) {
	return t.db.GetModelGroupByName(ctx, name)
}

func (t *SQLiteTransaction) UpdateModelGroup(ctx context.Context, group *ModelGroup) error {
	return t.db.UpdateModelGroup(ctx, group)
}

func (t *SQLiteTransaction) DeleteModelGroup(ctx context.Context, id int64) error {
	return t.db.DeleteModelGroup(ctx, id)
}

func (t *SQLiteTransaction) ListModelGroups(ctx context.Context) ([]*ModelGroup, error) {
	return t.db.ListModelGroups(ctx)
}

func (t *SQLiteTransaction) AddGroupMember(ctx context.Context, member *GroupMember) error {
	return t.db.AddGroupMember(ctx, member)
}

func (t *SQLiteTransaction) RemoveGroupMember(ctx context.Context, id int64) error {
	return t.db.RemoveGroupMember(ctx, id)
}

func (t *SQLiteTransaction) GetGroupMembers(ctx context.Context, groupID int64) ([]*GroupMember, error) {
	return t.db.GetGroupMembers(ctx, groupID)
}

func (t *SQLiteTransaction) CreateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	return t.db.CreateAPIKey(ctx, apiKey)
}

func (t *SQLiteTransaction) GetAPIKey(ctx context.Context, id int64) (*ClientAPIKey, error) {
	return t.db.GetAPIKey(ctx, id)
}

func (t *SQLiteTransaction) GetAPIKeyByKeyID(ctx context.Context, keyID string) (*ClientAPIKey, error) {
	return t.db.GetAPIKeyByKeyID(ctx, keyID)
}

func (t *SQLiteTransaction) UpdateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	return t.db.UpdateAPIKey(ctx, apiKey)
}

func (t *SQLiteTransaction) DeleteAPIKey(ctx context.Context, id int64) error {
	return t.db.DeleteAPIKey(ctx, id)
}

func (t *SQLiteTransaction) ListAPIKeys(ctx context.Context, filter *APIKeyFilter) ([]*ClientAPIKey, error) {
	return t.db.ListAPIKeys(ctx, filter)
}

func (t *SQLiteTransaction) GetRouterConfig(ctx context.Context) (*RouterConfig, error) {
	return t.db.GetRouterConfig(ctx)
}

func (t *SQLiteTransaction) UpdateRouterConfig(ctx context.Context, config *RouterConfig) error {
	return t.db.UpdateRouterConfig(ctx, config)
}

func (t *SQLiteTransaction) ExportConfig(ctx context.Context) (*goconfig.Config, error) {
	return t.db.ExportConfig(ctx)
}

func (t *SQLiteTransaction) ImportConfig(ctx context.Context, cfg *goconfig.Config) error {
	return t.db.ImportConfig(ctx, cfg)
}

func (t *SQLiteTransaction) StoreRequestMetrics(ctx context.Context, metrics *RequestMetrics) error {
	return t.db.StoreRequestMetrics(ctx, metrics)
}

func (t *SQLiteTransaction) StoreBatchRequestMetrics(ctx context.Context, metrics []*RequestMetrics) error {
	return t.db.StoreBatchRequestMetrics(ctx, metrics)
}

func (t *SQLiteTransaction) GetRequestMetrics(ctx context.Context, query *MetricsQuery) ([]*RequestMetrics, error) {
	return t.db.GetRequestMetrics(ctx, query)
}

func (t *SQLiteTransaction) GetAggregatedMetrics(ctx context.Context, query *AggregatedQuery) ([]*AggregatedMetrics, error) {
	return t.db.GetAggregatedMetrics(ctx, query)
}

func (t *SQLiteTransaction) CleanupOldMetrics(ctx context.Context, olderThan time.Time) error {
	return t.db.CleanupOldMetrics(ctx, olderThan)
}

func (t *SQLiteTransaction) GetMetricsRetention(ctx context.Context) (time.Duration, error) {
	return t.db.GetMetricsRetention(ctx)
}

func (t *SQLiteTransaction) GetProviderHealthStats(ctx context.Context, providerID int64, timeRange TimeRange) (map[string]interface{}, error) {
	return t.db.GetProviderHealthStats(ctx, providerID, timeRange)
}

func (t *SQLiteTransaction) GetSystemMetrics(ctx context.Context, timeRange TimeRange) (map[string]interface{}, error) {
	return t.db.GetSystemMetrics(ctx, timeRange)
}

func (t *SQLiteTransaction) AggregateMetrics(ctx context.Context) error {
	return t.db.AggregateMetrics(ctx)
}

func (t *SQLiteTransaction) BatchRecordRequests(ctx context.Context, requests []*RequestMetrics) error {
	return t.db.BatchRecordRequests(ctx, requests)
}

func (t *SQLiteTransaction) RecordProviderHealth(ctx context.Context, health interface{}) error {
	return t.db.RecordProviderHealth(ctx, health)
}