package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	goconfig "github.com/cecil-the-coder/Cortex/internal/config"
)

// MySQLDatabase implements Database interface for MySQL
type MySQLDatabase struct {
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

	// Connection retry management
	retryConfig *RetryConfig
}

// RetryConfig holds configuration for connection retries
type RetryConfig struct {
	MaxRetries      int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffMultiplier float64
}

// NewMySQLDatabase creates a new MySQL database instance
func NewMySQLDatabase(config *DatabaseConfig, logger *slog.Logger) (Database, error) {
	if config.Host == "" || config.Database == "" || config.Username == "" {
		return nil, fmt.Errorf("MySQL host, database, and username are required")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	db := &MySQLDatabase{
		config: config,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		batchQueue: make(chan []*RequestMetrics, 1000),
		batchWorkers: 4, // More workers for MySQL
		retryConfig: &RetryConfig{
			MaxRetries:      5,
			InitialBackoff:  time.Second,
			MaxBackoff:      time.Minute,
			BackoffMultiplier: 2.0,
		},
	}

	return db, nil
}

// Connect establishes connection to MySQL database with retry logic
func (m *MySQLDatabase) Connect(ctx context.Context) error {
	// Build DSN
	dsn := m.buildDSN()

	var lastErr error
	backoff := m.retryConfig.InitialBackoff

	for attempt := 0; attempt <= m.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			m.logger.Info("Retrying MySQL connection attempt",
				"attempt", attempt,
				"max_retries", m.retryConfig.MaxRetries,
				"backoff", backoff)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			backoff = time.Duration(float64(backoff) * m.retryConfig.BackoffMultiplier)
			if backoff > m.retryConfig.MaxBackoff {
				backoff = m.retryConfig.MaxBackoff
			}
		}

		var err error
		m.db, err = sql.Open("mysql", dsn)
		if err != nil {
			lastErr = fmt.Errorf("failed to open MySQL database: %w", err)
			continue
		}

		// Setup connection pool
		if err := SetupConnectionPool(m.db, m.config, "mysql"); err != nil {
			lastErr = fmt.Errorf("failed to setup connection pool: %w", err)
			m.db.Close()
			m.db = nil
			continue
		}

		// Test connection
		if err := m.db.PingContext(ctx); err != nil {
			lastErr = fmt.Errorf("failed to ping MySQL database: %w", err)
			m.db.Close()
			m.db = nil
			continue
		}

		// Connection successful
		break
	}

	if m.db == nil {
		return fmt.Errorf("failed to connect to MySQL after %d attempts: %w", m.retryConfig.MaxRetries, lastErr)
	}

	// Start background batch workers
	m.startBatchWorkers()

	m.logger.Info("Connected to MySQL database",
		"host", m.config.Host,
		"port", m.config.Port,
		"database", m.config.Database)

	return nil
}

// buildDSN builds MySQL DSN string
func (m *MySQLDatabase) buildDSN() string {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		m.config.Username,
		m.config.Password,
		m.config.Host,
		m.config.Port,
		m.config.Database)

	// Add parameters
	params := make(map[string]string)

	// Character set and collation
	if m.config.MySQLCharset != "" {
		params["charset"] = m.config.MySQLCharset
	} else {
		params["charset"] = "utf8mb4"
	}

	if m.config.MySQLCollation != "" {
		params["collation"] = m.config.MySQLCollation
	} else {
		params["collation"] = "utf8mb4_unicode_ci"
	}

	// Parse time
	if m.config.MySQLParseTime {
		params["parseTime"] = "true"
	} else {
		params["parseTime"] = "false"
	}

	// Other important parameters
	params["loc"] = "Local"
	params["timeout"] = "30s"
	params["readTimeout"] = "30s"
	params["writeTimeout"] = "30s"
	params["allowNativePasswords"] = "true"
	params["rejectReadOnly"] = "false"

	// Build query string
	separator := "?"
	for key, value := range params {
		dsn += separator + key + "=" + value
		separator = "&"
	}

	return dsn
}

// Close closes the database connection gracefully
func (m *MySQLDatabase) Close() error {
	m.shutdownMutex.Lock()
	defer m.shutdownMutex.Unlock()

	if m.isShuttingDown {
		return nil // Already shutting down
	}

	m.isShuttingDown = true
	m.logger.Info("Starting graceful shutdown of MySQL database")

	// Cancel context to signal shutdown
	m.cancel()

	// Close batch queue to stop accepting new items
	close(m.batchQueue)

	// Wait for all batch workers to finish with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All batch workers completed")
	case <-time.After(30 * time.Second):
		m.logger.Warn("Timeout waiting for batch workers, proceeding with shutdown")
	}

	// Close database connection
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			m.logger.Error("Error closing MySQL database", "error", err)
			return err
		}
	}

	m.logger.Info("MySQL database closed gracefully")
	return nil
}

// Ping checks database connectivity
func (m *MySQLDatabase) Ping(ctx context.Context) error {
	if m.db == nil {
		return fmt.Errorf("database not connected")
	}
	return m.db.PingContext(ctx)
}

// BeginTx starts a new transaction
func (m *MySQLDatabase) BeginTx(ctx context.Context, opts *sql.TxOptions) (Transaction, error) {
	tx, err := m.db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &MySQLTransaction{tx: tx, db: m}, nil
}

// Migrate runs database migrations
func (m *MySQLDatabase) Migrate(ctx context.Context) error {
	migrator := NewMigrator(m.db, m.logger)
	InitializeMigrations(migrator)
	return migrator.Migrate(ctx)
}

// GetVersion returns current database version
func (m *MySQLDatabase) GetVersion() (string, error) {
	migrator := NewMigrator(m.db, m.logger)
	return migrator.getCurrentVersion(context.Background())
}

// HealthCheck performs comprehensive health check
func (m *MySQLDatabase) HealthCheck(ctx context.Context) error {
	if m.db == nil {
		return fmt.Errorf("database not connected")
	}

	// Check basic connectivity
	if err := m.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Check if we can perform a simple query
	var result string
	err := m.db.QueryRowContext(ctx, "SELECT 'health_check'").Scan(&result)
	if err != nil {
		return fmt.Errorf("database health check query failed: %w", err)
	}

	if result != "health_check" {
		return fmt.Errorf("unexpected health check result: %s", result)
	}

	// Check connection pool stats
	stats := m.db.Stats()
	if stats.OpenConnections == 0 {
		return fmt.Errorf("no open database connections")
	}

	rows, err := m.db.QueryContext(ctx, "SHOW STATUS WHERE Variable_name IN ('Connections', 'Threads_connected', 'Qcache_hits')")
	if err != nil {
		m.logger.Warn("Failed to get MySQL status variables", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var v struct {
				VariableName string `db:"Variable_name"`
				Value        string `db:"Value"`
			}
			if err := rows.Scan(&v.VariableName, &v.Value); err == nil {
				m.logger.Debug("MySQL status",
					"variable", v.VariableName,
					"value", v.Value)
			}
		}
	}

	return nil
}

// startBatchWorkers starts background workers for batch processing
func (m *MySQLDatabase) startBatchWorkers() {
	for i := 0; i < m.batchWorkers; i++ {
		m.wg.Add(1)
		go m.batchWorker(i)
	}
}

// batchWorker processes batches of metrics
func (m *MySQLDatabase) batchWorker(workerID int) {
	defer m.wg.Done()

	m.logger.Debug("Started MySQL batch worker", "worker_id", workerID)

	for {
		select {
		case <-m.ctx.Done():
			m.logger.Debug("MySQL batch worker stopping", "worker_id", workerID)
			return
		case batch, ok := <-m.batchQueue:
			if !ok {
				m.logger.Debug("MySQL batch worker terminating (queue closed)", "worker_id", workerID)
				return
			}

			if err := m.processBatch(batch); err != nil {
				m.logger.Error("Failed to process batch in MySQL worker",
					"worker_id", workerID,
					"batch_size", len(batch),
					"error", err)
			}
		}
	}
}

// processBatch processes a batch of metrics
func (m *MySQLDatabase) processBatch(batch []*RequestMetrics) error {
	if len(batch) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	tx, err := m.BeginTx(ctx, nil)
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

	m.logger.Debug("Processed batch successfully", "batch_size", len(batch))
	return nil
}

// MySQLTransaction implements Transaction interface for MySQL
type MySQLTransaction struct {
	tx *sql.Tx
	db *MySQLDatabase
}

// Commit commits the transaction
func (t *MySQLTransaction) Commit() error {
	return t.tx.Commit()
}

// Rollback rolls back the transaction
func (t *MySQLTransaction) Rollback() error {
	return t.tx.Rollback()
}

// ConfigRepository methods (delegates to implementation)
func (t *MySQLTransaction) CreateProvider(ctx context.Context, provider *Provider) error {
	return t.db.CreateProvider(ctx, provider)
}

func (t *MySQLTransaction) GetProvider(ctx context.Context, id int64) (*Provider, error) {
	return t.db.GetProvider(ctx, id)
}

func (t *MySQLTransaction) GetProviderByName(ctx context.Context, name string) (*Provider, error) {
	return t.db.GetProviderByName(ctx, name)
}

func (t *MySQLTransaction) UpdateProvider(ctx context.Context, provider *Provider) error {
	return t.db.UpdateProvider(ctx, provider)
}

func (t *MySQLTransaction) DeleteProvider(ctx context.Context, id int64) error {
	return t.db.DeleteProvider(ctx, id)
}

func (t *MySQLTransaction) ListProviders(ctx context.Context, filter *ProviderFilter) ([]*Provider, error) {
	return t.db.ListProviders(ctx, filter)
}

func (t *MySQLTransaction) CreateModel(ctx context.Context, model *Model) error {
	return t.db.CreateModel(ctx, model)
}

func (t *MySQLTransaction) GetModel(ctx context.Context, id int64) (*Model, error) {
	return t.db.GetModel(ctx, id)
}

func (t *MySQLTransaction) GetModelByName(ctx context.Context, providerID int64, modelName string) (*Model, error) {
	return t.db.GetModelByName(ctx, providerID, modelName)
}

func (t *MySQLTransaction) UpdateModel(ctx context.Context, model *Model) error {
	return t.db.UpdateModel(ctx, model)
}

func (t *MySQLTransaction) DeleteModel(ctx context.Context, id int64) error {
	return t.db.DeleteModel(ctx, id)
}

func (t *MySQLTransaction) ListModels(ctx context.Context, filter *ModelFilter) ([]*Model, error) {
	return t.db.ListModels(ctx, filter)
}

func (t *MySQLTransaction) CreateModelGroup(ctx context.Context, group *ModelGroup) error {
	return t.db.CreateModelGroup(ctx, group)
}

func (t *MySQLTransaction) GetModelGroup(ctx context.Context, id int64) (*ModelGroup, error) {
	return t.db.GetModelGroup(ctx, id)
}

func (t *MySQLTransaction) GetModelGroupByName(ctx context.Context, name string) (*ModelGroup, error) {
	return t.db.GetModelGroupByName(ctx, name)
}

func (t *MySQLTransaction) UpdateModelGroup(ctx context.Context, group *ModelGroup) error {
	return t.db.UpdateModelGroup(ctx, group)
}

func (t *MySQLTransaction) DeleteModelGroup(ctx context.Context, id int64) error {
	return t.db.DeleteModelGroup(ctx, id)
}

func (t *MySQLTransaction) ListModelGroups(ctx context.Context) ([]*ModelGroup, error) {
	return t.db.ListModelGroups(ctx)
}

func (t *MySQLTransaction) AddGroupMember(ctx context.Context, member *GroupMember) error {
	return t.db.AddGroupMember(ctx, member)
}

func (t *MySQLTransaction) RemoveGroupMember(ctx context.Context, id int64) error {
	return t.db.RemoveGroupMember(ctx, id)
}

func (t *MySQLTransaction) GetGroupMembers(ctx context.Context, groupID int64) ([]*GroupMember, error) {
	return t.db.GetGroupMembers(ctx, groupID)
}

func (t *MySQLTransaction) CreateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	return t.db.CreateAPIKey(ctx, apiKey)
}

func (t *MySQLTransaction) GetAPIKey(ctx context.Context, id int64) (*ClientAPIKey, error) {
	return t.db.GetAPIKey(ctx, id)
}

func (t *MySQLTransaction) GetAPIKeyByKeyID(ctx context.Context, keyID string) (*ClientAPIKey, error) {
	return t.db.GetAPIKeyByKeyID(ctx, keyID)
}

func (t *MySQLTransaction) UpdateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error {
	return t.db.UpdateAPIKey(ctx, apiKey)
}

func (t *MySQLTransaction) DeleteAPIKey(ctx context.Context, id int64) error {
	return t.db.DeleteAPIKey(ctx, id)
}

func (t *MySQLTransaction) ListAPIKeys(ctx context.Context, filter *APIKeyFilter) ([]*ClientAPIKey, error) {
	return t.db.ListAPIKeys(ctx, filter)
}

func (t *MySQLTransaction) GetRouterConfig(ctx context.Context) (*RouterConfig, error) {
	return t.db.GetRouterConfig(ctx)
}

func (t *MySQLTransaction) UpdateRouterConfig(ctx context.Context, config *RouterConfig) error {
	return t.db.UpdateRouterConfig(ctx, config)
}

func (t *MySQLTransaction) ExportConfig(ctx context.Context) (*goconfig.Config, error) {
	return t.db.ExportConfig(ctx)
}

func (t *MySQLTransaction) ImportConfig(ctx context.Context, cfg *goconfig.Config) error {
	return t.db.ImportConfig(ctx, cfg)
}

func (t *MySQLTransaction) StoreRequestMetrics(ctx context.Context, metrics *RequestMetrics) error {
	return t.db.StoreRequestMetrics(ctx, metrics)
}

func (t *MySQLTransaction) StoreBatchRequestMetrics(ctx context.Context, metrics []*RequestMetrics) error {
	return t.db.StoreBatchRequestMetrics(ctx, metrics)
}

func (t *MySQLTransaction) GetRequestMetrics(ctx context.Context, query *MetricsQuery) ([]*RequestMetrics, error) {
	return t.db.GetRequestMetrics(ctx, query)
}

func (t *MySQLTransaction) GetAggregatedMetrics(ctx context.Context, query *AggregatedQuery) ([]*AggregatedMetrics, error) {
	return t.db.GetAggregatedMetrics(ctx, query)
}

func (t *MySQLTransaction) CleanupOldMetrics(ctx context.Context, olderThan time.Time) error {
	return t.db.CleanupOldMetrics(ctx, olderThan)
}

func (t *MySQLTransaction) GetMetricsRetention(ctx context.Context) (time.Duration, error) {
	return t.db.GetMetricsRetention(ctx)
}

func (t *MySQLTransaction) GetProviderHealthStats(ctx context.Context, providerID int64, timeRange TimeRange) (map[string]interface{}, error) {
	return t.db.GetProviderHealthStats(ctx, providerID, timeRange)
}

func (t *MySQLTransaction) GetSystemMetrics(ctx context.Context, timeRange TimeRange) (map[string]interface{}, error) {
	return t.db.GetSystemMetrics(ctx, timeRange)
}

func (t *MySQLTransaction) AggregateMetrics(ctx context.Context) error {
	return t.db.AggregateMetrics(ctx)
}

func (t *MySQLTransaction) BatchRecordRequests(ctx context.Context, requests []*RequestMetrics) error {
	return t.db.BatchRecordRequests(ctx, requests)
}

func (t *MySQLTransaction) RecordProviderHealth(ctx context.Context, health interface{}) error {
	return t.db.RecordProviderHealth(ctx, health)
}