package database

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DatabaseMonitor provides monitoring and alerting capabilities for databases
type DatabaseMonitor struct {
	db     Database
	logger *slog.Logger
	config *MonitorConfig

	// monitoring state
	isRunning     bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
	metrics       *DatabaseMetrics
	metricsMutex  sync.RWMutex

	// alerting
	alertHandlers []AlertHandler
}

// MonitorConfig holds configuration for database monitoring
type MonitorConfig struct {
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	MetricsInterval     time.Duration `yaml:"metrics_interval" json:"metrics_interval"`
	AlertThresholds     AlertThresholds `yaml:"alert_thresholds" json:"alert_thresholds"`
	EnableMetrics       bool         `yaml:"enable_metrics" json:"enable_metrics"`
	EnableAlerts        bool         `yaml:"enable_alerts" json:"enable_alerts"`
}

// AlertThresholds defines thresholds for various database metrics
type AlertThresholds struct {
	ConnectionPoolUsage     float64 `yaml:"connection_pool_usage" json:"connection_pool_usage"`     // Percentage (0-100)
	QueryLatencyMs         int64   `yaml:"query_latency_ms" json:"query_latency_ms"`               // Milliseconds
	ErrorRate              float64 `yaml:"error_rate" json:"error_rate"`                           // Percentage (0-100)
	QueueDepth             int     `yaml:"queue_depth" json:"queue_depth"`                         // Number of queued operations
	DiskUsagePercent       float64 `yaml:"disk_usage_percent" json:"disk_usage_percent"`           // Percentage (0-100)
	SlowQueryThresholdMs   int64   `yaml:"slow_query_threshold_ms" json:"slow_query_threshold_ms"` // Milliseconds
}

// DatabaseMetrics holds current database metrics
type DatabaseMetrics struct {
	// Connection metrics
	OpenConnections     int           `json:"open_connections"`
	IdleConnections     int           `json:"idle_connections"`
	InUseConnections    int           `json:"in_use_connections"`
	MaxOpenConnections  int           `json:"max_open_connections"`
	WaitCount           int64         `json:"wait_count"`
	WaitDuration        time.Duration `json:"wait_duration"`
	MaxIdleClosed       int64         `json:"max_idle_closed"`
	MaxLifetimeClosed   int64         `json:"max_lifetime_closed"`

	// Performance metrics
	HealthCheckLatency   time.Duration `json:"health_check_latency_ms"`
	QueryLatency         time.Duration `json:"query_latency_ms"`
	ErrorCount           int64         `json:"error_count"`
	SuccessCount         int64         `json:"success_count"`
	LastHealthCheck      time.Time     `json:"last_health_check"`
	LastError            time.Time     `json:"last_error"`

	// Database-specific metrics
	DatabaseSize     int64         `json:"database_size_bytes"`
	TablesCount      int           `json:"tables_count"`
	RowsCount        int64         `json:"rows_count"`
	IndexSize        int64         `json:"index_size_bytes"`
	LastBackup       time.Time     `json:"last_backup"`
	LastVacuum       time.Time     `json:"last_vacuum"`

	// Application metrics
	RequestsPerSecond float64       `json:"requests_per_second"`
	BatchQueueLength  int           `json:"batch_queue_length"`
	CacheHitRate     float64       `json:"cache_hit_rate"`
	UpdatedAt        time.Time     `json:"updated_at"`
}

// AlertHandler defines interface for handling alerts
type AlertHandler interface {
	HandleAlert(ctx context.Context, alert *DatabaseAlert) error
}

// DatabaseAlert represents a database alert
type DatabaseAlert struct {
	Severity    AlertSeverity `json:"severity"`
	Type        AlertType     `json:"type"`
	Message     string        `json:"message"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time     `json:"timestamp"`
	Database    string        `json:"database_type"`
}

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo    AlertSeverity = "info"
	AlertSeverityWarning AlertSeverity = "warning"
	AlertSeverityError   AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertType defines different types of alerts
type AlertType string

const (
	AlertTypeHealthCheck   AlertType = "health_check"
	AlertTypePerformance   AlertType = "performance"
	AlertTypeConnection    AlertType = "connection"
	AlertTypeCapacity      AlertType = "capacity"
	AlertTypeError         AlertType = "error"
	AlertTypeSlowQuery     AlertType = "slow_query"
)

// NewDatabaseMonitor creates a new database monitor
func NewDatabaseMonitor(db Database, logger *slog.Logger, config *MonitorConfig) *DatabaseMonitor {
	if config == nil {
		config = DefaultMonitorConfig()
	}

	return &DatabaseMonitor{
		db:      db,
		logger:  logger,
		config:  config,
		metrics: &DatabaseMetrics{},
	}
}

// DefaultMonitorConfig returns default monitoring configuration
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		HealthCheckInterval: 30 * time.Second,
		MetricsInterval:     60 * time.Second,
		AlertThresholds: AlertThresholds{
			ConnectionPoolUsage:   80.0,
			QueryLatencyMs:       5000,
			ErrorRate:            10.0,
			QueueDepth:           100,
			DiskUsagePercent:     90.0,
			SlowQueryThresholdMs: 1000,
		},
		EnableMetrics: true,
		EnableAlerts:  true,
	}
}

// Start begins monitoring the database
func (m *DatabaseMonitor) Start(ctx context.Context) error {
	m.metricsMutex.Lock()
	defer m.metricsMutex.Unlock()

	if m.isRunning {
		return fmt.Errorf("monitor is already running")
	}

	m.isRunning = true
	m.stopChan = make(chan struct{})

	// Start health check goroutine
	if m.config.HealthCheckInterval > 0 {
		m.wg.Add(1)
		go m.healthCheckLoop(ctx)
	}

	// Start metrics collection goroutine
	if m.config.EnableMetrics && m.config.MetricsInterval > 0 {
		m.wg.Add(1)
		go m.metricsLoop(ctx)
	}

	m.logger.Info("Database monitor started",
		"health_check_interval", m.config.HealthCheckInterval,
		"metrics_interval", m.config.MetricsInterval)

	return nil
}

// Stop stops monitoring the database
func (m *DatabaseMonitor) Stop() error {
	m.metricsMutex.Lock()
	defer m.metricsMutex.Unlock()

	if !m.isRunning {
		return nil
	}

	m.isRunning = false
	close(m.stopChan)

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("Database monitor stopped")
	case <-time.After(30 * time.Second):
		m.logger.Warn("Timeout waiting for monitor goroutines to stop")
	}

	return nil
}

// AddAlertHandler adds an alert handler
func (m *DatabaseMonitor) AddAlertHandler(handler AlertHandler) {
	m.alertHandlers = append(m.alertHandlers, handler)
}

// GetMetrics returns current database metrics
func (m *DatabaseMonitor) GetMetrics() *DatabaseMetrics {
	m.metricsMutex.RLock()
	defer m.metricsMutex.RUnlock()

	// Return a copy to prevent external modification
	metrics := *m.metrics
	return &metrics
}

// healthCheckLoop runs periodic health checks
func (m *DatabaseMonitor) healthCheckLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.performHealthCheck(ctx)
		}
	}
}

// metricsLoop collects metrics periodically
func (m *DatabaseMonitor) metricsLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.collectMetrics(ctx)
		}
	}
}

// performHealthCheck performs a health check and updates metrics
func (m *DatabaseMonitor) performHealthCheck(ctx context.Context) {
	start := time.Now()

	// Perform health check
	if err := m.db.HealthCheck(ctx); err != nil {
		m.handleHealthCheckFailure(ctx, err)
		return
	}

	// Update metrics
	m.metricsMutex.Lock()
	defer m.metricsMutex.Unlock()

	m.metrics.HealthCheckLatency = time.Since(start)
	m.metrics.LastHealthCheck = time.Now()
	m.metrics.SuccessCount++
}

// collectMetrics collects comprehensive database metrics
func (m *DatabaseMonitor) collectMetrics(ctx context.Context) {
	m.metricsMutex.Lock()
	defer m.metricsMutex.Unlock()

	m.collectConnectionMetrics(ctx)
	m.collectDatabaseMetrics(ctx)
	m.collectPerformanceMetrics(ctx)
	m.metrics.UpdatedAt = time.Now()

	// Check thresholds and trigger alerts
	if m.config.EnableAlerts {
		m.checkThresholds(ctx)
	}
}

// collectConnectionMetrics collects database connection pool metrics
func (m *DatabaseMonitor) collectConnectionMetrics(ctx context.Context) {
	// Get database stats if available
	if db, ok := m.db.(*SQLiteDatabase); ok && db.db != nil {
		stats := db.db.Stats()
		m.metrics.OpenConnections = stats.OpenConnections
		m.metrics.InUseConnections = stats.InUse
		m.metrics.IdleConnections = stats.Idle
		m.metrics.WaitCount = stats.WaitCount
		m.metrics.WaitDuration = stats.WaitDuration
		m.metrics.MaxIdleClosed = stats.MaxIdleClosed
		m.metrics.MaxLifetimeClosed = stats.MaxLifetimeClosed

		// For SQLite, max connections is typically 1
		m.metrics.MaxOpenConnections = 1
	}

	if db, ok := m.db.(*MySQLDatabase); ok && db.db != nil {
		stats := db.db.Stats()
		m.metrics.OpenConnections = stats.OpenConnections
		m.metrics.InUseConnections = stats.InUse
		m.metrics.IdleConnections = stats.Idle
		m.metrics.WaitCount = stats.WaitCount
		m.metrics.WaitDuration = stats.WaitDuration
		m.metrics.MaxIdleClosed = stats.MaxIdleClosed
		m.metrics.MaxLifetimeClosed = stats.MaxLifetimeClosed

		// For MySQL, check actual max connections from config
		if db.config != nil {
			m.metrics.MaxOpenConnections = db.config.MaxOpenConns
		}
	}
}

// collectDatabaseMetrics collects database-specific metrics
func (m *DatabaseMonitor) collectDatabaseMetrics(ctx context.Context) {
	// This would be database-specific implementation
	// For now, we'll implement basic queries

	// Get table count
	tables, err := m.getDatabaseStats(ctx)
	if err != nil {
		m.logger.Warn("Failed to collect database metrics", "error", err)
		m.metrics.ErrorCount++
		m.metrics.LastError = time.Now()
		return
	}

	m.metrics.TablesCount = tables
}

// collectPerformanceMetrics collects performance-related metrics
func (m *DatabaseMonitor) collectPerformanceMetrics(ctx context.Context) {
	// Measure query performance with a simple query
	start := time.Now()

	// Perform a simple query to measure latency
	if err := m.db.Ping(ctx); err != nil {
		m.logger.Warn("Failed to measure query performance", "error", err)
		m.metrics.ErrorCount++
		m.metrics.LastError = time.Now()
		return
	}

	m.metrics.QueryLatency = time.Since(start)
}

// getDatabaseStats retrieves basic database statistics
func (m *DatabaseMonitor) getDatabaseStats(ctx context.Context) (int, error) {
	// This is a simplified implementation
	// In production, this would be database-specific queries
	return 0, nil // Placeholder implementation
}

// checkThresholds checks if any metrics exceed thresholds and triggers alerts
func (m *DatabaseMonitor) checkThresholds(ctx context.Context) {
	// Check connection pool usage
	if m.metrics.MaxOpenConnections > 0 {
		usagePercent := float64(m.metrics.InUseConnections) / float64(m.metrics.MaxOpenConnections) * 100
		if usagePercent > m.config.AlertThresholds.ConnectionPoolUsage {
			m.triggerAlert(ctx, &DatabaseAlert{
				Severity: AlertSeverityWarning,
				Type:     AlertTypeConnection,
				Message:  fmt.Sprintf("Connection pool usage is high: %.1f%%", usagePercent),
				Metadata: map[string]interface{}{
					"usage_percent":    usagePercent,
					"connections":      m.metrics.InUseConnections,
					"max_connections":  m.metrics.MaxOpenConnections,
				},
				Database: m.getDatabaseType(),
			})
		}
	}

	// Check query latency
	queryLatencyMs := m.metrics.QueryLatency.Milliseconds()
	if queryLatencyMs > int64(m.config.AlertThresholds.QueryLatencyMs) {
		m.triggerAlert(ctx, &DatabaseAlert{
			Severity: AlertSeverityWarning,
			Type:     AlertTypePerformance,
			Message:  fmt.Sprintf("High query latency detected: %dms", queryLatencyMs),
			Metadata: map[string]interface{}{
				"query_latency_ms": queryLatencyMs,
				"threshold_ms":     m.config.AlertThresholds.QueryLatencyMs,
			},
			Database: m.getDatabaseType(),
		})
	}

	// Check error rate
	totalRequests := m.metrics.SuccessCount + m.metrics.ErrorCount
	if totalRequests > 0 {
		errorRate := float64(m.metrics.ErrorCount) / float64(totalRequests) * 100
		if errorRate > m.config.AlertThresholds.ErrorRate {
			m.triggerAlert(ctx, &DatabaseAlert{
				Severity: AlertSeverityError,
				Type:     AlertTypeError,
				Message:  fmt.Sprintf("High error rate detected: %.1f%%", errorRate),
				Metadata: map[string]interface{}{
					"error_rate_percent": errorRate,
					"error_count":        m.metrics.ErrorCount,
					"success_count":      m.metrics.SuccessCount,
				},
				Database: m.getDatabaseType(),
			})
		}
	}
}

// handleHealthCheckFailure handles health check failures
func (m *DatabaseMonitor) handleHealthCheckFailure(ctx context.Context, err error) {
	m.metricsMutex.Lock()
	defer m.metricsMutex.Unlock()

	m.metrics.ErrorCount++
	m.metrics.LastError = time.Now()
	m.metrics.HealthCheckLatency = 0 // Reset on failure

	// Trigger critical alert for health check failure
	m.triggerAlert(ctx, &DatabaseAlert{
		Severity: AlertSeverityCritical,
		Type:     AlertTypeHealthCheck,
		Message:  fmt.Sprintf("Database health check failed: %v", err),
		Metadata: map[string]interface{}{
			"error": err.Error(),
		},
		Database: m.getDatabaseType(),
	})
}

// triggerAlert sends alert to all registered handlers
func (m *DatabaseMonitor) triggerAlert(ctx context.Context, alert *DatabaseAlert) {
	alert.Timestamp = time.Now()

	for _, handler := range m.alertHandlers {
		if err := handler.HandleAlert(ctx, alert); err != nil {
			m.logger.Error("Failed to handle alert", "error", err, "alert_type", alert.Type)
		}
	}

	// Always log the alert
	m.logger.Warn("Database alert triggered",
		"severity", alert.Severity,
		"type", alert.Type,
		"message", alert.Message,
		"database", alert.Database)
}

// getDatabaseType returns the type of database being monitored
func (m *DatabaseMonitor) getDatabaseType() string {
	switch m.db.(type) {
	case *SQLiteDatabase:
		return "sqlite"
	case *MySQLDatabase:
		return "mysql"
	default:
		return "unknown"
	}
}

// LogAlertHandler is a simple alert handler that logs alerts
type LogAlertHandler struct {
	logger *slog.Logger
}

// NewLogAlertHandler creates a new log alert handler
func NewLogAlertHandler(logger *slog.Logger) *LogAlertHandler {
	return &LogAlertHandler{
		logger: logger,
	}
}

// HandleAlert logs the alert
func (h *LogAlertHandler) HandleAlert(ctx context.Context, alert *DatabaseAlert) error {
	switch alert.Severity {
	case AlertSeverityCritical:
		h.logger.Error("Critical database alert",
			"type", alert.Type,
			"message", alert.Message,
			"metadata", alert.Metadata,
			"database", alert.Database)
	case AlertSeverityError:
		h.logger.Error("Database error alert",
			"type", alert.Type,
			"message", alert.Message,
			"metadata", alert.Metadata,
			"database", alert.Database)
	case AlertSeverityWarning:
		h.logger.Warn("Database warning alert",
			"type", alert.Type,
			"message", alert.Message,
			"metadata", alert.Metadata,
			"database", alert.Database)
	case AlertSeverityInfo:
		h.logger.Info("Database info alert",
			"type", alert.Type,
			"message", alert.Message,
			"metadata", alert.Metadata,
			"database", alert.Database)
	}
	return nil
}