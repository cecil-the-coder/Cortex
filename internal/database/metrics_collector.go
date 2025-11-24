package database

import (
	"context"
	"sync"
	"time"
	"log/slog"
	"github.com/cecil-the-coder/Cortex/internal/health"
)

// MetricsCollector handles high-performance metrics collection using async batching
type MetricsCollector struct {
	repo          MetricsRepository
	requestBuffer chan *RequestMetrics
	healthBuffer  chan *health.ProviderHealthStatus

	batchSize     int
	flushInterval time.Duration

	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *slog.Logger
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(repo MetricsRepository, config *DatabaseConfig, logger *slog.Logger) *MetricsCollector {
	ctx, cancel := context.WithCancel(context.Background())

	mc := &MetricsCollector{
		repo:          repo,
		requestBuffer: make(chan *RequestMetrics, config.BatchSize*10), // 10x buffer
		healthBuffer:  make(chan *health.ProviderHealthStatus, 1000),
		batchSize:     config.BatchSize,
		flushInterval: config.FlushInterval,
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
	}

	// Start worker goroutines
	mc.startWorkers()

	return mc
}

// startWorkers starts the background processing goroutines
func (mc *MetricsCollector) startWorkers() {
	// Request metrics worker
	mc.wg.Add(1)
	go mc.requestMetricsWorker()

	// Health metrics worker
	mc.wg.Add(1)
	go mc.healthMetricsWorker()

	// Periodic aggregation worker
	mc.wg.Add(1)
	go mc.aggregationWorker()
}

// requestMetricsWorker processes request metrics in batches
func (mc *MetricsCollector) requestMetricsWorker() {
	defer mc.wg.Done()

	ticker := time.NewTicker(mc.flushInterval)
	defer ticker.Stop()

	batch := make([]*RequestMetrics, 0, mc.batchSize)
	lastFlush := time.Now()

	for {
		select {
		case <-mc.ctx.Done():
			// Flush remaining batch before exit
			if len(batch) > 0 {
				mc.flushRequestBatch(batch)
			}
			return

		case metric := <-mc.requestBuffer:
			batch = append(batch, metric)

			// Flush if batch is full
			if len(batch) >= mc.batchSize {
				mc.flushRequestBatch(batch)
				batch = batch[:0] // Reset slice
				lastFlush = time.Now()
			}

		case <-ticker.C:
			// Flush if we have pending metrics or it's been too long
			if len(batch) > 0 || time.Since(lastFlush) > mc.flushInterval*2 {
				if len(batch) > 0 {
					mc.flushRequestBatch(batch)
					batch = batch[:0]
				}
				lastFlush = time.Now()
			}
		}
	}
}

// healthMetricsWorker processes health metrics
func (mc *MetricsCollector) healthMetricsWorker() {
	defer mc.wg.Done()

	ticker := time.NewTicker(30 * time.Second) // Health checks are less frequent
	defer ticker.Stop()

	batch := make([]*health.ProviderHealthStatus, 0, 50)

	for {
		select {
		case <-mc.ctx.Done():
			if len(batch) > 0 {
				mc.flushHealthBatch(batch)
			}
			return

		case health := <-mc.healthBuffer:
			batch = append(batch, health)

			if len(batch) >= 50 {
				mc.flushHealthBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				mc.flushHealthBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// aggregationWorker performs periodic aggregation of metrics
func (mc *MetricsCollector) aggregationWorker() {
	defer mc.wg.Done()

	ticker := time.NewTicker(10 * time.Minute) // Run aggregation every 10 minutes
	defer ticker.Stop()

	for {
		select {
		case <-mc.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(mc.ctx, 5*time.Minute)
			if err := mc.repo.AggregateMetrics(ctx); err != nil {
				mc.logger.Error("metrics aggregation failed",
					"error", err)
			}
			cancel()
		}
	}
}

// RecordRequest records a request metric (non-blocking)
func (mc *MetricsCollector) RecordRequest(metric *RequestMetrics) {
	select {
	case mc.requestBuffer <- metric:
		// Successfully queued
	default:
		mc.logger.Warn("metrics buffer full, dropping metric",
			"request_id", metric.RequestID,
			"buffer_size", len(mc.requestBuffer))
	}
}

// RecordProviderHealth records a provider health metric (non-blocking)
func (mc *MetricsCollector) RecordProviderHealth(health *health.ProviderHealthStatus) {
	select {
	case mc.healthBuffer <- health:
		// Successfully queued
	default:
		mc.logger.Warn("health metrics buffer full, dropping metric",
			"provider_name", health.ProviderName)
	}
}

// flushRequestBatch flushes a batch of request metrics to the database
func (mc *MetricsCollector) flushRequestBatch(batch []*RequestMetrics) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(mc.ctx, 30*time.Second)
	defer cancel()

	start := time.Now()
	if err := mc.repo.BatchRecordRequests(ctx, batch); err != nil {
		mc.logger.Error("failed to flush request metrics batch",
			"error", err,
			"batch_size", len(batch))
		return
	}

	duration := time.Since(start)
	mc.logger.Debug("flushed request metrics batch",
		"batch_size", len(batch),
		"duration_ms", duration.Milliseconds(),
		"metrics_per_second", float64(len(batch))/duration.Seconds())
}

// flushHealthBatch flushes a batch of health metrics to the database
func (mc *MetricsCollector) flushHealthBatch(batch []*health.ProviderHealthStatus) {
	if len(batch) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(mc.ctx, 10*time.Second)
	defer cancel()

	// For now, we don't have batch health recording, so record individually
	for _, health := range batch {
		if err := mc.repo.RecordProviderHealth(ctx, health); err != nil {
			mc.logger.Error("failed to record provider health",
				"error", err,
				"provider_name", health.ProviderName)
		}
	}
}

// Stop gracefully shuts down the metrics collector
func (mc *MetricsCollector) Stop() {
	mc.logger.Info("stopping metrics collector")

	// Signal goroutines to stop
	mc.cancel()

	// Wait for workers to finish
	mc.wg.Wait()

	// Close buffers
	close(mc.requestBuffer)
	close(mc.healthBuffer)

	mc.logger.Info("metrics collector stopped")
}

// GetStats returns statistics about the collector
func (mc *MetricsCollector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"request_buffer_size":    len(mc.requestBuffer),
		"request_buffer_capacity": cap(mc.requestBuffer),
		"health_buffer_size":     len(mc.healthBuffer),
		"health_buffer_capacity":  cap(mc.healthBuffer),
		"batch_size":             mc.batchSize,
		"flush_interval":         mc.flushInterval.String(),
	}
}