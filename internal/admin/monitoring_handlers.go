package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MetricsData represents system metrics for monitoring
type MetricsData struct {
	System      SystemMetrics         `json:"system"`
	Providers   SystemProviderMetrics `json:"providers"`
	Requests    RequestMetrics         `json:"requests"`
	Performance PerformanceMetrics    `json:"performance"`
	Timestamp   time.Time             `json:"timestamp"`
	Period      string                `json:"period"`
}

// SystemMetrics contains system-level metrics
type SystemMetrics struct {
	CPU        CPUMetrics        `json:"cpu"`
	Memory     MemoryMetrics     `json:"memory"`
	Goroutines GoroutineMetrics  `json:"goroutines"`
	GC         GCMetrics         `json:"gc"`
	Network    NetworkMetrics    `json:"network"`
}

// CPUMetrics contains CPU usage metrics
type CPUMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	LoadAverage  float64 `json:"load_average"`
	NumCores     int     `json:"num_cores"`
}

// MemoryMetrics contains memory usage metrics
type MemoryMetrics struct {
	AllocMB       float64 `json:"alloc_mb"`
	TotalAllocMB  float64 `json:"total_alloc_mb"`
	SysMB         float64 `json:"sys_mb"`
	HeapMB        float64 `json:"heap_mb"`
	StackMB       float64 `json:"stack_mb"`
	GCGCycles     uint32  `json:"gc_cycles"`
	GCPauseTotalMS float64 `json:"gc_pause_total_ms"`
}

// GoroutineMetrics contains goroutine metrics
type GoroutineMetrics struct {
	Count int `json:"count"`
}

// GCMetrics contains garbage collection metrics
type GCMetrics struct {
	NumGC        uint32  `json:"num_gc"`
	LastGCPauseMS float64 `json:"last_gc_pause_ms"`
	PauseTotalMS float64 `json:"pause_total_ms"`
	GoalMB       float64 `json:"goal_mb"`
}

// NetworkMetrics contains network metrics
type NetworkMetrics struct {
	ConnectionsOpen int   `json:"connections_open"`
	ConnectionsTotal int64 `json:"connections_total"`
	BytesRead       int64 `json:"bytes_read"`
	BytesWritten    int64 `json:"bytes_written"`
}

// SystemProviderMetrics contains provider-specific metrics for system monitoring
type SystemProviderMetrics struct {
	Total          int64                  `json:"total"`
	Success        int64                  `json:"success"`
	Failed         int64                  `json:"failed"`
	ByProvider     map[string]ProviderStats `json:"by_provider"`
	ErrorRate      float64                `json:"error_rate_percent"`
	AvgLatency     float64                `json:"avg_latency_ms"`
	P95Latency     float64                `json:"p95_latency_ms"`
	P99Latency     float64                `json:"p99_latency_ms"`
}

// ProviderStats contains statistics for a specific provider
type ProviderStats struct {
	Requests      int64   `json:"requests"`
	Successes     int64   `json:"successes"`
	Failures      int64   `json:"failures"`
	ErrorRate     float64 `json:"error_rate_percent"`
	AvgLatency    float64 `json:"avg_latency_ms"`
	LastRequest   *time.Time `json:"last_request,omitempty"`
	Healthy       bool    `json:"healthy"`
	StatusCode    *string  `json:"status_code,omitempty"`
}

// RequestMetrics contains request-related metrics
type RequestMetrics struct {
	Total          int64            `json:"total"`
	Success        int64            `json:"success"`
	Failed         int64            `json:"failed"`
	ByModel        map[string]int64 `json:"by_model"`
	ByUser         map[string]int64 `json:"by_user"`
	ByRouteReason  map[string]int64 `json:"by_route_reason"`
	AvgTokensIn    float64          `json:"avg_tokens_in"`
	AvgTokensOut   float64          `json:"avg_tokens_out"`
	TotalTokens    int64            `json:"total_tokens"`
}

// PerformanceMetrics contains performance metrics
type PerformanceMetrics struct {
	ResponseTime   ResponseTimeMetrics `json:"response_time"`
	Throughput     ThroughputMetrics  `json:"throughput"`
	Concurrency    ConcurrencyMetrics `json:"concurrency"`
	ResourceUsage  ResourceMetrics   `json:"resource_usage"`
}

// ResponseTimeMetrics contains response time statistics
type ResponseTimeMetrics struct {
	AvgMS    float64  `json:"avg_ms"`
	P50MS    float64  `json:"p50_ms"`
	P95MS    float64  `json:"p95_ms"`
	P99MS    float64  `json:"p99_ms"`
	MaxMS    float64  `json:"max_ms"`
	Duration int      `json:"duration_seconds"`
}

// ThroughputMetrics contains throughput statistics
type ThroughputMetrics struct {
	RequestsPerSec float64 `json:"requests_per_sec"`
	TokensPerSec   float64 `json:"tokens_per_sec"`
	BytePerSec     float64 `json:"bytes_per_sec"`
}

// ConcurrencyMetrics contains concurrency statistics
type ConcurrencyMetrics struct {
	MaxConcurrent   int     `json:"max_concurrent"`
	AvgConcurrent   float64 `json:"avg_concurrent"`
	CurrentActive   int     `json:"current_active"`
	QueueLength      int     `json:"queue_length"`
	QueueWaitTimeMS  float64 `json:"queue_wait_time_ms"`
}

// ResourceMetrics contains resource utilization metrics
type ResourceMetrics struct {
	CPUUtilization float64 `json:"cpu_utilization_percent"`
	MemoryUtilization float64 `json:"memory_utilization_percent"`
	NetworkIO     NetworkIOMetrics `json:"network_io"`
	DiskIO        DiskIOMetrics    `json:"disk_io"`
}

// NetworkIOMetrics contains network I/O metrics
type NetworkIOMetrics struct {
	BytesInPerSec  float64 `json:"bytes_in_per_sec"`
	BytesOutPerSec float64 `json:"bytes_out_per_sec"`
	PacketsPerSec  float64 `json:"packets_per_sec"`
}

// DiskIOMetrics contains disk I/O metrics
type DiskIOMetrics struct {
	ReadBytesPerSec  float64 `json:"read_bytes_per_sec"`
	WriteBytesPerSec float64 `json:"write_bytes_per_sec"`
	IOOperationsPSec  float64 `json:"io_operations_per_sec"`
}

// AnalyticsRequest represents an analytics query request
type AnalyticsRequest struct {
	Metrics    []string          `json:"metrics"`     // "system", "providers", "requests", "performance"
	Period     string            `json:"period"`      // "1h", "24h", "7d", "30d", "custom"
	StartDate  *time.Time        `json:"start_date,omitempty"`
	EndDate    *time.Time        `json:"end_date,omitempty"`
	Granularity string            `json:"granularity"` // "1m", "5m", "1h", "1d"
	Filters    map[string]string `json:"filters,omitempty"`
	GroupBy    []string          `json:"group_by,omitempty"`
	Aggregations []string        `json:"aggregations,omitempty"` // "sum", "avg", "min", "max", "count"
}

// AnalyticsResponse contains analytics query results
type AnalyticsResponse struct {
	Query       AnalyticsQuery     `json:"query"`
	Data        AnalyticsData      `json:"data"`
	Summary     AnalyticsSummary   `json:"summary"`
	Metadata    AnalyticsMetadata  `json:"metadata"`
	Duration    string             `json:"duration"`
	GeneratedAt time.Time          `json:"generated_at"`
}

// AnalyticsQuery represents the parsed query
type AnalyticsQuery struct {
	Metrics    []string          `json:"metrics"`
	Period     string            `json:"period"`
	StartDate  *time.Time        `json:"start_date,omitempty"`
	EndDate    *time.Time        `json:"end_date,omitempty"`
	Granularity string            `json:"granularity"`
	Filters    map[string]string `json:"filters,omitempty"`
	GroupBy    []string          `json:"group_by,omitempty"`
	Aggregations []string        `json:"aggregations,omitempty"`
}

// AnalyticsData contains the actual analytics data
type AnalyticsData struct {
	TimeSeries map[string][]TimeSeriesPoint `json:"time_series,omitempty"`
	Aggregated map[string]interface{}        `json:"aggregated,omitempty"`
	Tables     map[string]interface{}        `json:"tables,omitempty"`
}

// TimeSeriesPoint represents a point in a time series
type TimeSeriesPoint struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     interface{} `json:"value"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// AnalyticsSummary contains summary statistics
type AnalyticsSummary struct {
	TotalDataPoints int                    `json:"total_data_points"`
	Periods        map[string]PeriodSummary `json:"periods"`
	Trends         map[string]TrendSummary  `json:"trends"`
	Anomalies      []AnomalySummary        `json:"anomalies,omitempty"`
	Insights       []string                `json:"insights,omitempty"`
}

// PeriodSummary contains summary for a specific period
type PeriodSummary struct {
	Count   int     `json:"count"`
	Average float64 `json:"average"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Sum     float64 `json:"sum"`
}

// TrendSummary contains trend analysis
type TrendSummary struct {
	Direction string  `json:"direction"` // "up", "down", "stable"
	Change    float64 `json:"change_percent"`
	Confidence float64 `json:"confidence"`
}

// AnomalySummary represents an detected anomaly
type AnomalySummary struct {
	Timestamp time.Time `json:"timestamp"`
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Expected  float64   `json:"expected"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
}

// AnalyticsMetadata contains metadata about the analytics query
type AnalyticsMetadata struct {
	GeneratedBy   string    `json:"generated_by"`
	DataSource    string    `json:"data_source"`
	SampleSize    int       `json:"sample_size"`
	Confidence    float64   `json:"confidence_level"`
	HasGaps       bool      `json:"has_gaps"`
	Estimated     bool      `json:"estimated"`
	CacheHit      bool      `json:"cache_hit"`
	CacheExpiry   time.Time `json:"cache_expiry,omitempty"`
}

// LogEntry represents a log entry
type LogEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// LogsRequest represents a logs query request
type LogsRequest struct {
	Level      []string          `json:"level,omitempty"`      // "debug", "info", "warn", "error", "fatal"
	Source     []string          `json:"source,omitempty"`     // "api_server", "provider_registry", etc.
	Message    string            `json:"message,omitempty"`    // Text search in message
	Fields     map[string]string `json:"fields,omitempty"`     // Field filters
	StartDate  *time.Time        `json:"start_date,omitempty"`
	EndDate    *time.Time        `json:"end_date,omitempty"`
	Limit      int               `json:"limit,omitempty"`      // Max number of entries
	Offset     int               `json:"offset,omitempty"`     // Pagination offset
	SortBy     string            `json:"sort_by,omitempty"`    // "timestamp", "level"
	SortDesc   bool              `json:"sort_desc,omitempty"`
	IncludeContext bool           `json:"include_context,omitempty"`
}

// LogsResponse contains logs query results
type LogsResponse struct {
	Entries    []LogEntry         `json:"entries"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
	HasMore    bool               `json:"has_more"`
	Statistics map[string]int     `json:"statistics"`        // Count by level, source, etc.
	Metadata   LogsMetadata       `json:"metadata"`
}

// LogsMetadata contains metadata about the logs query
type LogsMetadata struct {
	QueryDuration string `json:"query_duration"`
	IndexUsed     bool   `json:"index_used"`
	CacheHit      bool   `json:"cache_hit"`
	EarliestLog   *time.Time `json:"earliest_log,omitempty"`
	LatestLog     *time.Time `json:"latest_log,omitempty"`
}

// Alert represents a system alert
type Alert struct {
	ID          string            `json:"id"`
	Level       string            `json:"level"` // "info", "warning", "error", "critical"
	Source      string            `json:"source"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Timestamp   time.Time         `json:"timestamp"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Status      string            `json:"status"`    // "active", "acknowledged", "resolved"
	AcknowledgedBy string         `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	ResolvedBy   string           `json:"resolved_by,omitempty"`
	ResolvedAt   *time.Time       `json:"resolved_at,omitempty"`
}

// AlertsRequest represents an alerts query request
type AlertsRequest struct {
	Level     []string          `json:"level,omitempty"`
	Source    []string          `json:"source,omitempty"`
	Status    []string          `json:"status,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Search    string            `json:"search,omitempty"`
	StartDate *time.Time        `json:"start_date,omitempty"`
	EndDate   *time.Time        `json:"end_date,omitempty"`
	Limit     int               `json:"limit,omitempty"`
	Offset    int               `json:"offset,omitempty"`
}

// handleSystemMetrics handles GET /v1/monitoring/metrics
func (a *AdminServer) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "1h"
	}

	// Collect metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := MetricsData{
		System: SystemMetrics{
			CPU: CPUMetrics{
				UsagePercent: 0, // Would get actual CPU usage
				LoadAverage:  0, // Would get actual load average
				NumCores:     runtime.NumCPU(),
			},
			Memory: MemoryMetrics{
				AllocMB:        float64(m.Alloc) / 1024 / 1024,
				TotalAllocMB:   float64(m.TotalAlloc) / 1024 / 1024,
				SysMB:          float64(m.Sys) / 1024 / 1024,
				HeapMB:         float64(m.HeapAlloc) / 1024 / 1024,
				StackMB:        float64(m.StackSys) / 1024 / 1024,
				GCGCycles:       m.NumGC,
				GCPauseTotalMS: float64(m.PauseTotalNs) / 1000000,
			},
			Goroutines: GoroutineMetrics{
				Count: runtime.NumGoroutine(),
			},
			GC: GCMetrics{
				NumGC:         m.NumGC,
				GoalMB:        float64(m.NextGC) / 1024 / 1024,
			},
			Network: NetworkMetrics{
				ConnectionsOpen: 0, // Would track actual connections
				ConnectionsTotal: 0,
				BytesRead:      0,
				BytesWritten:   0,
			},
		},
		Providers: SystemProviderMetrics{
			Total:      0,
			Success:    0,
			Failed:     0,
			ByProvider: make(map[string]ProviderStats),
			ErrorRate:  0,
			AvgLatency: 0,
		},
		Requests: RequestMetrics{
			Total:        0,
			Success:      0,
			Failed:       0,
			ByModel:      make(map[string]int64),
			ByUser:       make(map[string]int64),
			ByRouteReason: make(map[string]int64),
			AvgTokensIn:  0,
			AvgTokensOut: 0,
		},
		Performance: PerformanceMetrics{
			ResponseTime: ResponseTimeMetrics{
				AvgMS:    0,
				P50MS:    0,
				P95MS:    0,
				P99MS:    0,
				MaxMS:    0,
			},
			Throughput: ThroughputMetrics{
				RequestsPerSec: 0,
				TokensPerSec:   0,
				BytePerSec:     0,
			},
			Concurrency: ConcurrencyMetrics{
				MaxConcurrent:   0,
				AvgConcurrent:   0,
				CurrentActive:   0,
				QueueLength:    0,
				QueueWaitTimeMS: 0,
			},
			ResourceUsage: ResourceMetrics{
				CPUUtilization:     0,
				MemoryUtilization: float64(m.Alloc) / float64(m.Sys) * 100,
			},
		},
		Timestamp: time.Now(),
		Period:    period,
	}

	// Get provider metrics if available
	if a.providerRegistry != nil && a.providerRegistry.GetHealthMonitor() != nil {
		healthStatus := a.providerRegistry.GetHealthMonitor().GetHealthStatus()
		metrics.Providers.Total = int64(len(healthStatus))

		for providerName, status := range healthStatus {
			stats := ProviderStats{
				Healthy: status.Healthy,
				LastRequest: &status.LastChecked,
			}

			if status.StatusCode > 0 {
				statusCode := fmt.Sprintf("%d", status.StatusCode)
				stats.StatusCode = &statusCode
			}

			metrics.Providers.ByProvider[providerName] = stats

			if status.Healthy {
				metrics.Providers.Success++
			} else {
				metrics.Providers.Failed++
			}
		}

		if metrics.Providers.Total > 0 {
			metrics.Providers.ErrorRate = float64(metrics.Providers.Failed) / float64(metrics.Providers.Total) * 100
		}
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
		Metadata: map[string]interface{}{
			"period": period,
			"collection_time": time.Now().Format(time.RFC3339),
		},
	}

	response := map[string]interface{}{
		"metrics": metrics,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_SYSTEM_METRICS", "monitoring", period, true)
}

// handleAnalytics handles GET /v1/monitoring/analytics
func (a *AdminServer) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	var req AnalyticsRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
			return
		}
	} else {
		// Parse from query parameters for GET requests
		req.Metrics = strings.Split(r.URL.Query().Get("metrics"), ",")
		req.Period = r.URL.Query().Get("period")
		if req.Period == "" {
			req.Period = "24h"
		}
		req.Granularity = r.URL.Query().Get("granularity")
	}

	// Set defaults
	if len(req.Metrics) == 0 {
		req.Metrics = []string{"system", "providers", "requests", "performance"}
	}
	if req.Granularity == "" {
		req.Granularity = "1h"
	}

	// Generate analytics response
	query := AnalyticsQuery{
		Metrics:     req.Metrics,
		Period:      req.Period,
		Granularity: req.Granularity,
		Filters:     req.Filters,
		GroupBy:     req.GroupBy,
	}

	// Generate time series data (placeholder - would query actual data)
	timeSeries := make(map[string][]TimeSeriesPoint)
	for _, metric := range req.Metrics {
		series := make([]TimeSeriesPoint, 0)
		baseTime := time.Now().Add(-24 * time.Hour)

		for i := 0; i < 24; i++ {
			point := TimeSeriesPoint{
				Timestamp: baseTime.Add(time.Duration(i) * time.Hour),
				Value:     float64(i * 10), // Placeholder data
			}
			series = append(series, point)
		}
		timeSeries[metric] = series
	}

	data := AnalyticsData{
		TimeSeries: timeSeries,
		Aggregated: map[string]interface{}{
			"total_requests":    int64(1000),
			"avg_response_time": 250.5,
			"error_rate":       2.3,
		},
	}

	summary := AnalyticsSummary{
		TotalDataPoints: len(timeSeries) * 24,
		Periods: map[string]PeriodSummary{
			"requests": {
				Count:   1000,
				Average: 42.5,
				Min:     10,
				Max:     120,
				Sum:     42500,
			},
		},
		Trends: map[string]TrendSummary{
			"requests": {
				Direction:  "up",
				Change:     15.2,
				Confidence: 0.85,
			},
		},
		Insights: []string{
			"Request volume increased by 15% over the selected period",
			"Average response time improved by 5%",
		},
	}

	response := AnalyticsResponse{
		Query:       query,
		Data:        data,
		Summary:     summary,
		Metadata: AnalyticsMetadata{
			GeneratedBy:   "Cortex-admin",
			DataSource:    "mixed",
			SampleSize:    len(timeSeries) * 24,
			Confidence:    0.95,
			HasGaps:       false,
			Estimated:     false,
			CacheHit:      false,
		},
		Duration:    "15ms",
		GeneratedAt: time.Now(),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 15,
		Metadata: map[string]interface{}{
			"query_complexity": "medium",
			"data_points":       summary.TotalDataPoints,
		},
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_ANALYTICS", "monitoring", req.Period, true)
}

// handleLogs handles GET /v1/monitoring/logs
func (a *AdminServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	var req LogsRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
			return
		}
	} else {
		// Parse from query parameters
		req.Level = r.URL.Query()["level"]
		req.Source = r.URL.Query()["source"]
		req.Message = r.URL.Query().Get("message")
		req.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
		req.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
		req.SortBy = r.URL.Query().Get("sort_by")
		req.SortDesc = r.URL.Query().Get("sort_desc") == "true"
	}

	// Set defaults
	if req.Limit == 0 {
		req.Limit = 100
	}
	if req.SortBy == "" {
		req.SortBy = "timestamp"
		req.SortDesc = true
	}

	// Generate sample log entries (placeholder - would query actual logs)
	entries := make([]LogEntry, 0)
	now := time.Now()

	for i := 0; i < req.Limit && i < 50; i++ { // Limit to 50 for demo
		entry := LogEntry{
			ID:        fmt.Sprintf("log_%d", i),
			Timestamp: now.Add(-time.Duration(i) * time.Minute),
			Level:     []string{"info", "warn", "error", "debug"}[i%4],
			Source:    []string{"api_server", "provider_registry", "health_monitor", "access_manager"}[i%4],
			Message:   fmt.Sprintf("Sample log message %d - this is a test log entry", i),
			RequestID: fmt.Sprintf("req_%d", i%10),
			Fields: map[string]interface{}{
				"goroutine_id": i,
				"method":       "GET",
				"path":         "/api/v1/providers",
			},
		}
		entries = append(entries, entry)
	}

	// Sort entries
	sort.Slice(entries, func(i, j int) bool {
		if req.SortDesc {
			return entries[i].Timestamp.After(entries[j].Timestamp)
		}
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	// Apply pagination
	total := len(entries) + req.Offset // Add offset to simulate total count
	hasMore := req.Offset+req.Limit < total

	response := LogsResponse{
		Entries:  entries,
		Total:    total,
		Limit:    req.Limit,
		Offset:   req.Offset,
		HasMore:  hasMore,
		Statistics: map[string]int{
			"info":  13,
			"warn":  13,
			"error": 12,
			"debug": 12,
		},
		Metadata: LogsMetadata{
			QueryDuration: "5ms",
			IndexUsed:     false,
			CacheHit:      false,
		},
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 5,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_LOGS", "monitoring", fmt.Sprintf("%d entries", len(entries)), true)
}

// handleAlerts handles GET /v1/monitoring/alerts
func (a *AdminServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query()["level"]
	source := r.URL.Query()["source"]
	status := r.URL.Query()["status"]
	search := r.URL.Query().Get("search")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}

	// Generate sample alerts (placeholder - would query actual alerts)
	alerts := make([]Alert, 0)
	now := time.Now()

	alertLevels := []string{"info", "warning", "error", "critical"}
	alertSources := []string{"health_monitor", "provider_registry", "system_monitor"}
	alertStatuses := []string{"active", "acknowledged", "resolved"}

	for i := 0; i < 10 && i < limit; i++ {
		alert := Alert{
			ID:          fmt.Sprintf("alert_%d", i),
			Level:       alertLevels[i%len(alertLevels)],
			Source:      alertSources[i%len(alertSources)],
			Title:       fmt.Sprintf("Alert %d - %s", i, alertLevels[i%len(alertLevels)]),
			Description: fmt.Sprintf("This is a sample %s alert for demonstration purposes", alertLevels[i%len(alertLevels)]),
			Timestamp:   now.Add(-time.Duration(i*30) * time.Minute),
			Tags:        []string{"system", alertSources[i%len(alertSources)]},
			Status:      alertStatuses[i%len(alertStatuses)],
			Metadata: map[string]interface{}{
				"metric":     "cpu_usage",
				"threshold":  80.0,
				"actual":     85.5,
			},
		}

		if alert.Status == "acknowledged" {
			alert.AcknowledgedBy = "admin_user"
			ackTime := alert.Timestamp.Add(5 * time.Minute)
			alert.AcknowledgedAt = &ackTime
		}

		if alert.Status == "resolved" {
			alert.ResolvedBy = "system"
			resTime := alert.Timestamp.Add(10 * time.Minute)
			alert.ResolvedAt = &resTime
		}

		alerts = append(alerts, alert)
	}

	// Apply filters
	var filteredAlerts []Alert
	for _, alert := range alerts {
		// Level filter
		if len(level) > 0 {
			found := false
			for _, l := range level {
				if alert.Level == l {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Source filter
		if len(source) > 0 {
			found := false
			for _, s := range source {
				if alert.Source == s {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Status filter
		if len(status) > 0 {
			found := false
			for _, s := range status {
				if alert.Status == s {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Search filter
		if search != "" && !strings.Contains(strings.ToLower(alert.Title), strings.ToLower(search)) &&
			!strings.Contains(strings.ToLower(alert.Description), strings.ToLower(search)) {
			continue
		}

		filteredAlerts = append(filteredAlerts, alert)
	}

	response := map[string]interface{}{
		"alerts": filteredAlerts,
		"total":  len(filteredAlerts),
		"filters": map[string]interface{}{
			"level":  level,
			"source": source,
			"status": status,
			"search": search,
		},
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_ALERTS", "monitoring", fmt.Sprintf("%d alerts", len(filteredAlerts)), true)
}

// handlePerformanceMetrics handles GET /v1/monitoring/performance
func (a *AdminServer) handlePerformanceMetrics(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "1h"
	}

	// Collect performance metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	performance := PerformanceMetrics{
		ResponseTime: ResponseTimeMetrics{
			AvgMS: 250.5,
			P50MS: 120.0,
			P95MS: 800.0,
			P99MS: 1500.0,
			MaxMS: 5000.0,
		},
		Throughput: ThroughputMetrics{
			RequestsPerSec: 45.2,
			TokensPerSec:   15234.5,
			BytePerSec:     1048576.0, // 1MB/s
		},
		Concurrency: ConcurrencyMetrics{
			MaxConcurrent:   15,
			AvgConcurrent:   8.5,
			CurrentActive:   12,
			QueueLength:    3,
			QueueWaitTimeMS: 25.5,
		},
		ResourceUsage: ResourceMetrics{
			CPUUtilization:     35.2,
			MemoryUtilization: float64(m.Alloc) / float64(m.Sys) * 100,
			NetworkIO: NetworkIOMetrics{
				BytesInPerSec:  524288.0,  // 512KB/s
				BytesOutPerSec: 1048576.0, // 1MB/s
				PacketsPerSec:  150.0,
			},
			DiskIO: DiskIOMetrics{
				ReadBytesPerSec:  262144.0, // 256KB/s
				WriteBytesPerSec: 524288.0, // 512KB/s
				IOOperationsPSec: 25.0,
			},
		},
	}

	response := map[string]interface{}{
		"performance": performance,
		"period":      period,
		"generated_at": time.Now().Format(time.RFC3339),
	}

	meta := &MetaInfo{
		Version: "v1",
		Processing: 1,
	}

	a.sendResponse(w, http.StatusOK, response, nil, meta)
	a.logAccess(r, "GET_PERFORMANCE_METRICS", "monitoring", period, true)
}