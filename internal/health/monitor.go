package health

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// HealthMonitor provides comprehensive health monitoring for AI providers
// It leverages the HealthCheckProvider interface from ai-provider-kit
type HealthMonitor struct {
	providers           map[string]types.HealthCheckProvider
	providerConfigs     map[string]*config.Provider
	healthStatus        map[string]*ProviderHealthStatus
	metrics             map[string]*types.ProviderMetrics
	mu                  sync.RWMutex
	checkInterval       time.Duration
	timeout             time.Duration
	alertThreshold      int
	enabled             bool
	stopChan            chan struct{}
	stopOnce            sync.Once
	statusChangeCallbacks []StatusChangeCallback
}

// ProviderHealthStatus extends the basic health status with additional monitoring data
type ProviderHealthStatus struct {
	types.HealthStatus
	ProviderName    string                    `json:"provider_name"`
	ProviderType    types.ProviderType        `json:"provider_type"`
	ConsecutiveFails int                       `json:"consecutive_fails"`
	LastSuccess     time.Time                 `json:"last_success"`
	Alerts          []HealthAlert             `json:"alerts"`
	Metrics         *types.ProviderMetrics    `json:"metrics"`
}

// HealthAlert represents a health-related alert
type HealthAlert struct {
	Level       string    `json:"level"`       // "info", "warning", "error", "critical"
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// StatusChangeCallback is called when a provider's health status changes
type StatusChangeCallback func(providerName string, oldStatus, newStatus *ProviderHealthStatus)

// NewHealthMonitor creates a new health monitoring service
func NewHealthMonitor(checkInterval, timeout time.Duration, alertThreshold int) *HealthMonitor {
	return &HealthMonitor{
		providers:              make(map[string]types.HealthCheckProvider),
		providerConfigs:        make(map[string]*config.Provider),
		healthStatus:           make(map[string]*ProviderHealthStatus),
		metrics:                make(map[string]*types.ProviderMetrics),
		checkInterval:          checkInterval,
		timeout:                timeout,
		alertThreshold:         alertThreshold,
		enabled:                false,
		stopChan:               make(chan struct{}),
		stopOnce:               sync.Once{},
		statusChangeCallbacks:  make([]StatusChangeCallback, 0),
	}
}

// AddProvider adds a provider to health monitoring
func (hm *HealthMonitor) AddProvider(name string, provider types.HealthCheckProvider, config *config.Provider) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if _, exists := hm.providers[name]; exists {
		return fmt.Errorf("provider %s is already being monitored", name)
	}

	hm.providers[name] = provider
	hm.providerConfigs[name] = config

	// Initialize health status
	hm.healthStatus[name] = &ProviderHealthStatus{
		HealthStatus: types.HealthStatus{
			Healthy:     true,
			LastChecked: time.Now(),
			Message:     "Initial status - not yet checked",
		},
		ProviderName:    name,
		ProviderType:    getProviderType(provider),
		ConsecutiveFails: 0,
		LastSuccess:     time.Now(),
		Alerts:          make([]HealthAlert, 0),
		Metrics:         &types.ProviderMetrics{},
	}

	// Initialize metrics from provider if available
	if metricsProvider, ok := provider.(interface{ GetMetrics() types.ProviderMetrics }); ok {
		metrics := metricsProvider.GetMetrics()
		hm.metrics[name] = &metrics
	}

	log.Printf("Added provider %s to health monitoring", name)
	return nil
}

// RemoveProvider removes a provider from health monitoring
func (hm *HealthMonitor) RemoveProvider(name string) error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if _, exists := hm.providers[name]; !exists {
		return fmt.Errorf("provider %s is not being monitored", name)
	}

	delete(hm.providers, name)
	delete(hm.providerConfigs, name)
	delete(hm.healthStatus, name)
	delete(hm.metrics, name)

	log.Printf("Removed provider %s from health monitoring", name)
	return nil
}

// Start begins the health monitoring loop
func (hm *HealthMonitor) Start() {
	hm.mu.Lock()
	if hm.enabled {
		hm.mu.Unlock()
		return
	}
	hm.enabled = true
	// Create a new stop channel if the old one was closed
	hm.stopChan = make(chan struct{})
	hm.stopOnce = sync.Once{}
	hm.mu.Unlock()

	log.Printf("Starting health monitoring with %v check interval", hm.checkInterval)

	go hm.monitorLoop()
}

// Stop stops the health monitoring loop
func (hm *HealthMonitor) Stop() {
	hm.mu.Lock()
	if !hm.enabled {
		hm.mu.Unlock()
		return
	}
	hm.enabled = false
	hm.mu.Unlock()

	hm.stopOnce.Do(func() {
		close(hm.stopChan)
		log.Println("Health monitoring stopped")
	})
}

// monitorLoop runs the periodic health checks
func (hm *HealthMonitor) monitorLoop() {
	ticker := time.NewTicker(hm.checkInterval)
	defer ticker.Stop()

	// Perform initial check
	hm.performHealthChecks()

	for {
		select {
		case <-ticker.C:
			hm.performHealthChecks()
		case <-hm.stopChan:
			return
		}
	}
}

// performHealthChecks checks the health of all registered providers
func (hm *HealthMonitor) performHealthChecks() {
	hm.mu.RLock()
	providers := make(map[string]types.HealthCheckProvider)
	for name, provider := range hm.providers {
		providers[name] = provider
	}
	hm.mu.RUnlock()

	var wg sync.WaitGroup
	for name, provider := range providers {
		wg.Add(1)
		go func(name string, provider types.HealthCheckProvider) {
			defer wg.Done()
			hm.checkProviderHealth(name, provider)
		}(name, provider)
	}
	wg.Wait()
}

// checkProviderHealth checks the health of a single provider
func (hm *HealthMonitor) checkProviderHealth(name string, provider types.HealthCheckProvider) {
	startTime := time.Now()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), hm.timeout)
	defer cancel()

	// Perform health check
	err := provider.HealthCheck(ctx)
	responseTime := time.Since(startTime).Seconds()

	hm.mu.Lock()
	defer hm.mu.Unlock()

	status, exists := hm.healthStatus[name]
	if !exists {
		return
	}

	// Store old status for callback comparison
	oldStatus := *status

	// Update health status
	status.LastChecked = time.Now()
	status.ResponseTime = responseTime

	if err != nil {
		// Health check failed
		status.Healthy = false
		status.Message = fmt.Sprintf("Health check failed: %v", err)
		status.ConsecutiveFails++
		status.StatusCode = 503 // Service Unavailable

		// Add alert if threshold reached
		if status.ConsecutiveFails >= hm.alertThreshold {
			hm.addAlert(name, "error",
				fmt.Sprintf("Provider %s has failed %d consecutive health checks", name, status.ConsecutiveFails))
		}

		log.Printf("Health check failed for provider %s: %v", name, err)
	} else {
		// Health check succeeded
		wasUnhealthy := !status.Healthy
		status.Healthy = true
		status.Message = "Health check passed"
		status.ConsecutiveFails = 0
		status.LastSuccess = time.Now()
		status.StatusCode = 200

		// Resolve any previous failure alerts
		if wasUnhealthy {
			hm.resolveAlerts(name)
			hm.addAlert(name, "info", fmt.Sprintf("Provider %s is now healthy", name))
		}

		log.Printf("Health check passed for provider %s (%.3fs)", name, responseTime)
	}

	// Update metrics if provider supports it
	if metricsProvider, ok := provider.(interface{ GetMetrics() types.ProviderMetrics }); ok {
		metrics := metricsProvider.GetMetrics()
		hm.metrics[name] = &metrics
		status.Metrics = hm.metrics[name]
	}

	// Trigger status change callbacks if status changed
	if hm.statusChanged(&oldStatus, status) {
		hm.triggerStatusChangeCallbacks(name, &oldStatus, status)
	}
}

// GetHealthStatus returns the current health status of all providers
func (hm *HealthMonitor) GetHealthStatus() map[string]*ProviderHealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	status := make(map[string]*ProviderHealthStatus)
	for name, s := range hm.healthStatus {
		// Return a copy to avoid external modification
		statusCopy := *s
		status[name] = &statusCopy
	}
	return status
}

// GetProviderHealthStatus returns the health status of a specific provider
func (hm *HealthMonitor) GetProviderHealthStatus(name string) (*ProviderHealthStatus, error) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	status, exists := hm.healthStatus[name]
	if !exists {
		return nil, fmt.Errorf("provider %s is not being monitored", name)
	}

	// Return a copy to avoid external modification
	statusCopy := *status
	return &statusCopy, nil
}

// GetHealthyProviders returns a list of currently healthy providers
func (hm *HealthMonitor) GetHealthyProviders() []string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var healthy []string
	for name, status := range hm.healthStatus {
		if status.Healthy {
			healthy = append(healthy, name)
		}
	}
	return healthy
}

// GetUnhealthyProviders returns a list of currently unhealthy providers
func (hm *HealthMonitor) GetUnhealthyProviders() []string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	var unhealthy []string
	for name, status := range hm.healthStatus {
		if !status.Healthy {
			unhealthy = append(unhealthy, name)
		}
	}
	return unhealthy
}

// TriggerManualHealthCheck manually triggers a health check for a specific provider
func (hm *HealthMonitor) TriggerManualHealthCheck(name string) error {
	hm.mu.RLock()
	provider, exists := hm.providers[name]
	hm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("provider %s is not being monitored", name)
	}

	hm.checkProviderHealth(name, provider)
	return nil
}

// GetProviderMetrics returns metrics for a specific provider
func (hm *HealthMonitor) GetProviderMetrics(name string) (*types.ProviderMetrics, error) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	metrics, exists := hm.metrics[name]
	if !exists {
		return nil, fmt.Errorf("no metrics available for provider %s", name)
	}

	// Return a copy to avoid external modification
	metricsCopy := *metrics
	return &metricsCopy, nil
}

// GetAllMetrics returns metrics for all providers
func (hm *HealthMonitor) GetAllMetrics() map[string]*types.ProviderMetrics {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	metrics := make(map[string]*types.ProviderMetrics)
	for name, m := range hm.metrics {
		metricsCopy := *m
		metrics[name] = &metricsCopy
	}
	return metrics
}

// AddStatusChangeCallback adds a callback that will be called when a provider's status changes
func (hm *HealthMonitor) AddStatusChangeCallback(callback StatusChangeCallback) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.statusChangeCallbacks = append(hm.statusChangeCallbacks, callback)
}

// addAlert adds a new alert for a provider
func (hm *HealthMonitor) addAlert(providerName, level, message string) {
	status, exists := hm.healthStatus[providerName]
	if !exists {
		return
	}

	alert := HealthAlert{
		Level:     level,
		Message:   message,
		Timestamp: time.Now(),
		Resolved:  false,
	}

	status.Alerts = append(status.Alerts, alert)

	// Keep only the last 100 alerts to prevent memory leaks
	if len(status.Alerts) > 100 {
		status.Alerts = status.Alerts[len(status.Alerts)-100:]
	}

	log.Printf("ALERT [%s] for provider %s: %s", level, providerName, message)
}

// resolveAlerts marks all unresolved alerts for a provider as resolved
func (hm *HealthMonitor) resolveAlerts(providerName string) {
	status, exists := hm.healthStatus[providerName]
	if !exists {
		return
	}

	now := time.Now()
	for i := range status.Alerts {
		if !status.Alerts[i].Resolved {
			status.Alerts[i].Resolved = true
			status.Alerts[i].ResolvedAt = &now
		}
	}
}

// statusChanged checks if the health status has significantly changed
func (hm *HealthMonitor) statusChanged(oldStatus, newStatus *ProviderHealthStatus) bool {
	return oldStatus.Healthy != newStatus.Healthy
}

// triggerStatusChangeCallbacks calls all registered status change callbacks
func (hm *HealthMonitor) triggerStatusChangeCallbacks(providerName string, oldStatus, newStatus *ProviderHealthStatus) {
	for _, callback := range hm.statusChangeCallbacks {
		go func(cb StatusChangeCallback) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Status change callback panicked: %v", r)
				}
			}()
			cb(providerName, oldStatus, newStatus)
		}(callback)
	}
}

// getProviderType attempts to determine the provider type from the provider interface
func getProviderType(provider types.HealthCheckProvider) types.ProviderType {
	// Try to get type from CoreProvider interface if available
	if coreProvider, ok := provider.(types.CoreProvider); ok {
		return coreProvider.Type()
	}

	// Default to unknown
	return ""
}

// IsEnabled returns whether health monitoring is currently enabled
func (hm *HealthMonitor) IsEnabled() bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.enabled
}

// GetMonitoringStats returns statistics about the health monitoring itself
func (hm *HealthMonitor) GetMonitoringStats() map[string]interface{} {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	totalProviders := len(hm.providers)
	healthyCount := 0
	totalAlerts := 0

	for _, status := range hm.healthStatus {
		if status.Healthy {
			healthyCount++
		}
		totalAlerts += len(status.Alerts)
	}

	return map[string]interface{}{
		"total_providers":     totalProviders,
		"healthy_providers":   healthyCount,
		"unhealthy_providers": totalProviders - healthyCount,
		"total_alerts":        totalAlerts,
		"monitoring_enabled":  hm.enabled,
		"check_interval":      hm.checkInterval.String(),
		"timeout":             hm.timeout.String(),
		"alert_threshold":     hm.alertThreshold,
	}
}