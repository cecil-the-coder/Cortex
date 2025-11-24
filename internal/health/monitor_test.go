package health

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cecil-the-coder/ai-provider-kit/pkg/types"
	"github.com/cecil-the-coder/Cortex/internal/config"
)

// MockHealthProvider implements a mock health check provider
type MockHealthProvider struct {
	name          string
	shouldFail    bool
	failCount     int
	responseTime  time.Duration
	metrics       types.ProviderMetrics
	callCount     int
	mu            sync.Mutex
}

func NewMockHealthProvider(name string) *MockHealthProvider {
	return &MockHealthProvider{
		name:         name,
		shouldFail:   false,
		responseTime: 10 * time.Millisecond,
		metrics: types.ProviderMetrics{
			RequestCount:   0,
			ErrorCount:     0,
			AverageLatency: 0,
		},
	}
}

func (m *MockHealthProvider) HealthCheck(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++

	// Simulate response time
	time.Sleep(m.responseTime)

	if m.shouldFail {
		m.failCount++
		return errors.New("mock health check failure")
	}

	return nil
}

func (m *MockHealthProvider) GetMetrics() types.ProviderMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics := m.metrics
	metrics.RequestCount = int64(m.callCount)
	metrics.ErrorCount = int64(m.failCount)

	if m.callCount > 0 {
		metrics.AverageLatency = m.responseTime
	}

	return metrics
}

func (m *MockHealthProvider) SetShouldFail(shouldFail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
}

func (m *MockHealthProvider) SetResponseTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responseTime = duration
}

func (m *MockHealthProvider) GetCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *MockHealthProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
	m.failCount = 0
	m.shouldFail = false
}

// ============================================================================
// Basic Health Monitor Tests
// ============================================================================

func TestHealthMonitorCreation(t *testing.T) {
	hm := NewHealthMonitor(5*time.Second, 1*time.Second, 3)

	if hm == nil {
		t.Fatal("Health monitor should not be nil")
	}

	if hm.checkInterval != 5*time.Second {
		t.Errorf("Expected check interval 5s, got %v", hm.checkInterval)
	}

	if hm.timeout != 1*time.Second {
		t.Errorf("Expected timeout 1s, got %v", hm.timeout)
	}

	if hm.alertThreshold != 3 {
		t.Errorf("Expected alert threshold 3, got %d", hm.alertThreshold)
	}

	if hm.IsEnabled() {
		t.Error("Health monitor should not be enabled initially")
	}
}

func TestAddProvider(t *testing.T) {
	hm := NewHealthMonitor(1*time.Second, 100*time.Millisecond, 2)

	// Create mock provider and config
	mockProvider := NewMockHealthProvider("test-provider")
	providerConfig := &config.Provider{
		Name:    "test-provider",
		APIKEY:  "test-key",
		Models:  []string{"gpt-4"},
		BaseURL: "https://api.test.com",
	}

	// Add provider
	err := hm.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Try to add same provider again (should fail)
	err = hm.AddProvider("test-provider", mockProvider, providerConfig)
	if err == nil {
		t.Error("Expected error when adding duplicate provider")
	}

	// Verify provider was added
	status, err := hm.GetProviderHealthStatus("test-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if status.ProviderName != "test-provider" {
		t.Errorf("Expected provider name 'test-provider', got '%s'", status.ProviderName)
	}
}

func TestRemoveProvider(t *testing.T) {
	hm := NewHealthMonitor(1*time.Second, 100*time.Millisecond, 2)

	// Add provider
	mockProvider := NewMockHealthProvider("test-provider")
	providerConfig := &config.Provider{
		Name:   "test-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("test-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Remove provider
	err = hm.RemoveProvider("test-provider")
	if err != nil {
		t.Fatalf("Failed to remove provider: %v", err)
	}

	// Try to get status for removed provider (should fail)
	_, err = hm.GetProviderHealthStatus("test-provider")
	if err == nil {
		t.Error("Expected error when getting status for removed provider")
	}

	// Try to remove non-existent provider (should fail)
	err = hm.RemoveProvider("non-existent")
	if err == nil {
		t.Error("Expected error when removing non-existent provider")
	}
}

func TestHealthCheckPassing(t *testing.T) {
	hm := NewHealthMonitor(500*time.Millisecond, 100*time.Millisecond, 2)

	// Add healthy provider
	mockProvider := NewMockHealthProvider("healthy-provider")
	providerConfig := &config.Provider{
		Name:   "healthy-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("healthy-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for at least one health check
	time.Sleep(600 * time.Millisecond)

	// Check status
	status, err := hm.GetProviderHealthStatus("healthy-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if !status.Healthy {
		t.Error("Provider should be healthy")
	}

	if status.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", status.StatusCode)
	}

	if mockProvider.GetCallCount() == 0 {
		t.Error("Health check should have been called")
	}
}

func TestHealthCheckFailing(t *testing.T) {
	hm := NewHealthMonitor(200*time.Millisecond, 100*time.Millisecond, 2)

	// Add failing provider
	mockProvider := NewMockHealthProvider("failing-provider")
	mockProvider.SetShouldFail(true)

	providerConfig := &config.Provider{
		Name:   "failing-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("failing-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for multiple health checks to trigger alerts
	time.Sleep(500 * time.Millisecond)

	// Check status
	status, err := hm.GetProviderHealthStatus("failing-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if status.Healthy {
		t.Error("Provider should be unhealthy")
	}

	if status.StatusCode != 503 {
		t.Errorf("Expected status code 503, got %d", status.StatusCode)
	}

	if status.ConsecutiveFails < 2 {
		t.Errorf("Expected at least 2 consecutive failures, got %d", status.ConsecutiveFails)
	}

	if len(status.Alerts) == 0 {
		t.Error("Expected alerts to be generated")
	}
}

func TestProviderRecovery(t *testing.T) {
	hm := NewHealthMonitor(200*time.Millisecond, 100*time.Millisecond, 2)

	// Add provider that initially fails then recovers
	mockProvider := NewMockHealthProvider("recovering-provider")
	mockProvider.SetShouldFail(true)

	providerConfig := &config.Provider{
		Name:   "recovering-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("recovering-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for initial failures
	time.Sleep(500 * time.Millisecond)

	// Check that provider is unhealthy
	status, err := hm.GetProviderHealthStatus("recovering-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if status.Healthy {
		t.Error("Provider should be unhealthy initially")
	}

	// Make provider healthy again
	mockProvider.SetShouldFail(false)

	// Wait for recovery
	time.Sleep(500 * time.Millisecond)

	// Check that provider recovered
	status, err = hm.GetProviderHealthStatus("recovering-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if !status.Healthy {
		t.Error("Provider should have recovered")
	}

	if status.ConsecutiveFails != 0 {
		t.Errorf("Expected 0 consecutive failures after recovery, got %d", status.ConsecutiveFails)
	}
}

func TestGetHealthStatus(t *testing.T) {
	hm := NewHealthMonitor(1*time.Second, 100*time.Millisecond, 2)

	// Add multiple providers
	providers := []string{"provider1", "provider2", "provider3"}

	for _, name := range providers {
		mockProvider := NewMockHealthProvider(name)
		if name == "provider2" {
			mockProvider.SetShouldFail(true)
		}

		providerConfig := &config.Provider{
			Name:   name,
			APIKEY: "test-key",
			Models: []string{"gpt-4"},
		}

		err := hm.AddProvider(name, mockProvider, providerConfig)
		if err != nil {
			t.Fatalf("Failed to add provider %s: %v", name, err)
		}
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for health checks
	time.Sleep(300 * time.Millisecond)

	// Get all status
	allStatus := hm.GetHealthStatus()
	if len(allStatus) != 3 {
		t.Errorf("Expected 3 providers in status, got %d", len(allStatus))
	}

	// Verify healthy providers
	healthy := hm.GetHealthyProviders()
	if len(healthy) != 2 {
		t.Errorf("Expected 2 healthy providers, got %d", len(healthy))
	}

	// Verify unhealthy providers
	unhealthy := hm.GetUnhealthyProviders()
	if len(unhealthy) != 1 {
		t.Errorf("Expected 1 unhealthy provider, got %d", len(unhealthy))
	}
}

func TestManualHealthCheck(t *testing.T) {
	hm := NewHealthMonitor(1*time.Second, 100*time.Millisecond, 2)

	// Add provider
	mockProvider := NewMockHealthProvider("manual-provider")
	providerConfig := &config.Provider{
		Name:   "manual-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("manual-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Don't start monitoring - test manual check

	// Trigger manual health check
	err = hm.TriggerManualHealthCheck("manual-provider")
	if err != nil {
		t.Fatalf("Failed to trigger manual health check: %v", err)
	}

	// Verify check was called
	if mockProvider.GetCallCount() == 0 {
		t.Error("Manual health check should have been called")
	}

	// Try manual check on non-existent provider
	err = hm.TriggerManualHealthCheck("non-existent")
	if err == nil {
		t.Error("Expected error when triggering manual health check on non-existent provider")
	}
}

func TestStatusChangeCallbacks(t *testing.T) {
	hm := NewHealthMonitor(200*time.Millisecond, 100*time.Millisecond, 2)

	// Track callback calls
	callbackCalls := make(map[string][]string)
	var callbackMu sync.Mutex

	// Add callback
	hm.AddStatusChangeCallback(func(providerName string, oldStatus, newStatus *ProviderHealthStatus) {
		callbackMu.Lock()
		defer callbackMu.Unlock()

		oldState := "healthy"
		if !oldStatus.Healthy {
			oldState = "unhealthy"
		}

		newState := "healthy"
		if !newStatus.Healthy {
			newState = "unhealthy"
		}

		callbackCalls[providerName] = append(callbackCalls[providerName],
			fmt.Sprintf("%s->%s", oldState, newState))
	})

	// Add provider that will fail then recover
	mockProvider := NewMockHealthProvider("callback-provider")
	mockProvider.SetShouldFail(true)

	providerConfig := &config.Provider{
		Name:   "callback-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("callback-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for initial failure
	time.Sleep(300 * time.Millisecond)

	// Make provider recover
	mockProvider.SetShouldFail(false)

	// Wait for recovery
	time.Sleep(300 * time.Millisecond)

	// Check callbacks
	callbackMu.Lock()
	defer callbackMu.Unlock()

	calls, exists := callbackCalls["callback-provider"]
	if !exists {
		t.Error("Expected callbacks to be triggered")
	}

	if len(calls) < 2 {
		t.Errorf("Expected at least 2 callbacks, got %d: %v", len(calls), calls)
	}
}

func TestProviderMetrics(t *testing.T) {
	hm := NewHealthMonitor(200*time.Millisecond, 100*time.Millisecond, 2)

	// Add provider with controlled response time
	mockProvider := NewMockHealthProvider("metrics-provider")
	mockProvider.SetResponseTime(50 * time.Millisecond)

	providerConfig := &config.Provider{
		Name:   "metrics-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("metrics-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for several checks
	time.Sleep(500 * time.Millisecond)

	// Get provider metrics
	metrics, err := hm.GetProviderMetrics("metrics-provider")
	if err != nil {
		t.Fatalf("Failed to get provider metrics: %v", err)
	}

	if metrics.RequestCount == 0 {
		t.Error("Expected request count > 0")
	}

	if metrics.AverageLatency <= 0 {
		t.Error("Expected average latency > 0")
	}

	// Get all metrics
	allMetrics := hm.GetAllMetrics()
	if len(allMetrics) != 1 {
		t.Errorf("Expected 1 provider in all metrics, got %d", len(allMetrics))
	}
}

func TestMonitoringStats(t *testing.T) {
	hm := NewHealthMonitor(300*time.Millisecond, 100*time.Millisecond, 3)

	// Add mix of healthy and unhealthy providers
	providers := []string{"healthy1", "healthy2", "unhealthy"}

	for i, name := range providers {
		mockProvider := NewMockHealthProvider(name)
		if i == 2 { // Make the third provider unhealthy
			mockProvider.SetShouldFail(true)
		}

		providerConfig := &config.Provider{
			Name:   name,
			APIKEY: "test-key",
			Models: []string{"gpt-4"},
		}

		err := hm.AddProvider(name, mockProvider, providerConfig)
		if err != nil {
			t.Fatalf("Failed to add provider %s: %v", name, err)
		}
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for health checks and alerts
	time.Sleep(800 * time.Millisecond)

	// Get monitoring stats
	stats := hm.GetMonitoringStats()

	// Verify stats structure
	if totalProviders, ok := stats["total_providers"].(int); !ok || totalProviders != 3 {
		t.Errorf("Expected total_providers=3, got %v", stats["total_providers"])
	}

	if healthyProviders, ok := stats["healthy_providers"].(int); !ok || healthyProviders != 2 {
		t.Errorf("Expected healthy_providers=2, got %v", stats["healthy_providers"])
	}

	if unhealthyProviders, ok := stats["unhealthy_providers"].(int); !ok || unhealthyProviders != 1 {
		t.Errorf("Expected unhealthy_providers=1, got %v", stats["unhealthy_providers"])
	}

	if monitoringEnabled, ok := stats["monitoring_enabled"].(bool); !ok || !monitoringEnabled {
		t.Error("Expected monitoring_enabled=true")
	}

	if totalAlerts, ok := stats["total_alerts"].(int); !ok || totalAlerts < 1 {
		t.Errorf("Expected some alerts, got %v", stats["total_alerts"])
	}
}

func TestHealthMonitorLifecycle(t *testing.T) {
	hm := NewHealthMonitor(100*time.Millisecond, 50*time.Millisecond, 2)

	// Verify initial state
	if hm.IsEnabled() {
		t.Error("Monitor should be disabled initially")
	}

	// Add provider
	mockProvider := NewMockHealthProvider("lifecycle-provider")
	providerConfig := &config.Provider{
		Name:   "lifecycle-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("lifecycle-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()

	if !hm.IsEnabled() {
		t.Error("Monitor should be enabled after start")
	}

	// Wait for some checks
	time.Sleep(200 * time.Millisecond)

	// Stop monitoring
	hm.Stop()

	if hm.IsEnabled() {
		t.Error("Monitor should be disabled after stop")
	}

	// Try to start again (should work)
	hm.Start()

	if !hm.IsEnabled() {
		t.Error("Monitor should be enabled after restart")
	}

	hm.Stop()
}

func TestAlertManagement(t *testing.T) {
	hm := NewHealthMonitor(200*time.Millisecond, 100*time.Millisecond, 1) // Low threshold for testing

	// Add failing provider
	mockProvider := NewMockHealthProvider("alert-provider")
	mockProvider.SetShouldFail(true)

	providerConfig := &config.Provider{
		Name:   "alert-provider",
		APIKEY: "test-key",
		Models: []string{"gpt-4"},
	}

	err := hm.AddProvider("alert-provider", mockProvider, providerConfig)
	if err != nil {
		t.Fatalf("Failed to add provider: %v", err)
	}

	// Start monitoring
	hm.Start()
	defer hm.Stop()

	// Wait for alerts to be generated
	time.Sleep(400 * time.Millisecond)

	// Check alerts
	status, err := hm.GetProviderHealthStatus("alert-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	if len(status.Alerts) == 0 {
		t.Error("Expected alerts to be generated")
	}

	// Verify alert structure
	alert := status.Alerts[0]
	if alert.Level != "error" {
		t.Errorf("Expected alert level 'error', got '%s'", alert.Level)
	}

	if alert.Resolved {
		t.Error("Alert should not be resolved initially")
	}

	if alert.Timestamp.IsZero() {
		t.Error("Alert should have a timestamp")
	}

	// Make provider recover to test alert resolution
	mockProvider.SetShouldFail(false)
	time.Sleep(400 * time.Millisecond)

	// Check that previous alerts were resolved
	status, err = hm.GetProviderHealthStatus("alert-provider")
	if err != nil {
		t.Fatalf("Failed to get provider status: %v", err)
	}

	resolvedCount := 0
	for _, alert := range status.Alerts {
		if alert.Resolved {
			resolvedCount++
			if alert.ResolvedAt == nil {
				t.Error("Resolved alert should have resolved_at timestamp")
			}
		}
	}

	if resolvedCount == 0 {
		t.Error("Expected some alerts to be resolved")
	}
}