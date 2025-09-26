// file: internal/metrics/metrics.go
// version: 1.0.0
// guid: b1c2d3e4-f5a6-7b8c-9d0e-1f2a3b4c5d6e

package metrics

import (
	"fmt"
	"sync"
	"time"
)

// Metrics defines the interface for application metrics
type Metrics interface {
	// Counter operations
	IncrementCounter(name string, labels map[string]string)
	AddCounter(name string, value float64, labels map[string]string)

	// Gauge operations
	SetGauge(name string, value float64, labels map[string]string)
	AddGauge(name string, value float64, labels map[string]string)

	// Histogram operations
	ObserveHistogram(name string, value float64, labels map[string]string)

	// Timer operations
	StartTimer(name string, labels map[string]string) Timer
}

// Timer represents a timer for measuring durations
type Timer interface {
	Stop()
}

// Config holds metrics configuration
type Config struct {
	Enabled   bool   `yaml:"enabled"`
	Namespace string `yaml:"namespace"`
	Subsystem string `yaml:"subsystem"`
}

// memoryMetrics implements Metrics using in-memory storage
type memoryMetrics struct {
	namespace  string
	subsystem  string
	counters   map[string]*counter
	gauges     map[string]*gauge
	histograms map[string]*histogram
	mu         sync.RWMutex
}

type counter struct {
	value  float64
	labels map[string]string
}

type gauge struct {
	value  float64
	labels map[string]string
}

type histogram struct {
	observations []float64
	labels       map[string]string
}

type timer struct {
	start   time.Time
	metrics Metrics
	name    string
	labels  map[string]string
}

// NewMetrics creates a new metrics instance
func NewMetrics(config *Config) Metrics {
	if config == nil {
		config = &Config{
			Enabled:   true,
			Namespace: "gcommon",
			Subsystem: "",
		}
	}

	return &memoryMetrics{
		namespace:  config.Namespace,
		subsystem:  config.Subsystem,
		counters:   make(map[string]*counter),
		gauges:     make(map[string]*gauge),
		histograms: make(map[string]*histogram),
	}
}

// IncrementCounter increments a counter by 1
func (m *memoryMetrics) IncrementCounter(name string, labels map[string]string) {
	m.AddCounter(name, 1, labels)
}

// AddCounter adds a value to a counter
func (m *memoryMetrics) AddCounter(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getMetricKey(name, labels)
	if c, exists := m.counters[key]; exists {
		c.value += value
	} else {
		m.counters[key] = &counter{
			value:  value,
			labels: labels,
		}
	}
}

// SetGauge sets a gauge value
func (m *memoryMetrics) SetGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getMetricKey(name, labels)
	m.gauges[key] = &gauge{
		value:  value,
		labels: labels,
	}
}

// AddGauge adds a value to a gauge
func (m *memoryMetrics) AddGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getMetricKey(name, labels)
	if g, exists := m.gauges[key]; exists {
		g.value += value
	} else {
		m.gauges[key] = &gauge{
			value:  value,
			labels: labels,
		}
	}
}

// ObserveHistogram records an observation for a histogram
func (m *memoryMetrics) ObserveHistogram(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.getMetricKey(name, labels)
	if h, exists := m.histograms[key]; exists {
		h.observations = append(h.observations, value)
	} else {
		m.histograms[key] = &histogram{
			observations: []float64{value},
			labels:       labels,
		}
	}
}

// StartTimer starts a timer for measuring duration
func (m *memoryMetrics) StartTimer(name string, labels map[string]string) Timer {
	return &timer{
		start:   time.Now(),
		metrics: m,
		name:    name,
		labels:  labels,
	}
}

// Stop stops the timer and records the duration
func (t *timer) Stop() {
	duration := time.Since(t.start).Seconds()
	t.metrics.ObserveHistogram(t.name, duration, t.labels)
}

// getMetricKey generates a unique key for a metric
func (m *memoryMetrics) getMetricKey(name string, labels map[string]string) string {
	key := m.namespace
	if m.subsystem != "" {
		key += "_" + m.subsystem
	}
	key += "_" + name

	// Add labels to key for uniqueness
	for k, v := range labels {
		key += fmt.Sprintf("_%s=%s", k, v)
	}

	return key
}

// GetCounterValue returns the current value of a counter (for testing)
func (m *memoryMetrics) GetCounterValue(name string, labels map[string]string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.getMetricKey(name, labels)
	if c, exists := m.counters[key]; exists {
		return c.value
	}
	return 0
}

// GetGaugeValue returns the current value of a gauge (for testing)
func (m *memoryMetrics) GetGaugeValue(name string, labels map[string]string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.getMetricKey(name, labels)
	if g, exists := m.gauges[key]; exists {
		return g.value
	}
	return 0
}

// GetHistogramObservations returns histogram observations (for testing)
func (m *memoryMetrics) GetHistogramObservations(name string, labels map[string]string) []float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.getMetricKey(name, labels)
	if h, exists := m.histograms[key]; exists {
		// Return a copy to avoid concurrent access issues
		observations := make([]float64, len(h.observations))
		copy(observations, h.observations)
		return observations
	}
	return nil
}

// CommonMetrics provides commonly used metrics
type CommonMetrics struct {
	Metrics
}

// NewCommonMetrics creates metrics with common application metrics
func NewCommonMetrics(config *Config) *CommonMetrics {
	return &CommonMetrics{
		Metrics: NewMetrics(config),
	}
}

// RecordRequest records a request metric
func (c *CommonMetrics) RecordRequest(method string, status string, duration time.Duration) {
	labels := map[string]string{
		"method": method,
		"status": status,
	}

	c.IncrementCounter("requests_total", labels)
	c.ObserveHistogram("request_duration_seconds", duration.Seconds(), labels)
}

// RecordDatabaseOperation records database operation metrics
func (c *CommonMetrics) RecordDatabaseOperation(operation string, table string, duration time.Duration) {
	labels := map[string]string{
		"operation": operation,
		"table":     table,
	}

	c.IncrementCounter("database_operations_total", labels)
	c.ObserveHistogram("database_operation_duration_seconds", duration.Seconds(), labels)
}

// RecordError records error metrics
func (c *CommonMetrics) RecordError(component string, errorType string) {
	labels := map[string]string{
		"component": component,
		"type":      errorType,
	}

	c.IncrementCounter("errors_total", labels)
}

// SetActiveConnections sets the number of active connections
func (c *CommonMetrics) SetActiveConnections(count int) {
	c.SetGauge("active_connections", float64(count), nil)
}
