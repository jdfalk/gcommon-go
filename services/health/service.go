package health
// file: services/health/service.go
// version: 1.0.0
// guid: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d

package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	healthpb "github.com/jdfalk/gcommon/pkg/healthpb"
)

// Service implements the health service with comprehensive health checking
type Service struct {
	healthpb.UnimplementedHealthServiceServer

	mu sync.RWMutex

	// Service status tracking
	status        healthpb.HealthStatus
	startTime     time.Time
	lastCheck     time.Time

	// Dependencies for health checking
	dependencies  map[string]HealthChecker

	// Configuration
	config        *Config
}

// HealthChecker defines the interface for checking dependency health
type HealthChecker interface {
	Check(ctx context.Context) error
	Name() string
}

// Config holds the health service configuration
type Config struct {
	CheckInterval    time.Duration `yaml:"check_interval" default:"30s"`
	UnhealthyTimeout time.Duration `yaml:"unhealthy_timeout" default:"5m"`
	EnableDetailed   bool          `yaml:"enable_detailed" default:"true"`
}

// Dependencies holds all service dependencies
type Dependencies struct {
	Database  HealthChecker
	Cache     HealthChecker
	Queue     HealthChecker
	External  map[string]HealthChecker
}

// NewService creates a new health service with the given dependencies
func NewService(config *Config, deps Dependencies) *Service {
	if config == nil {
		config = &Config{
			CheckInterval:    30 * time.Second,
			UnhealthyTimeout: 5 * time.Minute,
			EnableDetailed:   true,
		}
	}

	service := &Service{
		status:       healthpb.HealthStatus_HEALTH_STATUS_HEALTHY,
		startTime:    time.Now(),
		lastCheck:    time.Now(),
		dependencies: make(map[string]HealthChecker),
		config:       config,
	}

	// Register core dependencies
	if deps.Database != nil {
		service.dependencies["database"] = deps.Database
	}
	if deps.Cache != nil {
		service.dependencies["cache"] = deps.Cache
	}
	if deps.Queue != nil {
		service.dependencies["queue"] = deps.Queue
	}

	// Register external dependencies
	for name, checker := range deps.External {
		service.dependencies[name] = checker
	}

	// Start background health monitoring
	go service.backgroundHealthCheck()

	return service
}

// Check implements the HealthService.Check method
func (s *Service) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	s.mu.RLock()
	currentStatus := s.status
	lastCheck := s.lastCheck
	s.mu.RUnlock()

	response := &healthpb.HealthCheckResponse{
		Status:    currentStatus,
		Timestamp: lastCheck.Unix(),
		// Add other required fields from the protobuf definition
	}

	// TODO: Add detailed dependency status if requested in the protobuf

	return response, nil
}

// CheckReadiness implements the HealthService.CheckReadiness method
func (s *Service) CheckReadiness(ctx context.Context, req *healthpb.ReadinessCheckRequest) (*healthpb.ReadinessCheckResponse, error) {
	// Check if all critical dependencies are healthy
	for name, checker := range s.dependencies {
		if err := checker.Check(ctx); err != nil {
			return &healthpb.ReadinessCheckResponse{
				Ready:   false,
				Message: fmt.Sprintf("Dependency %s is not ready: %v", name, err),
			}, nil
		}
	}

	return &healthpb.ReadinessCheckResponse{
		Ready:   true,
		Message: "Service is ready",
	}, nil
}

// WatchHealth implements the HealthService.WatchHealth method for streaming health updates
func (s *Service) WatchHealth(req *healthpb.WatchHealthRequest, stream grpc.ServerStreamingServer[*healthpb.WatchHealthResponse]) error {
	ticker := time.NewTicker(30 * time.Second) // Default interval
	defer ticker.Stop()

	ctx := stream.Context()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.mu.RLock()
			currentStatus := s.status
			lastCheck := s.lastCheck
			s.mu.RUnlock()

			response := &healthpb.WatchHealthResponse{
				Status:    currentStatus,
				Timestamp: lastCheck.Unix(),
			}

			if err := stream.Send(response); err != nil {
				return err
			}
		}
	}
}

// backgroundHealthCheck runs continuous health monitoring
func (s *Service) backgroundHealthCheck() {
	ticker := time.NewTicker(s.config.CheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.performHealthCheck()
	}
}

// performHealthCheck checks all dependencies and updates service status
func (s *Service) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	allHealthy := true

	for name, checker := range s.dependencies {
		if err := checker.Check(ctx); err != nil {
			// Log the error (in a real implementation, use structured logging)
			fmt.Printf("Health check failed for %s: %v\n", name, err)
			allHealthy = false
		}
	}

	s.mu.Lock()
	if allHealthy {
		s.status = healthpb.HealthStatus_HEALTH_STATUS_HEALTHY
	} else {
		s.status = healthpb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	}
	s.lastCheck = time.Now()
	s.mu.Unlock()
}

// Shutdown gracefully shuts down the health service
func (s *Service) Shutdown() {
	s.mu.Lock()
	s.status = healthpb.HealthStatus_HEALTH_STATUS_UNHEALTHY
	s.mu.Unlock()
}

// AddDependency adds a new dependency to monitor
func (s *Service) AddDependency(name string, checker HealthChecker) {
	s.mu.Lock()
	s.dependencies[name] = checker
	s.mu.Unlock()
}

// RemoveDependency removes a dependency from monitoring
func (s *Service) RemoveDependency(name string) {
	s.mu.Lock()
	delete(s.dependencies, name)
	s.mu.Unlock()
}
