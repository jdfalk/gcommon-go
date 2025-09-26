package main
// file: services/health/example/main.go
// version: 1.0.0
// guid: c1b2a3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d

package main

import (
	"context"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	healthpb "github.com/jdfalk/gcommon/pkg/healthpb"
	"github.com/jdfalk/gcommon/services/health"
)

// DatabaseHealthChecker is an example implementation of HealthChecker for database
type DatabaseHealthChecker struct {
	// In a real implementation, this would contain database connection
}

func (d *DatabaseHealthChecker) Check(ctx context.Context) error {
	// In a real implementation, ping the database
	// For demo purposes, just simulate a check
	time.Sleep(10 * time.Millisecond)
	return nil
}

func (d *DatabaseHealthChecker) Name() string {
	return "postgresql"
}

// CacheHealthChecker is an example implementation for cache
type CacheHealthChecker struct{}

func (c *CacheHealthChecker) Check(ctx context.Context) error {
	// In a real implementation, ping the cache server
	time.Sleep(5 * time.Millisecond)
	return nil
}

func (c *CacheHealthChecker) Name() string {
	return "redis"
}

func main() {
	// Create health service dependencies
	deps := health.Dependencies{
		Database: &DatabaseHealthChecker{},
		Cache:    &CacheHealthChecker{},
	}

	// Create health service configuration
	config := &health.Config{
		CheckInterval:    15 * time.Second,
		UnhealthyTimeout: 2 * time.Minute,
		EnableDetailed:   true,
	}

	// Create the health service
	healthService := health.NewService(config, deps)

	// Create gRPC server
	server := grpc.NewServer()

	// Register the health service
	healthpb.RegisterHealthServiceServer(server, healthService)

	// Enable reflection for testing with tools like grpcurl
	reflection.Register(server)

	// Listen on port 8080
	lis, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Health service starting on :8080")
	log.Println("Available methods:")
	log.Println("  - health.v1.HealthService/Check")
	log.Println("  - health.v1.HealthService/CheckReadiness")
	log.Println("  - health.v1.HealthService/WatchHealth")
	log.Println()
	log.Println("Test with grpcurl:")
	log.Println("  grpcurl -plaintext localhost:8080 health.v1.HealthService/Check")

	// Start the server
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
