// file: internal/middleware/middleware.go
// version: 1.0.0
// guid: a1b2c3d4-e5f6-7890-abcd-ef1234567890

package middleware

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Logger interface for middleware logging
type Logger interface {
	Info(ctx context.Context, msg string, args ...interface{})
	Error(ctx context.Context, msg string, args ...interface{})
}

// RequestLoggingInterceptor logs incoming requests
func RequestLoggingInterceptor(logger Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Extract metadata
		md, _ := metadata.FromIncomingContext(ctx)

		// Add request ID to context
		requestID := generateRequestID()
		ctx = context.WithValue(ctx, "request_id", requestID)

		// Log request start
		logger.Info(ctx, "Request started",
			"method", info.FullMethod,
			"request_id", requestID,
			"metadata", md,
		)

		// Call the handler
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start)

		// Log request completion
		if err != nil {
			logger.Error(ctx, "Request completed with error",
				"method", info.FullMethod,
				"request_id", requestID,
				"duration", duration,
				"error", err,
			)
		} else {
			logger.Info(ctx, "Request completed successfully",
				"method", info.FullMethod,
				"request_id", requestID,
				"duration", duration,
			)
		}

		return resp, err
	}
}

// RequestLoggingStreamInterceptor logs streaming requests
func RequestLoggingStreamInterceptor(logger Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		ctx := stream.Context()

		// Extract metadata
		md, _ := metadata.FromIncomingContext(ctx)

		// Add request ID to context
		requestID := generateRequestID()

		// Log stream start
		logger.Info(ctx, "Stream started",
			"method", info.FullMethod,
			"request_id", requestID,
			"metadata", md,
		)

		// Create wrapped stream with new context
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          context.WithValue(ctx, "request_id", requestID),
		}

		// Call the handler
		err := handler(srv, wrappedStream)

		// Calculate duration
		duration := time.Since(start)

		// Log stream completion
		if err != nil {
			logger.Error(ctx, "Stream completed with error",
				"method", info.FullMethod,
				"request_id", requestID,
				"duration", duration,
				"error", err,
			)
		} else {
			logger.Info(ctx, "Stream completed successfully",
				"method", info.FullMethod,
				"request_id", requestID,
				"duration", duration,
			)
		}

		return err
	}
}

// RecoveryInterceptor recovers from panics and returns proper gRPC errors
func RecoveryInterceptor(logger Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(ctx, "Panic recovered",
					"method", info.FullMethod,
					"panic", r,
				)
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor recovers from panics in stream handlers
func RecoveryStreamInterceptor(logger Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(stream.Context(), "Panic recovered in stream",
					"method", info.FullMethod,
					"panic", r,
				)
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		return handler(srv, stream)
	}
}

// ValidationInterceptor validates requests before processing
func ValidationInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Check if request implements validator interface
		if validator, ok := req.(interface{ Validate() error }); ok {
			if err := validator.Validate(); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "Validation failed: %v", err)
			}
		}

		return handler(ctx, req)
	}
}

// AuthInterceptor handles authentication
func AuthInterceptor(authFunc func(ctx context.Context) error) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip auth for health checks and reflection
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		if err := authFunc(ctx); err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "Authentication failed: %v", err)
		}

		return handler(ctx, req)
	}
}

// AuthStreamInterceptor handles authentication for streams
func AuthStreamInterceptor(authFunc func(ctx context.Context) error) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip auth for public methods
		if isPublicMethod(info.FullMethod) {
			return handler(srv, stream)
		}

		if err := authFunc(stream.Context()); err != nil {
			return status.Errorf(codes.Unauthenticated, "Authentication failed: %v", err)
		}

		return handler(srv, stream)
	}
}

// RateLimitingInterceptor applies rate limiting
func RateLimitingInterceptor(limiter RateLimiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !limiter.Allow(ctx, info.FullMethod) {
			return nil, status.Errorf(codes.ResourceExhausted, "Rate limit exceeded")
		}

		return handler(ctx, req)
	}
}

// RateLimiter interface for rate limiting
type RateLimiter interface {
	Allow(ctx context.Context, key string) bool
}

// wrappedServerStream wraps grpc.ServerStream to provide custom context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// isPublicMethod checks if a method should skip authentication
func isPublicMethod(method string) bool {
	publicMethods := []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1.Health/Watch",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	}

	for _, publicMethod := range publicMethods {
		if method == publicMethod {
			return true
		}
	}

	return false
}
