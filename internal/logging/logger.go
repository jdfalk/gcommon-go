// file: internal/logging/logger.go
// version: 1.0.0
// guid: e1f2a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b

package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Logger defines the interface for structured logging
type Logger interface {
	Debug(ctx context.Context, msg string, args ...interface{})
	Info(ctx context.Context, msg string, args ...interface{})
	Warn(ctx context.Context, msg string, args ...interface{})
	Error(ctx context.Context, msg string, args ...interface{})

	// With creates a new logger with the given key-value pairs
	With(args ...interface{}) Logger

	// WithContext creates a new logger with context values
	WithContext(ctx context.Context) Logger
}

// Config holds the logging configuration
type Config struct {
	Level      string `yaml:"level" default:"info"`
	Format     string `yaml:"format" default:"json"`   // json or text
	Output     string `yaml:"output" default:"stdout"` // stdout, stderr, or file path
	TimeFormat string `yaml:"time_format" default:"2006-01-02T15:04:05.000Z07:00"`
}

// slogLogger implements Logger using the standard slog package
type slogLogger struct {
	logger *slog.Logger
}

// NewLogger creates a new structured logger with the given configuration
func NewLogger(config *Config) (Logger, error) {
	if config == nil {
		config = &Config{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			TimeFormat: time.RFC3339,
		}
	}

	// Parse log level
	var level slog.Level
	switch config.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Configure output
	var output *os.File
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", config.Output, err)
		}
		output = file
	}

	// Configure handler
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(config.TimeFormat))
				}
			}
			return a
		},
	}

	switch config.Format {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	case "text":
		handler = slog.NewTextHandler(output, opts)
	default:
		handler = slog.NewJSONHandler(output, opts)
	}

	logger := slog.New(handler)
	return &slogLogger{logger: logger}, nil
}

// Debug logs a debug message
func (l *slogLogger) Debug(ctx context.Context, msg string, args ...interface{}) {
	l.logger.DebugContext(ctx, msg, args...)
}

// Info logs an info message
func (l *slogLogger) Info(ctx context.Context, msg string, args ...interface{}) {
	l.logger.InfoContext(ctx, msg, args...)
}

// Warn logs a warning message
func (l *slogLogger) Warn(ctx context.Context, msg string, args ...interface{}) {
	l.logger.WarnContext(ctx, msg, args...)
}

// Error logs an error message
func (l *slogLogger) Error(ctx context.Context, msg string, args ...interface{}) {
	l.logger.ErrorContext(ctx, msg, args...)
}

// With creates a new logger with the given key-value pairs
func (l *slogLogger) With(args ...interface{}) Logger {
	return &slogLogger{
		logger: l.logger.With(args...),
	}
}

// WithContext creates a new logger with context values
func (l *slogLogger) WithContext(ctx context.Context) Logger {
	// Extract common context values
	var attrs []slog.Attr

	if requestID := ctx.Value("request_id"); requestID != nil {
		attrs = append(attrs, slog.String("request_id", fmt.Sprint(requestID)))
	}

	if userID := ctx.Value("user_id"); userID != nil {
		attrs = append(attrs, slog.String("user_id", fmt.Sprint(userID)))
	}

	if traceID := ctx.Value("trace_id"); traceID != nil {
		attrs = append(attrs, slog.String("trace_id", fmt.Sprint(traceID)))
	}

	if len(attrs) == 0 {
		return l
	}

	// Convert attrs to args
	args := make([]interface{}, 0, len(attrs)*2)
	for _, attr := range attrs {
		args = append(args, attr.Key, attr.Value)
	}

	return &slogLogger{
		logger: l.logger.With(args...),
	}
}

// convertArgs converts interface{} args to slog.Attr
func convertArgs(args []interface{}) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(args)/2)

	for i := 0; i < len(args); i += 2 {
		if i+1 < len(args) {
			key := fmt.Sprint(args[i])
			value := args[i+1]
			attrs = append(attrs, slog.Any(key, value))
		}
	}

	return attrs
}

// DefaultLogger creates a default logger for development
func DefaultLogger() Logger {
	logger, _ := NewLogger(&Config{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	})
	return logger
}
