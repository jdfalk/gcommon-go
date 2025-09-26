// file: internal/config/config.go
// version: 1.0.0
// guid: f2e3d4c5-b6a7-8c9d-0e1f-2a3b4c5d6e7f

package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server"`

	// Database configuration
	Database DatabaseConfig `yaml:"database"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging"`

	// Authentication configuration
	Auth AuthConfig `yaml:"auth"`

	// Metrics configuration
	Metrics MetricsConfig `yaml:"metrics"`

	// Cache configuration
	Cache CacheConfig `yaml:"cache"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host             string `yaml:"host" default:"localhost"`
	Port             int    `yaml:"port" default:"8080"`
	GRPCPort         int    `yaml:"grpc_port" default:"9090"`
	ReadTimeout      string `yaml:"read_timeout" default:"30s"`
	WriteTimeout     string `yaml:"write_timeout" default:"30s"`
	ShutdownTimeout  string `yaml:"shutdown_timeout" default:"10s"`
	EnableTLS        bool   `yaml:"enable_tls" default:"false"`
	TLSCertFile      string `yaml:"tls_cert_file"`
	TLSKeyFile       string `yaml:"tls_key_file"`
	EnableReflection bool   `yaml:"enable_reflection" default:"true"`
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Driver          string `yaml:"driver" default:"postgres"`
	DSN             string `yaml:"dsn"`
	MaxOpenConns    int    `yaml:"max_open_conns" default:"25"`
	MaxIdleConns    int    `yaml:"max_idle_conns" default:"5"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime" default:"5m"`
	MigrationsPath  string `yaml:"migrations_path" default:"migrations"`
}

// LoggingConfig holds logging-related configuration
type LoggingConfig struct {
	Level      string `yaml:"level" default:"info"`
	Format     string `yaml:"format" default:"json"`
	Output     string `yaml:"output" default:"stdout"`
	TimeFormat string `yaml:"time_format" default:"2006-01-02T15:04:05.000Z07:00"`
}

// AuthConfig holds authentication-related configuration
type AuthConfig struct {
	JWTSecret       string `yaml:"jwt_secret"`
	TokenExpiration string `yaml:"token_expiration" default:"24h"`
	EnableAPIKey    bool   `yaml:"enable_api_key" default:"true"`
	APIKeyHeader    string `yaml:"api_key_header" default:"X-API-Key"`
}

// MetricsConfig holds metrics-related configuration
type MetricsConfig struct {
	Enabled   bool   `yaml:"enabled" default:"true"`
	Path      string `yaml:"path" default:"/metrics"`
	Port      int    `yaml:"port" default:"2112"`
	Namespace string `yaml:"namespace" default:"gcommon"`
}

// CacheConfig holds cache-related configuration
type CacheConfig struct {
	Enabled    bool   `yaml:"enabled" default:"true"`
	Type       string `yaml:"type" default:"memory"` // memory, redis
	RedisURL   string `yaml:"redis_url"`
	DefaultTTL string `yaml:"default_ttl" default:"1h"`
	MaxSize    int    `yaml:"max_size" default:"1000"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	if err := setDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %w", err)
	}

	// Load from file if provided
	if configPath != "" {
		if err := loadFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load from file: %w", err)
		}
	}

	// Override with environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load from environment: %w", err)
	}

	return config, nil
}

// loadFromFile loads configuration from a YAML file
func loadFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config interface{}) error {
	return loadFromEnvWithPrefix(config, "GCOMMON")
}

// loadFromEnvWithPrefix loads configuration from environment variables with a prefix
func loadFromEnvWithPrefix(config interface{}, prefix string) error {
	v := reflect.ValueOf(config)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("config must be a pointer to struct")
	}

	return setFieldsFromEnv(v.Elem(), reflect.TypeOf(config).Elem(), prefix)
}

// setFieldsFromEnv recursively sets struct fields from environment variables
func setFieldsFromEnv(v reflect.Value, t reflect.Type, prefix string) error {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		yamlTag := fieldType.Tag.Get("yaml")
		if yamlTag == "" || yamlTag == "-" {
			continue
		}

		fieldName := strings.Split(yamlTag, ",")[0]
		envKey := fmt.Sprintf("%s_%s", prefix, strings.ToUpper(strings.ReplaceAll(fieldName, "-", "_")))

		if field.Kind() == reflect.Struct {
			// Recursively handle nested structs
			nestedPrefix := fmt.Sprintf("%s_%s", prefix, strings.ToUpper(strings.ReplaceAll(fieldName, "-", "_")))
			if err := setFieldsFromEnv(field, field.Type(), nestedPrefix); err != nil {
				return err
			}
			continue
		}

		envValue := os.Getenv(envKey)
		if envValue == "" {
			continue
		}

		if err := setFieldValue(field, envValue); err != nil {
			return fmt.Errorf("failed to set field %s from env %s: %w", fieldType.Name, envKey, err)
		}
	}

	return nil
}

// setFieldValue sets a field value from a string
func setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int value: %s", value)
		}
		field.SetInt(intVal)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid uint value: %s", value)
		}
		field.SetUint(uintVal)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid bool value: %s", value)
		}
		field.SetBool(boolVal)
	case reflect.Float32, reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float value: %s", value)
		}
		field.SetFloat(floatVal)
	default:
		return fmt.Errorf("unsupported field type: %v", field.Kind())
	}

	return nil
}

// setDefaults sets default values for configuration fields
func setDefaults(config interface{}) error {
	return setDefaultsRecursive(reflect.ValueOf(config).Elem(), reflect.TypeOf(config).Elem())
}

// setDefaultsRecursive recursively sets default values
func setDefaultsRecursive(v reflect.Value, t reflect.Type) error {
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		if !field.CanSet() {
			continue
		}

		if field.Kind() == reflect.Struct {
			if err := setDefaultsRecursive(field, field.Type()); err != nil {
				return err
			}
			continue
		}

		defaultTag := fieldType.Tag.Get("default")
		if defaultTag == "" {
			continue
		}

		if err := setFieldValue(field, defaultTag); err != nil {
			return fmt.Errorf("failed to set default for field %s: %w", fieldType.Name, err)
		}
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.GRPCPort <= 0 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPCPort)
	}

	if c.Server.EnableTLS {
		if c.Server.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file is required when TLS is enabled")
		}
		if c.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}
	}

	// Validate database configuration
	if c.Database.DSN == "" {
		return fmt.Errorf("database DSN is required")
	}

	// Validate auth configuration
	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	return nil
}
