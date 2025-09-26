// file: services/health/cli.go
// version: 1.0.0
// guid: a1b2c3d4-5e6f-7g8h-9i0j-1k2l3m4n5o6p

package health

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// AddCliFlags adds health service configuration flags to a cobra command
func AddCliFlags(cmd *cobra.Command, prefix string) {
	if prefix != "" {
		prefix = prefix + "."
	}

	cmd.Flags().Duration(prefix+"health.check-interval", 30*time.Second, "Health check interval")
	cmd.Flags().Duration(prefix+"health.unhealthy-timeout", 5*time.Minute, "Timeout before marking service as unhealthy")
	cmd.Flags().Bool(prefix+"health.enable-detailed", true, "Enable detailed health information")
	cmd.Flags().String(prefix+"health.http-addr", "", "HTTP address for health endpoints (optional)")
	cmd.Flags().Int(prefix+"health.http-port", 0, "HTTP port for health endpoints (0 = disabled)")

	// Bind flags to viper
	viper.BindPFlag(prefix+"health.check_interval", cmd.Flags().Lookup(prefix+"health.check-interval"))
	viper.BindPFlag(prefix+"health.unhealthy_timeout", cmd.Flags().Lookup(prefix+"health.unhealthy-timeout"))
	viper.BindPFlag(prefix+"health.enable_detailed", cmd.Flags().Lookup(prefix+"health.enable-detailed"))
	viper.BindPFlag(prefix+"health.http_addr", cmd.Flags().Lookup(prefix+"health.http-addr"))
	viper.BindPFlag(prefix+"health.http_port", cmd.Flags().Lookup(prefix+"health.http-port"))
}

// ConfigFromViper creates a health service config from viper settings
func ConfigFromViper(prefix string) *Config {
	if prefix != "" {
		prefix = prefix + "."
	}

	return &Config{
		CheckInterval:    viper.GetDuration(prefix + "health.check_interval"),
		UnhealthyTimeout: viper.GetDuration(prefix + "health.unhealthy_timeout"),
		EnableDetailed:   viper.GetBool(prefix + "health.enable_detailed"),
	}
}

// HTTPConfig represents HTTP-specific health configuration
type HTTPConfig struct {
	Address string
	Port    int
}

// HTTPConfigFromViper creates HTTP health config from viper settings
func HTTPConfigFromViper(prefix string) *HTTPConfig {
	if prefix != "" {
		prefix = prefix + "."
	}

	return &HTTPConfig{
		Address: viper.GetString(prefix + "health.http_addr"),
		Port:    viper.GetInt(prefix + "health.http_port"),
	}
}
