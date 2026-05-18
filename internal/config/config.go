package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration structure.
type Config struct {
	Docker     DockerConfig     `mapstructure:"docker"`
	Policies   PoliciesConfig   `mapstructure:"policies"`
	Protection ProtectionConfig `mapstructure:"protection"`
	Watch      WatchConfig      `mapstructure:"watch"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

// DockerConfig holds Docker daemon connection settings.
type DockerConfig struct {
	Socket  string        `mapstructure:"socket"`
	Timeout time.Duration `mapstructure:"timeout"`
}

// ContainerRule defines when a container should be deleted.
type ContainerRule struct {
	Status    string        `mapstructure:"status"`
	OlderThan time.Duration `mapstructure:"older_than"`
}

// ImagePolicy defines image cleanup rules.
type ImagePolicy struct {
	Dangling        bool          `mapstructure:"dangling"`
	UnusedOlderThan time.Duration `mapstructure:"unused_older_than"`
}

// VolumePolicy defines volume cleanup rules.
type VolumePolicy struct {
	Orphaned bool `mapstructure:"orphaned"`
}

// NetworkPolicy defines network cleanup rules.
type NetworkPolicy struct {
	Unused bool `mapstructure:"unused"`
}

// PoliciesConfig groups all resource cleanup policies.
type PoliciesConfig struct {
	Containers []ContainerRule `mapstructure:"containers"`
	Images     ImagePolicy     `mapstructure:"images"`
	Volumes    VolumePolicy    `mapstructure:"volumes"`
	Networks   NetworkPolicy   `mapstructure:"networks"`
}

// ProtectionConfig defines what should never be deleted.
type ProtectionConfig struct {
	Label        string   `mapstructure:"label"`
	NamePatterns []string `mapstructure:"name_patterns"`
}

// WatchConfig controls daemon scheduling.
type WatchConfig struct {
	Interval time.Duration `mapstructure:"interval"`
	Cron     string        `mapstructure:"cron"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// Defaults returns a Config populated with safe default values.
func Defaults() *Config {
	return &Config{
		Docker: DockerConfig{
			Socket:  "/var/run/docker.sock",
			Timeout: 30 * time.Second,
		},
		Protection: ProtectionConfig{
			Label: "dredge.keep=true",
		},
		Watch: WatchConfig{
			Interval: 6 * time.Hour,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stderr",
		},
	}
}

// Load reads config from configPath (or searches default locations), applies
// defaults, and validates. If no config file is found, safe defaults are used.
func Load(configPath string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("dredge")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
		v.AddConfigPath("/etc/dredge")
	}

	if err := v.ReadInConfig(); err != nil {
		if configPath != "" {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		// ConfigFileNotFoundError when searching default paths — use defaults.
	}

	cfg := &Config{}
	// [SECURITY] Strict config — unknown fields rejected. Prevents typos hiding dangerous misconfig.
	if err := v.UnmarshalExact(cfg); err != nil {
		if strings.Contains(err.Error(), "invalid keys") {
			return nil, fmt.Errorf("unknown config field: %w", err)
		}
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("docker.socket", "/var/run/docker.sock")
	v.SetDefault("docker.timeout", "30s")
	v.SetDefault("protection.label", "dredge.keep=true")
	v.SetDefault("watch.interval", "6h")
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stderr")
}

// validContainerStatuses are the only allowed values for container deletion rules.
// [SECURITY] "running" is NOT included — running containers are always protected, never configurable.
var validContainerStatuses = map[string]bool{
	"exited":  true,
	"created": true,
	"dead":    true,
}

// Validate checks all config values for correctness.
// [SECURITY] Strict config validation — reject invalid values, negative durations, and
// any attempt to configure deletion rules for running containers.
func (c *Config) Validate() error {
	if c.Docker.Timeout <= 0 {
		return fmt.Errorf("invalid timeout duration: must be > 0, got %s", c.Docker.Timeout)
	}

	for i, rule := range c.Policies.Containers {
		// [SECURITY] "running" status in a deletion policy is an explicit attack vector —
		// reject immediately with a clear error to prevent accidental or malicious misconfiguration.
		if rule.Status == "running" {
			return fmt.Errorf(
				"container status 'running' is not allowed in deletion policies — running containers are always protected",
			)
		}
		if !validContainerStatuses[rule.Status] {
			return fmt.Errorf(
				"invalid container status at rule %d: %q (allowed: exited, created, dead)",
				i, rule.Status,
			)
		}
		if rule.OlderThan < 0 {
			return fmt.Errorf(
				"invalid duration for container rule %d: older_than must be >= 0, got %s",
				i, rule.OlderThan,
			)
		}
	}

	// [SECURITY] Strict config validation — negative image unused_older_than silently
	// disables the rule in the engine (threshold > 0 check). Reject explicitly so
	// misconfigurations surface immediately rather than producing a silent no-op.
	if c.Policies.Images.UnusedOlderThan < 0 {
		return fmt.Errorf(
			"invalid duration for images.unused_older_than: must be >= 0, got %s",
			c.Policies.Images.UnusedOlderThan,
		)
	}

	if c.Watch.Interval > 0 && c.Watch.Interval < time.Minute {
		return fmt.Errorf("watch interval must be >= 1 minute, got %s", c.Watch.Interval)
	}

	if c.Protection.Label != "" && !strings.Contains(c.Protection.Label, "=") {
		return fmt.Errorf(
			"invalid protection label format: %q — must be in key=value format",
			c.Protection.Label,
		)
	}

	// [SECURITY] Validate name protection patterns at load time — an invalid pattern
	// is silently skipped by filepath.Match, leaving protected resources unguarded.
	for i, pattern := range c.Protection.NamePatterns {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid protection name_pattern at index %d: %q — %w", i, pattern, err)
		}
	}

	return nil
}
