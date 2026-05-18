package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/user/dredge/internal/config"
)

func TestConfigLoad(t *testing.T) {
	tests := []struct {
		name        string
		configPath  string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cfg *config.Config)
	}{
		{
			name:       "valid config loads correctly",
			configPath: "../testdata/configs/valid.yaml",
			wantErr:    false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "/var/run/docker.sock", cfg.Docker.Socket)
				assert.Equal(t, 30*time.Second, cfg.Docker.Timeout)
				assert.Equal(t, "dredge.keep=true", cfg.Protection.Label)
				assert.Equal(t, 6*time.Hour, cfg.Watch.Interval)
				assert.Equal(t, "info", cfg.Logging.Level)
				assert.Equal(t, "json", cfg.Logging.Format)
				require.Len(t, cfg.Policies.Containers, 3)
				assert.Equal(t, "exited", cfg.Policies.Containers[0].Status)
				assert.Equal(t, 24*time.Hour, cfg.Policies.Containers[0].OlderThan)
				assert.True(t, cfg.Policies.Images.Dangling)
				assert.True(t, cfg.Policies.Volumes.Orphaned)
				assert.True(t, cfg.Policies.Networks.Unused)
			},
		},
		{
			name:       "minimal config uses defaults",
			configPath: "../testdata/configs/minimal.yaml",
			wantErr:    false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "/var/run/docker.sock", cfg.Docker.Socket)
				assert.Equal(t, 30*time.Second, cfg.Docker.Timeout)
				assert.Equal(t, "dredge.keep=true", cfg.Protection.Label)
				assert.Equal(t, 6*time.Hour, cfg.Watch.Interval)
				assert.Equal(t, "info", cfg.Logging.Level)
				assert.Equal(t, "json", cfg.Logging.Format)
			},
		},
		{
			// [SECURITY] Test: strict config rejects unknown fields.
			// Typos in config fields could hide dangerous misconfigurations.
			name:        "unknown field rejected",
			configPath:  "../testdata/configs/invalid_unknown_field.yaml",
			wantErr:     true,
			errContains: "unknown",
		},
		{
			name:        "negative duration rejected",
			configPath:  "../testdata/configs/invalid_negative_duration.yaml",
			wantErr:     true,
			errContains: "older_than must be >= 0",
		},
		{
			// [SECURITY] Test: cannot create deletion rule for running containers.
			// Running containers are always protected — this must be enforced at config load.
			name:        "running status rejected in container policy",
			configPath:  "testdata_running_status",
			wantErr:     true,
			errContains: "running containers are always protected",
		},
		{
			name:        "invalid container status rejected",
			configPath:  "testdata_invalid_status",
			wantErr:     true,
			errContains: "invalid container status",
		},
		{
			name:        "watch interval too small",
			configPath:  "testdata_small_interval",
			wantErr:     true,
			errContains: "watch interval must be >= 1 minute",
		},
		{
			name:       "missing config file uses defaults",
			configPath: "",
			wantErr:    false,
			validate: func(t *testing.T, cfg *config.Config) {
				assert.Equal(t, "/var/run/docker.sock", cfg.Docker.Socket)
				assert.Equal(t, 30*time.Second, cfg.Docker.Timeout)
				assert.Equal(t, "dredge.keep=true", cfg.Protection.Label)
			},
		},
		{
			name:        "protection label format validated",
			configPath:  "testdata_bad_label",
			wantErr:     true,
			errContains: "key=value format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				cfg *config.Config
				err error
			)

			switch tt.configPath {
			case "testdata_running_status":
				cfg, err = loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
policies:
  containers:
    - status: "running"
      older_than: "1h"
`)
			case "testdata_invalid_status":
				cfg, err = loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
policies:
  containers:
    - status: "banana"
      older_than: "1h"
`)
			case "testdata_small_interval":
				cfg, err = loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
watch:
  interval: "10s"
`)
			case "testdata_bad_label":
				cfg, err = loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
protection:
  label: "nodequals"
`)
			default:
				cfg, err = config.Load(tt.configPath)
			}

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.True(t, strings.Contains(err.Error(), tt.errContains),
						"expected error to contain %q, got: %s", tt.errContains, err.Error())
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestConfigLoadFromHomeDir verifies that config search includes the home directory.
// viper v1.19+ calls os.ExpandEnv in absPathify so "$HOME" is correctly expanded.
func TestConfigLoadFromHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	// Write a minimal config to ~/.dredge.yaml temporarily.
	cfgPath := filepath.Join(home, ".dredge.yaml")
	content := `
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
`
	// Skip if file already exists to avoid clobbering real config.
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		t.Skip("~/.dredge.yaml already exists — skipping to avoid overwrite")
	}

	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	t.Cleanup(func() { os.Remove(cfgPath) })

	cfg, err := config.Load("")
	require.NoError(t, err, "config.Load('') must find ~/.dredge.yaml when home dir is properly searched")
	assert.Equal(t, "/var/run/docker.sock", cfg.Docker.Socket,
		"values from ~/.dredge.yaml must be loaded")
}

// TestConfigEmptyProtectionLabelDefaultsToKeepTrue verifies that explicitly setting
// protection.label to "" is handled safely by defaulting to "dredge.keep=true".
// Without this, an explicit empty label silently disables all label-based protection.
// [SECURITY] Empty label = all label protection disabled without user awareness.
func TestConfigEmptyProtectionLabelDefaultsToKeepTrue(t *testing.T) {
	cfg, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
protection:
  label: ""
`)
	require.NoError(t, err, "empty protection label must not error — must default safely")
	require.NotNil(t, cfg)
	assert.Equal(t, "dredge.keep=true", cfg.Protection.Label,
		"empty label must be restored to default to prevent silent protection bypass")
}

// TestConfigWatchIntervalZeroRejected verifies that explicitly setting watch.interval
// to 0 is rejected at validation time. time.NewTicker(0) panics at runtime.
func TestConfigWatchIntervalZeroRejected(t *testing.T) {
	_, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
watch:
  interval: "0s"
`)
	require.Error(t, err, "watch interval of 0 must be rejected to prevent ticker panic")
	assert.Contains(t, err.Error(), "watch interval",
		"error must name the invalid field")
}

// TestConfigNegativeImageUnusedOlderThanRejected verifies that a negative duration
// for images.unused_older_than is rejected by Validate, matching the strict validation
// already applied to container rules.
func TestConfigNegativeImageUnusedOlderThanRejected(t *testing.T) {
	_, err := loadInlineConfig(`
docker:
  socket: "/var/run/docker.sock"
  timeout: "30s"
policies:
  images:
    unused_older_than: "-1h"
`)
	require.Error(t, err, "negative images.unused_older_than must be rejected")
	assert.Contains(t, err.Error(), "unused_older_than",
		"error must name the invalid field")
}

// loadInlineConfig writes a YAML string to a temp file and loads it.
func loadInlineConfig(yaml string) (*config.Config, error) {
	f, err := createTempConfig(yaml)
	if err != nil {
		return nil, err
	}
	return config.Load(f)
}

func createTempConfig(content string) (string, error) {
	f, err := tmpFile(content)
	if err != nil {
		return "", err
	}
	return f, nil
}
