package test

import (
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
