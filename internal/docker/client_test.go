package docker

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPinger satisfies the ping interface for white-box testing.
type mockLogger struct {
	*slog.Logger
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestNewClient_InvalidSocket(t *testing.T) {
	// [SECURITY] Test: connecting to a non-existent socket must fail with a clear error.
	// This validates that error propagation from Docker daemon is working correctly.
	_, err := NewClient("/nonexistent/docker.sock", 2*time.Second, testLogger())
	require.Error(t, err, "expected error for non-existent socket")
	assert.Contains(t, err.Error(), "cannot connect to Docker daemon")
}

func TestNewClient_SocketTimeout(t *testing.T) {
	// A socket that exists as a file but is not a valid Docker daemon should fail.
	f, err := os.CreateTemp("", "fake-docker-*.sock")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.Close()

	_, err = NewClient(f.Name(), 1*time.Second, testLogger())
	require.Error(t, err, "expected error connecting to a fake socket")
}

func TestClientPing_RequiresRunningDocker(t *testing.T) {
	// This test only runs when Docker is actually available.
	// In CI without Docker, the test is skipped gracefully.
	socketPath := "/var/run/docker.sock"
	if _, statErr := os.Stat(socketPath); os.IsNotExist(statErr) {
		t.Skip("Docker socket not available — skipping live ping test")
	}

	c, err := NewClient(socketPath, 10*time.Second, testLogger())
	if err != nil {
		t.Skipf("Docker not reachable: %v — skipping live ping test", err)
	}
	defer c.Close()

	ctx := context.Background()
	err = c.Ping(ctx)
	assert.NoError(t, err)
}
