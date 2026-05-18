package docker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/docker/docker/client"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/sweeper"
)

// Compile-time checks: *Client must implement all consumer interfaces.
var _ collector.DockerClient = (*Client)(nil)
var _ sweeper.DockerClient = (*Client)(nil)

// Client wraps the Docker Engine SDK client with timeout and logging.
// [SECURITY] Docker socket = root access to the host — handle with extreme care.
type Client struct {
	cli     *client.Client
	logger  *slog.Logger
	timeout time.Duration
}

// NewClient creates a Docker client connected to the given Unix socket.
// It immediately pings the daemon to verify connectivity.
// [SECURITY] Socket path comes from config — never hardcoded.
func NewClient(socketPath string, timeout time.Duration, logger *slog.Logger) (*Client, error) {
	cli, err := client.NewClientWithOpts(
		// [SECURITY] Socket path from config — never hardcoded
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Docker client: %w", err)
	}

	c := &Client{
		cli:     cli,
		logger:  logger,
		timeout: timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := c.Ping(ctx); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("cannot connect to Docker daemon at %s: %w", socketPath, err)
	}

	return c, nil
}

// Ping verifies the Docker daemon is reachable.
// [SECURITY] Context with timeout — prevents hanging on unresponsive Docker daemon.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if _, err := c.cli.Ping(ctx); err != nil {
		return fmt.Errorf("pinging Docker daemon: %w", err)
	}
	return nil
}

// Close releases the underlying Docker client connection.
func (c *Client) Close() error {
	return c.cli.Close()
}
