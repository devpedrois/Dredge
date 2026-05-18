package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/errdefs"
	"github.com/user/dredge/internal/model"
)

// defaultDockerNetworks are the built-in Docker networks that must never be deleted.
// [SECURITY] Default networks are infrastructure — never deleted.
var defaultDockerNetworks = map[string]bool{
	"bridge": true,
	"host":   true,
	"none":   true,
}

// ListNetworks returns all networks as normalised Resources.
// Default Docker networks (bridge, host, none) are flagged via IsDefault.
// [SECURITY] Context with timeout — prevents hanging on unresponsive Docker daemon.
// [SECURITY] Default networks flagged — will be protected by policy engine.
func (c *Client) ListNetworks(ctx context.Context) ([]model.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	networks, err := c.cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing networks from Docker daemon: %w", err)
	}

	resources := make([]model.Resource, 0, len(networks))
	for _, net := range networks {
		resources = append(resources, normalizeNetwork(net))
	}
	return resources, nil
}

func normalizeNetwork(net network.Summary) model.Resource {
	id := net.ID
	if len(net.ID) > 12 {
		id = net.ID[:12]
	}

	return model.Resource{
		ID:        id,
		Name:      net.Name,
		Type:      model.TypeNetwork,
		State:     model.StateActive,
		CreatedAt: net.Created,
		Labels:    net.Labels,
		IsDefault: defaultDockerNetworks[net.Name],
	}
}

// RemoveNetwork removes the network with the given ID.
func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.cli.NetworkRemove(ctx, id)
}

// InspectNetwork returns whether the network still exists.
// Returns exists=false (no error) when the network is not found.
// [SECURITY] Used by sweeper for TOCTOU re-check before each deletion.
func (c *Client) InspectNetwork(ctx context.Context, id string) (exists bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, inspectErr := c.cli.NetworkInspect(ctx, id, network.InspectOptions{})
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return false, nil
		}
		return false, fmt.Errorf("inspecting network %s: %w", id, inspectErr)
	}
	return true, nil
}
