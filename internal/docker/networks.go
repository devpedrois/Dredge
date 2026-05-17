package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/network"
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
		State:     "active",
		CreatedAt: net.Created,
		Labels:    net.Labels,
		IsDefault: defaultDockerNetworks[net.Name],
	}
}

// RemoveNetwork removes the network with the given ID.
// [SECURITY] Implemented in PR #5 — sweeper layer adds TOCTOU re-check before calling.
func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.cli.NetworkRemove(ctx, id)
}
