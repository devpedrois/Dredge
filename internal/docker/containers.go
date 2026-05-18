package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/errdefs"
	"github.com/user/dredge/internal/model"
)

// ListContainers returns all containers (running and stopped) as normalised Resources.
// All: true ensures stopped/dead/created containers are included — the policy engine
// must see them to evaluate deletion rules.
// [SECURITY] Context with timeout — prevents hanging on unresponsive Docker daemon.
func (c *Client) ListContainers(ctx context.Context) ([]model.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("listing containers from Docker daemon: %w", err)
	}

	resources := make([]model.Resource, 0, len(containers))
	for _, ctr := range containers {
		resources = append(resources, normalizeContainer(ctr))
	}
	return resources, nil
}

func normalizeContainer(ctr dockertypes.Container) model.Resource {
	name := ctr.ID
	if len(ctr.ID) >= 12 {
		name = ctr.ID[:12]
	}
	if len(ctr.Names) > 0 {
		name = strings.TrimPrefix(ctr.Names[0], "/")
	}

	id := ctr.ID
	if len(ctr.ID) >= 12 {
		id = ctr.ID[:12]
	}

	return model.Resource{
		ID:        id,
		Name:      name,
		Type:      model.TypeContainer,
		State:     ctr.State,
		CreatedAt: time.Unix(ctr.Created, 0),
		Size:      ctr.SizeRw + ctr.SizeRootFs,
		Labels:    ctr.Labels,
		ImageID:   ctr.ImageID,
	}
}

// RemoveContainer removes the container with the given ID.
// [SECURITY] Force: false — never force-remove; if container restarted, the call fails safely.
func (c *Client) RemoveContainer(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.cli.ContainerRemove(ctx, id, container.RemoveOptions{Force: false})
}

// InspectContainer returns the current existence and state of a container.
// Returns exists=false (no error) when the container is not found.
// [SECURITY] Used by sweeper for TOCTOU re-check before each deletion.
func (c *Client) InspectContainer(ctx context.Context, id string) (exists bool, state string, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	info, inspectErr := c.cli.ContainerInspect(ctx, id)
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("inspecting container %s: %w", id, inspectErr)
	}
	return true, info.State.Status, nil
}
