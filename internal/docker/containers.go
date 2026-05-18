package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
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
	// [SECURITY] Full ID stored for unambiguous deletion — 12-char short IDs can
	// collide when two containers share the same prefix, causing the wrong container
	// to be targeted by Docker API calls.
	name := ctr.ID
	if len(ctr.ID) >= 12 {
		name = ctr.ID[:12]
	}
	if len(ctr.Names) > 0 {
		name = strings.TrimPrefix(ctr.Names[0], "/")
	}

	id := ctr.ID

	// Collect named volume mounts so ResolveReferences can build volume dependency graph.
	// [SECURITY] Named volume mounts are tracked to prevent orphan-deletion of mounted volumes.
	var mountedVolumes []string
	for _, m := range ctr.Mounts {
		if m.Type == mount.TypeVolume && m.Name != "" {
			mountedVolumes = append(mountedVolumes, m.Name)
		}
	}

	// Collect connected network IDs (short form) so ResolveReferences can build network graph.
	// [SECURITY] Network connections tracked to prevent unused-deletion of connected networks.
	var connectedNetworkIDs []string
	if ctr.NetworkSettings != nil {
		for _, endpoint := range ctr.NetworkSettings.Networks {
			if endpoint == nil || endpoint.NetworkID == "" {
				continue
			}
			netID := endpoint.NetworkID
			if len(netID) > 12 {
				netID = netID[:12]
			}
			connectedNetworkIDs = append(connectedNetworkIDs, netID)
		}
	}

	// [SECURITY] Normalize state to lowercase ResourceState — Docker SDK may return
	// mixed-case values across versions (e.g. "Exited" vs "exited").
	state := model.ResourceState(strings.ToLower(ctr.State))

	// SizeRw and SizeRootFs can be -1 when Docker has not computed them yet.
	// Clamp to 0 to prevent uint64 wrap-around when formatting human-readable sizes.
	size := ctr.SizeRw + ctr.SizeRootFs
	if size < 0 {
		size = 0
	}

	return model.Resource{
		ID:                  id,
		Name:                name,
		Type:                model.TypeContainer,
		State:               state,
		CreatedAt:           time.Unix(ctr.Created, 0),
		Size:                size,
		Labels:              ctr.Labels,
		ImageID:             ctr.ImageID,
		MountedVolumes:      mountedVolumes,
		ConnectedNetworkIDs: connectedNetworkIDs,
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
// State is normalized to lowercase ResourceState to match model constants.
// [SECURITY] Used by sweeper for TOCTOU re-check before each deletion.
func (c *Client) InspectContainer(ctx context.Context, id string) (exists bool, state model.ResourceState, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	info, inspectErr := c.cli.ContainerInspect(ctx, id)
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("inspecting container %s: %w", id, inspectErr)
	}
	return true, model.ResourceState(strings.ToLower(info.State.Status)), nil
}
