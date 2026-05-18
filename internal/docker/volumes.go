package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/errdefs"
	"github.com/user/dredge/internal/model"
)

// ListVolumes returns all volumes as normalised Resources.
// [SECURITY] Context with timeout — prevents hanging on unresponsive Docker daemon.
func (c *Client) ListVolumes(ctx context.Context) ([]model.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.cli.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing volumes from Docker daemon: %w", err)
	}

	resources := make([]model.Resource, 0, len(resp.Volumes))
	for _, vol := range resp.Volumes {
		resources = append(resources, normalizeVolume(vol))
	}
	return resources, nil
}

func normalizeVolume(vol *volume.Volume) model.Resource {
	createdAt := time.Time{}
	if vol.CreatedAt != "" {
		// Docker returns RFC3339 format for volume creation time.
		if t, err := time.Parse(time.RFC3339, vol.CreatedAt); err == nil {
			createdAt = t
		}
	}

	return model.Resource{
		ID:        vol.Name,
		Name:      vol.Name,
		Type:      model.TypeVolume,
		State:     "available",
		CreatedAt: createdAt,
		Labels:    vol.Labels,
	}
}

// RemoveVolume removes the volume with the given name.
// [SECURITY] force=false — fails safely if the volume is still mounted by a container.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.cli.VolumeRemove(ctx, name, false)
}

// InspectVolume returns whether the volume still exists.
// Returns exists=false (no error) when the volume is not found.
// [SECURITY] Used by sweeper for TOCTOU re-check before each deletion.
func (c *Client) InspectVolume(ctx context.Context, name string) (exists bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, inspectErr := c.cli.VolumeInspect(ctx, name)
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return false, nil
		}
		return false, fmt.Errorf("inspecting volume %s: %w", name, inspectErr)
	}
	return true, nil
}
