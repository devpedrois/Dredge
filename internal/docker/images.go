package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/errdefs"
	"github.com/user/dredge/internal/model"
)

// ListImages returns all images as normalised Resources, including dangling ones.
// [SECURITY] Context with timeout — prevents hanging on unresponsive Docker daemon.
func (c *Client) ListImages(ctx context.Context) ([]model.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	images, err := c.cli.ImageList(ctx, image.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("listing images from Docker daemon: %w", err)
	}

	resources := make([]model.Resource, 0, len(images))
	for _, img := range images {
		resources = append(resources, normalizeImage(img))
	}
	return resources, nil
}

func normalizeImage(img image.Summary) model.Resource {
	// Strip "sha256:" prefix and use short 12-char ID for readability.
	id := strings.TrimPrefix(img.ID, "sha256:")
	if len(id) > 12 {
		id = id[:12]
	}

	isDangling := len(img.RepoTags) == 0 || img.RepoTags[0] == "<none>:<none>"

	name := "<none>:<none>"
	if !isDangling {
		for _, tag := range img.RepoTags {
			if tag != "<none>:<none>" {
				name = tag
				break
			}
		}
	}

	state := "used"
	if isDangling {
		state = "dangling"
	}

	return model.Resource{
		ID:        id,
		Name:      name,
		Type:      model.TypeImage,
		State:     state,
		CreatedAt: time.Unix(img.Created, 0),
		Size:      img.Size,
		Labels:    img.Labels,
	}
}

// RemoveImage removes the image with the given ID.
// [SECURITY] Force: false, PruneChildren: false — conservative; fails safely if image is still referenced.
func (c *Client) RemoveImage(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err := c.cli.ImageRemove(ctx, id, image.RemoveOptions{Force: false, PruneChildren: false})
	return err
}

// InspectImage returns whether the image still exists.
// Returns exists=false (no error) when the image is not found.
// [SECURITY] Used by sweeper for TOCTOU re-check before each deletion.
func (c *Client) InspectImage(ctx context.Context, id string) (exists bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, _, inspectErr := c.cli.ImageInspectWithRaw(ctx, id)
	if inspectErr != nil {
		if errdefs.IsNotFound(inspectErr) {
			return false, nil
		}
		return false, fmt.Errorf("inspecting image %s: %w", id, inspectErr)
	}
	return true, nil
}
