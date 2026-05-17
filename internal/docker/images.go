package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
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
// [SECURITY] Implemented in PR #5 — sweeper layer adds TOCTOU re-check before calling.
func (c *Client) RemoveImage(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err := c.cli.ImageRemove(ctx, id, image.RemoveOptions{})
	return err
}
