package collector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/user/dredge/internal/model"
)

// DockerClient is the interface the Collector uses to fetch resources.
// Using an interface instead of the concrete *docker.Client enables unit testing
// without a live Docker daemon.
// [SECURITY] Interface for Docker client — enables mocking without real Docker in unit tests.
type DockerClient interface {
	ListContainers(ctx context.Context) ([]model.Resource, error)
	ListImages(ctx context.Context) ([]model.Resource, error)
	ListVolumes(ctx context.Context) ([]model.Resource, error)
	ListNetworks(ctx context.Context) ([]model.Resource, error)
	Ping(ctx context.Context) error
	Close() error
}

// Inventory is a point-in-time snapshot of all Docker resources on the daemon.
type Inventory struct {
	Containers  []model.Resource
	Images      []model.Resource
	Volumes     []model.Resource
	Networks    []model.Resource
	CollectedAt time.Time
}

// Collector gathers all Docker resources and normalises them into an Inventory.
type Collector struct {
	client DockerClient
	logger *slog.Logger
}

// New constructs a Collector with the given client and logger.
func New(client DockerClient, logger *slog.Logger) *Collector {
	return &Collector{client: client, logger: logger}
}

// CollectAll fetches all four resource types and returns a fully-resolved Inventory.
// References (image → containers) are resolved before returning.
func (c *Collector) CollectAll(ctx context.Context) (*Inventory, error) {
	containers, err := c.client.ListContainers(ctx)
	if err != nil {
		return nil, newCollectError("containers", err)
	}

	images, err := c.client.ListImages(ctx)
	if err != nil {
		return nil, newCollectError("images", err)
	}

	volumes, err := c.client.ListVolumes(ctx)
	if err != nil {
		return nil, newCollectError("volumes", err)
	}

	networks, err := c.client.ListNetworks(ctx)
	if err != nil {
		return nil, newCollectError("networks", err)
	}

	inv := &Inventory{
		Containers:  containers,
		Images:      images,
		Volumes:     volumes,
		Networks:    networks,
		CollectedAt: time.Now(),
	}

	inv.ResolveReferences()

	c.logger.Info("collected docker resources",
		"containers", len(containers),
		"images", len(images),
		"volumes", len(volumes),
		"networks", len(networks),
	)

	return inv, nil
}

func newCollectError(resourceType string, err error) error {
	return fmt.Errorf("listing %s: %w", resourceType, err)
}

// ResolveReferences populates Resource.References for each image by scanning
// all containers and recording which image ID they use.
// [SECURITY] Reference resolution is the foundation of the dependency graph.
// An image with live references must never be deleted.
func (inv *Inventory) ResolveReferences() {
	imageByID := make(map[string]*model.Resource, len(inv.Images))
	for i := range inv.Images {
		imageByID[inv.Images[i].ID] = &inv.Images[i]
	}

	for _, ctr := range inv.Containers {
		if img, ok := imageByID[ctr.ImageID]; ok {
			img.References = append(img.References, ctr.ID)
		}
	}
}
