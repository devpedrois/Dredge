package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// ResolveReferences populates Resource.References for images, volumes, and networks
// by scanning all containers and recording which resources they use.
// [SECURITY] Reference resolution is the foundation of the dependency graph.
// Images/volumes/networks with live references must never be deleted.
func (inv *Inventory) ResolveReferences() {
	// Image graph: image short-ID → resource pointer.
	// [SECURITY] ImageID from ContainerList is "sha256:<hex64>" — must be normalized to
	// match the 12-char short IDs stored in image Resources by normalizeImage().
	// Without this normalization, the lookup always misses and ALL images appear unreferenced.
	imageByID := make(map[string]*model.Resource, len(inv.Images))
	for i := range inv.Images {
		imageByID[inv.Images[i].ID] = &inv.Images[i]
	}

	// Volume graph: volume name → resource pointer.
	volumeByName := make(map[string]*model.Resource, len(inv.Volumes))
	for i := range inv.Volumes {
		volumeByName[inv.Volumes[i].Name] = &inv.Volumes[i]
	}

	// Network graph: network short-ID → resource pointer.
	networkByID := make(map[string]*model.Resource, len(inv.Networks))
	for i := range inv.Networks {
		networkByID[inv.Networks[i].ID] = &inv.Networks[i]
	}

	for _, ctr := range inv.Containers {
		// Image reference: normalize sha256: prefix + truncate to 12 chars.
		// [SECURITY] Without normalization the lookup always misses, breaking image dependency graph.
		imgID := strings.TrimPrefix(ctr.ImageID, "sha256:")
		if len(imgID) > 12 {
			imgID = imgID[:12]
		}
		if img, ok := imageByID[imgID]; ok {
			img.References = append(img.References, ctr.ID)
		}

		// Volume references: named volumes mounted by this container.
		for _, volName := range ctr.MountedVolumes {
			if vol, ok := volumeByName[volName]; ok {
				vol.References = append(vol.References, ctr.ID)
			}
		}

		// Network references: networks this container is connected to.
		for _, netID := range ctr.ConnectedNetworkIDs {
			if net, ok := networkByID[netID]; ok {
				net.References = append(net.References, ctr.ID)
			}
		}
	}
}
