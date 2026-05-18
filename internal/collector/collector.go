package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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

// CollectionWarning records a partial failure during resource collection.
// When only some resource types fail, the Collector returns what it could
// gather rather than aborting entirely.
type CollectionWarning struct {
	ResourceType string
	Error        error
}

// Inventory is a point-in-time snapshot of all Docker resources on the daemon.
type Inventory struct {
	Containers  []model.Resource
	Images      []model.Resource
	Volumes     []model.Resource
	Networks    []model.Resource
	CollectedAt time.Time
	Warnings    []CollectionWarning // non-nil when some resource types failed to list
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

// CollectAll fetches all four resource types concurrently and returns a fully-resolved Inventory.
// All four Docker API calls are independent and issued in parallel to reduce collection latency.
// References (image → containers) are resolved before returning.
func (c *Collector) CollectAll(ctx context.Context) (*Inventory, error) {
	var (
		containers, images, volumes, networks []model.Resource
		errContainers, errImages, errVolumes, errNetworks error
	)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		var err error
		containers, err = c.client.ListContainers(ctx)
		errContainers = newCollectError("containers", err)
	}()
	go func() {
		defer wg.Done()
		var err error
		images, err = c.client.ListImages(ctx)
		errImages = newCollectError("images", err)
	}()
	go func() {
		defer wg.Done()
		var err error
		volumes, err = c.client.ListVolumes(ctx)
		errVolumes = newCollectError("volumes", err)
	}()
	go func() {
		defer wg.Done()
		var err error
		networks, err = c.client.ListNetworks(ctx)
		errNetworks = newCollectError("networks", err)
	}()

	wg.Wait()

	// If all four types failed, there is nothing useful to return.
	// If at least one succeeded, return a partial inventory with warnings.
	typeErrors := []struct {
		name string
		err  error
	}{
		{"containers", errContainers},
		{"images", errImages},
		{"volumes", errVolumes},
		{"networks", errNetworks},
	}

	var warnings []CollectionWarning
	allFailed := true
	for _, te := range typeErrors {
		if te.err == nil {
			allFailed = false
		} else {
			warnings = append(warnings, CollectionWarning{ResourceType: te.name, Error: te.err})
		}
	}

	if allFailed {
		return nil, errContainers
	}

	for _, w := range warnings {
		c.logger.Warn("partial collection failure — resource type skipped",
			"type", w.ResourceType, "error", w.Error)
	}

	inv := &Inventory{
		Containers:  containers,
		Images:      images,
		Volumes:     volumes,
		Networks:    networks,
		CollectedAt: time.Now(),
		Warnings:    warnings,
	}

	inv.ResolveReferences()

	c.logger.Info("collected docker resources",
		"containers", len(containers),
		"images", len(images),
		"volumes", len(volumes),
		"networks", len(networks),
		"warnings", len(warnings),
	)

	return inv, nil
}

func newCollectError(resourceType string, err error) error {
	if err == nil {
		return nil
	}
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
