package stats

import "github.com/user/dredge/internal/collector"

// ContainerStats holds container counts by state.
type ContainerStats struct {
	Total   int
	Running int
	Exited  int
	Created int
	Dead    int
	Other   int
}

// ImageStats holds image counts.
type ImageStats struct {
	Total   int
	Dangling int
	Tagged  int
}

// VolumeStats holds volume counts.
type VolumeStats struct {
	Total int
}

// NetworkStats holds network counts.
type NetworkStats struct {
	Total   int
	Default int
	Custom  int
}

// DiskUsage holds disk usage by resource type in bytes.
type DiskUsage struct {
	Images     int64
	Containers int64
	Volumes    int64
	Total      int64
}

// ResourceStats is the complete resource usage snapshot.
type ResourceStats struct {
	Containers ContainerStats
	Images     ImageStats
	Volumes    VolumeStats
	Networks   NetworkStats
	DiskUsage  DiskUsage
}

// Calculate computes a ResourceStats snapshot from an inventory.
// Pure function: does not modify the inventory.
// [SECURITY] Read-only — never modifies inventory data or Docker state.
func Calculate(inv *collector.Inventory) *ResourceStats {
	s := &ResourceStats{}

	for _, r := range inv.Containers {
		s.Containers.Total++
		s.DiskUsage.Containers += r.Size
		switch r.State {
		case "running":
			s.Containers.Running++
		case "exited":
			s.Containers.Exited++
		case "created":
			s.Containers.Created++
		case "dead":
			s.Containers.Dead++
		default:
			s.Containers.Other++
		}
	}

	for _, r := range inv.Images {
		s.Images.Total++
		s.DiskUsage.Images += r.Size
		if r.State == "dangling" {
			s.Images.Dangling++
		} else {
			s.Images.Tagged++
		}
	}

	for _, r := range inv.Volumes {
		s.Volumes.Total++
		s.DiskUsage.Volumes += r.Size
	}

	for _, r := range inv.Networks {
		s.Networks.Total++
		if r.IsDefault {
			s.Networks.Default++
		} else {
			s.Networks.Custom++
		}
	}

	s.DiskUsage.Total = s.DiskUsage.Images + s.DiskUsage.Containers + s.DiskUsage.Volumes

	return s
}
