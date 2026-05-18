package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/user/dredge/internal/collector"
	"github.com/user/dredge/internal/model"
	"github.com/user/dredge/internal/stats"
)

func buildInventory() *collector.Inventory {
	return &collector.Inventory{
		Containers: []model.Resource{
			{ID: "c1", Name: "app1", Type: model.TypeContainer, State: model.StateRunning},
			{ID: "c2", Name: "app2", Type: model.TypeContainer, State: model.StateExited},
			{ID: "c3", Name: "app3", Type: model.TypeContainer, State: model.StateExited},
		},
		Images: []model.Resource{
			{ID: "i1", Name: "myimage:latest", Type: model.TypeImage, State: model.StateUsed},
			{ID: "i2", Name: "<none>:<none>", Type: model.TypeImage, State: model.StateDangling},
		},
		Volumes: []model.Resource{
			{ID: "v1", Name: "v1", Type: model.TypeVolume},
			{ID: "v2", Name: "v2", Type: model.TypeVolume},
		},
		Networks: []model.Resource{
			{ID: "n1", Name: "bridge", Type: model.TypeNetwork, IsDefault: true},
			{ID: "n2", Name: "custom", Type: model.TypeNetwork, IsDefault: false},
		},
	}
}

// TestStatsShowsCorrectCounts verifies each resource type is counted correctly
// by state, dangling flag, and default network flag.
func TestStatsShowsCorrectCounts(t *testing.T) {
	s := stats.Calculate(buildInventory())

	assert.Equal(t, 3, s.Containers.Total)
	assert.Equal(t, 1, s.Containers.Running)
	assert.Equal(t, 2, s.Containers.Exited)
	assert.Equal(t, 2, s.Images.Total)
	assert.Equal(t, 1, s.Images.Dangling)
	assert.Equal(t, 1, s.Images.Tagged)
	assert.Equal(t, 2, s.Volumes.Total)
	assert.Equal(t, 2, s.Networks.Total)
	assert.Equal(t, 1, s.Networks.Default)
	assert.Equal(t, 1, s.Networks.Custom)
}

// TestStatsCalculatesDiskUsage verifies disk usage is summed correctly per
// resource type and in total.
func TestStatsCalculatesDiskUsage(t *testing.T) {
	inv := &collector.Inventory{
		Containers: []model.Resource{
			{ID: "c1", Type: model.TypeContainer, Size: 100},
			{ID: "c2", Type: model.TypeContainer, Size: 200},
		},
		Images: []model.Resource{
			{ID: "i1", Type: model.TypeImage, Size: 500},
		},
		Volumes:  []model.Resource{},
		Networks: []model.Resource{},
	}

	s := stats.Calculate(inv)

	assert.Equal(t, int64(300), s.DiskUsage.Containers)
	assert.Equal(t, int64(500), s.DiskUsage.Images)
	assert.Equal(t, int64(0), s.DiskUsage.Volumes)
	assert.Equal(t, int64(800), s.DiskUsage.Total)
}

// TestStatsDoesNotModifyInventory verifies stats.Calculate is a pure read-only
// operation — it must never mutate the inventory.
// [SECURITY] Stats command is read-only — must not alter Docker state or inventory data.
func TestStatsDoesNotModifyInventory(t *testing.T) {
	inv := buildInventory()
	originalContainerCount := len(inv.Containers)
	originalFirstID := inv.Containers[0].ID

	s := stats.Calculate(inv)

	assert.Equal(t, originalContainerCount, len(inv.Containers), "inventory slice must not change")
	assert.Equal(t, originalFirstID, inv.Containers[0].ID, "container IDs must not change")
	assert.Equal(t, 3, s.Containers.Total)
}
